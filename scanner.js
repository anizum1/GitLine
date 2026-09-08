"use strict";

/**
 * Pure scanning logic — no network, no DOM.
 *
 * Runs unchanged in a browser (<script> tag) and in Node (require), so the
 * page and the cron worker always agree on what counts as a finding.
 *
 * The central rule here: a secret is redacted at the moment it is detected.
 * Findings never carry the plaintext, so nothing downstream — IndexedDB, the
 * committed JSON feed, an export — can leak one by accident.
 */

/* eslint-disable no-undef */
const P = (typeof module !== "undefined" && typeof require !== "undefined")
  ? require("./patterns.js")
  : {
      SECRET_PATTERNS, LOCKFILE_PATTERNS, LOCKFILE_SAFE_PATTERN_NAMES,
      SKIP_DIRS, BINARY_EXTENSIONS, STRINGS_WORTHY_EXTENSIONS,
    };

const SCAN_DEFAULTS = {
  maxFileSizeBytes: 300 * 1024,   // deep mode raises this
  includeLockfiles: false,
  includeBinaries: false,
  entropy: true,
  entropyBase64Threshold: 4.5,
  entropyHexThreshold: 3.0,
  minCandidateLength: 24,
  maxLineLength: 2000,            // skip minified / pathological lines
  snippetContext: 80,             // chars of context kept either side
};

const ENTROPY_SKIP_LINE_HINTS = [
  "sha1", "sha256", "sha512", "commit", "checksum", "integrity",
  "lockfileversion", "resolved", "swagger", "openapi",
];

/* =========================================================
   Fingerprinting — dedupe without retaining the secret
========================================================= */

/**
 * FNV-1a, 32-bit. Used only to recognise "this is the same string we already
 * reported" across files, commits and scan runs. Non-reversible and never
 * treated as a security boundary.
 */
function fnv1a(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

/* =========================================================
   Entropy
========================================================= */
function shannonEntropy(str) {
  const freq = Object.create(null);
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  let entropy = 0;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const BASE64_CANDIDATE_RE = /[A-Za-z0-9+/]{24,}={0,2}/g;
const HEX_CANDIDATE_RE = /[0-9a-fA-F]{32,}/g;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const REPEATED_CHAR_RE = /^(.)\1+$/;

function findEntropyCandidates(line, cfg) {
  const o = cfg || SCAN_DEFAULTS;
  const lowerLine = line.toLowerCase();
  if (ENTROPY_SKIP_LINE_HINTS.some((hint) => lowerLine.includes(hint))) return [];

  const results = [];
  const seen = new Set();

  for (const re of [BASE64_CANDIDATE_RE, HEX_CANDIDATE_RE]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(line)) !== null) {
      const candidate = m[0];
      if (candidate.length < o.minCandidateLength) continue;
      if (UUID_RE.test(candidate)) continue;
      if (REPEATED_CHAR_RE.test(candidate)) continue;
      if (seen.has(candidate)) continue;

      const isHexOnly = /^[0-9a-fA-F]+$/.test(candidate);
      const entropy = shannonEntropy(candidate);
      const threshold = isHexOnly ? o.entropyHexThreshold : o.entropyBase64Threshold;

      if (entropy >= threshold) {
        seen.add(candidate);
        results.push({ match: candidate, index: m.index, entropy });
      }
    }
  }
  return results;
}

/* =========================================================
   Redaction
========================================================= */
function redact(match) {
  if (match.length <= 10) {
    return match[0] + "•".repeat(Math.max(match.length - 2, 1)) + match[match.length - 1];
  }
  return match.slice(0, 4) + "•".repeat(Math.min(match.length - 8, 24)) + match.slice(-4);
}

/**
 * Build the display snippet for one span, with every *other* known span on the
 * same line redacted too. Two secrets on one line must not leak each other
 * through the neighbouring finding's context window.
 *
 * `spans` must be sorted by `start`.
 */
function renderLineParts(line, spans, target, ctxChars) {
  const build = (from, to) => {
    let out = "";
    let cursor = from;
    for (const s of spans) {
      if (s === target) continue;
      if (s.start >= cursor && s.end <= to && s.start >= from) {
        out += line.slice(cursor, s.start) + redact(s.text);
        cursor = s.end;
      }
    }
    return out + line.slice(cursor, to);
  };

  let before = build(0, target.start);
  let after = build(target.end, line.length);
  if (before.length > ctxChars) before = "…" + before.slice(-ctxChars);
  if (after.length > ctxChars) after = after.slice(0, ctxChars) + "…";
  return { before, redacted: redact(target.text), after };
}

/* =========================================================
   Line offset helpers
========================================================= */
function lineOffsets(text) {
  const offs = [0];
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10) offs.push(i + 1);
  }
  return offs;
}

function lineIndexAt(offs, pos) {
  let lo = 0, hi = offs.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (offs[mid] <= pos) lo = mid; else hi = mid - 1;
  }
  return lo;
}

/* =========================================================
   Core: scan a block of text
========================================================= */
/**
 * @param text        full text to scan
 * @param opts.lineNumberFor  (lineIdx) => reported line number. Lets a diff or
 *                            a strings dump report real file line numbers.
 * @param opts.patternNames   optional Set restricting which named patterns run
 *                            (lockfiles and binaries use a narrow allowlist)
 * @returns findings without repo context — the caller attaches that
 */
function scanBlock(text, opts) {
  const o = { ...SCAN_DEFAULTS, ...(opts || {}) };
  const lineNumberFor = o.lineNumberFor || ((i) => i + 1);
  const patternNames = o.patternNames || null;

  const lines = text.split("\n");
  const offs = lineOffsets(text);
  const spansByLine = new Map();

  const addSpan = (lineIdx, span) => {
    let arr = spansByLine.get(lineIdx);
    if (!arr) { arr = []; spansByLine.set(lineIdx, arr); }
    arr.push(span);
  };

  // --- Named pattern pass, over the whole block so multi-line patterns work
  for (const pattern of P.SECRET_PATTERNS) {
    if (patternNames && !patternNames.has(pattern.name)) continue;
    pattern.regex.lastIndex = 0;
    let m;
    while ((m = pattern.regex.exec(text)) !== null) {
      const full = m[0];
      if (full.length === 0) { pattern.regex.lastIndex++; continue; }

      const lineIdx = lineIndexAt(offs, m.index);
      const lineStart = offs[lineIdx];
      const lineText = lines[lineIdx] || "";
      // Clip to this line — a multi-line match is attributed to where it starts.
      const start = m.index - lineStart;
      const end = Math.min(start + full.length, lineText.length);

      addSpan(lineIdx, {
        start, end,
        text: lineText.slice(start, end),
        fpText: full,
        name: pattern.name,
        severity: pattern.severity,
      });

      if (pattern.regex.lastIndex === m.index) pattern.regex.lastIndex++;
    }
  }

  // --- Entropy pass, per line, skipping lines a named pattern already claimed
  if (o.entropy) {
    for (let i = 0; i < lines.length; i++) {
      if (spansByLine.has(i)) continue;
      const lineText = lines[i];
      if (lineText.length > o.maxLineLength) continue;

      for (const c of findEntropyCandidates(lineText, o)) {
        addSpan(i, {
          start: c.index,
          end: c.index + c.match.length,
          text: c.match,
          fpText: c.match,
          name: "High-entropy string",
          severity: "low",
        });
      }
    }
  }

  // --- Materialise findings with everything on the line redacted
  const findings = [];
  for (const [lineIdx, spans] of spansByLine) {
    spans.sort((a, b) => a.start - b.start || a.end - b.end);
    const lineText = lines[lineIdx] || "";
    for (const span of spans) {
      const parts = renderLineParts(lineText, spans, span, o.snippetContext);
      findings.push({
        line: lineNumberFor(lineIdx),
        name: span.name,
        severity: span.severity,
        before: parts.before,
        redacted: parts.redacted,
        after: parts.after,
        fp: fnv1a(span.fpText),
      });
    }
  }
  return findings;
}

/* =========================================================
   Source-specific entry points
========================================================= */

/** A whole file's text, from the current tree or a historical commit. */
function scanText(path, content, opts) {
  const o = { ...SCAN_DEFAULTS, ...(opts || {}) };
  return scanBlock(content, o).map((f) => ({ ...f, file: path, source: o.source || "tree" }));
}

/**
 * Added lines of a unified diff.
 *
 * Line numbers come from the `+` side of each `@@ -a,b +c,d @@` hunk header, so
 * a finding points at the line as it existed in *that* commit.
 */
function scanPatch(path, patch, opts) {
  const o = { ...SCAN_DEFAULTS, ...(opts || {}) };
  const added = [];
  let newLine = 0;

  for (const raw of patch.split("\n")) {
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
    if (hunk) { newLine = parseInt(hunk[1], 10); continue; }
    if (raw.startsWith("+++") || raw.startsWith("---")) continue;

    if (raw.startsWith("+")) {
      added.push({ n: newLine, text: raw.slice(1) });
      newLine++;
    } else if (raw.startsWith("-") || raw.startsWith("\\")) {
      // removed line / "\ No newline" — consumes no new-side number
    } else {
      newLine++; // context line
    }
  }

  if (!added.length) return [];
  const block = added.map((a) => a.text).join("\n");
  return scanBlock(block, { ...o, lineNumberFor: (i) => added[i].n })
    .map((f) => ({ ...f, file: path, source: "history" }));
}

/* =========================================================
   Binaries
========================================================= */
/**
 * A `strings(1)`-style extractor: printable-ASCII runs, plus a UTF-16LE pass
 * so keys embedded in Windows binaries are not missed.
 */
function extractStrings(bytes, minLen) {
  const min = minLen || 6;
  const out = [];

  const flush = (buf) => { if (buf.length >= min) out.push(buf); };

  // ASCII
  let cur = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === 9 || (b >= 0x20 && b <= 0x7e)) cur += String.fromCharCode(b);
    else { flush(cur); cur = ""; }
  }
  flush(cur);

  // UTF-16LE: printable byte followed by a zero byte
  cur = "";
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    const b = bytes[i], hi = bytes[i + 1];
    if (hi === 0 && (b === 9 || (b >= 0x20 && b <= 0x7e))) cur += String.fromCharCode(b);
    else { flush(cur); cur = ""; }
  }
  flush(cur);

  return out;
}

/**
 * Named patterns only. Binaries are wall-to-wall high-entropy bytes, so the
 * entropy pass would report the entire file.
 */
function scanBinary(path, bytes, opts) {
  const o = { ...SCAN_DEFAULTS, ...(opts || {}) };
  const strings = extractStrings(bytes, o.minStringLength || 6);
  if (!strings.length) return [];

  return scanBlock(strings.join("\n"), {
    ...o,
    entropy: false,
    patternNames: null,
    lineNumberFor: () => 0, // no meaningful line number inside a binary
  }).map((f) => ({ ...f, file: path, source: "binary", binary: true, line: 0 }));
}

/* =========================================================
   Path classification
========================================================= */
/** Git LFS stores a small pointer stub in the repo; raw fetches return the stub. */
function isLfsPointer(text) {
  return typeof text === "string" && text.startsWith("version https://git-lfs.github.com/spec/");
}

/**
 * Replaces the old boolean `shouldSkipPath`. Deep mode turns the previous
 * hard exclusions (lockfiles, binaries, oversize) into scannable classes.
 */
function classifyPath(path, sizeBytes, opts) {
  const o = { ...SCAN_DEFAULTS, ...(opts || {}) };
  const size = sizeBytes || 0;

  const segments = path.split("/");
  const dirs = segments.slice(0, -1);
  const dot = path.lastIndexOf(".");
  const ext = dot === -1 ? "" : path.slice(dot + 1).toLowerCase();

  const isBinary = P.BINARY_EXTENSIONS.has(ext);
  const isLockfile = P.LOCKFILE_PATTERNS.some((re) => re.test(path));
  const stringsWorthy = P.STRINGS_WORTHY_EXTENSIONS.has(ext);
  const oversize = size > o.maxFileSizeBytes;

  const out = { isBinary, isLockfile, stringsWorthy, oversize, skip: false, reason: null };

  if (dirs.some((seg) => P.SKIP_DIRS.has(seg))) { out.skip = true; out.reason = "dependency-dir"; return out; }
  if (oversize) { out.skip = true; out.reason = "oversize"; return out; }
  if (isBinary) {
    // Compressed and media containers stay out even in deep mode: their bytes
    // are noise no strings extractor can read through.
    if (!o.includeBinaries) { out.skip = true; out.reason = "binary"; return out; }
    if (!stringsWorthy) { out.skip = true; out.reason = "binary-opaque"; return out; }
  }
  if (isLockfile && !o.includeLockfiles) { out.skip = true; out.reason = "lockfile"; return out; }

  return out;
}

/** Scan options for a file, given how classifyPath labelled it. */
function optionsForFile(cls, base) {
  const o = { ...SCAN_DEFAULTS, ...(base || {}) };
  if (cls.isLockfile) {
    // Integrity hashes make entropy useless here, but a committed registry
    // token is very real — so run the narrow allowlist only.
    return { ...o, entropy: false, patternNames: P.LOCKFILE_SAFE_PATTERN_NAMES };
  }
  return o;
}

/* =========================================================
   Exports
========================================================= */
const SCANNER = {
  SCAN_DEFAULTS, fnv1a, shannonEntropy, findEntropyCandidates, redact,
  scanBlock, scanText, scanPatch, extractStrings, scanBinary,
  classifyPath, optionsForFile, isLfsPointer, lineOffsets, lineIndexAt,
};

if (typeof module !== "undefined") module.exports = SCANNER;
