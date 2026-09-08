"use strict";

/**
 * Scan orchestration — shared by the page and the cron worker.
 *
 * scanRepo() runs up to three passes over one repository:
 *   1. the current tree            (always)
 *   2. git history                 (opts.history)
 *   3. binaries / lockfiles / big  (opts.deep)
 *
 * A history finding whose fingerprint is absent from the current tree is
 * flagged `historical` — a credential deleted in a later commit but still
 * reachable in an old one. That case is the whole point of scanning history,
 * and it is the one people wrongly believe they have fixed.
 */

/* eslint-disable no-undef */
const _node = (typeof module !== "undefined" && typeof require !== "undefined");
const SC = _node ? require("./scanner.js") : SCANNER;
const GHUB = _node ? require("./github.js") : GH;

const ENGINE_DEFAULTS = {
  maxFilesToScan: 1500,
  fileConcurrency: 6,       // the client's own semaphores are the real throttle
  historyConcurrency: 2,
  historyMaxCommits: 100,
  history: false,
  deep: false,
  deepMaxFileSizeBytes: 5 * 1024 * 1024,
};

/** Concurrency-limited map that preserves input order. */
async function runPool(items, worker, concurrency) {
  let cursor = 0;
  const results = new Array(items.length);
  async function next() {
    while (cursor < items.length) {
      const i = cursor++;
      results[i] = await worker(items[i], i);
    }
  }
  await Promise.all(
    Array.from({ length: Math.max(1, Math.min(concurrency, items.length)) }, next)
  );
  return results;
}

/** Turn engine options into the scanner's per-file options. */
function scanOptionsFor(opts) {
  const o = { ...ENGINE_DEFAULTS, ...(opts || {}) };
  return {
    maxFileSizeBytes: o.deep ? o.deepMaxFileSizeBytes : SC.SCAN_DEFAULTS.maxFileSizeBytes,
    includeLockfiles: !!o.deep,
    includeBinaries: !!o.deep,
    entropy: o.entropy !== false,
  };
}

/**
 * What a scan will cost in API calls. Public repos read file bytes from raw
 * (free); private repos need one API call per file, which is worth telling the
 * user before they spend 40% of an hour's budget on one repository.
 */
function estimateCost(fileCount, isPrivate, opts) {
  const o = { ...ENGINE_DEFAULTS, ...(opts || {}) };
  let calls = 1; // tree
  if (isPrivate) calls += fileCount;
  if (o.history) calls += Math.ceil(o.historyMaxCommits / 100) + o.historyMaxCommits;
  return calls;
}

/* =========================================================
   Pass 1 — current tree
========================================================= */
async function scanTree(client, ctx, opts, cb) {
  const o = { ...ENGINE_DEFAULTS, ...(opts || {}) };
  const scanOpts = scanOptionsFor(o);

  const tree = await client.getTree(ctx.owner, ctx.repo, ctx.ref);
  const blobs = (tree.tree || []).filter((e) => e.type === "blob");

  const selected = [];
  let skipped = 0;
  for (const entry of blobs) {
    const cls = SC.classifyPath(entry.path, entry.size || 0, scanOpts);
    if (cls.skip) { skipped++; continue; }
    selected.push({ entry, cls });
  }

  const truncatedByLimit = selected.length > o.maxFilesToScan;
  const files = truncatedByLimit ? selected.slice(0, o.maxFilesToScan) : selected;

  const findings = [];
  let scanned = 0, errors = 0, lfsSkipped = 0;

  await runPool(files, async ({ entry, cls }) => {
    try {
      const wantBytes = cls.isBinary;
      const content = await client.fileContent(ctx, entry, wantBytes);

      let fileFindings;
      if (wantBytes) {
        fileFindings = SC.scanBinary(entry.path, content, scanOpts);
      } else {
        if (SC.isLfsPointer(content)) { lfsSkipped++; return; }
        fileFindings = SC.scanText(entry.path, content, SC.optionsForFile(cls, scanOpts));
      }

      for (const f of fileFindings) {
        findings.push(f);
        if (cb && cb.onFinding) cb.onFinding(f);
      }
    } catch (e) {
      errors++;
      if (e && e.name === "RateLimitError") throw e; // stop, don't grind through
    } finally {
      scanned++;
      if (cb && cb.onProgress) cb.onProgress(scanned, files.length);
    }
  }, o.fileConcurrency);

  return {
    findings,
    filesScanned: scanned - errors,
    filesSkipped: skipped,
    filesTotal: blobs.length,
    fetchErrors: errors,
    lfsSkipped,
    truncatedByGithub: !!tree.truncated,
    truncatedByLimit,
  };
}

/* =========================================================
   Pass 2 — git history
========================================================= */
/**
 * One API call per commit for the diff. GitHub omits `patch` for binary files
 * and very large diffs; for public repos we recover by pulling that file's full
 * body at that commit from raw, which costs no quota (a commit SHA is a valid
 * raw ref).
 */
async function scanHistory(client, ctx, opts, cb) {
  const o = { ...ENGINE_DEFAULTS, ...(opts || {}) };
  const scanOpts = scanOptionsFor(o);

  if (cb && cb.onStatus) cb.onStatus(`Reading commit history for ${ctx.owner}/${ctx.repo}…`);
  const commits = await client.listCommits(ctx.owner, ctx.repo, ctx.ref, o.historyMaxCommits);

  const findings = [];
  let done = 0, errors = 0, patchless = 0;

  await runPool(commits, async (commit) => {
    try {
      const detail = await client.getCommit(ctx.owner, ctx.repo, commit.sha);
      const meta = {
        commit: commit.sha,
        commitShort: commit.sha.slice(0, 7),
        commitDate: (commit.commit && commit.commit.author && commit.commit.author.date) || null,
        author: (commit.commit && commit.commit.author && commit.commit.author.name) || null,
      };

      for (const file of detail.files || []) {
        if (file.status === "removed") continue; // its content lives in an earlier commit
        const cls = SC.classifyPath(file.filename, 0, scanOpts);
        if (cls.skip) continue;

        let fileFindings = [];
        if (file.patch) {
          fileFindings = SC.scanPatch(file.filename, file.patch, SC.optionsForFile(cls, scanOpts));
        } else if (!ctx.private) {
          // No patch (binary or oversized diff) — read the whole file at this
          // commit instead. Free for public repos.
          patchless++;
          try {
            const text = await client.raw(ctx.owner, ctx.repo, commit.sha, file.filename);
            if (!SC.isLfsPointer(text)) {
              fileFindings = SC.scanText(file.filename, text, SC.optionsForFile(cls, scanOpts))
                .map((f) => ({ ...f, source: "history" }));
            }
          } catch { /* file may not exist at that ref; skip quietly */ }
        } else {
          patchless++;
        }

        for (const f of fileFindings) {
          const withMeta = { ...f, ...meta };
          findings.push(withMeta);
          if (cb && cb.onFinding) cb.onFinding(withMeta);
        }
      }
    } catch (e) {
      errors++;
      if (e && e.name === "RateLimitError") throw e;
    } finally {
      done++;
      if (cb && cb.onHistoryProgress) cb.onHistoryProgress(done, commits.length);
    }
  }, o.historyConcurrency);

  return { findings, commitsScanned: done - errors, commitsTotal: commits.length, errors, patchless };
}

/* =========================================================
   Orchestration
========================================================= */
async function scanRepo(client, target, opts, callbacks) {
  const o = { ...ENGINE_DEFAULTS, ...(opts || {}) };
  const cb = callbacks || {};
  const started = Date.now();

  // Resolve just enough metadata. `HEAD` is a valid ref everywhere we use it,
  // so a repo whose visibility and branch we already know costs no extra call.
  let ctx = {
    owner: target.owner,
    repo: target.repo,
    ref: target.ref || target.defaultBranch || "HEAD",
    private: target.private,
  };

  if (ctx.private === undefined) {
    if (cb.onStatus) cb.onStatus(`Looking up ${ctx.owner}/${ctx.repo}…`);
    const meta = await client.getRepo(ctx.owner, ctx.repo);
    ctx.private = !!meta.private;
    if (!target.ref) ctx.ref = meta.default_branch || "HEAD";
    ctx.meta = { stars: meta.stargazers_count, pushedAt: meta.pushed_at, size: meta.size };
  }

  if (cb.onStatus) cb.onStatus(`Scanning ${ctx.owner}/${ctx.repo} on ${ctx.ref}…`);
  const treeResult = await scanTree(client, ctx, o, cb);

  let historyResult = null;
  if (o.history) {
    historyResult = await scanHistory(client, ctx, o, cb);
  }

  // Anything found only in history is a secret someone believes they deleted.
  const inHead = new Set(treeResult.findings.map((f) => f.fp));
  const historyFindings = (historyResult ? historyResult.findings : []).map((f) => ({
    ...f, historical: !inHead.has(f.fp),
  }));

  const all = [...treeResult.findings, ...historyFindings].map((f) => ({
    ...f,
    owner: ctx.owner,
    repo: ctx.repo,
    branch: ctx.ref,
    private: !!ctx.private,
  }));

  return {
    owner: ctx.owner,
    repo: ctx.repo,
    branch: ctx.ref,
    private: !!ctx.private,
    findings: dedupe(all),
    tree: treeResult,
    history: historyResult,
    durationMs: Date.now() - started,
    scannedAt: new Date().toISOString(),
  };
}

/** Same secret, same file, same line, same commit — report it once. */
function dedupe(findings) {
  const seen = new Set();
  const out = [];
  for (const f of findings) {
    const key = `${f.source}|${f.file}|${f.line}|${f.fp}|${f.commit || ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function sortFindings(findings) {
  return findings.slice().sort((a, b) => {
    if (a.historical !== b.historical) return a.historical ? -1 : 1;
    const s = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (s !== 0) return s;
    if (a.file !== b.file) return a.file < b.file ? -1 : 1;
    return a.line - b.line;
  });
}

function countBySeverity(findings) {
  const c = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) if (c[f.severity] !== undefined) c[f.severity]++;
  return c;
}

/** Permalink to the exact line, on the commit when we have one. */
function findingUrl(f) {
  const ref = f.commit || f.branch || "HEAD";
  if (f.binary) return `https://github.com/${f.owner}/${f.repo}/blob/${ref}/${f.file}`;
  return `https://github.com/${f.owner}/${f.repo}/blob/${ref}/${f.file}#L${f.line}`;
}

const ENGINE = {
  ENGINE_DEFAULTS, scanRepo, scanTree, scanHistory, runPool,
  estimateCost, dedupe, sortFindings, countBySeverity, findingUrl,
  scanOptionsFor, SEVERITY_ORDER,
};

if (typeof module !== "undefined") module.exports = ENGINE;
