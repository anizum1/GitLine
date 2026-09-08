"use strict";

/* =========================================================
   Config
========================================================= */
const CONFIG = {
  maxFileSizeBytes: 300 * 1024, // 300 KB
  maxFilesToScan: 1500,
  concurrency: 6,
  entropyBase64Threshold: 4.5,
  entropyHexThreshold: 3.0,
  minCandidateLength: 24,
};

const ENTROPY_SKIP_LINE_HINTS = [
  "sha1", "sha256", "sha512", "commit", "checksum", "integrity",
  "lockfileversion", "resolved", "swagger", "openapi",
];

/* =========================================================
   Repo input parsing
========================================================= */
function parseRepoInput(raw) {
  let input = raw.trim();
  if (!input) throw new Error("Enter a GitHub repository first.");

  input = input.replace(/^git@github\.com:/, "github.com/");
  input = input.replace(/\.git$/, "");
  input = input.replace(/^https?:\/\//, "");
  input = input.replace(/^www\./, "");
  input = input.replace(/^github\.com\//, "");
  input = input.replace(/\/+$/, "");

  const parts = input.split("/").filter(Boolean);
  if (parts.length < 2) {
    throw new Error("That doesn't look like a GitHub repo. Try owner/repository or a full github.com URL.");
  }

  const owner = parts[0];
  const repo = parts[1];
  let branch = null;
  const treeIdx = parts.indexOf("tree");
  if (treeIdx !== -1 && parts[treeIdx + 1]) {
    branch = parts.slice(treeIdx + 1).join("/");
  }
  return { owner, repo, branch };
}

/* =========================================================
   GitHub API
========================================================= */
async function githubFetch(url, token) {
  const headers = { Accept: "application/vnd.github+json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(url, { headers });
  if (!res.ok) {
    if (res.status === 404) {
      throw new Error("Repository not found. It may be private, misspelled, or removed — private repos need a token with read access.");
    }
    if (res.status === 403) {
      const remaining = res.headers.get("x-ratelimit-remaining");
      if (remaining === "0") {
        const reset = res.headers.get("x-ratelimit-reset");
        const resetTime = reset ? new Date(parseInt(reset, 10) * 1000).toLocaleTimeString() : "soon";
        throw new Error(`GitHub's API rate limit is used up (resets ${resetTime}). Add a personal access token above to scan with a higher limit.`);
      }
      throw new Error("GitHub refused the request (403). If this is a private repo, add a token with read access.");
    }
    throw new Error(`GitHub API returned an unexpected error (${res.status}).`);
  }
  return res.json();
}

async function fetchRepoMeta(owner, repo, token) {
  return githubFetch(`https://api.github.com/repos/${owner}/${repo}`, token);
}

async function fetchTree(owner, repo, branch, token) {
  return githubFetch(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
    token
  );
}

async function fetchRawFile(owner, repo, branch, path) {
  const encodedPath = path.split("/").map(encodeURIComponent).join("/");
  const url = `https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(branch)}/${encodedPath}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`fetch failed (${res.status})`);
  return res.text();
}

/* =========================================================
   File filtering
========================================================= */
function shouldSkipPath(path, sizeBytes) {
  if (sizeBytes > CONFIG.maxFileSizeBytes) return true;

  const segments = path.split("/");
  if (segments.some((seg) => SKIP_DIRS.has(seg))) return true;

  if (SKIP_FILENAME_PATTERNS.some((re) => re.test(path))) return true;

  const dot = path.lastIndexOf(".");
  if (dot !== -1) {
    const ext = path.slice(dot + 1).toLowerCase();
    if (SKIP_EXTENSIONS.has(ext)) return true;
  }
  return false;
}

/* =========================================================
   Entropy detection
========================================================= */
function shannonEntropy(str) {
  const freq = {};
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

function findEntropyCandidates(line) {
  const lowerLine = line.toLowerCase();
  if (ENTROPY_SKIP_LINE_HINTS.some((hint) => lowerLine.includes(hint))) return [];

  const results = [];
  const seen = new Set();

  for (const re of [BASE64_CANDIDATE_RE, HEX_CANDIDATE_RE]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(line)) !== null) {
      const candidate = m[0];
      if (candidate.length < CONFIG.minCandidateLength) continue;
      if (UUID_RE.test(candidate)) continue;
      if (REPEATED_CHAR_RE.test(candidate)) continue;
      if (seen.has(candidate)) continue;

      const isHexOnly = /^[0-9a-fA-F]+$/.test(candidate);
      const entropy = shannonEntropy(candidate);
      const threshold = isHexOnly ? CONFIG.entropyHexThreshold : CONFIG.entropyBase64Threshold;

      if (entropy >= threshold) {
        seen.add(candidate);
        results.push({ match: candidate, index: m.index, entropy });
      }
    }
  }
  return results;
}

/* =========================================================
   Scanning a single file's text
========================================================= */
function redact(match) {
  if (match.length <= 10) return match[0] + "•".repeat(Math.max(match.length - 2, 1)) + match[match.length - 1];
  return match.slice(0, 4) + "•".repeat(Math.min(match.length - 8, 24)) + match.slice(-4);
}

function scanFileContent(path, content) {
  const findings = [];
  const lines = content.split("\n");
  const matchedLineIndices = new Set();

  // Named pattern pass
  for (const pattern of SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0;
    let m;
    while ((m = pattern.regex.exec(content)) !== null) {
      const upTo = content.slice(0, m.index);
      const lineNumber = upTo.split("\n").length;
      const lineText = lines[lineNumber - 1] || "";
      matchedLineIndices.add(lineNumber - 1);

      findings.push({
        file: path,
        line: lineNumber,
        name: pattern.name,
        severity: pattern.severity,
        rawLine: lineText,
        matchText: m[0],
        redacted: redact(m[0]),
      });

      if (pattern.regex.lastIndex === m.index) pattern.regex.lastIndex++; // guard against zero-length loops
    }
  }

  // Entropy pass — skip lines already flagged by a named pattern
  lines.forEach((lineText, idx) => {
    if (matchedLineIndices.has(idx)) return;
    if (lineText.length > 2000) return; // skip pathological long lines (minified etc.)

    const candidates = findEntropyCandidates(lineText);
    for (const c of candidates) {
      findings.push({
        file: path,
        line: idx + 1,
        name: "High-entropy string",
        severity: "low",
        rawLine: lineText,
        matchText: c.match,
        redacted: redact(c.match),
      });
    }
  });

  return findings;
}

/* =========================================================
   Concurrency-limited pool
========================================================= */
async function runPool(items, worker, concurrency) {
  let cursor = 0;
  const results = [];
  async function next() {
    while (cursor < items.length) {
      const i = cursor++;
      results[i] = await worker(items[i], i);
    }
  }
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, next);
  await Promise.all(workers);
  return results;
}

/* =========================================================
   Orchestration
========================================================= */
async function runScan({ owner, repo, branch, token }, callbacks) {
  const { onStatus, onFinding, onProgress } = callbacks;

  onStatus(`Looking up ${owner}/${repo}…`);
  const meta = await fetchRepoMeta(owner, repo, token);
  const resolvedBranch = branch || meta.default_branch;

  onStatus(`Reading file tree on ${resolvedBranch}…`);
  const treeData = await fetchTree(owner, repo, resolvedBranch, token);

  const candidates = (treeData.tree || [])
    .filter((entry) => entry.type === "blob")
    .filter((entry) => !shouldSkipPath(entry.path, entry.size || 0));

  const truncatedByGithub = !!treeData.truncated;
  let filesToScan = candidates;
  let truncatedByLimit = false;
  if (filesToScan.length > CONFIG.maxFilesToScan) {
    filesToScan = filesToScan.slice(0, CONFIG.maxFilesToScan);
    truncatedByLimit = true;
  }

  if (filesToScan.length === 0) {
    return {
      owner, repo, branch: resolvedBranch,
      findings: [], filesScanned: 0, filesSkipped: candidates.length,
      truncatedByGithub, truncatedByLimit,
    };
  }

  onStatus(`Scanning ${filesToScan.length} files on ${resolvedBranch}…`);

  let done = 0;
  let fetchErrors = 0;
  const allFindings = [];

  await runPool(filesToScan, async (entry) => {
    try {
      const content = await fetchRawFile(owner, repo, resolvedBranch, entry.path);
      const findings = scanFileContent(entry.path, content);
      for (const f of findings) {
        allFindings.push(f);
        onFinding(f);
      }
    } catch (e) {
      fetchErrors++;
    } finally {
      done++;
      onProgress(done, filesToScan.length);
    }
  }, CONFIG.concurrency);

  return {
    owner, repo, branch: resolvedBranch,
    findings: allFindings,
    filesScanned: filesToScan.length - fetchErrors,
    filesSkipped: candidates.length - filesToScan.length,
    fetchErrors,
    truncatedByGithub,
    truncatedByLimit,
  };
}

/* =========================================================
   UI wiring
========================================================= */
const els = {
  form: document.getElementById("scan-form"),
  repoInput: document.getElementById("repo-input"),
  scanBtn: document.getElementById("scan-btn"),
  toggleAdvanced: document.getElementById("toggle-advanced"),
  advancedRow: document.getElementById("advanced-row"),
  tokenInput: document.getElementById("token-input"),
  rememberToken: document.getElementById("remember-token"),
  statusArea: document.getElementById("status-area"),
  statusText: document.getElementById("status-text"),
  statusCount: document.getElementById("status-count"),
  progressFill: document.getElementById("progress-fill"),
  errorArea: document.getElementById("error-area"),
  resultsArea: document.getElementById("results-area"),
  summaryRow: document.getElementById("summary-row"),
  findingsList: document.getElementById("findings-list"),
};

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const SEVERITY_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };

// Restore a remembered token, if any.
(function restoreToken() {
  const saved = localStorage.getItem("tripline_token");
  if (saved) {
    els.tokenInput.value = saved;
    els.rememberToken.checked = true;
    els.advancedRow.classList.remove("hidden");
  }
})();

els.toggleAdvanced.addEventListener("click", () => {
  els.advancedRow.classList.toggle("hidden");
});

function setStatus(text) {
  els.statusText.textContent = text;
}

function setProgress(done, total) {
  const pct = total ? Math.round((done / total) * 100) : 0;
  els.progressFill.style.width = pct + "%";
  els.statusCount.textContent = `${done} / ${total} files`;
}

function showError(message) {
  els.errorArea.textContent = message;
  els.errorArea.classList.remove("hidden");
}

function clearError() {
  els.errorArea.classList.add("hidden");
  els.errorArea.textContent = "";
}

function escapeHtml(str) {
  return str.replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function renderSnippet(finding) {
  const idx = finding.rawLine.indexOf(finding.matchText);
  if (idx === -1) return escapeHtml(finding.rawLine.trim()).slice(0, 200);
  const before = finding.rawLine.slice(0, idx);
  const after = finding.rawLine.slice(idx + finding.matchText.length);
  return (
    escapeHtml(before) +
    `<span class="match">${escapeHtml(finding.redacted)}</span>` +
    escapeHtml(after)
  );
}

function findingToElement(finding, repoCtx) {
  const wrap = document.createElement("div");
  wrap.className = `finding sev-${finding.severity}`;

  const fileUrl = `https://github.com/${repoCtx.owner}/${repoCtx.repo}/blob/${encodeURIComponent(repoCtx.branch)}/${finding.file}#L${finding.line}`;

  wrap.innerHTML = `
    <div class="finding-head">
      <span class="sev-tag sev-${finding.severity}">${SEVERITY_LABEL[finding.severity]}</span>
      <span class="finding-name">${escapeHtml(finding.name)}</span>
    </div>
    <div class="finding-location">
      <a href="${fileUrl}" target="_blank" rel="noopener">${escapeHtml(finding.file)}:${finding.line}</a>
    </div>
    <div class="finding-snippet">${renderSnippet(finding)}</div>
  `;
  return wrap;
}

function renderSummary(counts, meta) {
  const total = counts.critical + counts.high + counts.medium + counts.low;
  els.summaryRow.innerHTML = "";

  if (total === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.innerHTML = `<span>No credential-shaped findings across ${meta.filesScanned} scanned files.</span>`;
    els.summaryRow.appendChild(empty);
    return;
  }

  const chips = [
    ["Total", total, ""],
    ["Critical", counts.critical, "crit"],
    ["High", counts.high, "high"],
    ["Medium", counts.medium, "med"],
    ["Low", counts.low, "low"],
  ];

  for (const [label, count, cls] of chips) {
    if (label !== "Total" && count === 0) continue;
    const chip = document.createElement("span");
    chip.className = `summary-chip ${cls}`;
    chip.innerHTML = `<strong>${count}</strong> ${label.toLowerCase()}`;
    els.summaryRow.appendChild(chip);
  }
}

els.form.addEventListener("submit", async (e) => {
  e.preventDefault();
  clearError();
  els.resultsArea.classList.add("hidden");
  els.findingsList.innerHTML = "";
  els.summaryRow.innerHTML = "";

  const rawInput = els.repoInput.value;
  const token = els.tokenInput.value.trim() || null;

  if (els.rememberToken.checked && token) {
    localStorage.setItem("tripline_token", token);
  } else if (!els.rememberToken.checked) {
    localStorage.removeItem("tripline_token");
  }

  let parsed;
  try {
    parsed = parseRepoInput(rawInput);
  } catch (err) {
    showError(err.message);
    return;
  }

  els.scanBtn.disabled = true;
  els.scanBtn.textContent = "Scanning…";
  els.statusArea.classList.remove("hidden");
  els.progressFill.style.width = "0%";
  els.statusCount.textContent = "";
  setStatus("Starting…");

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  let repoCtx = { owner: parsed.owner, repo: parsed.repo, branch: parsed.branch };

  try {
    const result = await runScan(
      { ...parsed, token },
      {
        onStatus: setStatus,
        onProgress: setProgress,
        onFinding: (finding) => {
          counts[finding.severity]++;
        },
      }
    );

    repoCtx = { owner: result.owner, repo: result.repo, branch: result.branch };

    // Sort findings by severity, then file, then line, and render once scanning completes
    const sorted = result.findings.slice().sort((a, b) => {
      const sevDiff = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
      if (sevDiff !== 0) return sevDiff;
      if (a.file !== b.file) return a.file < b.file ? -1 : 1;
      return a.line - b.line;
    });

    renderSummary(counts, result);
    for (const finding of sorted) {
      els.findingsList.appendChild(findingToElement(finding, repoCtx));
    }

    let statusMsg = `Done — ${result.filesScanned} files scanned`;
    if (result.filesSkipped) statusMsg += `, ${result.filesSkipped} skipped by size/type`;
    if (result.fetchErrors) statusMsg += `, ${result.fetchErrors} failed to fetch`;
    setStatus(statusMsg);

    if (result.truncatedByGithub) {
      showError("GitHub truncated the file listing for this repo (it's very large) — some files were not scanned.");
    } else if (result.truncatedByLimit) {
      showError(`This repo has more than ${CONFIG.maxFilesToScan} scannable files — only the first ${CONFIG.maxFilesToScan} were checked.`);
    }

    els.resultsArea.classList.remove("hidden");
  } catch (err) {
    showError(err.message || "Something went wrong while scanning.");
    els.statusArea.classList.add("hidden");
  } finally {
    els.scanBtn.disabled = false;
    els.scanBtn.textContent = "Run scan";
  }
});
