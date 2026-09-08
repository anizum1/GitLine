"use strict";

/**
 * UI layer. All scanning logic lives in scanner.js / engine.js so the page and
 * the cron worker agree; this file is views, queues and wiring.
 *
 * Rendering rule: anything derived from repository content is written with
 * textContent, never innerHTML. This page displays files from repositories we
 * do not control, so escaping is structural rather than a function call someone
 * has to remember.
 */

/* =========================================================
   State
========================================================= */
const client = new GH.GitHubClient({ onRateLimit: renderRateMeter });

const settings = {
  token: null,
  rememberToken: false,
};

const live = {
  running: false,
  cursor: 0,
  discovered: 0,
  scanned: 0,
  findings: 0,
  startedAt: null,
};

const $ = (id) => document.getElementById(id);

/* =========================================================
   Token
========================================================= */
const TOKEN_KEY = "tripline_token";

function loadToken() {
  let saved = null;
  try { saved = localStorage.getItem(TOKEN_KEY); } catch { /* blocked storage */ }
  if (saved) {
    settings.token = saved;
    settings.rememberToken = true;
    $("token-input").value = saved;
    $("remember-token").checked = true;
    $("advanced-row").classList.remove("hidden");
  }
  client.setToken(settings.token);
}

function syncToken() {
  const value = $("token-input").value.trim() || null;
  settings.token = value;
  settings.rememberToken = $("remember-token").checked;
  client.setToken(value);
  try {
    if (settings.rememberToken && value) localStorage.setItem(TOKEN_KEY, value);
    else localStorage.removeItem(TOKEN_KEY);
  } catch { /* blocked storage — token just stays in memory */ }
}

/* =========================================================
   Rate meter
========================================================= */
function renderRateMeter() {
  const core = client.ledger.get("core");
  const fill = $("rate-fill");
  const value = $("rate-value");
  if (!core || core.limit == null) { value.textContent = client.authenticated ? "—" : "60/hr"; return; }

  const pct = Math.max(0, Math.min(100, (core.remaining / core.limit) * 100));
  fill.style.width = pct + "%";
  fill.className = "meter-fill" + (pct < 10 ? " is-low" : pct < 30 ? " is-mid" : "");
  value.textContent = `${core.remaining}/${core.limit}`;
  $("rate-meter").title =
    `${core.remaining} of ${core.limit} API requests left this hour` +
    (core.resetAt ? ` — resets ${new Date(core.resetAt).toLocaleTimeString()}` : "");
}

function renderQueuePill(text) {
  const pill = $("queue-pill");
  if (!text) { pill.classList.add("hidden"); return; }
  pill.classList.remove("hidden");
  pill.textContent = text;
}

/* =========================================================
   Views
========================================================= */
function showView(name) {
  for (const el of document.querySelectorAll(".view")) el.classList.toggle("is-active", el.id === "view-" + name);
  for (const el of document.querySelectorAll(".tab")) el.classList.toggle("is-active", el.dataset.view === name);
  if (name === "dashboard") refreshDashboard();
  try { history.replaceState(null, "", "#" + name); } catch { /* file:// */ }
}

/* =========================================================
   Repo input parsing
========================================================= */
function parseRepoInput(raw) {
  let input = (raw || "").trim();
  if (!input) throw new Error("Enter a GitHub repository first.");

  input = input.replace(/^git@github\.com:/, "github.com/")
               .replace(/\.git$/, "")
               .replace(/^https?:\/\//, "")
               .replace(/^www\./, "")
               .replace(/^github\.com\//, "")
               .replace(/\/+$/, "");

  const parts = input.split("/").filter(Boolean);
  if (parts.length < 2) {
    throw new Error("That doesn't look like a GitHub repo. Try owner/repository or a full github.com URL.");
  }
  const treeIdx = parts.indexOf("tree");
  return {
    owner: parts[0],
    repo: parts[1],
    ref: treeIdx !== -1 && parts[treeIdx + 1] ? parts.slice(treeIdx + 1).join("/") : undefined,
  };
}

/* =========================================================
   Finding rendering
========================================================= */
const SEVERITY_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };

function findingElement(f) {
  const wrap = document.createElement("div");
  wrap.className = `finding sev-${f.severity}` + (f.historical ? " is-historical" : "");

  const head = document.createElement("div");
  head.className = "finding-head";

  const sev = document.createElement("span");
  sev.className = `sev-tag sev-${f.severity}`;
  sev.textContent = SEVERITY_LABEL[f.severity] || f.severity;
  head.appendChild(sev);

  const name = document.createElement("span");
  name.className = "finding-name";
  name.textContent = f.name;
  head.appendChild(name);

  if (f.historical) {
    const tag = document.createElement("span");
    tag.className = "tag tag-historical";
    tag.textContent = "Removed from HEAD — still in history";
    head.appendChild(tag);
  }
  if (f.binary) {
    const tag = document.createElement("span");
    tag.className = "tag";
    tag.textContent = "In binary";
    head.appendChild(tag);
  }
  if (f.private) {
    const tag = document.createElement("span");
    tag.className = "tag";
    tag.textContent = "Private";
    head.appendChild(tag);
  }
  wrap.appendChild(head);

  const loc = document.createElement("div");
  loc.className = "finding-location";
  const a = document.createElement("a");
  a.href = ENGINE.findingUrl(f);
  a.target = "_blank";
  a.rel = "noopener";
  a.textContent = `${f.owner}/${f.repo} · ${f.file}` + (f.line ? `:${f.line}` : "");
  loc.appendChild(a);
  if (f.commitShort) {
    const c = document.createElement("span");
    c.className = "finding-commit";
    c.textContent = ` @ ${f.commitShort}` + (f.commitDate ? ` · ${f.commitDate.slice(0, 10)}` : "");
    loc.appendChild(c);
  }
  wrap.appendChild(loc);

  // Snippet: textContent throughout — this is other people's file content.
  const snip = document.createElement("div");
  snip.className = "finding-snippet";
  snip.appendChild(document.createTextNode(f.before || ""));
  const match = document.createElement("span");
  match.className = "match";
  match.textContent = f.redacted || "";
  snip.appendChild(match);
  snip.appendChild(document.createTextNode(f.after || ""));
  wrap.appendChild(snip);

  return wrap;
}

function renderSummary(container, findings, note) {
  container.innerHTML = "";
  const counts = ENGINE.countBySeverity(findings);
  const total = findings.length;

  if (total === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = note || "No credential-shaped findings.";
    container.appendChild(empty);
    return;
  }

  const chips = [
    ["Total", total, ""],
    ["Critical", counts.critical, "crit"],
    ["High", counts.high, "high"],
    ["Medium", counts.medium, "med"],
    ["Low", counts.low, "low"],
  ];
  const historical = findings.filter((f) => f.historical).length;
  if (historical) chips.push(["In history only", historical, "hist"]);

  for (const [label, count, cls] of chips) {
    if (label !== "Total" && count === 0) continue;
    const chip = document.createElement("span");
    chip.className = `summary-chip ${cls}`;
    const strong = document.createElement("strong");
    strong.textContent = String(count);
    chip.appendChild(strong);
    chip.appendChild(document.createTextNode(" " + label.toLowerCase()));
    container.appendChild(chip);
  }
}

function showError(el, message) {
  el.textContent = message;
  el.classList.remove("hidden");
}
function clearError(el) {
  el.classList.add("hidden");
  el.textContent = "";
}

/** Persist to IndexedDB, but never let a storage failure break a scan. */
async function persist(result) {
  try {
    await STORE.putFindings(result.findings.map((f) => ({ ...f, scannedAt: result.scannedAt })));
    await STORE.putRepo({
      fullName: `${result.owner}/${result.repo}`,
      owner: result.owner, repo: result.repo,
      private: result.private,
      findings: result.findings.length,
      historical: result.findings.filter((f) => f.historical).length,
      filesScanned: result.tree.filesScanned,
      scannedAt: result.scannedAt,
    });
  } catch { /* private window, blocked storage */ }
}

function scanOptionsFromForm(historyEl, deepEl) {
  return {
    history: historyEl && historyEl.checked,
    deep: deepEl && deepEl.checked,
  };
}

/* =========================================================
   Scan view
========================================================= */
async function runSingleScan(e) {
  e.preventDefault();
  syncToken();
  clearError($("scan-error"));
  $("scan-results").classList.add("hidden");
  $("findings-list").innerHTML = "";
  $("summary-row").innerHTML = "";
  $("cost-note").classList.add("hidden");

  let target;
  try { target = parseRepoInput($("repo-input").value); }
  catch (err) { showError($("scan-error"), err.message); return; }

  const opts = scanOptionsFromForm($("opt-history"), $("opt-deep"));

  $("scan-btn").disabled = true;
  $("scan-btn").textContent = "Scanning…";
  $("scan-status").classList.remove("hidden");
  $("progress-fill").style.width = "0%";
  $("status-count").textContent = "";
  $("status-text").textContent = "Starting…";

  try {
    const result = await ENGINE.scanRepo(client, target, opts, {
      onStatus: (t) => { $("status-text").textContent = t; },
      onProgress: (done, total) => {
        $("progress-fill").style.width = (total ? Math.round((done / total) * 100) : 0) + "%";
        $("status-count").textContent = `${done} / ${total} files`;
      },
      onHistoryProgress: (done, total) => {
        $("status-text").textContent = `Scanning history — commit ${done} of ${total}…`;
      },
    });

    if (result.private) {
      const note = $("cost-note");
      const cost = ENGINE.estimateCost(result.tree.filesScanned, true, opts);
      note.textContent =
        `Private repo: file contents came from the API, not the free raw host — ` +
        `about ${cost} requests for ${result.tree.filesScanned} files.`;
      note.classList.remove("hidden");
    }

    renderSummary($("summary-row"), result.findings,
      `No credential-shaped findings across ${result.tree.filesScanned} scanned files.`);
    const frag = document.createDocumentFragment();
    for (const f of ENGINE.sortFindings(result.findings)) frag.appendChild(findingElement(f));
    $("findings-list").appendChild(frag);

    let msg = `Done — ${result.tree.filesScanned} files scanned`;
    if (result.tree.filesSkipped) msg += `, ${result.tree.filesSkipped} skipped`;
    if (result.tree.lfsSkipped) msg += `, ${result.tree.lfsSkipped} LFS pointers`;
    if (result.tree.fetchErrors) msg += `, ${result.tree.fetchErrors} failed`;
    if (result.history) {
      const n = result.history.commitsScanned;
      msg += ` · ${n} commit${n === 1 ? "" : "s"}`;
    }
    $("status-text").textContent = msg;

    if (result.tree.truncatedByGithub) {
      showError($("scan-error"), "GitHub truncated the file listing for this repo (it's very large) — some files were not scanned.");
    } else if (result.tree.truncatedByLimit) {
      showError($("scan-error"), `More than ${ENGINE.ENGINE_DEFAULTS.maxFilesToScan} scannable files — only the first ${ENGINE.ENGINE_DEFAULTS.maxFilesToScan} were checked.`);
    }

    $("scan-results").classList.remove("hidden");
    await persist(result);
  } catch (err) {
    showError($("scan-error"), err.message || "Something went wrong while scanning.");
    $("scan-status").classList.add("hidden");
  } finally {
    $("scan-btn").disabled = false;
    $("scan-btn").textContent = "Run scan";
    renderRateMeter();
  }
}

/* =========================================================
   Scan queue — shared by Batch and Live
========================================================= */
class ScanQueue {
  constructor({ concurrency = 2, onEvent }) {
    this.items = [];
    this.concurrency = concurrency;
    this.onEvent = onEvent || (() => {});
    this.running = false;
    this.paused = false;
    this.cancelled = false;
    this.active = 0;
    this.done = 0;
    this.findings = [];
  }

  add(targets, opts) {
    for (const t of targets) {
      this.items.push({ target: t, opts, status: "queued", findings: 0, error: null });
    }
    this.onEvent({ type: "added" });
  }

  get pending() { return this.items.filter((i) => i.status === "queued").length; }
  get total() { return this.items.length; }

  async start() {
    if (this.running) return;
    this.running = true;
    this.cancelled = false;
    const workers = Array.from({ length: this.concurrency }, () => this.worker());
    await Promise.all(workers);
    this.running = false;
    this.onEvent({ type: "finished" });
  }

  async worker() {
    for (;;) {
      if (this.cancelled) return;
      while (this.paused && !this.cancelled) await GH.sleep(200);
      const item = this.items.find((i) => i.status === "queued");
      if (!item) return;

      item.status = "scanning";
      this.active++;
      this.onEvent({ type: "item", item });

      try {
        const result = await ENGINE.scanRepo(client, item.target, item.opts, {});
        item.status = "done";
        item.findings = result.findings.length;
        item.result = result;
        this.findings.push(...result.findings);
        await persist(result);
        this.onEvent({ type: "item", item, result });
      } catch (e) {
        item.status = "error";
        item.error = e.message;
        // A rate limit affects every worker, not just this item — hold the queue.
        if (e.name === "RateLimitError") {
          this.paused = true;
          this.onEvent({ type: "ratelimited", message: e.message });
        }
        this.onEvent({ type: "item", item });
      } finally {
        this.active--;
        this.done++;
        renderRateMeter();
      }
    }
  }

  pause() { this.paused = true; this.onEvent({ type: "paused" }); }
  resume() { this.paused = false; this.onEvent({ type: "resumed" }); if (!this.running) this.start(); }
  cancel() { this.cancelled = true; this.paused = false; this.onEvent({ type: "cancelled" }); }
}

/* =========================================================
   Batch view
========================================================= */
let batchQueue = null;

async function runBatch(e) {
  e.preventDefault();
  syncToken();
  clearError($("batch-error"));
  $("batch-queue").innerHTML = "";
  $("batch-findings").innerHTML = "";

  const login = $("batch-input").value.trim().replace(/^@/, "").replace(/\/+$/, "");
  if (!login) { showError($("batch-error"), "Enter a user or organisation."); return; }

  $("batch-btn").disabled = true;
  $("batch-btn").textContent = "Listing…";

  try {
    const me = await client.getAuthenticatedUser();
    const repos = await client.listOwnerRepos(login, {
      authenticatedLogin: me && me.login,
      includeForks: $("batch-forks").checked,
      includeArchived: $("batch-archived").checked,
    });

    if (!repos.length) { showError($("batch-error"), `No scannable repositories found for ${login}.`); return; }

    const privateCount = repos.filter((r) => r.private).length;
    if (privateCount) {
      showError($("batch-error"),
        `${privateCount} of ${repos.length} repos are private — those cost about one API request per file. ` +
        `Watch the meter in the header.`);
    }

    const targets = repos.map((r) => ({
      owner: r.owner.login, repo: r.name,
      private: !!r.private, defaultBranch: r.default_branch || "HEAD",
    }));
    const opts = scanOptionsFromForm($("batch-history"), $("batch-deep"));

    batchQueue = new ScanQueue({ concurrency: 2, onEvent: onBatchEvent });
    batchQueue.add(targets, opts);
    renderBatchQueue();
    $("batch-controls").classList.remove("hidden");
    batchQueue.start();
  } catch (err) {
    showError($("batch-error"), err.message);
  } finally {
    $("batch-btn").disabled = false;
    $("batch-btn").textContent = "Queue all repos";
  }
}

function onBatchEvent(ev) {
  if (ev.type === "ratelimited") showError($("batch-error"), ev.message + " Queue paused — resume when it resets.");
  renderBatchQueue();
  if (ev.type === "item" && ev.result && ev.result.findings.length) {
    const frag = document.createDocumentFragment();
    for (const f of ENGINE.sortFindings(ev.result.findings)) frag.appendChild(findingElement(f));
    $("batch-findings").appendChild(frag);
  }
  if (ev.type === "finished") renderQueuePill(null);
}

function renderBatchQueue() {
  if (!batchQueue) return;
  const q = batchQueue;
  const list = $("batch-queue");
  list.innerHTML = "";

  for (const item of q.items) {
    const row = document.createElement("div");
    row.className = `queue-row is-${item.status}`;

    const name = document.createElement("span");
    name.className = "queue-name";
    name.textContent = `${item.target.owner}/${item.target.repo}`;
    row.appendChild(name);

    const status = document.createElement("span");
    status.className = "queue-status";
    status.textContent = item.status === "done"
      ? (item.findings ? `${item.findings} finding${item.findings === 1 ? "" : "s"}` : "clean")
      : item.status === "error" ? (item.error || "error") : item.status;
    row.appendChild(status);
    list.appendChild(row);
  }

  const doneCount = q.items.filter((i) => i.status === "done" || i.status === "error").length;
  $("batch-progress").textContent = `${doneCount} / ${q.total} repos · ${q.findings.length} findings`;
  $("batch-pause").textContent = q.paused ? "Resume" : "Pause";
  renderQueuePill(doneCount < q.total ? `${doneCount}/${q.total}` : null);
}

/* =========================================================
   Live view — continuous discovery
========================================================= */
let liveQueue = null;

async function toggleLive() {
  if (live.running) { stopLive(); return; }
  syncToken();
  clearError($("live-error"));

  if (!client.authenticated) {
    showError($("live-error"),
      "Without a token this gets 60 API requests an hour, which is barely enough to discover, " +
      "let alone scan. Add a token on the Scan tab for 5,000/hour.");
  }

  live.running = true;
  live.startedAt = Date.now();
  $("live-toggle").textContent = "Stop watching";
  $("live-state").textContent = "Watching";
  $("live-stats").classList.remove("hidden");

  live.cursor = await STORE.getMeta("discoveryCursor", 0).catch(() => 0);
  liveQueue = new ScanQueue({ concurrency: 2, onEvent: onLiveEvent });
  liveLoop();
}

function stopLive() {
  live.running = false;
  if (liveQueue) liveQueue.cancel();
  $("live-toggle").textContent = "Start watching";
  $("live-state").textContent = "Stopped";
  renderQueuePill(null);
}

async function liveLoop() {
  const opts = { history: false, deep: $("live-deep").checked, maxFilesToScan: 300 };

  while (live.running) {
    try {
      // Cold start: begin at the present rather than replaying all of GitHub.
      if (!live.cursor) {
        const probe = await client.listPublicRepositoriesSince(0);
        live.cursor = probe.maxId || 0;
      }

      const page = await client.listPublicRepositoriesSince(live.cursor);
      const returned = page.repos || [];
      const fresh = returned.filter((r) => !r.fork && !r.private);

      // Advance on what GitHub returned, not on what survived filtering: a
      // page that is entirely forks would otherwise stall the cursor and
      // re-fetch the same page forever.
      if (returned.length) {
        live.cursor = page.maxId;
        await STORE.setMeta("discoveryCursor", live.cursor).catch(() => {});
      }

      if (fresh.length) {
        live.discovered += fresh.length;

        liveQueue.add(fresh.map((r) => ({
          owner: r.owner.login, repo: r.name,
          private: false, defaultBranch: r.default_branch || "HEAD",
        })), opts);

        if (!liveQueue.running) liveQueue.start();
      }

      renderLiveStats();
      // Back off when the queue is deep — discovery outruns scanning by orders
      // of magnitude, and queueing more we'll never reach helps nobody.
      const backlog = liveQueue.pending;
      await GH.sleep(backlog > 50 ? 15000 : 4000);
    } catch (e) {
      if (e.name === "RateLimitError") {
        showError($("live-error"), e.message + " Discovery paused until it resets.");
        $("live-state").textContent = "Rate limited";
        await GH.sleep(60000);
        clearError($("live-error"));
        $("live-state").textContent = "Watching";
      } else {
        showError($("live-error"), e.message);
        await GH.sleep(10000);
      }
    }
  }
}

function onLiveEvent(ev) {
  if (ev.type === "item" && ev.item.status === "done") {
    live.scanned++;
    if (ev.result && ev.result.findings.length) {
      live.findings += ev.result.findings.length;
      const frag = document.createDocumentFragment();
      for (const f of ENGINE.sortFindings(ev.result.findings)) frag.appendChild(findingElement(f));
      const feed = $("live-feed");
      feed.insertBefore(frag, feed.firstChild);
      while (feed.childElementCount > 200) feed.removeChild(feed.lastChild);
    }
  }
  if (ev.type === "ratelimited") {
    showError($("live-error"), ev.message);
    $("live-state").textContent = "Rate limited";
  }
  renderLiveStats();
}

function renderLiveStats() {
  const el = $("live-stats");
  const mins = live.startedAt ? Math.max(1, (Date.now() - live.startedAt) / 60000) : 1;
  const pending = liveQueue ? liveQueue.pending : 0;
  const stats = [
    ["Discovered", live.discovered],
    ["Scanned", live.scanned],
    ["Queued", pending],
    ["Findings", live.findings],
    ["Repos/min", (live.scanned / mins).toFixed(1)],
  ];
  el.innerHTML = "";
  for (const [label, value] of stats) {
    const s = document.createElement("div");
    s.className = "stat";
    const v = document.createElement("div");
    v.className = "stat-value";
    v.textContent = String(value);
    const l = document.createElement("div");
    l.className = "stat-label";
    l.textContent = label;
    s.appendChild(v); s.appendChild(l);
    el.appendChild(s);
  }
  renderQueuePill(pending ? `${pending} queued` : null);
}

/* =========================================================
   Dashboard
========================================================= */
let dashTimer = null;
let dashCache = { local: [], worker: null, workerFindings: [] };

async function fetchWorkerData() {
  const bust = `?t=${Date.now()}`;
  try {
    const [s, f] = await Promise.all([
      fetch("./data/summary.json" + bust).then((r) => (r.ok ? r.json() : null)).catch(() => null),
      fetch("./data/findings.json" + bust).then((r) => (r.ok ? r.json() : null)).catch(() => null),
    ]);
    dashCache.worker = s;
    dashCache.workerFindings = (f && f.findings) || [];
  } catch { /* worker has never run, or we're on file:// */ }
}

async function refreshDashboard() {
  await fetchWorkerData();
  try { dashCache.local = await STORE.allFindings(2000); } catch { dashCache.local = []; }

  const seen = new Set();
  const all = [];
  for (const f of [...dashCache.local, ...dashCache.workerFindings]) {
    const key = STORE.findingId(f);
    if (seen.has(key)) continue;
    seen.add(key);
    all.push(f);
  }
  all.sort((a, b) => String(b.scannedAt || "").localeCompare(String(a.scannedAt || "")));

  renderWorkerState();
  renderDashStats(all);
  renderCoverage();
  renderSeverityBars(all);
  renderTopPatterns(all);
  renderDashFindings(all);

  if (!dashTimer) dashTimer = setInterval(refreshDashboard, 60000);
}

function renderWorkerState() {
  const el = $("dash-worker-state");
  const w = dashCache.worker;
  el.innerHTML = "";
  const dot = document.createElement("span");
  const text = document.createElement("span");

  // A seeded but never-run worker has null timestamps; treat that as idle
  // rather than letting Date(null) report a run in 1970.
  if (!w || !(w.lastRunAt || w.generatedAt)) {
    el.className = "worker-state is-idle";
    dot.className = "dot";
    text.textContent =
      "Scheduled worker hasn't published anything yet. Enable the Tripline scan workflow, " +
      "or run it once from the Actions tab, and results will appear here automatically.";
  } else {
    const age = Date.now() - new Date(w.lastRunAt || w.generatedAt).getTime();
    const mins = Math.round(age / 60000);
    const stale = age > 45 * 60 * 1000;
    el.className = "worker-state " + (stale ? "is-stale" : "is-live");
    dot.className = "dot";
    text.textContent =
      `Worker last ran ${mins < 1 ? "just now" : mins + " min ago"}` +
      ` · ${w.runStats ? w.runStats.reposScanned : 0} repos, ${w.runStats ? w.runStats.apiCalls : 0} API calls` +
      (w.lastRunStoppedBecause ? ` · stopped: ${w.lastRunStoppedBecause}` : "") +
      (stale ? " · looks stale" : "");
  }
  el.appendChild(dot);
  el.appendChild(text);
}

function renderDashStats(all) {
  const w = dashCache.worker;
  const historical = all.filter((f) => f.historical).length;
  const repos = new Set(all.map((f) => `${f.owner}/${f.repo}`)).size;

  const stats = [
    ["Findings", all.length],
    ["Repos affected", repos],
    ["In history only", historical],
    ["Repos scanned", w ? w.totals.reposScanned : "—"],
    ["Repos discovered", w ? w.totals.reposDiscovered : "—"],
  ];

  const el = $("dash-stats");
  el.innerHTML = "";
  for (const [label, value] of stats) {
    const s = document.createElement("div");
    s.className = "stat";
    const v = document.createElement("div");
    v.className = "stat-value";
    v.textContent = String(value);
    const l = document.createElement("div");
    l.className = "stat-label";
    l.textContent = label;
    s.appendChild(v); s.appendChild(l);
    el.appendChild(s);
  }
}

/**
 * Discovery and scan coverage are shown separately and deliberately. Every new
 * public repo is enumerated; only a tiny fraction can be scanned. One blended
 * percentage would imply a completeness this does not have.
 */
function renderCoverage() {
  const el = $("dash-coverage");
  const c = dashCache.worker && dashCache.worker.coverage;
  el.innerHTML = "";
  if (!c) { el.classList.add("hidden"); return; }
  el.classList.remove("hidden");

  const mk = (label, value, note) => {
    const d = document.createElement("div");
    d.className = "coverage-item";
    const v = document.createElement("div");
    v.className = "coverage-value";
    v.textContent = value;
    const l = document.createElement("div");
    l.className = "coverage-label";
    l.textContent = label;
    const n = document.createElement("div");
    n.className = "coverage-note";
    n.textContent = note;
    d.appendChild(v); d.appendChild(l); d.appendChild(n);
    return d;
  };

  el.appendChild(mk("Discovery", "Complete",
    "Every new public repo is enumerated in creation order, with no gaps."));
  el.appendChild(mk("Scan coverage", c.scanCoveragePercent + "%",
    `${c.reposScannedLast24h.toLocaleString()} scanned in the last 24h, against roughly ` +
    `${c.estimatedNewPublicReposPerDay.toLocaleString()} new public repos a day.`));
}

function renderSeverityBars(all) {
  const counts = ENGINE.countBySeverity(all);
  const max = Math.max(1, ...Object.values(counts));
  const el = $("dash-severity");
  el.innerHTML = "";
  for (const sev of ["critical", "high", "medium", "low"]) {
    const row = document.createElement("div");
    row.className = "sev-bar-row";
    const label = document.createElement("span");
    label.className = "sev-bar-label";
    label.textContent = SEVERITY_LABEL[sev];
    const track = document.createElement("span");
    track.className = "sev-bar-track";
    const fill = document.createElement("span");
    fill.className = `sev-bar-fill sev-${sev}`;
    fill.style.width = (counts[sev] / max) * 100 + "%";
    track.appendChild(fill);
    const value = document.createElement("span");
    value.className = "sev-bar-value";
    value.textContent = String(counts[sev]);
    row.appendChild(label); row.appendChild(track); row.appendChild(value);
    el.appendChild(row);
  }
}

function renderTopPatterns(all) {
  const byName = {};
  for (const f of all) byName[f.name] = (byName[f.name] || 0) + 1;
  const top = Object.entries(byName).sort((a, b) => b[1] - a[1]).slice(0, 8);

  const el = $("dash-patterns");
  el.innerHTML = "";
  if (!top.length) {
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent = "Nothing found yet.";
    el.appendChild(p);
    return;
  }
  const max = top[0][1];
  for (const [name, count] of top) {
    const row = document.createElement("div");
    row.className = "rank-row";
    const n = document.createElement("span");
    n.className = "rank-name";
    n.textContent = name;
    const track = document.createElement("span");
    track.className = "rank-track";
    const fill = document.createElement("span");
    fill.className = "rank-fill";
    fill.style.width = (count / max) * 100 + "%";
    track.appendChild(fill);
    const c = document.createElement("span");
    c.className = "rank-count";
    c.textContent = String(count);
    row.appendChild(n); row.appendChild(track); row.appendChild(c);
    el.appendChild(row);
  }
}

function renderDashFindings(all) {
  const filter = $("dash-filter").value;
  const shown = (filter ? all.filter((f) => f.severity === filter) : all).slice(0, 200);
  const el = $("dash-findings");
  el.innerHTML = "";
  if (!shown.length) {
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent = "No findings yet. Run a scan, or let the scheduled worker publish some.";
    el.appendChild(p);
    return;
  }
  const frag = document.createDocumentFragment();
  for (const f of shown) frag.appendChild(findingElement(f));
  el.appendChild(frag);
}

async function exportFindings() {
  const all = await STORE.allFindings(5000).catch(() => []);
  // Findings were redacted at detection time, so this file contains no
  // usable credential — only locations and redacted forms.
  const blob = new Blob([JSON.stringify({
    exportedAt: new Date().toISOString(),
    note: "Secrets are redacted. Values shown are partial and non-recoverable.",
    findings: all,
  }, null, 2)], { type: "application/json" });

  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `tripline-findings-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

/* =========================================================
   Wiring
========================================================= */
function init() {
  loadToken();
  renderRateMeter();

  for (const tab of document.querySelectorAll(".tab")) {
    tab.addEventListener("click", () => showView(tab.dataset.view));
  }
  const hash = (location.hash || "").replace("#", "");
  if (["scan", "batch", "live", "dashboard"].includes(hash)) showView(hash);

  $("scan-form").addEventListener("submit", runSingleScan);
  $("toggle-advanced").addEventListener("click", () => $("advanced-row").classList.toggle("hidden"));
  $("token-input").addEventListener("change", syncToken);
  $("remember-token").addEventListener("change", syncToken);

  $("batch-form").addEventListener("submit", runBatch);
  $("batch-pause").addEventListener("click", () => {
    if (!batchQueue) return;
    batchQueue.paused ? batchQueue.resume() : batchQueue.pause();
    renderBatchQueue();
  });
  $("batch-cancel").addEventListener("click", () => {
    if (!batchQueue) return;
    batchQueue.cancel();
    renderBatchQueue();
  });

  $("live-toggle").addEventListener("click", toggleLive);

  $("dash-filter").addEventListener("change", () => refreshDashboard());
  $("dash-export").addEventListener("click", exportFindings);
  $("dash-clear").addEventListener("click", async () => {
    if (!confirm("Clear all findings stored in this browser? The worker's published results are unaffected.")) return;
    await STORE.clearAll().catch(() => {});
    refreshDashboard();
  });

  window.addEventListener("beforeunload", (e) => {
    if (live.running || (batchQueue && batchQueue.running)) {
      e.preventDefault();
      e.returnValue = "";
    }
  });
}

document.addEventListener("DOMContentLoaded", init);
