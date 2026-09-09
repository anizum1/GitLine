#!/usr/bin/env node
"use strict";

/**
 * Gitline cron worker.
 *
 * Runs on a schedule in GitHub Actions, scans what it can inside a fixed
 * budget, and writes JSON into data/ for the static dashboard to read. No
 * dependencies and no build step — Node 18+ only, for its global fetch.
 *
 *   node worker/run.js [--dry-run] [--once] [--owner <login>]
 *
 * Two things it deliberately will not do:
 *
 *  - Publish findings from private repositories. data/ is committed to a public
 *    repo, so publishing them would expose private file paths and line numbers
 *    to the world. Set publish.includePrivate only if this repo is private.
 *  - Publish plaintext secrets. Findings are redacted by scanner.js at
 *    detection time, so there is no plaintext here to leak in the first place.
 */

const fs = require("fs");
const path = require("path");

const GH = require("../github.js");
const E = require("../engine.js");

const ROOT = path.resolve(__dirname, "..");
const DATA_DIR = path.join(ROOT, "data");
const CONFIG_PATH = path.join(__dirname, "config.json");

/**
 * GitHub's Octoverse 2025 puts new repositories at ~331k/day across public and
 * private. The public share is the honest denominator for coverage, and it is
 * a range, not a number — so the dashboard shows it as one.
 */
const EST_NEW_PUBLIC_REPOS_PER_DAY = 200000;

const args = process.argv.slice(2);
const DRY_RUN = args.includes("--dry-run");
const ownerFlag = args.indexOf("--owner");
const ONLY_OWNER = ownerFlag !== -1 ? args[ownerFlag + 1] : null;

/* =========================================================
   Small helpers
========================================================= */
function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); }
  catch { return fallback; }
}

/** Write only when the content actually changed, so cron runs don't churn git. */
function writeJsonIfChanged(file, value) {
  const next = JSON.stringify(value, null, 2) + "\n";
  let prev = null;
  try { prev = fs.readFileSync(file, "utf8"); } catch { /* new file */ }
  if (prev === next) return false;
  if (DRY_RUN) { console.log(`  [dry-run] would write ${path.relative(ROOT, file)} (${next.length} bytes)`); return true; }
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, next);
  return true;
}

const nowIso = () => new Date().toISOString();

function log(...a) { console.log(...a); }

/* =========================================================
   Budget
========================================================= */
class Budget {
  constructor(client, limits) {
    this.client = client;
    this.limits = limits;
    this.startedAt = Date.now();
    this.startCalls = client.stats.apiCalls;
    this.repos = 0;
  }
  get callsUsed() { return this.client.stats.apiCalls - this.startCalls; }
  get secondsUsed() { return (Date.now() - this.startedAt) / 1000; }
  /** Why we stopped, or null to keep going. */
  exhausted() {
    if (this.callsUsed >= this.limits.maxApiCalls) return "api-call budget";
    if (this.repos >= this.limits.maxRepos) return "repo budget";
    if (this.secondsUsed >= this.limits.maxSeconds) return "time budget";
    // Leave GitHub's own reserve alone so an interactive scan isn't starved.
    if (this.client.ledger.inReserve("core")) return "approaching GitHub's rate limit";
    return null;
  }
}

/* =========================================================
   Target selection
========================================================= */
/**
 * Newly created public repos. GET /repositories enumerates every public repo in
 * creation order behind an id cursor, so this is gap-free — unlike the events
 * timeline (30s-6h latency, 300-event window) or repo search (no `created`
 * sort, 1,000-result cap), neither of which can enumerate reliably.
 */
async function discoverNew(client, state, budget) {
  const out = [];
  let cursor = state.discoveryCursor || 0;

  // Cold start: begin near the present rather than replaying all of GitHub.
  if (!cursor) {
    const probe = await client.listPublicRepositoriesSince(0);
    cursor = probe.maxId || 0;
    log(`  cold start — discovery cursor set to ${cursor}`);
  }

  while (!budget.exhausted() && out.length < budget.limits.maxRepos * 3) {
    const page = await client.listPublicRepositoriesSince(cursor, state.discoveryEtag);
    if (page.notModified || !page.repos.length) break;

    for (const r of page.repos) {
      if (r.fork || r.private) continue;
      out.push({
        owner: r.owner.login, repo: r.name, id: r.id,
        private: false, defaultBranch: r.default_branch || "HEAD",
        discoveredAt: nowIso(),
      });
    }
    cursor = page.maxId;
    state.discoveryEtag = page.etag;
    if (page.repos.length < 100) break;
  }

  state.discoveryCursor = cursor;
  state.totals.discovered = (state.totals.discovered || 0) + out.length;
  return out;
}

/**
 * Watchlist owners. Only rescans a repo when its pushed_at moved, which keeps
 * a large watchlist affordable.
 */
async function watchlistTargets(client, config, state, budget) {
  const out = [];
  const owners = ONLY_OWNER ? [ONLY_OWNER] : (config.watchlist || []);
  const me = await client.getAuthenticatedUser();

  for (const login of owners) {
    if (budget.exhausted()) break;
    let repos;
    try {
      repos = await client.listOwnerRepos(login, {
        authenticatedLogin: me && me.login,
        includeForks: false,
        includeArchived: false,
      });
    } catch (e) {
      log(`  ! watchlist ${login}: ${e.message}`);
      continue;
    }

    for (const r of repos) {
      const key = r.full_name;
      const prev = state.watchlist[key];
      if (prev && prev.lastPushedAt === r.pushed_at) continue; // unchanged
      out.push({
        owner: r.owner.login, repo: r.name,
        private: !!r.private, defaultBranch: r.default_branch || "HEAD",
        pushedAt: r.pushed_at, watchlist: true,
      });
    }
  }
  return out;
}

/* =========================================================
   Publishing
========================================================= */
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

function publishableFindings(findings, config) {
  const minRank = SEV_RANK[config.publish.minSeverity] ?? 3;
  return findings.filter((f) => {
    if (f.private && !config.publish.includePrivate) return false;
    return (SEV_RANK[f.severity] ?? 3) <= minRank;
  });
}

function buildSummary(state, findings, recentRepos, client, runInfo) {
  const severity = E.countBySeverity(findings);
  const byPattern = {};
  const byOwner = {};
  for (const f of findings) {
    byPattern[f.name] = (byPattern[f.name] || 0) + 1;
    byOwner[f.owner] = (byOwner[f.owner] || 0) + 1;
  }
  const top = (obj, n) => Object.entries(obj)
    .sort((a, b) => b[1] - a[1]).slice(0, n).map(([k, v]) => ({ name: k, count: v }));

  const scanned24h = state.totals.reposScanned24h || 0;

  return {
    generatedAt: nowIso(),
    lastRunAt: runInfo.finishedAt,
    lastRunStoppedBecause: runInfo.stoppedBecause,
    totals: {
      reposScanned: state.totals.reposScanned || 0,
      reposDiscovered: state.totals.discovered || 0,
      findings: findings.length,
      historical: findings.filter((f) => f.historical).length,
    },
    severity,
    // Discovery and scan coverage are deliberately separate numbers.
    // Enumerating every new public repo is cheap; scanning them is not, and
    // blending the two into one figure would misrepresent what this sees.
    coverage: {
      discoveryComplete: true,
      discoveryNote: "Every new public repo is enumerated in creation order.",
      reposScannedLast24h: scanned24h,
      estimatedNewPublicReposPerDay: EST_NEW_PUBLIC_REPOS_PER_DAY,
      scanCoveragePercent: Number(((scanned24h / EST_NEW_PUBLIC_REPOS_PER_DAY) * 100).toFixed(4)),
    },
    topPatterns: top(byPattern, 10),
    topOwners: top(byOwner, 10),
    recentRepos: recentRepos.slice(0, 100),
    rateLimit: client.ledger.snapshot(),
    runStats: runInfo.stats,
  };
}

/* =========================================================
   Main
========================================================= */
async function main() {
  const config = readJson(CONFIG_PATH, null);
  if (!config) { console.error("Cannot read worker/config.json"); process.exit(1); }

  // TRIPLINE_TOKEN is the pre-rename name, still honoured so an existing
  // Actions secret keeps working. GITHUB_TOKEN is the Actions default.
  const token =
    process.env.GITLINE_TOKEN || process.env.TRIPLINE_TOKEN || process.env.GITHUB_TOKEN || null;
  if (!token) {
    log("! No token (GITLINE_TOKEN or GITHUB_TOKEN). Falling back to 60 requests/hour.");
  }

  const client = new GH.GitHubClient({ token });
  const budget = new Budget(client, config.budget);

  const state = readJson(path.join(DATA_DIR, "state.json"), {
    discoveryCursor: 0, discoveryEtag: null, watchlist: {}, totals: {},
  });
  state.watchlist = state.watchlist || {};
  state.totals = state.totals || {};

  const existing = readJson(path.join(DATA_DIR, "findings.json"), { findings: [] });
  const knownKeys = new Set(existing.findings.map((f) => `${f.owner}/${f.repo}|${f.fp}|${f.file}|${f.line}`));

  log(`Gitline worker — ${nowIso()}${DRY_RUN ? " (dry run)" : ""}`);
  log(`  auth: ${token ? "token" : "anonymous"}`);

  /* ---- pick targets ---- */
  const targets = [];
  let selectionStopped = null;

  // A rate limit while picking targets must not lose the run: fall through and
  // publish whatever this run (and previous ones) already produced.
  try {
    if (config.modes.watchlist || ONLY_OWNER) {
      const w = await watchlistTargets(client, config, state, budget);
      log(`  watchlist: ${w.length} repo(s) changed since last run`);
      targets.push(...w);
    }
    if (config.modes.discovery && !ONLY_OWNER) {
      const d = await discoverNew(client, state, budget);
      log(`  discovery: ${d.length} newly created public repo(s)`);
      targets.push(...d);
    }
  } catch (e) {
    if (e.name !== "RateLimitError") throw e;
    selectionStopped = e.message;
    log(`  ! target selection stopped: ${e.message}`);
  }

  /* ---- scan ---- */
  const newFindings = [];
  const recentRepos = [];
  let stoppedBecause = selectionStopped;

  for (const target of targets) {
    if (stoppedBecause) break;
    stoppedBecause = budget.exhausted();
    if (stoppedBecause) { log(`  stopping: ${stoppedBecause}`); break; }

    const scanOpts = target.watchlist ? config.watchlistScan : config.discoveryScan;
    try {
      const result = await E.scanRepo(client, target, scanOpts, {});
      budget.repos++;
      state.totals.reposScanned = (state.totals.reposScanned || 0) + 1;

      const fresh = result.findings.filter(
        (f) => !knownKeys.has(`${f.owner}/${f.repo}|${f.fp}|${f.file}|${f.line}`)
      ).map((f) => ({ ...f, scannedAt: result.scannedAt }));

      newFindings.push(...fresh);
      recentRepos.push({
        fullName: `${target.owner}/${target.repo}`,
        private: !!result.private,
        findings: result.findings.length,
        historical: result.findings.filter((f) => f.historical).length,
        filesScanned: result.tree.filesScanned,
        scannedAt: result.scannedAt,
        watchlist: !!target.watchlist,
      });

      if (target.watchlist) {
        state.watchlist[`${target.owner}/${target.repo}`] = {
          lastScannedAt: result.scannedAt, lastPushedAt: target.pushedAt || null,
        };
      }
      if (result.findings.length) {
        log(`  ${target.owner}/${target.repo}: ${result.findings.length} finding(s)`);
      }
    } catch (e) {
      if (e.name === "RateLimitError") { stoppedBecause = e.message; log(`  stopping: ${e.message}`); break; }
      log(`  ! ${target.owner}/${target.repo}: ${e.message}`);
    }
  }

  /* ---- publish ---- */
  const publishable = publishableFindings(newFindings, config);
  const withheld = newFindings.length - publishable.length;

  const merged = [...publishable, ...existing.findings]
    .sort((a, b) => String(b.scannedAt || "").localeCompare(String(a.scannedAt || "")))
    .slice(0, config.publish.maxFindings);

  // Rolling 24h window, so the coverage figure means what it says.
  const cutoff = Date.now() - 24 * 3600 * 1000;
  state.scanLog = (state.scanLog || []).filter((e) => e.t >= cutoff);
  if (budget.repos) state.scanLog.push({ t: Date.now(), n: budget.repos });
  state.totals.reposScanned24h = state.scanLog.reduce((a, e) => a + e.n, 0);
  state.lastRunAt = nowIso();

  const runInfo = {
    finishedAt: nowIso(),
    stoppedBecause,
    stats: {
      reposScanned: budget.repos,
      apiCalls: budget.callsUsed,
      rawCalls: client.stats.rawCalls,
      rawThrottles: client.stats.rawThrottles,
      notModified: client.stats.notModified,
      seconds: Math.round(budget.secondsUsed),
      newFindings: publishable.length,
      findingsWithheldPrivate: withheld,
    },
  };

  const wroteFindings = writeJsonIfChanged(
    path.join(DATA_DIR, "findings.json"),
    { generatedAt: nowIso(), count: merged.length, findings: merged }
  );
  const wroteSummary = writeJsonIfChanged(
    path.join(DATA_DIR, "summary.json"),
    buildSummary(state, merged, recentRepos, client, runInfo)
  );
  const wroteState = writeJsonIfChanged(path.join(DATA_DIR, "state.json"), state);

  log(`\n  repos scanned: ${budget.repos}`);
  log(`  api calls: ${budget.callsUsed} | raw: ${client.stats.rawCalls} (${client.stats.rawThrottles} throttled)`);
  log(`  new findings: ${publishable.length}${withheld ? ` (${withheld} withheld: private)` : ""}`);
  log(`  wrote: ${[wroteFindings && "findings", wroteSummary && "summary", wroteState && "state"].filter(Boolean).join(", ") || "nothing (no change)"}`);

  if (!wroteFindings && !wroteSummary && !wroteState) process.exitCode = 0;
}

main().catch((e) => {
  if (e && e.name === "AuthError") {
    console.error(
      "\nWorker failed: " + e.message +
      "\nSet a valid GITLINE_TOKEN secret, or unset it to run anonymously at 60 requests/hour."
    );
    process.exit(1);
  }
  console.error("Worker failed:", e);
  process.exit(1);
});
