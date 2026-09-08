"use strict";

/**
 * GitHub API client — shared by the page and the cron worker. No DOM.
 *
 * Call-pattern choices worth knowing (all verified against GitHub's docs):
 *
 *  - Public file bytes come from raw.githubusercontent.com, which costs no API
 *    quota. It has its own unpublished per-IP throttle, though, so it gets a
 *    circuit breaker rather than a quota meter — in practice it, not the
 *    5,000/hr API limit, is what caps scan throughput.
 *  - A token can never be sent to raw.githubusercontent.com from a browser: it
 *    returns 403 to the CORS preflight that any custom header triggers. Private
 *    content therefore goes through the API blob endpoint instead.
 *  - `HEAD` works as a ref for both the tree API and raw, so scanning a repo
 *    needs no separate "what's the default branch" lookup.
 *  - New-repo discovery uses GET /repositories, which enumerates every public
 *    repo in creation order with an id cursor. The events timeline documents
 *    30s-6h latency and a 300-event window, and repo search has no `created`
 *    sort and a 1,000-result cap — neither can enumerate reliably.
 */

const API_ROOT = "https://api.github.com";
const RAW_ROOT = "https://raw.githubusercontent.com";

/**
 * GitHub asks for serial requests and treats 100 concurrent as the ban
 * threshold. api.github.com is HTTP/2, so the browser's old 6-per-host cap does
 * not apply and gives us no free throttling — the limits below are ours.
 */
const NET_DEFAULTS = {
  apiConcurrency: 3,
  apiRatePerSec: 1,        // 3,600/hr, comfortably inside 5,000
  rawConcurrency: 4,
  maxWaitMs: 60000,        // longer waits are surfaced instead of slept through
  maxRetries: 3,
  reserveFraction: 0.1,    // keep 10% so interactive scans never starve
};

/* =========================================================
   Errors
========================================================= */
class RateLimitError extends Error {
  constructor(message, info) {
    super(message);
    this.name = "RateLimitError";
    Object.assign(this, info || {});
  }
}
class NotFoundError extends Error {
  constructor(message) { super(message); this.name = "NotFoundError"; }
}
class AuthError extends Error {
  constructor(message) { super(message); this.name = "AuthError"; }
}

/* =========================================================
   Concurrency + pacing primitives
========================================================= */
class Semaphore {
  constructor(n) { this.free = n; this.waiters = []; }
  acquire() {
    if (this.free > 0) { this.free--; return Promise.resolve(); }
    return new Promise((res) => this.waiters.push(res));
  }
  release() {
    const next = this.waiters.shift();
    if (next) next(); else this.free++;
  }
  async run(fn) {
    await this.acquire();
    try { return await fn(); } finally { this.release(); }
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Simple token bucket, so sustained request rate stays under the limit. */
class Pacer {
  constructor(ratePerSec) { this.interval = 1000 / ratePerSec; this.next = 0; }
  async wait() {
    const now = Date.now();
    const at = Math.max(now, this.next);
    this.next = at + this.interval;
    if (at > now) await sleep(at - now);
  }
}

/* =========================================================
   Rate limit ledger
========================================================= */
/**
 * Tracks each bucket separately — core, search and graphql have independent
 * budgets — refreshed from response headers rather than by polling /rate_limit.
 */
class RateLedger {
  constructor() { this.buckets = Object.create(null); }

  update(headers) {
    const resource = headers.get("x-ratelimit-resource");
    if (!resource) return null;
    const b = {
      resource,
      limit: num(headers.get("x-ratelimit-limit")),
      remaining: num(headers.get("x-ratelimit-remaining")),
      used: num(headers.get("x-ratelimit-used")),
      resetAt: num(headers.get("x-ratelimit-reset")) * 1000 || null,
      at: Date.now(),
    };
    this.buckets[resource] = b;
    return b;
  }

  get(resource) { return this.buckets[resource || "core"] || null; }
  snapshot() { return JSON.parse(JSON.stringify(this.buckets)); }

  /** True when a bucket is into its reserve — background work should yield. */
  inReserve(resource, fraction) {
    const b = this.get(resource);
    if (!b || b.limit == null || b.remaining == null) return false;
    return b.remaining < b.limit * (fraction ?? NET_DEFAULTS.reserveFraction);
  }
}

function num(v) { return v == null ? null : Number(v); }

function parseLink(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(",")) {
    const m = /<([^>]+)>\s*;\s*rel="([^"]+)"/.exec(part.trim());
    if (m) out[m[2]] = m[1];
  }
  return out;
}

/* =========================================================
   Client
========================================================= */
class GitHubClient {
  constructor(opts) {
    const o = { ...NET_DEFAULTS, ...(opts || {}) };
    this.token = o.token || null;
    this.opts = o;
    this.fetch = o.fetchImpl || ((...a) => fetch(...a));
    this.ledger = new RateLedger();
    this.apiSem = new Semaphore(o.apiConcurrency);
    this.rawSem = new Semaphore(o.rawConcurrency);
    this.apiPacer = new Pacer(o.apiRatePerSec);
    this.rawPausedUntil = 0;      // circuit breaker for raw's own throttle
    this.rawBackoffMs = 1000;
    this.onRateLimit = o.onRateLimit || (() => {});
    this.stats = { apiCalls: 0, rawCalls: 0, notModified: 0, rawThrottles: 0 };
  }

  setToken(token) { this.token = token || null; }
  get authenticated() { return !!this.token; }

  headers(extra) {
    const h = { Accept: "application/vnd.github+json", ...(extra || {}) };
    if (this.token) h.Authorization = `Bearer ${this.token}`;
    return h;
  }

  /* ---------- core API request ---------- */
  /**
   * @param opts.etag      sends If-None-Match; a 304 costs no quota when
   *                       authenticated, so poll loops should always pass it
   * @param opts.accept    media type override (e.g. the raw blob type)
   * @param opts.as        "json" | "text" | "bytes"
   */
  async api(pathOrUrl, opts) {
    const o = opts || {};
    const url = pathOrUrl.startsWith("http") ? pathOrUrl : API_ROOT + pathOrUrl;

    for (let attempt = 0; ; attempt++) {
      await this.apiPacer.wait();
      const res = await this.apiSem.run(() => {
        const h = this.headers(o.accept ? { Accept: o.accept } : null);
        if (o.etag) h["If-None-Match"] = o.etag;
        this.stats.apiCalls++;
        return this.fetch(url, { headers: h, method: o.method || "GET" });
      });

      const bucket = this.ledger.update(res.headers);
      if (bucket) this.onRateLimit(this.ledger.snapshot());

      if (res.status === 304) {
        this.stats.notModified++;
        return { notModified: true, status: 304, headers: res.headers, etag: o.etag };
      }

      if (res.ok) {
        const etag = res.headers.get("etag");
        const link = parseLink(res.headers.get("link"));
        let body;
        if (o.as === "bytes") body = new Uint8Array(await res.arrayBuffer());
        else if (o.as === "text") body = await res.text();
        else body = await res.json();
        return { status: res.status, headers: res.headers, etag, link, body };
      }

      // --- error paths
      if (res.status === 404) {
        throw new NotFoundError(
          "Not found. It may be private, misspelled, or removed — private repos need a token with read access."
        );
      }
      if (res.status === 401) {
        throw new AuthError("GitHub rejected the token (401). It may be expired or revoked.");
      }
      if (res.status === 403 || res.status === 429) {
        const wait = this.retryDelay(res, attempt);
        if (attempt < this.opts.maxRetries && wait.ms <= this.opts.maxWaitMs) {
          await sleep(wait.ms);
          continue;
        }
        throw new RateLimitError(wait.message, {
          resource: res.headers.get("x-ratelimit-resource") || "core",
          resetAt: num(res.headers.get("x-ratelimit-reset")) * 1000 || null,
          retryAfterMs: wait.ms,
          secondary: wait.secondary,
        });
      }
      if (res.status >= 500 && attempt < this.opts.maxRetries) {
        await sleep(500 * Math.pow(2, attempt));
        continue;
      }
      throw new Error(`GitHub API returned an unexpected error (${res.status}).`);
    }
  }

  /**
   * Primary and secondary limits look alike but recover differently: a primary
   * limit is out of quota until reset, a secondary one is "slow down" and
   * carries Retry-After.
   */
  retryDelay(res, attempt) {
    const retryAfter = res.headers.get("retry-after");
    const remaining = res.headers.get("x-ratelimit-remaining");
    const reset = num(res.headers.get("x-ratelimit-reset"));

    if (retryAfter) {
      return {
        ms: Number(retryAfter) * 1000,
        secondary: true,
        message: `GitHub applied a secondary rate limit. Retry after ${retryAfter}s.`,
      };
    }
    if (remaining === "0" && reset) {
      const ms = Math.max(0, reset * 1000 - Date.now());
      const at = new Date(reset * 1000).toLocaleTimeString();
      return {
        ms, secondary: false,
        message: this.token
          ? `API rate limit used up (resets ${at}).`
          : `API rate limit used up (resets ${at}). Add a personal access token to raise the limit to 5,000/hour.`,
      };
    }
    return {
      ms: Math.max(60000, 1000 * Math.pow(2, attempt)),
      secondary: true,
      message: "GitHub refused the request (403). If this is a private repo, add a token with read access.",
    };
  }

  /* ---------- raw.githubusercontent.com ---------- */
  /**
   * No headers, ever: any custom header triggers a CORS preflight that this
   * host answers with 403. That also means no auth, so this path is public-only.
   */
  async raw(owner, repo, ref, path, asBytes) {
    const encoded = path.split("/").map(encodeURIComponent).join("/");
    const url = `${RAW_ROOT}/${owner}/${repo}/${encodeURIComponent(ref)}/${encoded}`;

    for (let attempt = 0; ; attempt++) {
      const pause = this.rawPausedUntil - Date.now();
      if (pause > 0) await sleep(Math.min(pause, this.opts.maxWaitMs));

      const res = await this.rawSem.run(() => {
        this.stats.rawCalls++;
        return this.fetch(url);
      });

      if (res.ok) {
        this.rawBackoffMs = 1000; // recovered
        return asBytes ? new Uint8Array(await res.arrayBuffer()) : res.text();
      }
      if (res.status === 429 || res.status === 403) {
        // raw has its own unpublished per-IP throttle; back the whole client off.
        this.stats.rawThrottles++;
        this.rawBackoffMs = Math.min(this.rawBackoffMs * 2, 60000);
        this.rawPausedUntil = Date.now() + this.rawBackoffMs;
        if (attempt < this.opts.maxRetries) continue;
        throw new RateLimitError("raw.githubusercontent.com is throttling this IP.", { raw: true });
      }
      if (res.status === 404) throw new NotFoundError(`File not found: ${path}`);
      throw new Error(`raw fetch failed (${res.status})`);
    }
  }

  /* =========================================================
     Repo metadata and contents
  ========================================================= */
  async getRepo(owner, repo) {
    return (await this.api(`/repos/${owner}/${repo}`)).body;
  }

  /** `HEAD` is a valid ref, so the default-branch lookup is usually skippable. */
  async getTree(owner, repo, ref) {
    const r = await this.api(
      `/repos/${owner}/${repo}/git/trees/${encodeURIComponent(ref || "HEAD")}?recursive=1`
    );
    return r.body;
  }

  /**
   * Public repos read from raw (free); private repos must use the blob API,
   * which costs one call per file — the UI projects that before starting.
   */
  async fileContent(ctx, entry, asBytes) {
    if (!ctx.private) {
      return this.raw(ctx.owner, ctx.repo, ctx.ref, entry.path, asBytes);
    }
    const r = await this.api(
      `/repos/${ctx.owner}/${ctx.repo}/git/blobs/${entry.sha}`,
      { accept: "application/vnd.github.raw+json", as: asBytes ? "bytes" : "text" }
    );
    return r.body;
  }

  /* =========================================================
     Owner enumeration (batch scanning)
  ========================================================= */
  async getAuthenticatedUser() {
    if (!this.token) return null;
    try { return (await this.api("/user")).body; } catch { return null; }
  }

  /**
   * Every repo owned by a user or org. Falls back from /users to /orgs, and
   * uses /user/repos when the login is the authenticated user so private repos
   * are included.
   */
  async listOwnerRepos(login, opts) {
    const o = opts || {};
    const me = o.authenticatedLogin;
    const first = (me && me.toLowerCase() === login.toLowerCase())
      ? "/user/repos?per_page=100&affiliation=owner&visibility=all&sort=pushed"
      : `/users/${encodeURIComponent(login)}/repos?per_page=100&type=owner&sort=pushed`;

    let repos;
    try {
      repos = await this.paginate(first, o.maxRepos);
    } catch (e) {
      if (e instanceof NotFoundError) {
        repos = await this.paginate(
          `/orgs/${encodeURIComponent(login)}/repos?per_page=100&type=all&sort=pushed`, o.maxRepos
        );
      } else throw e;
    }

    return repos.filter((r) => {
      if (!o.includeForks && r.fork) return false;
      if (!o.includeArchived && r.archived) return false;
      if (r.size === 0) return false; // empty repo, nothing to scan
      return true;
    });
  }

  async paginate(startPath, max) {
    const out = [];
    let url = startPath;
    while (url) {
      const r = await this.api(url);
      out.push(...r.body);
      if (max && out.length >= max) return out.slice(0, max);
      url = r.link && r.link.next ? r.link.next : null;
    }
    return out;
  }

  /* =========================================================
     Discovery — every public repo, in creation order
  ========================================================= */
  /**
   * GET /repositories is a gap-free enumeration cursored on repo id, ~100 per
   * call. Tracking the entire public firehose costs roughly 2,500 calls/day.
   */
  async listPublicRepositoriesSince(sinceId, etag) {
    const path = `/repositories?per_page=100${sinceId ? `&since=${sinceId}` : ""}`;
    const r = await this.api(path, { etag });
    if (r.notModified) return { notModified: true, repos: [], etag };
    const repos = r.body || [];
    return {
      repos,
      etag: r.etag,
      maxId: repos.reduce((m, x) => Math.max(m, x.id), sinceId || 0),
    };
  }

  /* =========================================================
     History
  ========================================================= */
  async listCommits(owner, repo, ref, max) {
    const out = [];
    let url = `/repos/${owner}/${repo}/commits?per_page=100${ref ? `&sha=${encodeURIComponent(ref)}` : ""}`;
    while (url && out.length < max) {
      const r = await this.api(url);
      out.push(...r.body);
      url = r.link && r.link.next ? r.link.next : null;
    }
    return out.slice(0, max);
  }

  /**
   * `files[].patch` is optional: GitHub omits it for binary files and very
   * large diffs, and can 5xx outright on huge ones. Callers must cope with a
   * file entry that has no patch.
   */
  async getCommit(owner, repo, sha) {
    return (await this.api(`/repos/${owner}/${repo}/commits/${sha}`)).body;
  }
}

const GH = {
  GitHubClient, RateLedger, Semaphore, Pacer,
  RateLimitError, NotFoundError, AuthError,
  NET_DEFAULTS, API_ROOT, RAW_ROOT, parseLink, sleep,
};

if (typeof module !== "undefined") module.exports = GH;
