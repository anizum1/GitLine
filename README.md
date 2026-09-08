# Tripline

A scanner that checks GitHub repositories for hard-coded credentials — API keys,
tokens, private key blocks, connection strings — plus unlabelled high-entropy
strings that look like secrets even without a recognisable prefix.

It scans four ways:

| View | What it does |
| --- | --- |
| **Scan** | One repository, optionally including its git history and binaries |
| **Batch** | Every repository a user or organisation owns, queued |
| **Live** | Every newly created public repository on GitHub, as they appear |
| **Dashboard** | Everything found, from the browser and the scheduled worker, auto-refreshing |

The site itself is static — no build step, no bundler, no server. It runs in the
visitor's browser and talks directly to GitHub. A GitHub Actions workflow runs
the same scanner on a schedule so the dashboard keeps filling in when nobody has
the page open.

## What it scans

- Every text file on a branch, up to 300 KB per file
- **Git history** — a secret deleted in a later commit still exists in an older
  one. Findings that are no longer in `HEAD` are flagged *"Removed from HEAD —
  still in history"*, which is the case people most often believe they have fixed
- **Lockfiles, binaries and large files** in deep mode. Binaries go through a
  `strings(1)`-style extractor with an ASCII and a UTF-16LE pass, so keys
  compiled into an executable are still found
- **Private repositories**, with a token that has read access
- ~50 known credential formats (`patterns.js`) and a Shannon-entropy pass for
  unlabelled secrets

## Limits worth knowing

These are real constraints, not to-do items:

- **History is bounded.** It reads the most recent commits (100 by default), not
  back to the first commit. A secret added and removed before that window is not
  found.
- **GitHub omits the diff for very large commits**, and returns none at all for
  binary files. For public repos Tripline recovers by reading the whole file at
  that commit; for private repos those files are skipped.
- **Private repos cost one API request per file.** Public repos read file bytes
  from `raw.githubusercontent.com`, which costs no API quota — but a token can
  never be sent there from a browser, because that host answers the CORS
  preflight with a 403. So private content must go through the API. A 2,000-file
  private repo is roughly 40% of an hourly budget; the header shows a live meter.
- **Compressed and media files are skipped even in deep mode.** Their bytes are
  noise no extractor can read through.
- **Findings are pattern matches, not confirmed leaks.** Verify before rotating,
  and expect false positives from entropy detection — it trades precision for
  not missing the unlabelled cases.

## Secrets are redacted when they're found

`scanner.js` redacts a match at the moment it detects it. A finding carries the
file, the line, a redacted form and a non-reversible fingerprint — never the
plaintext. That holds all the way through: nothing stored in IndexedDB, committed
to `data/`, or exported contains a usable credential.

Two secrets on one line don't leak each other either — every known match on a
line is redacted before the surrounding context is kept.

If you scan repositories you don't own and find something real, report it to the
owner or through GitHub's private vulnerability reporting. Don't publish it.

## Run it locally

No build step — just serve the folder:

```bash
python3 -m http.server 8000
# then open http://localhost:8000
```

Run the tests with Node 18+ (no dependencies, no framework):

```bash
node test/scanner.test.js   # detection, redaction, diff line math, binaries
node test/engine.test.js    # orchestration, historical tagging, deep mode
```

## Continuous scanning

`.github/workflows/scan.yml` runs `worker/run.js` every 15 minutes, commits
redacted results into `data/`, and the dashboard picks them up automatically.

**Setup:**

1. Enable Actions on the repo (Settings → Actions → General).
2. *Optional but recommended:* create a fine-grained PAT with read-only Contents
   access and save it as a repository secret named `TRIPLINE_TOKEN`. Without it
   the workflow uses the built-in `GITHUB_TOKEN`, which is capped at **1,000
   requests/hour per repository** instead of 5,000 — enough to try it out, but it
   will limit how many repos each run gets through.
3. Edit `worker/config.json` to choose what it scans.
4. Run it once manually from the Actions tab (**Tripline scan → Run workflow**)
   before trusting the cron.

**`worker/config.json`:**

```jsonc
{
  "modes": {
    "discovery": true,      // scan newly created public repos
    "watchlist": true       // scan repos owned by the logins below
  },
  "watchlist": ["your-org", "your-username"],

  "budget": {               // per run; the cron fires every 15 minutes
    "maxApiCalls": 700,
    "maxRepos": 40,
    "maxSeconds": 540
  },

  "discoveryScan":  { "history": false, "deep": false, "maxFilesToScan": 300 },
  "watchlistScan":  { "history": true,  "deep": true,  "historyMaxCommits": 100 },

  "publish": {
    "maxFindings": 2000,
    "includePrivate": false // see the warning below
  }
}
```

The worker only rescans a watchlist repo when its `pushed_at` has moved, which
keeps a large watchlist affordable. It writes only when content actually changed,
so the cron doesn't churn git history.

> **`publish.includePrivate` is off for a reason.** `data/` is committed to this
> repository. If this repo is public, publishing private findings would expose
> private file paths and line numbers to the world. Only turn it on if this
> repository is private. Private repos are best scanned from the browser with
> your own token.

**A note on Pages:** pushes authenticated with the built-in `GITHUB_TOKEN`
deliberately do not trigger further workflow runs, which includes the Pages
build. If your dashboard doesn't refresh after a worker commit, set
`TRIPLINE_TOKEN` — the workflow checks out with it, so the resulting commit does
trigger a rebuild.

## How discovery works

Finding every new repository sounds like it needs a firehose. It doesn't:
`GET /repositories` enumerates every public repository **in creation order**
behind an id cursor, ~100 per call. Following all of GitHub costs roughly 2,500
calls/day — about 2% of one authenticated hour.

The two obvious alternatives don't work:

- **The events timeline** (`GET /events`) is documented as having 30s–6h latency
  and a 300-event window. It cannot see most of what is created.
- **Repo search** (`GET /search/repositories?q=created:>…`) has no `created`
  sort option and a hard 1,000-result cap, so its ordering reshuffles under you
  and can't be paged as a stable window.

So **discovery is complete, but scanning is sampled.** GitHub gets roughly
200,000 new public repos a day; a browser tab or a cron job gets a few thousand
API requests an hour. The dashboard therefore reports discovery coverage and scan
coverage as two separate numbers — collapsing them into one would misrepresent
what this actually sees.

## Rate limits

- Unauthenticated: **60 requests/hour**. Enough for a couple of scans.
- With a token: **5,000/hour** (`GITHUB_TOKEN` in Actions: 1,000/hour per repo).
- Search is a separate bucket: 30/min authenticated, 10/min unauthenticated.

Tripline tracks each bucket separately from the `x-ratelimit-resource` response
header and shows `core` in the header meter. It keeps API concurrency at 3 with
about one request per second — GitHub asks for serial requests, and
`api.github.com` is HTTP/2, so the browser's old six-connections-per-host limit
gives no throttling for free.

`raw.githubusercontent.com` has its own separate, unpublished per-IP throttle
that ignores authentication. It gets a circuit breaker rather than a quota meter,
and in practice **it, not the 5,000/hour API limit, is what caps scan throughput.**

## Tokens

Use a **fine-grained personal access token with read-only Contents access**,
scoped to just the repositories you mean to scan. The token is sent only to
`api.github.com`, from your own browser. Leaving "Remember on this device"
unchecked keeps it in the tab only; checking it stores the token in that
browser's `localStorage`.

## Deploy to GitHub Pages

1. Push this folder to a GitHub repository (repo root or `/docs`).
2. Settings → Pages → Build and deployment → Source: "Deploy from a branch".
3. Pick your branch and folder, and save.

No secrets or environment variables are needed for the deploy itself. The
scheduled worker needs `TRIPLINE_TOKEN` to be useful, but the site works without
it.

## Project structure

```
index.html      four views: Scan, Batch, Live, Dashboard
style.css       design tokens and layout
patterns.js     credential regex library and skip/deep lists   shared
scanner.js      detection, redaction, diffs, binaries          shared, pure
github.js       API client, rate limits, pagination            shared
engine.js       scanRepo() over tree, history and deep passes  shared
store.js        IndexedDB persistence                          browser
app.js          views, queues, live polling                    browser
worker/run.js   cron entry: discover, scan, publish            Node
data/*.json     what the worker publishes; the dashboard reads it
test/           fixture tests, no framework
```

`patterns.js`, `scanner.js`, `github.js` and `engine.js` are written to run
unchanged in both a browser `<script>` tag and Node's `require`, so the page and
the worker can never disagree about what counts as a finding.

## Extending the pattern library

Add an entry to `SECRET_PATTERNS` in `patterns.js`:

```js
{ name: "My Service Token", severity: "high", regex: /\bmst_[A-Za-z0-9]{32}\b/g },
```

`severity` must be `"critical"`, `"high"`, `"medium"` or `"low"` — it drives both
sort order and colour. If the pattern is also meaningful inside lockfiles, add
its name to `LOCKFILE_SAFE_PATTERN_NAMES`.
