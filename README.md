# Gitline

A scanner that checks GitHub repositories for hard-coded credentials — API keys,
tokens, private key blocks, connection strings — plus unlabelled high-entropy
strings that look like secrets even without a recognisable prefix.

It runs on your own machine, in your own browser. There is no build step, no
bundler, no backend and no dependencies: `serve.js` hands the folder to your
browser, and every scan happens in that tab, talking straight to GitHub. Nothing
about the repositories you scan is uploaded anywhere, and your token never
leaves your browser.

---

## Quick start

You need **Node 18 or newer** and nothing else.

```bash
git clone https://github.com/anizum1/tripline.git gitline
cd gitline
node serve.js
```

Then open **<http://localhost:9292>**.

(The GitHub repository is still called `tripline` — only the tool was renamed,
so the clone URL above is correct.)

The server binds every interface, so it prints your LAN address too — open that
from a phone or another laptop on the same network:

```
  Gitline — serving /home/you/gitline

  Local     http://localhost:9292
  Network   http://192.168.1.24:9292

  Bound to every interface — anyone on this network can open it.
  Use --host 127.0.0.1 to keep it to this machine.

  Ctrl-C to stop.
```

Options:

```bash
node serve.js --port 8080         # different port
node serve.js --host 127.0.0.1    # this machine only, not the network
PORT=8080 node serve.js           # same thing via the environment
node serve.js --help
```

If you prefer npm scripts: `npm start` (port 9292, network) or `npm run serve`
(localhost only). There are no packages to install — `npm install` has nothing
to do.

---

## Running it on Kali Linux

Kali doesn't ship Node by default. One command fixes that:

```bash
sudo apt update
sudo apt install -y nodejs npm
node -v          # must print v18 or higher
```

If Kali's repo gives you something older than v18 (rare on rolling, possible on
an old image), install a current Node instead:

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

Then start it as usual:

```bash
cd gitline
node serve.js
```

**Opening the port.** Kali ships `ufw` inactive; if you have turned it on, let
the port through before trying to reach it from another machine:

```bash
sudo ufw status                   # check whether it's active at all
sudo ufw allow 9292/tcp           # only if it is
```

Find the address other machines should use:

```bash
ip -4 addr show | grep inet        # or just read the banner serve.js prints
```

**No Node at all?** Kali always has Python, and the site is fully static, so
this works for the browser side of Gitline:

```bash
python3 -m http.server 9292 --bind 0.0.0.0
```

Everything in the page — Scan, Batch, Live, Dashboard — works under that. Only
the scheduled worker (`worker/run.js`) genuinely needs Node, and only because it
uses `fetch`. `serve.js` is still worth having: it refuses to serve `.git/`,
which `http.server` will happily hand out.

**Offline or air-gapped?** The page pulls its webfont from Google Fonts; if
that's blocked it falls back to system fonts and everything still works.
Scanning obviously needs to reach `api.github.com`.

**Leaving it running on a lab box.** A systemd unit, if you want it up after a
reboot — save as `/etc/systemd/system/gitline.service`:

```ini
[Unit]
Description=Gitline secret scanner
After=network.target

[Service]
ExecStart=/usr/bin/node /opt/gitline/serve.js
WorkingDirectory=/opt/gitline
Restart=on-failure
User=kali

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now gitline
sudo systemctl status gitline
```

---

## Running it with Docker

No Node on the host, no install:

```bash
docker build -t gitline .
docker run --rm -p 9292:9292 gitline
```

Open <http://localhost:9292>. To reach it from elsewhere on the network, publish
on all interfaces explicitly: `docker run --rm -p 0.0.0.0:9292:9292 gitline`.

The container serves files and nothing more — the scanning, and your token, stay
in the browser.

---

## Giving it a token

Gitline works with no token at all, but GitHub only allows **60 requests/hour**
anonymously, which is a couple of small scans. A token raises that to
**5,000/hour** and is the single biggest thing you can do for scan throughput.
It is also the only way to scan **private** repositories.

### 1. Create the token

1. GitHub → **Settings** → **Developer settings** → **Personal access tokens** →
   **Fine-grained tokens** → **Generate new token**.
2. **Repository access:** *Only select repositories* — pick just the ones you
   mean to scan. (Choose *All repositories* only if you're scanning your whole
   account.)
3. **Permissions:** under *Repository permissions*, set **Contents** to
   **Read-only**. Nothing else is needed. Metadata is added automatically.
4. Set a short expiry and generate. Copy the `github_pat_…` value — GitHub shows
   it once.

A classic token (`ghp_…`) with the `repo` scope also works, but it is far
broader than this needs. Prefer fine-grained.

### 2. Give it to the browser

On the **Scan** view, click **"Private repo, or hitting rate limits? Add a
token"**, and paste it in.

- Leave **"Remember on this device"** unchecked and the token lives in that tab
  only — closing the tab forgets it.
- Check it and the token is saved in that browser's `localStorage`, so it
  survives a reload. Only do that on a machine you control.
- The token is sent **only to `api.github.com`**, directly from your browser. It
  never reaches `serve.js`, which is why running Gitline on a shared machine
  still doesn't share your token — but a browser that has *remembered* one holds
  it for whoever next uses that browser profile.

The **API meter** in the header shows what you have left in the current hour,
live, from GitHub's own response headers.

The token applies to every view — Scan, Batch and Live all use it.

### 3. Give it to the worker (optional)

The scheduled scanner reads it from the environment:

```bash
GITLINE_TOKEN=github_pat_xxx node worker/run.js
```

Or in GitHub Actions, as a repository secret named `GITLINE_TOKEN` — see
[Continuous scanning](#continuous-scanning).

> **One thing a token will not fix.** Public file contents are read from
> `raw.githubusercontent.com`, which has its own unpublished per-IP throttle
> that ignores authentication entirely. In practice that, not the 5,000/hour API
> budget, is what caps how fast big scans go. Gitline puts a circuit breaker on
> it and keeps going.

---

## Exposing it on your network

`serve.js` binds `0.0.0.0` on purpose — that's what makes "open it from my
phone" work. Be deliberate about it:

- **There is no authentication.** Anyone who can reach the port can open the
  page and run scans.
- Scans they run cost **their** browser's rate limit, not yours — unless they
  land on a browser profile where you checked "Remember on this device", in
  which case they are using your token. Don't do that on a shared machine.
- `serve.js` refuses any path starting with a dot, so `.git/` is not served.
  That matters: a repo's git history is exactly the kind of thing this tool is
  built to find secrets in.
- On an untrusted network, run `node serve.js --host 127.0.0.1` and use an SSH
  tunnel instead: `ssh -L 9292:localhost:9292 you@box`.

---

## Using it

Four views, all from the same scanner:

| View | What it does |
| --- | --- |
| **Scan** | One repository, optionally including its git history and binaries |
| **Batch** | Every repository a user or organisation owns, queued |
| **Live** | Every newly created public repository on GitHub, as they appear |
| **Dashboard** | Everything found, from the browser and the scheduled worker, auto-refreshing |

Paste a repo as `github.com/owner/repository` or just `owner/repository`. Two
checkboxes change what gets read:

- **Scan git history** — reads recent commits, so a secret deleted in a later
  commit is still found. Costs roughly one API call per commit.
- **Deep scan** — adds lockfiles, binaries and large files.

Results stay in your browser (IndexedDB) and show up on the Dashboard, where
**Export JSON** saves them and **Clear local** wipes them.

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
  binary files. For public repos Gitline recovers by reading the whole file at
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

## Tests

Node 18+, no dependencies, no framework:

```bash
npm test
# or individually:
node test/scanner.test.js   # detection, redaction, diff line math, binaries
node test/engine.test.js    # orchestration, historical tagging, deep mode
```

---

## Continuous scanning

The scanner also runs headless, so the Dashboard keeps filling in when nobody
has the page open. Run it by hand:

```bash
GITLINE_TOKEN=github_pat_xxx node worker/run.js
node worker/run.js --dry-run          # scan, print, write nothing
node worker/run.js --owner some-org   # just this owner
```

It writes redacted results into `data/`, which the Dashboard reads on its own.

**On a schedule (your fork):** `.github/workflows/scan.yml` runs it every 15
minutes and commits what it finds.

1. Enable Actions on your fork (Settings → Actions → General).
2. *Optional but recommended:* create a fine-grained PAT with read-only Contents
   access and save it as a repository secret named `GITLINE_TOKEN`. Without it
   the workflow uses the built-in `GITHUB_TOKEN`, which is capped at **1,000
   requests/hour per repository** instead of 5,000 — enough to try it out, but it
   will limit how many repos each run gets through.
3. Edit `worker/config.json` to choose what it scans.
4. Run it once manually from the Actions tab (**Gitline scan → Run workflow**)
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

Most people want `discovery: false` and their own logins in `watchlist` — that
scans what you own instead of sampling all of GitHub.

The worker only rescans a watchlist repo when its `pushed_at` has moved, which
keeps a large watchlist affordable. It writes only when content actually changed,
so the cron doesn't churn git history.

> **`publish.includePrivate` is off for a reason.** `data/` is committed to your
> repository. If that repository is public, publishing private findings would
> expose private file paths and line numbers to the world. Only turn it on if
> your repository is private. Private repos are best scanned from the browser
> with your own token.

**A note on Pages:** pushes authenticated with the built-in `GITHUB_TOKEN`
deliberately do not trigger further workflow runs, which includes the Pages
build. If your dashboard doesn't refresh after a worker commit, set
`GITLINE_TOKEN` — the workflow checks out with it, so the resulting commit does
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

Gitline tracks each bucket separately from the `x-ratelimit-resource` response
header and shows `core` in the header meter. It keeps API concurrency at 3 with
about one request per second — GitHub asks for serial requests, and
`api.github.com` is HTTP/2, so the browser's old six-connections-per-host limit
gives no throttling for free.

`raw.githubusercontent.com` has its own separate, unpublished per-IP throttle
that ignores authentication. It gets a circuit breaker rather than a quota meter,
and in practice **it, not the 5,000/hour API limit, is what caps scan throughput.**

## Deploy to GitHub Pages

Local is the primary way to run this, but the site is static, so Pages works:

1. Push this folder to a GitHub repository (repo root or `/docs`).
2. Settings → Pages → Build and deployment → Source: "Deploy from a branch".
3. Pick your branch and folder, and save.

No secrets or environment variables are needed for the deploy itself. The
scheduled worker needs `GITLINE_TOKEN` to be useful, but the site works without
it. Remember that a Pages deployment is public: anyone can open it, and each
visitor supplies their own token.

## Project structure

```
serve.js        local server, port 9292, binds the network          Node
package.json    npm start / npm test / npm run scan
Dockerfile      container image, no host Node needed
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

## Licence

MIT — see [LICENSE](LICENSE).

Scan what you own, or what you have permission to scan. Findings from other
people's repositories go to the owner or through GitHub's private vulnerability
reporting, not into a public post.
