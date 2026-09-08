# Tripline

A browser-based scanner that checks a public GitHub repository's default
branch for hard-coded credentials — API keys, tokens, private key blocks,
connection strings — plus unlabeled high-entropy strings that look like
secrets even without a recognizable prefix.

It's a static site: no backend, no build step, no server-side code. It runs
entirely in the visitor's browser and talks directly to GitHub's API and to
`raw.githubusercontent.com`. Nothing about the scanned repo is sent anywhere
else.

## How it works

1. You paste a repo (`owner/repo`, a full `github.com/...` URL, or a URL with
   `/tree/<branch>`).
2. The page asks GitHub's API for the repo's default branch and its file
   tree.
3. It filters out binaries, lockfiles, and anything over 300 KB, then fetches
   the remaining files' raw contents directly from
   `raw.githubusercontent.com` (this doesn't count against GitHub's API rate
   limit).
4. Each file is checked against ~20 known credential patterns
   (`patterns.js`) and scanned line-by-line for high-entropy strings that
   don't match a known format.
5. Results render as a findings list with severity, file, line number, a
   redacted snippet, and a link straight to that line on GitHub.

**What it doesn't do:** scan git history (a secret removed in a later commit
can still exist in an old one), scan private repos without a token, or
guarantee a finding is a real, live secret — it's pattern matching, so verify
before you rotate anything.

## Run it locally

No build step — just serve the folder. From this directory:

```bash
python3 -m http.server 8000
# then open http://localhost:8000
```

Or open `index.html` directly in a browser. (Some browsers block `fetch()`
from a `file://` page, so a local server is more reliable.)

## Deploy to GitHub Pages

1. Push this folder to a GitHub repository — either at the repo root, or in
   a `/docs` folder.
2. In the repo, go to **Settings → Pages**.
3. Under **Build and deployment**, set **Source** to "Deploy from a branch."
4. Pick your branch and the folder (`/root` or `/docs`, matching step 1).
5. Save. GitHub will publish the site at
   `https://<your-username>.github.io/<repo-name>/` within a minute or two.

No secrets, API keys, or environment variables are needed for the deploy
itself — the app doesn't have a backend.

## Rate limits

GitHub's unauthenticated API allows 60 requests/hour per IP address, but
each scan only uses **2** of those calls (repo lookup + file tree) — file
contents come from `raw.githubusercontent.com`, which has its own, much more
generous limit. If someone scans many repos in a short window and starts
seeing rate-limit errors, the app has an optional token field: a
[personal access token](https://github.com/settings/tokens) with just
`public_repo` (or no scopes, for public-only use) raises the API limit to
5,000 requests/hour. The token is only ever sent to `api.github.com` from
the visitor's own browser — it's never transmitted anywhere else — and
"Remember on this device" just stores it in that browser's `localStorage`.

## Project structure

```
webapp/
├── index.html      structure and copy
├── style.css       design tokens and layout
├── patterns.js     the credential regex library (shared config, no logic)
└── app.js          GitHub API calls, entropy detection, scan pipeline, UI wiring
```

## Extending the pattern library

Add an entry to `SECRET_PATTERNS` in `patterns.js`:

```js
{ name: "My Service Token", severity: "high", regex: /\bmst_[A-Za-z0-9]{32}\b/g },
```

`severity` must be `"critical"`, `"high"`, `"medium"`, or `"low"` — this
controls both sort order and the color used in the findings list.
