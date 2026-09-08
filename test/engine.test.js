"use strict";

/**
 * Engine orchestration tests against a mock client — no network.
 * `node test/engine.test.js`
 */
const assert = require("assert");
const E = require("../engine.js");

let passed = 0;
function test(name, fn) {
  return fn().then(
    () => { passed++; console.log("  ok   " + name); },
    (e) => { console.error("  FAIL " + name + "\n       " + e.message); process.exitCode = 1; }
  );
}

const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const OLD_KEY = "AKIA1234567890ABCDEF";

/** Minimal stand-in for GitHubClient. */
function mockClient({ files = {}, commits = [], commitFiles = {}, isPrivate = false }) {
  return {
    calls: [],
    async getRepo(o, r) {
      this.calls.push("getRepo");
      return { private: isPrivate, default_branch: "main", stargazers_count: 1, size: 10 };
    },
    async getTree(o, r, ref) {
      this.calls.push("getTree:" + ref);
      return {
        truncated: false,
        tree: Object.keys(files).map((path) => ({
          type: "blob", path, sha: "sha-" + path, size: files[path].length,
        })),
      };
    },
    async fileContent(ctx, entry) {
      this.calls.push("fileContent:" + entry.path);
      return files[entry.path];
    },
    async listCommits() { this.calls.push("listCommits"); return commits; },
    async getCommit(o, r, sha) {
      this.calls.push("getCommit:" + sha);
      return { files: commitFiles[sha] || [] };
    },
    async raw(o, r, ref, path) { this.calls.push("raw:" + ref + ":" + path); return files[path] || ""; },
  };
}

const mkCommit = (sha, date) => ({
  sha, commit: { author: { date, name: "Dev" } },
});

(async () => {
console.log("\ntree scanning");

await test("finds a secret on the current tree", async () => {
  const c = mockClient({ files: { "config.js": `const k = "${AWS_KEY}";` } });
  const r = await E.scanRepo(c, { owner: "o", repo: "r" }, {});
  assert.strictEqual(r.findings.length, 1);
  assert.strictEqual(r.findings[0].name, "AWS Access Key ID");
  assert.strictEqual(r.findings[0].owner, "o");
  assert.strictEqual(r.findings[0].source, "tree");
});

await test("skips the repo lookup when visibility and branch are known", async () => {
  const c = mockClient({ files: { "a.js": "clean" } });
  await E.scanRepo(c, { owner: "o", repo: "r", private: false, defaultBranch: "main" }, {});
  assert.ok(!c.calls.includes("getRepo"), "should not have called getRepo: " + c.calls.join(","));
});

await test("uses HEAD as the ref when nothing else is known", async () => {
  const c = mockClient({ files: { "a.js": "clean" } });
  await E.scanRepo(c, { owner: "o", repo: "r", private: false }, {});
  assert.ok(c.calls.includes("getTree:HEAD"), "expected getTree:HEAD, got " + c.calls.join(","));
});

console.log("\nhistory scanning");

await test("flags a secret deleted from HEAD as historical", async () => {
  const c = mockClient({
    files: { "config.js": "const k = process.env.KEY;" },   // clean now
    commits: [mkCommit("abc1234def", "2024-01-01T00:00:00Z")],
    commitFiles: {
      abc1234def: [{
        filename: "config.js", status: "modified",
        patch: `@@ -1,1 +1,1 @@\n+const k = "${OLD_KEY}";`,
      }],
    },
  });
  const r = await E.scanRepo(c, { owner: "o", repo: "r", private: false }, { history: true });
  const hist = r.findings.filter((f) => f.source === "history");
  assert.strictEqual(hist.length, 1, "expected one history finding");
  assert.strictEqual(hist[0].historical, true, "should be flagged historical");
  assert.strictEqual(hist[0].commit, "abc1234def");
  assert.strictEqual(hist[0].commitShort, "abc1234");
  assert.strictEqual(hist[0].author, "Dev");
});

await test("does not flag a still-present secret as historical", async () => {
  const c = mockClient({
    files: { "config.js": `const k = "${AWS_KEY}";` },      // still there
    commits: [mkCommit("abc1234def", "2024-01-01T00:00:00Z")],
    commitFiles: {
      abc1234def: [{
        filename: "config.js", status: "modified",
        patch: `@@ -1,1 +1,1 @@\n+const k = "${AWS_KEY}";`,
      }],
    },
  });
  const r = await E.scanRepo(c, { owner: "o", repo: "r", private: false }, { history: true });
  const hist = r.findings.filter((f) => f.source === "history");
  assert.strictEqual(hist.length, 1);
  assert.strictEqual(hist[0].historical, false, "secret is still in HEAD, not historical");
});

await test("falls back to the full file when a commit has no patch", async () => {
  const c = mockClient({
    files: { "big.js": `key = "${OLD_KEY}"` },
    commits: [mkCommit("deadbeef99", "2024-01-01T00:00:00Z")],
    commitFiles: { deadbeef99: [{ filename: "big.js", status: "modified" }] }, // no patch (oversized diff)
  });
  const r = await E.scanRepo(c, { owner: "o", repo: "r", private: false }, { history: true });
  assert.ok(c.calls.some((x) => x.startsWith("raw:deadbeef99:")), "expected a raw fallback at the commit sha");
  assert.strictEqual(r.history.patchless, 1);
  assert.ok(r.findings.some((f) => f.source === "history"));
});

await test("ignores removed files in history", async () => {
  const c = mockClient({
    files: { "a.js": "clean" },
    commits: [mkCommit("c0ffee1234", "2024-01-01T00:00:00Z")],
    commitFiles: {
      c0ffee1234: [{ filename: "gone.js", status: "removed", patch: `@@ -1,1 +0,0 @@\n-k="${OLD_KEY}"` }],
    },
  });
  const r = await E.scanRepo(c, { owner: "o", repo: "r", private: false }, { history: true });
  assert.strictEqual(r.findings.filter((f) => f.source === "history").length, 0);
});

console.log("\ndeep mode");

await test("ignores lockfiles by default and scans them in deep mode", async () => {
  const files = { "package-lock.json": `{"_authToken": "npm_${"a".repeat(36)}"}` };
  const shallow = await E.scanRepo(mockClient({ files }), { owner: "o", repo: "r", private: false }, {});
  assert.strictEqual(shallow.findings.length, 0);
  const deep = await E.scanRepo(mockClient({ files }), { owner: "o", repo: "r", private: false }, { deep: true });
  assert.ok(deep.findings.length >= 1, "deep mode should scan lockfiles");
});

console.log("\nhelpers");

await test("dedupes identical findings", async () => {
  const f = { source: "tree", file: "a", line: 1, fp: "x" };
  assert.strictEqual(E.dedupe([f, { ...f }, { ...f, line: 2 }]).length, 2);
});

await test("sorts historical findings first, then by severity", async () => {
  const s = E.sortFindings([
    { severity: "low", historical: false, file: "a", line: 1 },
    { severity: "critical", historical: false, file: "a", line: 2 },
    { severity: "medium", historical: true, file: "a", line: 3 },
  ]);
  assert.strictEqual(s[0].historical, true);
  assert.strictEqual(s[1].severity, "critical");
});

await test("links to the commit when a finding is historical", async () => {
  const url = E.findingUrl({ owner: "o", repo: "r", file: "a.js", line: 7, commit: "abc123", branch: "main" });
  assert.strictEqual(url, "https://github.com/o/r/blob/abc123/a.js#L7");
});

await test("estimates cost: public is one call, private is per-file", async () => {
  assert.strictEqual(E.estimateCost(500, false, {}), 1);
  assert.strictEqual(E.estimateCost(500, true, {}), 501);
});

console.log(`\n${passed} passed\n`);
})();
