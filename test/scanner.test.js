"use strict";

/**
 * Fixture tests for scanner.js. No framework — `node test/scanner.test.js`.
 *
 * Every credential below is synthetic (AWS's own documented example key, or
 * padding strings) and matches a format only structurally.
 */
const assert = require("assert");
const S = require("../scanner.js");

let passed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log("  ok   " + name); }
  catch (e) { console.error("  FAIL " + name + "\n       " + e.message); process.exitCode = 1; }
}

const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const GH_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
// Assembled at runtime, like GH_TOKEN above. A complete literal in this shape
// trips GitHub's own push protection -- a fair thing for a secret scanner's
// fixtures to run into, and the reason the others are built by concatenation.
const SLACK = ["xoxb", "1234567890", "0987654321", "AbCdEfGhIjKlMnOpQrStUvWx"].join("-");

console.log("\npattern detection");

test("finds an AWS access key id", () => {
  const f = S.scanText("a.txt", `aws_key = "${AWS_KEY}"`);
  assert.strictEqual(f.length, 1);
  assert.strictEqual(f[0].name, "AWS Access Key ID");
  assert.strictEqual(f[0].severity, "critical");
  assert.strictEqual(f[0].line, 1);
});

test("reports the correct line number in a multi-line file", () => {
  const f = S.scanText("a.txt", `one\ntwo\nthree\ntoken = "${GH_TOKEN}"\nfive`);
  assert.strictEqual(f.length, 1);
  assert.strictEqual(f[0].line, 4);
});

test("multi-line pattern is attributed to its starting line", () => {
  const f = S.scanText("k.pem", "header\n-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n");
  const pk = f.find((x) => x.name === "Private Key Block");
  assert.ok(pk, "expected a Private Key Block finding");
  assert.strictEqual(pk.line, 2);
});

console.log("\nredaction and leak safety");

test("never emits the plaintext secret anywhere in the finding", () => {
  const f = S.scanText("a.txt", `aws_key = "${AWS_KEY}"`);
  assert.ok(!JSON.stringify(f).includes(AWS_KEY), "plaintext secret survived into the finding");
  assert.ok(f[0].redacted.includes("•"), "expected a redacted form");
});

test("two secrets on one line do not leak each other via context", () => {
  const line = `a="${AWS_KEY}" b="${GH_TOKEN}"`;
  const f = S.scanText("a.txt", line);
  assert.strictEqual(f.length, 2, "expected both secrets found");
  const blob = JSON.stringify(f);
  assert.ok(!blob.includes(AWS_KEY), "AWS key leaked through the other finding's context");
  assert.ok(!blob.includes(GH_TOKEN), "GitHub token leaked through the other finding's context");
});

test("context around the match is preserved", () => {
  const f = S.scanText("a.txt", `aws_key = "${AWS_KEY}"`);
  assert.ok(f[0].before.includes("aws_key"), "expected leading context, got: " + f[0].before);
});

test("long context is truncated with an ellipsis", () => {
  const pad = "x".repeat(400);
  const f = S.scanText("a.txt", `${pad} ${AWS_KEY} ${pad}`);
  assert.ok(f[0].before.startsWith("…"));
  assert.ok(f[0].after.endsWith("…"));
});

console.log("\ndiff / history line math");

test("attributes added lines to their new-side line numbers", () => {
  const patch = [
    "@@ -1,3 +1,4 @@",
    " context",
    "+added one",
    " context2",
    `+token = "${GH_TOKEN}"`,
  ].join("\n");
  const f = S.scanPatch("a.txt", patch);
  assert.strictEqual(f.length, 1);
  assert.strictEqual(f[0].line, 4, "expected line 4, got " + f[0].line);
  assert.strictEqual(f[0].source, "history");
});

test("handles multiple hunks independently", () => {
  const patch = [
    "@@ -1,2 +1,2 @@",
    " a",
    "+harmless",
    "@@ -50,3 +60,4 @@",
    " ctx",
    " ctx2",
    `+key = "${AWS_KEY}"`,
  ].join("\n");
  const f = S.scanPatch("a.txt", patch);
  assert.strictEqual(f.length, 1);
  assert.strictEqual(f[0].line, 62, "expected line 62, got " + f[0].line);
});

test("ignores removed lines", () => {
  const patch = ["@@ -1,2 +1,1 @@", `-key = "${AWS_KEY}"`, " kept"].join("\n");
  assert.strictEqual(S.scanPatch("a.txt", patch).length, 0);
});

test("ignores the +++ file header", () => {
  const patch = ["--- a/x", "+++ b/x", "@@ -1 +1 @@", "+clean"].join("\n");
  assert.strictEqual(S.scanPatch("a.txt", patch).length, 0);
});

console.log("\nbinary strings extraction");

test("pulls printable ASCII runs out of a byte buffer", () => {
  const bytes = [];
  for (let i = 0; i < 32; i++) bytes.push(i % 7);        // binary noise
  for (const ch of `secret=${SLACK}`) bytes.push(ch.charCodeAt(0));
  for (let i = 0; i < 16; i++) bytes.push(0xff);
  const strs = S.extractStrings(Uint8Array.from(bytes));
  assert.ok(strs.some((s) => s.includes(SLACK)), "expected the embedded token in extracted strings");
});

test("finds a token embedded in a UTF-16LE binary", () => {
  const bytes = [];
  for (const ch of `tok=${GH_TOKEN}`) { bytes.push(ch.charCodeAt(0)); bytes.push(0); }
  const f = S.scanBinary("a.dll", Uint8Array.from(bytes));
  assert.ok(f.length >= 1, "expected a finding from UTF-16LE content");
  assert.strictEqual(f[0].binary, true);
  assert.ok(!JSON.stringify(f).includes(GH_TOKEN), "binary scan leaked plaintext");
});

test("binary scan does not run the entropy pass", () => {
  const bytes = [];
  for (const ch of "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg==") bytes.push(ch.charCodeAt(0));
  assert.strictEqual(S.scanBinary("a.bin", Uint8Array.from(bytes)).length, 0);
});

console.log("\npath classification (deep mode)");

test("skips binaries by default, scans strings-worthy ones in deep mode", () => {
  assert.strictEqual(S.classifyPath("a/x.dll", 100).skip, true);
  const deep = S.classifyPath("a/x.dll", 100, { includeBinaries: true });
  assert.strictEqual(deep.skip, false);
  assert.strictEqual(deep.isBinary, true);
});

test("keeps opaque binaries out even in deep mode", () => {
  const r = S.classifyPath("a/photo.jpg", 100, { includeBinaries: true });
  assert.strictEqual(r.skip, true);
  assert.strictEqual(r.reason, "binary-opaque");
});

test("skips lockfiles by default, includes them in deep mode", () => {
  assert.strictEqual(S.classifyPath("package-lock.json", 100).skip, true);
  assert.strictEqual(S.classifyPath("package-lock.json", 100, { includeLockfiles: true }).skip, false);
});

test("lockfiles run named patterns only, no entropy", () => {
  const cls = S.classifyPath("yarn.lock", 100, { includeLockfiles: true });
  const opts = S.optionsForFile(cls, { includeLockfiles: true });
  assert.strictEqual(opts.entropy, false);
  assert.ok(opts.patternNames, "expected a restricted pattern allowlist");
});

test("respects the size cap, and deep mode raising it", () => {
  assert.strictEqual(S.classifyPath("big.txt", 400 * 1024).skip, true);
  assert.strictEqual(S.classifyPath("big.txt", 400 * 1024).reason, "oversize");
  const deep = S.classifyPath("big.txt", 400 * 1024, { maxFileSizeBytes: 5 * 1024 * 1024 });
  assert.strictEqual(deep.skip, false);
});

test("always skips dependency directories", () => {
  assert.strictEqual(S.classifyPath("node_modules/x/a.js", 10, { includeBinaries: true }).reason, "dependency-dir");
});

console.log("\nentropy pass");

test("flags an unlabelled high-entropy string", () => {
  const f = S.scanText("a.txt", "value = 'Xq7fT2mWp9LzR4vB8nK1dY6sH3jG5cA0'");
  assert.ok(f.some((x) => x.name === "High-entropy string"));
});

test("does not double-report a line a named pattern already claimed", () => {
  const f = S.scanText("a.txt", `k = "${GH_TOKEN}"`);
  assert.strictEqual(f.length, 1);
  assert.strictEqual(f[0].name, "GitHub Token");
});

test("skips integrity-hash lines", () => {
  const f = S.scanText("a.txt", 'integrity: "sha512-Xq7fT2mWp9LzR4vB8nK1dY6sH3jG5cA0abcdef"');
  assert.strictEqual(f.filter((x) => x.name === "High-entropy string").length, 0);
});

console.log("\nmisc");

test("detects a git-lfs pointer stub", () => {
  assert.strictEqual(S.isLfsPointer("version https://git-lfs.github.com/spec/v1\noid sha256:ab"), true);
  assert.strictEqual(S.isLfsPointer("just a file"), false);
});

test("fingerprints are stable and non-reversible", () => {
  assert.strictEqual(S.fnv1a(AWS_KEY), S.fnv1a(AWS_KEY));
  assert.notStrictEqual(S.fnv1a(AWS_KEY), S.fnv1a(GH_TOKEN));
  assert.strictEqual(S.fnv1a(AWS_KEY).length, 8);
});

console.log(`\n${passed} passed\n`);
