#!/usr/bin/env node
/**
 * Gitline local server.
 *
 * Serves this folder over HTTP so you can open Gitline from any machine on
 * your network. There is no build step and no dependencies — the site is
 * static, and every scan runs in the browser that loads it.
 *
 *   node serve.js                 # http://0.0.0.0:9292
 *   node serve.js --port 8080
 *   node serve.js --host 127.0.0.1    # this machine only
 *   PORT=8080 node serve.js
 *
 * It binds 0.0.0.0 by default, which means anyone who can reach this machine
 * can open the page. That is the point — but see "Exposing it on a network"
 * in README.md before running it somewhere untrusted.
 */

"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");
const os = require("os");

const ROOT = __dirname;

/* ---------------------------------------------------------- arguments */
const args = process.argv.slice(2);

function flag(name, fallback) {
  const i = args.indexOf(name);
  return i !== -1 && args[i + 1] ? args[i + 1] : fallback;
}

if (args.includes("--help") || args.includes("-h")) {
  console.log(
    "Gitline local server\n\n" +
      "  node serve.js [--port <n>] [--host <addr>]\n\n" +
      "  --port  port to listen on         (default 9292, or $PORT)\n" +
      "  --host  address to bind           (default 0.0.0.0, or $HOST)\n" +
      "          0.0.0.0   reachable from your network\n" +
      "          127.0.0.1 this machine only\n"
  );
  process.exit(0);
}

const PORT = Number(flag("--port", process.env.PORT || 9292));
const HOST = flag("--host", process.env.HOST || "0.0.0.0");

if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  console.error(`Not a usable port: ${flag("--port", process.env.PORT)}`);
  process.exit(1);
}

/* ---------------------------------------------------------- mime types */
const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".map": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".md": "text/plain; charset=utf-8",
};

/* ---------------------------------------------------------- resolution */
/**
 * Map a request path to a file inside ROOT, or null if it escapes the folder
 * or reaches for something we never serve. Rejecting dot-prefixed segments
 * keeps .git/ — which holds every credential this repo's own history ever
 * touched — off the network.
 */
function resolve(urlPath) {
  let decoded;
  try {
    decoded = decodeURIComponent(urlPath.split("?")[0].split("#")[0]);
  } catch {
    return null; // malformed percent-encoding
  }

  if (decoded.endsWith("/")) decoded += "index.html";
  if (decoded === "") decoded = "/index.html";

  const segments = decoded.split("/").filter(Boolean);
  if (segments.some((s) => s.startsWith("."))) return null;

  const file = path.resolve(ROOT, ...segments);
  if (file !== ROOT && !file.startsWith(ROOT + path.sep)) return null;
  return file;
}

/* ---------------------------------------------------------- server */
const server = http.createServer((req, res) => {
  const send = (status, body, headers = {}) => {
    res.writeHead(status, {
      "Content-Length": Buffer.byteLength(body),
      "X-Content-Type-Options": "nosniff",
      ...headers,
    });
    res.end(req.method === "HEAD" ? undefined : body);
  };

  if (req.method !== "GET" && req.method !== "HEAD") {
    return send(405, "Method not allowed\n", {
      "Content-Type": "text/plain; charset=utf-8",
      Allow: "GET, HEAD",
    });
  }

  const file = resolve(req.url || "/");
  if (!file) return send(403, "Forbidden\n", { "Content-Type": "text/plain; charset=utf-8" });

  fs.readFile(file, (err, body) => {
    if (err) {
      return send(404, "Not found\n", { "Content-Type": "text/plain; charset=utf-8" });
    }
    const ext = path.extname(file).toLowerCase();
    // data/ is rewritten by the worker while the dashboard is open, and the
    // page adds its own cache-buster — but say so explicitly anyway.
    const inData = file.startsWith(path.join(ROOT, "data") + path.sep);
    send(200, body, {
      "Content-Type": TYPES[ext] || "application/octet-stream",
      "Cache-Control": inData ? "no-store" : "no-cache",
    });
  });
});

server.on("error", (err) => {
  if (err.code === "EADDRINUSE") {
    console.error(
      `Port ${PORT} is already in use.\n` +
        `Something else is on it — stop that, or pick another port:\n\n` +
        `  node serve.js --port 9393\n`
    );
  } else if (err.code === "EACCES") {
    console.error(`Not allowed to bind ${HOST}:${PORT}. Ports below 1024 need root.`);
  } else {
    console.error(err.message);
  }
  process.exit(1);
});

/* ---------------------------------------------------------- addresses */
function lanAddresses() {
  const out = [];
  for (const entries of Object.values(os.networkInterfaces())) {
    for (const e of entries || []) {
      if (e.family === "IPv4" && !e.internal) out.push(e.address);
    }
  }
  return out;
}

server.listen(PORT, HOST, () => {
  const bound = HOST === "0.0.0.0" || HOST === "::";
  console.log(`\n  Gitline — serving ${ROOT}\n`);
  console.log(`  Local     http://localhost:${PORT}`);
  if (bound) {
    for (const addr of lanAddresses()) console.log(`  Network   http://${addr}:${PORT}`);
    console.log(`\n  Bound to every interface — anyone on this network can open it.`);
    console.log(`  Use --host 127.0.0.1 to keep it to this machine.`);
  } else {
    console.log(`\n  Bound to ${HOST} only.`);
  }
  console.log(`\n  Ctrl-C to stop.\n`);
});

for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => {
    console.log("\nStopped.");
    server.close(() => process.exit(0));
    // Don't hang on a client holding a connection open.
    setTimeout(() => process.exit(0), 500).unref();
  });
}
