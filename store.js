"use strict";

/**
 * IndexedDB persistence for the dashboard.
 *
 * Scans accumulate here across reloads so the dashboard has history even
 * before the cron worker's feed is consulted. Findings are already redacted by
 * scanner.js before they ever reach this layer, so nothing stored here is a
 * usable credential.
 *
 * Browser only — the worker keeps its state in data/state.json instead.
 */

const DB_NAME = "tripline";
const DB_VERSION = 1;

const STORE_FINDINGS = "findings";
const STORE_REPOS = "repos";
const STORE_META = "meta";

let _dbPromise = null;

function openDb() {
  if (_dbPromise) return _dbPromise;
  _dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_FINDINGS)) {
        const s = db.createObjectStore(STORE_FINDINGS, { keyPath: "id" });
        s.createIndex("scannedAt", "scannedAt");
        s.createIndex("severity", "severity");
        s.createIndex("owner", "owner");
      }
      if (!db.objectStoreNames.contains(STORE_REPOS)) {
        db.createObjectStore(STORE_REPOS, { keyPath: "fullName" });
      }
      if (!db.objectStoreNames.contains(STORE_META)) {
        db.createObjectStore(STORE_META, { keyPath: "key" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return _dbPromise;
}

function tx(db, storeName, mode) {
  return db.transaction(storeName, mode).objectStore(storeName);
}

function wrap(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

/** Stable across rescans, so re-finding the same secret updates rather than duplicates. */
function findingId(f) {
  return `${f.owner}/${f.repo}|${f.source}|${f.file}|${f.line}|${f.fp}|${f.commit || ""}`;
}

async function putFindings(findings) {
  if (!findings.length) return 0;
  const db = await openDb();
  const t = db.transaction(STORE_FINDINGS, "readwrite");
  const store = t.objectStore(STORE_FINDINGS);
  for (const f of findings) {
    store.put({ ...f, id: findingId(f), scannedAt: f.scannedAt || new Date().toISOString() });
  }
  return new Promise((resolve, reject) => {
    t.oncomplete = () => resolve(findings.length);
    t.onerror = () => reject(t.error);
  });
}

/** Newest first. */
async function allFindings(limit) {
  const db = await openDb();
  const store = tx(db, STORE_FINDINGS, "readonly");
  const idx = store.index("scannedAt");
  return new Promise((resolve, reject) => {
    const out = [];
    const req = idx.openCursor(null, "prev");
    req.onsuccess = () => {
      const cur = req.result;
      if (!cur || (limit && out.length >= limit)) return resolve(out);
      out.push(cur.value);
      cur.continue();
    };
    req.onerror = () => reject(req.error);
  });
}

async function countFindings() {
  const db = await openDb();
  return wrap(tx(db, STORE_FINDINGS, "readonly").count());
}

async function putRepo(record) {
  const db = await openDb();
  return wrap(tx(db, STORE_REPOS, "readwrite").put(record));
}

async function allRepos(limit) {
  const db = await openDb();
  const rows = await wrap(tx(db, STORE_REPOS, "readonly").getAll());
  rows.sort((a, b) => String(b.scannedAt || "").localeCompare(String(a.scannedAt || "")));
  return limit ? rows.slice(0, limit) : rows;
}

async function getMeta(key, fallback) {
  const db = await openDb();
  const row = await wrap(tx(db, STORE_META, "readonly").get(key));
  return row ? row.value : fallback;
}

async function setMeta(key, value) {
  const db = await openDb();
  return wrap(tx(db, STORE_META, "readwrite").put({ key, value }));
}

async function clearAll() {
  const db = await openDb();
  for (const name of [STORE_FINDINGS, STORE_REPOS, STORE_META]) {
    await wrap(db.transaction(name, "readwrite").objectStore(name).clear());
  }
}

/** Best-effort: a private window or blocked site data makes IndexedDB throw. */
async function available() {
  try { await openDb(); return true; } catch { return false; }
}

const STORE = {
  openDb, putFindings, allFindings, countFindings,
  putRepo, allRepos, getMeta, setMeta, clearAll, available, findingId,
};

if (typeof module !== "undefined") module.exports = STORE;
