// File-backed local store + remote read-through for verdict records.
//
// Layout is a sharded static-file tree so the SAME shape works everywhere the DB
// might live — a client's ~/.deltagate, a git repo served over GitHub raw, a CDN,
// or an object store. Records are content-addressed by subjectKey; the first two
// hex chars form a shard directory to keep any single directory small:
//
//   <home>/verdicts/<ab>/<abcdef…>.json
//
// A lookup is read-through: local cache first, then (if DELTAGATE_DB_URL is set)
// the public DB, then a miss. Nothing here mutates a shared resource — the remote
// is fetched read-only; publishing to it is the central backend's job (out of
// scope), fed by the JSONL bundles exportBundle() produces.

import { readFileSync, writeFileSync, mkdirSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';
import { subjectKey } from './record.js';

/** Root of the local store: $DELTAGATE_HOME or ~/.deltagate. Read at call time
 *  (not cached) so tests and callers can point it at a scratch dir per run. */
export function homeDir() {
  return process.env.DELTAGATE_HOME || join(homedir(), '.deltagate');
}

/** On-disk path for a record, sharded by the first two hex chars of its key. */
export function localPath(key) {
  return join(homeDir(), 'verdicts', key.slice(0, 2), `${key}.json`);
}

/** Read a cached record by subjectKey, or null if it isn't present/parseable. */
export function getLocal(key) {
  try {
    return JSON.parse(readFileSync(localPath(key), 'utf8'));
  } catch {
    return null; // ENOENT or corrupt file → treat as a cache miss
  }
}

/** Write a record to the local store (creating shard dirs). Returns its path. */
export function putLocal(record) {
  const key = record.subjectKey || subjectKey(record.subject || {});
  const p = localPath(key);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, JSON.stringify(record, null, 2) + '\n');
  return p;
}

/**
 * Read a record from the remote public DB, if one is configured. GETs the same
 * sharded static path against DELTAGATE_DB_URL. Any non-200, network error, or
 * bad JSON is a null (a miss) — never a throw — so a flaky/absent DB degrades to
 * "analyse it yourself" rather than failing the gate.
 * @param {string} key subjectKey
 * @returns {Promise<object|null>}
 */
export async function getRemote(key) {
  const base = process.env.DELTAGATE_DB_URL;
  if (!base) return null;
  const url = `${base.replace(/\/+$/, '')}/${key.slice(0, 2)}/${key}.json`;
  try {
    const res = await fetch(url, { headers: { accept: 'application/json' } });
    if (!res.ok) return null; // 404 (not analysed yet) or any other error
    return await res.json();
  } catch {
    return null;
  }
}

/**
 * The client lookup: local cache → remote public DB → null. This is the
 * "one analysis serves everyone" entry point analyze.js consults before running
 * the engine.
 * @param {object} subject
 * @returns {Promise<object|null>} the cached/published record, or null on a miss
 */
export async function lookup(subject) {
  const key = subjectKey(subject || {});
  return getLocal(key) || (await getRemote(key)) || null;
}

/**
 * Serialise every locally-stored record as JSONL to outPath — the shareable set
 * a client contributes upstream (or a backend publishes as the static tree).
 * @param {string} outPath
 * @returns {number} count of records written
 */
export function exportBundle(outPath) {
  const root = join(homeDir(), 'verdicts');
  const lines = [];
  let shards;
  try { shards = readdirSync(root, { withFileTypes: true }); } catch { shards = []; }
  for (const shard of shards) {
    if (!shard.isDirectory()) continue;
    const shardDir = join(root, shard.name);
    for (const name of readdirSync(shardDir)) {
      if (!name.endsWith('.json')) continue;
      try {
        const rec = JSON.parse(readFileSync(join(shardDir, name), 'utf8'));
        lines.push(JSON.stringify(rec)); // one compact record per line
      } catch { /* skip unreadable shard entry */ }
    }
  }
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, lines.length ? lines.join('\n') + '\n' : '');
  return lines.length;
}

/**
 * Load a JSONL bundle into the local store (the inverse of exportBundle).
 * @param {string} inPath
 * @returns {number} count of records imported
 */
export function importBundle(inPath) {
  const text = readFileSync(inPath, 'utf8');
  let count = 0;
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      putLocal(JSON.parse(trimmed));
      count++;
    } catch { /* skip a malformed line rather than aborting the whole import */ }
  }
  return count;
}

/**
 * Find a stored verdict for a CANDIDATE version, ignoring the installed `from`.
 * The enforcement proxy only knows name + the version being resolved (not what's
 * installed), so it can't build the exact subjectKey — this scans local records
 * for any whose subject targets this (ecosystem, name, to=version), preferring a
 * HOLD. Local-only by design: the candidate-version query needs an index the
 * static remote layout (keyed by full subjectKey) doesn't provide.
 * @returns {object|null}
 */
export function findByCandidate(ecosystem, name, version) {
  const root = join(homeDir(), 'verdicts');
  let shards;
  try { shards = readdirSync(root, { withFileTypes: true }); } catch { return null; }
  let fallback = null;
  for (const shard of shards) {
    if (!shard.isDirectory()) continue;
    const dir = join(root, shard.name);
    let entries;
    try { entries = readdirSync(dir); } catch { continue; }
    for (const fn of entries) {
      if (!fn.endsWith('.json')) continue;
      let rec;
      try { rec = JSON.parse(readFileSync(join(dir, fn), 'utf8')); } catch { continue; }
      const s = rec.subject || {};
      if (s.ecosystem === ecosystem && s.name === name && s.to === version) {
        if (rec.verdict === 'HOLD') return rec;   // most-damning match wins immediately
        fallback = fallback || rec;
      }
    }
  }
  return fallback;
}
