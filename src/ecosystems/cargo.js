// Cargo (crates.io) adapter.
//
// Fetch: crates.io serves each release as a ".crate" file — a gzipped tar whose
// entries are nested under "{name}-{version}/". We resolve the version and its
// sha256 from the JSON API, then download from the CDN (no rate limit) and verify:
//   metadata:  https://crates.io/api/v1/crates/{name}            (crate.max_stable_version, versions[].checksum)
//              https://crates.io/api/v1/crates/{name}/{version}  (version.checksum, version.num)
//   download:  https://static.crates.io/crates/{name}/{name}-{version}.crate
// The API `checksum` is the sha256 (hex) of the .crate bytes; we verify it.
// crates.io requires a descriptive User-Agent or it returns 403.
//
// manifestRules — Cargo build/compile-time execution signals:
//   • build.rs new/modified  — a build script runs arbitrary code at build time (hard cap)
//   • proc-macro crate       — proc-macros run arbitrary code in the compiler of every dependent
//   • new non-registry dep   — a git/path dependency in Cargo.toml pulls code from outside the registry

import { createHash } from 'node:crypto';
import { unpackTarGz } from '../unpack.js';

const UA = 'deltagate (supply-chain update gate; https://github.com/reactivezero/deltagate)';

async function getJson(url) {
  const res = await fetch(url, { headers: { accept: 'application/json', 'user-agent': UA } });
  if (!res.ok) throw new Error(`crates.io ${res.status} for ${url}`);
  return res.json();
}

function sha256hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

// A .crate nests everything under a single "{name}-{version}/" directory. Strip
// that common top-level dir so paths line up across versions (otherwise every
// file reads as added+removed and the diff is meaningless).
function stripCommonTopDir(files) {
  const tops = new Set([...files.keys()].map((p) => p.split('/')[0]));
  if (tops.size !== 1) return files;
  const prefix = [...tops][0] + '/';
  const out = new Map();
  for (const [p, b] of files) out.set(p.startsWith(prefix) ? p.slice(prefix.length) : p, b);
  return out;
}

export default {
  name: 'cargo',

  async fetch(name, version) {
    let resolvedVersion = version;
    let checksum = null;

    if (version && version !== 'latest') {
      const meta = await getJson(`https://crates.io/api/v1/crates/${encodeURIComponent(name)}/${encodeURIComponent(version)}`);
      resolvedVersion = meta.version?.num || version;
      checksum = meta.version?.checksum || null;
    } else {
      const meta = await getJson(`https://crates.io/api/v1/crates/${encodeURIComponent(name)}`);
      resolvedVersion = meta.crate?.max_stable_version || meta.crate?.newest_version || meta.crate?.max_version;
      if (!resolvedVersion) throw new Error(`could not resolve latest version for crate ${name}`);
      checksum = (meta.versions || []).find((v) => v.num === resolvedVersion)?.checksum || null;
    }

    const dl = `https://static.crates.io/crates/${encodeURIComponent(name)}/${encodeURIComponent(name)}-${encodeURIComponent(resolvedVersion)}.crate`;
    const res = await fetch(dl, { headers: { 'user-agent': UA } });
    if (!res.ok) throw new Error(`crate download ${res.status} for ${name}@${resolvedVersion}`);
    const bytes = Buffer.from(await res.arrayBuffer());

    const got = sha256hex(bytes);
    if (checksum && got !== checksum) throw new Error(`crate checksum mismatch for ${name}@${resolvedVersion}`);

    return { bytes, digest: 'sha256:' + got, resolvedVersion, files: stripCommonTopDir(unpackTarGz(bytes)) };
  },

  manifestRules,
};

// ── manifest rules ────────────────────────────────────────────────────────────
function cap(code, capValue, severity, title, evidence) {
  return { code, cap: capValue, severity, title, evidence };
}
function trunc(s, n = 100) { s = String(s); return s.length > n ? s.slice(0, n) + '…' : s; }
const isBuildRs = (p) => p === 'build.rs' || p.endsWith('/build.rs');
const isCargoToml = (p) => p === 'Cargo.toml' || p.endsWith('/Cargo.toml');
const textOf = (profiles, path) => { const p = profiles.get(path); return p && p.text != null ? p.text : null; };

// A crate is a proc-macro when its [lib] table sets proc-macro = true.
function isProcMacro(text) {
  if (text == null) return false;
  return /\bproc[-_]macro\s*=\s*true/.test(text);
}

// git/path dependency references in a Cargo.toml (no TOML dep — line scan with
// section tracking so we only flag inside *dependencies tables or inline dep specs).
function nonRegistryRefs(text) {
  if (text == null) return [];
  const hits = new Set();
  let section = '';
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;
    const h = line.match(/^\[([^\]]+)\]/);
    if (h) { section = h[1]; continue; }
    const inDep = /dependencies/i.test(section);
    // inline dep: `foo = { git = "..." }` / `{ path = "..." }`
    const inline = line.match(/=\s*\{[^}]*\b(git|path)\s*=\s*["']([^"']+)["']/);
    if (inline) { hits.add(trunc(line)); continue; }
    // table dep: under [dependencies.foo] a `git = "..."` / `path = "..."` line
    if (inDep && /^\s*(git|path)\s*=\s*["']/.test(line)) hits.add(trunc(`${section}: ${line}`));
  }
  return [...hits];
}

function manifestRules(fromP, toP, d) {
  const findings = [];
  const add = (f) => findings.push(f);
  const changed = [...d.added, ...d.modified];

  // ── build.rs: arbitrary code at build time ────────────────────────────────
  for (const path of changed) {
    if (!isBuildRs(path)) continue;
    if (d.added.includes(path)) {
      add(cap('BUILD_RS_NEW', 15, 'critical',
        'new build.rs runs arbitrary code at build time',
        [{ file: path, detail: 'build-time code execution' }]));
    } else {
      add(cap('BUILD_RS_MODIFIED', 20, 'high',
        'build.rs changed — build-time code path modified',
        [{ file: path, detail: 'build-time code execution' }]));
    }
  }

  // ── proc-macro: runs in the compiler of every dependent ───────────────────
  for (const path of changed) {
    if (!isCargoToml(path)) continue;
    if (isProcMacro(textOf(toP, path)) && !isProcMacro(textOf(fromP, path))) {
      add(cap('PROC_MACRO_NEW', 20, 'high',
        'crate is now a proc-macro — its code runs inside the compiler of every dependent',
        [{ file: path, detail: 'proc-macro = true' }]));
    }
  }

  // ── new non-registry (git/path) deps ──────────────────────────────────────
  for (const path of changed) {
    if (!isCargoToml(path)) continue;
    const toRefs = nonRegistryRefs(textOf(toP, path));
    if (!toRefs.length) continue;
    const fromRefs = new Set(nonRegistryRefs(textOf(fromP, path)));
    for (const ref of toRefs) {
      if (fromRefs.has(ref)) continue;
      add(cap('NON_REGISTRY_DEP', 15, 'high',
        'dependency resolves outside crates.io — code pulled from a git/path source',
        [{ file: path, detail: ref }]));
    }
  }

  return findings;
}
