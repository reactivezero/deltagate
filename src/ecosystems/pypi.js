// PyPI adapter.
//
// Fetch: the PyPI JSON API (https://pypi.org/pypi/{name}[/{version}]/json) returns
// an `info.version` plus a `urls` array. Each url entry carries `packagetype`
// ('bdist_wheel' | 'sdist'), a fully-qualified `url`, and `digests.sha256`. We pull
// BOTH the built wheel (a ZIP) and the sdist (a .tar.gz — occasionally a .zip),
// verify each download's sha256 against the API digest, unpack each, and MERGE the
// two into one file map.
//   docs: https://docs.pypi.org/api/json/
//
// Merge scheme: wheel entries are kept at their natural paths; sdist entries are
// re-rooted under an "sdist/" prefix (after stripping the sdist's own
// "{name}-{version}/" top-level dir). This guarantees the two never collide, keeps
// every real path readable, and — because manifestRules matches on basename — still
// lets us find setup.py / pyproject.toml (sdist) and .pth files (wheel).
//
// manifestRules — PyPI install-time execution signals:
//   • setup.py new/modified          — runs arbitrary code when an sdist installs
//   • setup.py with cmdclass         — custom build/install commands
//   • new .pth file                  — executes on *every* interpreter start (the
//                                      LiteLLM vector); capped hard
//   • pyproject build-backend change — the backend runs arbitrary build code
//   • new non-registry dep           — direct URL / git reference (PEP 508)

import { createHash } from 'node:crypto';
import { unpackZip, unpackTarGz } from '../unpack.js';

const UA = 'deltagate (supply-chain update gate)';

async function getJson(url) {
  const res = await fetch(url, { headers: { accept: 'application/json', 'user-agent': UA } });
  if (!res.ok) throw new Error(`PyPI ${res.status} for ${url}`);
  return res.json();
}

async function download(url) {
  const res = await fetch(url, { headers: { 'user-agent': UA } });
  if (!res.ok) throw new Error(`PyPI download ${res.status} for ${url}`);
  return Buffer.from(await res.arrayBuffer());
}

function sha256hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

// Strip a shared leading "root/" directory (sdists nest everything under
// "{name}-{version}/"), then re-root under an "sdist/" prefix.
function rerootSdist(files) {
  const keys = [...files.keys()];
  let root = null;
  for (const k of keys) {
    const seg = k.indexOf('/') >= 0 ? k.slice(0, k.indexOf('/') + 1) : null;
    if (!seg) { root = null; break; }
    if (root === null) root = seg;
    else if (root !== seg) { root = null; break; }
  }
  const out = new Map();
  for (const [k, v] of files) {
    const stripped = root && k.startsWith(root) ? k.slice(root.length) : k;
    out.set('sdist/' + stripped, v);
  }
  return out;
}

export default {
  name: 'pypi',

  /**
   * @returns {{bytes:Buffer, digest:string, resolvedVersion:string, files:Map<string,Buffer>}}
   */
  async fetch(name, version) {
    const base = 'https://pypi.org/pypi/' + encodeURIComponent(name);
    const url = version && version !== 'latest'
      ? `${base}/${encodeURIComponent(version)}/json`
      : `${base}/json`;
    const meta = await getJson(url);
    const resolvedVersion = meta.info?.version;
    const urls = meta.urls || [];
    if (!resolvedVersion || !urls.length) throw new Error(`no release files for ${name}@${version || 'latest'}`);

    const wheelMeta = urls.find((u) => u.packagetype === 'bdist_wheel');
    const sdistMeta = urls.find((u) => u.packagetype === 'sdist');
    if (!wheelMeta && !sdistMeta) throw new Error(`no wheel or sdist for ${name}@${resolvedVersion}`);

    const files = new Map();
    let primaryBytes = null;

    if (wheelMeta) {
      const bytes = await download(wheelMeta.url);
      const want = wheelMeta.digests?.sha256;
      if (want && sha256hex(bytes) !== want) throw new Error(`wheel sha256 mismatch for ${name}@${resolvedVersion}`);
      primaryBytes = bytes; // the wheel is what actually gets installed
      for (const [k, v] of unpackZip(bytes)) files.set(k, v);
    }

    if (sdistMeta) {
      const bytes = await download(sdistMeta.url);
      const want = sdistMeta.digests?.sha256;
      if (want && sha256hex(bytes) !== want) throw new Error(`sdist sha256 mismatch for ${name}@${resolvedVersion}`);
      if (!primaryBytes) primaryBytes = bytes;
      const fn = (sdistMeta.filename || '').toLowerCase();
      // sdists are almost always .tar.gz; very old ones are .zip.
      const inner = fn.endsWith('.zip') ? unpackZip(bytes) : unpackTarGz(bytes);
      for (const [k, v] of rerootSdist(inner)) files.set(k, v);
    }

    // The reported digest is the sha256 of the primary (installed) artifact — the
    // wheel when present, otherwise the sdist — and matches PyPI's published digest.
    const digest = 'sha256:' + sha256hex(primaryBytes);
    return { bytes: primaryBytes, digest, resolvedVersion, files };
  },

  manifestRules,
};

// ── manifest rules ────────────────────────────────────────────────────────────
function cap(code, capValue, severity, title, evidence) {
  return { code, cap: capValue, severity, title, evidence };
}
function trunc(s, n = 80) { s = String(s); return s.length > n ? s.slice(0, n) + '…' : s; }
const isSetupPy = (p) => p === 'setup.py' || p.endsWith('/setup.py');
const isPth = (p) => p.toLowerCase().endsWith('.pth');
const isPyproject = (p) => p === 'pyproject.toml' || p.endsWith('/pyproject.toml');
const isReqs = (p) => /(^|\/)requirements[\w.-]*\.txt$/i.test(p);
const textOf = (profiles, path) => { const p = profiles.get(path); return p && p.text != null ? p.text : null; };

// build-backend line from a pyproject.toml (no TOML dep — lightweight extraction).
function buildBackend(text) {
  if (text == null) return null;
  const m = text.match(/build-backend\s*=\s*["']([^"']+)["']/);
  return m ? m[1] : null;
}

// A .pth line that actually executes code starts with "import " (optionally several
// statements joined by ';'). Plain path lines and comments do not run anything — so
// this is the discriminator between the LiteLLM-style attack and benign namespace .pth.
function pthHasCode(text) {
  if (text == null) return false;
  return text.split(/\r?\n/).some((l) => /^\s*import\s/.test(l) || /\b(exec|eval)\s*\(/.test(l));
}

// PEP 508 direct references / VCS installs inside a dependency spec.
function nonRegistryRefs(text) {
  if (text == null) return [];
  const hits = new Set();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    // "name @ https://...", "pkg @ git+https://...", bare "git+https://...", file://, direct URL
    if (/@\s*(https?|git\+|file):/i.test(line) || /^(git\+|https?:|file:)/i.test(line) || /\bgit\+(https?|ssh):/i.test(line)) {
      hits.add(trunc(line, 100));
    }
  }
  return [...hits];
}

function manifestRules(fromP, toP, d) {
  const findings = [];
  const add = (f) => findings.push(f);
  const changed = [...d.added, ...d.modified];

  // ── setup.py: arbitrary code at install time ──────────────────────────────
  for (const path of changed) {
    if (!isSetupPy(path)) continue;
    const isNew = d.added.includes(path);
    if (isNew) {
      add(cap('SETUP_PY_NEW', 25, 'high',
        'new setup.py runs arbitrary Python when the sdist is installed',
        [{ file: path, detail: 'install-time code execution' }]));
    } else {
      add(cap('SETUP_PY_MODIFIED', 30, 'medium',
        'setup.py changed — install-time code path modified',
        [{ file: path, detail: 'install-time code execution' }]));
    }
    const t = textOf(toP, path);
    if (t && /\bcmdclass\b/.test(t)) {
      add(cap('SETUP_PY_CUSTOM_BUILD', 20, 'high',
        'setup.py overrides build/install commands (cmdclass) — custom install-time steps',
        [{ file: path, detail: 'cmdclass=' }]));
    }
  }

  // ── new .pth file: executes on every interpreter start (LiteLLM vector) ────
  for (const path of d.added) {
    if (!isPth(path)) continue;
    const t = textOf(toP, path);
    if (pthHasCode(t)) {
      add(cap('PTH_INSTALL_EXEC', 15, 'critical',
        'new .pth file executes code on every Python start — a persistent-execution vector',
        [{ file: path, detail: 'contains an executable import/exec line' }]));
    } else {
      add(cap('PTH_FILE_NEW', 25, 'high',
        'new .pth file added — .pth files are processed at interpreter startup',
        [{ file: path, detail: 'review contents' }]));
    }
  }

  // ── pyproject build-backend change: the backend runs arbitrary build code ──
  for (const path of changed) {
    if (!isPyproject(path)) continue;
    const toBackend = buildBackend(textOf(toP, path));
    const fromBackend = buildBackend(textOf(fromP, path));
    if (toBackend && toBackend !== fromBackend) {
      if (!fromBackend) {
        add(cap('BUILD_BACKEND_NEW', 25, 'high',
          `new build backend "${toBackend}" runs on build/install`,
          [{ file: path, detail: `build-backend = ${toBackend}` }]));
      } else {
        add(cap('BUILD_BACKEND_CHANGED', 30, 'medium',
          `build backend changed from "${fromBackend}" to "${toBackend}"`,
          [{ file: path, detail: `build-backend = ${toBackend}` }]));
      }
    }
  }

  // ── new non-registry deps (direct URL / git) in pyproject or requirements ──
  for (const path of changed) {
    if (!isPyproject(path) && !isReqs(path)) continue;
    const toRefs = nonRegistryRefs(textOf(toP, path));
    if (!toRefs.length) continue;
    const fromRefs = new Set(nonRegistryRefs(textOf(fromP, path)));
    for (const ref of toRefs) {
      if (fromRefs.has(ref)) continue; // only newly-introduced references
      add(cap('NON_REGISTRY_DEP', 15, 'high',
        'dependency resolves outside PyPI — code fetched from a URL / git source',
        [{ file: path, detail: ref }]));
    }
  }

  return findings;
}
