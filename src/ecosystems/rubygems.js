// RubyGems adapter.
//
// A ".gem" is a *plain* (uncompressed) tar whose members are themselves gzipped:
//   data.tar.gz       — a gzipped tar of the gem's actual files (lib/, ext/, …)
//   metadata.gz       — a gzipped YAML dump of the gemspec (deps, extensions, …)
//   checksums.yaml.gz — integrity of the above
// So we read the outer tar (readTar — NOT unpackTarGz, the outer layer is not
// gzipped), gunzip the inner data.tar.gz through unpackTarGz, and gunzip metadata.gz
// which we surface as a synthetic "metadata.yaml" entry so manifestRules can read the
// gemspec. Files therefore merge as: data.tar.gz entries at their natural paths PLUS
// one "metadata.yaml" holding the decoded spec.
//
// Fetch/verify:
//   resolve:  https://rubygems.org/api/v1/versions/{name}/latest.json  ({version})
//   sha:      https://rubygems.org/api/v1/versions/{name}.json         ([{number, platform, sha}])  sha = sha256(.gem)
//   download: https://rubygems.org/downloads/{name}-{version}.gem
//
// manifestRules — RubyGems install-time execution signals:
//   • gemspec extensions      — a native extension compiles + runs at install (hard cap)
//   • new non-registry dep    — a Gemfile git/github/path source, or a non-default gem source

import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import { readTar, unpackTarGz } from '../unpack.js';

const UA = 'deltagate (supply-chain update gate)';

async function getJson(url) {
  const res = await fetch(url, { headers: { accept: 'application/json', 'user-agent': UA } });
  if (!res.ok) throw new Error(`RubyGems ${res.status} for ${url}`);
  return res.json();
}

function sha256hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

export default {
  name: 'rubygems',

  async fetch(name, version) {
    let resolvedVersion = version;
    if (!version || version === 'latest') {
      const latest = await getJson(`https://rubygems.org/api/v1/versions/${encodeURIComponent(name)}/latest.json`);
      resolvedVersion = latest.version;
      if (!resolvedVersion || resolvedVersion === 'unknown') throw new Error(`could not resolve latest version for gem ${name}`);
    }

    // Look up the published sha256 for the ruby-platform build of this version.
    let sha = null;
    try {
      const versions = await getJson(`https://rubygems.org/api/v1/versions/${encodeURIComponent(name)}.json`);
      const match = versions.find((v) => v.number === resolvedVersion && (v.platform === 'ruby' || !v.platform))
        || versions.find((v) => v.number === resolvedVersion);
      sha = match?.sha || null;
    } catch { /* verification is best-effort; download still proceeds */ }

    const dl = `https://rubygems.org/downloads/${encodeURIComponent(name)}-${encodeURIComponent(resolvedVersion)}.gem`;
    const res = await fetch(dl, { headers: { 'user-agent': UA } });
    if (!res.ok) throw new Error(`gem download ${res.status} for ${name}@${resolvedVersion}`);
    const bytes = Buffer.from(await res.arrayBuffer());

    const got = sha256hex(bytes);
    if (sha && got !== sha) throw new Error(`gem sha256 mismatch for ${name}@${resolvedVersion}`);

    // Outer tar (uncompressed) -> {data.tar.gz, metadata.gz, ...}
    const outer = readTar(bytes);
    const files = new Map();

    const dataGz = outer.get('data.tar.gz');
    if (dataGz) for (const [k, v] of unpackTarGz(dataGz)) files.set(k, v);

    const metaGz = outer.get('metadata.gz');
    if (metaGz) files.set('metadata.yaml', Buffer.from(gunzipSync(metaGz)));

    return { bytes, digest: 'sha256:' + got, resolvedVersion, files };
  },

  manifestRules,
};

// ── manifest rules ────────────────────────────────────────────────────────────
function cap(code, capValue, severity, title, evidence) {
  return { code, cap: capValue, severity, title, evidence };
}
function trunc(s, n = 100) { s = String(s); return s.length > n ? s.slice(0, n) + '…' : s; }
const isGemfile = (p) => /(^|\/)Gemfile$/.test(p) || /\.gemspec$/.test(p);
const textOf = (profiles, path) => { const p = profiles.get(path); return p && p.text != null ? p.text : null; };

// Extract the gemspec `extensions:` list from the YAML metadata (no YAML dep —
// handles both the flow form `extensions: [a, b]` and the block form).
function gemExtensions(yaml) {
  if (yaml == null) return [];
  const lines = yaml.split(/\r?\n/);
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^extensions:\s*(.*)$/);
    if (!m) continue;
    const inline = m[1].trim();
    if (inline && inline !== '[]') {
      out.push(...inline.replace(/^\[|\]$/g, '').split(',').map((s) => s.trim()).filter(Boolean));
    }
    for (let j = i + 1; j < lines.length; j++) {
      const bm = lines[j].match(/^\s*-\s+(.*)$/);
      if (!bm) break;
      out.push(bm[1].trim());
    }
    break;
  }
  return out.filter(Boolean);
}

// git/github/path sources or a non-default gem source in a Gemfile / *.gemspec.
function nonRegistryRefs(text) {
  if (text == null) return [];
  const hits = new Set();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;
    // hash-key forms: `git: "..."`, `github: "..."`, `path: "..."`, and hashrocket `:git => "..."`
    if (/\b(git|github|path)\s*:\s*["']/.test(line) || /:\s*(git|github|path)\s*=>\s*["']/.test(line)) {
      hits.add(trunc(line));
    }
    // a source pointing somewhere other than the default registry
    const src = line.match(/^source\s+["'](https?:\/\/[^"']+)["']/);
    if (src && !/rubygems\.org/.test(src[1])) hits.add(trunc(line));
  }
  return [...hits];
}

function manifestRules(fromP, toP, d) {
  const findings = [];
  const add = (f) => findings.push(f);
  const changed = [...d.added, ...d.modified];

  // ── native extension: compiles + runs at install time ─────────────────────
  const toExt = gemExtensions(textOf(toP, 'metadata.yaml'));
  const fromExt = new Set(gemExtensions(textOf(fromP, 'metadata.yaml')));
  const newExt = toExt.filter((e) => !fromExt.has(e));
  if (newExt.length) {
    add(cap('GEM_EXTENSIONS', 15, 'critical',
      'gemspec declares a native extension — it is compiled and executed at install time',
      newExt.slice(0, 4).map((e) => ({ file: 'metadata.yaml', detail: `extension: ${e}` }))));
  }

  // ── new non-registry deps (Gemfile git/github/path, or a foreign source) ───
  for (const path of changed) {
    if (!isGemfile(path)) continue;
    const toRefs = nonRegistryRefs(textOf(toP, path));
    if (!toRefs.length) continue;
    const fromRefs = new Set(nonRegistryRefs(textOf(fromP, path)));
    for (const ref of toRefs) {
      if (fromRefs.has(ref)) continue;
      add(cap('NON_REGISTRY_DEP', 15, 'high',
        'dependency resolves outside RubyGems — code pulled from a git/path/foreign source',
        [{ file: path, detail: ref }]));
    }
  }

  return findings;
}
