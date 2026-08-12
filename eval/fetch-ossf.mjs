// fetch-ossf.mjs — pull a labelled sample of real malicious npm packages from
// the OpenSSF malicious-packages advisory list and write eval/labels-npm.json.
//
// What this list is (and isn't):
//   ossf/malicious-packages is the authoritative, OSV-format ADVISORY corpus —
//   it records WHICH package@version was found malicious, not the payload bytes.
//   Registry takedowns remove the actual code, so there is nothing to download
//   here but labels. We use these labels as ground truth; for real bytes you
//   need the Datadog dataset (see eval/README.md), and for negatives we
//   live-fetch benign adjacent versions in run.mjs.
//
// Layout we rely on (verified against the repo, Aug 2026):
//   osv/malicious/npm/<pkg>/<MAL-YYYY-N>.json          (unscoped)
//   osv/malicious/npm/@scope/<pkg>/<MAL-YYYY-N>.json   (scoped)
// Each file is an OSV record; the fields we keep are id, package name, summary,
// and whatever version information the record carries (usually "all versions").
//
// Zero dependencies: Node built-ins + global fetch only.
//
// Usage:
//   node eval/fetch-ossf.mjs [sampleCap]     # default cap 200
//   GITHUB_TOKEN=ghp_... node eval/fetch-ossf.mjs 300   # higher API rate limit
//
// The one metadata call goes through the GitHub API (rate-limited: 60/hr
// unauthenticated, 5000/hr with GITHUB_TOKEN). Every record body is then read
// from the raw.githubusercontent.com CDN, which does NOT spend API quota.

import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, 'labels-npm.json');

const REPO = 'ossf/malicious-packages';
const NPM_DIR = 'osv/malicious/npm';
const RAW_BASE = `https://raw.githubusercontent.com/${REPO}/main/${NPM_DIR}`;
const API = 'https://api.github.com';

const SAMPLE_CAP = Number(process.argv[2]) || 200;
const CONCURRENCY = 8;

const ghHeaders = () => {
  const h = { accept: 'application/vnd.github+json', 'user-agent': 'deltagate-eval' };
  if (process.env.GITHUB_TOKEN) h.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  return h;
};

async function ghJson(url) {
  const res = await fetch(url, { headers: ghHeaders() });
  if (res.status === 403 && res.headers.get('x-ratelimit-remaining') === '0') {
    const reset = Number(res.headers.get('x-ratelimit-reset')) * 1000;
    const mins = reset ? Math.max(0, Math.ceil((reset - Date.now()) / 60000)) : '?';
    throw new Error(
      `GitHub API rate limit hit (resets in ~${mins} min). ` +
      `Set GITHUB_TOKEN for 5000 req/hr, or retry later.`,
    );
  }
  if (!res.ok) throw new Error(`GitHub API ${res.status} for ${url}`);
  return res.json();
}

// Turn OSV affected[] into a compact, human-readable version list. In practice
// this corpus almost always marks the whole package (introduced "0"), so most
// records come out as ["*"] — we surface that honestly rather than inventing
// specific versions the advisory never claimed.
function versionsFromAffected(affected) {
  const out = new Set();
  for (const a of affected || []) {
    for (const v of a.versions || []) out.add(String(v));
    for (const r of a.ranges || []) {
      const parts = [];
      for (const e of r.events || []) {
        if (e.introduced != null) parts.push(`>=${e.introduced}`);
        else if (e.fixed != null) parts.push(`<${e.fixed}`);
        else if (e.last_affected != null) parts.push(`<=${e.last_affected}`);
      }
      if (parts.length) out.add(parts.join(' '));
    }
  }
  return [...out].map((s) => (s === '>=0' ? '*' : s));
}

// Bucket the record paths by MAL year (MAL-YYYY-N.json) so an evenly spread
// sample spans 2022→2026 instead of just the head of the alphabet — the tree
// listing is returned in path order and is often truncated by GitHub.
function yearOf(path) {
  const m = /MAL-(\d{4})-/.exec(path);
  return m ? m[1] : 'other';
}

function sampleAcrossYears(paths, cap) {
  const byYear = new Map();
  for (const p of paths) {
    const y = yearOf(p);
    if (!byYear.has(y)) byYear.set(y, []);
    byYear.get(y).push(p);
  }
  const years = [...byYear.keys()].sort();
  const picked = [];
  // round-robin: take one from each year in turn until we hit the cap
  let added = true;
  const cursors = new Map(years.map((y) => [y, 0]));
  while (added && picked.length < cap) {
    added = false;
    for (const y of years) {
      if (picked.length >= cap) break;
      const list = byYear.get(y);
      const i = cursors.get(y);
      if (i < list.length) {
        picked.push(list[i]);
        cursors.set(y, i + 1);
        added = true;
      }
    }
  }
  return picked;
}

// map over items with a small concurrency pool
async function pool(items, n, fn) {
  const out = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      out[idx] = await fn(items[idx], idx);
    }
  });
  await Promise.all(workers);
  return out;
}

// encode each path segment but keep the "/" separators
const rawUrl = (relPath) =>
  `${RAW_BASE}/${relPath.split('/').map(encodeURIComponent).join('/')}`;

async function main() {
  console.log(`[ossf] listing ${NPM_DIR} in ${REPO} …`);

  // 1) find the npm tree's sha (one small API call), then list it recursively
  //    (one more API call) — that's the entire GitHub-API budget for this run.
  const malicious = await ghJson(`${API}/repos/${REPO}/contents/osv/malicious`);
  const npmEntry = malicious.find((e) => e.path === NPM_DIR && e.type === 'dir');
  if (!npmEntry) throw new Error(`could not locate ${NPM_DIR} in the repo`);

  const tree = await ghJson(`${API}/repos/${REPO}/git/trees/${npmEntry.sha}?recursive=1`);
  const blobs = (tree.tree || []).filter(
    (t) => t.type === 'blob' && t.path.endsWith('.json'),
  );
  const listedTruncated = !!tree.truncated;
  console.log(
    `[ossf] listed ${blobs.length} advisory records` +
      (listedTruncated ? ' (GitHub truncated the tree; sampling the listed subset)' : ''),
  );

  // 2) sample, spread across years
  const paths = blobs.map((b) => b.path);
  const sample = sampleAcrossYears(paths, SAMPLE_CAP);
  console.log(`[ossf] sampling ${sample.length} of ${paths.length} (cap ${SAMPLE_CAP}) …`);

  // 3) read each record body from the raw CDN (no API quota spent)
  const dropped = [];
  const results = await pool(sample, CONCURRENCY, async (relPath) => {
    try {
      const res = await fetch(rawUrl(relPath), { headers: { 'user-agent': 'deltagate-eval' } });
      if (!res.ok) {
        dropped.push({ path: relPath, reason: `HTTP ${res.status}` });
        return null;
      }
      const rec = JSON.parse(await res.text());
      const name =
        rec.affected?.[0]?.package?.name ||
        relPath.replace(/\/MAL-[^/]+\.json$/i, ''); // fall back to the path
      const id = rec.id || relPath.split('/').pop().replace(/\.json$/i, '');
      const versions = versionsFromAffected(rec.affected);
      return {
        name,
        versions: versions.length ? versions : ['*'],
        id,
        summary: rec.summary || `Malicious code in ${name} (npm)`,
      };
    } catch (err) {
      dropped.push({ path: relPath, reason: err.message });
      return null;
    }
  });

  const labels = results.filter(Boolean);
  // de-dupe by id (a package can appear once per advisory; ids are unique)
  const seen = new Set();
  const unique = labels.filter((l) => (seen.has(l.id) ? false : seen.add(l.id)));

  const payload = {
    source: `github.com/${REPO} (${NPM_DIR})`,
    note:
      'OSV advisory labels only — no payload bytes. Versions are usually "*" ' +
      '(the advisory marks the whole package). Real bytes: DataDog/' +
      'malicious-software-packages-dataset. Negatives: live benign in benign.json.',
    generatedAt: new Date().toISOString(),
    listedTotal: blobs.length,
    listedTruncated,
    sampled: sample.length,
    kept: unique.length,
    droppedCount: dropped.length,
    labels: unique,
  };
  writeFileSync(OUT, JSON.stringify(payload, null, 2) + '\n');

  console.log(`[ossf] kept ${unique.length} labels → ${OUT}`);
  if (dropped.length) {
    console.log(`[ossf] dropped ${dropped.length} record(s):`);
    for (const d of dropped.slice(0, 10)) console.log(`         ${d.path} — ${d.reason}`);
    if (dropped.length > 10) console.log(`         … and ${dropped.length - 10} more`);
  }
}

main().catch((err) => {
  console.error(`fetch-ossf: ${err.message}`);
  process.exit(1);
});
