// Local enforcement, part 1: a read-through npm-registry proxy on localhost.
//
// The enforcement principle is *metadata filtering*, not byte rewriting: we ask
// the injected getDecision(name, version) about every published version and then
// DELETE the held ones from the packument the resolver sees. A risky version
// simply doesn't exist for npm's resolver, so it silently settles on the newest
// ALLOWED version — no error, no forced pin. We NEVER touch tarball bytes, so
// npm's dist.integrity check still passes on whatever it does install.
//
// Everything that isn't a packument read (tarballs, /-/ registry endpoints,
// single-version manifests, publishes) is proxied straight through untouched.

import http from 'node:http';
import { Readable } from 'node:stream';
import { randomBytes } from 'node:crypto';

// ── semver, just enough to pick the "newest allowed" version ──────────────────
// Zero deps, so a compact comparator. Handles major.minor.patch + prerelease
// (build metadata after '+' is ignored, per semver §10).
function parseSemver(v) {
  const [core, pre] = String(v).split('+')[0].split('-');
  const n = core.split('.').map((x) => parseInt(x, 10) || 0);
  return { major: n[0] || 0, minor: n[1] || 0, patch: n[2] || 0, pre: pre ? pre.split('.') : [] };
}
function cmpId(a, b) {
  const an = /^\d+$/.test(a), bn = /^\d+$/.test(b);
  if (an && bn) return Number(a) - Number(b);   // numeric identifiers compare numerically
  if (an) return -1;                            // numeric < alphanumeric
  if (bn) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}
function compareSemver(a, b) {
  const x = parseSemver(a), y = parseSemver(b);
  if (x.major !== y.major) return x.major - y.major;
  if (x.minor !== y.minor) return x.minor - y.minor;
  if (x.patch !== y.patch) return x.patch - y.patch;
  if (x.pre.length && !y.pre.length) return -1;  // a prerelease is lower than its release
  if (!x.pre.length && y.pre.length) return 1;
  for (let i = 0; i < Math.max(x.pre.length, y.pre.length); i++) {
    if (i >= x.pre.length) return -1;
    if (i >= y.pre.length) return 1;
    const c = cmpId(x.pre[i], y.pre[i]);
    if (c) return c;
  }
  return 0;
}
// Newest allowed version, preferring stable releases; falls back to the newest
// prerelease only if nothing stable survives.
function newestAllowed(versions) {
  if (!versions.length) return undefined;
  const stable = versions.filter((v) => !v.includes('-'));
  const pool = stable.length ? stable : versions;
  return pool.reduce((best, v) => (compareSemver(v, best) > 0 ? v : best));
}

// ── path classification ───────────────────────────────────────────────────────
// A packument read is `GET /<name>` or `GET /@scope%2fname` (scoped names arrive
// percent-encoded from npm, but tolerate an unencoded `/@scope/name` too).
// Anything containing `/-/` is a tarball or a registry endpoint; a two-segment
// unscoped path like `/name/1.2.3` is a single-version manifest — both proxy
// through untouched.
function isPackumentPath(p) {
  if (p.includes('/-/')) return false;
  const segs = p.split('/').filter(Boolean);
  if (segs.length === 1) return true;
  if (segs.length === 2 && segs[0].startsWith('@')) return true;
  return false;
}
function packumentName(p) {
  const segs = p.split('/').filter(Boolean);
  if (segs.length === 1) return decodeURIComponent(segs[0]);
  return decodeURIComponent(segs[0]) + '/' + decodeURIComponent(segs[1]);
}
// Rebuild the upstream packument path in npm's canonical form (scoped slash
// encoded, '@' left literal), normalizing whichever form the client sent.
function upstreamPackumentPath(name) {
  if (name.startsWith('@')) return '/@' + encodeURIComponent(name.slice(1));
  return '/' + encodeURIComponent(name);
}

// Only forward the request headers upstream that matter for a registry read,
// so we don't leak the client's Host/Connection or accidentally shape caching.
function fwdHeaders(req) {
  const h = {};
  for (const k of ['accept', 'authorization', 'user-agent', 'content-type', 'npm-command']) {
    if (req.headers[k]) h[k] = req.headers[k];
  }
  return h;
}

/**
 * Filter a packument in place: drop every held version from `versions` and
 * `time`, then repoint any dist-tag that pointed at a held version to the newest
 * surviving allowed version.
 * @param {object} json the upstream packument (full or abbreviated/corgi)
 * @param {string} name decoded package name (authoritative over json.name)
 * @param {(name:string,version:string)=>Promise<'allow'|'hold'>} decide
 */
async function filterPackument(json, name, decide) {
  const versions = json.versions;
  if (!versions || typeof versions !== 'object') return json;

  const keys = Object.keys(versions);
  const verdicts = await Promise.all(keys.map(async (v) => {
    try { return [v, (await decide(name, v)) === 'hold']; }
    catch { return [v, false]; } // fail-open: a broken verdict lookup must not brick installs
  }));
  const held = new Set(verdicts.filter(([, h]) => h).map(([v]) => v));
  if (!held.size) return json;

  for (const v of held) {
    delete versions[v];
    if (json.time) delete json.time[v];
  }

  // Repoint any tag (latest included) that referenced a now-missing version.
  const newest = newestAllowed(Object.keys(versions));
  const tags = json['dist-tags'];
  if (tags) {
    for (const [tag, ver] of Object.entries(tags)) {
      if (!held.has(ver)) continue;
      if (newest) tags[tag] = newest;
      else delete tags[tag]; // nothing allowed remains — the tag can't resolve
    }
  }
  return json;
}

// Transparent byte-for-byte proxy for everything that isn't a packument.
async function passThrough(req, res, url) {
  const init = { method: req.method, headers: fwdHeaders(req) };
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    init.body = Readable.toWeb(req); // e.g. `npm publish` PUTs a body
    init.duplex = 'half';
  }
  const up = await fetch(url, init);
  const headers = { 'cache-control': 'no-cache' };
  const ct = up.headers.get('content-type');
  if (ct) headers['content-type'] = ct;
  res.writeHead(up.status, headers);
  if (up.body) Readable.fromWeb(up.body).pipe(res);
  else res.end(Buffer.from(await up.arrayBuffer()));
}

/**
 * Start a localhost npm read proxy.
 * @param {object} o
 * @param {number} [o.port=0] listen port (0 = ephemeral)
 * @param {string} [o.upstream='https://registry.npmjs.org'] real registry
 * @param {(name:string,version:string)=>Promise<'allow'|'hold'>} o.getDecision injected policy
 * @param {string|false} [o.token] per-instance URL path token (random by default; false to disable)
 * @returns {Promise<{server:import('node:http').Server, url:string, port:number, token:string|null, close:()=>Promise<void>}>}
 */
export function createProxy({ port = 0, upstream = 'https://registry.npmjs.org', getDecision, token } = {}) {
  const base = upstream.replace(/\/+$/, '');
  const decide = typeof getDecision === 'function' ? getDecision : async () => 'allow';
  const tok = token === undefined ? randomBytes(9).toString('hex') : (token || null);
  const state = { boundPort: 0 };

  const handler = async (req, res) => {
    try {
      // Anti DNS-rebinding: only accept requests addressed to our loopback host.
      if (req.headers.host !== `127.0.0.1:${state.boundPort}`) {
        res.writeHead(403, { 'content-type': 'text/plain' });
        res.end('deltagate proxy: forbidden host\n');
        return;
      }

      let pathAndQuery = req.url;
      // Strip the per-instance token prefix; reject anything outside it.
      if (tok) {
        const prefix = `/${tok}`;
        if (pathAndQuery === prefix) pathAndQuery = '/';
        else if (pathAndQuery.startsWith(prefix + '/')) pathAndQuery = pathAndQuery.slice(prefix.length);
        else { res.writeHead(404, { 'content-type': 'text/plain' }); res.end('deltagate proxy: not found\n'); return; }
      }

      const q = pathAndQuery.indexOf('?');
      const rawPath = q === -1 ? pathAndQuery : pathAndQuery.slice(0, q);
      const query = q === -1 ? '' : pathAndQuery.slice(q);

      if (req.method === 'GET' && isPackumentPath(rawPath)) {
        const name = packumentName(rawPath);
        const up = await fetch(base + upstreamPackumentPath(name) + query, { headers: fwdHeaders(req) });
        if (!up.ok) { // pass registry errors (404 etc.) straight through
          const buf = Buffer.from(await up.arrayBuffer());
          res.writeHead(up.status, { 'content-type': up.headers.get('content-type') || 'application/json', 'cache-control': 'no-cache' });
          res.end(buf);
          return;
        }
        const filtered = await filterPackument(await up.json(), name, decide);
        const body = Buffer.from(JSON.stringify(filtered));
        res.writeHead(200, {
          'content-type': 'application/json',
          // Short-lived so a flipped decision propagates on the next resolve.
          'cache-control': 'max-age=0, must-revalidate',
          'content-length': body.length,
        });
        res.end(body);
        return;
      }

      await passThrough(req, res, base + rawPath + query);
    } catch (err) {
      if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' });
      res.end(`deltagate proxy error: ${err.message}\n`);
    }
  };

  const server = http.createServer(handler);
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      state.boundPort = server.address().port;
      const url = `http://127.0.0.1:${state.boundPort}` + (tok ? `/${tok}` : '');
      const close = () => new Promise((r) => server.close(() => r()));
      resolve({ server, url, port: state.boundPort, token: tok, close });
    });
  });
}
