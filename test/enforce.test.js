// Enforcement tests. Node built-ins only, no real network to npm: a second
// node:http server stands in for the registry. Prints "N passed, M failed"
// like test/run.js.

import http from 'node:http';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createProxy } from '../src/enforce/proxy.js';

let pass = 0, fail = 0;
function check(name, cond, detail = '') {
  if (cond) { pass++; console.log(`  \x1b[32m✓\x1b[0m ${name}`); }
  else { fail++; console.log(`  \x1b[31m✗ ${name}\x1b[0m ${detail}`); }
}

// A GET that lets us set a raw Host header (fetch forbids overriding Host).
function rawGet(port, path, host) {
  return new Promise((resolve) => {
    const req = http.request({ host: '127.0.0.1', port, path, method: 'GET', headers: host ? { Host: host } : {} }, (res) => {
      res.resume();
      resolve(res.statusCode);
    });
    req.on('error', () => resolve(0));
    req.end();
  });
}

async function main() {
  // ── proxy: filter a canned packument served by a fake upstream ──────────────
  const tarball = Buffer.from([0x1f, 0x8b, 0x08, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xff]); // fake .tgz bytes
  const packument = {
    name: 'demo-pkg',
    'dist-tags': { latest: '3.0.0', next: '2.0.0' }, // `next` points at the version we'll hold
    versions: {
      '1.0.0': { name: 'demo-pkg', version: '1.0.0', dist: { tarball: 'x', integrity: 'sha512-a' } },
      '2.0.0': { name: 'demo-pkg', version: '2.0.0', dist: { tarball: 'x', integrity: 'sha512-b' } },
      '3.0.0': { name: 'demo-pkg', version: '3.0.0', dist: { tarball: 'x', integrity: 'sha512-c' } },
    },
    time: { created: 't0', modified: 't3', '1.0.0': 't1', '2.0.0': 't2', '3.0.0': 't3' },
  };

  const upstream = http.createServer((req, res) => {
    if (req.url === '/demo-pkg') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(packument)); // proxy parses & mutates its own copy; our closure object is untouched
    } else if (req.url === '/demo-pkg/-/demo-pkg-2.0.0.tgz') {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.end(tarball);
    } else {
      res.writeHead(404); res.end('nope');
    }
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const upstreamUrl = `http://127.0.0.1:${upstream.address().port}`;

  // Stub policy: hold version 2.0.0, allow everything else.
  const getDecision = async (_name, version) => (version === '2.0.0' ? 'hold' : 'allow');
  const proxy = await createProxy({ upstream: upstreamUrl, getDecision });

  console.log('\nproxy: packument filtering (hold demo-pkg@2.0.0)');
  const pj = await (await fetch(`${proxy.url}/demo-pkg`)).json();
  check('held v2 removed from versions', !pj.versions['2.0.0'], Object.keys(pj.versions).join(','));
  check('allowed v1 kept', !!pj.versions['1.0.0']);
  check('allowed v3 kept', !!pj.versions['3.0.0']);
  check('held v2 removed from time', !!pj.time && !pj.time['2.0.0']);
  check('time keeps allowed entries', !!pj.time && !!pj.time['1.0.0'] && !!pj.time['3.0.0']);
  check('latest tag stays at v3', pj['dist-tags'].latest === '3.0.0', pj['dist-tags'].latest);
  check('next tag repointed off v2 to newest allowed (v3)', pj['dist-tags'].next === '3.0.0', pj['dist-tags'].next);

  console.log('\nproxy: tarball pass-through is byte-for-byte');
  const tb = Buffer.from(await (await fetch(`${proxy.url}/demo-pkg/-/demo-pkg-2.0.0.tgz`)).arrayBuffer());
  check('tarball bytes identical through proxy', tb.equals(tarball), `${tb.length}B vs ${tarball.length}B`);

  console.log('\nproxy: hardening');
  const badHost = await rawGet(proxy.port, `/${proxy.token}/demo-pkg`, 'evil.example');
  check('rejects wrong Host header (403)', badHost === 403, String(badHost));
  const badToken = await fetch(`http://127.0.0.1:${proxy.port}/wrong-token/demo-pkg`);
  check('rejects wrong path token (404)', badToken.status === 404, String(badToken.status));

  await proxy.close();
  await new Promise((r) => upstream.close(r));

  // ── config: enable/disable round-trip against temp files ────────────────────
  const tmp = mkdtempSync(join(tmpdir(), 'deltagate-enforce-'));
  process.env.DELTAGATE_HOME = join(tmp, 'home'); // redirect the manifest/backup
  const { enable, disable, status } = await import('../src/enforce/config.js');
  const proxyUrl = 'http://127.0.0.1:4873/tok123';

  console.log('\nconfig: pre-existing .npmrc restored byte-for-byte');
  const npmrcA = join(tmp, 'npmrcA');
  writeFileSync(npmrcA, 'registry=https://registry.npmjs.org/\nsave-exact=true\n; a comment\n@myscope:registry=https://npm.pkg.github.com/\n');
  const beforeA = readFileSync(npmrcA);
  enable(proxyUrl, { npmrcPath: npmrcA });
  const enabledText = readFileSync(npmrcA, 'utf8');
  check('enable wrote our registry line', enabledText.includes(`registry=${proxyUrl}`));
  check('enable replaced the old global registry', !enabledText.includes('registry=https://registry.npmjs.org/'));
  check('enable left the scoped registry untouched', enabledText.includes('@myscope:registry=https://npm.pkg.github.com/'));
  check('status reports enabled', status({ npmrcPath: npmrcA }).enabled === true);
  check('status reads current registry', status({ npmrcPath: npmrcA }).currentRegistry === proxyUrl);
  disable({ npmrcPath: npmrcA });
  check('disable restored file byte-for-byte', readFileSync(npmrcA).equals(beforeA));
  check('status reports disabled after undo', status({ npmrcPath: npmrcA }).enabled === false);

  console.log('\nconfig: no prior .npmrc — enable creates, disable removes');
  const npmrcB = join(tmp, 'npmrcB');
  enable(proxyUrl, { npmrcPath: npmrcB });
  check('enable created the npmrc', existsSync(npmrcB));
  check('created npmrc carries our block', readFileSync(npmrcB, 'utf8').includes(`registry=${proxyUrl}`));
  disable({ npmrcPath: npmrcB });
  check('disable removed the created npmrc', !existsSync(npmrcB));

  console.log('\nconfig: surgical undo when the user edits after us');
  const npmrcC = join(tmp, 'npmrcC');
  writeFileSync(npmrcC, 'registry=https://registry.npmjs.org/\n');
  enable(proxyUrl, { npmrcPath: npmrcC });
  writeFileSync(npmrcC, readFileSync(npmrcC, 'utf8') + 'fund=false\n'); // user edits after enable
  const res = disable({ npmrcPath: npmrcC });
  const afterC = readFileSync(npmrcC, 'utf8');
  check('surgical undo path taken', res.outcome === 'surgical-restored-line', res.outcome);
  check('our line reverted to the original registry', afterC.includes('registry=https://registry.npmjs.org/'));
  check('our proxy line is gone', !afterC.includes(proxyUrl));
  check('user edit preserved', afterC.includes('fund=false'));

  rmSync(tmp, { recursive: true, force: true });

  console.log(`\n${fail === 0 ? '\x1b[32m' : '\x1b[31m'}${pass} passed, ${fail} failed\x1b[0m\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
