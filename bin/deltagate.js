#!/usr/bin/env node
// deltagate — cross-language dependency-update gate.
//
//   deltagate npm|pypi|cargo|gem <package> <from> <to>   analyze a live update
//   deltagate diff <dirA> <dirB>                         analyze two local dirs
//   deltagate lookup <eco> <pkg> <from> <to>             query the verdict DB only
//   deltagate export <file>                              dump local verdicts (JSONL)
//   deltagate proxy [--port N] [--upstream URL]          run the npm filtering proxy
//   deltagate enable [--registry URL] | disable | status  wire ~/.npmrc (reversible)
//   deltagate run -- <cmd...>                            run a command through the gate
//   flags: --ai · --json · --fresh (bypass the verdict cache)

import { analyzeNpm, analyzePypi, analyzeCargo, analyzeRubygems, analyzeArtifacts, analyzeArtifactsAI } from '../src/analyze.js';
import { loadDir } from '../src/loaders.js';
import { hasApiKey } from '../src/ai/index.js';
import { getAdapter } from '../src/ecosystems/index.js';
import { lookup, exportBundle, findByCandidate } from '../src/verdict/index.js';
import { createProxy } from '../src/enforce/proxy.js';
import { runWrapped } from '../src/enforce/wrap.js';
import { enable, disable, status } from '../src/enforce/config.js';

const REGISTRIES = { npm: analyzeNpm, pypi: analyzePypi, cargo: analyzeCargo, gem: analyzeRubygems };

const BANDS = {
  block:   { label: 'BLOCK',   sym: '●', color: '\x1b[31m' },
  hold:    { label: 'HOLD',    sym: '●', color: '\x1b[33m' },
  caution: { label: 'CAUTION', sym: '○', color: '\x1b[33m' },
  clear:   { label: 'CLEAR',   sym: '○', color: '\x1b[32m' },
};
const DIM = '\x1b[2m', RST = '\x1b[0m', B = '\x1b[1m';
const tty = process.stdout.isTTY;
const paint = (s, c) => (tty ? c + s + RST : s);

// The enforcement proxy knows only the candidate version, not what's installed,
// so it gates on any stored HOLD verdict for that version. Unknown → policy:
// allow-with-log by default, deny (hold) under DELTAGATE_POLICY=strict.
const getDecision = async (name, version) => {
  const rec = findByCandidate('npm', name, version);
  if (rec) return rec.verdict === 'HOLD' ? 'hold' : 'allow';
  if (process.env.DELTAGATE_POLICY === 'strict') return 'hold';
  return 'allow';
};

function print(v) {
  const band = BANDS[v.band] || BANDS.caution;
  const s = v.subject || {};
  const head = s.name ? `${s.ecosystem} ${s.name}  ${s.from} → ${s.to}` : `${s.from} → ${s.to}`;
  console.log('');
  console.log(`  ${B}${head}${RST}`);
  console.log(
    `  ${paint(band.sym + ' ' + band.label, band.color)}  ` +
    `${B}${v.score}${RST}${DIM}/100${RST}  ` +
    `verdict ${B}${v.verdict}${RST}  ${DIM}confidence ${v.confidence}${RST}`
  );
  if (v.stats) console.log(`  ${DIM}${v.stats.added} added · ${v.stats.modified} modified · ${v.stats.removed} removed${RST}`);
  if (!v.stats) console.log(`  ${DIM}(from the verdict database)${RST}`);

  if (v.findings && v.findings.length) {
    console.log('');
    for (const f of v.findings) {
      const tag = Number.isFinite(f.cap) ? `caps at ${f.cap}` : Number.isFinite(f.penalty) ? `−${f.penalty}` : (f.severity || '');
      console.log(`  ${paint('→', band.color)} ${B}${f.code}${RST} ${DIM}(${tag})${RST}`);
      if (f.title) console.log(`    ${f.title}`);
      if (f.evidence) for (const e of f.evidence) console.log(`    ${DIM}${e.file} — ${e.detail}${RST}`);
    }
  } else {
    console.log(`  ${DIM}no red flags${RST}`);
  }

  const a = v.engine?.ai;
  if (a?.ran) {
    const state = a.reliable ? 'reliable' : `unreliable${a.flags?.length ? ' (' + a.flags.join(', ') + ')' : ''}`;
    console.log(`  ${DIM}AI layer: ${a.model} — ${state}${RST}`);
  } else if (a && a.error) {
    console.log(`  ${DIM}AI layer: skipped (${a.error})${RST}`);
  }

  console.log('');
  if (v.verdict === 'HOLD') console.log(`  ${paint('Held.', band.color)} You stay on ${s.from}. ${DIM}Override once you've reviewed it.${RST}`);
  else console.log(`  ${DIM}Allowed. Nothing in the diff tripped a rule.${RST}`);
  console.log('');
}

function usage() {
  console.error('deltagate — cross-language dependency-update gate\n');
  console.error('  deltagate npm|pypi|cargo|gem <package> <from> <to>   analyze a live update');
  console.error('  deltagate diff <dirA> <dirB>                         analyze two local package dirs');
  console.error('  deltagate lookup <eco> <pkg> <from> <to>             query the verdict DB (no analysis)');
  console.error('  deltagate export <file>                              write local verdicts as JSONL');
  console.error('  deltagate proxy [--port N] [--upstream URL]          run the npm metadata-filtering proxy');
  console.error('  deltagate enable [--registry URL] | disable | status  wire ~/.npmrc (reversible)');
  console.error('  deltagate run -- <command...>                        run a command through the gate');
  console.error('  flags: --ai (LLM layer, needs ANTHROPIC_API_KEY) · --json · --fresh (bypass cache)');
}

async function main() {
  const argv = process.argv.slice(2);
  const json = argv.includes('--json');
  const fresh = argv.includes('--fresh');
  let ai = argv.includes('--ai');
  const args = argv.filter((a) => a !== '--json' && a !== '--ai' && a !== '--fresh');
  const cmd = args[0];
  const flagVal = (name) => { const i = argv.indexOf(name); return i >= 0 && i + 1 < argv.length ? argv[i + 1] : null; };

  if (ai && !hasApiKey()) {
    console.error('deltagate: --ai needs ANTHROPIC_API_KEY (an Anthropic API key, not a Claude.ai subscription). Running deterministic-only.\n');
    ai = false;
  }

  try {
    // ── action commands (no verdict to print) ────────────────────────────────
    if (cmd === 'export') {
      const [, file] = args;
      if (!file) throw new Error('usage: deltagate export <file>');
      console.log(`deltagate: wrote ${exportBundle(file)} record(s) to ${file}`);
      return;
    }
    if (cmd === 'enable') {
      const url = flagVal('--registry') || 'http://127.0.0.1:31510';
      const m = enable(url);
      console.log(`deltagate: npm registry → ${url}  ${DIM}(backup + manifest saved; run "deltagate disable" to revert)${RST}`);
      if (json) console.log(JSON.stringify(m, null, 2));
      return;
    }
    if (cmd === 'disable') {
      const m = disable();
      console.log('deltagate: reverted ~/.npmrc');
      if (json) console.log(JSON.stringify(m, null, 2));
      return;
    }
    if (cmd === 'status') {
      console.log(JSON.stringify(status(), null, 2));
      return;
    }
    if (cmd === 'proxy') {
      const port = flagVal('--port');
      const upstream = flagVal('--upstream') || 'https://registry.npmjs.org';
      const { url, close } = await createProxy({ port: port ? Number(port) : 31510, upstream, getDecision, token: false });
      console.error(`deltagate proxy on ${url}  ${DIM}(npm registry filter; Ctrl-C to stop)${RST}`);
      console.error(`  point npm at it:  deltagate enable --registry ${url}   ${DIM}(or npm --registry ${url} install …)${RST}`);
      const shutdown = async () => { await close(); process.exit(0); };
      process.on('SIGINT', shutdown);
      process.on('SIGTERM', shutdown);
      return; // keep the process alive on the listening server
    }
    if (cmd === 'run') {
      let rest = args.slice(1);
      if (rest[0] === '--') rest = rest.slice(1);
      if (!rest.length) throw new Error('usage: deltagate run -- <command...>');
      const { url, close } = await createProxy({ getDecision });
      let code = 0;
      try { code = (await runWrapped(rest, { registryUrl: url })).code; }
      finally { await close(); }
      process.exit(code || 0);
    }

    // ── verdict-producing commands ────────────────────────────────────────────
    let verdict;
    if (cmd === 'lookup') {
      const [, eco, name, from, to] = args;
      if (!eco || !name || !from || !to) throw new Error('usage: deltagate lookup <eco> <pkg> <from> <to>');
      let subject = { ecosystem: eco, name, from, to };
      try {
        const ad = getAdapter(eco);
        const [f, t] = await Promise.all([ad.fetch(name, from), ad.fetch(name, to)]);
        subject = { ecosystem: eco, name, from: f.resolvedVersion, to: t.resolvedVersion, fromDigest: f.digest, toDigest: t.digest };
      } catch { /* fall back to the digest-less key */ }
      verdict = await lookup(subject);
      if (!verdict) { console.error(`deltagate: no verdict on record for ${name} ${from} → ${to}`); process.exit(2); }
    } else if (REGISTRIES[cmd]) {
      const [, name, from, to] = args;
      if (!name || !from || !to) throw new Error(`usage: deltagate ${cmd} <package> <from> <to>`);
      verdict = await REGISTRIES[cmd](name, from, to, { ai, fresh });
    } else if (cmd === 'diff') {
      const [, a, b] = args;
      if (!a || !b) throw new Error('usage: deltagate diff <dirA> <dirB>');
      const subject = { ecosystem: 'dir', from: a, to: b };
      verdict = ai ? await analyzeArtifactsAI(loadDir(a), loadDir(b), subject, { ai: true }) : analyzeArtifacts(loadDir(a), loadDir(b), subject);
    } else {
      usage();
      process.exit(2);
    }

    if (json) console.log(JSON.stringify(verdict, null, 2));
    else print(verdict);
    process.exit(verdict.verdict === 'HOLD' ? 1 : 0); // non-zero on hold → CI-friendly
  } catch (err) {
    console.error(`deltagate: ${err.message}`);
    process.exit(2);
  }
}

main();
