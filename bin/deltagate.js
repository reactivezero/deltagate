#!/usr/bin/env node
// deltagate — Phase 1 CLI (npm deterministic engine)
//
//   deltagate npm  <package> <from> <to>   analyze a live npm update
//   deltagate diff <dirA> <dirB>           analyze two local package dirs
//   ... add --json for the raw verdict record

import { analyzeNpm, analyzePypi, analyzeCargo, analyzeRubygems, analyzeArtifacts, analyzeArtifactsAI } from '../src/analyze.js';
import { loadDir } from '../src/loaders.js';
import { hasApiKey } from '../src/ai/index.js';

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

function print(v) {
  const band = BANDS[v.band];
  const s = v.subject;
  const head = s.name ? `${s.ecosystem} ${s.name}  ${s.from} → ${s.to}` : `${s.from} → ${s.to}`;
  console.log('');
  console.log(`  ${B}${head}${RST}`);
  console.log(
    `  ${paint(band.sym + ' ' + band.label, band.color)}  ` +
    `${B}${v.score}${RST}${DIM}/100${RST}  ` +
    `verdict ${B}${v.verdict}${RST}  ${DIM}confidence ${v.confidence}${RST}`
  );
  console.log(`  ${DIM}${v.stats.added} added · ${v.stats.modified} modified · ${v.stats.removed} removed${RST}`);

  if (v.findings.length) {
    console.log('');
    for (const f of v.findings) {
      console.log(`  ${paint('→', band.color)} ${B}${f.code}${RST} ${DIM}(caps at ${f.cap})${RST}`);
      console.log(`    ${f.title}`);
      for (const e of f.evidence) console.log(`    ${DIM}${e.file} — ${e.detail}${RST}`);
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
  if (v.verdict === 'HOLD') {
    console.log(`  ${paint('Held.', band.color)} You stay on ${s.from}. ` +
      `${DIM}Override once you've reviewed it.${RST}`);
  } else {
    console.log(`  ${DIM}Allowed. Nothing in the diff tripped a rule.${RST}`);
  }
  console.log('');
}

async function main() {
  const argv = process.argv.slice(2);
  const json = argv.includes('--json');
  let ai = argv.includes('--ai');
  const args = argv.filter((a) => a !== '--json' && a !== '--ai');
  const cmd = args[0];

  if (ai && !hasApiKey()) {
    console.error('deltagate: --ai needs ANTHROPIC_API_KEY (an Anthropic API key, not a Claude.ai subscription). Running deterministic-only.\n');
    ai = false;
  }

  try {
    let verdict;
    if (REGISTRIES[cmd]) {
      const [, name, from, to] = args;
      if (!name || !from || !to) throw new Error(`usage: deltagate ${cmd} <package> <from> <to>`);
      verdict = await REGISTRIES[cmd](name, from, to, { ai });
    } else if (cmd === 'diff') {
      const [, a, b] = args;
      if (!a || !b) throw new Error('usage: deltagate diff <dirA> <dirB>');
      const subject = { ecosystem: 'dir', from: a, to: b };
      verdict = ai
        ? await analyzeArtifactsAI(loadDir(a), loadDir(b), subject, { ai: true })
        : analyzeArtifacts(loadDir(a), loadDir(b), subject);
    } else {
      console.error('deltagate — dependency-update gate\n');
      console.error('  deltagate npm|pypi|cargo|gem <package> <from> <to>   analyze a live update');
      console.error('  deltagate diff <dirA> <dirB>                        analyze two local package dirs');
      console.error('  flags: --ai (LLM intent layer, needs ANTHROPIC_API_KEY) · --json (raw record)');
      process.exit(2);
    }

    if (json) console.log(JSON.stringify(verdict, (k, val) => (k === 'text' ? undefined : val), 2));
    else print(verdict);

    // Exit non-zero when the gate would hold — lets CI use it directly.
    process.exit(verdict.verdict === 'HOLD' ? 1 : 0);
  } catch (err) {
    console.error(`deltagate: ${err.message}`);
    process.exit(2);
  }
}

main();
