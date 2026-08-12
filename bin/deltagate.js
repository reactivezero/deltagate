#!/usr/bin/env node
// deltagate — Phase 1 CLI (npm deterministic engine)
//
//   deltagate npm  <package> <from> <to>   analyze a live npm update
//   deltagate diff <dirA> <dirB>           analyze two local package dirs
//   ... add --json for the raw verdict record

import { analyzeNpm, analyzeArtifacts } from '../src/analyze.js';
import { loadDir } from '../src/loaders.js';

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
    console.log(`  ${DIM}no deterministic red flags (Phase 2 AI layer would judge intent here)${RST}`);
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
  const args = argv.filter((a) => a !== '--json');
  const cmd = args[0];

  try {
    let verdict;
    if (cmd === 'npm') {
      const [, name, from, to] = args;
      if (!name || !from || !to) throw new Error('usage: deltagate npm <package> <from> <to>');
      verdict = await analyzeNpm(name, from, to);
    } else if (cmd === 'diff') {
      const [, a, b] = args;
      if (!a || !b) throw new Error('usage: deltagate diff <dirA> <dirB>');
      verdict = analyzeArtifacts(loadDir(a), loadDir(b), { ecosystem: 'dir', from: a, to: b });
    } else {
      console.error('deltagate — dependency-update gate (Phase 1)\n');
      console.error('  deltagate npm  <package> <from> <to>   analyze a live npm update');
      console.error('  deltagate diff <dirA> <dirB>           analyze two local package dirs');
      console.error('  (add --json for the raw verdict record)');
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
