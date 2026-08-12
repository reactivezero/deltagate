// worker-analyze.mjs — runs one deterministic analysis in an isolated thread.
//
// analyzeArtifacts() is synchronous, so a pathological input (e.g. a regex with
// catastrophic backtracking on a large minified bundle) blocks the event loop
// and cannot be timed out in-process. Running it in a worker lets the harness
// hard-terminate the thread from outside and keep going. This is what turns
// run.mjs into a ReDoS/DoS *detector* instead of a victim of one.
//
// Zero dependencies: node:worker_threads + the engine under test.

import { parentPort } from 'node:worker_threads';
import { analyzeArtifacts } from '../src/analyze.js';

// Structured clone across the thread boundary turns each Buffer into a plain
// Uint8Array, which lacks Buffer methods the engine relies on (readUInt32BE,
// subarray().toString('hex'), …). Re-wrap as Buffers, zero-copy.
function rehydrate(map) {
  const out = new Map();
  for (const [k, v] of map) {
    out.set(k, Buffer.isBuffer(v) ? v : Buffer.from(v.buffer, v.byteOffset, v.byteLength));
  }
  return out;
}

parentPort.on('message', ({ fromFiles, toFiles, subject }) => {
  try {
    const v = analyzeArtifacts(rehydrate(fromFiles), rehydrate(toFiles), subject);
    parentPort.postMessage({
      ok: true,
      verdict: v.verdict,
      score: v.score,
      findings: v.findings.map((f) => ({ code: f.code, cap: f.cap, title: f.title, evidence: f.evidence })),
      stats: v.stats,
    });
  } catch (err) {
    parentPort.postMessage({ ok: false, error: err.message });
  }
});
