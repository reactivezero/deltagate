// Orchestrator: two artifacts (as Map<path,Buffer>) -> a verdict record.
// The deterministic Sentinel layer always runs. The AI layer is optional and
// async; its findings are merged in and can only lower the score.

import { profileArtifact } from './normalize.js';
import { runSentinel } from './heuristics.js';
import { fuse } from './score.js';
import { fetchNpm } from './loaders.js';
import { analyzeDiffWithAI } from './ai/index.js';

function delta(from, to) {
  const added = [], modified = [], removed = [];
  for (const [p, tp] of to) {
    const fp = from.get(p);
    if (!fp) added.push(p);
    else if (fp.sha256 !== tp.sha256) modified.push(p);
  }
  for (const p of from.keys()) if (!to.has(p)) removed.push(p);
  return { added, modified, removed };
}

// most-damning first: hard caps (low) before big penalties
const rank = (f) => (Number.isFinite(f.cap) ? f.cap : 100 - (f.penalty || 0));

function assemble(subject, fromP, toP, findings, ai) {
  findings.sort((a, b) => rank(a) - rank(b));
  const result = fuse(findings, { aiReliable: ai?.reliable });
  const d = delta(fromP, toP);
  return {
    subject,
    ...result,
    findings,
    stats: { filesFrom: fromP.size, filesTo: toP.size, added: d.added.length, modified: d.modified.length, removed: d.removed.length },
    engine: {
      sentinel: 'v0.0.1',
      ai: ai ? { model: ai.model, ran: ai.ran, reliable: ai.reliable, flags: ai.flags, error: ai.error } : null,
    },
  };
}

/** Deterministic-only analysis (synchronous). */
export function analyzeArtifacts(fromFiles, toFiles, subject = {}) {
  const fromP = profileArtifact(fromFiles);
  const toP = profileArtifact(toFiles);
  return assemble(subject, fromP, toP, runSentinel(fromP, toP), null);
}

/** Deterministic + optional AI layer (async). opts: {ai, callModel, model, probe}. */
export async function analyzeArtifactsAI(fromFiles, toFiles, subject = {}, opts = {}) {
  const fromP = profileArtifact(fromFiles);
  const toP = profileArtifact(toFiles);
  const findings = runSentinel(fromP, toP);
  let ai = null;
  if (opts.ai) {
    const d = delta(fromP, toP);
    ai = await analyzeDiffWithAI(
      { toProfiles: toP, changed: [...d.added, ...d.modified], subject },
      { callModel: opts.callModel, model: opts.model, probe: opts.probe },
    );
    findings.push(...ai.findings);
  }
  return assemble(subject, fromP, toP, findings, ai);
}

/** Fetch two npm versions live and analyze them (AI optional via opts.ai). */
export async function analyzeNpm(name, fromVer, toVer, opts = {}) {
  const [from, to] = await Promise.all([fetchNpm(name, fromVer), fetchNpm(name, toVer)]);
  const subject = {
    ecosystem: 'npm', name,
    from: from.resolvedVersion, to: to.resolvedVersion,
    fromDigest: from.digest, toDigest: to.digest,
  };
  return analyzeArtifactsAI(from.files, to.files, subject, opts);
}
