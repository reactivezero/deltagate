// Orchestrator: two artifacts (as Map<path,Buffer>) -> a verdict record.
// This is the shape that will one day be signed and published to the open DB.

import { profileArtifact } from './normalize.js';
import { runSentinel } from './heuristics.js';
import { fuse } from './score.js';
import { fetchNpm } from './loaders.js';

function delta(from, to) {
  let added = 0, modified = 0, removed = 0;
  for (const [p, tp] of to) {
    const fp = from.get(p);
    if (!fp) added++;
    else if (fp.sha256 !== tp.sha256) modified++;
  }
  for (const p of from.keys()) if (!to.has(p)) removed++;
  return { added, modified, removed };
}

/**
 * @param {Map<string,Buffer>} fromFiles
 * @param {Map<string,Buffer>} toFiles
 * @param {object} subject { ecosystem, name, from, to, fromDigest, toDigest }
 */
export function analyzeArtifacts(fromFiles, toFiles, subject = {}) {
  const fromP = profileArtifact(fromFiles);
  const toP = profileArtifact(toFiles);
  const findings = runSentinel(fromP, toP);
  findings.sort((a, b) => a.cap - b.cap); // most damning first
  const result = fuse(findings);

  return {
    subject,
    ...result, // score, band, verdict, confidence, threshold
    findings,
    stats: {
      filesFrom: fromP.size,
      filesTo: toP.size,
      ...delta(fromP, toP),
    },
    engine: { sentinel: 'v0.0.1', ai: null }, // Phase 2 fills in ai
  };
}

/** Convenience: fetch two npm versions live and analyze them. */
export async function analyzeNpm(name, fromVer, toVer) {
  const [from, to] = await Promise.all([fetchNpm(name, fromVer), fetchNpm(name, toVer)]);
  return analyzeArtifacts(from.files, to.files, {
    ecosystem: 'npm',
    name,
    from: from.resolvedVersion,
    to: to.resolvedVersion,
    fromDigest: from.digest,
    toDigest: to.digest,
  });
}
