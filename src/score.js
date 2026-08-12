// Monotone fusion. The deterministic layer only sets ceilings, so the score is
// the MIN of every fired cap. (Phase 2 adds the LLM layer, which can lower the
// score further via typed findings but can never raise it above these caps.)

const THRESHOLD = 50; // block below this by default

export function fuse(findings, opts = {}) {
  // Both caps (ceilings) and penalties (deductions) only ever LOWER the score.
  // Sentinel and the AI layer both feed findings here; neither can raise it.
  const caps = findings.map((f) => f.cap).filter((c) => Number.isFinite(c));
  const penalty = findings.reduce((s, f) => s + (Number.isFinite(f.penalty) ? f.penalty : 0), 0);
  const base = 100 - penalty;
  const score = Math.max(0, Math.min(base, caps.length ? Math.min(...caps) : 100));

  let band;
  if (score < 25) band = 'block';
  else if (score < 50) band = 'hold';
  else if (score < 70) band = 'caution';
  else band = 'clear';

  const verdict = score < THRESHOLD ? 'HOLD' : 'ALLOW';

  // A clean *deterministic-only* result is low-confidence — it means "no rule
  // flags", not "safe". A reliable AI pass supplies the semantic judgment that
  // makes a clean verdict trustworthy; any finding is high-confidence evidence.
  const confidence = (opts.aiReliable || findings.length) ? 'high' : 'low';

  return { score, band, verdict, confidence, threshold: THRESHOLD };
}

export { THRESHOLD };
