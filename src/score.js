// Monotone fusion. The deterministic layer only sets ceilings, so the score is
// the MIN of every fired cap. (Phase 2 adds the LLM layer, which can lower the
// score further via typed findings but can never raise it above these caps.)

const THRESHOLD = 50; // block below this by default

export function fuse(findings) {
  const caps = findings.map((f) => f.cap).filter((c) => Number.isFinite(c));
  const score = caps.length ? Math.min(100, ...caps) : 100;

  let band;
  if (score < 25) band = 'block';
  else if (score < 50) band = 'hold';
  else if (score < 70) band = 'caution';
  else band = 'clear';

  const verdict = score < THRESHOLD ? 'HOLD' : 'ALLOW';

  // Deterministic findings are high-confidence evidence. A *clean* deterministic
  // result is only low-confidence here — it means "no red flags in the rules",
  // not "safe". The Phase-2 LLM layer supplies semantic judgment on clean diffs.
  const confidence = findings.length ? 'high' : 'low';

  return { score, band, verdict, confidence, threshold: THRESHOLD };
}

export { THRESHOLD };
