// The publishable verdict RECORD — the unit of the open verdict database.
//
// DeltaGate's premise is "one analysis serves everyone": once anybody analyses
// pkg X from→to, the signed result can be shared so nobody else re-runs the
// engine. That only works if the record is (a) content-addressed by the subject
// so any client computes the same lookup key, (b) reproducible so its id doesn't
// depend on WHEN it was analysed, and (c) free of attacker-controlled free text.
//
// (c) is the security crux: findings[].title and findings[].evidence[].detail are
// derived from the artifact under analysis — i.e. from data an attacker publishes.
// Copying that text into a record that is then replayed into other users' terminals
// (or an LLM's context) is a second-order injection vector. So a record stores only
// the finding CODE plus its numeric caps/penalties/severity — the machine-checkable
// skeleton — and never the human-readable strings.

import { createHash } from 'node:crypto';

const sha256hex = (s) => createHash('sha256').update(s).digest('hex');

// Subject fields that make up a record's identity, in a fixed order.
const SUBJECT_FIELDS = ['ecosystem', 'name', 'from', 'to', 'fromDigest', 'toDigest'];

/** Copy only the known, defined subject fields (drops undefined/null noise). */
function pickSubject(subject = {}) {
  const out = {};
  for (const k of SUBJECT_FIELDS) {
    if (subject[k] !== undefined && subject[k] !== null) out[k] = subject[k];
  }
  return out;
}

/**
 * Stable content-address for an update. sha256 hex of the canonical join key
 *   ecosystem|name|from|to|fromDigest|toDigest
 * Digests pin the exact bytes, so two publishers of the same tarball agree on the
 * key. When digests are absent (e.g. the 'dir' ecosystem, which has no registry
 * bytes) we fall back to ecosystem|name|from|to so the key is still deterministic.
 * @param {object} subject
 * @returns {string} 64-char hex
 */
export function subjectKey(subject = {}) {
  const { ecosystem = '', name = '', from = '', to = '', fromDigest, toDigest } = subject;
  const parts = (fromDigest || toDigest)
    ? [ecosystem, name, from, to, fromDigest || '', toDigest || '']
    : [ecosystem, name, from, to];
  return sha256hex(parts.join('|'));
}

/**
 * Deterministic canonical JSON: recursively sort object keys so semantically
 * equal objects serialise identically (arrays keep their order). Used to hash a
 * record into a stable id regardless of property insertion order.
 * @param {*} obj
 * @returns {string}
 */
export function canonicalize(obj) {
  if (obj === undefined) return 'null'; // records never carry undefined; be safe
  if (Array.isArray(obj)) return '[' + obj.map(canonicalize).join(',') + ']';
  if (obj && typeof obj === 'object') {
    const keys = Object.keys(obj).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(obj[k])).join(',') + '}';
  }
  return JSON.stringify(obj); // string | number | boolean | null
}

/**
 * Build a canonical, publishable record from a verdict.
 *
 * PURE by design: `ts` (the ISO timestamp) is passed in by the caller, never read
 * from the clock here, so the same verdict always yields the same record — which
 * keeps recordId() reproducible. Thread `new Date().toISOString()` at the call
 * site (see integration notes), not inside this function.
 *
 * @param {object} verdict a verdict record from analyzeArtifacts/analyzeArtifactsAI
 * @param {string} ts ISO timestamp supplied by the caller
 * @returns {object} the deltagate.verdict.v1 record
 */
export function makeRecord(verdict, ts) {
  const subject = pickSubject(verdict.subject);
  // Strip every free-text field: keep only the machine-checkable skeleton.
  const findings = (verdict.findings || []).map((f) => {
    const rec = { code: f.code, severity: f.severity };
    if (Number.isFinite(f.cap)) rec.cap = f.cap;
    if (Number.isFinite(f.penalty)) rec.penalty = f.penalty;
    return rec;
  });
  return {
    schema: 'deltagate.verdict.v1',
    subjectKey: subjectKey(subject),
    subject,
    score: verdict.score,
    band: verdict.band,
    verdict: verdict.verdict,
    confidence: verdict.confidence,
    findings,
    engine: verdict.engine,
    ts,
  };
}

/**
 * Stable id of a record: sha256 of its canonical JSON with `ts` removed, so the
 * id depends on WHAT was decided, not WHEN. Two records of the same update made a
 * week apart share an id — the property that lets caches dedupe and lets a signer
 * sign the decision rather than the moment.
 * @param {object} record
 * @returns {string} 64-char hex
 */
export function recordId(record) {
  const { ts, ...rest } = record; // eslint-disable-line no-unused-vars
  return sha256hex(canonicalize(rest));
}
