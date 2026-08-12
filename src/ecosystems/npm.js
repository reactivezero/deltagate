// npm adapter. Wraps the existing, unchanged npm behaviour behind the common
// adapter interface. The ecosystem-agnostic rules (opaque blob, native binary,
// invisible unicode, eval/obf/net) still live in heuristics.js and run for every
// ecosystem; manifestRules() here contributes only the *npm-specific* signals,
// with the exact cap values and logic copied verbatim from the original
// heuristics.js so behaviour is byte-for-byte unchanged.

import { fetchNpm } from '../loaders.js';

// NB: 'prepare' is intentionally excluded — it does NOT run when a package is
// installed as a normal registry dependency (only on git/local installs and at
// publish time), so flagging a changed `prepare` false-positives on routine
// build-tooling churn (e.g. tshy migrations in rimraf/glob). Real install-time
// worms (Shai-Hulud, keyv) use preinstall/postinstall.
const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall'];

// ── shared helpers (copied from heuristics.js to keep behaviour identical) ─────
function cap(code, capValue, severity, title, evidence) {
  return { code, cap: capValue, severity, title, evidence };
}
function trunc(s, n = 80) { s = String(s); return s.length > n ? s.slice(0, n) + '…' : s; }

function parseJson(profiles, path) {
  const p = profiles.get(path);
  if (!p || p.text == null) return null;
  try { return JSON.parse(p.text); } catch { return null; }
}

function isNonRegistrySpec(spec) {
  if (typeof spec !== 'string') return false;
  if (spec.includes('://')) return true;
  if (/^(git\+|git:|file:|github:|bitbucket:|gitlab:)/i.test(spec)) return true;
  // owner/repo shorthand — but not the npm: alias form
  if (!spec.startsWith('npm:') && /^[\w.-]+\/[\w.-]+/.test(spec)) return true;
  return false;
}

function allDeps(pkg) {
  return {
    ...(pkg?.dependencies || {}),
    ...(pkg?.optionalDependencies || {}),
    ...(pkg?.devDependencies || {}),
  };
}

// The opaque-blob criterion (same thresholds as the agnostic OPAQUE_BLOB_NEW rule).
// Recomputed here so the INSTALL_HOOK_WITH_BLOB combo stays self-contained.
function isOpaqueBlob(p) {
  return p && p.binary && !p.native && !p.media && p.size >= 50_000 && p.entropy >= 7.2;
}

/**
 * npm-specific manifest rules: R1 (install hooks), R3 (hook+blob combo) and
 * R6 (non-registry deps) from the original heuristics.js.
 * @param {Map<string,object>} fromP
 * @param {Map<string,object>} toP
 * @param {{added:string[],modified:string[],removed:string[]}} d
 * @returns {Array<object>} Findings
 */
function manifestRules(fromP, toP, d) {
  const findings = [];
  const add = (f) => findings.push(f);
  const changed = [...d.added, ...d.modified];

  const fromPkg = parseJson(fromP, 'package.json');
  const toPkg = parseJson(toP, 'package.json');

  // ── R1: install-time lifecycle hooks (Shai-Hulud, keyv, LiteLLM) ──────────
  const fromScripts = fromPkg?.scripts || {};
  const toScripts = toPkg?.scripts || {};
  let hookNew = false, hookMod = false;
  for (const h of INSTALL_HOOKS) {
    if (toScripts[h] && !fromScripts[h]) {
      hookNew = true;
      add(cap('INSTALL_HOOK_NEW', 25, 'high',
        `new "${h}" lifecycle script runs code on install`,
        [{ file: 'package.json', detail: `${h}: ${trunc(toScripts[h])}` }]));
    } else if (toScripts[h] && fromScripts[h] && toScripts[h] !== fromScripts[h]) {
      hookMod = true;
      add(cap('INSTALL_HOOK_MODIFIED', 30, 'medium',
        `existing "${h}" install script changed`,
        [{ file: 'package.json', detail: `${h}: ${trunc(toScripts[h])}` }]));
    }
  }

  // ── R3: the keyv signature — install hook + opaque blob together ──────────
  const opaque = changed.filter((path) => isOpaqueBlob(toP.get(path)));
  if ((hookNew || hookMod) && opaque.length) {
    add(cap('INSTALL_HOOK_WITH_BLOB', 8, 'critical',
      'install-time script paired with a new opaque blob — the classic dropper shape',
      [{ file: opaque[0], detail: 'runs on install and cannot be read' }]));
  }

  // ── R6: new non-registry dependency (PhantomRaven remote deps) ────────────
  const fromDeps = allDeps(fromPkg), toDeps = allDeps(toPkg);
  for (const [name, spec] of Object.entries(toDeps)) {
    if (fromDeps[name] === spec) continue;
    if (isNonRegistrySpec(spec)) {
      add(cap('NON_REGISTRY_DEP', 15, 'high',
        `dependency "${name}" resolves outside the registry — code fetched from ${trunc(spec)}`,
        [{ file: 'package.json', detail: `${name}: ${spec}` }]));
    }
  }

  return findings;
}

export default {
  name: 'npm',
  // fetchNpm already returns {bytes, digest, resolvedVersion, files} and verifies
  // dist.integrity, so it satisfies the adapter contract directly.
  async fetch(name, version) {
    return fetchNpm(name, version);
  },
  manifestRules,
};
