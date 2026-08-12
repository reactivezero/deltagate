// Sentinel — the deterministic rule layer. Each fired rule emits a score CEILING
// (cap). Ceilings compose by MIN downstream, so no AI or vote can lift them.
// Every rule traces to a real 2024–26 supply-chain attack.

const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare'];
const CODE_RE = /\.(c?js|mjs|jsx|tsx?|json)$/i;

function parseJson(profiles, path) {
  const p = profiles.get(path);
  if (!p || p.text == null) return null;
  try { return JSON.parse(p.text); } catch { return null; }
}

function deltas(from, to) {
  const added = [], modified = [], removed = [];
  for (const [path, tp] of to) {
    const fp = from.get(path);
    if (!fp) added.push(path);
    else if (fp.sha256 !== tp.sha256) modified.push(path);
  }
  for (const path of from.keys()) if (!to.has(path)) removed.push(path);
  return { added, modified, removed };
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

/**
 * @param {Map<string,object>} fromP  profileArtifact() of the installed version
 * @param {Map<string,object>} toP    profileArtifact() of the candidate version
 * @returns {Array<Finding>}
 */
export function runSentinel(fromP, toP) {
  const findings = [];
  const { added, modified } = deltas(fromP, toP);
  const changed = [...added, ...modified];
  const add = (f) => findings.push(f);

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

  // ── R2: new opaque/encrypted blob (keyv 727KB second stage) ───────────────
  const opaque = [];
  for (const path of changed) {
    const p = toP.get(path);
    if (p.binary && !p.native && !p.media && p.size >= 50_000 && p.entropy >= 7.2) {
      opaque.push(path);
      add(cap('OPAQUE_BLOB_NEW', 20, 'high',
        `new ${kb(p.size)} high-entropy blob (${p.entropy.toFixed(2)} bits/byte) — unreadable, so unauditable`,
        [{ file: path, detail: `${kb(p.size)}, entropy ${p.entropy.toFixed(2)}` }]));
    }
  }

  // ── R3: the keyv signature — install hook + opaque blob together ──────────
  if ((hookNew || hookMod) && opaque.length) {
    add(cap('INSTALL_HOOK_WITH_BLOB', 8, 'critical',
      'install-time script paired with a new opaque blob — the classic dropper shape',
      [{ file: opaque[0], detail: 'runs on install and cannot be read' }]));
  }

  // ── R4: first native machine-code binary in a source package ──────────────
  const fromHasNative = [...fromP.values()].some((p) => p.native);
  for (const path of added) {
    const p = toP.get(path);
    if (p.native && !fromHasNative) {
      add(cap('NATIVE_BINARY_NEW', 25, 'high',
        `new ${p.native} native binary added to a source-only package`,
        [{ file: path, detail: `${p.native}, ${kb(p.size)}` }]));
    }
  }

  // ── R5: invisible / bidi unicode in code (GlassWorm) ──────────────────────
  for (const path of changed) {
    const p = toP.get(path);
    if (CODE_RE.test(path) && p.invisible?.length) {
      add(cap('INVISIBLE_UNICODE', 10, 'high',
        `invisible/bidi unicode hidden in code (${p.invisible.slice(0, 4).join(', ')}…)`,
        [{ file: path, detail: `${p.invisible.length} hidden codepoints` }]));
    }
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

  // ── R7: decode-then-execute + fetch-then-execute droppers ─────────────────
  const evalDecode = /\b(eval|new\s+Function)\s*\(\s*(atob|unescape|decodeURIComponent|Buffer\.from|String\.fromCharCode)/;
  const netApi = /require\(\s*['"](https?|node:https?|node-fetch|axios|got|undici)['"]|\bfetch\s*\(|XMLHttpRequest/;
  const execApi = /require\(\s*['"](child_process|node:child_process)['"]|\b(exec|execSync|spawn|spawnSync|fork)\s*\(/;
  const packed = /\\x[0-9a-f]{2}(?:.*\\x[0-9a-f]{2}){40,}|_0x[0-9a-f]{4,}/i;
  for (const path of changed) {
    if (!CODE_RE.test(path) || path.endsWith('.json')) continue;
    const p = toP.get(path);
    const t = p.text;
    if (t == null) continue;
    if (evalDecode.test(t)) {
      add(cap('EVAL_DECODE_EXEC', 20, 'high',
        'decodes a string and executes it (eval/Function of atob/Buffer/fromCharCode)',
        [{ file: path, detail: 'decode-then-exec' }]));
    } else if (packed.test(t) && longestLine(t) > 3000) {
      add(cap('OBFUSCATION_PACKED', 45, 'medium',
        'heavily obfuscated / packed code (hex-escape or _0x string arrays on very long lines)',
        [{ file: path, detail: `longest line ${longestLine(t)} chars` }]));
    }
    if (netApi.test(t) && execApi.test(t) && (added.includes(path))) {
      add(cap('NET_PLUS_EXEC', 30, 'high',
        'new file both fetches from the network and executes commands — remote-payload loader shape',
        [{ file: path, detail: 'network + child_process in one added file' }]));
    }
  }

  return findings;
}

// ── helpers ─────────────────────────────────────────────────────────────────
function cap(code, capValue, severity, title, evidence) {
  return { code, cap: capValue, severity, title, evidence };
}
function trunc(s, n = 80) { s = String(s); return s.length > n ? s.slice(0, n) + '…' : s; }
function kb(bytes) { return (bytes / 1024).toFixed(0) + ' KB'; }
function longestLine(t) { let m = 0; for (const l of t.split('\n')) if (l.length > m) m = l.length; return m; }
