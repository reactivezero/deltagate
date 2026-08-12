// Sentinel — the deterministic rule layer. Each fired rule emits a score CEILING
// (cap). Ceilings compose by MIN downstream, so no AI or vote can lift them.
//
// This file holds the ECOSYSTEM-AGNOSTIC rules (opaque blobs, native binaries,
// invisible unicode, decode-then-exec / packing / network+exec). The per-ecosystem
// install/build-hook and dependency rules live in each adapter's manifestRules()
// (src/ecosystems/*) and are injected here via the `adapter` argument.

const CODE_RE = /\.(c?js|mjs|jsx|tsx?|json)$/i;

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

/**
 * @param {Map<string,object>} fromP  profileArtifact() of the installed version
 * @param {Map<string,object>} toP    profileArtifact() of the candidate version
 * @param {object|null} adapter       ecosystem adapter (provides manifestRules)
 * @returns {Array<Finding>}
 */
export function runSentinel(fromP, toP, adapter = null) {
  const findings = [];
  const { added, modified, removed } = deltas(fromP, toP);
  const changed = [...added, ...modified];
  const add = (f) => findings.push(f);

  // ── R2: new opaque/encrypted blob (keyv 727KB second stage) ───────────────
  for (const path of changed) {
    const p = toP.get(path);
    if (p.binary && !p.native && !p.media && p.size >= 50_000 && p.entropy >= 7.2) {
      add(cap('OPAQUE_BLOB_NEW', 20, 'high',
        `new ${kb(p.size)} high-entropy blob (${p.entropy.toFixed(2)} bits/byte) — unreadable, so unauditable`,
        [{ file: path, detail: `${kb(p.size)}, entropy ${p.entropy.toFixed(2)}` }]));
    }
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

  // ── R7: decode-then-execute + fetch-then-execute droppers ─────────────────
  const evalDecode = /\b(eval|new\s+Function)\s*\(\s*(atob|unescape|decodeURIComponent|Buffer\.from|String\.fromCharCode)/;
  const netApi = /require\(\s*['"](https?|node:https?|node-fetch|axios|got|undici)['"]|\bfetch\s*\(|XMLHttpRequest/;
  const execApi = /require\(\s*['"](child_process|node:child_process)['"]|\b(exec|execSync|spawn|spawnSync|fork)\s*\(/;
  // NB: requires 40+ CONSECUTIVE \x escapes. The earlier form used `.*` between
  // escapes, which caused catastrophic backtracking (ReDoS) that hung the CLI on
  // large minified bundles — this form is linear.
  const packed = /(?:\\x[0-9a-f]{2}){40,}|_0x[0-9a-f]{4,}/i;
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
      // Only flag obfuscation that NEWLY appears — a package that already shipped
      // a minified/packed bundle in the prior version (prettier's vendored
      // plugins, etc.) isn't a signal; obfuscation injected into a previously
      // readable file is (the chalk/debug clipper).
      const ft = fromP.get(path)?.text;
      const wasPacked = ft != null && packed.test(ft) && longestLine(ft) > 3000;
      if (!wasPacked) {
        add(cap('OBFUSCATION_PACKED', 45, 'medium',
          'code became obfuscated/packed in this version (hex-escape or _0x string arrays on very long lines)',
          [{ file: path, detail: `longest line ${longestLine(t)} chars` }]));
      }
    }
    if (netApi.test(t) && execApi.test(t) && added.includes(path)) {
      add(cap('NET_PLUS_EXEC', 30, 'high',
        'new file both fetches from the network and executes commands — remote-payload loader shape',
        [{ file: path, detail: 'network + child_process in one added file' }]));
    }
  }

  // ── ecosystem-specific install/build-hook + dependency rules ──────────────
  if (adapter?.manifestRules) {
    findings.push(...adapter.manifestRules(fromP, toP, { added, modified, removed }));
  }

  return findings;
}

// ── helpers ─────────────────────────────────────────────────────────────────
function cap(code, capValue, severity, title, evidence) {
  return { code, cap: capValue, severity, title, evidence };
}
function kb(bytes) { return (bytes / 1024).toFixed(0) + ' KB'; }
function longestLine(t) { let m = 0; for (const l of t.split('\n')) if (l.length > m) m = l.length; return m; }
