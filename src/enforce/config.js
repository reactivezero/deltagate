// Local enforcement, part 3: reversible ~/.npmrc wiring for "always-on" mode.
//
// enable() points the global `registry=` line at the proxy; disable() undoes it.
// Every machine change is reversible and recorded in a manifest under
// DELTAGATE_HOME. Two restore paths:
//   • if the file is byte-for-byte as we left it, we restore the original bytes
//     verbatim (a true round-trip);
//   • if the user edited it after us, we surgically undo ONLY our line/block and
//     leave their edits untouched.
// We only ever touch the global `registry=` key — never `@scope:registry=` lines.

import { readFileSync, writeFileSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { createHash } from 'node:crypto';

// Global registry key only. `@scope:registry=` lines start with '@' and won't match.
const REGISTRY_LINE = /^\s*registry\s*=/;
const BEGIN = '# deltagate:begin';
const END = '# deltagate:end';

// DELTAGATE_HOME is read at call time so tests can redirect it via the env var.
function home() { return process.env.DELTAGATE_HOME || join(homedir(), '.deltagate'); }
function manifestPath() { return join(home(), 'enforce-manifest.json'); }
function backupPath() { return join(home(), 'npmrc.backup'); }
function defaultNpmrc() { return join(homedir(), '.npmrc'); }
function sha256(buf) { return createHash('sha256').update(buf).digest('hex'); }

function readManifest() {
  const p = manifestPath();
  if (!existsSync(p)) return null;
  try { return JSON.parse(readFileSync(p, 'utf8')); } catch { return null; }
}

/**
 * Wire ~/.npmrc to the proxy and record how to undo it.
 * @param {string} registryUrl the DeltaGate proxy URL
 * @param {{npmrcPath?:string}} [opts] override the npmrc path (default ~/.npmrc)
 * @returns {object} the recorded manifest
 */
export function enable(registryUrl, opts = {}) {
  if (!registryUrl) throw new Error('enable() needs a registry URL');
  const npmrcPath = opts.npmrcPath || defaultNpmrc();
  mkdirSync(home(), { recursive: true });

  const existedBefore = existsSync(npmrcPath);
  const originalBuf = existedBefore ? readFileSync(npmrcPath) : Buffer.alloc(0);
  const originalText = originalBuf.toString('utf8');

  // Back up the exact original bytes so disable() can restore them verbatim.
  writeFileSync(backupPath(), originalBuf);

  const ourLine = `registry=${registryUrl}`;
  const lines = originalText.length ? originalText.split('\n') : [];
  let replacedLine = null, replaced = false;
  for (let i = 0; i < lines.length; i++) {
    if (REGISTRY_LINE.test(lines[i])) { replacedLine = lines[i]; lines[i] = ourLine; replaced = true; break; }
  }

  let newText;
  if (replaced) {
    newText = lines.join('\n');
  } else {
    // No existing registry line — append a clearly-marked block we can find later.
    const block = `${BEGIN}\n${ourLine}\n${END}\n`;
    newText = originalText.length && !originalText.endsWith('\n') ? originalText + '\n' + block : originalText + block;
  }

  const newBuf = Buffer.from(newText, 'utf8');
  writeFileSync(npmrcPath, newBuf);

  const manifest = {
    tool: 'deltagate', action: 'enforce',
    npmrcPath, registryUrl, ourLine,
    mode: replaced ? 'replaced' : 'added-block',
    replacedLine, existedBefore,
    backupPath: backupPath(),
    originalHash: sha256(originalBuf),
    newHash: sha256(newBuf),
    at: new Date().toISOString(),
  };
  writeFileSync(manifestPath(), JSON.stringify(manifest, null, 2));
  return manifest;
}

// User edited the file after us: undo only our own line/block, keep their edits.
function surgicalUndo(npmrcPath, text, manifest) {
  let lines = text.split('\n');
  if (manifest.mode === 'replaced') {
    for (let i = 0; i < lines.length; i++) {
      if (lines[i] === manifest.ourLine) {
        if (manifest.replacedLine != null) lines[i] = manifest.replacedLine;
        else lines.splice(i, 1);
        writeFileSync(npmrcPath, lines.join('\n'));
        return 'surgical-restored-line';
      }
    }
    return 'our-line-already-gone'; // user removed/changed it — nothing to undo
  }
  // added-block: drop the marker block if intact, else any bare copy of our line.
  const b = lines.indexOf(BEGIN), e = lines.indexOf(END);
  if (b !== -1 && e !== -1 && e >= b) lines.splice(b, e - b + 1);
  else lines = lines.filter((l) => l !== manifest.ourLine);
  writeFileSync(npmrcPath, lines.join('\n'));
  return 'surgical-removed-block';
}

/**
 * Undo whatever enable() did and clear the manifest.
 * @param {{npmrcPath?:string}} [opts]
 * @returns {{changed:boolean, outcome?:string, npmrcPath?:string, reason?:string}}
 */
export function disable(opts = {}) {
  const manifest = readManifest();
  if (!manifest) return { changed: false, reason: 'not enabled (no manifest)' };
  const npmrcPath = opts.npmrcPath || manifest.npmrcPath || defaultNpmrc();

  const currentBuf = existsSync(npmrcPath) ? readFileSync(npmrcPath) : Buffer.alloc(0);
  const untouched = sha256(currentBuf) === manifest.newHash;

  let outcome;
  if (untouched) {
    // Exactly as we left it — restore the original state precisely.
    if (manifest.existedBefore) {
      const backup = existsSync(manifest.backupPath) ? readFileSync(manifest.backupPath) : Buffer.alloc(0);
      writeFileSync(npmrcPath, backup);
      outcome = 'restored-from-backup';
    } else if (existsSync(npmrcPath)) {
      rmSync(npmrcPath); // we created the file — remove it
      outcome = 'removed-created-file';
    } else {
      outcome = 'nothing-to-do';
    }
  } else {
    outcome = surgicalUndo(npmrcPath, currentBuf.toString('utf8'), manifest);
  }

  if (existsSync(manifestPath())) rmSync(manifestPath());
  if (existsSync(backupPath())) rmSync(backupPath());
  return { changed: true, outcome, npmrcPath };
}

/**
 * Report the current wiring.
 * @param {{npmrcPath?:string}} [opts]
 * @returns {{enabled:boolean, npmrcPath:string, registryUrl:string|null,
 *            currentRegistry:string|null, tampered:boolean,
 *            manifestPath:string, backupPath:string|null}}
 */
export function status(opts = {}) {
  const manifest = readManifest();
  const npmrcPath = opts.npmrcPath || manifest?.npmrcPath || defaultNpmrc();
  const currentBuf = existsSync(npmrcPath) ? readFileSync(npmrcPath) : Buffer.alloc(0);

  let currentRegistry = null;
  for (const line of currentBuf.toString('utf8').split('\n')) {
    if (REGISTRY_LINE.test(line)) { currentRegistry = line.replace(REGISTRY_LINE, '').trim(); break; }
  }

  return {
    enabled: !!manifest,
    npmrcPath,
    registryUrl: manifest?.registryUrl || null,
    currentRegistry,
    // true if the file changed since we wrote it (disable will fall back to surgical undo)
    tampered: manifest ? sha256(currentBuf) !== manifest.newHash : false,
    manifestPath: manifestPath(),
    backupPath: manifest ? manifest.backupPath : null,
  };
}
