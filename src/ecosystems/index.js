// Ecosystem registry. Each adapter default-exports an object of the shape:
//   { name,
//     async fetch(name, version) -> { bytes, digest, resolvedVersion, files:Map<path,Buffer> },
//     manifestRules(fromProfiles, toProfiles, {added, modified, removed}) -> Finding[] }
// The agnostic Sentinel rules (opaque blob, native binary, invisible unicode,
// eval/obf/net) live in heuristics.js and run for every ecosystem; each adapter's
// manifestRules only adds its ecosystem-specific install/build-time signals.

import npm from './npm.js';
import pypi from './pypi.js';
import cargo from './cargo.js';
import rubygems from './rubygems.js';

const ADAPTERS = { npm, pypi, cargo, rubygems };

/** @param {string} ecosystem one of 'npm' | 'pypi' | 'cargo' | 'rubygems' */
export function getAdapter(ecosystem) {
  const a = ADAPTERS[ecosystem];
  if (!a) throw new Error(`unknown ecosystem "${ecosystem}" (have: ${Object.keys(ADAPTERS).join(', ')})`);
  return a;
}

/** @returns {Array<object>} every registered adapter */
export function listAdapters() {
  return Object.values(ADAPTERS);
}
