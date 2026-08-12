// Local enforcement, part 2: an sfw-style command wrapper.
//
// Runs a package-manager command with its registry pointed at the DeltaGate
// proxy for THIS child process only. Nothing is written to disk — the override
// lives in the child's environment and dies with it — so `deltagate run -- npm i`
// is a zero-persistence, opt-in way to install through the gate.

import { spawn } from 'node:child_process';

/**
 * Spawn a package-manager command with its registry redirected to the proxy.
 * @param {string[]} argv the command + args, e.g. ['npm','install','left-pad']
 * @param {{registryUrl:string}} opts the DeltaGate proxy URL
 * @returns {Promise<{code:number, signal:string|null}>} the child's exit status
 */
export function runWrapped(argv, { registryUrl } = {}) {
  if (!Array.isArray(argv) || argv.length === 0) {
    throw new Error('runWrapped needs a non-empty argv, e.g. ["npm","install"]');
  }
  if (!registryUrl) throw new Error('runWrapped needs { registryUrl }');

  const [command, ...args] = argv;

  // Cover the common clients in one shot. Each reads a different env var, but all
  // of them are process-scoped, so setting the lot is harmless and only the one
  // the child actually is will take effect.
  const env = {
    ...process.env,
    npm_config_registry: registryUrl,       // npm, npx, pnpm
    YARN_REGISTRY: registryUrl,             // yarn classic (v1)
    YARN_NPM_REGISTRY_SERVER: registryUrl,  // yarn berry (v2+)
  };

  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      env,
      stdio: 'inherit',                       // the user drives the install directly
      shell: process.platform === 'win32',    // npm/pnpm/yarn are .cmd shims on Windows
    });
    child.on('error', reject);                // e.g. command not found
    child.on('close', (code, signal) => resolve({ code: code ?? 0, signal }));
  });
}
