// Ways to get an artifact as a Map<path, Buffer>: from a local directory, or
// live from the npm registry (with integrity verification of the tarball bytes).

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { createHash } from 'node:crypto';
import { readNpmTarball } from './untar.js';

const SKIP_DIRS = new Set(['node_modules', '.git']);

/** Load a directory tree into Map<relativePath, Buffer>. */
export function loadDir(dir) {
  const files = new Map();
  const walk = (d) => {
    for (const name of readdirSync(d)) {
      const full = join(d, name);
      const st = statSync(full);
      if (st.isDirectory()) {
        if (!SKIP_DIRS.has(name)) walk(full);
      } else if (st.isFile()) {
        const rel = relative(dir, full).split(sep).join('/');
        files.set(rel, readFileSync(full));
      }
    }
  };
  walk(dir);
  return files;
}

async function getJson(url) {
  const res = await fetch(url, { headers: { accept: 'application/json' } });
  if (!res.ok) throw new Error(`registry ${res.status} for ${url}`);
  return res.json();
}

/**
 * Fetch one npm version's published tarball bytes, verifying dist.integrity.
 * @returns {{ bytes: Buffer, digest: string, resolvedVersion: string }}
 */
export async function fetchNpm(pkg, version) {
  const packument = await getJson(`https://registry.npmjs.org/${pkg}`);
  let v = version;
  if (!v || v === 'latest') v = packument['dist-tags']?.latest;
  const meta = packument.versions?.[v];
  if (!meta) throw new Error(`${pkg}@${v} not found in registry`);

  const res = await fetch(meta.dist.tarball);
  if (!res.ok) throw new Error(`tarball ${res.status} for ${pkg}@${v}`);
  const bytes = Buffer.from(await res.arrayBuffer());

  // Verify the bytes match what the registry metadata promised.
  const integrity = meta.dist.integrity;
  if (integrity?.startsWith('sha512-')) {
    const want = integrity.slice('sha512-'.length);
    const got = createHash('sha512').update(bytes).digest('base64');
    if (got !== want) throw new Error(`integrity mismatch for ${pkg}@${v}`);
  } else if (meta.dist.shasum) {
    const got = createHash('sha1').update(bytes).digest('hex');
    if (got !== meta.dist.shasum) throw new Error(`shasum mismatch for ${pkg}@${v}`);
  }

  const digest = 'sha256:' + createHash('sha256').update(bytes).digest('hex');
  return { bytes, digest, resolvedVersion: v, files: readNpmTarball(bytes) };
}
