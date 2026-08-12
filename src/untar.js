// Minimal, dependency-free tar reader for npm package tarballs.
// npm publishes a gzipped tar where every entry is prefixed with "package/".
// We handle regular files, GNU long names ('L'), and pax extended headers ('x'),
// which npm's own tar writer emits for long paths / large files.

import { gunzipSync } from 'node:zlib';

const BLOCK = 512;

function readString(buf, off, len) {
  let end = off;
  const max = off + len;
  while (end < max && buf[end] !== 0) end++;
  return buf.toString('utf8', off, end);
}

// tar size fields are octal ASCII, but GNU may use base-256 (high bit set) for big files.
function readSize(buf, off, len) {
  if (buf[off] & 0x80) {
    let n = 0;
    for (let i = off + 1; i < off + len; i++) n = n * 256 + buf[i];
    return n;
  }
  const s = readString(buf, off, len).trim();
  return s ? parseInt(s, 8) : 0;
}

function parsePax(data) {
  // records: "<len> key=value\n"
  const out = {};
  const text = data.toString('utf8');
  let i = 0;
  while (i < text.length) {
    let sp = text.indexOf(' ', i);
    if (sp < 0) break;
    const recLen = parseInt(text.slice(i, sp), 10);
    if (!Number.isFinite(recLen) || recLen <= 0) break;
    const rec = text.slice(sp + 1, i + recLen - 1); // drop trailing \n
    const eq = rec.indexOf('=');
    if (eq > 0) out[rec.slice(0, eq)] = rec.slice(eq + 1);
    i += recLen;
  }
  return out;
}

/**
 * @param {Buffer} tgz gzipped tarball bytes
 * @returns {Map<string, Buffer>} path (with leading "package/" stripped) -> file bytes
 */
export function readNpmTarball(tgz) {
  const buf = gunzipSync(tgz);
  const files = new Map();
  let off = 0;
  let longName = null; // from 'L'
  let paxOverrides = null; // from 'x'

  while (off + BLOCK <= buf.length) {
    // A header of all-zero bytes marks the end.
    if (buf[off] === 0 && buf[off + 1] === 0 && buf[off + 2] === 0) break;

    const type = String.fromCharCode(buf[off + 156]);
    const size = readSize(buf, off + 124, 12);
    let name = readString(buf, off, 100);
    const prefix = readString(buf, off + 345, 155);
    if (prefix) name = prefix + '/' + name;

    const dataStart = off + BLOCK;
    const data = buf.subarray(dataStart, dataStart + size);
    const padded = Math.ceil(size / BLOCK) * BLOCK;

    if (type === 'L') {
      longName = readString(data, 0, data.length);
    } else if (type === 'x' || type === 'g') {
      paxOverrides = parsePax(data);
    } else if (type === '0' || type === '\0' || type === '') {
      let path = paxOverrides?.path || longName || name;
      path = path.replace(/^\.?\//, '').replace(/^package\//, '');
      if (path && !path.endsWith('/')) files.set(path, Buffer.from(data));
      longName = null;
      paxOverrides = null;
    } else {
      // directories ('5'), symlinks ('2'), etc. — ignored for analysis, but a
      // reset so overrides don't leak onto the wrong entry.
      longName = null;
      paxOverrides = null;
    }

    off = dataStart + padded;
  }
  return files;
}
