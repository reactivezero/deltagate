// Dependency-free multi-format artifact unpacker. Every ecosystem ships its
// package as either a gzipped tar (npm .tgz, PyPI sdist, Cargo .crate, the inner
// data.tar.gz of a RubyGems .gem) or a ZIP (PyPI wheels, .jar, .nupkg). Both are
// read here with nothing but node:zlib — a supply-chain tool must not itself pull
// in a tar/zip dependency.
//
// Two guards apply to every extracted entry:
//   • zip-slip / path-traversal — absolute paths and any ".." segment are dropped
//     so a malicious archive can never point an entry outside the tree.
//   • decompression bomb — expansion is capped (MAX_TOTAL) both cumulatively and
//     per-entry (via zlib's maxOutputLength), so a tiny archive can't exhaust RAM.

import { gunzipSync, inflateRawSync } from 'node:zlib';

const BLOCK = 512;
const MAX_TOTAL = 512 * 1024 * 1024; // 512 MB expanded, across the whole archive

// ── path safety ───────────────────────────────────────────────────────────────
// Normalise separators, then reject absolute paths and any ".." traversal. Returns
// a clean forward-slash path, or null if the entry must be skipped.
function safePath(name) {
  if (!name) return null;
  let p = name.replace(/\\/g, '/').replace(/^\.?\//, '');
  if (!p || p.endsWith('/')) return null;                 // directory marker
  if (p.startsWith('/') || /^[a-zA-Z]:/.test(p)) return null; // absolute (posix / win)
  if (p.split('/').some((seg) => seg === '..')) return null;  // traversal
  return p;
}

// ── tar (uncompressed) ──────────────────────────────────────────────────────────
// A generic POSIX/GNU tar reader over already-decompressed bytes. Handles regular
// files, GNU long names ('L') and pax extended headers ('x'/'g') — the same forms
// npm's own tar writer (and most others) emit. Unlike untar.js this does NOT strip
// any "package/" prefix: it exposes raw entry paths so each ecosystem adapter can
// decide how to normalise them.
export function readTar(buf) {
  const files = new Map();
  let off = 0;
  let longName = null;    // pending GNU 'L' long-name
  let paxOverrides = null; // pending pax 'x' overrides
  let total = 0;

  while (off + BLOCK <= buf.length) {
    // An all-zero header block marks the end of the archive.
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
      const raw = paxOverrides?.path || longName || name;
      const path = safePath(raw);
      if (path) {
        total += size;
        if (total > MAX_TOTAL) throw new Error('tar exceeds expansion cap (possible decompression bomb)');
        files.set(path, Buffer.from(data));
      }
      longName = null;
      paxOverrides = null;
    } else {
      // directories ('5'), symlinks ('2'), etc. — skipped, but reset the pending
      // overrides so they can't leak onto the next entry.
      longName = null;
      paxOverrides = null;
    }

    off = dataStart + padded;
  }
  return files;
}

// tar size fields are octal ASCII, except GNU uses base-256 (high bit set) for big files.
function readSize(buf, off, len) {
  if (buf[off] & 0x80) {
    let n = 0;
    for (let i = off + 1; i < off + len; i++) n = n * 256 + buf[i];
    return n;
  }
  const s = readString(buf, off, len).trim();
  return s ? parseInt(s, 8) : 0;
}

function readString(buf, off, len) {
  let end = off;
  const max = Math.min(off + len, buf.length);
  while (end < max && buf[end] !== 0) end++;
  return buf.toString('utf8', off, end);
}

function parsePax(data) {
  // pax records are "<len> key=value\n"
  const out = {};
  const text = data.toString('utf8');
  let i = 0;
  while (i < text.length) {
    const sp = text.indexOf(' ', i);
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

// ── gzip + tar ──────────────────────────────────────────────────────────────────
/**
 * Read a gzipped tar into Map<path, Buffer>. Used for npm .tgz, PyPI sdists,
 * Cargo .crate files, and the inner data.tar.gz of a RubyGems .gem. Paths are raw
 * (no "package/" stripping) — callers normalise as they see fit. Defensive: if the
 * buffer is not actually gzip-framed it is treated as a plain tar.
 * @param {Buffer} buf
 * @returns {Map<string, Buffer>}
 */
export function unpackTarGz(buf) {
  const isGzip = buf.length > 2 && buf[0] === 0x1f && buf[1] === 0x8b;
  const tar = isGzip ? gunzipSync(buf, { maxOutputLength: MAX_TOTAL }) : buf;
  return readTar(tar);
}

// ── zip ───────────────────────────────────────────────────────────────────────
// A ZIP is a stream of local-file records followed by a central directory and an
// End-Of-Central-Directory (EOCD) record at the very end. We parse the central
// directory (the authoritative index) rather than the local headers, because entries
// that use a data descriptor carry zeroed sizes in their local header. Zip64 is
// handled at the per-entry level (sizes/offset promoted to 0xFFFFFFFF) and via the
// Zip64 EOCD record; multi-disk archives are not supported (irrelevant for packages).
const SIG_EOCD = 0x06054b50;   // PK\x05\x06
const SIG_EOCD64 = 0x06064b50; // PK\x06\x06
const SIG_LOC64 = 0x07064b50;  // PK\x06\x07
const SIG_CEN = 0x02014b50;    // PK\x01\x02

/**
 * @param {Buffer} buf raw .zip / .whl / .jar / .nupkg bytes
 * @returns {Map<string, Buffer>}
 */
export function unpackZip(buf) {
  const files = new Map();
  const eocd = findEOCD(buf);
  if (eocd < 0) throw new Error('not a zip: no End-Of-Central-Directory record found');

  let cdOffset = buf.readUInt32LE(eocd + 16);
  let cdCount = buf.readUInt16LE(eocd + 10);

  // Zip64: the 32-bit fields saturate to 0xFFFF / 0xFFFFFFFF and the real values live
  // in the Zip64 EOCD, located via the Zip64 EOCD locator that precedes the EOCD.
  if (cdOffset === 0xffffffff || cdCount === 0xffff) {
    const locPos = eocd - 20;
    if (locPos >= 0 && buf.readUInt32LE(locPos) === SIG_LOC64) {
      const z64 = Number(buf.readBigUInt64LE(locPos + 8));
      if (buf.readUInt32LE(z64) === SIG_EOCD64) {
        cdCount = Number(buf.readBigUInt64LE(z64 + 32));
        cdOffset = Number(buf.readBigUInt64LE(z64 + 48));
      }
    }
  }

  let ptr = cdOffset;
  let total = 0;
  for (let i = 0; i < cdCount && ptr + 46 <= buf.length; i++) {
    if (buf.readUInt32LE(ptr) !== SIG_CEN) break;

    const method = buf.readUInt16LE(ptr + 10);
    let compSize = buf.readUInt32LE(ptr + 20);
    let uncompSize = buf.readUInt32LE(ptr + 24);
    const nameLen = buf.readUInt16LE(ptr + 28);
    const extraLen = buf.readUInt16LE(ptr + 30);
    const commentLen = buf.readUInt16LE(ptr + 32);
    let localOff = buf.readUInt32LE(ptr + 42);
    const rawName = buf.toString('utf8', ptr + 46, ptr + 46 + nameLen);

    // Promote any saturated 32-bit fields from the Zip64 extended-info extra field
    // (header id 0x0001); its members appear in a fixed order, only for saturated fields.
    if (uncompSize === 0xffffffff || compSize === 0xffffffff || localOff === 0xffffffff) {
      const extraStart = ptr + 46 + nameLen;
      let e = extraStart;
      const extraEnd = extraStart + extraLen;
      while (e + 4 <= extraEnd) {
        const id = buf.readUInt16LE(e);
        const dsz = buf.readUInt16LE(e + 2);
        let f = e + 4;
        if (id === 0x0001) {
          if (uncompSize === 0xffffffff) { uncompSize = Number(buf.readBigUInt64LE(f)); f += 8; }
          if (compSize === 0xffffffff)   { compSize   = Number(buf.readBigUInt64LE(f)); f += 8; }
          if (localOff === 0xffffffff)   { localOff   = Number(buf.readBigUInt64LE(f)); f += 8; }
          break;
        }
        e += 4 + dsz;
      }
    }

    ptr += 46 + nameLen + extraLen + commentLen;

    const path = safePath(rawName);
    if (!path) continue; // directory entry or unsafe path

    // Locate the file data: the local header repeats name/extra lengths, which can
    // differ from the central-directory copy, so we read them fresh at localOff.
    if (localOff + 30 > buf.length) continue;
    const lNameLen = buf.readUInt16LE(localOff + 26);
    const lExtraLen = buf.readUInt16LE(localOff + 28);
    const dataStart = localOff + 30 + lNameLen + lExtraLen;

    total += uncompSize;
    if (total > MAX_TOTAL) throw new Error('zip exceeds expansion cap (possible decompression bomb)');

    const comp = buf.subarray(dataStart, dataStart + compSize);
    let out;
    if (method === 0) {
      out = Buffer.from(comp); // stored
    } else if (method === 8) {
      // raw DEFLATE; cap the output so a bomb can't blow past the declared size.
      out = inflateRawSync(comp, { maxOutputLength: Math.max(uncompSize, 1) + BLOCK });
    } else {
      throw new Error(`unsupported zip compression method ${method} for ${path}`);
    }
    files.set(path, out);
  }
  return files;
}

function findEOCD(buf) {
  // EOCD is 22 bytes plus a comment of up to 65535 bytes, so scan backwards.
  const min = Math.max(0, buf.length - 22 - 0xffff);
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf.readUInt32LE(i) === SIG_EOCD) return i;
  }
  return -1;
}

/*
  Self-test (dependency-free round-trip of a stored + a DEFLATE'd entry).
  Run with:  node -e "$(sed -n '/SELFTEST-START/,/SELFTEST-END/p' src/unpack.js | sed 's|^  //||')"

  // SELFTEST-START
  // import { deflateRawSync } from 'node:zlib';
  // import { unpackZip } from './src/unpack.js';
  //
  // // Build a minimal ZIP by hand: two entries, stored + deflated.
  // function le16(n){const b=Buffer.alloc(2);b.writeUInt16LE(n);return b;}
  // function le32(n){const b=Buffer.alloc(4);b.writeUInt32LE(n>>>0);return b;}
  // function entry(name, data, method){
  //   const nameB=Buffer.from(name);
  //   const body=method===8?deflateRawSync(data):data;
  //   const local=Buffer.concat([le32(0x04034b50),le16(20),le16(0),le16(method),
  //     le16(0),le16(0),le32(0),le32(body.length),le32(data.length),
  //     le16(nameB.length),le16(0),nameB,body]);
  //   return {name:nameB,data,body,method,local};
  // }
  // const e1=entry('a.txt', Buffer.from('hello stored'), 0);
  // const e2=entry('b/c.txt', Buffer.from('hello '.repeat(50)), 8);
  // let files=Buffer.concat([e1.local,e2.local]);
  // let cd=Buffer.alloc(0), off=0;
  // for(const e of [e1,e2]){
  //   const h=Buffer.concat([le32(0x02014b50),le16(20),le16(20),le16(0),le16(e.method),
  //     le16(0),le16(0),le32(0),le32(e.body.length),le32(e.data.length),
  //     le16(e.name.length),le16(0),le16(0),le16(0),le16(0),le32(0),le32(off),e.name]);
  //   cd=Buffer.concat([cd,h]); off+=e.local.length;
  // }
  // const eocd=Buffer.concat([le32(0x06054b50),le16(0),le16(0),le16(2),le16(2),
  //   le32(cd.length),le32(files.length),le16(0)]);
  // const zip=Buffer.concat([files,cd,eocd]);
  // const out=unpackZip(zip);
  // console.assert(out.get('a.txt').toString()==='hello stored','stored');
  // console.assert(out.get('b/c.txt').toString()==='hello '.repeat(50),'deflate');
  // console.log('unpack.js self-test OK', [...out.keys()]);
  // SELFTEST-END
*/
