// Per-file analysis over RAW BYTES (never rendered text). Produces a compact
// "profile" the heuristics layer reasons about. This is the layer that makes
// GlassWorm-style invisible-unicode and keyv-style opaque blobs visible.

import { createHash } from 'node:crypto';

// Invisible / format / bidi codepoints that have no business in source code.
function invisibleCodepoints(text) {
  const hits = [];
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    const bad =
      (cp >= 0x200b && cp <= 0x200f) || // zero-width + LRM/RLM
      (cp >= 0x202a && cp <= 0x202e) || // bidi embedding/override
      (cp >= 0x2066 && cp <= 0x2069) || // bidi isolates
      cp === 0x2060 || cp === 0xfeff || // word-joiner, BOM mid-file
      (cp >= 0xfe00 && cp <= 0xfe0f) || // variation selectors
      (cp >= 0xe0000 && cp <= 0xe007f); // tags block (GlassWorm)
    if (bad) hits.push('U+' + cp.toString(16).toUpperCase().padStart(4, '0'));
    if (hits.length > 12) break;
  }
  return hits;
}

function shannonEntropy(buf) {
  if (buf.length === 0) return 0;
  const freq = new Array(256).fill(0);
  for (let i = 0; i < buf.length; i++) freq[buf[i]]++;
  let e = 0;
  for (let i = 0; i < 256; i++) {
    if (!freq[i]) continue;
    const p = freq[i] / buf.length;
    e -= p * Math.log2(p);
  }
  return e; // 0..8 bits/byte
}

// Executable machine code that has no source form.
function nativeMagic(b) {
  if (b.length < 4) return null;
  if (b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return 'ELF';
  if (b[0] === 0x4d && b[1] === 0x5a) return 'PE';               // MZ
  if (b[0] === 0x00 && b[1] === 0x61 && b[2] === 0x73 && b[3] === 0x6d) return 'WASM';
  const u32 = b.readUInt32BE(0);
  if ([0xfeedface, 0xfeedfacf, 0xcafebabe, 0xcffaedfe, 0xcefaedfe].includes(u32)) return 'MachO';
  return null;
}

// Legitimate binary asset formats — high entropy but explainable, so NOT opaque.
function knownMediaMagic(b) {
  if (b.length < 4) return null;
  const h4 = b.subarray(0, 4).toString('hex');
  if (h4 === '89504e47') return 'PNG';
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'JPEG';
  if (b.subarray(0, 3).toString() === 'GIF') return 'GIF';
  if (b.subarray(0, 4).toString() === '%PDF') return 'PDF';
  if (b[0] === 0x50 && b[1] === 0x4b) return 'ZIP';
  if (b[0] === 0x1f && b[1] === 0x8b) return 'GZIP';
  if (b.subarray(0, 4).toString() === 'wOFF' || b.subarray(0, 4).toString() === 'wOF2') return 'WOFF';
  if (b.subarray(4, 8).toString() === 'ftyp') return 'MP4';
  if (b.subarray(0, 4).toString() === 'OggS') return 'OGG';
  return null;
}

function looksBinary(buf) {
  const n = Math.min(buf.length, 8000);
  if (n === 0) return false;
  let nonText = 0;
  for (let i = 0; i < n; i++) {
    const c = buf[i];
    if (c === 0) return true; // NUL => definitely binary
    if (c < 9 || (c > 13 && c < 32)) nonText++;
  }
  return nonText / n > 0.15;
}

/** @param {string} path @param {Buffer} bytes */
export function profileFile(path, bytes) {
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  const native = nativeMagic(bytes);
  const media = knownMediaMagic(bytes);
  const binary = !!native || looksBinary(bytes);
  const entropy = shannonEntropy(bytes);

  let invisible = [];
  let text = null;
  if (!binary) {
    text = bytes.toString('utf8');
    invisible = invisibleCodepoints(text);
  }

  return {
    path,
    size: bytes.length,
    sha256,
    binary,
    native,        // 'ELF' | 'PE' | 'WASM' | 'MachO' | null
    media,         // 'PNG' | ... | null
    entropy,       // bits/byte
    invisible,     // list of invisible codepoints found in a text file
    text,          // decoded text, or null for binary
  };
}

/** Build a Map<path, profile> from a Map<path, Buffer>. */
export function profileArtifact(files) {
  const out = new Map();
  for (const [path, bytes] of files) out.set(path, profileFile(path, bytes));
  return out;
}

export { shannonEntropy };
