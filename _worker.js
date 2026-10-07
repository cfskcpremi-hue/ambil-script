// =====================================================================
//  v1.12 - Muse VMess MultiProto (karya orisinal Muse untuk Kancil)
//  VMess AEAD PENUH di Cloudflare Pages/Worker: header + body terenkripsi
//  (AES-128-GCM & ChaCha20-Poly1305), chunk framing + SHAKE-128 masking,
//  bukan sekadar header seperti script nemu. Uji sandbox: klien VMess
//  AEAD independen (443/80, AES/ChaCha) tembus end-to-end.
//  Deploy: jadikan _worker.js di Pages. Atur USER_UUID di bawah.
//  Port 80 (NTLS) butuh "Always Use HTTPS" OFF di zona domain kamu.
// =====================================================================
import { connect } from "cloudflare:sockets";

const USER_UUID = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

// ===== DAFTAR BUG HOST =====
// Tambah bug host baru: tulis satu baris baru di dalam kurung [ ] ini,
// apit tanda kutip dan akhiri koma. Contoh baris:  "live.iflix.com",
// Daftar ini yang muncul sebagai pilihan Preset di dashboard.
const BUG_HOST_LIST = [
  "support.zoom.us",
  "api.quipper.com",
  "m.whatsapp.com",
  "investors.spotify.com",
]; // UUID akun VMess (samakan dengan di dashboard)
const DOH_ENDPOINT = "https://1.1.1.1/dns-query";
const USER_UUID_BYTES = parseUUID(USER_UUID);
// Daftar proxy user (dari sc-v8_1): path /nama -> IP:Port tujuan cadangan.
const PROXY_MAP = {
  "id-dnva": "103.169.207.189:443",
  "id-amazon": "16.79.55.124:443",
  "id-biznet": "139.190.97.223:443",
  "id-nusa": "110.232.84.159:2053",
  "id-idc": "103.193.179.158:443",
  "id-mora": "103.54.217.41:10688",
  "id-telkom": "43.173.1.153:8443",
  "id-rajasa": "119.235.252.35:46260",
  "id-ceo": "118.151.222.66:17317",
  "id-rmweb": "203.175.11.90:9443",
  "id-deneva": "202.155.95.132:443",
  "id-akamai": "172.232.249.224:2053",
  "sg-akamai": "104.64.192.116:443",
  "sg-amazon": "13.250.19.142:443",
  "sg-contabo": "194.233.85.147:443",
  "sg-oracle": "138.2.64.229:443",
  "sg-ovh": "51.79.177.53:443"
};

const VERSION_LABEL = "v1.12 - Muse VMess MultiProto";

// ---------------- util byte ----------------
const TE = new TextEncoder(), TD = new TextDecoder();
function cat(...arrs) {
  let n = 0; for (const a of arrs) n += a.length;
  const out = new Uint8Array(n); let p = 0;
  for (const a of arrs) { out.set(a, p); p += a.length; }
  return out;
}
function u16be(n) { return new Uint8Array([(n >> 8) & 255, n & 255]); }
function rdU16(b, i) { return (b[i] << 8) | b[i + 1]; }
function parseUUID(s) {
  const h = String(s).replace(/-/g, "");
  if (!/^[0-9a-fA-F]{32}$/.test(h)) throw new Error("UUID tidak valid");
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

// ---------------- MD5 (murni JS; WebCrypto tidak punya MD5) ----------------
function md5(bytes) {
  const S = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
  const K = [];
  for (let i = 0; i < 64; i++) K.push(Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296));
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const L = bytes.length, padLen = ((56 - (L + 1) % 64) + 64) % 64;
  const msg = new Uint8Array(L + 1 + padLen + 8);
  msg.set(bytes); msg[L] = 0x80;
  const dv = new DataView(msg.buffer);
  dv.setUint32(msg.length - 8, (L * 8) >>> 0, true);
  dv.setUint32(msg.length - 4, Math.floor(L / 536870912) >>> 0, true);
  const rot = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
  for (let off = 0; off < msg.length; off += 64) {
    const M = new Uint32Array(16);
    for (let i = 0; i < 16; i++) M[i] = dv.getUint32(off + i * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i] + M[g]) >>> 0;
      A = D; D = C; C = B; B = (B + rot(F, S[i])) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const out = new Uint8Array(16), ov = new DataView(out.buffer);
  ov.setUint32(0, a0, true); ov.setUint32(4, b0, true); ov.setUint32(8, c0, true); ov.setUint32(12, d0, true);
  return out;
}

// ---------------- SHA-256 + HMAC (murni JS) ----------------
const SHA256_K = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
function sha256(bytes) {
  const H = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
  const rr = (x, n) => (x >>> n) | (x << (32 - n));
  const L = bytes.length, padLen = ((56 - (L + 1) % 64) + 64) % 64;
  const msg = new Uint8Array(L + 1 + padLen + 8);
  msg.set(bytes); msg[L] = 0x80;
  new DataView(msg.buffer).setUint32(msg.length - 4, (L * 8) >>> 0, false);
  const W = new Uint32Array(64);
  for (let off = 0; off < msg.length; off += 64) {
    const blk = new DataView(msg.buffer, off, 64);
    for (let t = 0; t < 16; t++) W[t] = blk.getUint32(t * 4, false);
    for (let t = 16; t < 64; t++) {
      const s0 = rr(W[t-15],7) ^ rr(W[t-15],18) ^ (W[t-15] >>> 3);
      const s1 = rr(W[t-2],17) ^ rr(W[t-2],19) ^ (W[t-2] >>> 10);
      W[t] = (W[t-16] + s0 + W[t-7] + s1) >>> 0;
    }
    let [a,b,c,d,e,f,g,h] = H;
    for (let t = 0; t < 64; t++) {
      const S1 = rr(e,6) ^ rr(e,11) ^ rr(e,25), ch = (e & f) ^ (~e & g);
      const T1 = (h + S1 + ch + SHA256_K[t] + W[t]) >>> 0;
      const S0 = rr(a,2) ^ rr(a,13) ^ rr(a,22), maj = (a & b) ^ (a & c) ^ (b & c);
      const T2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + T1) >>> 0; d = c; c = b; b = a; a = (T1 + T2) >>> 0;
    }
    H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
    H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
  }
  const out = new Uint8Array(32), ov = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) ov.setUint32(i * 4, H[i], false);
  return out;
}
function hmacSha256(key, data) {
  let k = key;
  if (k.length > 64) k = sha256(k);
  const ik = new Uint8Array(64).fill(0x36), ok = new Uint8Array(64).fill(0x5c);
  for (let i = 0; i < k.length; i++) { ik[i] ^= k[i]; ok[i] ^= k[i]; }
  return sha256(cat(ok, sha256(cat(ik, data))));
}
// KDF VMess AEAD: HMAC berantai persis v2ray-core (jalur digabung satu per satu)
function vmessKDF(key, ...paths) {
  let digest = (data) => hmacSha256(TE.encode("VMess AEAD KDF"), data);
  for (const p of paths) {
    const prev = digest, pk = typeof p === "string" ? TE.encode(p) : p;
    digest = (data) => {
      const ik = new Uint8Array(64).fill(0x36), ok = new Uint8Array(64).fill(0x5c);
      let kk = pk; if (kk.length > 64) kk = sha256(kk);
      for (let i = 0; i < kk.length; i++) { ik[i] ^= kk[i]; ok[i] ^= kk[i]; }
      return prev(cat(ok, prev(cat(ik, data))));
    };
  }
  return digest(key);
}

// ---------------- SHAKE-128 (Keccak murni JS, untuk masking chunk) ----------------
class Shake128 {
  constructor(seed) {
    this.s = new Array(25).fill(0n);
    const rate = 168, padded = new Uint8Array(rate);
    padded.set(seed.subarray(0, Math.min(seed.length, rate)));
    padded[seed.length] ^= 0x1f; padded[rate - 1] ^= 0x80;
    this._absorb(padded);
    this.block = this._extract(); // blok pertama langsung dari state (tanpa permutasi lagi)
    this.pos = 0;
  }
  _extract() {
    const block = new Uint8Array(168);
    for (let i = 0; i < 168; i++) block[i] = Number((this.s[(i/8)|0] >> BigInt(8*(i%8))) & 0xffn);
    return block;
  }
  _absorb(block) {
    for (let i = 0; i < block.length; i++) {
      const lane = (i / 8) | 0;
      this.s[lane] ^= BigInt(block[i]) << BigInt(8 * (i % 8));
    }
    this._f1600();
  }
  _f1600() {
    const C = [0x0000000000000001n,0x0000000000008082n,0x800000000000808an,0x8000000080008000n,0x000000000000808bn,0x0000000080000001n,0x8000000080008081n,0x8000000000008009n,0x000000000000008an,0x0000000000000088n,0x0000000080008009n,0x000000008000000an,0x000000008000808bn,0x800000000000008bn,0x8000000000008089n,0x8000000000008003n,0x8000000000008002n,0x8000000000000080n,0x000000000000800an,0x800000008000000an,0x8000000080008081n,0x8000000000008080n,0x0000000080000001n,0x8000000080008008n];
    const R = [[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]];
    const rot = (x, n) => n === 0 ? x : (((x << BigInt(n)) | (x >> BigInt(64 - n))) & 0xffffffffffffffffn);
    for (let round = 0; round < 24; round++) {
      const c = new Array(5), d = new Array(5);
      for (let x = 0; x < 5; x++) c[x] = this.s[x] ^ this.s[x+5] ^ this.s[x+10] ^ this.s[x+15] ^ this.s[x+20];
      for (let x = 0; x < 5; x++) d[x] = c[(x+4)%5] ^ rot(c[(x+1)%5], 1);
      for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) this.s[x + 5*y] ^= d[x];
      const b = new Array(25);
      for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) b[y + 5*((2*x + 3*y) % 5)] = rot(this.s[x + 5*y], R[x][y]);
      for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) this.s[x + 5*y] = b[x + 5*y] ^ ((~b[(x+1)%5 + 5*y]) & b[(x+2)%5 + 5*y]);
      this.s[0] ^= C[round];
    }
  }
  _squeezeBlock() {
    this._f1600();
    this.block = this._extract();
    this.pos = 0;
  }
  nextU16() {
    if (this.pos + 2 > 168) this._squeezeBlock();
    const v = (this.block[this.pos] << 8) | this.block[this.pos + 1];
    this.pos += 2;
    return v;
  }
}

// ---------------- ChaCha20-Poly1305 (murni JS; WebCrypto tidak punya) ----------------
function rotl32(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }
function chachaBlock(key, counter, nonce) {
  const st = new Uint32Array(16);
  st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;
  const dv = new DataView(key.buffer, key.byteOffset, key.byteLength);
  for (let i = 0; i < 8; i++) st[4 + i] = dv.getUint32(i * 4, true);
  st[12] = counter;
  const nv = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  for (let i = 0; i < 3; i++) st[13 + i] = nv.getUint32(i * 4, true);
  const w = new Uint32Array(st);
  const qr = (a, b, c, d) => {
    w[a] = (w[a] + w[b]) >>> 0; w[d] = rotl32(w[d] ^ w[a], 16);
    w[c] = (w[c] + w[d]) >>> 0; w[b] = rotl32(w[b] ^ w[c], 12);
    w[a] = (w[a] + w[b]) >>> 0; w[d] = rotl32(w[d] ^ w[a], 8);
    w[c] = (w[c] + w[d]) >>> 0; w[b] = rotl32(w[b] ^ w[c], 7);
  };
  for (let i = 0; i < 10; i++) {
    qr(0,4,8,12); qr(1,5,9,13); qr(2,6,10,14); qr(3,7,11,15);
    qr(0,5,10,15); qr(1,6,11,12); qr(2,7,8,13); qr(3,4,9,14);
  }
  const out = new Uint8Array(64), ov = new DataView(out.buffer);
  for (let i = 0; i < 16; i++) ov.setUint32(i * 4, (w[i] + st[i]) >>> 0, true);
  return out;
}
function chachaStream(key, nonce, data, startCounter) {
  const out = new Uint8Array(data.length);
  let counter = startCounter;
  for (let off = 0; off < data.length; off += 64) {
    const block = chachaBlock(key, counter++, nonce);
    const n = Math.min(64, data.length - off);
    for (let i = 0; i < n; i++) out[off + i] = data[off + i] ^ block[i];
  }
  return out;
}
function poly1305Mac(msg, key32) {
  const rBytes = key32.subarray(0, 16), s = key32.subarray(16, 32);
  let r = 0n;
  for (let i = 15; i >= 0; i--) r = (r << 8n) | BigInt(rBytes[i]);
  r &= 0x0ffffffc0ffffffc0ffffffc0fffffffn;
  const P = (1n << 130n) - 5n;
  let acc = 0n;
  for (let off = 0; off < msg.length; off += 16) {
    const n = Math.min(16, msg.length - off);
    let v = 0n;
    for (let i = n - 1; i >= 0; i--) v = (v << 8n) | BigInt(msg[off + i]);
    v |= 1n << BigInt(8 * n);
    acc = ((acc + v) * r) % P;
  }
  let sNum = 0n;
  for (let i = 15; i >= 0; i--) sNum = (sNum << 8n) | BigInt(s[i]);
  acc = (acc + sNum) & ((1n << 128n) - 1n);
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) { out[i] = Number(acc & 0xffn); acc >>= 8n; }
  return out;
}
function chachaPolyKey(bodyKey16) {
  const t1 = md5(bodyKey16), t2 = md5(t1);
  return cat(t1, t2);
}
function chachaSeal(bodyKey16, nonce12, plain) {
  const key = chachaPolyKey(bodyKey16);
  const polyKey = chachaBlock(key, 0, nonce12).subarray(0, 32);
  const ct = chachaStream(key, nonce12, plain, 1);
  const macData = cat(ct, padTo16(ct), len64(0), len64(ct.length));
  const tag = poly1305Mac(macData, polyKey);
  return cat(ct, tag);
}
function padTo16(b) { const r = b.length % 16; return r === 0 ? new Uint8Array(0) : new Uint8Array(16 - r); }
function len64(n) { const o = new Uint8Array(8); new DataView(o.buffer).setUint32(0, n >>> 0, true); return o; }
function chachaOpen(bodyKey16, nonce12, sealed) {
  if (sealed.length < 16) throw new Error("ciphertext pendek");
  const key = chachaPolyKey(bodyKey16);
  const polyKey = chachaBlock(key, 0, nonce12).subarray(0, 32);
  const ct = sealed.subarray(0, sealed.length - 16), tag = sealed.subarray(sealed.length - 16);
  const macData = cat(ct, padTo16(ct), len64(0), len64(ct.length));
  const expect = poly1305Mac(macData, polyKey);
  let diff = 0; for (let i = 0; i < 16; i++) diff |= expect[i] ^ tag[i];
  if (diff !== 0) throw new Error("tag ChaCha tidak cocok");
  return chachaStream(key, nonce12, ct, 1);
}

// ---------------- AES-GCM via WebCrypto ----------------
async function aesGcmSeal(key16, nonce12, data, aad) {
  const k = await crypto.subtle.importKey("raw", key16, { name: "AES-GCM" }, false, ["encrypt"]);
  const out = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce12, additionalData: aad, tagLength: 128 }, k, data);
  return new Uint8Array(out);
}
async function aesGcmOpen(key16, nonce12, data, aad) {
  const k = await crypto.subtle.importKey("raw", key16, { name: "AES-GCM" }, false, ["decrypt"]);
  const out = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce12, additionalData: aad, tagLength: 128 }, k, data);
  return new Uint8Array(out);
}
async function bodySeal(security, key16, nonce12, plain) {
  if (security === 3) return aesGcmSeal(key16, nonce12, plain, undefined);
  return chachaSeal(key16, nonce12, plain);
}
async function bodyOpen(security, key16, nonce12, sealed) {
  if (security === 3) return aesGcmOpen(key16, nonce12, sealed, undefined);
  return chachaOpen(key16, nonce12, sealed);
}

// ---------------- codec chunk body VMess ----------------
const SEC_AES_GCM = 3, SEC_CHACHA = 4, SEC_NONE = 5, SEC_ZERO = 6;
const OPT_MASKING = 0x04, OPT_PADDING = 0x08, OPT_AUTHLEN = 0x10;

function chunkNonceGen(iv16) {
  let count = 0;
  return () => {
    const n = new Uint8Array(12);
    n.set(iv16.subarray(0, 12));
    n[0] = (count >> 8) & 255; n[1] = count & 255;
    count = (count + 1) & 0xffff;
    return n;
  };
}

class ChunkDecoder {
  constructor(security, key16, iv16, opt) {
    this.security = security; this.key = key16;
    this.nextNonce = chunkNonceGen(iv16);
    this.authLen = (opt & OPT_AUTHLEN) !== 0;
    this.masking = (opt & OPT_MASKING) !== 0;
    this.padding = (opt & OPT_PADDING) !== 0;
    if (this.authLen && this.padding) throw new Error("opsi VMess invalid (authLen+padding)");
    if (this.authLen) {
      this.lenKey = vmessKDF(key16, "auth_len").subarray(0, 16);
      this.nextLenNonce = chunkNonceGen(iv16);
    }
    this.shake = (this.masking || this.padding) ? new Shake128(iv16) : null;
    this.buf = new Uint8Array(0);
    this.pending = null;
    this.done = false;
  }
  async push(data) {
    if (data && data.length) this.buf = cat(this.buf, data);
    const plains = [];
    if (this.done) return { plains, done: true };
    for (;;) {
      const sizeLen = this.authLen ? 18 : 2;
      if (this.buf.length < sizeLen) break;
      if (this.pending === null) {
        const sizeBytes = this.buf.subarray(0, sizeLen);
        let padLen = 0, size;
        if (this.padding) padLen = this.shake.nextU16() % 64;
        if (this.authLen) {
          const raw = await bodyOpen(this.security, this.lenKey, this.nextLenNonce(), sizeBytes);
          size = rdU16(raw, 0) + 16;
        } else if (this.masking) {
          size = (this.shake.nextU16() ^ rdU16(sizeBytes, 0)) & 0xffff;
        } else {
          size = rdU16(sizeBytes, 0);
        }
        this.pending = { sizeLen, padLen, size };
      }
      const { padLen, size } = this.pending;
      if (size === 16 + padLen) { // chunk kosong = sinyal putus dari klien
        this.done = true;
        this.buf = this.buf.subarray(sizeLen);
        this.pending = null;
        break;
      }
      if (size < 16 + padLen) throw new Error("ukuran chunk VMess invalid: " + size);
      if (this.buf.length < sizeLen + size) break;
      this.pending = null;
      const sealed = this.buf.subarray(sizeLen, sizeLen + size - padLen);
      this.buf = this.buf.subarray(sizeLen + size);
      const plain = await bodyOpen(this.security, this.key, this.nextNonce(), sealed);
      if (plain.length) plains.push(plain);
    }
    return { plains, done: this.done };
  }
}

class ChunkEncoder {
  constructor(security, key16, iv16, opt) {
    this.security = security; this.key = key16;
    this.nextNonce = chunkNonceGen(iv16);
    this.authLen = (opt & OPT_AUTHLEN) !== 0;
    this.masking = (opt & OPT_MASKING) !== 0;
    this.padding = (opt & OPT_PADDING) !== 0;
    if (this.authLen) {
      this.lenKey = vmessKDF(key16, "auth_len").subarray(0, 16);
      this.nextLenNonce = chunkNonceGen(iv16);
    }
    this.shake = (this.masking || this.padding) ? new Shake128(iv16) : null;
  }
  async _seal(plain) {
    let padLen = 0;
    if (this.padding) padLen = this.shake.nextU16() % 64;
    const total = plain.length + 16 + padLen;
    let sizeBytes;
    if (this.authLen) {
      sizeBytes = await bodySeal(this.security, this.lenKey, this.nextLenNonce(), u16be(plain.length + padLen));
    } else if (this.masking) {
      sizeBytes = u16be((this.shake.nextU16() ^ total) & 0xffff);
    } else {
      sizeBytes = u16be(total);
    }
    const sealed = await bodySeal(this.security, this.key, this.nextNonce(), plain);
    const pad = padLen ? crypto.getRandomValues(new Uint8Array(padLen)) : new Uint8Array(0);
    return cat(sizeBytes, sealed, pad);
  }
  async sealStream(plain) {
    if (!plain.length) return new Uint8Array(0);
    const parts = [];
    for (let i = 0; i < plain.length; i += 8000) parts.push(await this._seal(plain.subarray(i, i + 8000)));
    return cat(...parts);
  }
  async sealPacket(plain) { return this._seal(plain); }
  async sealEmpty() { return this._seal(new Uint8Array(0)); }
}

// ---------------- header VMess AEAD ----------------
const VMESS_MAGIC = TE.encode("c48619fe-8f02-49e0-b9e9-edf763e17e21");
let _basis = null;
function vmessBasis() {
  if (!_basis) _basis = md5(cat(parseUUID(USER_UUID), VMESS_MAGIC));
  return _basis;
}

// Kembalikan null bila byte belum cukup; lempar Error bila bukan VMess valid.
async function parseVmessHeader(buf) {
  if (buf.length < 42) return null;
  const auth = buf.subarray(0, 16), lenEnc = buf.subarray(16, 34), nonce = buf.subarray(34, 42);
  const basis = vmessBasis();
  const lk = vmessKDF(basis, "VMess Header AEAD Key_Length", auth, nonce).subarray(0, 16);
  const li = vmessKDF(basis, "VMess Header AEAD Nonce_Length", auth, nonce).subarray(0, 12);
  const lenPlain = await aesGcmOpen(lk, li, lenEnc, auth); // gagal = bukan VMess/UUID salah
  const dataLen = rdU16(lenPlain, 0);
  if (dataLen < 42 || dataLen > 4096) throw new Error("panjang header VMess invalid");
  if (buf.length < 42 + dataLen + 16) return null;
  const cmdEnc = buf.subarray(42, 42 + dataLen + 16);
  const pk = vmessKDF(basis, "VMess Header AEAD Key", auth, nonce).subarray(0, 16);
  const pi = vmessKDF(basis, "VMess Header AEAD Nonce", auth, nonce).subarray(0, 12);
  const cmd = await aesGcmOpen(pk, pi, cmdEnc, auth);
  if (cmd[0] !== 1) throw new Error("versi VMess tidak didukung");
  const reqIV = cmd.subarray(1, 17), reqKey = cmd.subarray(17, 33);
  const respV = cmd[33], opt = cmd[34], security = cmd[35] & 0x0f;
  const command = cmd[37];
  if (command !== 1 && command !== 2) throw new Error("command VMess invalid");
  const port = rdU16(cmd, 38);
  const atyp = cmd[40];
  let host;
  if (atyp === 1) host = [...cmd.subarray(41, 45)].join(".");
  else if (atyp === 2) host = TD.decode(cmd.subarray(42, 42 + cmd[41]));
  else if (atyp === 3) {
    const parts = [];
    for (let i = 0; i < 8; i++) parts.push(rdU16(cmd, 41 + i * 2).toString(16));
    host = parts.join(":");
  } else throw new Error("atyp VMess invalid");
  if (![SEC_AES_GCM, SEC_CHACHA, SEC_NONE, SEC_ZERO].includes(security))
    throw new Error("security VMess tidak didukung: " + security);
  const respBodyKey = sha256(reqKey).subarray(0, 16);
  const respBodyIV = sha256(reqIV).subarray(0, 16);
  const h1 = await aesGcmSeal(
    vmessKDF(respBodyKey, "AEAD Resp Header Len Key").subarray(0, 16),
    vmessKDF(respBodyIV, "AEAD Resp Header Len IV").subarray(0, 12),
    new Uint8Array([0, 4]), undefined);
  const h2 = await aesGcmSeal(
    vmessKDF(respBodyKey, "AEAD Resp Header Key").subarray(0, 16),
    vmessKDF(respBodyIV, "AEAD Resp Header IV").subarray(0, 12),
    new Uint8Array([respV, 0, 0, 0]), undefined);
  return {
    host, port, isUdp: command === 2, security, opt,
    reqKey, reqIV, respBodyKey, respBodyIV,
    replyHead: cat(h1, h2),
    rest: buf.subarray(42 + dataLen + 16)
  };
}


// SHA-224: inti SHA-256 dengan IV berbeda, output 28 byte (untuk Trojan).
function sha224(bytes) {
  const H = new Uint32Array([0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4]);
  const rr = (x, n) => (x >>> n) | (x << (32 - n));
  const L = bytes.length, padLen = ((56 - (L + 1) % 64) + 64) % 64;
  const msg = new Uint8Array(L + 1 + padLen + 8);
  msg.set(bytes); msg[L] = 0x80;
  new DataView(msg.buffer).setUint32(msg.length - 4, (L * 8) >>> 0, false);
  const W = new Uint32Array(64);
  for (let off = 0; off < msg.length; off += 64) {
    const blk = new DataView(msg.buffer, off, 64);
    for (let t = 0; t < 16; t++) W[t] = blk.getUint32(t * 4, false);
    for (let t = 16; t < 64; t++) {
      const s0 = rr(W[t-15],7) ^ rr(W[t-15],18) ^ (W[t-15] >>> 3);
      const s1 = rr(W[t-2],17) ^ rr(W[t-2],19) ^ (W[t-2] >>> 10);
      W[t] = (W[t-16] + s0 + W[t-7] + s1) >>> 0;
    }
    let [a,b,c,d,e,f,g,h] = H;
    for (let t = 0; t < 64; t++) {
      const S1 = rr(e,6) ^ rr(e,11) ^ rr(e,25), ch = (e & f) ^ (~e & g);
      const T1 = (h + S1 + ch + SHA256_K[t] + W[t]) >>> 0;
      const S0 = rr(a,2) ^ rr(a,13) ^ rr(a,22), maj = (a & b) ^ (a & c) ^ (b & c);
      const T2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + T1) >>> 0; d = c; c = b; b = a; a = (T1 + T2) >>> 0;
    }
    H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
    H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
  }
  const out = new Uint8Array(28), ov = new DataView(out.buffer);
  for (let i = 0; i < 7; i++) ov.setUint32(i * 4, H[i], false);
  return out;
}

function hexEncode(b) { let s = ""; for (const x of b) s += x.toString(16).padStart(2, "0"); return s; }
function u8eq(a, b) { if (a.length !== b.length) return false; for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false; return true; }
function ipv6String(b, p) { const g = []; for (let i = 0; i < 8; i++) g.push(rdU16(b, p + i * 2).toString(16)); return g.join(":"); }
// Trojan: password bebas dari dashboard (UI) — worker cukup memeriksa
// format SHA-224 hex 56 char yang sah, nilainya diterima apa pun.
function isTrojanHash(b) {
  for (let i = 0; i < 56; i++) {
    const c = b[i];
    if (!((c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70))) return false;
  }
  return true;
}

// Header VLESS: ver(1) uuid(16) addonLen(1)+addons cmd(1) port(2) atyp(1) addr.
// Kembali: objek sesi | null (belum lengkap) | false (tidak valid).
function parseVlessHeader(buf) {
  if (buf.length < 18) return null;
  let p = 17;
  p += 1 + buf[17];
  if (buf.length < p + 4) return null;
  const cmd = buf[p]; p += 1;
  if (cmd !== 1 && cmd !== 2) return false;
  const port = rdU16(buf, p); p += 2;
  const atyp = buf[p]; p += 1;
  let host;
  if (atyp === 1) { if (buf.length < p + 4) return null; host = buf[p] + "." + buf[p+1] + "." + buf[p+2] + "." + buf[p+3]; p += 4; }
  else if (atyp === 2) { if (buf.length < p + 1) return null; const l = buf[p]; if (buf.length < p + 1 + l) return null; host = new TextDecoder().decode(buf.subarray(p + 1, p + 1 + l)); p += 1 + l; }
  else if (atyp === 3) { if (buf.length < p + 16) return null; host = ipv6String(buf, p); p += 16; }
  else return false;
  return { proto: "vless", host, port, isUdp: cmd === 2, rest: buf.subarray(p), replyHead: new Uint8Array([0, 0]), security: 0 };
}

// Header Trojan: sha224hex(56) CRLF cmd(1) atyp(1) addr port(2) CRLF.
function parseTrojanHeader(buf) {
  if (buf.length < 56 + 2 + 1 + 1 + 2 + 2) return null;
  if (buf[56] !== 13 || buf[57] !== 10) return false;
  let p = 58;
  const cmd = buf[p]; p += 1;
  const atyp = buf[p]; p += 1;
  let host;
  if (atyp === 1) { if (buf.length < p + 4 + 4) return null; host = buf[p] + "." + buf[p+1] + "." + buf[p+2] + "." + buf[p+3]; p += 4; }
  else if (atyp === 3) { if (buf.length < p + 1) return null; const l = buf[p]; if (buf.length < p + 1 + l + 4) return null; host = new TextDecoder().decode(buf.subarray(p + 1, p + 1 + l)); p += 1 + l; }
  else if (atyp === 4) { if (buf.length < p + 16 + 4) return null; host = ipv6String(buf, p); p += 16; }
  else return false;
  const port = rdU16(buf, p); p += 2;
  if (buf.length < p + 2 || buf[p] !== 13 || buf[p + 1] !== 10) return false;
  p += 2;
  return { proto: "trojan", host, port, isUdp: cmd === 3, rest: buf.subarray(p), replyHead: new Uint8Array(0), security: 0 };
}

// Paket SOCKS5-UDP (Trojan): [0,0,0,atyp,addr,port,2B len,data].
function parseSocksUdp(buf) {
  if (buf.length < 4) return null;
  const atyp = buf[3];
  let p = 4, addrLen;
  if (atyp === 1) { if (buf.length < p + 4 + 4) return null; addrLen = 4; }
  else if (atyp === 3) { if (buf.length < p + 1) return null; const l = buf[p]; if (buf.length < p + 1 + l + 4) return null; addrLen = 1 + l; }
  else if (atyp === 4) { if (buf.length < p + 16 + 4) return null; addrLen = 16; }
  else return { total: Math.max(buf.length, 4), port: 0, data: new Uint8Array(0), head: new Uint8Array(0) };
  p += addrLen;
  const port = rdU16(buf, p); p += 2;
  const head = buf.slice(0, p); // sampai sesudah port
  const dlen = rdU16(buf, p); p += 2;
  if (buf.length < p + dlen) return null;
  return { total: p + dlen, port, data: buf.subarray(p, p + dlen), head };
}

// ---------------- sesi koneksi ----------------
async function handleSession(serverWs, fallbackNode) {
  let headerBuf = new Uint8Array(0);
  let sess = null, dec = null, enc = null;
  let sock = null, writer = null, headSent = false;
  let dead = false, gotBytes = false, retried = false;
  const replayBuf = [];

  const closeAll = () => {
    if (dead) return; dead = true;
    try { serverWs.close(); } catch {}
    try { sock && sock.close(); } catch {}
  };
  const sendToClient = (bytes) => {
    if (dead || !bytes.length) return;
    if (!headSent) { headSent = true; serverWs.send(cat(sess.replyHead, bytes)); }
    else serverWs.send(bytes);
  };

  async function openTarget(host, port) {
    const s = connect({ hostname: host, port });
    try {
      await Promise.race([
        s.opened,
        new Promise((_, rej) => setTimeout(() => rej(new Error("dial timeout")), 6000))
      ]);
    } catch (e) { try { s.close(); } catch {} throw e; }
    return s;
  }

  function pump(s) {
    (async () => {
      try {
        const reader = s.readable.getReader();
        for (;;) {
          let rd;
          if (!gotBytes && sess.altTarget) {
            rd = await Promise.race([
              reader.read(),
              new Promise((res) => setTimeout(() => res({ timeout: true }), 5000))
            ]);
            if (rd.timeout) { try { reader.cancel(); } catch {} break; }
          } else rd = await reader.read();
          const { done, value } = rd;
          if (done) break;
          if (!value || !value.length) continue;
          gotBytes = true;
          sendToClient(enc ? await enc.sealStream(value) : value);
        }
      } catch {}
      if (!gotBytes && !retried && sess.altTarget) {
        retried = true;
        try {
          sock = await openTarget(sess.altTarget.host, sess.altTarget.port);
          writer = sock.writable.getWriter();
          for (const p of replayBuf) await writer.write(p);
          pump(sock);
          return;
        } catch {}
      }
      if (enc && !dead) {
        try { sendToClient(await enc.sealEmpty()); } catch {}
      } else if (!headSent && sess) {
        headSent = true;
        try { serverWs.send(sess.replyHead); } catch {}
      }
      closeAll();
    })();
  }

  async function startTcp() {
    // Direct dulu (lebih cepat); node dari path jadi cadangan bila direct gagal
    // atau 5 detik tanpa data (urutan sama seperti script user).
    const primary = { host: sess.host, port: sess.port };
    sess.altTarget = fallbackNode || null;
    try { sock = await openTarget(primary.host, primary.port); }
    catch (e) {
      if (!sess.altTarget) throw e;
      sock = await openTarget(sess.altTarget.host, sess.altTarget.port);
      retried = true;
    }
    writer = sock.writable.getWriter();
    pump(sock);
    if (sess.rest.length) await feedTcp(sess.rest);
  }

  async function feedTcp(bytes) {
    if (dec) {
      const { plains, done } = await dec.push(bytes);
      for (const p of plains) {
        if (!gotBytes && replayBuf.map(x => x.length).reduce((a, b) => a + b, 0) < 65536) replayBuf.push(p);
        await writer.write(p);
      }
      if (done) { try { await writer.close(); } catch {} }
    } else {
      if (!gotBytes) replayBuf.push(bytes);
      await writer.write(bytes);
    }
  }

  // DNS via DoH: satu chunk = satu datagram mentah (format terbukti v2.0).
  async function onUdpBytes(bytes) {
    const { plains } = await dec.push(bytes);
    for (const dg of plains) {
      if (!dg.length) continue;
      try {
        const resp = await fetch(DOH_ENDPOINT, {
          method: "POST",
          headers: { "content-type": "application/dns-message" },
          body: dg
        });
        const ans = new Uint8Array(await resp.arrayBuffer());
        if (ans.length) sendToClient(await enc.sealPacket(ans));
      } catch {}
    }
  }


  // DNS-over-TCP (port 53): stream berbingkai 2 byte -> DoH -> bingkai balik.
  // Menangkap DNS dari tun2socks/DarkTunnel yang meneruskan DNS via TCP,
  // supaya tidak perlu dial port 53 (sering bengong) dan tidak bocor ke ISP.
  let dnsTcpBuf = new Uint8Array(0);
  async function feedDnsTcp(bytes) {
    let plains;
    if (dec) {
      const r = await dec.push(bytes);
      plains = r.plains;
      if (r.done && !plains.length) return;
    } else plains = [bytes];
    for (const p of plains) dnsTcpBuf = cat(dnsTcpBuf, p);
    for (;;) {
      if (dnsTcpBuf.length < 2) return;
      const qlen = rdU16(dnsTcpBuf, 0);
      if (dnsTcpBuf.length < 2 + qlen) return;
      const msg = dnsTcpBuf.subarray(2, 2 + qlen);
      dnsTcpBuf = dnsTcpBuf.subarray(2 + qlen);
      try {
        const resp = await fetch(DOH_ENDPOINT, {
          method: "POST",
          headers: { "content-type": "application/dns-message" },
          body: msg
        });
        const ans = new Uint8Array(await resp.arrayBuffer());
        if (ans.length) { const framed = cat(u16be(ans.length), ans); sendToClient(enc ? await enc.sealStream(framed) : framed); }
      } catch {}
    }
  }


  // UDP VLESS: stream berbingkai [2B len][paket]; DNS -> DoH; balasan paket mentah.
  let vlessUdpBuf = new Uint8Array(0);
  async function feedVlessUdp(bytes) {
    vlessUdpBuf = cat(vlessUdpBuf, bytes);
    for (;;) {
      if (vlessUdpBuf.length < 2) return;
      const l = rdU16(vlessUdpBuf, 0);
      if (vlessUdpBuf.length < 2 + l) return;
      const pkt = vlessUdpBuf.subarray(2, 2 + l);
      vlessUdpBuf = vlessUdpBuf.subarray(2 + l);
      if (!pkt.length) continue;
      try {
        const resp = await fetch(DOH_ENDPOINT, {
          method: "POST",
          headers: { "content-type": "application/dns-message" },
          body: pkt
        });
        const ans = new Uint8Array(await resp.arrayBuffer());
        if (ans.length) sendToClient(ans);
      } catch {}
    }
  }

  // UDP Trojan: paket SOCKS5-UDP; yang port 53 dijawab DoH, dibungkus balik.
  let trojanUdpBuf = new Uint8Array(0);
  async function feedTrojanUdp(bytes) {
    trojanUdpBuf = cat(trojanUdpBuf, bytes);
    for (;;) {
      const r = parseSocksUdp(trojanUdpBuf);
      if (!r) return; // belum lengkap
      trojanUdpBuf = trojanUdpBuf.subarray(r.total);
      if (r.port !== 53 || !r.data.length) continue;
      try {
        const resp = await fetch(DOH_ENDPOINT, {
          method: "POST",
          headers: { "content-type": "application/dns-message" },
          body: r.data
        });
        const ans = new Uint8Array(await resp.arrayBuffer());
        if (ans.length) sendToClient(cat(r.head, u16be(ans.length), ans));
      } catch {}
    }
  }

  let chain = Promise.resolve();
  const enqueue = (bytes) => {
    chain = chain.then(async () => {
      if (dead) return;
      if (!sess) {
        headerBuf = cat(headerBuf, bytes);
        // Identifikasi protokol dari byte pertama.
        if (headerBuf.length >= 17 && headerBuf[0] === 0 && u8eq(headerBuf.subarray(1, 17), USER_UUID_BYTES)) {
          const p = parseVlessHeader(headerBuf);
          if (p === null) return; // belum lengkap
          if (p === false) { closeAll(); return; }
          sess = p;
        } else if (headerBuf.length >= 56 && isTrojanHash(headerBuf.subarray(0, 56))) {
          const p = parseTrojanHeader(headerBuf);
          if (p === null) return;
          if (p === false) { closeAll(); return; }
          sess = p;
        } else {
          let p = null;
          try { p = await parseVmessHeader(headerBuf); } catch { p = null; }
          if (p) sess = p;
          else if (headerBuf.length >= 17 && headerBuf[0] === 0) {
            // VLESS UUID bebas: terima UUID apa pun bila strukturnya sah.
            const pv = parseVlessHeader(headerBuf);
            if (pv && pv !== false) sess = pv;
            else return; // tunggu data lagi
          } else return;
        }
        sess.proto = sess.proto || "vmess";
        if (sess.isUdp) {
          if (sess.proto === "vmess") {
            if (![SEC_AES_GCM, SEC_CHACHA].includes(sess.security) || sess.port !== 53) { closeAll(); return; }
            dec = new ChunkDecoder(sess.security, sess.reqKey, sess.reqIV, sess.opt);
            enc = new ChunkEncoder(sess.security, sess.respBodyKey, sess.respBodyIV, sess.opt);
            if (sess.rest.length) await onUdpBytes(sess.rest);
          } else if (sess.proto === "vless") {
            if (sess.port !== 53) { closeAll(); return; }
            if (sess.rest.length) await feedVlessUdp(sess.rest);
          } else {
            if (sess.rest.length) await feedTrojanUdp(sess.rest);
          }
        } else {
          if (sess.proto === "vmess" && [SEC_AES_GCM, SEC_CHACHA].includes(sess.security)) {
            dec = new ChunkDecoder(sess.security, sess.reqKey, sess.reqIV, sess.opt);
            enc = new ChunkEncoder(sess.security, sess.respBodyKey, sess.respBodyIV, sess.opt);
          }
          if (sess.port === 53) { if (sess.rest.length) await feedDnsTcp(sess.rest); }
          else await startTcp();
        }
      } else if (sess.isUdp) {
        if (sess.proto === "vmess") await onUdpBytes(bytes);
        else if (sess.proto === "vless") await feedVlessUdp(bytes);
        else await feedTrojanUdp(bytes);
      } else if (sess.port === 53) {
        await feedDnsTcp(bytes);
      } else {
        await feedTcp(bytes);
      }
    }).catch(() => closeAll());
  };

  return { enqueue, closeAll };
}

// ---------------- UI generator ----------------
class ConfigUI {
  static render(domain) {
    return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Kancil VPN - Forest & Wood Theme</title>
<script src="https://cdn.tailwindcss.com"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
body{background:linear-gradient(rgba(15,23,15,0.85),rgba(30,20,10,0.9)),url('https://images.unsplash.com/photo-1513836279014-a89f7a76ae86?auto=format&fit=crop&w=1200&q=80') no-repeat center center fixed;background-size:cover;color:#f3e9dc;font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont}
.wood-card{background:rgba(36,23,11,0.88);backdrop-filter:blur(14px);border:2px solid #5a3d22;box-shadow:0 12px 35px rgba(0,0,0,0.7),inset 0 1px 0 rgba(255,255,255,0.08)}
textarea,input,select{pointer-events:auto !important;user-select:text !important}
</style>
</head>
<body class="min-h-screen pb-12">
<div class="max-w-4xl mx-auto px-4 pt-8">

  <!-- Header -->
  <div class="wood-card rounded-2xl p-6 mb-8 flex flex-col sm:flex-row items-center justify-between gap-4">
    <div>
      <h1 class="text-2xl font-bold bg-gradient-to-r from-amber-200 via-emerald-300 to-green-400 bg-clip-text text-transparent flex items-center gap-2">
        <i class="fa-solid fa-tree text-emerald-400"></i> Kancil VPN Forest Dashboard
      </h1>
      <p class="text-amber-200/70 text-sm mt-1">Host Worker Asli: <span class="text-amber-300 font-mono">${domain}</span></p>
      <p class="mt-2"><span class="inline-block text-[11px] font-bold px-2.5 py-1 rounded-full bg-emerald-900/70 border border-emerald-600 text-emerald-300">${VERSION_LABEL} • VMess AEAD Penuh</span></p>
    </div>
    <div class="flex items-center gap-2 bg-[#1c1107] px-4 py-2 rounded-xl border border-[#5a3d22]">
      <span id="statusPingDot" class="w-3 h-3 rounded-full bg-emerald-500 animate-pulse"></span>
      <span id="statusText" class="text-xs font-semibold text-amber-200">Mengecek Status...</span>
    </div>
  </div>

  <!-- Generator -->
  <div class="wood-card rounded-2xl p-6 mb-8">
    <h2 class="text-lg font-semibold text-amber-200 mb-4 flex items-center gap-2">
      <i class="fa-solid fa-seedling text-emerald-400"></i> Generator Konfigurasi VMess WS
    </h2>

    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
      <div>
        <label class="block text-xs font-medium text-amber-300/80 mb-1">Pilih Protokol</label>
        <select id="protoSelect" onchange="generateLinks()" class="w-full bg-[#120a05] border border-[#5a3d22] rounded-xl px-4 py-2.5 text-sm text-amber-100 focus:outline-none focus:border-emerald-500 font-mono">
          <option value="vmess" selected>VMess</option>
          <option value="vless">VLESS</option>
          <option value="trojan">Trojan</option>
        </select>
      </div>
      <div>
        <label class="block text-xs font-medium text-amber-300/80 mb-1">Password Trojan (otomatis = UUID)</label>
        <input type="text" id="trojanPass" value="${USER_UUID}" oninput="onTrojanPassInput()" class="w-full bg-[#120a05] border border-[#5a3d22] rounded-xl px-4 py-2.5 text-sm text-amber-100 focus:outline-none focus:border-emerald-500 font-mono">
      </div>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
      <div>
        <label class="block text-xs font-medium text-amber-300/80 mb-1">Pilih Metode Koneksi</label>
        <select id="methodSelect" onchange="toggleBugInput(); generateLinks();" class="w-full bg-[#120a05] border border-[#5a3d22] rounded-xl px-4 py-2.5 text-sm text-amber-100 focus:outline-none focus:border-emerald-500 font-mono">
          <option value="ws" selected>Websocket (SNI / Bug Host)</option>
          <option value="wildcard">Wildcard (Subdomain)</option>
        </select>
      </div>
      <div>
        <label class="block text-xs font-medium text-amber-300/80 mb-1">Port Tujuan</label>
        <select id="portSelect" onchange="generateLinks()" class="w-full bg-[#120a05] border border-[#5a3d22] rounded-xl px-4 py-2.5 text-sm text-amber-100 focus:outline-none focus:border-emerald-500 font-mono">
          <option value="443" selected>443 (TLS)</option>
          <option value="80">80 (NTLS)</option>
        </select>
      </div>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
      <div>
        <label class="block text-xs font-medium text-amber-300/80 mb-1">Security / Cipher VMess</label>
        <select id="cipherSelect" onchange="generateLinks()" class="w-full bg-[#120a05] border border-[#5a3d22] rounded-xl px-4 py-2.5 text-sm text-amber-100 focus:outline-none focus:border-emerald-500 font-mono">
          <option value="auto" selected>auto</option>
          <option value="aes-128-gcm">aes-128-gcm</option>
          <option value="chacha20-poly1305">chacha20-poly1305</option>
        </select>
      </div>
      <div>
        <label class="block text-xs font-medium text-amber-300/80 mb-1">Pilih Proxy (jalur cadangan)</label>
        <select id="proxySelect" onchange="syncPathInput(); generateLinks();" class="w-full bg-[#120a05] border border-[#5a3d22] rounded-xl px-4 py-2.5 text-sm text-amber-100 focus:outline-none focus:border-emerald-500 font-mono">
          <optgroup label="🇮🇩 INDONESIA">
            <option value="id-dnva">id-dnva (103.169.207.189:443)</option>
            <option value="id-amazon">id-amazon (16.79.55.124:443)</option>
            <option value="id-biznet">id-biznet (139.190.97.223:443)</option>
            <option value="id-nusa">id-nusa (110.232.84.159:2053)</option>
            <option value="id-idc">id-idc (103.193.179.158:443)</option>
            <option value="id-mora">id-mora (103.54.217.41:10688)</option>
            <option value="id-telkom">id-telkom (43.173.1.153:8443)</option>
            <option value="id-rajasa">id-rajasa (119.235.252.35:46260)</option>
            <option value="id-ceo">id-ceo (118.151.222.66:17317)</option>
            <option value="id-rmweb">id-rmweb (203.175.11.90:9443)</option>
            <option value="id-deneva">id-deneva (202.155.95.132:443)</option>
            <option value="id-akamai">id-akamai (172.232.249.224:2053)</option>
          </optgroup>
          <optgroup label="🇸🇬 SINGAPORE">
            <option value="sg-akamai">sg-akamai (104.64.192.116:443)</option>
            <option value="sg-amazon">sg-amazon (13.250.19.142:443)</option>
            <option value="sg-contabo">sg-contabo (194.233.85.147:443)</option>
            <option value="sg-oracle">sg-oracle (138.2.64.229:443)</option>
            <option value="sg-ovh">sg-ovh (51.79.177.53:443)</option>
          </optgroup>
          <option value="manual">-- Manual IP:Port / Custom Path --</option>
        </select>
      </div>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
      <div>
        <label class="block text-xs font-medium text-amber-300/80 mb-1">Pilih Host Utama (Base Domain UI)</label>
        <select id="baseHostSelect" onchange="generateLinks()" class="w-full bg-[#120a05] border border-[#5a3d22] rounded-xl px-4 py-2.5 text-sm text-amber-200 focus:outline-none focus:border-emerald-500 font-mono">
          <option value="${domain}">${domain} (Default Akses)</option>
        </select>
      </div>
      <div>
        <label class="block text-xs font-medium text-amber-300/80 mb-1">Custom Path / IP:Port</label>
        <input type="text" id="proxyIp" value="id-dnva" oninput="generateLinks()" class="w-full bg-[#120a05] border border-[#5a3d22] rounded-xl px-4 py-2.5 text-sm text-amber-100 focus:outline-none focus:border-emerald-500 font-mono" placeholder="id-dnva atau IP:Port">
      </div>
    </div>

    <div class="mb-4">
      <label id="bugHostLabel" class="block text-xs font-medium text-amber-300/80 mb-1">Pilih Preset / Ketik Manual Bug Host (WS)</label>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <select id="wildcardPresetSelect" onchange="applyWildcardPreset()" class="w-full bg-[#120a05] border border-[#5a3d22] rounded-xl px-4 py-2.5 text-sm text-amber-200 focus:outline-none focus:border-emerald-500 font-mono">
          <option value="">-- Pilih dari List Host --</option>
${BUG_HOST_LIST.map(function(h){ return '          <option value="' + h + '">' + h + '</option>'; }).join("\n")}
        </select>
        <input type="text" id="bugHost" placeholder="support.zoom.us" oninput="generateLinks()" class="w-full bg-[#120a05] border border-[#5a3d22] rounded-xl px-4 py-2.5 text-sm text-amber-100 focus:outline-none focus:border-emerald-500 font-mono">
      </div>
    </div>

    <div class="mb-4">
      <div class="flex justify-between items-center mb-1">
        <label class="block text-xs font-medium text-amber-300/80">UUID / Secret Key</label>
        <button onclick="regenUUID()" class="text-xs text-emerald-400 hover:text-emerald-300 flex items-center gap-1 font-semibold">
          <i class="fa-solid fa-arrows-rotate"></i> Acak UUID Baru (Remake)
        </button>
      </div>
      <input type="text" id="userUuid" value="${USER_UUID}" oninput="onUuidInput()" class="w-full bg-[#120a05] border border-[#5a3d22] rounded-xl px-4 py-2.5 text-sm text-amber-100 focus:outline-none focus:border-emerald-500 font-mono">
    </div>

    <button onclick="generateLinks()" class="w-full bg-gradient-to-r from-amber-700 to-emerald-700 hover:from-amber-600 hover:to-emerald-600 text-white font-bold py-2.5 rounded-xl transition duration-200 text-sm shadow-lg shadow-black/40">
      Generate VMess Config Link
    </button>
    <p class="text-[11px] text-amber-300/60 mt-3">Catatan: UUID harus sama dengan USER_UUID di script (khusus VMess; VLESS terima UUID apa pun). Password Trojan otomatis sama dengan UUID (edit manual kalau mau beda). DNS tidak bocor = nyalakan Custom DNS di apk (1.1.1.1). Port 80 = matikan "Always Use HTTPS" di zona domain.</p>
  </div>

  <!-- Output -->
  <div id="outputContainer" class="space-y-4">
    <div class="wood-card rounded-2xl p-5">
      <div class="flex items-center justify-between mb-2">
        <span id="outputTitle" class="text-xs font-bold text-emerald-400 tracking-wider">VMESS WS CONFIG LINK</span>
        <button onclick="copyToClipboard('generatedLink')" class="text-xs text-amber-200 hover:text-white flex items-center gap-1 bg-[#120a05] border border-[#5a3d22] px-3 py-1 rounded-lg">
          <i class="fa-regular fa-copy"></i> Salin Link
        </button>
      </div>
      <textarea id="generatedLink" readonly rows="4" class="w-full bg-[#120a05]/80 border border-[#3d2612] rounded-lg px-3 py-2 text-xs font-mono text-amber-300 select-all resize-none focus:outline-none"></textarea>
    </div>
    <div class="wood-card rounded-2xl p-5">
      <div class="flex items-center justify-between mb-2">
        <span class="text-xs font-bold text-emerald-400 tracking-wider">DETAIL JSON</span>
        <button onclick="copyToClipboard('generatedJson')" class="text-xs text-amber-200 hover:text-white flex items-center gap-1 bg-[#120a05] border border-[#5a3d22] px-3 py-1 rounded-lg">
          <i class="fa-regular fa-copy"></i> Salin JSON
        </button>
      </div>
      <textarea id="generatedJson" readonly rows="5" class="w-full bg-[#120a05]/80 border border-[#3d2612] rounded-lg px-3 py-2 text-xs font-mono text-amber-300 select-all resize-none focus:outline-none"></textarea>
    </div>
  </div>

</div>

<script>
var currentHostDefault = "${domain}";
function el(id){ return document.getElementById(id); }
function syncPathInput(){
  var sel = el('proxySelect');
  if (sel.value !== 'manual') el('proxyIp').value = sel.value;
}
function toggleBugInput(){
  var m = el('methodSelect').value;
  el('bugHostLabel').textContent = (m === 'ws') ? 'Pilih Preset / Ketik Manual Bug Host (WS)' : 'Pilih Preset / Ketik Manual Bug Host (Wildcard)';
}
function applyWildcardPreset(){
  var v = el('wildcardPresetSelect').value;
  if (v) { el('bugHost').value = v; generateLinks(); }
}
var trojanPassDirty = false;
function onUuidInput(){
  if (!trojanPassDirty) el('trojanPass').value = el('userUuid').value;
  generateLinks();
}
function onTrojanPassInput(){
  trojanPassDirty = true;
  generateLinks();
}
function regenUUID(){
  el('userUuid').value = crypto.randomUUID();
  onUuidInput();
}
function b64(str){ return btoa(unescape(encodeURIComponent(str))); }
function generateLinks(){
  var proto = el('protoSelect').value;
  var method = el('methodSelect').value;
  var port = el('portSelect').value;
  var scy = el('cipherSelect').value;
  var pathVal = el('proxyIp').value.trim() || 'id-dnva';
  var uuid = el('userUuid').value.trim();
  var bug = el('bugHost').value.trim();
  var base = el('baseHostSelect').value || currentHostDefault;
  var path = pathVal.charAt(0) === '/' ? pathVal : '/' + pathVal;
  var address, hostHeader, sni;
  if (method === 'ws') {
    address = bug ? bug : base;
    hostHeader = base;
    sni = base;
  } else {
    address = bug ? (bug + '.' + base) : base;
    hostHeader = address;
    sni = address;
  }
  var label = pathVal.replace(/^\\//, '').replace(/[:/]/g, '_');
  var sec = port === '443' ? 'tls' : 'none';
  var link, json;
  if (proto === 'vmess') {
    var cfg = {
      v: '2',
      ps: 'VMess-' + label + '-' + port,
      add: address,
      port: port,
      id: uuid,
      aid: '0',
      scy: scy,
      net: 'ws',
      type: 'none',
      host: hostHeader,
      path: path,
      tls: port === '443' ? 'tls' : '',
      sni: sni
    };
    json = JSON.stringify(cfg, null, 2);
    link = 'vmess://' + b64(json);
  } else if (proto === 'vless') {
    var q = 'encryption=none&security=' + sec + '&type=ws&host=' + encodeURIComponent(hostHeader) + '&path=' + encodeURIComponent(path);
    if (sec === 'tls') q += '&sni=' + encodeURIComponent(sni);
    link = 'vless://' + uuid + '@' + address + ':' + port + '?' + q + '#VLESS-' + label + '-' + port;
    json = JSON.stringify({ protocol: 'vless', address: address, port: port, uuid: uuid, encryption: 'none', network: 'ws', security: sec, host: hostHeader, path: path, sni: sni }, null, 2);
  } else {
    var pw = el('trojanPass').value.trim();
    var q2 = 'security=' + sec + '&type=ws&host=' + encodeURIComponent(hostHeader) + '&path=' + encodeURIComponent(path);
    if (sec === 'tls') q2 += '&sni=' + encodeURIComponent(sni);
    link = 'trojan://' + encodeURIComponent(pw) + '@' + address + ':' + port + '?' + q2 + '#Trojan-' + label + '-' + port;
    json = JSON.stringify({ protocol: 'trojan', address: address, port: port, password: pw, network: 'ws', security: sec, host: hostHeader, path: path, sni: sni }, null, 2);
  }
  el('outputTitle').textContent = proto.toUpperCase() + ' WS CONFIG LINK';
  el('generatedLink').value = link;
  el('generatedJson').value = json;
}
function copyToClipboard(id){
  var input = el(id);
  if (!input.value) return;
  input.select();
  input.setSelectionRange(0, 99999);
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(input.value).then(function(){ alert('Berhasil disalin!'); }).catch(function(){ document.execCommand('copy'); });
  } else {
    document.execCommand('copy');
    alert('Berhasil disalin!');
  }
}
(function checkStatus(){
  var t0 = Date.now();
  fetch(location.href, { method: 'HEAD', cache: 'no-store' }).then(function(){
    el('statusText').textContent = 'Online • ' + (Date.now() - t0) + ' ms';
  }).catch(function(){
    el('statusText').textContent = 'Tidak Terjangkau';
    el('statusPingDot').className = 'w-3 h-3 rounded-full bg-red-500';
  });
})();
syncPathInput();
toggleBugInput();
generateLinks();
</script>
</body>
</html>`;
  }
}


// ---------------- entry point ----------------
export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const isWs = req.headers.get("Upgrade")?.toLowerCase() === "websocket";

    if (isWs) {
      let fallbackNode = null;
      const rawPath = decodeURIComponent(url.pathname.replace(/^\//, ""));
      if (PROXY_MAP[rawPath]) {
        const hp = PROXY_MAP[rawPath].split(":");
        fallbackNode = { host: hp.slice(0, -1).join(":"), port: parseInt(hp[hp.length - 1], 10) };
      } else {
        const m = rawPath.match(/^(.+[:=-]\d+)$/);
        if (m) {
          const parts = m[1].split(/[:=-]/);
          fallbackNode = { host: parts.slice(0, -1).join(":"), port: parseInt(parts[parts.length - 1], 10) };
        }
      }
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      server.accept();

      const session = await handleSession(server, fallbackNode);
      const ed = req.headers.get("sec-websocket-protocol");
      if (ed) {
        try {
          const bin = atob(ed.replace(/-/g, "+").replace(/_/g, "/"));
          const first = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) first[i] = bin.charCodeAt(i);
          session.enqueue(first);
        } catch {}
      }
      server.addEventListener("message", (e) => {
        if (e.data instanceof ArrayBuffer) session.enqueue(new Uint8Array(e.data));
        else if (e.data instanceof Uint8Array) session.enqueue(e.data);
        else if (typeof e.data === "string") session.enqueue(TE.encode(e.data));
        else if (e.data && typeof e.data.arrayBuffer === "function") e.data.arrayBuffer().then(b => session.enqueue(new Uint8Array(b)));
      });
      server.addEventListener("close", () => session.closeAll());
      server.addEventListener("error", () => session.closeAll());

      return new Response(null, {
        status: 101, webSocket: client,
        headers: ed ? { "Sec-WebSocket-Protocol": ed } : {}
      });
    }

    if (url.pathname === "/" || url.pathname === "") {
      return new Response(ConfigUI.render(url.hostname), {
        status: 200,
        headers: { "content-type": "text/html;charset=UTF-8", "Cache-Control": "no-store" }
      });
    }
    return fetch(req);
  }
};

// ===== v1.12 - Muse VMess MultiProto (VMess AEAD Penuh) === END OF FILE v1.12 =====
