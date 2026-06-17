'use strict';
// Hand-rolled SHA-256 compression (textbook) - no crypto imports at all.

const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
];

const H_INIT = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

function rotr(x, n) {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function compress(state, w) {
  let [a, b, c, d, e, f, g, h] = state;
  for (let t = 0; t < K.length; t++) {
    const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const ch = (e & f) ^ (~e & g);
    const t1 = (h + s1 + ch + K[t] + (w[t] | 0)) >>> 0;
    h = g; g = f; f = e; e = (d + t1) >>> 0;
    d = c; c = b; b = a; a = t1;
  }
  return [a, b, c, d, e, f, g, h];
}

module.exports = { H_INIT, compress };
