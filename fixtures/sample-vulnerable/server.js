// Intentionally vulnerable sample — DO NOT USE.
const crypto = require('crypto');

// MD5 digest — broken hash.
function etag(body) {
  return crypto.createHash('md5').update(body).digest('hex');
}

// RC4 — a broken stream cipher.
function obfuscate(data, key) {
  const cipher = crypto.createCipheriv('rc4', key, '');
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

// Hardcoded private key material.
const PRIVATE_KEY = '0123456789abcdef0123456789abcdef';

module.exports = { etag, obfuscate, PRIVATE_KEY };
