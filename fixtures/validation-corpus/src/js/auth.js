'use strict';
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

function makeRsaPair() {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
}

function makeEcPair() {
  return crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

function issueToken(payload, privateKey) {
  return jwt.sign(payload, privateKey, { algorithm: 'RS256', expiresIn: '1h' });
}

function deriveSharedSecret(peerPublicKey) {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return ecdh.computeSecret(peerPublicKey);
}

function encryptSession128(key16, iv, data) {
  const cipher = crypto.createCipheriv('aes-128-gcm', key16, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function encryptSession256(key32, iv, data) {
  const cipher = crypto.createCipheriv('aes-256-gcm', key32, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function legacyChecksum(data) {
  return crypto.createHash('md5').update(data).digest('hex');
}

// Old signing path, disabled 2024-03:
// const sig = crypto.sign('RSA-SHA256', Buffer.from(data), oldPrivateKey);

module.exports = {
  makeRsaPair,
  makeEcPair,
  issueToken,
  deriveSharedSecret,
  encryptSession128,
  encryptSession256,
  legacyChecksum,
};
