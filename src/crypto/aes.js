const crypto = require('crypto');
const config = require('../config');

const ALGORITHM = 'aes-256-gcm';

/**
 * Returns the Master Key as a 32-byte Buffer.
 * Supports loading dynamically if key changes in environment.
 */
function getMasterKey() {
  const hexKey = process.env.MASTER_ENCRYPTION_KEY || config.MASTER_ENCRYPTION_KEY;
  if (!hexKey) {
    throw new Error('MASTER_ENCRYPTION_KEY environment variable is not defined.');
  }
  const keyBuf = Buffer.from(hexKey, 'hex');
  if (keyBuf.length !== 32) {
    throw new Error(`MASTER_ENCRYPTION_KEY must be exactly 32 bytes (64 hex characters). Got ${keyBuf.length} bytes.`);
  }
  return keyBuf;
}

/**
 * Encrypts a plaintext string (e.g. Base32 TOTP secret) using AES-256-GCM.
 * A new random 12-byte IV is generated for each operation.
 *
 * @param {string} plaintext - The plaintext string to encrypt.
 * @returns {{ iv: string, ciphertext: string, authTag: string }} Hex-encoded encryption components.
 */
function encrypt(plaintext) {
  if (typeof plaintext !== 'string') {
    throw new TypeError('Plaintext must be a string');
  }

  const masterKey = getMasterKey();
  // Standard 12-byte (96-bit) IV for GCM
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv(ALGORITHM, masterKey, iv);

  let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
  ciphertext += cipher.final('hex');

  const authTag = cipher.getAuthTag().toString('hex');

  return {
    iv: iv.toString('hex'),
    ciphertext,
    authTag
  };
}

/**
 * Decrypts ciphertext back to plaintext using AES-256-GCM and verifies authenticity.
 *
 * @param {string} ivHex - The 12-byte IV in hex format.
 * @param {string} ciphertextHex - The encrypted data in hex format.
 * @param {string} authTagHex - The 16-byte authentication tag in hex format.
 * @returns {string} The original plaintext.
 * @throws {Error} Throws if authentication fails or payload has been tampered with.
 */
function decrypt(ivHex, ciphertextHex, authTagHex) {
  if (!ivHex || !ciphertextHex || !authTagHex) {
    throw new Error('Missing decryption parameters: iv, ciphertext, and authTag are all required');
  }

  const masterKey = getMasterKey();
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');

  const decipher = crypto.createDecipheriv(ALGORITHM, masterKey, iv);
  decipher.setAuthTag(authTag);

  let plaintext = decipher.update(ciphertextHex, 'hex', 'utf8');
  plaintext += decipher.final('utf8');

  return plaintext;
}

module.exports = {
  encrypt,
  decrypt,
  getMasterKey
};
