/**
 * RFC 4648 Base32 implementation.
 * Standard alphabet: A-Z (0-25) and 2-7 (26-31).
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Encodes a Buffer to an RFC 4648 Base32 string (unpadded).
 * @param {Buffer} buf - Input buffer
 * @returns {string} Base32 encoded string
 */
function base32Encode(buf) {
  if (!Buffer.isBuffer(buf)) {
    buf = Buffer.from(buf);
  }

  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i];
    bits += 8;
    while (bits >= 5) {
      output += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

/**
 * Decodes an RFC 4648 Base32 string to a Buffer.
 * @param {string} str - Base32 string (case-insensitive, optional '=' padding allowed)
 * @returns {Buffer} Decoded buffer
 */
function base32Decode(str) {
  if (typeof str !== 'string') {
    throw new TypeError('Expected Base32 string as input');
  }

  const clean = str.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];

  for (let i = 0; i < clean.length; i++) {
    const idx = ALPHABET.indexOf(clean[i]);
    if (idx === -1) {
      throw new Error(`Invalid Base32 character: "${clean[i]}" at index ${i}`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

module.exports = {
  base32Encode,
  base32Decode
};
