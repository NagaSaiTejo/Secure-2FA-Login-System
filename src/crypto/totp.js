const crypto = require('crypto');
const { base32Encode, base32Decode } = require('./base32');

const DEFAULT_TIME_STEP = 30; // 30 seconds period (RFC 6238)
const DEFAULT_DIGITS = 6;     // 6-digit OTP

/**
 * Computes an HMAC-based One-Time Password (HOTP) per RFC 4226.
 *
 * @param {Buffer} secretBuf - Decoded secret key buffer
 * @param {number} counter - 64-bit integer counter value
 * @param {number} digits - Number of digits (default 6)
 * @returns {string} Zero-padded OTP code
 */
function generateHOTP(secretBuf, counter, digits = DEFAULT_DIGITS) {
  // Construct 8-byte big-endian counter buffer
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigInt64BE(BigInt(counter));

  // HMAC-SHA1
  const hmac = crypto.createHmac('sha1', secretBuf).update(counterBuf).digest();

  // Dynamic truncation (RFC 4226 Section 5.4)
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = binary % Math.pow(10, digits);
  return otp.toString().padStart(digits, '0');
}

/**
 * Generates a Time-based One-Time Password (TOTP) per RFC 6238.
 *
 * @param {string} base32Secret - The Base32 encoded shared secret
 * @param {number} [timestampSeconds] - Optional epoch timestamp in seconds (defaults to now)
 * @param {number} [timeStep=30] - Time window step in seconds
 * @param {number} [digits=6] - Number of digits
 * @returns {string} 6-digit TOTP code
 */
function generateTOTP(base32Secret, timestampSeconds, timeStep = DEFAULT_TIME_STEP, digits = DEFAULT_DIGITS) {
  const secretBuf = base32Decode(base32Secret);
  const now = timestampSeconds !== undefined ? timestampSeconds : Math.floor(Date.now() / 1000);
  const windowCounter = Math.floor(now / timeStep);
  return generateHOTP(secretBuf, windowCounter, digits);
}

/**
 * Verifies a TOTP code against a Base32 secret with clock drift tolerance
 * and constant-time string comparison.
 *
 * @param {string} base32Secret - The Base32 encoded shared secret
 * @param {string} userCode - The user-provided 6-digit code
 * @param {object} [options] - Verification options
 * @param {number} [options.window=1] - Number of time steps forward/backward to check
 * @param {number} [options.timeStep=30] - Time window step in seconds
 * @param {number} [options.timestamp] - Current timestamp in seconds (defaults to Date.now()/1000)
 * @returns {{ valid: boolean, matchingWindow: number | null }} Verification result and matched window
 */
function verifyTOTP(base32Secret, userCode, options = {}) {
  const window = options.window !== undefined ? options.window : 1;
  const timeStep = options.timeStep || DEFAULT_TIME_STEP;
  const now = options.timestamp !== undefined ? options.timestamp : Math.floor(Date.now() / 1000);
  const currentWindow = Math.floor(now / timeStep);

  const cleanCode = String(userCode || '').trim();
  if (!/^\d{6}$/.test(cleanCode)) {
    return { valid: false, matchingWindow: null };
  }

  let secretBuf;
  try {
    secretBuf = base32Decode(base32Secret);
  } catch (err) {
    return { valid: false, matchingWindow: null };
  }

  // Ordered list of candidate windows: current window (T), then T-1, then T+1
  const candidateWindows = [currentWindow];
  for (let w = 1; w <= window; w++) {
    candidateWindows.push(currentWindow - w);
    candidateWindows.push(currentWindow + w);
  }

  const userBuf = Buffer.from(cleanCode, 'utf8');

  for (const w of candidateWindows) {
    const expected = generateHOTP(secretBuf, w, DEFAULT_DIGITS);
    const expectedBuf = Buffer.from(expected, 'utf8');

    // Constant-time comparison to prevent timing attacks
    if (expectedBuf.length === userBuf.length && crypto.timingSafeEqual(expectedBuf, userBuf)) {
      return { valid: true, matchingWindow: w };
    }
  }

  return { valid: false, matchingWindow: null };
}

/**
 * Generates a cryptographically random Base32 secret for TOTP setup.
 *
 * @param {number} [byteLength=20] - Number of random bytes (20 bytes = 160 bits, standard for SHA-1)
 * @returns {string} Base32 encoded secret string
 */
function generateSecret(byteLength = 20) {
  const bytes = crypto.randomBytes(byteLength);
  return base32Encode(bytes);
}

/**
 * Constructs an otpauth:// URI for authenticator applications.
 *
 * @param {string} issuer - Name of the application / service
 * @param {string} account - User's account identifier (e.g. email)
 * @param {string} base32Secret - The Base32 shared secret
 * @returns {string} Formatted otpauth:// URI
 */
function buildOtpAuthUri(issuer, account, base32Secret) {
  const safeIssuer = encodeURIComponent(issuer);
  const safeAccount = encodeURIComponent(account);
  return `otpauth://totp/${safeIssuer}:${safeAccount}?secret=${base32Secret}&issuer=${safeIssuer}&algorithm=SHA1&digits=6&period=30`;
}

module.exports = {
  generateHOTP,
  generateTOTP,
  verifyTOTP,
  generateSecret,
  buildOtpAuthUri
};
