const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('../config');
const { query } = require('../db');
const { encrypt, decrypt } = require('../crypto/aes');
const { generateSecret, buildOtpAuthUri, verifyTOTP } = require('../crypto/totp');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Helper to generate full access JWT.
 */
function createFullAccessToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      scope: 'full_access'
    },
    config.JWT_SECRET,
    { expiresIn: '24h' }
  );
}

/**
 * Helper to generate short-lived 2FA challenge JWT.
 */
function createChallengeToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      scope: '2fa_challenge'
    },
    config.JWT_SECRET,
    { expiresIn: '5m' }
  );
}

/**
 * POST /api/auth/register
 * Registers a new user with hashed password.
 */
router.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || typeof email !== 'string' || !EMAIL_REGEX.test(email.trim())) {
      return res.status(400).json({ error: 'Valid email is required' });
    }

    if (!password || typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long' });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Check if user already exists
    const existing = await query('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    // Hash password with bcrypt
    const passwordHash = await bcrypt.hash(password, 10);

    const insertResult = await query(
      'INSERT INTO users (email, password_hash, totp_enabled) VALUES ($1, $2, false) RETURNING id, email',
      [normalizedEmail, passwordHash]
    );

    const newUser = insertResult.rows[0];
    return res.status(201).json({
      id: String(newUser.id),
      email: newUser.email
    });
  } catch (err) {
    console.error('[Register Error]', err);
    return res.status(500).json({ error: 'Internal server error during registration' });
  }
});

/**
 * POST /api/auth/login
 * Primary password login. Branches based on totp_enabled status.
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const normalizedEmail = String(email).toLowerCase().trim();

    const userResult = await query(
      'SELECT id, email, password_hash, totp_enabled FROM users WHERE email = $1',
      [normalizedEmail]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = userResult.rows[0];
    const passwordMatch = await bcrypt.compare(String(password), user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Branching: If 2FA enabled, return challenge token and halt
    if (user.totp_enabled) {
      const challengeToken = createChallengeToken(user);
      return res.status(200).json({
        requires_2fa: true,
        challenge_token: challengeToken
      });
    }

    // If 2FA not enabled, issue full access token
    const token = createFullAccessToken(user);
    return res.status(200).json({
      token
    });
  } catch (err) {
    console.error('[Login Error]', err);
    return res.status(500).json({ error: 'Internal server error during login' });
  }
});

/**
 * POST /api/auth/2fa/setup
 * Initiates TOTP setup. Returns secret and otpauth URI; stores encrypted secret in DB.
 */
router.post('/2fa/setup', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;

    // Fetch user to confirm existence
    const userResult = await query('SELECT id, email FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    const user = userResult.rows[0];

    // 1. Generate 20-byte cryptographically secure Base32 secret
    const secret = generateSecret(20);

    // 2. Encrypt secret with AES-256-GCM (generates fresh 12-byte IV every call)
    const encrypted = encrypt(secret);

    // 3. Store encrypted secret in DB (totp_enabled remains false until verified)
    await query(
      `UPDATE users
       SET totp_secret_encrypted = $1,
           totp_iv = $2,
           totp_tag = $3,
           totp_enabled = false
       WHERE id = $4`,
      [encrypted.ciphertext, encrypted.iv, encrypted.authTag, userId]
    );

    // 4. Construct otpauth URI
    const uri = buildOtpAuthUri('Secure2FA', user.email, secret);

    return res.status(200).json({
      secret,
      uri
    });
  } catch (err) {
    console.error('[2FA Setup Error]', err);
    return res.status(500).json({ error: 'Internal server error during 2FA setup' });
  }
});

/**
 * POST /api/auth/2fa/verify
 * Validates first TOTP code after setup and officially enables 2FA.
 */
router.post('/2fa/verify', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { code } = req.body || {};

    const cleanCode = String(code || '').trim();
    if (!/^\d{6}$/.test(cleanCode)) {
      return res.status(400).json({ error: 'Valid 6-digit numeric code is required' });
    }

    const userResult = await query(
      'SELECT id, email, totp_secret_encrypted, totp_iv, totp_tag, last_totp_window FROM users WHERE id = $1',
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userResult.rows[0];
    if (!user.totp_secret_encrypted || !user.totp_iv || !user.totp_tag) {
      return res.status(400).json({ error: '2FA setup has not been initiated for this account' });
    }

    // Decrypt the secret from DB
    let plaintextSecret;
    try {
      plaintextSecret = decrypt(user.totp_iv, user.totp_secret_encrypted, user.totp_tag);
    } catch (decErr) {
      console.error('[Decryption Failed on Verify]', decErr);
      return res.status(500).json({ error: 'Failed to decrypt TOTP credentials' });
    }

    // Verify TOTP code with standard drift window (window = 1: T-1, T, T+1)
    const verification = verifyTOTP(plaintextSecret, cleanCode, { window: 1 });
    if (!verification.valid) {
      return res.status(400).json({ error: 'Invalid TOTP code' });
    }

    // Update DB: officially enable 2FA and record window to prevent code reuse
    await query(
      'UPDATE users SET totp_enabled = true, last_totp_window = $1 WHERE id = $2',
      [verification.matchingWindow, userId]
    );

    return res.status(200).json({
      message: '2FA successfully enabled'
    });
  } catch (err) {
    console.error('[2FA Verify Error]', err);
    return res.status(500).json({ error: 'Internal server error during 2FA verification' });
  }
});

/**
 * POST /api/auth/2fa/login
 * Completes secondary login stage by verifying TOTP code against challenge token.
 * Strictly enforces replay protection via last_totp_window.
 */
router.post('/2fa/login', async (req, res) => {
  try {
    const { challenge_token, code } = req.body || {};

    if (!challenge_token) {
      return res.status(401).json({ error: 'Challenge token is required' });
    }

    const cleanCode = String(code || '').trim();
    if (!/^\d{6}$/.test(cleanCode)) {
      return res.status(401).json({ error: 'Invalid TOTP code format' });
    }

    // Verify challenge token
    let decoded;
    try {
      decoded = jwt.verify(challenge_token, config.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired challenge token' });
    }

    if (decoded.scope !== '2fa_challenge') {
      return res.status(401).json({ error: 'Invalid challenge token scope' });
    }

    // Fetch user and encrypted credentials
    const userResult = await query(
      'SELECT id, email, totp_enabled, totp_secret_encrypted, totp_iv, totp_tag, last_totp_window FROM users WHERE id = $1',
      [decoded.sub]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'User not found' });
    }

    const user = userResult.rows[0];
    if (!user.totp_enabled || !user.totp_secret_encrypted) {
      return res.status(401).json({ error: '2FA is not enabled for this user' });
    }

    // Decrypt the TOTP secret
    let plaintextSecret;
    try {
      plaintextSecret = decrypt(user.totp_iv, user.totp_secret_encrypted, user.totp_tag);
    } catch (decErr) {
      console.error('[Decryption Failed on 2FA Login]', decErr);
      return res.status(500).json({ error: 'Failed to decrypt TOTP credentials' });
    }

    // Validate TOTP code with clock drift (T-1, T, T+1)
    const verification = verifyTOTP(plaintextSecret, cleanCode, { window: 1 });
    if (!verification.valid) {
      return res.status(401).json({ error: 'Invalid TOTP code' });
    }

    const matchingWindow = verification.matchingWindow;

    // Replay Protection Check:
    // If matchingWindow <= last_totp_window, code was already used or expired
    if (user.last_totp_window !== null && matchingWindow <= user.last_totp_window) {
      return res.status(401).json({
        error: 'Replay detected: TOTP code has already been used in this or a prior window'
      });
    }

    // Atomic update to avoid race conditions:
    // Only updates if last_totp_window is still less than matchingWindow
    const updateResult = await query(
      `UPDATE users
       SET last_totp_window = $1
       WHERE id = $2 AND (last_totp_window IS NULL OR last_totp_window < $1)
       RETURNING id`,
      [matchingWindow, user.id]
    );

    if (updateResult.rowCount === 0) {
      return res.status(401).json({
        error: 'Replay detected: concurrent login attempt already consumed this TOTP window'
      });
    }

    // Issue Full Access Token
    const fullToken = createFullAccessToken(user);
    return res.status(200).json({
      token: fullToken
    });
  } catch (err) {
    console.error('[2FA Login Error]', err);
    return res.status(500).json({ error: 'Internal server error during 2FA login' });
  }
});

/**
 * GET /api/user/me
 * Protected endpoint returning the authenticated user profile.
 */
router.get('/user/me', requireAuth, async (req, res) => {
  try {
    const userResult = await query(
      'SELECT id, email, totp_enabled, last_totp_window FROM users WHERE id = $1',
      [req.user.id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userResult.rows[0];
    return res.status(200).json({
      id: user.id,
      email: user.email,
      totp_enabled: user.totp_enabled,
      last_totp_window: user.last_totp_window
    });
  } catch (err) {
    console.error('[User Me Error]', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
