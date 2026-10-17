const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const { query } = require('./index');
const { encrypt } = require('../crypto/aes');

/**
 * Seeds the database with the test user defined in submission.json.
 * Ensures the user has:
 *  - email: submission.json testUser.email
 *  - password_hash: bcrypt hash of testUser.password
 *  - totp_enabled: true
 *  - totp_secret_encrypted, totp_iv, totp_tag: AES-256-GCM encrypted plaintextTotpSecret
 *  - last_totp_window: NULL (ready for fresh TOTP login verification)
 */
async function seed() {
  console.log('[Seed] Seeding database with predefined test user...');

  const submissionPath = path.resolve(__dirname, '../../submission.json');
  let testUser = {
    email: 'test_2fa@example.com',
    password: 'securePassword123',
    plaintextTotpSecret: 'JBSWY3DPEHPK3PXP'
  };

  if (fs.existsSync(submissionPath)) {
    try {
      const raw = fs.readFileSync(submissionPath, 'utf8');
      const data = JSON.parse(raw);
      if (data.testUser) {
        testUser = { ...testUser, ...data.testUser };
      }
    } catch (err) {
      console.warn('[Seed Warning] Failed to parse submission.json, using defaults:', err.message);
    }
  }

  // 1. Hash the password with bcrypt (10 rounds)
  const passwordHash = await bcrypt.hash(testUser.password, 10);

  // 2. Encrypt the Base32 TOTP secret with AES-256-GCM
  const encryptedPayload = encrypt(testUser.plaintextTotpSecret);

  // 3. Upsert user into database
  const upsertQuery = `
    INSERT INTO users (
      email,
      password_hash,
      totp_enabled,
      totp_secret_encrypted,
      totp_iv,
      totp_tag,
      last_totp_window
    )
    VALUES ($1, $2, true, $3, $4, $5, NULL)
    ON CONFLICT (email) DO UPDATE SET
      password_hash = EXCLUDED.password_hash,
      totp_enabled = true,
      totp_secret_encrypted = EXCLUDED.totp_secret_encrypted,
      totp_iv = EXCLUDED.totp_iv,
      totp_tag = EXCLUDED.totp_tag,
      last_totp_window = NULL
    RETURNING id, email, totp_enabled;
  `;

  const res = await query(upsertQuery, [
    testUser.email.toLowerCase().trim(),
    passwordHash,
    encryptedPayload.ciphertext,
    encryptedPayload.iv,
    encryptedPayload.authTag
  ]);

  console.log(`[Seed] Seeded user "${res.rows[0].email}" (id: ${res.rows[0].id}, 2FA: ${res.rows[0].totp_enabled})`);
}

if (require.main === module) {
  seed()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('[Seed Failed]', err);
      process.exit(1);
    });
}

module.exports = { seed };
