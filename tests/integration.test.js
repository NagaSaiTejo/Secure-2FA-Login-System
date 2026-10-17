const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { query, closePool, ping } = require('../src/db');
const { generateTOTP, verifyTOTP } = require('../src/crypto/totp');
const { decrypt } = require('../src/crypto/aes');
const config = require('../src/config');

const BASE_URL = `http://localhost:${config.PORT}`;

// Helper HTTP client using native Node fetch
async function request(endpoint, options = {}) {
  const url = `${BASE_URL}${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {})
  };

  const fetchOptions = {
    method: options.method || 'GET',
    headers
  };

  if (options.body) {
    fetchOptions.body = typeof options.body === 'string' ? options.body : JSON.stringify(options.body);
  }

  const res = await fetch(url, fetchOptions);
  let data;
  try {
    data = await res.json();
  } catch (err) {
    data = null;
  }

  return {
    status: res.status,
    headers: res.headers,
    body: data
  };
}

let passedCount = 0;
let failedCount = 0;

async function test(name, fn) {
  try {
    process.stdout.write(`  Testing: ${name}... `);
    await fn();
    console.log(`\x1b[32mPASSED\x1b[0m`);
    passedCount++;
  } catch (err) {
    console.log(`\x1b[31mFAILED\x1b[0m`);
    console.error(`    \x1b[31mError: ${err.message}\x1b[0m`);
    if (err.stack) {
      console.error(err.stack.split('\n').slice(1, 3).map(l => '    ' + l).join('\n'));
    }
    failedCount++;
  }
}

async function runAllTests() {
  console.log('\n======================================================');
  console.log('  SECURE 2FA LOGIN SYSTEM - INTEGRATION TEST SUITE');
  console.log('======================================================\n');

  // Verify server is reachable
  const isHealthy = await ping();
  if (!isHealthy) {
    console.error('\x1b[31m[ERROR] Database connection failed. Make sure PostgreSQL is running.\x1b[0m');
    process.exit(1);
  }

  // 1. Docker Compose setup & env example test
  await test('Requirement 1 & 2: .env.example exists and contains required keys', async () => {
    const envExamplePath = path.resolve(__dirname, '../.env.example');
    assert(fs.existsSync(envExamplePath), '.env.example file must exist');

    const content = fs.readFileSync(envExamplePath, 'utf8');
    assert(content.includes('DATABASE_URL='), '.env.example must define DATABASE_URL');
    assert(content.includes('JWT_SECRET='), '.env.example must define JWT_SECRET');
    assert(content.includes('MASTER_ENCRYPTION_KEY='), '.env.example must define MASTER_ENCRYPTION_KEY');
  });

  // 2. Database Schema Check
  await test('Requirement 3: users table exists with all 8 specified columns and constraints', async () => {
    const res = await query(`
      SELECT column_name, data_type, is_nullable
      FROM information_schema.columns
      WHERE table_name = 'users';
    `);

    assert(res.rows.length >= 8, `Expected at least 8 columns, found ${res.rows.length}`);

    const columns = {};
    res.rows.forEach(r => {
      columns[r.column_name] = r.data_type;
    });

    const expectedCols = [
      'id',
      'email',
      'password_hash',
      'totp_enabled',
      'totp_secret_encrypted',
      'totp_iv',
      'totp_tag',
      'last_totp_window'
    ];

    for (const col of expectedCols) {
      assert(columns[col] !== undefined, `Missing column "${col}" in users table`);
    }

    // Verify types
    assert(['uuid', 'integer', 'bigint'].includes(columns.id), `Expected UUID or Integer id, got ${columns.id}`);
    assert(['character varying', 'text'].includes(columns.email), `Email should be string`);
    assert(columns.totp_enabled === 'boolean', `totp_enabled must be boolean`);
    assert(columns.last_totp_window === 'integer', `last_totp_window must be integer`);
  });

  // 3. User Registration
  const testEmail = `user_${Date.now()}@test.com`;
  const testPassword = 'StrongPassword123!';
  let registeredUserId = null;

  await test('Requirement 4: POST /api/auth/register hashes password and returns 201 Created', async () => {
    const res = await request('/api/auth/register', {
      method: 'POST',
      body: {
        email: testEmail,
        password: testPassword
      }
    });

    assert.strictEqual(res.status, 201, `Expected status 201, got ${res.status}`);
    assert(res.body.id, 'Response must contain user id');
    assert.strictEqual(res.body.email, testEmail, 'Response email must match input');
    registeredUserId = res.body.id;

    // Verify password is NOT plaintext in DB
    const dbRes = await query('SELECT password_hash FROM users WHERE email = $1', [testEmail]);
    assert(dbRes.rows.length === 1, 'User row must exist in DB');
    const hash = dbRes.rows[0].password_hash;
    assert.notStrictEqual(hash, testPassword, 'Password must not be stored in plaintext');
    assert(hash.startsWith('$2a$') || hash.startsWith('$2b$'), 'Password must be bcrypt hash');
  });

  // 4. Primary Login for non-2FA user
  let fullAccessToken = null;

  await test('Requirement 5 (Part A): POST /api/auth/login returns full token for non-2FA user', async () => {
    const res = await request('/api/auth/login', {
      method: 'POST',
      body: {
        email: testEmail,
        password: testPassword
      }
    });

    assert.strictEqual(res.status, 200, `Expected 200 OK, got ${res.status}`);
    assert(res.body.token, 'Must return full access token');
    assert.strictEqual(res.body.requires_2fa, undefined, 'Non-2FA user should not have requires_2fa');
    fullAccessToken = res.body.token;

    // Bad password test
    const badRes = await request('/api/auth/login', {
      method: 'POST',
      body: {
        email: testEmail,
        password: 'wrong_password_999'
      }
    });
    assert.strictEqual(badRes.status, 401, 'Wrong password must return 401 Unauthorized');
  });

  // 5. TOTP Provisioning & Encryption at Rest
  let provisionedSecret = null;
  let firstIv = null;

  await test('Requirement 6 & 7: POST /api/auth/2fa/setup returns Base32 secret & URI, encrypts at rest', async () => {
    const res = await request('/api/auth/2fa/setup', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${fullAccessToken}` }
    });

    assert.strictEqual(res.status, 200, `Expected 200 OK, got ${res.status}`);
    assert(res.body.secret, 'Response must contain Base32 secret');
    assert(res.body.uri, 'Response must contain otpauth URI');
    assert(res.body.uri.startsWith('otpauth://totp/'), 'URI must start with otpauth://totp/');
    assert(/^[A-Z2-7]{16,64}$/.test(res.body.secret), 'Secret must be valid Base32 format');
    provisionedSecret = res.body.secret;

    // Check DB row
    const dbRes = await query(
      'SELECT totp_enabled, totp_secret_encrypted, totp_iv, totp_tag FROM users WHERE email = $1',
      [testEmail]
    );

    const row = dbRes.rows[0];
    assert.strictEqual(row.totp_enabled, false, 'totp_enabled must remain false before verify');
    assert(row.totp_secret_encrypted, 'totp_secret_encrypted must be populated');
    assert(row.totp_iv, 'totp_iv must be populated');
    assert(row.totp_tag, 'totp_tag must be populated');
    firstIv = row.totp_iv;

    // Cryptographic validation: plaintext must NOT appear in encrypted column
    assert.notStrictEqual(row.totp_secret_encrypted, provisionedSecret, 'Secret must not be stored in plaintext');
    assert(!row.totp_secret_encrypted.includes(provisionedSecret), 'Secret must not appear as substring');

    // Decrypt and ensure roundtrip
    const decrypted = decrypt(row.totp_iv, row.totp_secret_encrypted, row.totp_tag);
    assert.strictEqual(decrypted, provisionedSecret, 'Decrypted secret must match provisioned secret');

    // Repeated setup check: IV must change per request (fresh random IV)
    const res2 = await request('/api/auth/2fa/setup', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${fullAccessToken}` }
    });
    const dbRes2 = await query('SELECT totp_iv FROM users WHERE email = $1', [testEmail]);
    assert.notStrictEqual(dbRes2.rows[0].totp_iv, firstIv, 'Subsequent setup must generate unique IV');
    provisionedSecret = res2.body.secret;
  });

  // 6. TOTP Verification / Activation
  await test('Requirement 8: POST /api/auth/2fa/verify activates 2FA with valid code', async () => {
    // Generate valid TOTP code
    const validCode = generateTOTP(provisionedSecret);

    const res = await request('/api/auth/2fa/verify', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${fullAccessToken}` },
      body: { code: validCode }
    });

    assert.strictEqual(res.status, 200, `Expected 200 OK, got ${res.status}`);
    assert(res.body.message, 'Must return success message');

    // Check DB: totp_enabled must now be true
    const dbRes = await query('SELECT totp_enabled, last_totp_window FROM users WHERE email = $1', [testEmail]);
    assert.strictEqual(dbRes.rows[0].totp_enabled, true, 'totp_enabled must now be true');
    assert(dbRes.rows[0].last_totp_window !== null, 'last_totp_window should be initialized');
  });

  // 7. Login Branching for 2FA-Enabled User
  let challengeToken = null;

  await test('Requirement 5 (Part B): POST /api/auth/login returns challenge_token for 2FA user', async () => {
    const res = await request('/api/auth/login', {
      method: 'POST',
      body: {
        email: testEmail,
        password: testPassword
      }
    });

    assert.strictEqual(res.status, 200, `Expected 200 OK, got ${res.status}`);
    assert.strictEqual(res.body.requires_2fa, true, 'requires_2fa must be true');
    assert(res.body.challenge_token, 'Must return challenge_token');
    assert.strictEqual(res.body.token, undefined, 'Must NOT return full token when 2FA is required');
    challengeToken = res.body.challenge_token;
  });

  // 8. Strict 2FA Enforcement
  await test('Requirement 10: Challenge token is strictly forbidden from accessing protected routes', async () => {
    const res = await request('/api/auth/2fa/setup', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${challengeToken}` }
    });

    assert([401, 403].includes(res.status), `Expected 401 or 403 Forbidden, got ${res.status}`);
  });

  // 9. Secondary 2FA Login
  await test('Requirement 9: POST /api/auth/2fa/login validates TOTP and issues full access JWT', async () => {
    // We simulate a fresh window ahead to avoid collision with setup verify window
    const futureWindow = Math.floor(Date.now() / 1000 / 30) + 1;
    const futureTimestamp = futureWindow * 30;
    const code = generateTOTP(provisionedSecret, futureTimestamp);

    // First test invalid code rejection
    const invalidRes = await request('/api/auth/2fa/login', {
      method: 'POST',
      body: {
        challenge_token: challengeToken,
        code: '000000'
      }
    });
    assert.strictEqual(invalidRes.status, 401, 'Invalid code must return 401');

    // Test with valid code (using current live window)
    // First, let's clear last_totp_window for clean test
    await query('UPDATE users SET last_totp_window = NULL WHERE email = $1', [testEmail]);

    const liveCode = generateTOTP(provisionedSecret);
    const validRes = await request('/api/auth/2fa/login', {
      method: 'POST',
      body: {
        challenge_token: challengeToken,
        code: liveCode
      }
    });

    assert.strictEqual(validRes.status, 200, `Expected 200 OK, got ${validRes.status}`);
    assert(validRes.body.token, 'Must return full access token');
  });

  // 10. Replay Protection
  await test('Requirement 11: System rejects replayed TOTP code within same window with 401', async () => {
    // 1. Get new challenge token
    const loginRes = await request('/api/auth/login', {
      method: 'POST',
      body: { email: testEmail, password: testPassword }
    });
    const cToken = loginRes.body.challenge_token;

    // 2. Generate valid current code
    const currentCode = generateTOTP(provisionedSecret);

    // Clear window to ensure first request succeeds
    await query('UPDATE users SET last_totp_window = NULL WHERE email = $1', [testEmail]);

    // 3. First request (Legitimate)
    const req1 = await request('/api/auth/2fa/login', {
      method: 'POST',
      body: { challenge_token: cToken, code: currentCode }
    });
    assert.strictEqual(req1.status, 200, 'First submission must succeed with 200 OK');

    // 4. Second identical request (Replay Attack)
    const req2 = await request('/api/auth/2fa/login', {
      method: 'POST',
      body: { challenge_token: cToken, code: currentCode }
    });
    assert.strictEqual(req2.status, 401, `Replayed code must return 401 Unauthorized, got ${req2.status}`);

    // Verify last_totp_window in DB
    const dbRes = await query('SELECT last_totp_window FROM users WHERE email = $1', [testEmail]);
    const expectedWindow = Math.floor(Date.now() / 1000 / 30);
    assert.strictEqual(dbRes.rows[0].last_totp_window, expectedWindow, 'last_totp_window must equal current window');
  });

  // 11. Seeded User in submission.json
  await test('Requirement 12: Predefined testUser in submission.json exists with valid 2FA setup', async () => {
    const subPath = path.resolve(__dirname, '../submission.json');
    assert(fs.existsSync(subPath), 'submission.json must exist');

    const sub = JSON.parse(fs.readFileSync(subPath, 'utf8'));
    assert(sub.testUser, 'submission.json must have testUser');
    assert.strictEqual(sub.testUser.email, 'test_2fa@example.com');
    assert.strictEqual(sub.testUser.password, 'securePassword123');
    assert.strictEqual(sub.testUser.plaintextTotpSecret, 'JBSWY3DPEHPK3PXP');

    // Login with seeded user credentials
    const loginRes = await request('/api/auth/login', {
      method: 'POST',
      body: {
        email: sub.testUser.email,
        password: sub.testUser.password
      }
    });

    assert.strictEqual(loginRes.status, 200, 'Seeded user login must succeed');
    assert.strictEqual(loginRes.body.requires_2fa, true, 'Seeded user must require 2FA');
    assert(loginRes.body.challenge_token, 'Seeded user must receive challenge_token');

    // Clear last window for clean test
    await query('UPDATE users SET last_totp_window = NULL WHERE email = $1', [sub.testUser.email]);

    // Dynamically sign code with testUser.plaintextTotpSecret
    const liveTestCode = generateTOTP(sub.testUser.plaintextTotpSecret);

    const mfaRes = await request('/api/auth/2fa/login', {
      method: 'POST',
      body: {
        challenge_token: loginRes.body.challenge_token,
        code: liveTestCode
      }
    });

    assert.strictEqual(mfaRes.status, 200, `Seeded user 2FA login must succeed, got ${mfaRes.status}`);
    assert(mfaRes.body.token, 'Must return full access token for seeded user');
  });

  console.log('\n------------------------------------------------------');
  console.log(`  SUMMARY: ${passedCount} PASSED, ${failedCount} FAILED`);
  console.log('------------------------------------------------------\n');

  await closePool();

  if (failedCount > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

if (require.main === module) {
  runAllTests().catch(err => {
    console.error('Test runner fatal error:', err);
    process.exit(1);
  });
}

module.exports = { runAllTests };
