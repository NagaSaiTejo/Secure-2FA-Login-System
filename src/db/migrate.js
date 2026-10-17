const { query } = require('./index');

/**
 * Migration script that ensures the `users` table exists matching the exact required schema.
 */
async function migrate() {
  console.log('[Migration] Running database migrations...');

  // Ensure pgcrypto extension is available for UUID generation if needed
  try {
    await query('CREATE EXTENSION IF NOT EXISTS "pgcrypto";');
  } catch (err) {
    // In Postgres 13+, gen_random_uuid() is built-in; extension creation may fail if non-superuser, which is safe to ignore
    if (process.env.DEBUG_SQL) {
      console.log('[Migration Info] pgcrypto extension notice:', err.message);
    }
  }

  // Create users table matching all 8 specified columns
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      totp_enabled BOOLEAN DEFAULT false,
      totp_secret_encrypted TEXT,
      totp_iv VARCHAR(255),
      totp_tag VARCHAR(255),
      last_totp_window INTEGER
    );
  `;

  await query(createTableQuery);

  // Ensure indexes for fast lookups
  await query('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);');

  console.log('[Migration] Database migration completed successfully.');
}

if (require.main === module) {
  migrate()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('[Migration Failed]', err);
      process.exit(1);
    });
}

module.exports = { migrate };
