require('dotenv').config();

const config = {
  DATABASE_URL: process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5432/authdb',
  JWT_SECRET: process.env.JWT_SECRET || 'default_jwt_secret_must_be_changed_in_prod_1234567890',
  MASTER_ENCRYPTION_KEY: process.env.MASTER_ENCRYPTION_KEY || '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  PORT: parseInt(process.env.PORT, 10) || 3000,
  NODE_ENV: process.env.NODE_ENV || 'development'
};

// Validate MASTER_ENCRYPTION_KEY (must be 32 bytes = 64 hex characters)
if (!/^[0-9a-fA-F]{64}$/.test(config.MASTER_ENCRYPTION_KEY)) {
  console.warn('[Config Warning] MASTER_ENCRYPTION_KEY should be a 32-byte (64 hex characters) string.');
}

module.exports = config;
