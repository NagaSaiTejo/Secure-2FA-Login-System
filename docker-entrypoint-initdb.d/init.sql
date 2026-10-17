-- PostgreSQL database initialization script
-- Automatically executed on container first boot if data directory is empty

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

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

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
