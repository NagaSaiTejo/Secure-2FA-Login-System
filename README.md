# Secure 2FA Login System with TOTP and Encrypted Credential Storage

A robust, enterprise-grade authentication system implementing two-factor authentication (2FA) with Time-Based One-Time Passwords (**RFC 6238**), symmetric credential encryption at rest using **AES-256-GCM** (AEAD), and stateful **replay attack protection**.

---

## Table of Contents
1. [Architecture & System Flow](#architecture--system-flow)
2. [Core Security Mechanisms](#core-security-mechanisms)
3. [Database Schema](#database-schema)
4. [Environment Configuration](#environment-configuration)
5. [API Specification](#api-specification)
6. [Predefined Evaluation User (`submission.json`)](#predefined-evaluation-user-submissionjson)
7. [Running with Docker Compose](#running-with-docker-compose)
8. [Automated Verification & Testing](#automated-verification--testing)

---

## Architecture & System Flow

### Data Flow & Component Architecture
The critical security constraint is that the Base32 TOTP secret **never enters the database in plaintext**. It is encrypted with AES-256-GCM before storage.

```
+-------------------------------------------------------------------------------------------------------+
|                                          CLIENT APPLICATION                                           |
|                                       (User / Web Application)                                        |
+-------------------------------------------------------------------------------------------------------+
           |                                                                               ^
   1. Credentials                                                                    10. Full JWT
           |                                                                               |
           v                                                                               |
+-------------------------------------------------------------------------------------------------------+
|                                         AUTHENTICATION API                                            |
|                                                                                                       |
|  +--------------------+         +----------------------------------+         +---------------------+  |
|  |   API Controller   | ------> |      Auth and State Manager      | <------ |     TOTP Engine     |  |
|  +--------------------+         +----------------------------------+         |     (RFC 6238)      |  |
|                                            |              ^                  +---------------------+  |
|                                            v              |                             ^             |
|                                 +--------------------+    | Plaintext                   |             |
|                                 | AES-256-GCM Crypto | ---+ Secret ---------------------+             |
|                                 +--------------------+                                                |
|                                            |                                                          |
+--------------------------------------------|----------------------------------------------------------+
                                             | Encrypted Payload (Ciphertext, IV, Tag)
                                             v
                             +-------------------------------+
                             |      POSTGRESQL DATABASE      |
                             |         (users table)         |
                             +-------------------------------+
```

### Authentication State Machine
Authentication strictly separates identity verification stages:
```
[ Unauthenticated ]
        |
        |  1. POST /api/auth/login (Correct email & password)
        v
    (Is 2FA Enabled?)
        |-- NO  --> Returns Full Access JWT (scope: "full_access") --> [ Authenticated ]
        |
       YES
        |
        v
[ ChallengePending ]
  (Short-lived token, scope: "2fa_challenge". Blocked from protected routes)
        |
        |  2. POST /api/auth/2fa/login (Valid TOTP code, T_match > last_totp_window)
        v
[ Authenticated ]
  (Full Access JWT issued, last_totp_window updated to prevent replay)
```

---

## Core Security Mechanisms

### 1. Time-Based One-Time Passwords (RFC 6238)
- **Mathematical Transformation**:
  $$\text{Window Counter } T = \left\lfloor \frac{\text{Current Unix Timestamp in Seconds}}{30} \right\rfloor$$
- **HMAC Computation**: Computes HMAC-SHA1 of the 8-byte big-endian representation of $T$ using the decoded Base32 secret as the key.
- **Dynamic Truncation**: Extracts a 4-byte dynamic binary code based on the lowest 4 bits of the HMAC digest, then computes modulo $10^6$ zero-padded to 6 digits.
- **Clock Drift Tolerance**: Checks windows $T$, $T-1$, and $T+1$ (accommodating $\pm 30$ seconds of clock drift).
- **Constant-Time Comparison**: Uses `crypto.timingSafeEqual` to eliminate timing side-channel attacks.

### 2. Symmetric Encryption at Rest (AES-256-GCM)
- Authenticated Encryption with Associated Data (AEAD) ensures both **confidentiality** and **ciphertext integrity**.
- **Unique IVs**: Generates a cryptographically random 12-byte (96-bit) Initialization Vector for every single encryption operation. IV reuse in GCM is mathematically prevented.
- **16-byte Authentication Tag**: Any tampering with ciphertext in the database causes decryption to fail and halts authentication.

### 3. Stateful Replay Attack Defense
- Even within the 30-second validity window, once a code has been successfully verified, its matching window $T_{\text{match}}$ is stored in `last_totp_window`.
- If an adversary intercepts and attempts to replay the code:
  $$T_{\text{match}} \le \text{last\_totp\_window} \implies \text{HTTP 401 Unauthorized (Replay Detected)}$$
- The check and update are executed using atomic SQL queries to prevent concurrent race conditions.

---

## Database Schema

Table name: **`users`**

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `UUID` | `PRIMARY KEY DEFAULT gen_random_uuid()` | Unique user identifier |
| `email` | `VARCHAR(255)` | `UNIQUE, NOT NULL` | User email address |
| `password_hash` | `VARCHAR(255)` | `NOT NULL` | Bcrypt hashed password (10 rounds) |
| `totp_enabled` | `BOOLEAN` | `DEFAULT false` | 2FA activation status |
| `totp_secret_encrypted` | `TEXT` | `NULLABLE` | AES-256-GCM encrypted Base32 secret |
| `totp_iv` | `VARCHAR(255)` | `NULLABLE` | 12-byte hex-encoded IV |
| `totp_tag` | `VARCHAR(255)` | `NULLABLE` | 16-byte hex-encoded GCM authentication tag |
| `last_totp_window` | `INTEGER` | `NULLABLE` | Time step counter of last used code |

---

## Environment Configuration

Documented in [`.env.example`](file:///.env.example):

| Variable | Description | Example Placeholder |
|---|---|---|
| `DATABASE_URL` | PostgreSQL connection string | `postgres://postgres:postgres@db:5432/authdb` |
| `JWT_SECRET` | Secret key for signing and verifying JWTs | `replace_with_a_secure_random_jwt_secret_key` |
| `MASTER_ENCRYPTION_KEY` | 32-byte (256-bit) hex-encoded AES key | `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef` |
| `PORT` | Application server port | `3000` |
| `NODE_ENV` | Application environment | `production` |

---

## API Specification

### 1. User Registration
- **`POST /api/auth/register`**
- **Body**:
  ```json
  { "email": "user@example.com", "password": "securePassword123" }
  ```
- **Response (201 Created)**:
  ```json
  { "id": "4b684cb3-00e1-4560-a8d7-...", "email": "user@example.com" }
  ```

### 2. Primary Login
- **`POST /api/auth/login`**
- **Body**:
  ```json
  { "email": "user@example.com", "password": "securePassword123" }
  ```
- **Response (2FA Not Enabled - 200 OK)**:
  ```json
  { "token": "<Full Access JWT>" }
  ```
- **Response (2FA Enabled - 200 OK)**:
  ```json
  { "requires_2fa": true, "challenge_token": "<Restricted Challenge JWT>" }
  ```

### 3. TOTP Provisioning
- **`POST /api/auth/2fa/setup`**
- **Header**: `Authorization: Bearer <Full Access Token>`
- **Response (200 OK)**:
  ```json
  {
    "secret": "JBSWY3DPEHPK3PXP",
    "uri": "otpauth://totp/Secure2FA:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Secure2FA&algorithm=SHA1&digits=6&period=30"
  }
  ```

### 4. 2FA Verification & Activation
- **`POST /api/auth/2fa/verify`**
- **Header**: `Authorization: Bearer <Full Access Token>`
- **Body**: `{ "code": "123456" }`
- **Response (200 OK)**: `{ "message": "2FA successfully enabled" }`

### 5. Secondary 2FA Login
- **`POST /api/auth/2fa/login`**
- **Body**:
  ```json
  { "challenge_token": "<Challenge Token>", "code": "123456" }
  ```
- **Response (200 OK)**: `{ "token": "<Full Access JWT>" }`
- **Replay Response (401 Unauthorized)**:
  ```json
  { "error": "Replay detected: TOTP code has already been used in this or a prior window" }
  ```

### 6. Protected Profile
- **`GET /api/user/me`**
- **Header**: `Authorization: Bearer <Full Access Token>`
- **Response (200 OK)**:
  ```json
  { "id": "...", "email": "...", "totp_enabled": true, "last_totp_window": 59741234 }
  ```

### 7. Health Check
- **`GET /api/health`**
- **Response (200 OK)**: `{ "status": "ok", "db": "connected", "timestamp": 1729160000000 }`

---

## Predefined Evaluation User (`submission.json`)

Located at [`submission.json`](file:///submission.json):
```json
{
  "testUser": {
    "email": "test_2fa@example.com",
    "password": "securePassword123",
    "plaintextTotpSecret": "JBSWY3DPEHPK3PXP"
  }
}
```
The database initialization automatically creates and seeds this user with encrypted credentials matching `JBSWY3DPEHPK3PXP` and `totp_enabled = true`.

---

## Running with Docker Compose

To build and run the entire stack:
```bash
docker compose up -d --build
```

Monitor service health:
```bash
docker compose ps
```
Both `app` and `db` will report as `healthy` within seconds.

View application logs:
```bash
docker compose logs -f app
```

Teardown:
```bash
docker compose down -v
```

---

## Automated Verification & Testing

Execute the comprehensive test suite verifying all 12 core requirements:
```bash
npm test
```
Or run directly with Node:
```bash
node tests/integration.test.js
```
