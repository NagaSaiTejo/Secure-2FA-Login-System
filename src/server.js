const app = require('./app');
const config = require('./config');
const { ping, closePool } = require('./db');
const { migrate } = require('./db/migrate');
const { seed } = require('./db/seed');

const MAX_DB_RETRIES = 30;
const DB_RETRY_INTERVAL_MS = 2000;

async function waitForDatabase() {
  console.log(`[Database] Connecting to PostgreSQL at ${config.DATABASE_URL.replace(/:[^:]*@/, ':****@')}...`);
  for (let attempt = 1; attempt <= MAX_DB_RETRIES; attempt++) {
    const isAlive = await ping();
    if (isAlive) {
      console.log(`[Database] Successfully connected on attempt ${attempt}.`);
      return;
    }
    console.log(`[Database] Waiting for database (attempt ${attempt}/${MAX_DB_RETRIES})...`);
    await new Promise((resolve) => setTimeout(resolve, DB_RETRY_INTERVAL_MS));
  }
  throw new Error('Database connection timed out after multiple attempts.');
}

async function startServer() {
  try {
    // 1. Wait for database readiness
    await waitForDatabase();

    // 2. Run migrations to ensure users table exists
    await migrate();

    // 3. Run seed to ensure predefined test user exists
    await seed();

    // 4. Start HTTP listener
    const server = app.listen(config.PORT, () => {
      console.log(`[Server] Secure 2FA Login System listening on port ${config.PORT}`);
      console.log(`[Server] Health check: http://localhost:${config.PORT}/api/health`);
    });

    // Graceful shutdown
    const shutdown = async (signal) => {
      console.log(`[Server] Received ${signal}. Gracefully shutting down...`);
      server.close(async () => {
        await closePool();
        console.log('[Server] Database pool closed. Process terminated.');
        process.exit(0);
      });
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  } catch (err) {
    console.error('[Server Fatal Error]', err);
    process.exit(1);
  }
}

startServer();
