const { Pool } = require('pg');
const config = require('../config');

const pool = new Pool({
  connectionString: config.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
  console.error('[PostgreSQL Pool Error]', err);
});

/**
 * Execute a parameterized query against PostgreSQL.
 *
 * @param {string} text - SQL query string
 * @param {any[]} [params] - Query parameters
 * @returns {Promise<import('pg').QueryResult>}
 */
async function query(text, params) {
  const start = Date.now();
  const res = await pool.query(text, params);
  const duration = Date.now() - start;
  if (process.env.DEBUG_SQL) {
    console.log(`[SQL] ${text} [params: ${JSON.stringify(params)}] (${duration}ms)`);
  }
  return res;
}

/**
 * Acquire a client for transaction management.
 * @returns {Promise<import('pg').PoolClient>}
 */
async function getClient() {
  return await pool.connect();
}

/**
 * Ping database to verify connection.
 * @returns {Promise<boolean>}
 */
async function ping() {
  try {
    const res = await pool.query('SELECT 1 AS alive');
    return res.rows[0].alive === 1;
  } catch (err) {
    return false;
  }
}

/**
 * Close database pool (useful for clean teardown during tests).
 */
async function closePool() {
  await pool.end();
}

module.exports = {
  pool,
  query,
  getClient,
  ping,
  closePool
};
