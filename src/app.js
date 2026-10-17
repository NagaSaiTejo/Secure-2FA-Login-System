const express = require('express');
const cors = require('cors');
const path = require('path');
const authRouter = require('./routes/auth');
const { ping } = require('./db');

const app = express();

// Enable CORS and JSON body parsing
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static frontend files
app.use(express.static(path.join(__dirname, '../public')));

// Health check endpoint (used by Docker Compose healthcheck and monitoring)
app.get('/api/health', async (req, res) => {
  const dbAlive = await ping();
  if (dbAlive) {
    return res.status(200).json({
      status: 'ok',
      db: 'connected',
      timestamp: Date.now()
    });
  }
  return res.status(503).json({
    status: 'degraded',
    db: 'disconnected',
    timestamp: Date.now()
  });
});

// Authentication routes
app.use('/api/auth', authRouter);

// Protected user routes
app.use('/api', authRouter);

// Fallback for API 404s
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('[Unhandled Error]', err);
  res.status(500).json({ error: 'An unexpected internal error occurred' });
});

module.exports = app;
