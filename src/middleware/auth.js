const jwt = require('jsonwebtoken');
const config = require('../config');

/**
 * Middleware requiring a valid Full Access JWT.
 * Rejects missing tokens, expired tokens, or restricted challenge tokens (401 or 403).
 */
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authorization header missing or malformed. Expected Bearer token.' });
  }

  const token = authHeader.substring(7).trim();
  if (!token) {
    return res.status(401).json({ error: 'Bearer token is empty' });
  }

  try {
    const decoded = jwt.verify(token, config.JWT_SECRET);

    // Strictly forbid challenge tokens from accessing protected routes
    if (decoded.scope === '2fa_challenge') {
      return res.status(403).json({
        error: 'Forbidden: 2FA challenge token cannot access protected resources. Complete 2FA login first.'
      });
    }

    if (decoded.scope !== 'full_access') {
      return res.status(403).json({
        error: 'Forbidden: Full access token required'
      });
    }

    req.user = {
      id: decoded.sub,
      email: decoded.email,
      scope: decoded.scope
    };

    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token has expired' });
    }
    return res.status(401).json({ error: 'Invalid authentication token' });
  }
}

module.exports = {
  requireAuth
};
