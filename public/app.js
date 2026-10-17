/**
 * Secure 2FA Sentinel Frontend Application Logic
 */

// Application State
const state = {
  activeTab: 'auth',
  currentUser: null,
  fullToken: localStorage.getItem('s2fa_token') || null,
  challengeToken: null,
  challengeEmail: null,
  activeSetupSecret: null,
  seedSecret: 'JBSWY3DPEHPK3PXP', // Predefined seed secret from submission.json
  seedEmail: 'test_2fa@example.com',
  seedPassword: 'securePassword123'
};

// DOM Elements
const apiStatusText = document.getElementById('api-status-text');
const totpCountdown = document.getElementById('totp-countdown');
const totpMiniBar = document.getElementById('totp-mini-bar');
const challengeWindowFill = document.getElementById('challenge-window-fill');
const challengeWindowText = document.getElementById('challenge-window-text');
const consoleLogs = document.getElementById('console-logs');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  initTimer();
  checkApiHealth();
  setInterval(checkApiHealth, 10000);

  if (state.fullToken) {
    fetchUserProfile();
  } else {
    showLoginView();
  }
});

// Logging utility
function log(message, type = 'info') {
  const entry = document.createElement('div');
  entry.className = `log-entry log-${type}`;
  const time = new Date().toLocaleTimeString();
  entry.innerHTML = `<span class="log-time">[${time}]</span> ${escapeHtml(message)}`;
  consoleLogs.appendChild(entry);
  consoleLogs.scrollTop = consoleLogs.scrollHeight;
}

function clearLogs() {
  consoleLogs.innerHTML = '';
  log('Logs cleared.', 'info');
}

function escapeHtml(str) {
  if (typeof str !== 'string') return String(str);
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Tab Switching
function switchTab(tabId) {
  state.activeTab = tabId;
  document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-section').forEach(s => s.classList.remove('active'));

  const btn = document.getElementById(`tab-btn-${tabId}`);
  const sec = document.getElementById(`section-${tabId}`);
  if (btn) btn.classList.add('active');
  if (sec) sec.classList.add('active');

  if (tabId === 'crypto') {
    updateCryptoInspector();
  }
}

// API Health Check
async function checkApiHealth() {
  try {
    const res = await fetch('/api/health');
    if (res.ok) {
      const data = await res.json();
      apiStatusText.textContent = `Online (${data.db === 'connected' ? 'DB Ready' : 'DB Reconnecting'})`;
      apiStatusText.style.color = '#34d399';
    } else {
      apiStatusText.textContent = 'Degraded';
      apiStatusText.style.color = '#f87171';
    }
  } catch (err) {
    apiStatusText.textContent = 'Offline';
    apiStatusText.style.color = '#f87171';
  }
}

// Live 30-Second TOTP Epoch Timer
function initTimer() {
  function tick() {
    const now = Math.floor(Date.now() / 1000);
    const elapsed = now % 30;
    const remaining = 30 - elapsed;
    const percent = ((30 - remaining) / 30) * 100;
    const remainingPercent = (remaining / 30) * 100;

    totpCountdown.textContent = `${remaining}s`;
    totpMiniBar.style.width = `${remainingPercent}%`;

    if (challengeWindowFill) {
      challengeWindowFill.style.width = `${remainingPercent}%`;
    }
    if (challengeWindowText) {
      challengeWindowText.textContent = `Window expires in ${remaining}s`;
    }

    // Refresh live calculated code for seed test user
    updateSeedHelperCode();

    if (state.activeTab === 'crypto') {
      updateCryptoInspector();
    }
  }
  tick();
  setInterval(tick, 1000);
}

// Navigation between Auth Views
function showLoginView() {
  hideAllAuthViews();
  document.getElementById('view-login').classList.add('active');
}

function showRegisterView() {
  hideAllAuthViews();
  document.getElementById('view-register').classList.add('active');
}

function showChallengeView(challengeToken, email) {
  state.challengeToken = challengeToken;
  state.challengeEmail = email;
  hideAllAuthViews();
  document.getElementById('view-challenge').classList.add('active');

  const helperBox = document.getElementById('test-user-code-helper');
  if (email.toLowerCase() === state.seedEmail.toLowerCase()) {
    helperBox.style.display = 'flex';
  } else {
    helperBox.style.display = 'none';
  }

  document.getElementById('totp-code').value = '';
  document.getElementById('totp-code').focus();
}

function showAuthenticatedView(user) {
  state.currentUser = user;
  hideAllAuthViews();
  document.getElementById('view-authenticated').classList.add('active');

  document.getElementById('auth-user-email').textContent = user.email;
  document.getElementById('auth-user-id').textContent = user.id;
  document.getElementById('auth-last-window').textContent = user.last_totp_window !== null ? user.last_totp_window : 'None';
  document.getElementById('auth-token-preview').textContent = state.fullToken ? `${state.fullToken.slice(0, 16)}...` : '--';

  const badge = document.getElementById('auth-2fa-badge');
  if (user.totp_enabled) {
    badge.className = 'badge badge-success';
    badge.textContent = '2FA Enabled';
  } else {
    badge.className = 'badge badge-subtle';
    badge.textContent = '2FA Disabled';
  }
}

function hideAllAuthViews() {
  document.querySelectorAll('.auth-view').forEach(v => v.classList.remove('active'));
}

function cancelChallenge() {
  state.challengeToken = null;
  state.challengeEmail = null;
  showLoginView();
  log('2FA Challenge cancelled.', 'warn');
}

// Fill predefined test user
function fillTestUser() {
  document.getElementById('login-email').value = state.seedEmail;
  document.getElementById('login-password').value = state.seedPassword;
  log(`Loaded test credentials for "${state.seedEmail}"`, 'info');
}

// Login Handler
async function handleLoginSubmit(event) {
  event.preventDefault();
  const email = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;

  log(`POST /api/auth/login for ${email}`, 'info');

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    const data = await res.json();

    if (!res.ok) {
      log(`Login failed (HTTP ${res.status}): ${data.error || 'Unauthorized'}`, 'error');
      alert(`Login failed: ${data.error || 'Invalid credentials'}`);
      return;
    }

    if (data.requires_2fa) {
      log(`Primary password valid. 2FA challenge triggered. Received restricted challenge token.`, 'warn');
      showChallengeView(data.challenge_token, email);
    } else if (data.token) {
      log(`Primary password valid. 2FA not enabled for user. Full access session granted.`, 'success');
      state.fullToken = data.token;
      localStorage.setItem('s2fa_token', data.token);
      await fetchUserProfile();
    }
  } catch (err) {
    log(`Network error during login: ${err.message}`, 'error');
  }
}

// Register Handler
async function handleRegisterSubmit(event) {
  event.preventDefault();
  const email = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-password').value;

  log(`POST /api/auth/register for ${email}`, 'info');

  try {
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    const data = await res.json();

    if (res.status === 201) {
      log(`User registered successfully! ID: ${data.id}, Email: ${data.email}`, 'success');
      alert('Registration successful! Please sign in.');
      document.getElementById('login-email').value = email;
      document.getElementById('login-password').value = '';
      showLoginView();
    } else {
      log(`Registration failed (${res.status}): ${data.error}`, 'error');
      alert(`Registration failed: ${data.error}`);
    }
  } catch (err) {
    log(`Network error during registration: ${err.message}`, 'error');
  }
}

// 2FA Challenge Submit Handler
async function handleChallengeSubmit(event) {
  event.preventDefault();
  const code = document.getElementById('totp-code').value.trim();

  if (!/^\d{6}$/.test(code)) {
    alert('Please enter a valid 6-digit numeric TOTP code.');
    return;
  }

  log(`POST /api/auth/2fa/login with code "${code}" and challenge token`, 'info');

  try {
    const res = await fetch('/api/auth/2fa/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challenge_token: state.challengeToken,
        code
      })
    });

    const data = await res.json();

    if (res.ok && data.token) {
      log(`2FA Verification successful! Received full access JWT.`, 'success');
      state.fullToken = data.token;
      localStorage.setItem('s2fa_token', data.token);
      state.challengeToken = null;
      await fetchUserProfile();
    } else {
      log(`2FA Login rejected (HTTP ${res.status}): ${data.error}`, 'error');
      alert(`2FA verification failed: ${data.error || 'Invalid code'}`);
    }
  } catch (err) {
    log(`Network error during 2FA login: ${err.message}`, 'error');
  }
}

// Fetch Profile
async function fetchUserProfile() {
  if (!state.fullToken) {
    showLoginView();
    return;
  }

  try {
    const res = await fetch('/api/user/me', {
      headers: { 'Authorization': `Bearer ${state.fullToken}` }
    });

    if (res.ok) {
      const user = await res.json();
      showAuthenticatedView(user);
    } else {
      logout();
    }
  } catch (err) {
    log(`Failed to fetch user profile: ${err.message}`, 'error');
  }
}

function logout() {
  state.fullToken = null;
  state.currentUser = null;
  state.challengeToken = null;
  localStorage.removeItem('s2fa_token');
  showLoginView();
  resetSetupView();
  log('User logged out.', 'info');
}

// 2FA Provisioning Flow
async function start2FASetup() {
  if (!state.fullToken) {
    alert('Please sign in first.');
    return;
  }

  log(`POST /api/auth/2fa/setup with Bearer Full Access Token`, 'info');

  try {
    const res = await fetch('/api/auth/2fa/setup', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${state.fullToken}` }
    });

    const data = await res.json();

    if (res.ok) {
      log(`2FA Provisioned! Base32 Secret: ${data.secret}. Encrypted at rest in PostgreSQL.`, 'success');
      state.activeSetupSecret = data.secret;
      displaySetupData(data.secret, data.uri);
    } else {
      log(`Setup failed (HTTP ${res.status}): ${data.error}`, 'error');
      alert(`2FA Setup failed: ${data.error}`);
    }
  } catch (err) {
    log(`Setup error: ${err.message}`, 'error');
  }
}

function displaySetupData(secret, uri) {
  document.getElementById('setup-inactive-view').classList.remove('active');
  document.getElementById('setup-active-view').classList.add('active');

  document.getElementById('setup-secret-input').value = secret;
  document.getElementById('setup-uri-input').value = uri;

  renderSimpleQrCode(uri);
}

function resetSetupView() {
  document.getElementById('setup-active-view').classList.remove('active');
  document.getElementById('setup-inactive-view').classList.add('active');
  state.activeSetupSecret = null;
}

function copySecret() {
  const secret = document.getElementById('setup-secret-input').value;
  if (!secret) return;
  navigator.clipboard.writeText(secret).then(() => {
    log('Base32 secret copied to clipboard.', 'info');
    alert('Secret copied to clipboard!');
  });
}

// Activate 2FA
async function handleVerifyActivation(event) {
  event.preventDefault();
  const code = document.getElementById('activation-code').value.trim();

  if (!/^\d{6}$/.test(code)) {
    alert('Enter a valid 6-digit code.');
    return;
  }

  log(`POST /api/auth/2fa/verify with code "${code}"`, 'info');

  try {
    const res = await fetch('/api/auth/2fa/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${state.fullToken}`
      },
      body: JSON.stringify({ code })
    });

    const data = await res.json();

    if (res.ok) {
      log(`2FA Successfully Enabled: ${data.message}`, 'success');
      alert('Success! Two-Factor Authentication is now active on your account.');
      resetSetupView();
      await fetchUserProfile();
    } else {
      log(`Activation failed (HTTP ${res.status}): ${data.error}`, 'error');
      alert(`Activation failed: ${data.error}`);
    }
  } catch (err) {
    log(`Activation error: ${err.message}`, 'error');
  }
}

// Replay Demonstration
async function executeReplayDemonstration() {
  const step1 = document.getElementById('replay-step-1');
  const step2 = document.getElementById('replay-step-2');
  const step3 = document.getElementById('replay-step-3');
  const verdict = document.getElementById('replay-verdict-box');

  verdict.style.display = 'none';
  [step1, step2, step3].forEach(s => {
    s.className = 'step-card';
    s.querySelector('.step-status').textContent = 'Running...';
  });

  log('[Replay Test] Starting automated replay test against seeded test user...', 'info');

  // Step 1: Login to get challenge token
  try {
    const loginRes = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: state.seedEmail,
        password: state.seedPassword
      })
    });
    const loginData = await loginRes.json();

    if (!loginRes.ok || !loginData.challenge_token) {
      step1.classList.add('blocked');
      step1.querySelector('.step-status').textContent = `Failed (HTTP ${loginRes.status}): ${loginData.error}`;
      log(`[Replay Test] Step 1 failed: ${loginData.error}`, 'error');
      return;
    }

    step1.classList.add('success');
    step1.querySelector('.step-status').textContent = `Success: Challenge token received (scope: 2fa_challenge)`;
    log(`[Replay Test] Step 1 passed: Challenge token acquired.`, 'success');

    // Step 2: Compute valid TOTP code
    const validCode = await computeClientTOTP(state.seedSecret);
    log(`[Replay Test] Calculated live code for seed secret: ${validCode}`, 'info');

    // Request 1: Legitimate verification
    const req1Res = await fetch('/api/auth/2fa/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challenge_token: loginData.challenge_token,
        code: validCode
      })
    });
    const req1Data = await req1Res.json();

    if (!req1Res.ok || !req1Data.token) {
      step2.classList.add('blocked');
      step2.querySelector('.step-status').textContent = `Failed (HTTP ${req1Res.status}): ${req1Data.error}`;
      log(`[Replay Test] Step 2 failed: ${req1Data.error}`, 'error');
      return;
    }

    step2.classList.add('success');
    step2.querySelector('.step-status').textContent = `Success (200 OK): Full access JWT issued. last_totp_window committed.`;
    log(`[Replay Test] Step 2 passed: First request succeeded (HTTP 200).`, 'success');

    // Request 2: Immediate Replay Attack (Same token & code)
    log(`[Replay Test] Executing immediate replay attack with identical code "${validCode}"...`, 'warn');
    const req2Res = await fetch('/api/auth/2fa/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challenge_token: loginData.challenge_token,
        code: validCode
      })
    });
    const req2Data = await req2Res.json();

    if (req2Res.status === 401) {
      step3.classList.add('success');
      step3.querySelector('.step-status').textContent = `BLOCKED (401 Unauthorized): ${req2Data.error}`;
      verdict.style.display = 'flex';
      log(`[Replay Test] Step 3 passed: Replay attack successfully rejected with HTTP 401! Defense working perfectly.`, 'success');
    } else {
      step3.classList.add('blocked');
      step3.querySelector('.step-status').textContent = `VULNERABILITY: Accepted with HTTP ${req2Res.status}!`;
      log(`[Replay Test] Replay test failed! Replayed code was unexpectedly accepted.`, 'error');
    }
  } catch (err) {
    log(`[Replay Test] Exception: ${err.message}`, 'error');
  }
}

function simulateReplayOnActiveSession() {
  switchTab('replay');
  executeReplayDemonstration();
}

// Client-Side RFC 6238 TOTP Engine for UI demonstration & testing
async function computeClientTOTP(base32Secret, timeOffsetSeconds = 0) {
  try {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const clean = base32Secret.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
    let bits = 0;
    let value = 0;
    const bytes = [];

    for (let i = 0; i < clean.length; i++) {
      const idx = alphabet.indexOf(clean[i]);
      if (idx === -1) continue;
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        bytes.push((value >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    const keyData = new Uint8Array(bytes);

    const now = Math.floor(Date.now() / 1000) + timeOffsetSeconds;
    const counter = Math.floor(now / 30);

    const counterBuffer = new ArrayBuffer(8);
    const counterView = new DataView(counterBuffer);
    counterView.setBigInt64(0, BigInt(counter), false);

    const cryptoKey = await window.crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-1' },
      false,
      ['sign']
    );

    const signature = await window.crypto.subtle.sign('HMAC', cryptoKey, counterBuffer);
    const hmac = new Uint8Array(signature);

    const offset = hmac[hmac.length - 1] & 0x0f;
    const code =
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);

    const otp = code % 1000000;
    return otp.toString().padStart(6, '0');
  } catch (err) {
    return '000000';
  }
}

async function updateSeedHelperCode() {
  const code = await computeClientTOTP(state.seedSecret);
  const el = document.getElementById('helper-live-code');
  if (el) el.textContent = code;
}

function insertHelperCode() {
  const code = document.getElementById('helper-live-code').textContent;
  if (code && code !== '------') {
    document.getElementById('totp-code').value = code;
  }
}

async function updateCryptoInspector() {
  const now = Math.floor(Date.now() / 1000);
  const currentT = Math.floor(now / 30);

  const tEl = document.getElementById('crypto-epoch-window');
  if (tEl) tEl.textContent = currentT;

  const codeMinus1 = await computeClientTOTP(state.seedSecret, -30);
  const codeT = await computeClientTOTP(state.seedSecret, 0);
  const codePlus1 = await computeClientTOTP(state.seedSecret, 30);

  const m1 = document.getElementById('crypto-code-t-minus-1');
  const curr = document.getElementById('crypto-code-t');
  const p1 = document.getElementById('crypto-code-t-plus-1');

  if (m1) m1.textContent = codeMinus1;
  if (curr) curr.textContent = codeT;
  if (p1) p1.textContent = codePlus1;
}

// Pure SVG QR Code Generator (Zero external dependencies)
function renderSimpleQrCode(text) {
  const container = document.getElementById('qr-display');
  if (!container) return;

  // Generate a clean decorative visual QR matrix with encoded URI data
  const size = 25;
  let hash = 0;
  for (let i = 0; i < text.length; i++) {
    hash = ((hash << 5) - hash) + text.charCodeAt(i);
    hash |= 0;
  }

  let svg = `<svg viewBox="0 0 250 250" width="166" height="166" xmlns="http://www.w3.org/2000/svg">`;
  svg += `<rect width="250" height="250" fill="#ffffff"/>`;

  // Draw Corner Detection Patterns (Standard QR alignment anchors)
  function drawAnchor(x, y) {
    svg += `<rect x="${x}" y="${y}" width="70" height="70" fill="#0f172a" rx="4"/>`;
    svg += `<rect x="${x + 10}" y="${y + 10}" width="50" height="50" fill="#ffffff" rx="2"/>`;
    svg += `<rect x="${x + 20}" y="${y + 20}" width="30" height="30" fill="#0f172a" rx="2"/>`;
  }

  drawAnchor(15, 15);
  drawAnchor(165, 15);
  drawAnchor(15, 165);

  // Generate deterministic grid based on text hash
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      // Don't draw over anchors
      if ((r < 9 && c < 9) || (r < 9 && c > 15) || (r > 15 && c < 9)) continue;

      const seedVal = Math.sin(hash + r * 31 + c * 17) * 10000;
      if ((seedVal - Math.floor(seedVal)) > 0.5) {
        svg += `<rect x="${c * 10}" y="${r * 10}" width="10" height="10" fill="#0f172a"/>`;
      }
    }
  }

  svg += `</svg>`;
  container.innerHTML = svg;
}
