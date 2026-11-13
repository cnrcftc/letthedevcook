'use strict';

require('dotenv').config();

const crypto = require('node:crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const GOOGLE_CLIENT_ID = (process.env.GOOGLE_CLIENT_ID || '').trim();
const SESSION_KEY_HEX = (process.env.SESSION_SIGNING_KEY || '').trim();
const PAIRING_TTL_MS = 5 * 60 * 1000;
const SESSION_TTL_SECONDS = 30 * 24 * 60 * 60;
const ISSUER = 'multix-auth';
const AUDIENCE = 'multix-desktop';

if (!GOOGLE_CLIENT_ID || GOOGLE_CLIENT_ID.includes('YOUR_GOOGLE_')) {
  console.error('Set GOOGLE_CLIENT_ID in the environment before starting the server.');
  process.exit(1);
}
if (!/^[a-fA-F0-9]{64}$/.test(SESSION_KEY_HEX)) {
  console.error('SESSION_SIGNING_KEY must contain exactly 64 hexadecimal characters.');
  process.exit(1);
}
const SESSION_KEY = Buffer.from(SESSION_KEY_HEX, 'hex');
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);
const allowedOrigins = new Set(
  (process.env.WEBSITE_ORIGINS || 'https://cnrcftc.github.io')
    .split(',').map((value) => value.trim()).filter(Boolean)
);

const pairings = new Map();
const revokedTokens = new Map();

app.disable('x-powered-by');
app.set('trust proxy', process.env.TRUST_PROXY === '0' ? false : Number(process.env.TRUST_PROXY || 1));
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20kb', strict: true }));
app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, false);
    return callback(null, allowedOrigins.has(origin));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 600
}));

const createPairingLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many pairing requests. Try again later.' }
});
const approveLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 12,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many sign-in attempts. Try again later.' }
});
const pollLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Polling too quickly.' }
});

function sha256(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}
function jsonError(res, status, message) {
  return res.status(status).json({ error: message });
}
function cleanup() {
  const now = Date.now();
  for (const [id, item] of pairings) {
    const expiresAt = item.status === 'approved' ? item.deliveryExpiresAt : item.expiresAt;
    if (expiresAt <= now || (item.status === 'completed' && item.completedAt < now - 60000)) {
      pairings.delete(id);
    }
  }
  for (const [tokenHash, expiresAt] of revokedTokens) {
    if (expiresAt <= now) revokedTokens.delete(tokenHash);
  }
}
function readBearer(req) {
  const header = req.get('authorization') || '';
  const match = /^Bearer\s+([A-Za-z0-9._~-]{20,4096})$/i.exec(header);
  return match ? match[1] : '';
}
function signToken(user, deviceName) {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    iss: ISSUER,
    aud: AUDIENCE,
    sub: user.sub,
    email: user.email,
    name: user.name,
    device: deviceName,
    iat: now,
    exp: now + SESSION_TTL_SECONDS,
    jti: crypto.randomUUID()
  })).toString('base64url');
  const unsigned = header + '.' + payload;
  const signature = crypto.createHmac('sha256', SESSION_KEY).update(unsigned).digest('base64url');
  return unsigned + '.' + signature;
}
function verifyToken(token) {
  if (typeof token !== 'string' || token.length > 4096) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const unsigned = parts[0] + '.' + parts[1];
  const expected = crypto.createHmac('sha256', SESSION_KEY).update(unsigned).digest();
  let supplied;
  try { supplied = Buffer.from(parts[2], 'base64url'); } catch { return null; }
  if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) return null;

  let header;
  let payload;
  try {
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch { return null; }

  const now = Math.floor(Date.now() / 1000);
  if (header.alg !== 'HS256' || header.typ !== 'JWT') return null;
  if (payload.iss !== ISSUER || payload.aud !== AUDIENCE) return null;
  if (!payload.sub || !payload.email || !Number.isInteger(payload.exp) || payload.exp <= now) return null;
  if (revokedTokens.has(sha256(token))) return null;
  return payload;
}
async function verifyGoogleCredential(credential, nonce) {
  if (typeof credential !== 'string' || credential.length < 100 || credential.length > 10000) {
    throw new Error('Google credential is invalid.');
  }
  const ticket = await googleClient.verifyIdToken({
    idToken: credential,
    audience: GOOGLE_CLIENT_ID
  });
  const payload = ticket.getPayload();
  if (!payload || !payload.sub || !payload.email || payload.email_verified !== true) {
    throw new Error('Google account could not be verified.');
  }
  if (typeof nonce !== 'string' || !nonce || payload.nonce !== nonce) {
    throw new Error('Google sign-in nonce did not match. Refresh the page and try again.');
  }
  return {
    sub: String(payload.sub),
    email: String(payload.email).toLowerCase(),
    name: String(payload.name || payload.given_name || 'Multix user').slice(0, 120)
  };
}
function authenticatePairing(req, res, next) {
  cleanup();
  const token = readBearer(req);
  const item = pairings.get(req.params.id);
  if (!token || !item || item.pollTokenHash !== sha256(token)) {
    return jsonError(res, 401, 'Pairing credentials are invalid or expired.');
  }
  req.pairing = item;
  next();
}
function authenticateSession(req, res, next) {
  const token = readBearer(req);
  const payload = verifyToken(token);
  if (!payload) return jsonError(res, 401, 'Session is invalid or expired.');
  req.session = payload;
  req.rawSessionToken = token;
  next();
}

app.get('/health', (_req, res) => {
  res.set('Cache-Control', 'no-store').json({ ok: true, service: 'multix-auth' });
});

app.post('/api/pairings', createPairingLimiter, (req, res) => {
  cleanup();
  const deviceName = typeof req.body?.deviceName === 'string'
    ? req.body.deviceName.trim().slice(0, 80)
    : 'Multix on Windows';
  const id = crypto.randomUUID();
  const code = String(crypto.randomInt(10000000, 100000000));
  const pollToken = crypto.randomBytes(32).toString('base64url');
  const now = Date.now();

  pairings.set(id, {
    codeHash: sha256('pair:' + code),
    pollTokenHash: sha256(pollToken),
    deviceName: deviceName || 'Multix on Windows',
    status: 'pending',
    expiresAt: now + PAIRING_TTL_MS,
    deliveryExpiresAt: 0,
    sessionToken: null,
    sessionExpiresAt: 0,
    user: null,
    completedAt: 0
  });

  res.set('Cache-Control', 'no-store').status(201).json({
    id,
    code,
    pollToken,
    expiresIn: Math.floor(PAIRING_TTL_MS / 1000)
  });
});

app.post('/api/pairings/approve', approveLimiter, async (req, res) => {
  const origin = req.get('origin');
  if (!origin || !allowedOrigins.has(origin)) {
    return jsonError(res, 403, 'This website origin is not allowed.');
  }
  const code = typeof req.body?.code === 'string' ? req.body.code.trim() : '';
  const credential = req.body?.credential;
  const nonce = req.body?.nonce;
  if (!/^\d{8}$/.test(code)) return jsonError(res, 400, 'Enter the 8-digit pairing code.');

  let user;
  try {
    user = await verifyGoogleCredential(credential, nonce);
  } catch (error) {
    return jsonError(res, 401, error.message || 'Google sign-in failed.');
  }

  cleanup();
  const codeHash = sha256('pair:' + code);
  const item = Array.from(pairings.values()).find((entry) => entry.codeHash === codeHash);
  if (!item || item.status !== 'pending' || item.expiresAt <= Date.now()) {
    return jsonError(res, 404, 'Pairing code was not found or has expired.');
  }

  const now = Date.now();
  item.status = 'approved';
  item.user = user;
  item.sessionToken = signToken(user, item.deviceName);
  item.sessionExpiresAt = now + SESSION_TTL_SECONDS * 1000;
  item.deliveryExpiresAt = now + 2 * 60 * 1000;

  res.set('Cache-Control', 'no-store').json({
    ok: true,
    message: 'Device approved. Return to Multix.'
  });
});

app.get('/api/pairings/:id/status', pollLimiter, authenticatePairing, (req, res) => {
  const item = req.pairing;
  if (item.status === 'approved') {
    return res.set('Cache-Control', 'no-store').json({
      status: 'approved',
      accessToken: item.sessionToken,
      expiresAt: item.sessionExpiresAt,
      user: { email: item.user.email, name: item.user.name }
    });
  }
  if (item.status === 'pending' && item.expiresAt <= Date.now()) {
    item.status = 'expired';
  }
  return res.set('Cache-Control', 'no-store').json({ status: item.status });
});

app.post('/api/pairings/:id/complete', authenticatePairing, (req, res) => {
  const item = req.pairing;
  if (item.status !== 'approved' && item.status !== 'completed') {
    return jsonError(res, 409, 'Pairing is not ready to complete.');
  }
  item.status = 'completed';
  item.sessionToken = null;
  item.completedAt = Date.now();
  res.set('Cache-Control', 'no-store').json({ ok: true });
});

app.get('/api/me', authenticateSession, (req, res) => {
  res.set('Cache-Control', 'no-store').json({
    authenticated: true,
    user: {
      email: req.session.email,
      name: req.session.name,
      device: req.session.device
    },
    expiresAt: req.session.exp * 1000
  });
});

app.post('/api/logout', authenticateSession, (req, res) => {
  revokedTokens.set(sha256(req.rawSessionToken), req.session.exp * 1000);
  res.set('Cache-Control', 'no-store').json({ ok: true });
});

app.use((error, _req, res, _next) => {
  if (error instanceof SyntaxError && Object.prototype.hasOwnProperty.call(error, 'body')) {
    return jsonError(res, 400, 'Invalid JSON body.');
  }
  console.error('Unhandled server error:', error);
  return jsonError(res, 500, 'Internal server error.');
});

const serverInstance = app.listen(PORT, () => {
  console.log('Multix auth server listening on port ' + PORT);
  console.log('Allowed website origins: ' + Array.from(allowedOrigins).join(', '));
  console.log('Pairing state is in memory; signed 30-day sessions survive restarts.');
});
function shutdown() {
  serverInstance.close(() => process.exit(0));
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
