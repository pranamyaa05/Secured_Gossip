import express from 'express';
import cors from 'cors';
import crypto from 'node:crypto';

const app = express();
const PORT = process.env.PORT || 3001;

// ---- Config ----
const PIN_ITERATIONS = 300000;
const PIN_KEYLEN = 32;
const PIN_DIGEST = 'sha256';
const MAX_PIN_ATTEMPTS = 5;
const REVEAL_RATE_LIMIT_WINDOW_MS = 60 * 1000;
const REVEAL_RATE_LIMIT_MAX = 30;

// In-memory store for ciphertext and crypto parameters.
const pastes = new Map();

// In-memory store for creator status tracking. 
// Separated from 'pastes' so burn-after-read can delete ciphertext 
// while leaving behind non-sensitive status metadata for the creator.
// id -> { deleteTokenHash, status, createdAt, expiresInSeconds, viewedAt }
const pasteStatus = new Map();

app.use(cors());
app.use(express.json());

const revealHits = new Map();
function isRateLimited(ip) {
  const now = Date.now();
  const entry = revealHits.get(ip);
  if (!entry || now > entry.resetAt) {
    revealHits.set(ip, { count: 1, resetAt: now + REVEAL_RATE_LIMIT_WINDOW_MS });
    return false;
  }
  entry.count += 1;
  return entry.count > REVEAL_RATE_LIMIT_MAX;
}

function isExpired(pasteOrMeta) {
  return Date.now() > pasteOrMeta.createdAt + pasteOrMeta.expiresInSeconds * 1000;
}

function hashPin(pin, salt) {
  return crypto.pbkdf2Sync(pin, salt, PIN_ITERATIONS, PIN_KEYLEN, PIN_DIGEST);
}

function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/pastes', (req, res) => {
  const {
    ciphertext,
    iv,
    expiresInSeconds = 3600,
    burnAfterRead = false,
    pin,
    contentSalt,
  } = req.body || {};

  if (typeof ciphertext !== 'string' || typeof iv !== 'string' || !ciphertext || !iv) {
    return res.status(400).json({ error: 'ciphertext and iv are required strings' });
  }

  let hasPin = false;
  let pinHash = null;
  let pinSalt = null;

  if (pin !== undefined && pin !== null && pin !== '') {
    if (typeof pin !== 'string' || pin.length < 4 || pin.length > 32) {
      return res.status(400).json({ error: 'pin must be a string between 4 and 32 characters' });
    }
    if (typeof contentSalt !== 'string' || !contentSalt) {
      return res.status(400).json({ error: 'contentSalt is required when pin is set' });
    }
    hasPin = true;
    pinSalt = crypto.randomBytes(16);
    pinHash = hashPin(pin, pinSalt);
  }

  const id = crypto.randomUUID();
  const deleteToken = crypto.randomBytes(24).toString('base64url');
  const deleteTokenHash = sha256Hex(deleteToken);

  pastes.set(id, {
    ciphertext,
    iv,
    createdAt: Date.now(),
    expiresInSeconds: Number(expiresInSeconds),
    burnAfterRead: Boolean(burnAfterRead),
    hasPin,
    pinHash,
    pinSalt,
    pinAttempts: 0,
    contentSalt: hasPin ? contentSalt : null,
    deleteTokenHash,
  });

  pasteStatus.set(id, {
    deleteTokenHash,
    status: 'waiting', // waiting | seen | revoked | expired | destroyed
    createdAt: Date.now(),
    expiresInSeconds: Number(expiresInSeconds),
    viewedAt: null
  });

  res.status(201).json({ id, deleteToken });
});

// Creator-authorized endpoint to check the status of a secret without consuming it.
app.get('/pastes/:id/status', (req, res) => {
  const { id } = req.params;
  const token = req.get('x-delete-token');
  const meta = pasteStatus.get(id);

  if (!meta) {
    return res.status(404).json({ error: 'not found' });
  }

  if (typeof token !== 'string' || !token) {
    return res.status(400).json({ error: 'delete token required' });
  }

  const candidateHash = Buffer.from(sha256Hex(token), 'hex');
  const storedHash = Buffer.from(meta.deleteTokenHash, 'hex');
  
  if (candidateHash.length !== storedHash.length || !crypto.timingSafeEqual(candidateHash, storedHash)) {
    return res.status(403).json({ error: 'invalid delete token' });
  }

  // Dynamically mark as expired if queried after time is up
  if (meta.status === 'waiting' && isExpired(meta)) {
    meta.status = 'expired';
    pastes.delete(id); // Ensure ciphertext is aggressively wiped
  }

  res.json({
    status: meta.status,
    viewedAt: meta.viewedAt
  });
});

app.get('/pastes/:id/meta', (req, res) => {
  const { id } = req.params;
  const paste = pastes.get(id);
  const meta = pasteStatus.get(id);

  if (!paste || isExpired(paste)) {
    if (paste) pastes.delete(id);
    if (meta && meta.status === 'waiting') meta.status = 'expired';
    return res.status(404).json({ error: 'not found' });
  }

  res.json({ hasPin: paste.hasPin });
});

app.post('/pastes/:id/reveal', (req, res) => {
  if (isRateLimited(req.ip)) {
    return res.status(429).json({ error: 'too many requests, slow down' });
  }

  const { id } = req.params;
  const { pin } = req.body || {};
  const paste = pastes.get(id);
  const meta = pasteStatus.get(id);

  if (!paste || isExpired(paste)) {
    if (paste) pastes.delete(id);
    if (meta && meta.status === 'waiting') meta.status = 'expired';
    return res.status(404).json({ error: 'not found' });
  }

  if (paste.hasPin) {
    if (typeof pin !== 'string' || !pin) {
      return res.status(400).json({ error: 'pin is required' });
    }

    const candidate = hashPin(pin, paste.pinSalt);
    const correct =
      candidate.length === paste.pinHash.length &&
      crypto.timingSafeEqual(candidate, paste.pinHash);

    if (!correct) {
      paste.pinAttempts += 1;
      if (paste.pinAttempts >= MAX_PIN_ATTEMPTS) {
        pastes.delete(id);
        if (meta) meta.status = 'destroyed';
        return res.status(429).json({ error: 'too many incorrect PIN attempts, secret deleted' });
      }
      return res.status(401).json({
        error: 'incorrect pin',
        attemptsRemaining: MAX_PIN_ATTEMPTS - paste.pinAttempts,
      });
    }
  }

  const payload = { ciphertext: paste.ciphertext, iv: paste.iv };
  if (paste.hasPin) payload.contentSalt = paste.contentSalt;

  // Mark as seen *before* potential burn-after-read deletion
  if (meta) {
    meta.status = 'seen';
    meta.viewedAt = Date.now();
  }

  if (paste.burnAfterRead) {
    pastes.delete(id);
  } else {
    paste.pinAttempts = 0;
  }

  res.json(payload);
});

app.delete('/pastes/:id', (req, res) => {
  const { id } = req.params;
  const token = req.get('x-delete-token') || (req.body && req.body.deleteToken);
  const meta = pasteStatus.get(id);

  if (!meta) {
    return res.status(404).json({ error: 'not found' });
  }

  if (typeof token !== 'string' || !token) {
    return res.status(400).json({ error: 'delete token required' });
  }

  const candidateHash = Buffer.from(sha256Hex(token), 'hex');
  const storedHash = Buffer.from(meta.deleteTokenHash, 'hex');
  const match =
    candidateHash.length === storedHash.length &&
    crypto.timingSafeEqual(candidateHash, storedHash);

  if (!match) {
    return res.status(403).json({ error: 'invalid delete token' });
  }

  if (pastes.has(id)) {
    pastes.delete(id);
  }

  if (meta.status === 'waiting') {
    meta.status = 'revoked';
  }

  res.status(204).end();
});

setInterval(() => {
  const now = Date.now();
  
  // 1. Wipe expired ciphertext
  for (const [id, paste] of pastes.entries()) {
    if (now > paste.createdAt + paste.expiresInSeconds * 1000) {
      pastes.delete(id);
      const meta = pasteStatus.get(id);
      if (meta && meta.status === 'waiting') {
        meta.status = 'expired';
      }
    }
  }

  // 2. Clean up old metadata (keep for 24 hours after expiration so creator can still check status)
  for (const [id, meta] of pasteStatus.entries()) {
    if (now > meta.createdAt + meta.expiresInSeconds * 1000 + (24 * 60 * 60 * 1000)) {
      pasteStatus.delete(id);
    }
  }
}, 60000);

app.listen(PORT, () => {
  console.log(`Secured_Gossip backend listening on port ${PORT}`);
});
