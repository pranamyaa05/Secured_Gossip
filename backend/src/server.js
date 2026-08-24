import express from 'express';
import cors from 'cors';
import crypto from 'node:crypto';

const app = express();
const PORT = process.env.PORT || 3001;

// ---- Config ----
const PIN_ITERATIONS = 300000; // PBKDF2 iterations for the server-side PIN verifier
const PIN_KEYLEN = 32; // bytes
const PIN_DIGEST = 'sha256';
const MAX_PIN_ATTEMPTS = 5; // wrong PIN attempts before the secret is destroyed
const REVEAL_RATE_LIMIT_WINDOW_MS = 60 * 1000;
const REVEAL_RATE_LIMIT_MAX = 30; // requests per IP per window, across all pastes

// In-memory store for pastes: id -> {
//   ciphertext, iv, createdAt, expiresInSeconds, burnAfterRead,
//   hasPin, pinHash, pinSalt, pinAttempts, contentSalt,
//   deleteTokenHash
// }
// No persistence, no accounts. The PIN itself is NEVER stored (only a salted
// PBKDF2 hash of it) and is NEVER written to any log line.
const pastes = new Map();

app.use(cors());
app.use(express.json());

// ---- tiny in-memory IP rate limiter for the reveal endpoint ----
const revealHits = new Map(); // ip -> { count, resetAt }
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

function isExpired(paste) {
  return Date.now() > paste.createdAt + paste.expiresInSeconds * 1000;
}

function hashPin(pin, salt) {
  // Synchronous on purpose: it keeps the whole /reveal handler synchronous
  // (see comment in the route below) so burn-after-read deletion is atomic
  // with respect to concurrent requests, with no extra locking needed.
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
    // `pin` is not referenced again below and is never logged or persisted.
  }

  const id = crypto.randomUUID();
  const deleteToken = crypto.randomBytes(24).toString('base64url');

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
    deleteTokenHash: sha256Hex(deleteToken),
  });

  // deleteToken is handed back exactly once, to the creator only.
  res.status(201).json({ id, deleteToken });
});

// Lightweight metadata check. Safe for automated link scanners / preview bots:
// it never returns ciphertext and never consumes burn-after-read or a PIN attempt.
app.get('/pastes/:id/meta', (req, res) => {
  const { id } = req.params;
  const paste = pastes.get(id);

  if (!paste || isExpired(paste)) {
    if (paste) pastes.delete(id);
    return res.status(404).json({ error: 'not found' });
  }

  res.json({ hasPin: paste.hasPin });
});

// Explicit reveal action. This is the ONLY endpoint that returns ciphertext.
// The frontend calls it solely in response to the user clicking "Reveal
// Secret" (and, for PIN-protected secrets, only after submitting a PIN).
app.post('/pastes/:id/reveal', (req, res) => {
  if (isRateLimited(req.ip)) {
    return res.status(429).json({ error: 'too many requests, slow down' });
  }

  const { id } = req.params;
  const { pin } = req.body || {};
  const paste = pastes.get(id);

  if (!paste || isExpired(paste)) {
    if (paste) pastes.delete(id);
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
        // Destroy the secret outright so it can't keep being brute-forced.
        pastes.delete(id);
        return res.status(429).json({ error: 'too many incorrect PIN attempts, secret deleted' });
      }
      return res.status(401).json({
        error: 'incorrect pin',
        attemptsRemaining: MAX_PIN_ATTEMPTS - paste.pinAttempts,
      });
    }
  }

  // Everything above is synchronous (pbkdf2Sync + Map lookups), so this
  // handler runs to completion without ever yielding to the event loop.
  // That makes the delete below atomic w.r.t. concurrent/parallel requests
  // for the same id: two simultaneous reveals of a burn-after-read secret
  // cannot both succeed, because Node can't interleave two synchronous
  // handlers mid-execution.
  const payload = { ciphertext: paste.ciphertext, iv: paste.iv };
  if (paste.hasPin) payload.contentSalt = paste.contentSalt;

  if (paste.burnAfterRead) {
    pastes.delete(id);
  } else {
    paste.pinAttempts = 0;
  }

  res.json(payload);
});

// Creator-only revocation: requires the random delete token that was
// returned exactly once at creation time. Only a hash of it is ever stored.
app.delete('/pastes/:id', (req, res) => {
  const { id } = req.params;
  const token = req.get('x-delete-token') || (req.body && req.body.deleteToken);
  const paste = pastes.get(id);

  if (!paste) {
    return res.status(404).json({ error: 'not found' });
  }

  if (typeof token !== 'string' || !token) {
    return res.status(400).json({ error: 'delete token required' });
  }

  const candidateHash = Buffer.from(sha256Hex(token), 'hex');
  const storedHash = Buffer.from(paste.deleteTokenHash, 'hex');
  const match =
    candidateHash.length === storedHash.length &&
    crypto.timingSafeEqual(candidateHash, storedHash);

  if (!match) {
    return res.status(403).json({ error: 'invalid delete token' });
  }

  pastes.delete(id);
  res.status(204).end();
});

// Periodically clean up expired pastes
setInterval(() => {
  const now = Date.now();
  for (const [id, paste] of pastes.entries()) {
    if (now > paste.createdAt + paste.expiresInSeconds * 1000) {
      pastes.delete(id);
    }
  }
}, 60000); // Every 60 seconds

app.listen(PORT, () => {
  console.log(`Secured_Gossip backend listening on port ${PORT}`);
});
