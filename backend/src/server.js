import express from "express";
import cors from "cors";
import crypto from "node:crypto";

const app = express();
const PORT = process.env.PORT || 3001;

const PIN_ITERATIONS = 300000;
const PIN_KEYLEN = 32;
const PIN_DIGEST = "sha256";
const MAX_PIN_ATTEMPTS = 5;
const REVEAL_RATE_LIMIT_WINDOW_MS = 60 * 1000;
const REVEAL_RATE_LIMIT_MAX = 30;

const pastes = new Map();
const pasteStatus = new Map();

app.use(cors());
app.use(express.json({ limit: "15mb" }));

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
  const now = Date.now();
  if (now > pasteOrMeta.createdAt + pasteOrMeta.expiresInSeconds * 1000) return true;
  if (pasteOrMeta.notBefore !== null && pasteOrMeta.notBefore !== undefined && now < pasteOrMeta.notBefore) return true;
  if (pasteOrMeta.notAfter !== null && pasteOrMeta.notAfter !== undefined && now > pasteOrMeta.notAfter) return true;
  return false;
}

function hashPin(pin, salt) {
  return crypto.pbkdf2Sync(pin, salt, PIN_ITERATIONS, PIN_KEYLEN, PIN_DIGEST);
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.post("/pastes", (req, res) => {
  const {
    ciphertext,
    iv,
    expiresInSeconds = 3600,
    burnAfterRead = false,
    pin,
    contentSalt,
    version,
    keyEnvelopes,
    isMulti,
    notBefore,
    notAfter,
    attachmentCiphertext,
    attachmentIv
  } = req.body || {};

  if (typeof ciphertext !== "string" || typeof iv !== "string" || !ciphertext || !iv) {
    return res.status(400).json({ error: "ciphertext and iv are required strings" });
  }

  const now = Date.now();
  let validNotBefore = null;
  let validNotAfter = null;

  if (notBefore !== undefined && notBefore !== null && notBefore !== "") {
    const notBeforeNum = Number(notBefore);
    if (isNaN(notBeforeNum) || notBeforeNum <= now) {
      return res.status(400).json({ error: "notBefore must be a future timestamp" });
    }
    validNotBefore = notBeforeNum;
  }

  if (notAfter !== undefined && notAfter !== null && notAfter !== "") {
    const notAfterNum = Number(notAfter);
    if (isNaN(notAfterNum) || notAfterNum <= now) {
      return res.status(400).json({ error: "notAfter must be a future timestamp" });
    }
    if (validNotBefore !== null && notAfterNum <= validNotBefore) {
      return res.status(400).json({ error: "notAfter must be after notBefore" });
    }
    validNotAfter = notAfterNum;
  }

  let hasPin = false;
  let pinHash = null;
  let pinSalt = null;

  if (pin !== undefined && pin !== null && pin !== "") {
    if (typeof pin !== "string" || pin.length < 4 || pin.length > 32) {
      return res.status(400).json({ error: "pin must be a string between 4 and 32 characters" });
    }
    if (typeof contentSalt !== "string" || !contentSalt) {
      return res.status(400).json({ error: "contentSalt is required when pin is set" });
    }
    hasPin = true;
    pinSalt = crypto.randomBytes(16);
    pinHash = hashPin(pin, pinSalt);
  }

  const id = crypto.randomUUID();
  const deleteToken = crypto.randomBytes(24).toString("base64url");
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
    version: Number(version) || 0,
    keyEnvelopes: Array.isArray(keyEnvelopes) ? keyEnvelopes : [],
    isMulti: Boolean(isMulti),
    notBefore: validNotBefore,
    notAfter: validNotAfter,
    attachmentCiphertext: attachmentCiphertext || null,
    attachmentIv: attachmentIv || null
  });

  pasteStatus.set(id, {
    deleteTokenHash,
    status: "waiting",
    createdAt: Date.now(),
    expiresInSeconds: Number(expiresInSeconds),
    viewedAt: null,
    notBefore: validNotBefore,
    notAfter: validNotAfter
  });

  res.status(201).json({ id, deleteToken, version: Number(version) || 0 });
});

app.get("/pastes/:id/meta", (req, res) => {
  const { id } = req.params;
  const paste = pastes.get(id);
  const meta = pasteStatus.get(id);

  if (!paste || !meta) {
    return res.status(404).json({ error: "not found" });
  }

  const now = Date.now();
  if (now > paste.createdAt + paste.expiresInSeconds * 1000 || (paste.notAfter && now > paste.notAfter)) {
    pastes.delete(id);
    if (meta.status === "waiting") meta.status = "expired";
    return res.status(404).json({ error: "not found" });
  }

  res.json({
    hasPin: paste.hasPin,
    hasAttachment: Boolean(paste.attachmentCiphertext),
    version: paste.version,
    isMulti: paste.isMulti,
    notBefore: meta.notBefore,
    notAfter: meta.notAfter
  });
});

app.get("/pastes/:id/status", (req, res) => {
  const { id } = req.params;
  const token = req.get("x-delete-token");
  const meta = pasteStatus.get(id);

  if (!meta) {
    return res.status(404).json({ error: "not found" });
  }

  if (typeof token !== "string" || !token) {
    return res.status(400).json({ error: "delete token required" });
  }

  const candidateHash = Buffer.from(sha256Hex(token), "hex");
  const storedHash = Buffer.from(meta.deleteTokenHash, "hex");

  if (candidateHash.length !== storedHash.length || !crypto.timingSafeEqual(candidateHash, storedHash)) {
    return res.status(403).json({ error: "invalid delete token" });
  }

  if (meta.status === "waiting" && isExpired(meta)) {
    meta.status = "expired";
    pastes.delete(id);
  }

  res.json({
    status: meta.status,
    viewedAt: meta.viewedAt
  });
});

app.post("/pastes/:id/reveal", (req, res) => {
  if (isRateLimited(req.ip)) {
    return res.status(429).json({ error: "too many requests, slow down" });
  }

  const { id } = req.params;
  const { pin, recipientId } = req.body || {};
  const paste = pastes.get(id);
  const meta = pasteStatus.get(id);

  if (!paste || isExpired(paste)) {
    if (paste && (Date.now() > paste.createdAt + paste.expiresInSeconds * 1000 || (paste.notAfter && Date.now() > paste.notAfter))) {
      pastes.delete(id);
      if (meta && meta.status === "waiting") meta.status = "expired";
    }
    return res.status(404).json({ error: "not found or not currently available" });
  }

  if (!paste.isMulti) {
    if (paste.hasPin) {
      if (typeof pin !== "string" || !pin) {
        return res.status(400).json({ error: "pin is required" });
      }

      const candidate = hashPin(pin, paste.pinSalt);
      const correct =
        candidate.length === paste.pinHash.length &&
        crypto.timingSafeEqual(candidate, paste.pinHash);

      if (!correct) {
        paste.pinAttempts += 1;
        if (paste.pinAttempts >= MAX_PIN_ATTEMPTS) {
          pastes.delete(id);
          if (meta) meta.status = "destroyed";
          return res.status(429).json({ error: "too many incorrect PIN attempts, secret deleted" });
        }
        return res.status(401).json({
          error: "incorrect pin",
          attemptsRemaining: MAX_PIN_ATTEMPTS - paste.pinAttempts,
        });
      }
    }

    const payload = {
      ciphertext: paste.ciphertext,
      iv: paste.iv,
      version: paste.version,
      attachmentCiphertext: paste.attachmentCiphertext,
      attachmentIv: paste.attachmentIv
    };
    if (paste.hasPin) payload.contentSalt = paste.contentSalt;

    if (meta) {
      meta.status = "seen";
      meta.viewedAt = Date.now();
    }

    if (paste.burnAfterRead) {
      pastes.delete(id);
    } else {
      paste.pinAttempts = 0;
    }

    return res.json(payload);
  }

  if (typeof recipientId !== "string" || !recipientId) {
    return res.status(400).json({ error: "recipientId is required" });
  }

  const envelope = paste.keyEnvelopes.find(env => env.recipientId === recipientId);
  if (!envelope) {
    return res.status(401).json({ error: "invalid recipient ID or passphrase" });
  }

  if (meta) {
    meta.status = "seen";
    meta.viewedAt = Date.now();
  }

  if (paste.burnAfterRead) {
    pastes.delete(id);
  }

  return res.json({
    ciphertext: paste.ciphertext,
    iv: paste.iv,
    version: paste.version,
    attachmentCiphertext: paste.attachmentCiphertext,
    attachmentIv: paste.attachmentIv,
    keyEnvelope: {
      encryptedKey: envelope.encryptedKey,
      salt: envelope.salt,
      iv: envelope.iv
    }
  });
});

app.delete("/pastes/:id", (req, res) => {
  const { id } = req.params;
  const token = req.get("x-delete-token") || (req.body && req.body.deleteToken);
  const meta = pasteStatus.get(id);

  if (!meta) {
    return res.status(404).json({ error: "not found" });
  }

  if (typeof token !== "string" || !token) {
    return res.status(400).json({ error: "delete token required" });
  }

  const candidateHash = Buffer.from(sha256Hex(token), "hex");
  const storedHash = Buffer.from(meta.deleteTokenHash, "hex");
  const match =
    candidateHash.length === storedHash.length &&
    crypto.timingSafeEqual(candidateHash, storedHash);

  if (!match) {
    return res.status(403).json({ error: "invalid delete token" });
  }

  if (pastes.has(id)) {
    pastes.delete(id);
  }

  if (meta.status === "waiting") {
    meta.status = "revoked";
  }

  res.status(204).end();
});

setInterval(() => {
  const now = Date.now();

  for (const [id, paste] of pastes.entries()) {
    if (now > paste.createdAt + paste.expiresInSeconds * 1000 || (paste.notAfter && now > paste.notAfter)) {
      pastes.delete(id);
      const meta = pasteStatus.get(id);
      if (meta && meta.status === "waiting") {
        meta.status = "expired";
      }
    }
  }

  for (const [id, meta] of pasteStatus.entries()) {
    if (now > meta.createdAt + meta.expiresInSeconds * 1000 + (24 * 60 * 60 * 1000)) {
      pasteStatus.delete(id);
    }
  }
}, 60000);

app.listen(PORT, () => {
  console.log(`Secured_Gossip backend listening on port ${PORT}`);
});
