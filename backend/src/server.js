import express from 'express';
import cors from 'cors';
import crypto from 'node:crypto';

const app = express();
const PORT = process.env.PORT || 3001;

// In-memory store for pastes: id -> { ciphertext, iv, createdAt }
// No persistence, no expiry, no auth yet — per Step 4 of the roadmap.
const pastes = new Map();

app.use(cors());
app.use(express.json());

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/pastes', (req, res) => {
  const { ciphertext, iv, expiresInSeconds = 3600, burnAfterRead = false } = req.body || {};

  if (typeof ciphertext !== 'string' || typeof iv !== 'string' || !ciphertext || !iv) {
    return res.status(400).json({ error: 'ciphertext and iv are required strings' });
  }

  const id = crypto.randomUUID();
  pastes.set(id, {
    ciphertext,
    iv,
    createdAt: Date.now(),
    expiresInSeconds: Number(expiresInSeconds),
    burnAfterRead: Boolean(burnAfterRead)
  });

  res.status(201).json({ id });
});

app.get('/pastes/:id', (req, res) => {
  const { id } = req.params;
  const paste = pastes.get(id);

  if (!paste) {
    return res.status(404).json({ error: 'not found' });
  }

  const isExpired = Date.now() > paste.createdAt + (paste.expiresInSeconds * 1000);

  if (isExpired) {
    pastes.delete(id);
    return res.status(404).json({ error: 'not found' });
  }

  if (paste.burnAfterRead) {
    pastes.delete(id);
  }

  res.json({ ciphertext: paste.ciphertext, iv: paste.iv });
});

// Periodically clean up expired pastes
setInterval(() => {
  const now = Date.now();
  for (const [id, paste] of pastes.entries()) {
    if (now > paste.createdAt + (paste.expiresInSeconds * 1000)) {
      pastes.delete(id);
    }
  }
}, 60000); // Every 60 seconds

app.listen(PORT, () => {
  console.log(`Secured_Gossip backend listening on port ${PORT}`);
});
