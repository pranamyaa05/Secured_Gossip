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
  const { ciphertext, iv } = req.body || {};

  if (typeof ciphertext !== 'string' || typeof iv !== 'string' || !ciphertext || !iv) {
    return res.status(400).json({ error: 'ciphertext and iv are required strings' });
  }

  const id = crypto.randomUUID();
  pastes.set(id, { ciphertext, iv, createdAt: Date.now() });

  res.status(201).json({ id });
});

app.get('/pastes/:id', (req, res) => {
  const paste = pastes.get(req.params.id);

  if (!paste) {
    return res.status(404).json({ error: 'not found' });
  }

  res.json({ ciphertext: paste.ciphertext, iv: paste.iv });
});

app.listen(PORT, () => {
  console.log(`Secured_Gossip backend listening on port ${PORT}`);
});
