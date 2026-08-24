import { useState } from 'react';
import { encryptContent } from './crypto.js';

const API_BASE = 'http://localhost:3001';

function CreateSecret() {
  const [text, setText] = useState('');
  const [expiresInSeconds, setExpiresInSeconds] = useState(3600);
  const [burnAfterRead, setBurnAfterRead] = useState(false);
  const [link, setLink] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setLink('');

    if (!text.trim()) {
      setError('Please enter some content to encrypt.');
      return;
    }

    setSubmitting(true);
    try {
      const { ciphertext, iv, key } = await encryptContent(text);

      const response = await fetch(`${API_BASE}/pastes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ciphertext, iv, expiresInSeconds, burnAfterRead }),
      });

      if (!response.ok) {
        throw new Error(`Server returned ${response.status}`);
      }

      const { id } = await response.json();

      const url = `${window.location.origin}/#/view/${id}#${key}`;
      setLink(url);
      setText('');
    } catch (err) {
      setError('Failed to create secret. Please try again.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main>
      <h1>Secured_Gossip</h1>
      <form onSubmit={handleSubmit}>
        <div>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Type your secret here..."
            rows={8}
            cols={50}
          />
        </div>

        <div style={{ margin: '1rem 0' }}>
          <label>
            Expiry:{' '}
            <select
              value={expiresInSeconds}
              onChange={(e) => setExpiresInSeconds(Number(e.target.value))}
            >
              <option value={300}>5 minutes</option>
              <option value={3600}>1 hour</option>
              <option value={86400}>1 day</option>
            </select>
          </label>
        </div>

        <div style={{ margin: '1rem 0' }}>
          <label>
            <input
              type="checkbox"
              checked={burnAfterRead}
              onChange={(e) => setBurnAfterRead(e.target.checked)}
            />{' '}
            Burn after read
          </label>
        </div>

        <button type="submit" disabled={submitting}>
          {submitting ? 'Encrypting...' : 'Create Secret'}
        </button>
      </form>

      {error && <p style={{ color: 'red' }}>{error}</p>}

      {link && (
        <div>
          <p>Share this link (it will only work once you open it — the key is never sent to the server):</p>
          <input type="text" readOnly value={link} size={80} onFocus={(e) => e.target.select()} />
        </div>
      )}
    </main>
  );
}

export default CreateSecret;
