import { useState } from 'react';
import { encryptContent, encryptContentWithPin } from './crypto.js';

const API_BASE = 'http://localhost:3001';

function formatStatus(status) {
  switch (status) {
    case 'waiting': return 'Waiting to be opened';
    case 'seen': return 'Seen by recipient';
    case 'revoked': return 'Revoked';
    case 'expired': return 'Expired';
    case 'destroyed': return 'Destroyed after failed PIN attempts';
    case 'not_found': return 'Not found (Server memory wiped?)';
    default: return status;
  }
}

function CreateSecret() {
  const [text, setText] = useState('');
  const [expiresInSeconds, setExpiresInSeconds] = useState(3600);
  const [burnAfterRead, setBurnAfterRead] = useState(false);
  const [enablePin, setEnablePin] = useState(false);
  const [pin, setPin] = useState('');
  
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const [activeSecret, setActiveSecret] = useState(null);
  const [statusLoading, setStatusLoading] = useState(false);
  const [revokeLoading, setRevokeLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setActiveSecret(null);

    if (!text.trim()) {
      setError('Please enter some content to encrypt.');
      return;
    }

    if (enablePin && (pin.length < 4 || pin.length > 32)) {
      setError('PIN must be between 4 and 32 characters.');
      return;
    }

    setSubmitting(true);
    try {
      let payload;
      let urlFragmentKey;

      if (enablePin) {
        const { ciphertext, iv, fragmentKey, salt } = await encryptContentWithPin(text, pin);
        payload = { ciphertext, iv, expiresInSeconds, burnAfterRead, pin, contentSalt: salt };
        urlFragmentKey = fragmentKey;
      } else {
        const { ciphertext, iv, key } = await encryptContent(text);
        payload = { ciphertext, iv, expiresInSeconds, burnAfterRead };
        urlFragmentKey = key;
      }

      const response = await fetch(`${API_BASE}/pastes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        throw new Error(`Server returned ${response.status}`);
      }

      const { id, deleteToken } = await response.json();
      const url = `${window.location.origin}/#/view/${id}#${urlFragmentKey}`;
      
      setActiveSecret({
        id,
        link: url,
        deleteToken,
        status: 'waiting',
        viewedAt: null
      });

      setText('');
      setPin('');
      setEnablePin(false);
    } catch (err) {
      setError('Failed to create secret. Please try again.');
    } finally {
      setSubmitting(false);
    }
  }

  async function checkStatus() {
    if (!activeSecret) return;
    setStatusLoading(true);
    try {
      const res = await fetch(`${API_BASE}/pastes/${activeSecret.id}/status`, {
        headers: { 'x-delete-token': activeSecret.deleteToken }
      });
      if (res.ok) {
        const data = await res.json();
        setActiveSecret(prev => ({ ...prev, status: data.status, viewedAt: data.viewedAt }));
      } else {
        // If the server returns a 404, it means the secret is gone entirely.
        // During dev, this usually means the Node.js server restarted and wiped the in-memory Maps.
        if (res.status === 404) {
           setActiveSecret(prev => ({ ...prev, status: 'not_found' }));
        }
      }
    } catch (err) {
      console.error('Failed to fetch status', err);
    } finally {
      setStatusLoading(false);
    }
  }

  async function revokeSecret() {
    if (!activeSecret) return;
    setRevokeLoading(true);
    try {
      const res = await fetch(`${API_BASE}/pastes/${activeSecret.id}`, {
        method: 'DELETE',
        headers: { 'x-delete-token': activeSecret.deleteToken }
      });
      if (res.ok || res.status === 404) {
        setActiveSecret(prev => ({ ...prev, status: 'revoked' }));
      }
    } catch(err) {
      console.error('Failed to revoke', err);
    } finally {
      setRevokeLoading(false);
    }
  }

  return (
    <main>
      <h1>Secured_Gossip</h1>
      
      {!activeSecret ? (
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

          <div style={{ margin: '1rem 0' }}>
            <label>
              <input
                type="checkbox"
                checked={enablePin}
                onChange={(e) => setEnablePin(e.target.checked)}
              />{' '}
              Require a PIN to unlock
            </label>
          </div>

          {enablePin && (
            <div style={{ margin: '1rem 0' }}>
              <label>
                PIN:{' '}
                <input
                  type="password"
                  value={pin}
                  onChange={(e) => setPin(e.target.value)}
                  placeholder="4-32 characters"
                  minLength={4}
                  maxLength={32}
                />
              </label>
            </div>
          )}

          <button type="submit" disabled={submitting}>
            {submitting ? 'Encrypting...' : 'Create Secret'}
          </button>
        </form>
      ) : (
        <div style={{ textAlign: 'left' }}>
          <h3>Secret created successfully.</h3>
          <p>Share this link (it will only work once you open it — the key is never sent to the server):</p>
          <input 
            type="text" 
            readOnly 
            value={activeSecret.link} 
            style={{ width: '100%', padding: '0.5rem', boxSizing: 'border-box' }} 
            onFocus={(e) => e.target.select()} 
          />

          {/* ADDED: color: '#111' to ensure text is visible on the light gray background */}
          <div style={{ marginTop: '1.5rem', padding: '1rem', background: '#f5f5f5', color: '#111', borderRadius: '4px' }}>
            <p style={{ margin: '0 0 0.5rem 0' }}>
              <strong>Status:</strong> {formatStatus(activeSecret.status)}
            </p>
            {activeSecret.viewedAt && (
              <p style={{ margin: '0 0 1rem 0' }}>
                <strong>Seen at:</strong> {new Date(activeSecret.viewedAt).toLocaleString()}
              </p>
            )}
            
            <div style={{ display: 'flex', gap: '1rem', marginTop: '1rem' }}>
              <button onClick={checkStatus} disabled={statusLoading}>
                {statusLoading ? 'Checking...' : 'Check Status'}
              </button>
              <button 
                onClick={revokeSecret} 
                disabled={revokeLoading || activeSecret.status !== 'waiting'}
                style={{ 
                  backgroundColor: activeSecret.status === 'waiting' ? '#ff4444' : '#ccc', 
                  color: 'white',
                  border: 'none',
                  padding: '0.5rem 1rem',
                  borderRadius: '4px',
                  cursor: activeSecret.status === 'waiting' ? 'pointer' : 'not-allowed'
                }}
              >
                {revokeLoading ? 'Revoking...' : 'Revoke Secret'}
              </button>
            </div>
          </div>
          
          <div style={{ marginTop: '2rem' }}>
             <button onClick={() => setActiveSecret(null)}>Create Another Secret</button>
          </div>
        </div>
      )}

      {error && <p style={{ color: 'red', marginTop: '1rem' }}>{error}</p>}
    </main>
  );
}

export default CreateSecret;
