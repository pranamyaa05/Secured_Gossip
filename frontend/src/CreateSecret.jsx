import { useState } from 'react';
import {
  encryptContent,
  encryptContentWithPin,
  generateFragmentKey,
  wrapKeyWithPassphrase,
  getMasterSecret,
  getKeyVersion,
  hkdf,
  encrypt,
  importKey,
  generateKey
} from './crypto.js';

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
  const [mode, setMode] = useState('single');
  const [recipients, setRecipients] = useState([{ id: '', passphrase: '' }]);
  const [notBefore, setNotBefore] = useState('');
  const [notAfter, setNotAfter] = useState('');

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

    if (mode === 'multiple') {
      const validRecipients = recipients.filter(r => r.id.trim() && r.passphrase.trim());
      if (validRecipients.length === 0) {
        setError('Please add at least one recipient with both ID and passphrase.');
        return;
      }

      // Check for duplicate recipient IDs
      const recipientIds = validRecipients.map(r => r.id.trim());
      const uniqueIds = new Set(recipientIds);
      if (uniqueIds.size !== recipientIds.length) {
        setError('Recipient IDs must be unique.');
        return;
      }
    }

    setSubmitting(true);
    try {
      // Convert datetime-local strings to timestamps (milliseconds) for backend
      const notBeforeTimestamp = notBefore ? new Date(notBefore).getTime() : null;
      const notAfterTimestamp = notAfter ? new Date(notAfter).getTime() : null;
      let payload;
      let urlFragmentKey;

      if (enablePin) {
        const { ciphertext, iv, fragmentKey, salt } = await encryptContentWithPin(text, pin);
        payload = { ciphertext, iv, expiresInSeconds, burnAfterRead, pin, contentSalt: salt };
        urlFragmentKey = fragmentKey;
      } else if (mode === 'multiple') {
        // Multi-recipient mode: envelope encryption
        // 1. Generate a random DEK (Data Encryption Key)
        const { raw: dekRaw } = await generateKey();
        const dek = await importKey(dekRaw);

        // 2. Encrypt the secret with the DEK
        const { ciphertext, iv } = await encrypt(dek, text);

        // 3. For each recipient, encrypt the DEK with their passphrase
        const keyEnvelopes = await Promise.all(
          validRecipients.map(async (recipient) => {
            const { encryptedKey, salt, iv } = await wrapKeyWithPassphrase(
              await crypto.subtle.exportKey('raw', dek),
              recipient.passphrase.trim()
            );
            return {
              recipientId: recipient.id.trim(),
              encryptedKey,
              salt,
              iv
            };
          })
        );

        payload = {
          ciphertext,
          iv,
          expiresInSeconds,
          burnAfterRead,
          keyEnvelopes,
          isMulti: true
        };
        // For multi-recipient, we use a random fragment key that's not used for encryption
        urlFragmentKey = generateFragmentKey();
      } else {
        // Single recipient mode (existing logic)
        const { ciphertext, iv, key, version } = await encryptContent(text);
        payload = { ciphertext, iv, expiresInSeconds, burnAfterRead, version };
        // Add time constraints if provided
        if (notBeforeTimestamp !== null) {
          payload.notBefore = notBeforeTimestamp;
        }
        if (notAfterTimestamp !== null) {
          payload.notAfter = notAfterTimestamp;
        }
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

      const { id, deleteToken, version } = await response.json();
      const url = `${window.location.origin}/#/view/${id}?v=${version}#${urlFragmentKey}`;

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
      if (mode === 'multiple') {
        setRecipients([{ id: '', passphrase: '' }]); // Reset recipients
      }
    } catch (err) {
      console.error('Error creating secret:', err);
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
            <div style={{ marginBottom: '1rem' }}>
              <label>
                Mode:{' '}
                <select
                  value={mode}
                  onChange={(e) => setMode(e.target.value)}
                >
                  <option value="single">Single Recipient</option>
                  <option value="multiple">Multiple Recipients</option>
                </select>
              </label>
            </div>

            {mode === 'single' && (
              <>
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

                {/* Time-based access controls */}
                <div style={{ margin: '1.5rem 0' }}>
                  <h4>Access Schedule</h4>
                  <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                    <div>
                      <label>
                        Available from:{' '}
                        <input
                          type="datetime-local"
                          value={notBefore}
                          onChange={(e) => setNotBefore(e.target.value)}
                        />
                      </label>
                    </div>
                    <div>
                      <label>
                        Available until:{' '}
                        <input
                          type="datetime-local"
                          value={notAfter}
                          onChange={(e) => setNotAfter(e.target.value)}
                        />
                      </label>
                    </div>
                  </div>
                  <small style={{ display: 'block', marginTop: '0.5rem', color: '#666' }}>
                    Leave blank for immediate availability and no time-based expiration
                  </small>
                </div>
              </>
            )}

            {mode === 'multiple' && (
              <>
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

                <div style={{ margin: '1.5rem 0' }}>
                  <h4>Recipients</h4>
                  {recipients.map((recipient, index) => (
                    <div key={index} style={{ display: 'flex', gap: '1rem', alignItems: 'end', marginBottom: '0.5rem' }}>
                      <div style={{ flex: 1 }}>
                        <label>
                          Recipient ID:{' '}
                          <input
                            value={recipient.id}
                            onChange={(e) => {
                              const newRecipients = [...recipients];
                              newRecipients[index] = { ...newRecipients[index], id: e.target.value };
                              setRecipients(newRecipients);
                            }}
                            placeholder="e.g., alice@example.com"
                          />
                        </label>
                      </div>
                      <div style={{ flex: 1 }}>
                        <label>
                          Passphrase:{' '}
                          <input
                            type="password"
                            value={recipient.passphrase}
                            onChange={(e) => {
                              const newRecipients = [...recipients];
                              newRecipients[index] = { ...newRecipients[index], passphrase: e.target.value };
                              setRecipients(newRecipients);
                            }}
                            placeholder="Enter passphrase"
                          />
                        </label>
                      </div>
                      {recipients.length > 1 && (
                        <button
                          onClick={() => {
                            const newRecipients = recipients.filter((_, i) => i !== index);
                            setRecipients(newRecipients);
                          }}
                          style={{
                            backgroundColor: '#ff4444',
                            color: 'white',
                            border: 'none',
                            padding: '0.25rem 0.5rem',
                            borderRadius: '4px',
                            cursor: 'pointer'
                          }}
                        >
                          Remove
                        </button>
                      )}
                    </div>
                  ))}
                  <div style={{ marginTop: '0.5rem' }}>
                    <button
                      onClick={() => setRecipients([...recipients, { id: '', passphrase: '' }])}
                      style={{
                        backgroundColor: '#444',
                        color: 'white',
                        border: 'none',
                        padding: '0.25rem 0.5rem',
                        borderRadius: '4px',
                        cursor: 'pointer'
                      }}
                    >
                      Add Recipient
                    </button>
                  </div>
                </div>
              </>
            )}

            <div style={{ margin: '1rem 0' }}>
              <button type="submit" disabled={submitting}>
                {submitting ? 'Encrypting...' : 'Create Secret'}
              </button>
            </div>
          </div>
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
