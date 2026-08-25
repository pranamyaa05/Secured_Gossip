import { useState } from 'react';
import {
  encryptContent,
  encryptContentWithPin,
  generateFragmentKey,
  wrapKeyWithPassphrase,
  encrypt,
  importKey,
  generateKey,
  buildAttachmentPlaintext,
  MAX_ATTACHMENT_BYTES,
  ALLOWED_ATTACHMENT_EXTENSIONS,
} from './crypto.js';
import gossipImage from './assets/gossip.png';

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
function statusClass(status) { return `status-pill status-${status}`; }

function WaveField({ className }) {
  return (
    <svg viewBox="0 0 1440 300" preserveAspectRatio="none" className={className} aria-hidden="true">
      <path d="M0,180 C240,120 480,220 720,170 C960,120 1200,200 1440,150 L1440,300 L0,300 Z" fill="var(--mint)" opacity="0.18" />
      <path d="M0,210 C240,260 480,180 720,220 C960,260 1200,190 1440,230 L1440,300 L0,300 Z" fill="var(--lavender)" opacity="0.16" />
      <path d="M0,240 C240,200 480,270 720,230 C960,190 1200,260 1440,220 L1440,300 L0,300 Z" fill="var(--peach)" opacity="0.16" />
    </svg>
  );
}

function GossipIllustration() {
  return (
    <img
      src={gossipImage}
      alt="Two people whispering secrets"
      className="gossip-illustration"
    />
  );
}

function SealMark() {
  return (
    <svg viewBox="0 0 120 120" className="seal-wrap" role="img" aria-label="A sealed spiral mark">
      <path d="M60,20 C90,20 100,50 85,70 C73,86 48,86 40,68 C34,54 44,42 58,44 C68,46 72,56 64,60"
        fill="none" stroke="var(--ink-line)" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

function PrivacyDiagram() {
  return (
    <div className="privacy-diagram">
      <div className="privacy-node">
        <svg viewBox="0 0 100 70" className="privacy-node-svg" aria-hidden="true">
          <rect x="6" y="6" width="88" height="58" rx="10" fill="none" stroke="var(--ink-line)" strokeWidth="2" />
        </svg>
        <span>Your device</span>
      </div>
      <svg viewBox="0 0 80 20" className="privacy-line" aria-hidden="true">
        <line x1="0" y1="10" x2="80" y2="10" stroke="var(--mint-deep)" strokeWidth="3" strokeLinecap="round" />
      </svg>
      <div className="privacy-node privacy-node-seal"><SealMark /></div>
      <svg viewBox="0 0 80 20" className="privacy-line" aria-hidden="true">
        <line x1="0" y1="10" x2="80" y2="10" stroke="var(--ink-muted)" strokeWidth="2" strokeDasharray="4 6" strokeLinecap="round" />
      </svg>
      <div className="privacy-node">
        <svg viewBox="0 0 100 70" className="privacy-node-svg" aria-hidden="true">
          <rect x="6" y="6" width="88" height="58" rx="10" fill="none" stroke="var(--ink-line)" strokeWidth="2" />
          <line x1="20" y1="24" x2="80" y2="24" stroke="var(--ink-line)" strokeWidth="2" />
          <line x1="20" y1="38" x2="80" y2="38" stroke="var(--ink-line)" strokeWidth="2" />
          <line x1="20" y1="52" x2="60" y2="52" stroke="var(--ink-line)" strokeWidth="2" />
        </svg>
        <span>Our server — sees only ciphertext</span>
      </div>
    </div>
  );
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

  const [file, setFile] = useState(null);
  const [fileError, setFileError] = useState('');
  const [fileInputKey, setFileInputKey] = useState(0);

  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const [activeSecret, setActiveSecret] = useState(null);
  const [statusLoading, setStatusLoading] = useState(false);
  const [revokeLoading, setRevokeLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  function handleFileChange(e) {
    const selected = e.target.files && e.target.files[0];
    setFileError('');
    if (!selected) { setFile(null); return; }
    if (selected.size > MAX_ATTACHMENT_BYTES) {
      setFileError(`File exceeds the ${Math.floor(MAX_ATTACHMENT_BYTES / (1024 * 1024))}MB limit.`);
      setFile(null);
      return;
    }
    const lastDot = selected.name.lastIndexOf('.');
    const ext = lastDot >= 0 ? selected.name.slice(lastDot).toLowerCase() : '';
    if (!ALLOWED_ATTACHMENT_EXTENSIONS.includes(ext)) {
      setFileError('Unsupported file type for this demo.');
      setFile(null);
      return;
    }
    setFile(selected);
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setActiveSecret(null);

    if (!text.trim() && !file) {
      setError('Please enter some content or attach a file to encrypt.');
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

      const recipientIds = validRecipients.map(r => r.id.trim());
      const uniqueIds = new Set(recipientIds);
      if (uniqueIds.size !== recipientIds.length) {
        setError('Recipient IDs must be unique.');
        return;
      }
    }

    setSubmitting(true);
    try {
      const notBeforeTimestamp = notBefore ? new Date(notBefore).getTime() : null;
      const notAfterTimestamp = notAfter ? new Date(notAfter).getTime() : null;
      let payload;
      let urlFragmentKey;

      if (enablePin) {
        const encryptedData = await encryptContentWithPin(text, pin, file);
        payload = {
          ciphertext: encryptedData.ciphertext,
          iv: encryptedData.iv,
          expiresInSeconds,
          burnAfterRead,
          pin,
          contentSalt: encryptedData.salt,
          attachmentCiphertext: encryptedData.attachmentCiphertext,
          attachmentIv: encryptedData.attachmentIv
        };
        urlFragmentKey = encryptedData.fragmentKey;
      } else if (mode === 'multiple') {
        const { raw: dekRaw } = await generateKey();
        const dek = await importKey(dekRaw);
        const { ciphertext, iv } = await encrypt(dek, text);

        let attachmentCiphertext = null;
        let attachmentIv = null;
        if (file) {
          const attachmentPlaintext = await buildAttachmentPlaintext(file);
          const attEncrypted = await encrypt(dek, attachmentPlaintext);
          attachmentCiphertext = attEncrypted.ciphertext;
          attachmentIv = attEncrypted.iv;
        }

        const keyEnvelopes = await Promise.all(
          recipients.filter(r => r.id.trim() && r.passphrase.trim()).map(async (recipient) => {
            const { encryptedKey, salt, iv: wrapIv } = await wrapKeyWithPassphrase(
              await crypto.subtle.exportKey('raw', dek),
              recipient.passphrase.trim()
            );
            return {
              recipientId: recipient.id.trim(),
              encryptedKey,
              salt,
              iv: wrapIv
            };
          })
        );

        payload = {
          ciphertext,
          iv,
          expiresInSeconds,
          burnAfterRead,
          keyEnvelopes,
          isMulti: true,
          attachmentCiphertext,
          attachmentIv
        };
        urlFragmentKey = generateFragmentKey();
      } else {
        const encryptedData = await encryptContent(text, file);
        payload = {
          ciphertext: encryptedData.ciphertext,
          iv: encryptedData.iv,
          expiresInSeconds,
          burnAfterRead,
          version: encryptedData.version,
          attachmentCiphertext: encryptedData.attachmentCiphertext,
          attachmentIv: encryptedData.attachmentIv
        };
        if (notBeforeTimestamp !== null) payload.notBefore = notBeforeTimestamp;
        if (notAfterTimestamp !== null) payload.notAfter = notAfterTimestamp;
        urlFragmentKey = encryptedData.key;
      }

      const response = await fetch(`${API_BASE}/pastes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!response.ok) throw new Error(`Server returned ${response.status}`);

      const { id, deleteToken, version } = await response.json();
      const versionQuery = version ? `?v=${version}` : '';
      const url = `${window.location.origin}/#/view/${id}${versionQuery}#${urlFragmentKey}`;

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
      setNotBefore('');
      setNotAfter('');
      setFile(null);
      setFileError('');
      setFileInputKey(k => k + 1);
      if (mode === 'multiple') setRecipients([{ id: '', passphrase: '' }]);
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
      } else if (res.status === 404) {
        setActiveSecret(prev => ({ ...prev, status: 'not_found' }));
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
    } catch (err) {
      console.error('Failed to revoke', err);
    } finally {
      setRevokeLoading(false);
    }
  }

  async function copyLink() {
    if (!activeSecret) return;
    try {
      await navigator.clipboard.writeText(activeSecret.link);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch (err) {
      // Clipboard fallback
    }
  }

  function openRecipientView() {
    if (!activeSecret) return;
    window.open(activeSecret.link, '_blank', 'noopener');
  }

  return (
    <div className="page-shell">
      <header className="page-header"><span className="wordmark">Secured_Gossip</span></header>

      <section className="create-hero">
        <h1>Some things stay between two people.</h1>
        <p className="create-hero-sub">Write your secret below. It&rsquo;s encrypted on your device before anything is sent anywhere.</p>
        <div className="create-hero-rule" />
      </section>

      <div className="create-main">
        <div className="illustration-zone">
          <WaveField className="illustration-wave" />
          <GossipIllustration />
          <div className="illustration-copy">
            <p className="illustration-caption-lead">Gossip is human.</p>
            <p className="illustration-caption">Privacy should be too.</p>
            <p className="illustration-body">Some things are meant to be shared. Some are meant to stay between two people.</p>
          </div>
        </div>

        {!activeSecret ? (
          <div className="form-zone">
            <form onSubmit={handleSubmit}>
              <div className="field field-inline">
                <span className="eyebrow" style={{ marginBottom: 0 }}>Mode</span>
                <select className="field-select" value={mode} onChange={(e) => setMode(e.target.value)}>
                  <option value="single">Single Recipient</option>
                  <option value="multiple">Multiple Recipients</option>
                </select>
              </div>

              <div className="field">
                <span className="eyebrow">Your secret</span>
                <textarea
                  className="field-textarea"
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  placeholder="Type your secret here…"
                />
              </div>

              <div className="field">
                <span className="eyebrow">Attach a file (optional, up to 5MB)</span>
                <input
                  key={fileInputKey}
                  type="file"
                  className="field-file-input"
                  accept={ALLOWED_ATTACHMENT_EXTENSIONS.join(',')}
                  onChange={handleFileChange}
                />
                {file && (
                  <p className="file-selected-info">
                    Selected: <strong>{file.name}</strong> ({Math.round(file.size / 1024)} KB)
                  </p>
                )}
                {fileError && <p className="error-text">{fileError}</p>}
              </div>

              <div className="field field-inline">
                <span className="eyebrow" style={{ marginBottom: 0 }}>Expires</span>
                <select className="field-select" value={expiresInSeconds} onChange={(e) => setExpiresInSeconds(Number(e.target.value))}>
                  <option value={300}>5 minutes</option>
                  <option value={3600}>1 hour</option>
                  <option value={86400}>1 day</option>
                </select>
              </div>

              <div className="field">
                <label className="field-checkbox">
                  Burn after read
                  <input type="checkbox" checked={burnAfterRead} onChange={(e) => setBurnAfterRead(e.target.checked)} />
                </label>
              </div>

              {mode === 'single' && (
                <>
                  <div className="field">
                    <label className="field-checkbox">
                      Require a PIN to unlock
                      <input type="checkbox" checked={enablePin} onChange={(e) => setEnablePin(e.target.checked)} />
                    </label>
                  </div>

                  {enablePin && (
                    <div className="field">
                      <span className="eyebrow">PIN (4–32 characters)</span>
                      <input
                        type="password" className="field-input" value={pin}
                        onChange={(e) => setPin(e.target.value)} minLength={4} maxLength={32}
                      />
                    </div>
                  )}

                  <div className="field">
                    <span className="eyebrow">Access Schedule (Optional)</span>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginTop: '0.5rem' }}>
                      <div>
                        <span style={{ fontSize: '0.85rem', color: 'var(--ink-muted)' }}>Available from:</span>
                        <input
                          type="datetime-local" className="field-input" value={notBefore}
                          onChange={(e) => setNotBefore(e.target.value)}
                        />
                      </div>
                      <div>
                        <span style={{ fontSize: '0.85rem', color: 'var(--ink-muted)' }}>Available until:</span>
                        <input
                          type="datetime-local" className="field-input" value={notAfter}
                          onChange={(e) => setNotAfter(e.target.value)}
                        />
                      </div>
                    </div>
                  </div>
                </>
              )}

              {mode === 'multiple' && (
                <div className="field">
                  <span className="eyebrow">Recipients &amp; Passphrases</span>
                  {recipients.map((recipient, index) => (
                    <div key={index} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: '0.8rem', alignItems: 'center', marginBottom: '0.8rem' }}>
                      <input
                        className="field-input"
                        value={recipient.id}
                        onChange={(e) => {
                          const updated = [...recipients];
                          updated[index] = { ...updated[index], id: e.target.value };
                          setRecipients(updated);
                        }}
                        placeholder="Recipient ID (e.g. Alice)"
                      />
                      <input
                        type="password"
                        className="field-input"
                        value={recipient.passphrase}
                        onChange={(e) => {
                          const updated = [...recipients];
                          updated[index] = { ...updated[index], passphrase: e.target.value };
                          setRecipients(updated);
                        }}
                        placeholder="Passphrase"
                      />
                      {recipients.length > 1 && (
                        <button
                          type="button"
                          className="btn btn-danger-light"
                          style={{ padding: '0.4rem 0.8rem', fontSize: '0.85rem' }}
                          onClick={() => setRecipients(recipients.filter((_, i) => i !== index))}
                        >
                          ✕
                        </button>
                      )}
                    </div>
                  ))}
                  <button
                    type="button"
                    className="btn btn-secondary-light"
                    style={{ padding: '0.5rem 1rem', fontSize: '0.85rem', marginTop: '0.5rem' }}
                    onClick={() => setRecipients([...recipients, { id: '', passphrase: '' }])}
                  >
                    + Add Recipient
                  </button>
                </div>
              )}

              <button type="submit" className="btn btn-primary-light btn-block" disabled={submitting} style={{ marginTop: '1rem' }}>
                {submitting ? 'Encrypting…' : 'Create Secret'}
              </button>
              {error && <p className="error-text">{error}</p>}
            </form>
          </div>
        ) : (
          <div className="status-zone">
            <h3>Secret created</h3>
            <p className="muted-text">This link only works once opened — the key never touches our server.</p>

            <div className="status-link-row">
              <input
                type="text" readOnly value={activeSecret.link}
                className="status-link-input" onFocus={(e) => e.target.select()}
              />
              <button className="btn btn-secondary-light" onClick={copyLink} type="button">
                {copied ? 'Copied' : 'Copy Link'}
              </button>
            </div>

            <div className="status-row">
              <span className={statusClass(activeSecret.status)}>{formatStatus(activeSecret.status)}</span>
            </div>
            {activeSecret.viewedAt && (
              <p className="status-viewed-at">Seen at {new Date(activeSecret.viewedAt).toLocaleString()}</p>
            )}

            <div className="status-actions">
              <button className="btn btn-secondary-light" onClick={checkStatus} disabled={statusLoading} type="button">
                {statusLoading ? 'Checking…' : 'Check Status'}
              </button>
              <button
                className="btn btn-danger-light" onClick={revokeSecret}
                disabled={revokeLoading || activeSecret.status !== 'waiting'} type="button"
              >
                {revokeLoading ? 'Revoking…' : 'Revoke Secret'}
              </button>
              <button className="btn btn-secondary-light" onClick={openRecipientView} type="button">
                Open Recipient View
              </button>
            </div>
            {burnAfterRead && activeSecret.status === 'waiting' && (
              <p className="recipient-view-note">
                This secret is burn-after-read — opening it here will use its one view.
              </p>
            )}

            <div className="status-footer">
              <button className="btn btn-secondary-light" onClick={() => setActiveSecret(null)} type="button">
                Create Another Secret
              </button>
            </div>
          </div>
        )}
      </div>

      <section className="privacy-section">
        <h2>Your secret stays yours.</h2>
        <p>
          Everything is encrypted on your device before it&rsquo;s sent anywhere. Our server only
          ever stores that scrambled version — never your message, never your key.
        </p>
        <PrivacyDiagram />
      </section>

      <section id="how-it-works" className="how-it-works">
        <h2>How Secured_Gossip works</h2>
        <div className="how-it-works-row">
          <div className="how-step">
            <span className="how-step-ghost">01</span>
            <h3>Write</h3>
            <p>Enter your secret, configure recipients, or attach a file.</p>
          </div>
          <div className="how-step">
            <span className="how-step-ghost">02</span>
            <h3>Encrypt</h3>
            <p>Your content is encrypted on your device before it leaves your device.</p>
          </div>
          <div className="how-step">
            <span className="how-step-ghost">03</span>
            <h3>Share</h3>
            <p>Send the link. The recipient unlocks it with their passphrase or PIN.</p>
          </div>
        </div>
      </section>
    </div>
  );
}

export default CreateSecret;
