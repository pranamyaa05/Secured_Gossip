import { useEffect, useRef, useState } from 'react';
import {
  decryptContent,
  decryptContentWithPin,
  decrypt,
  unwrapKeyWithPassphrase,
  parseAttachmentPlaintext
} from './crypto.js';

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';

function parseViewHash(rawHash) {
  const hash = rawHash.replace(/^#/, '');
  const secondHashIndex = hash.indexOf('#');

  if (secondHashIndex === -1) {
    return { id: null, key: null, version: null };
  }

  const routePart = hash.slice(0, secondHashIndex);
  const key = hash.slice(secondHashIndex + 1);

  const queryIndex = routePart.indexOf('?');
  let version = null;
  let pathPart = routePart;
  if (queryIndex !== -1) {
    pathPart = routePart.slice(0, queryIndex);
    const queryStr = routePart.slice(queryIndex + 1);
    const params = new URLSearchParams(queryStr);
    version = params.get('v');
  }

  const segments = pathPart.split('/').filter(Boolean);
  const id = segments[0] === 'view' ? segments[1] : null;

  return { id, key, version };
}

function WaveField({ className }) {
  return (
    <svg viewBox="0 0 1440 300" preserveAspectRatio="none" className={className} aria-hidden="true">
      <path d="M0,180 C240,120 480,220 720,170 C960,120 1200,200 1440,150 L1440,300 L0,300 Z" fill="var(--sky)" opacity="0.16" />
      <path d="M0,210 C240,260 480,180 720,220 C960,260 1200,190 1440,230 L1440,300 L0,300 Z" fill="var(--lavender)" opacity="0.16" />
      <path d="M0,240 C240,200 480,270 720,230 C960,190 1200,260 1440,220 L1440,300 L0,300 Z" fill="var(--mint)" opacity="0.15" />
    </svg>
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

function ViewSecret() {
  const [status, setStatus] = useState('loading_meta');
  const [metaInfo, setMetaInfo] = useState({
    id: null,
    fragmentKey: null,
    hasPin: false,
    hasAttachment: false,
    version: null,
    isMulti: false,
    notBefore: null,
    notAfter: null
  });
  const [pinInput, setPinInput] = useState('');
  const [recipientId, setRecipientId] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [plaintext, setPlaintext] = useState('');
  const [attachment, setAttachment] = useState(null);
  const [errorMessage, setErrorMessage] = useState('');
  const hasFetchedRef = useRef(false);

  useEffect(() => {
    if (hasFetchedRef.current) return;
    hasFetchedRef.current = true;

    const { id, key, version: parsedVersion } = parseViewHash(window.location.hash);

    if (!id || !key) {
      setStatus('error');
      setErrorMessage('Invalid link format.');
      return;
    }

    async function fetchMeta() {
      try {
        const response = await fetch(`${API_BASE}/pastes/${id}/meta`);

        if (!response.ok) {
          throw new Error('not found');
        }

        const { hasPin, hasAttachment, version, isMulti, notBefore, notAfter } = await response.json();

        const now = Date.now();
        if (notBefore !== null && notBefore !== undefined && now < notBefore) {
          setStatus('error');
          setErrorMessage(`This secret is not yet available. Available from: ${new Date(notBefore).toLocaleString()}`);
          return;
        }

        if (notAfter !== null && notAfter !== undefined && now > notAfter) {
          setStatus('error');
          setErrorMessage(`This secret is no longer available. Expired at: ${new Date(notAfter).toLocaleString()}`);
          return;
        }

        setMetaInfo({
          id,
          fragmentKey: key,
          hasPin,
          hasAttachment: Boolean(hasAttachment),
          version: version ?? parsedVersion,
          isMulti: Boolean(isMulti),
          notBefore: notBefore ?? null,
          notAfter: notAfter ?? null
        });
        setStatus('ready');
      } catch (err) {
        setStatus('error');
        setErrorMessage('This secret has expired or already been viewed.');
      }
    }

    fetchMeta();
  }, []);

  useEffect(() => {
    return () => {
      if (attachment?.url) URL.revokeObjectURL(attachment.url);
    };
  }, [attachment]);

  async function handleReveal(e) {
    if (e) e.preventDefault();
    setErrorMessage('');
    setStatus('revealing');

    try {
      const payload = metaInfo.hasPin ? { pin: pinInput } :
                    metaInfo.isMulti ? { recipientId, passphrase } : {};

      const response = await fetch(`${API_BASE}/pastes/${metaInfo.id}/reveal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));

        if (response.status === 401) {
          setStatus('ready');
          if (metaInfo.isMulti) {
            setErrorMessage('Invalid recipient ID or passphrase.');
          } else {
            setErrorMessage(`Incorrect PIN. ${errData.attemptsRemaining} attempts remaining.`);
          }
          return;
        } else if (response.status === 403) {
          setStatus('error');
          setErrorMessage(errData.error || 'Access schedule violation: secret is locked.');
          return;
        } else if (response.status === 429) {
          setStatus('error');
          setErrorMessage(errData.error || 'Too many attempts. Secret deleted or rate limited.');
          return;
        } else {
          throw new Error('not found');
        }
      }

      const resData = await response.json();
      let decryptedResult = { plaintext: '', attachment: null };

      if (metaInfo.hasPin) {
        decryptedResult = await decryptContentWithPin(
          resData.ciphertext,
          resData.iv,
          metaInfo.fragmentKey,
          pinInput,
          resData.contentSalt,
          resData.attachmentCiphertext,
          resData.attachmentIv
        );
      } else if (metaInfo.isMulti) {
        const dekRaw = await unwrapKeyWithPassphrase(
          resData.keyEnvelope.encryptedKey,
          resData.keyEnvelope.salt,
          resData.keyEnvelope.iv,
          passphrase
        );

        const dekKey = await crypto.subtle.importKey(
          'raw',
          dekRaw,
          { name: 'AES-GCM' },
          true,
          ['decrypt']
        );

        const text = await decrypt(dekKey, resData.ciphertext, resData.iv);
        let parsedAtt = null;
        if (resData.attachmentCiphertext && resData.attachmentIv) {
          const attJson = await decrypt(dekKey, resData.attachmentCiphertext, resData.attachmentIv);
          parsedAtt = parseAttachmentPlaintext(attJson);
        }
        decryptedResult = { plaintext: text, attachment: parsedAtt };
      } else {
        decryptedResult = await decryptContent(
          resData.ciphertext,
          resData.iv,
          metaInfo.fragmentKey,
          resData.attachmentCiphertext,
          resData.attachmentIv
        );
      }

      setPlaintext(decryptedResult.plaintext);

      if (decryptedResult.attachment) {
        const blob = new Blob([decryptedResult.attachment.buffer], {
          type: decryptedResult.attachment.mimetype || 'application/octet-stream'
        });
        const url = URL.createObjectURL(blob);
        setAttachment({ filename: decryptedResult.attachment.filename, url });
      } else {
        setAttachment(null);
      }

      setStatus('success');
      setPinInput('');
      setRecipientId('');
      setPassphrase('');
    } catch (err) {
      console.error('Decryption error:', err);
      setStatus('error');
      setErrorMessage('Failed to decrypt. The key might be invalid or the data is corrupt.');
    }
  }

  return (
    <div className="page-shell page-shell-view">
      <header className="page-header"><span className="wordmark">Secured_Gossip</span></header>

      <main className="view-center">
        <WaveField className="view-wave" />
        <div className="panel view-card">
          {status === 'loading_meta' && <p className="muted-text">Checking secret status…</p>}

          {status === 'ready' && (
            <form onSubmit={handleReveal} className="reveal-form">
              <SealMark />
              <p className="view-lead">Someone trusted you with a secret.</p>
              <p className="view-sub">This message is encrypted and waiting for you.</p>
              {metaInfo.hasAttachment && (
                <p className="view-note">📁 This secret includes an encrypted file attachment.</p>
              )}

              {metaInfo.isMulti ? (
                <>
                  <div className="field">
                    <span className="eyebrow">Recipient ID</span>
                    <input
                      className="field-input"
                      value={recipientId}
                      onChange={e => setRecipientId(e.target.value)}
                      placeholder="e.g. Alice"
                      required
                    />
                  </div>
                  <div className="field">
                    <span className="eyebrow">Passphrase</span>
                    <input
                      type="password"
                      className="field-input"
                      value={passphrase}
                      onChange={e => setPassphrase(e.target.value)}
                      placeholder="Enter passphrase"
                      required
                    />
                  </div>
                </>
              ) : (
                <>
                  {metaInfo.hasPin && (
                    <div className="field">
                      <span className="eyebrow">PIN required</span>
                      <input
                        type="password"
                        className="field-input"
                        value={pinInput}
                        onChange={e => setPinInput(e.target.value)}
                        placeholder="Enter PIN"
                        required
                      />
                    </div>
                  )}
                </>
              )}

              <button type="submit" className="btn btn-primary-light" style={{ marginTop: '1rem' }}>
                Reveal Secret
              </button>
              {errorMessage && <p className="error-text">{errorMessage}</p>}
            </form>
          )}

          {status === 'revealing' && <p className="muted-text">Decrypting…</p>}
          {status === 'error' && <p className="error-text">{errorMessage}</p>}

          {status === 'success' && (
            <div className="reveal-success">
              <p className="view-lead">Secret unlocked</p>
              {plaintext && <pre className="secret-text">{plaintext}</pre>}
              {attachment && (
                <div className="attachment-card" style={{ marginTop: '1rem' }}>
                  <span className="attachment-name">{attachment.filename}</span>
                  <a href={attachment.url} download={attachment.filename} className="btn btn-secondary-light">
                    Download File
                  </a>
                </div>
              )}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

export default ViewSecret;
