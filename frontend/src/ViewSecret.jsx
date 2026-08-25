import { useEffect, useRef, useState } from 'react';
import { decryptContentAndAttachment, decryptContentAndAttachmentWithPin } from './crypto.js';

const API_BASE = 'http://localhost:3001';

/**
 * Parses the current URL hash into a paste id and decryption key.
 * Expected shape: #/view/{id}#{base64url key}
 */
function parseViewHash(hash) {
  const withoutLeadingHash = hash.replace(/^#/, '');
  const secondHashIndex = withoutLeadingHash.indexOf('#');

  if (secondHashIndex === -1) {
    return { id: null, key: null };
  }

  const routePart = withoutLeadingHash.slice(0, secondHashIndex);
  const key = withoutLeadingHash.slice(secondHashIndex + 1);

  const segments = routePart.split('/').filter(Boolean);
  const id = segments[0] === 'view' ? segments[1] : null;

  return { id, key };
}

function ViewSecret() {
  const [status, setStatus] = useState('loading_meta'); // loading_meta | ready | revealing | success | error
  const [metaInfo, setMetaInfo] = useState({ id: null, fragmentKey: null, hasPin: false, hasAttachment: false });
  const [pinInput, setPinInput] = useState('');
  const [plaintext, setPlaintext] = useState('');
  const [attachment, setAttachment] = useState(null); // { filename, url } | null
  const [errorMessage, setErrorMessage] = useState('');
  const hasFetchedRef = useRef(false);

  useEffect(() => {
    if (hasFetchedRef.current) return;
    hasFetchedRef.current = true;

    const { id, key } = parseViewHash(window.location.hash);

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

        const { hasPin, hasAttachment } = await response.json();
        setMetaInfo({ id, fragmentKey: key, hasPin, hasAttachment: Boolean(hasAttachment) });
        setStatus('ready');
      } catch (err) {
        setStatus('error');
        setErrorMessage('This secret has expired or already been viewed.');
      }
    }

    fetchMeta();
  }, []);

  // Revoke the object URL for any previously-created attachment blob when it's
  // replaced or when the component unmounts, so we don't leak memory.
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
      const payload = metaInfo.hasPin ? { pin: pinInput } : {};
      
      const response = await fetch(`${API_BASE}/pastes/${metaInfo.id}/reveal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        
        if (response.status === 401) {
          setStatus('ready');
          setErrorMessage(`Incorrect PIN. ${errData.attemptsRemaining} attempts remaining.`);
          return;
        } else if (response.status === 429) {
          setStatus('error');
          setErrorMessage(errData.error || 'Too many attempts. Secret deleted or rate limited.');
          return;
        } else {
          throw new Error('not found');
        }
      }

      const { ciphertext, iv, contentSalt, attachmentCiphertext, attachmentIv } = await response.json();

      let decrypted;
      if (metaInfo.hasPin) {
        decrypted = await decryptContentAndAttachmentWithPin(
          ciphertext,
          iv,
          metaInfo.fragmentKey,
          pinInput,
          contentSalt,
          attachmentCiphertext,
          attachmentIv
        );
      } else {
        decrypted = await decryptContentAndAttachment(
          ciphertext,
          iv,
          metaInfo.fragmentKey,
          attachmentCiphertext,
          attachmentIv
        );
      }

      setPlaintext(decrypted.plaintext);

      if (decrypted.attachment) {
        const blob = new Blob(
          [decrypted.attachment.buffer],
          { type: decrypted.attachment.mimetype || 'application/octet-stream' }
        );
        const url = URL.createObjectURL(blob);
        setAttachment({ filename: decrypted.attachment.filename, url });
      } else {
        setAttachment(null);
      }

      setStatus('success');
      setPinInput(''); // Clear PIN immediately
    } catch (err) {
      setStatus('error');
      setErrorMessage('Failed to decrypt. The key might be invalid or the data is corrupt.');
    }
  }

  return (
    <main>
      <h1>Secured_Gossip</h1>
      
      {status === 'loading_meta' && <p>Checking secret status...</p>}
      
      {status === 'ready' && (
        <form onSubmit={handleReveal}>
          <p>A secret has been shared with you.</p>
          {metaInfo.hasAttachment && <p>This secret includes a file attachment.</p>}
          {metaInfo.hasPin && (
            <div style={{ margin: '1rem 0' }}>
              <label>
                PIN Required:{' '}
                <input 
                  type="password" 
                  value={pinInput} 
                  onChange={e => setPinInput(e.target.value)} 
                  required 
                />
              </label>
            </div>
          )}
          <button type="submit">Reveal Secret</button>
        </form>
      )}

      {status === 'revealing' && <p>Decrypting...</p>}
      
      {status === 'error' && (
        <p style={{ color: 'red' }}>{errorMessage}</p>
      )}
      
      {errorMessage && status === 'ready' && (
        <p style={{ color: 'red' }}>{errorMessage}</p>
      )}
      
      {status === 'success' && (
        <>
          <pre style={{ whiteSpace: 'pre-wrap', textAlign: 'left', padding: '1rem', border: '1px solid #ccc' }}>
            {plaintext}
          </pre>
          {attachment && (
            <p>
              <a href={attachment.url} download={attachment.filename}>
                Download attachment: {attachment.filename}
              </a>
            </p>
          )}
        </>
      )}
    </main>
  );
}

export default ViewSecret;
