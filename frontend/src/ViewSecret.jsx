import { useEffect, useRef, useState } from 'react';
import { decryptContent, decryptContentWithPin, decrypt, getMasterSecret, hkdf, arrayBufferToBase64Url, base64UrlToArrayBuffer, unwrapKeyWithPassphrase } from './crypto.js';

const API_BASE = 'http://localhost:3001';

/**
 * Parses the current URL into paste id, version, and decryption key.
 * Expected shape: #/view/{id}?v={version}#{base64url key}
 */
function parseViewHash(hash) {
  const withoutLeadingHash = hash.replace(/^#/, '');
  const secondHashIndex = withoutLeadingHash.indexOf('#');

  if (secondHashIndex === -1) {
    return { id: null, key: null, version: null };
  }

  const routePart = withoutLeadingHash.slice(0, secondHashIndex);
  const key = withoutLeadingHash.slice(secondHashIndex + 1);

  // Extract version from query string in routePart
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

function ViewSecret() {
  const [status, setStatus] = useState('loading_meta'); // loading_meta | ready | revealing | success | error
  const [metaInfo, setMetaInfo] = useState({
    id: null,
    fragmentKey: null,
    hasPin: false,
    isMulti: false,
    notBefore: null,
    notAfter: null
  });
  const [pinInput, setPinInput] = useState('');
  const [recipientId, setRecipientId] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [plaintext, setPlaintext] = useState('');
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

        const { hasPin, version, isMulti, notBefore, notAfter } = await response.json();

        // Check time-based constraints
        const now = Date.now();
        if (notBefore !== null && now < notBefore) {
          setStatus('error');
          setErrorMessage(`This secret is not yet available. Available from: ${new Date(notBefore).toLocaleString()}`);
          return;
        }

        if (notAfter !== null && now > notAfter) {
          setStatus('error');
          setErrorMessage(`This secret is no longer available. Available until: ${new Date(notAfter).toLocaleString()}`);
          return;
        }

        setMetaInfo({
          id,
          fragmentKey: key,
          hasPin,
          version: Number(version),
          isMulti: Boolean(isMulti),
          notBefore: notBefore !== null ? notBefore : null,
          notAfter: notAfter !== null ? notAfter : null
        });
        setStatus('ready');
      } catch (err) {
        setStatus('error');
        setErrorMessage('This secret has expired or already been viewed.');
      }
    }

    fetchMeta();
  }, []);

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
        } else if (response.status === 429) {
          setStatus('error');
          setErrorMessage(errData.error || 'Too many attempts. Secret deleted or rate limited.');
          return;
        } else {
          throw new Error('not found');
        }
      }

      let decrypted;
      if (metaInfo.hasPin) {
        // Single recipient with PIN (existing logic)
        const { ciphertext, iv, contentSalt, version } = await response.json();
        decrypted = await decryptContentWithPin(
          ciphertext,
          iv,
          metaInfo.fragmentKey,
          pinInput,
          contentSalt
        );
      } else if (metaInfo.isMulti) {
        // Multi-recipient mode: unwrap DEK then decrypt secret
        const { ciphertext, iv, keyEnvelope } = await response.json();

        // 1. Unwrap the DEK using the recipient's passphrase
        const dekRaw = await unwrapKeyWithPassphrase(
          keyEnvelope.encryptedKey,
          keyEnvelope.salt,
          keyEnvelope.iv,
          passphrase
        );

        // 2. Import the unwrapped DEK
        const dekKey = await crypto.subtle.importKey(
          'raw',
          dekRaw,
          { name: 'AES-GCM' },
          true,
          ['decrypt']
        );

        // 3. Decrypt the secret with the DEK
        decrypted = await decrypt(dekKey, ciphertext, iv);
      } else {
        // Single recipient mode (forward secrecy)
        const { ciphertext, iv, contentSalt, version } = await response.json();
        // Reconstruct the DEK using forward secrecy (master secret + version)
        const masterSecret = await getMasterSecret();
        const salt = `secured-gossip-v${version}`;
        const dek = await hkdf(salt, masterSecret, "paste", 32);
        const key = await crypto.subtle.importKey(
          'raw',
          dek,
          { name: 'AES-GCM' },
          true,
          ['decrypt']
        );
        decrypted = await decrypt(key, ciphertext, iv);
      }

      setPlaintext(decrypted);
      setStatus('success');
      setPinInput(''); // Clear PIN immediately
      setRecipientId(''); // Clear recipient ID
      setPassphrase(''); // Clear passphrase
    } catch (err) {
      console.error('Decryption error:', err);
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
          {metaInfo.isMulti ? (
            <>
              <div style={{ margin: '1rem 0' }}>
                <label>
                  Recipient ID:{' '}
                  <input
                    value={recipientId}
                    onChange={e => setRecipientId(e.target.value)}
                    required
                  />
                </label>
              </div>
              <div style={{ margin: '1rem 0' }}>
                <label>
                  Passphrase:{' '}
                  <input
                    type="password"
                    value={passphrase}
                    onChange={e => setPassphrase(e.target.value)}
                    required
                  />
                </label>
              </div>
            </>
          ) : (
            <>
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
            </>
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
        <pre style={{ whiteSpace: 'pre-wrap', textAlign: 'left', padding: '1rem', border: '1px solid #ccc' }}>
          {plaintext}
        </pre>
      )}
    </main>
  );
}

export default ViewSecret;
