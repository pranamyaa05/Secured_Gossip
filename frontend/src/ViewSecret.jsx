import { useEffect, useRef, useState } from 'react';
import { decryptContent, decryptContentWithPin } from './crypto.js';

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
  const [metaInfo, setMetaInfo] = useState({ id: null, fragmentKey: null, hasPin: false });
  const [pinInput, setPinInput] = useState('');
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

        const { hasPin } = await response.json();
        setMetaInfo({ id, fragmentKey: key, hasPin });
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

      const { ciphertext, iv, contentSalt } = await response.json();
      
      let decrypted;
      if (metaInfo.hasPin) {
        decrypted = await decryptContentWithPin(
          ciphertext, 
          iv, 
          metaInfo.fragmentKey, 
          pinInput, 
          contentSalt
        );
      } else {
        decrypted = await decryptContent(ciphertext, iv, metaInfo.fragmentKey);
      }

      setPlaintext(decrypted);
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
        <pre style={{ whiteSpace: 'pre-wrap', textAlign: 'left', padding: '1rem', border: '1px solid #ccc' }}>
          {plaintext}
        </pre>
      )}
    </main>
  );
}

export default ViewSecret;
