import { useEffect, useRef, useState } from 'react';
import { decryptContent } from './crypto.js';

const API_BASE = 'http://localhost:3001';

/**
 * Parses the current URL hash into a paste id and decryption key.
 * Expected shape: #/view/{id}#{base64url key}
 * window.location.hash only reflects everything after the FIRST '#',
 * so the id/key split on the second '#' has to be done manually.
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
  // segments: ['view', '{id}']
  const id = segments[0] === 'view' ? segments[1] : null;

  return { id, key };
}

function ViewSecret() {
  const [status, setStatus] = useState('loading'); // loading | success | error
  const [plaintext, setPlaintext] = useState('');
  const hasFetchedRef = useRef(false);

  useEffect(() => {
    if (hasFetchedRef.current) return;
    hasFetchedRef.current = true;

    const { id, key } = parseViewHash(window.location.hash);

    if (!id || !key) {
      setStatus('error');
      return;
    }

    async function fetchAndDecrypt() {
      try {
        const response = await fetch(`${API_BASE}/pastes/${id}`);

        if (!response.ok) {
          throw new Error(`Server returned ${response.status}`);
        }

        const { ciphertext, iv } = await response.json();
        const decrypted = await decryptContent(ciphertext, iv, key);

        setPlaintext(decrypted);
        setStatus('success');
      } catch (err) {
        setStatus('error');
      }
    }

    fetchAndDecrypt();

    // No cleanup/cancellation needed: hasFetchedRef already guarantees this only
    // runs once per real mount, which is all that matters for a one-shot view page.
  }, []);

  return (
    <main>
      <h1>Secured_Gossip</h1>
      {status === 'loading' && <p>Decrypting...</p>}
      {status === 'error' && <p>This secret has expired or already been viewed</p>}
      {status === 'success' && (
        <pre style={{ whiteSpace: 'pre-wrap', textAlign: 'left' }}>{plaintext}</pre>
      )}
    </main>
  );
}

export default ViewSecret;
