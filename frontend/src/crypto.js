/**
 * AES-GCM encryption/decryption utilities using the Web Crypto API.
 * Works in browsers and in Node.js (via globalThis.crypto).
 * Includes forward secrecy via hierarchical keys (master secret -> per-paste DEK).
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// PBKDF2 iteration count used to derive a content key from (fragment key + PIN).
// Must match the server's PIN verifier iteration count in spirit (they are
// independent derivations with independent salts, but both should be slow).
export const PBKDF2_ITERATIONS = 300000;

// Forward secrecy: master secret and key versioning
const MASTER_SECRET_KEY = 'secured-gossip-master-secret';

/**
 * Get or create the master secret stored in localStorage.
 * The master secret is rotated periodically to provide forward secrecy.
 * @returns {Promise<Uint8Array>} The master secret as raw bytes
 */
export async function getMasterSecret() {
  let masterSecretB64 = localStorage.getItem(MASTER_SECRET_KEY);
  if (!masterSecretB64) {
    // Generate a new master secret (256 bits = 32 bytes)
    const masterSecret = crypto.getRandomValues(new Uint8Array(32));
    masterSecretB64 = arrayBufferToBase64Url(masterSecret);
    localStorage.setItem(MASTER_SECRET_KEY, masterSecretB64);
  }
  return base64UrlToArrayBuffer(masterSecretB64);
}

/**
 * Set a new master secret (for rotation).
 * @param {Uint8Array} newSecret - The new master secret as raw bytes
 */
export function setMasterSecret(newSecret) {
  const masterSecretB64 = arrayBufferToBase64Url(newSecret);
  localStorage.setItem(MASTER_SECRET_KEY, masterSecretB64);
}

/**
 * Get the current key version based on time.
 * For daily rotation: floor(Date.now() / (24 * 60 * 60 * 1000))
 * @returns {number} The current key version
 */
export function getKeyVersion() {
  return Math.floor(Date.now() / (24 * 60 * 60 * 1000)); // Daily rotation
}

/**
 * HKDF-SHA256 implementation using Web Crypto API.
 * Follows RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function.
 * @param {string|Uint8Array} salt - Salt value (optional)
 * @param {string|Uint8Array} ikm - Input key material
 * @param {string|Uint8Array} info - Context/application-specific info (optional)
 * @param {number} length - Length of output key material in bytes
 * @returns {Promise<Uint8Array>} Derived key material
 */
export async function hkdf(salt, ikm, info, length) {
  // Convert inputs to Uint8Array if they're strings
  const saltBytes = typeof salt === 'string'
    ? encoder.encode(salt)
    : salt;
  const ikmBytes = typeof ikm === 'string'
    ? encoder.encode(ikm)
    : ikm;
  const infoBytes = typeof info === 'string'
    ? encoder.encode(info)
    : info;

  // Step 1: Extract
  const extractKey = await crypto.subtle.importKey(
    'raw',
    saltBytes || new Uint8Array(0), // Use empty salt if not provided
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const extractResult = await crypto.subtle.sign(
    'HMAC',
    extractKey,
    ikmBytes
  );
  const prk = new Uint8Array(extractResult); // Pseudo-random key

  // Step 2: Expand
  const expandKey = await crypto.subtle.importKey(
    'raw',
    prk,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  // Create T = info || 0x01
  const TBuffer = new Uint8Array(infoBytes.length + 1);
  TBuffer.set(infoBytes);
  TBuffer[TBuffer.length - 1] = 0x01;

  const expandResult = await crypto.subtle.sign(
    'HMAC',
    expandKey,
    TBuffer
  );
  const okm = new Uint8Array(expandResult); // Output key material

  return okm.subarray(0, length);
}

const cryptoInstance = globalThis.crypto;
export { cryptoInstance as crypto };

// Envelope encryption for multi-recipient using passphrase-derived keys
/**
 * Encrypt a key (CEK) with a passphrase using PBKDF2 and AES-GCM.
 * @param {Uint8Array} key - The key to encrypt (CEK)
 * @param {string} passphrase - The recipient's passphrase
 * @param {number} iterations - PBKDF2 iteration count
 * @returns {Promise<{encryptedKey: string, salt: string, iv: string}>}
 *          encryptedKey, salt, iv are base64url-encoded
 */
export async function wrapKeyWithPassphrase(key, passphrase, iterations = PBKDF2_ITERATIONS) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const ikm = encoder.encode(passphrase);

  // Derive encryption key from passphrase
  const encKey = await crypto.subtle.importKey(
    'raw',
    ikm,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  const wrappingKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: iterations,
      hash: 'SHA-256'
    },
    encKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedKey = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    wrappingKey,
    key
  );

  return {
    encryptedKey: arrayBufferToBase64Url(encryptedKey),
    salt: arrayBufferToBase64Url(salt),
    iv: arrayBufferToBase64Url(iv)
  };
}

/**
 * Decrypt a key (CEK) that was encrypted with wrapKeyWithPassphrase.
 * @param {string} encryptedKeyBase64 - base64url encrypted key
 * @param {string} saltBase64 - base64url salt
 * @param {string} ivBase64 - base64url iv
 * @param {string} passphrase - The recipient's passphrase
 * @param {number} iterations - PBKDF2 iteration count
 * @returns {Promise<Uint8Array>} The decrypted key
 */
export async function unwrapKeyWithPassphrase(encryptedKeyBase64, saltBase64, ivBase64, passphrase, iterations = PBKDF2_ITERATIONS) {
  const encryptedKey = base64UrlToArrayBuffer(encryptedKeyBase64);
  const salt = base64UrlToArrayBuffer(saltBase64);
  const iv = base64UrlToArrayBuffer(ivBase64);

  const ikm = encoder.encode(passphrase);

  // Derive encryption key from passphrase
  const encKey = await crypto.subtle.importKey(
    'raw',
    ikm,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  const wrappingKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: iterations,
      hash: 'SHA-256'
    },
    encKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['decrypt']
  );

  const decryptedKey = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    wrappingKey,
    encryptedKey
  );

  return new Uint8Array(decryptedKey);
}

/**
 * Convert a base64url string to an ArrayBuffer.
 * Reverses the URL-safe encoding: '-' -> '+', '_' -> '/', padding restored.
 */
export function base64UrlToArrayBuffer(base64Url) {
  let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  // Restore '=' padding to a multiple of 4.
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Convert an ArrayBuffer to a base64url string.
 * URL-safe: '+ ' -> '-', '/' -> '_', '=' padding stripped.
 */
export function arrayBufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Generate a fresh 256-bit AES key (crypto.subtle), exported as raw base64.
 * @returns {Promise<{key: CryptoKey, raw: string}>}
 */
export async function generateKey() {
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const raw = await crypto.subtle.exportKey('raw', key);
  return { key, raw: arrayBufferToBase64Url(raw) };
}

/**
 * Import a raw base64-encoded 256-bit key.
 * @param {string} base64Key - base64 raw key bytes
 * @returns {Promise<CryptoKey>}
 */
export async function importKey(base64Key) {
  const raw = base64UrlToArrayBuffer(base64Key);
  return crypto.subtle.importKey(
    'raw',
    raw,
    { name: 'AES-GCM' },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt a plaintext string with the given CryptoKey.
 * Returns { ciphertext: base64, iv: base64 }.
 */
export async function encrypt(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoded
  );
  return {
    ciphertext: arrayBufferToBase64Url(ciphertext),
    iv: arrayBufferToBase64Url(iv),
  };
}

/**
 * Decrypt base64 ciphertext + base64 iv back to the original plaintext.
 * Returns the decrypted string.
 */
export async function decrypt(key, base64Ciphertext, base64Iv) {
  const { subtle } = crypto;
  const ciphertext = base64UrlToArrayBuffer(base64Ciphertext);
  const iv = base64UrlToArrayBuffer(base64Iv);
  const decrypted = await subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );
  return new TextDecoder().decode(decrypted);
}

/**
 * Encrypt string content using forward secrecy via hierarchical keys.
 * Derives a per-paste DEK from master secret + version using HKDF.
 * The DEK is NOT returned; it must be re-derived using the same master secret and version.
 * @param {string} plaintext - content to encrypt
 * @returns {Promise<{ciphertext: string, iv: string, version: number}>}
 *          ciphertext, iv are base64-encoded; version is the key version used.
 */
export async function encryptContent(plaintext) {
  // Get master secret and current version for forward secrecy
  const masterSecret = await getMasterSecret();
  const version = getKeyVersion();

  // Derive per-paste DEK using HKDF: salt = "secured-gossip-v" + version,
  // IKM = master secret, info = "paste", length = 32 bytes
  const salt = `secured-gossip-v${version}`;
  const dek = await hkdf(salt, masterSecret, "paste", 32);

  // Import the derived key for encryption
  const key = await crypto.subtle.importKey(
    'raw',
    dek,
    { name: 'AES-GCM' },
    true,
    ['encrypt', 'decrypt']
  );

  const { ciphertext, iv } = await encrypt(key, plaintext);
  return {
    ciphertext,
    iv,
    version // Return version so client knows which master secret to use
  };
}

/**
 * Decrypt content that was encrypted with encryptContent().
 * @param {string} base64Ciphertext - base64 ciphertext
 * @param {string} base64Iv - base64 IV
 * @param {string} base64Key - base64-encoded raw key
 * @returns {Promise<string>} the original plaintext
 */
export async function decryptContent(base64Ciphertext, base64Iv, base64Key) {
  const key = await importKey(base64Key);
  return decrypt(key, base64Ciphertext, base64Iv);
}

// ---------------------------------------------------------------------------
// PIN-protected content key derivation (Layer 1 of the PIN design).
//
// The content key is derived from BOTH the random URL-fragment key AND the
// user's PIN via PBKDF2-HMAC-SHA-256 with a high iteration count. This means:
//   - Someone with only the link (no PIN) cannot decrypt.
//   - Someone with only the PIN (no link/fragment key) cannot decrypt.
//   - Brute-forcing the PIN offline is slowed down by the iteration count.
// The fragment key and PIN never leave the browser for this derivation; only
// the (non-secret) salt is sent to the server so the recipient can repeat the
// derivation.
// ---------------------------------------------------------------------------

/**
 * Generate a fresh random fragment key (same shape as encryptContent's key),
 * exposed separately so PIN mode can put it in the URL fragment *before*
 * it's combined with the PIN for key derivation.
 */
export function generateFragmentKey() {
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  return arrayBufferToBase64Url(rawKey);
}

/**
 * Generate a fresh random salt for PBKDF2, base64url-encoded.
 */
export function generateSalt(byteLength = 16) {
  const salt = crypto.getRandomValues(new Uint8Array(byteLength));
  return arrayBufferToBase64Url(salt);
}

/**
 * Derive an AES-256-GCM CryptoKey from (fragment key + PIN) via PBKDF2.
 * NOT HKDF - HKDF is an extraction/expansion function and provides no
 * work-factor against low-entropy PIN guessing. PBKDF2's iteration count is
 * what makes offline PIN brute-forcing expensive.
 *
 * @param {string} fragmentKeyB64 - the random key that lives in the URL fragment
 * @param {string} pin - the user-supplied PIN
 * @param {string} saltB64 - base64url salt (stored alongside the ciphertext)
 * @param {number} iterations
 * @returns {Promise<CryptoKey>}
 */
export async function derivePinContentKey(
  fragmentKeyB64,
  pin,
  saltB64,
  iterations = PBKDF2_ITERATIONS
) {
  const keyMaterialBytes = encoder.encode(`${fragmentKeyB64}:${pin}`);
  const baseKey = await crypto.subtle.importKey(
    'raw',
    keyMaterialBytes,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  const saltBytes = base64UrlToArrayBuffer(saltB64);
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt content for the PIN-protected flow.
 * @param {string} plaintext
 * @param {string} pin
 * @returns {Promise<{ciphertext: string, iv: string, fragmentKey: string, salt: string}>}
 */
export async function encryptContentWithPin(plaintext, pin) {
  const fragmentKey = generateFragmentKey();
  const salt = generateSalt();
  const key = await derivePinContentKey(fragmentKey, pin, salt);
  const { ciphertext, iv } = await encrypt(key, plaintext);
  return { ciphertext, iv, fragmentKey, salt };
}

/**
 * Decrypt content that was encrypted with encryptContentWithPin().
 * @param {string} base64Ciphertext
 * @param {string} base64Iv
 * @param {string} fragmentKeyB64
 * @param {string} pin
 * @param {string} saltB64
 * @returns {Promise<string>}
 */
export async function decryptContentWithPin(base64Ciphertext, base64Iv, fragmentKeyB64, pin, saltB64) {
  const key = await derivePinContentKey(fragmentKeyB64, pin, saltB64);
  return decrypt(key, base64Ciphertext, base64Iv);
}
