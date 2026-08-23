/**
 * AES-GCM encryption/decryption utilities using the Web Crypto API.
 * Works in browsers and in Node.js (via globalThis.crypto).
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Convert a base64url string to an ArrayBuffer.
 * Reverses the URL-safe encoding: '-' -> '+', '_' -> '/', padding restored.
 */
function base64UrlToArrayBuffer(base64Url) {
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
function arrayBufferToBase64Url(buffer) {
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
 * Encrypt string content with a fresh random 256-bit AES-GCM key.
 * @param {string} plaintext - content to encrypt
 * @returns {Promise<{ciphertext: string, iv: string, key: string}>}
 *          ciphertext, iv, key are base64-encoded.
 */
export async function encryptContent(plaintext) {
  // Generate a fresh random 256-bit key (32 bytes) as required by the spec.
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.importKey(
    'raw',
    rawKey,
    { name: 'AES-GCM' },
    true,
    ['encrypt', 'decrypt']
  );
  const { ciphertext, iv } = await encrypt(key, plaintext);
  return {
    ciphertext,
    iv,
    key: arrayBufferToBase64Url(rawKey), // base64url-encoded key
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
