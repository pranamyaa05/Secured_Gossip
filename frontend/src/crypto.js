/**
 * AES-GCM encryption/decryption utilities using the Web Crypto API.
 * Works in browsers and in Node.js (via globalThis.crypto).
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// PBKDF2 iteration count used to derive a content key from (fragment key + PIN).
// Must match the server's PIN verifier iteration count in spirit (they are
// independent derivations with independent salts, but both should be slow).
export const PBKDF2_ITERATIONS = 300000;

// Attachment constraints (client-side convenience checks only — the server
// enforces its own independent size cap; neither side inspects file contents).
export const MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024; // 5 MB plaintext
export const ALLOWED_ATTACHMENT_EXTENSIONS = [
  // images
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.bmp',
  // documents
  '.pdf',
  // text / code
  '.txt', '.md', '.c', '.cpp', '.h', '.hpp', '.java', '.py',
  '.html', '.htm', '.css', '.js', '.jsx', '.ts', '.tsx',
  '.json', '.xml', '.yml', '.yaml', '.sh', '.csv',
];

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
 * Generates a FRESH random IV on every call — safe to call multiple times
 * with the same key (e.g. once for text, once for an attachment) because
 * each call gets its own independent 96-bit random IV.
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
 * (Unchanged, non-PIN flow: the key lives only in the URL fragment.)
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

// ---------------------------------------------------------------------------
// Attachments (encrypted-metadata approach).
//
// The attachment's filename + MIME type are bundled INSIDE the encrypted
// payload (as JSON, alongside the base64url-encoded file bytes), so the
// server never sees the filename or MIME type in plaintext either.
//
// The attachment reuses the SAME content key as the text (whichever key was
// used — random fragment key alone, or the PIN-derived key), but gets its
// OWN independent call to encrypt(), which means its own fresh random IV.
// Reusing a key is safe in AES-GCM as long as the IV is never reused with
// that key; encrypt() guarantees a fresh IV on every call.
// ---------------------------------------------------------------------------

/**
 * Read a File/Blob into a JSON string ready for encryption:
 * { filename, mimetype, data: base64url(file bytes) }
 */
async function buildAttachmentPlaintext(file) {
  if (file.size > MAX_ATTACHMENT_BYTES) {
    throw new Error(`Attachment exceeds ${MAX_ATTACHMENT_BYTES / (1024 * 1024)}MB limit`);
  }
  const buffer = await file.arrayBuffer();
  const dataB64 = arrayBufferToBase64Url(buffer);
  return JSON.stringify({
    filename: file.name,
    mimetype: file.type || 'application/octet-stream',
    data: dataB64,
  });
}

/**
 * Reverse buildAttachmentPlaintext(): decrypted JSON string -> usable parts.
 * @returns {{filename: string, mimetype: string, buffer: ArrayBuffer}}
 */
function parseAttachmentPlaintext(jsonString) {
  const { filename, mimetype, data } = JSON.parse(jsonString);
  const buffer = base64UrlToArrayBuffer(data);
  return { filename, mimetype, buffer };
}

/**
 * Non-PIN flow: encrypt text and (optionally) an attachment with one fresh
 * random 256-bit key. If `file` is null/undefined, behaves identically to
 * encryptContent() — no attachment fields are included in the result.
 * @param {string} plaintext
 * @param {File|null} file
 */
export async function encryptContentAndAttachment(plaintext, file) {
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.importKey(
    'raw', rawKey, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']
  );
  const { ciphertext, iv } = await encrypt(key, plaintext);
  const result = { ciphertext, iv, key: arrayBufferToBase64Url(rawKey) };

  if (file) {
    const attachmentPlaintext = await buildAttachmentPlaintext(file);
    const { ciphertext: attachmentCiphertext, iv: attachmentIv } = await encrypt(key, attachmentPlaintext);
    result.attachmentCiphertext = attachmentCiphertext;
    result.attachmentIv = attachmentIv;
  }

  return result;
}

/**
 * PIN flow: encrypt text and (optionally) an attachment with the same
 * PIN-derived key. If `file` is null/undefined, behaves identically to
 * encryptContentWithPin() — no attachment fields are included in the result.
 * @param {string} plaintext
 * @param {string} pin
 * @param {File|null} file
 */
export async function encryptContentAndAttachmentWithPin(plaintext, pin, file) {
  const fragmentKey = generateFragmentKey();
  const salt = generateSalt();
  const key = await derivePinContentKey(fragmentKey, pin, salt);
  const { ciphertext, iv } = await encrypt(key, plaintext);
  const result = { ciphertext, iv, fragmentKey, salt };

  if (file) {
    const attachmentPlaintext = await buildAttachmentPlaintext(file);
    const { ciphertext: attachmentCiphertext, iv: attachmentIv } = await encrypt(key, attachmentPlaintext);
    result.attachmentCiphertext = attachmentCiphertext;
    result.attachmentIv = attachmentIv;
  }

  return result;
}

/**
 * Non-PIN flow: decrypt text and (optionally) an attachment.
 * Pass attachmentCiphertext/attachmentIv as undefined when there is none —
 * result.attachment will be null.
 */
export async function decryptContentAndAttachment(
  base64Ciphertext, base64Iv, base64Key, attachmentCiphertext, attachmentIv
) {
  const key = await importKey(base64Key);
  const plaintext = await decrypt(key, base64Ciphertext, base64Iv);

  let attachment = null;
  if (attachmentCiphertext && attachmentIv) {
    const attachmentJson = await decrypt(key, attachmentCiphertext, attachmentIv);
    attachment = parseAttachmentPlaintext(attachmentJson);
  }

  return { plaintext, attachment };
}

/**
 * PIN flow: decrypt text and (optionally) an attachment using the same
 * PIN-derived key (derived once, reused for both).
 */
export async function decryptContentAndAttachmentWithPin(
  base64Ciphertext, base64Iv, fragmentKeyB64, pin, saltB64, attachmentCiphertext, attachmentIv
) {
  const key = await derivePinContentKey(fragmentKeyB64, pin, saltB64);
  const plaintext = await decrypt(key, base64Ciphertext, base64Iv);

  let attachment = null;
  if (attachmentCiphertext && attachmentIv) {
    const attachmentJson = await decrypt(key, attachmentCiphertext, attachmentIv);
    attachment = parseAttachmentPlaintext(attachmentJson);
  }

  return { plaintext, attachment };
}
