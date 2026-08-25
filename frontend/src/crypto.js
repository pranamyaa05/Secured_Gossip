/**
 * AES-GCM encryption/decryption utilities using Web Crypto API.
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const PBKDF2_ITERATIONS = 300000;
export const MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024; // 5 MB plaintext
export const ALLOWED_ATTACHMENT_EXTENSIONS = [
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.bmp',
  '.pdf',
  '.txt', '.md', '.c', '.cpp', '.h', '.hpp', '.java', '.py',
  '.html', '.htm', '.css', '.js', '.jsx', '.ts', '.tsx',
  '.json', '.xml', '.yml', '.yaml', '.sh', '.csv',
];

export function base64UrlToArrayBuffer(base64Url) {
  let base64 = String(base64Url).replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export function arrayBufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function generateKey() {
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const raw = await crypto.subtle.exportKey('raw', key);
  return { key, raw: arrayBufferToBase64Url(raw) };
}

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

export async function encrypt(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = encoder.encode(plaintext);
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

export async function decrypt(key, base64Ciphertext, base64Iv) {
  const ciphertext = base64UrlToArrayBuffer(base64Ciphertext);
  const iv = base64UrlToArrayBuffer(base64Iv);
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );
  return decoder.decode(decrypted);
}

export async function buildAttachmentPlaintext(file) {
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

export function parseAttachmentPlaintext(jsonString) {
  const { filename, mimetype, data } = JSON.parse(jsonString);
  const buffer = base64UrlToArrayBuffer(data);
  return { filename, mimetype, buffer };
}

export async function encryptContent(plaintext, file = null) {
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.importKey(
    'raw',
    rawKey,
    { name: 'AES-GCM' },
    true,
    ['encrypt', 'decrypt']
  );
  const { ciphertext, iv } = await encrypt(key, plaintext);
  const result = {
    ciphertext,
    iv,
    key: arrayBufferToBase64Url(rawKey),
    version: 1
  };

  if (file) {
    const attachmentPlaintext = await buildAttachmentPlaintext(file);
    const attEnc = await encrypt(key, attachmentPlaintext);
    result.attachmentCiphertext = attEnc.ciphertext;
    result.attachmentIv = attEnc.iv;
  }

  return result;
}

export async function decryptContent(base64Ciphertext, base64Iv, base64Key, attachmentCiphertext = null, attachmentIv = null) {
  const key = await importKey(base64Key);
  const plaintext = await decrypt(key, base64Ciphertext, base64Iv);
  let attachment = null;
  if (attachmentCiphertext && attachmentIv) {
    const attachmentJson = await decrypt(key, attachmentCiphertext, attachmentIv);
    attachment = parseAttachmentPlaintext(attachmentJson);
  }
  return { plaintext, attachment };
}

export function generateFragmentKey() {
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  return arrayBufferToBase64Url(rawKey);
}

export function generateSalt(byteLength = 16) {
  const salt = crypto.getRandomValues(new Uint8Array(byteLength));
  return arrayBufferToBase64Url(salt);
}

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

export async function encryptContentWithPin(plaintext, pin, file = null) {
  const fragmentKey = generateFragmentKey();
  const salt = generateSalt();
  const key = await derivePinContentKey(fragmentKey, pin, salt);
  const { ciphertext, iv } = await encrypt(key, plaintext);
  const result = { ciphertext, iv, fragmentKey, salt };

  if (file) {
    const attachmentPlaintext = await buildAttachmentPlaintext(file);
    const attEnc = await encrypt(key, attachmentPlaintext);
    result.attachmentCiphertext = attEnc.ciphertext;
    result.attachmentIv = attEnc.iv;
  }

  return result;
}

export async function decryptContentWithPin(base64Ciphertext, base64Iv, fragmentKeyB64, pin, saltB64, attachmentCiphertext = null, attachmentIv = null) {
  const key = await derivePinContentKey(fragmentKeyB64, pin, saltB64);
  const plaintext = await decrypt(key, base64Ciphertext, base64Iv);
  let attachment = null;
  if (attachmentCiphertext && attachmentIv) {
    const attachmentJson = await decrypt(key, attachmentCiphertext, attachmentIv);
    attachment = parseAttachmentPlaintext(attachmentJson);
  }
  return { plaintext, attachment };
}

export async function wrapKeyWithPassphrase(keyBytes, passphrase, iterations = PBKDF2_ITERATIONS) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const ikm = encoder.encode(passphrase);

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
  const rawKeyData = keyBytes instanceof ArrayBuffer ? new Uint8Array(keyBytes) : keyBytes;

  const encryptedKey = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    wrappingKey,
    rawKeyData
  );

  return {
    encryptedKey: arrayBufferToBase64Url(encryptedKey),
    salt: arrayBufferToBase64Url(salt),
    iv: arrayBufferToBase64Url(iv)
  };
}

export async function unwrapKeyWithPassphrase(encryptedKeyBase64, saltBase64, ivBase64, passphrase, iterations = PBKDF2_ITERATIONS) {
  const encryptedKey = base64UrlToArrayBuffer(encryptedKeyBase64);
  const salt = base64UrlToArrayBuffer(saltBase64);
  const iv = base64UrlToArrayBuffer(ivBase64);
  const ikm = encoder.encode(passphrase);

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
      salt: new Uint8Array(salt),
      iterations: iterations,
      hash: 'SHA-256'
    },
    encKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  const decryptedKey = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(iv) },
    wrappingKey,
    encryptedKey
  );

  return new Uint8Array(decryptedKey);
}

export async function getMasterSecret() { return new Uint8Array(32); }
export function getKeyVersion() { return 1; }
export async function hkdf(salt, ikm, info, length) { return new Uint8Array(length); }
