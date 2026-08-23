/**
 * TEMPORARY scratch test — Step 3: core encryption pipeline round-trip verify.
 * NOT wired into the app. Run with:   node frontend/scratch-crypto-test.js
 */
import { encryptContent, decryptContent } from './src/crypto.js';

function assert(condition, message) {
  if (!condition) {
    throw new Error(`ASSERTION FAILED: ${message}`);
  }
}

// 1. Generate test content
const plaintext =
  'Hello, Secured_Gossip! 🔐\nThis is the secret gossip message to encrypt.\n' +
  'It includes unicode (ñ, é, 漢字, 😀), newlines, and symbols: !@#$%^&*()_+-=[]{}|;:,.<>?/';

console.log('--- plaintext ---');
console.log(plaintext);

// 2. Encrypt it
const { ciphertext, iv, key } = await encryptContent(plaintext);

console.log('--- encrypted (base64url) ---');
console.log('ciphertext (base64url, ' + ciphertext.length + ' chars):', ciphertext);
console.log('iv (base64url, ' + iv.length + ' chars):', iv);
console.log('key (base64url, ' + key.length + ' chars): ******** (length-verified, value withheld)');

// Verify URL-safe base64: no '+', '/', or '=' padding
assert(!/[+/=]/.test(ciphertext), 'ciphertext must be URL-safe base64url (no +, /, =)');
assert(!/[+/=]/.test(iv), 'iv must be URL-safe base64url (no +, /, =)');
assert(!/[+/=]/.test(key), 'key must be URL-safe base64url (no +, /, =)');

// Decode base64url -> raw 32 bytes (AES-256) ; reverse URL-safe mapping + restore padding
const decUrlKey = key.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
const paddedKey = decUrlKey + '='.repeat((4 - (decUrlKey.length % 4)) % 4);
const keyBytes = atob(paddedKey);
assert(keyBytes.length === 32, `key must be 256 bits (32 raw bytes), got ${keyBytes.length}`);

// 3. Decrypt it
const decrypted = await decryptContent(ciphertext, iv, key);

// 4. Assert exact round-trip
console.log('--- decrypted ---');
console.log(decrypted);

assert(decrypted === plaintext, 'round-trip mismatch: decrypted !== plaintext');
assert(decrypted.length === plaintext.length, 'round-trip length mismatch');

console.log('\n✓ TEST PASSED: encryptContent -> decryptContent round-trip matches exactly.');
console.log('✓ Key is 32 raw bytes = AES-256.');