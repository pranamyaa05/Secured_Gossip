// Set up the environment to mimic the browser for the frontend's crypto.js
global.TextEncoder = require('util').TextEncoder;
global.TextDecoder = require('util').TextDecoder;
const { webcrypto } = require('crypto');
global.crypto = webcrypto;

// Mock localStorage (not used in the multi-recipient flow, but safe to mock)
global.localStorage = {
  getItem: () => null,
  setItem: (key, value) => {},
  removeItem: () => {},
  clear: () => {}
};

// Import the frontend's crypto.js functions we need
import { generateKey, importKey, encrypt, wrapKeyWithPassphrase, unwrapKeyWithPassphrase } from './frontend/src/crypto.js';

const fetch = require('node-fetch');

const API_BASE = 'http://localhost:3001';

// Helper to base64url encode (already handled by the frontend's functions, but we need it for the test)
function base64UrlEncode(buffer) {
  return Buffer.from(buffer).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

// Helper to base64url decode
function base64UrlDecode(string) {
  let base64 = string.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) base64 += '=';
  return Buffer.from(base64, 'base64');
}

// Main test function
async function testMultiRecipient() {
  console.log('Starting multi-recipient test using frontend\'s crypto.js...');

  // Step 1: Create a multi-recipient secret via the backend API (simulating frontend)
  const text = 'This is a secret message for multiple recipients.';
  const expiresInSeconds = 3600;
  const burnAfterRead = false;

  // Generate a random DEK using the frontend's generateKey
  const { key: dek, raw: dekRaw } = await generateKey();
  console.log('Generated DEK (raw):', dekRaw);

  // Encrypt the secret with the DEK using the frontend's encrypt
  const { ciphertext, iv } = await encrypt(dek, text);
  console.log('Encrypted secret with DEK:');
  console.log('  ciphertext:', ciphertext);
  console.log('  iv:', iv);

  // Define two recipients
  const recipients = [
    { id: 'alice@example.com', passphrase: 'alice123' },
    { id: 'bob@example.com', passphrase: 'bob456' }
  ];

  // For each recipient, encrypt the DEK with their passphrase using the frontend's wrapKeyWithPassphrase
  const keyEnvelopes = await Promise.all(
    recipients.map(async (recipient) => {
      const { encryptedKey, salt, iv } = await wrapKeyWithPassphrase(
        dekRaw, // Note: we pass the raw DEK as a base64url string
        recipient.passphrase
      );
      console.log(`Created envelope for ${recipient.id}:`);
      console.log(`  encryptedKey: ${encryptedKey}`);
      console.log(`  salt: ${salt}`);
      console.log(`  iv: ${iv}`);
      return {
        recipientId: recipient.id,
        encryptedKey,
        salt,
        iv
      };
    })
  );

  // Prepare the payload for the backend
  const payload = {
    ciphertext,
    iv,
    expiresInSeconds,
    burnAfterRead,
    keyEnvelopes,
    isMulti: true
  };

  // Create the secret via the backend
  let createRes;
  try {
    createRes = await fetch(`${API_BASE}/pastes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    console.error('Failed to create secret:', err);
    return false;
  }

  if (!createRes.ok) {
    console.error(`Failed to create secret: ${createRes.status}`);
    const errorText = await createRes.text();
    console.error(errorText);
    return false;
  }

  const { id, deleteToken, version } = await createRes.json();
  console.log(`Secret created with ID: ${id}`);

  // Step 2: For each recipient, attempt to decrypt the secret
  for (const recipient of recipients) {
    console.log(`\nAttempting to decrypt for recipient: ${recipient.id}`);

    // Call the reveal endpoint for multi-recipient mode
    let revealRes;
    try {
      revealRes = await fetch(`${API_BASE}/pastes/${id}/reveal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          recipientId: recipient.id,
          passphrase: recipient.passphrase
        }),
      });
    } catch (err) {
      console.error(`Failed to reveal for ${recipient.id}:`, err);
      return false;
    }

    if (!revealRes.ok) {
      console.error(`Failed to reveal for ${recipient.id}: ${revealRes.status}`);
      const errorText = await revealRes.text();
      console.error(errorText);
      return false;
    }

    const { ciphertext: returnedCiphertext, iv: returnedIv, keyEnvelope } = await revealRes.json();
    console.log(`Received envelope for ${recipient.id}:`);
    console.log(`  encryptedKey: ${keyEnvelope.encryptedKey}`);
    console.log(`  salt: ${keyEnvelope.salt}`);
    console.log(`  iv: ${keyEnvelope.iv}`);

    // Step 3: Unwrap the DEK using the recipient's passphrase
    let dekRawRecipient;
    try {
      dekRawRecipient = await unwrapKeyWithPassphrase(
        keyEnvelope.encryptedKey,
        keyEnvelope.salt,
        keyEnvelope.iv,
        recipient.passphrase
      );
      console.log(`Unwrapped DEK for ${recipient.id}:`, dekRawRecipient);
    } catch (err) {
      console.error(`Failed to unwrap DEK for ${recipient.id}:`, err);
      return false;
    }

    // Step 4: Import the unwrapped DEK
    let dekKeyRecipient;
    try {
      dekKeyRecipient = await importKey(dekRawRecipient);
    } catch (err) {
      console.error(`Failed to import DEK for ${recipient.id}:`, err);
      return false;
    }

    // Step 5: Decrypt the secret with the DEK
    let decrypted;
    try {
      decrypted = await decrypt(
        dekKeyRecipient,
        returnedCiphertext,
        returnedIv
      );
      console.log(`Decrypted secret for ${recipient.id}: ${decrypted}`);
    } catch (err) {
      console.error(`Failed to decrypt secret for ${recipient.id}:`, err);
      return false;
    }

    // Verify the decrypted secret matches the original
    if (decrypted !== text) {
      console.error(`Decrypted secret does not match for ${recipient.id}!`);
      console.error(`Expected: ${text}`);
      console.error(`Got: ${decrypted}`);
      return false;
    }
  }

  console.log('\n✅ All recipients successfully decrypted the secret!');
  return true;
}

// Run the test
testMultiRecipient()
  .then(success => {
    if (success) {
      console.log('\n🎉 Multi-recipient test passed!');
      process.exit(0);
    } else {
      console.log('\n❌ Multi-recipient test failed!');
      process.exit(1);
    }
  })
  .catch(err => {
    console.error('\n💥 Unexpected error during test:', err);
    process.exit(1);
  });