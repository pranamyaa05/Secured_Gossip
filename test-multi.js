const fetch = require('node-fetch');
const crypto = require('node:crypto');

const API_BASE = 'http://localhost:3001';

// Helper to base64url encode
function base64UrlEncode(buffer) {
  return buffer.toString('base64')
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

// Simulate the frontend's generateKey function
async function generateKey() {
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const raw = await crypto.subtle.exportKey('raw', key);
  return { key, raw: base64UrlEncode(raw) };
}

// Simulate the frontend's importKey function
async function importKey(base64Key) {
  const raw = base64UrlDecode(base64Key);
  return crypto.subtle.importKey(
    'raw',
    raw,
    { name: 'AES-GCM' },
    true,
    ['encrypt', 'decrypt']
  );
}

// Simulate the frontend's encrypt function
async function encrypt(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoded
  );
  return {
    ciphertext: base64UrlEncode(ciphertext),
    iv: base64UrlEncode(iv),
  };
}

// Simulate the frontend's wrapKeyWithPassphrase function
async function wrapKeyWithPassphrase(key, passphrase, iterations = 300000) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const ikm = new TextEncoder().encode(passphrase);

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
    encryptedKey: base64UrlEncode(encryptedKey),
    salt: base64UrlEncode(salt),
    iv: base64UrlEncode(iv)
  };
}

// Simulate the frontend's unwrapKeyWithPassphrase function
async function unwrapKeyWithPassphrase(encryptedKeyBase64, saltBase64, ivBase64, passphrase, iterations = 300000) {
  const encryptedKey = base64UrlDecode(encryptedKeyBase64);
  const salt = base64UrlDecode(saltBase64);
  const iv = base64UrlDecode(ivBase64);

  const ikm = new TextEncoder().encode(passphrase);

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

// Main test function
async function testMultiRecipient() {
  console.log('Starting multi-recipient test...');

  // Step 1: Create a multi-recipient secret via the backend API (simulating frontend)
  const text = 'This is a secret message for multiple recipients.';
  const expiresInSeconds = 3600;
  const burnAfterRead = false;

  // Generate a random DEK
  const { key: dek, raw: dekRaw } = await generateKey();

  // Encrypt the secret with the DEK
  const { ciphertext, iv } = await encrypt(dek, text);

  // Define two recipients
  const recipients = [
    { id: 'alice@example.com', passphrase: 'alice123' },
    { id: 'bob@example.com', passphrase: 'bob456' }
  ];

  // For each recipient, encrypt the DEK with their passphrase
  const keyEnvelopes = await Promise.all(
    recipients.map(async (recipient) => {
      const { encryptedKey, salt, iv } = await wrapKeyWithPassphrase(
        dek, // Pass the CryptoKey directly
        recipient.passphrase
      );
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

    // Step 3: Unwrap the DEK using the recipient's passphrase
    let dekRawRecipient;
    try {
      dekRawRecipient = await unwrapKeyWithPassphrase(
        keyEnvelope.encryptedKey,
        keyEnvelope.salt,
        keyEnvelope.iv,
        recipient.passphrase
      );
    } catch (err) {
      console.error(`Failed to unwrap DEK for ${recipient.id}:`, err);
      return false;
    }

    // Step 4: Import the unwrapped DEK
    let dekKeyRecipient;
    try {
      dekKeyRecipient = await importKey(base64UrlEncode(dekRawRecipient));
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
    } catch (err) {
      console.error(`Failed to decrypt secret for ${recipient.id}:`, err);
      return false;
    }

    console.log(`Decrypted secret for ${recipient.id}: ${decrypted}`);

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