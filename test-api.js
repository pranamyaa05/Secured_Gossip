// Import fetch for Node.js
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const API_BASE = 'http://localhost:3001';

// Test 1: Single recipient without PIN
async function testSingleNoPin() {
  console.log('=== Test 1: Single recipient without PIN ===');

  const payload = {
    ciphertext: 'dGVzdCBkYXRh', // "test data" base64 encoded
    iv: 'aW5pdGlhbFY=', // "initialV" base64 encoded
    expiresInSeconds: 3600,
    burnAfterRead: false
  };

  try {
    const res = await fetch(`${API_BASE}/pastes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    }

    const data = await res.json();
    console.log('Created secret:', data);
    return data;
  } catch (err) {
    console.error('Error:', err.message);
    return null;
  }
}

// Test 2: Single recipient with PIN
async function testSingleWithPin() {
  console.log('\n=== Test 2: Single recipient with PIN ===');

  const payload = {
    ciphertext: 'dGVzdCBkYXRh',
    iv: 'aW5pdGlhbFY=',
    expiresInSeconds: 3600,
    burnAfterRead: false,
    pin: '1234',
    contentSalt: 'c2FsdDEyMzQ=', // "salt1234" base64 encoded
    version: 0
  };

  try {
    const res = await fetch(`${API_BASE}/pastes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    }

    const data = await res.json();
    console.log('Created secret:', data);
    return data;
  } catch (err) {
    console.error('Error:', err.message);
    return null;
  }
}

// Test 3: Multi-recipient (simulating what frontend would send)
async function testMultiRecipient() {
  console.log('\n=== Test 3: Multi-recipient ===');

  // This simulates what the frontend would create:
  // 1. Generate a random DEK
  // 2. Encrypt the secret with the DEK
  // 3. Wrap the DEK for each recipient

  // For this test, we'll use predefined values
  const payload = {
    ciphertext: 'dGVzdCBkYXRh',
    iv: 'aW5pdGlhbFY=',
    expiresInSeconds: 3600,
    burnAfterRead: false,
    keyEnvelopes: [
      {
        recipientId: 'alice@example.com',
        encryptedKey: 'ZS+nFp93jog9zPIieJxDX+QMjc3e+6Q8tv90AkC24t3rE/6idJlHFurwzhM=',
        salt: 'ITS5PJv5aDYgOVzYn9TXpA==',
        iv: 'ugtO1KkVPS7bKwV3EgNQRQ=='
      },
      {
        recipientId: 'bob@example.com',
        encryptedKey: 'QOwu/v0lT0cVDIv1fpce+8RP+n8RNUdeBKYzYDMeJbT/9VKP/0hRpuqlrLc=',
        salt: '6pXzQjSMg0UrakR63F1Oow==',
        iv: '9SA0dC2lVFi2n1tBx+WPQA=='
      }
    ],
    isMulti: true
  };

  try {
    const res = await fetch(`${API_BASE}/pastes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    }

    const data = await res.json();
    console.log('Created secret:', data);
    return data;
  } catch (err) {
    console.error('Error:', err.message);
    return null;
  }
}

// Test revealing a secret
async function testReveal(id, deleteToken, isMulti = false, recipientId = null, passphrase = null, pin = null) {
  console.log(`\n=== Test Reveal: ${isMulti ? 'Multi-recipient' : 'Single recipient'} (${isMulti ? recipientId : 'with PIN'}) ===`);

  const payload = {};
  if (isMulti) {
    payload.recipientId = recipientId;
    payload.passphrase = passphrase;
  } else if (pin !== null) {
    payload.pin = pin;
  }

  try {
    const res = await fetch(`${API_BASE}/pastes/${id}/reveal`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      const errorData = await res.json();
      console.log('Error:', errorData.error || `HTTP ${res.status}`);
      return null;
    }

    const data = await res.json();
    console.log('Revealed data:', data);
    return data;
  } catch (err) {
    console.error('Error:', err.message);
    return null;
  }
}

// Run tests
async function runTests() {
  // Test backend health
  try {
    const healthRes = await fetch(`${API_BASE}/health`);
    if (!healthRes.ok) throw new Error('Backend not healthy');
    console.log('✅ Backend is healthy');
  } catch (err) {
    console.error('❌ Backend health check failed:', err.message);
    return;
  }

  // Run tests
  const singleNoPinSecret = await testSingleNoPin();
  const singleWithPinSecret = await testSingleWithPin();
  const multiSecret = await testMultiRecipient();

  // Test revealing secrets
  if (singleNoPinSecret) {
    await testReveal(singleNoPinSecret.id, singleNoPinSecret.deleteToken, false, null, null, null);
  }

  if (singleWithPinSecret) {
    await testReveal(singleWithPinSecret.id, singleWithPinSecret.deleteToken, false, null, null, '1234');
  }

  if (multiSecret) {
    // Test revealing for Alice
    await testReveal(multiSecret.id, multiSecret.deleteToken, true, 'alice@example.com', 'alice123', null);
    // Test revealing for Bob
    await testReveal(multiSecret.id, multiSecret.deleteToken, true, 'bob@example.com', 'bob456', null);
    // Test revealing with wrong credentials
    await testReveal(multiSecret.id, multiSecret.deleteToken, true, 'alice@example.com', 'wrongpass', null);
  }
}

runTests().catch(console.error);