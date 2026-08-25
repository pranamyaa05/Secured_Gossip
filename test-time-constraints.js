// Import fetch for Node.js
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const API_BASE = 'http://localhost:3001';

// Test time-based access constraints
async function testTimeConstraints() {
  console.log('=== Testing Time-based Access Constraints ===');

  const now = new Date();
  const futureTime = new Date(now.getTime() + (5 * 60 * 1000)); // 5 minutes from now
  const pastTime = new Date(now.getTime() - (5 * 60 * 1000));   // 5 minutes ago
  const futureTimePlus10 = new Date(futureTime.getTime() + (10 * 60 * 1000)); // 10 minutes after futureTime

  const payload = {
    ciphertext: 'dGVzdCBkYXRh', // "test data" base64 encoded
    iv: 'aW5pdGlhbFY=', // "initialV" base64 encoded
    expiresInSeconds: 3600,
    burnAfterRead: false,
    notBefore: futureTime.getTime(), // Timestamp in milliseconds
    notAfter: futureTimePlus10.getTime() // Timestamp in milliseconds
  };

  try {
    console.log('Creating secret with time constraints:');
    console.log(`  Not before: ${new Date(futureTime).toLocaleString()}`);
    console.log(`  Not after: ${new Date(futureTime.getTime() + (10 * 60 * 1000)).toLocaleString()}`);

    const res = await fetch(`${API_BASE}/pastes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    }

    const data = await res.json();
    console.log('✅ Secret created successfully:', { id: data.id });

    // Test 1: Try to get metadata (should show not yet available)
    console.log('\n--- Testing metadata retrieval (should show not yet available) ---');
    const metaRes = await fetch(`${API_BASE}/pastes/${data.id}/meta`);

    if (!metaRes.ok) {
      throw new Error(`HTTP ${metaRes.status}: ${await metaRes.text()}`);
    }

    const metaData = await metaRes.json();
    console.log('Metadata received:', metaData);

    // The secret should not be available yet (notBefore is in the future)
    if (metaData.notBefore !== null && Date.now() < metaData.notBefore) {
      console.log('✅ Secret correctly shows as not yet available');
    } else {
      console.log('⚠️  Secret availability check needs frontend validation');
    }

    // Test creating a secret with past notBefore (should fail)
    console.log('\n--- Testing invalid notBefore (past time) ---');
    const invalidPayload = {
      ...payload,
      notBefore: pastTime.toISOString().slice(0, 16)
    };

    const invalidRes = await fetch(`${API_BASE}/pastes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(invalidPayload)
    });

    if (invalidRes.ok) {
      console.log('❌ ERROR: Secret with past notBefore should have been rejected');
    } else {
      const errorData = await invalidRes.json();
      console.log('✅ Correctly rejected secret with past notBefore:', errorData.error);
    }

    // Test creating a secret with notAfter before notBefore (should fail)
    console.log('\n--- Testing invalid time range (notAfter before notBefore) ---');
    const invalidRangePayload = {
      ...payload,
      notAfter: new Date(futureTime.getTime() - (5 * 60 * 1000)).toISOString().slice(0, 16) // 5 minutes before notBefore
    };

    const invalidRangeRes = await fetch(`${API_BASE}/pastes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(invalidRangePayload)
    });

    if (invalidRangeRes.ok) {
      console.log('❌ ERROR: Secret with invalid time range should have been rejected');
    } else {
      const errorData = await invalidRangeRes.json();
      console.log('✅ Correctly rejected secret with invalid time range:', errorData.error);
    }

    return true;
  } catch (err) {
    console.error('❌ Test failed:', err.message);
    return false;
  }
}

// Run the test
testTimeConstraints()
  .then(success => {
    if (success) {
      console.log('\n🎉 Time constraint tests completed!');
      process.exit(0);
    } else {
      console.log('\n❌ Time constraint tests failed!');
      process.exit(1);
    }
  })
  .catch(err => {
    console.error('\n💥 Unexpected error during test:', err);
    process.exit(1);
  });