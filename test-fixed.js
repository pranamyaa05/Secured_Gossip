// Import fetch for Node.js
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const API_BASE = 'http://localhost:3004';

async function testFixed() {
  console.log('=== Testing Fixed Implementation ===');

  // Create a paste with time constraints
  const now = new Date();
  const futureTime = new Date(now.getTime() + (30 * 60 * 1000)); // 30 minutes from now
  const futureTimePlus10 = new Date(futureTime.getTime() + (10 * 60 * 1000)); // 10 minutes after futureTime

  const createPayload = {
    ciphertext: 'dGVzdCBkYXRh', // "test data" base64 encoded
    iv: 'aW5pdGlhbFY=', // "initialV" base64 encoded
    expiresInSeconds: 3600,
    burnAfterRead: false,
    notBefore: futureTime.getTime(), // Timestamp in milliseconds
    notAfter: futureTimePlus10.getTime() // Timestamp in milliseconds
  };

  try {
    console.log('Creating test paste with time constraints...');
    console.log(`  notBefore: ${createPayload.notBefore} (${new Date(createPayload.notBefore).toISOString()})`);
    console.log(`  notAfter: ${createPayload.notAfter} (${new Date(createPayload.notAfter).toISOString()})`);

    const createRes = await fetch(`${API_BASE}/pastes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(createPayload)
    });

    if (!createRes.ok) {
      throw new Error(`HTTP ${createRes.status}: ${await createRes.text()}`);
    }

    const createData = await createRes.json();
    console.log('✅ Paste created:', { id: createData.id });

    // Test 1: Try to get metadata immediately (should show not yet available for decryption)
    console.log(`\n--- Testing metadata retrieval (should show not yet available for decryption) ---`);
    const metaRes = await fetch(`${API_BASE}/pastes/${createData.id}/meta`);

    if (!metaRes.ok) {
      throw new Error(`HTTP ${metaRes.status}: ${await metaRes.text()}`);
    }

    const metaData = await metaRes.json();
    console.log('Metadata received:', JSON.stringify(metaData, null, 2));
    console.log('Individual fields:');
    console.log('  hasPin:', metaData.hasPin);
    console.log('  version:', metaData.version);
    console.log('  isMulti:', metaData.isMulti);
    console.log('  notBefore:', metaData.notBefore);
    console.log('  notAfter:', metaData.notAfter);

    // The secret should not be available for decryption yet (notBefore is in the future)
    // But we should still get the metadata back
    if (metaRes.ok) {
      console.log('✅ Metadata retrieved successfully');

      // Check that we got the time constraint fields
      if (metaData.notBefore !== null && metaData.notAfter !== null) {
        console.log('✅ Time constraint fields present in metadata');
      } else {
        console.log('⚠️  Time constraint fields missing from metadata');
      }
    } else {
      console.log('❌ Failed to retrieve metadata');
    }

    // Test 2: Try to reveal the secret (should fail with appropriate message)
    console.log(`\n--- Testing secret reveal (should fail - not yet available) ---`);
    const revealRes = await fetch(`${API_BASE}/pastes/${createData.id}/reveal`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}) // No PIN since we didn't set one
    });

    if (revealRes.ok) {
      console.log('❌ ERROR: Secret should not be revealable yet');
    } else {
      const errorData = await revealRes.json();
      console.log('✅ Secret correctly not revealable yet:', errorData.error);
    }

    return true;
  } catch (err) {
    console.error('❌ Test failed:', err.message);
    return false;
  }
}

testFixed()
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