// Import fetch for Node.js
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const API_BASE = 'http://localhost:3004';

async function testDebug() {
  console.log('=== Debugging Test ===');

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

    console.log('Create response status:', createRes.status);
    if (!createRes.ok) {
      const errorText = await createRes.text();
      throw new Error(`HTTP ${createRes.status}: ${errorText}`);
    }

    const createData = await createRes.json();
    console.log('✅ Paste created:', { id: createData.id });

    // Check status endpoint
    console.log(`\n--- Checking status endpoint ---`);
    const statusRes = await fetch(`${API_BASE}/pastes/${createData.id}/status`, {
      headers: { 'x-delete-token': createData.deleteToken }
    });

    console.log('Status response status:', statusRes.status);
    if (statusRes.ok) {
      const statusData = await statusRes.json();
      console.log('Status data:', statusData);
    } else {
      const errorText = await statusRes.text();
      console.log('Status error:', errorText);
    }

    // Try to get metadata
    console.log(`\n--- Trying metadata endpoint ---`);
    const metaRes = await fetch(`${API_BASE}/pastes/${createData.id}/meta`);

    console.log('Meta response status:', metaRes.status);
    console.log('Meta response headers:');
    for (const [key, value] of metaRes.headers.entries()) {
      console.log(`  ${key}: ${value}`);
    }

    if (!metaRes.ok) {
      const errorText = await metaRes.text();
      console.log('Meta error status:', metaRes.status);
      console.log('Meta error text:', errorText);
    } else {
      const metaData = await metaRes.json();
      console.log('Meta data:', JSON.stringify(metaData, null, 2));
    }

    return true;
  } catch (err) {
    console.error('❌ Test failed:', err.message);
    return false;
  }
}

testDebug()
  .then(success => {
    if (success) {
      console.log('\n🎉 Debug test passed!');
      process.exit(0);
    } else {
      console.log('\n❌ Debug test failed!');
      process.exit(1);
    }
  })
  .catch(err => {
    console.error('\n💥 Unexpected error during test:', err);
    process.exit(1);
  });