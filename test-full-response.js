// Import fetch for Node.js
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const API_BASE = 'http://localhost:3001';

async function testFullResponse() {
  console.log('=== Testing Full Response ===');

  // Create a paste with time constraints
  const now = new Date();
  const futureTime = new Date(now.getTime() + (5 * 60 * 1000)); // 5 minutes from now
  const futureTimePlus10 = new Date(futureTime.getTime() + (10 * 60 * 1000)); // 10 minutes after futureTime

  const createPayload = {
    ciphertext: 'dGVzdCBkYXRh', // "test data" base64 encoded
    iv: 'aW5pdGlhbFY=', // "initialV" base64 encoded
    expiresInSeconds: 3600,
    burnAfterRead: false,
    notBefore: futureTime.toISOString().slice(0, 16), // Format for datetime-local input
    notAfter: futureTimePlus10.toISOString().slice(0, 16) // 10 minutes after notBefore
  };

  try {
    console.log('Creating test paste with time constraints...');
    console.log(`  notBefore: ${createPayload.notBefore}`);
    console.log(`  notAfter: ${createPayload.notAfter}`);

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

    // Now test the metadata endpoint and get the FULL response
    console.log(`\nTesting metadata endpoint for ID: ${createData.id}`);
    const metaRes = await fetch(`${API_BASE}/pastes/${createData.id}/meta`);

    console.log('Metadata response status:', metaRes.status);

    // Get the full response text
    const rawText = await metaRes.text();
    console.log('Full response text:');
    console.log(rawText);

    // Try to parse as JSON and show all keys
    try {
      const parsedData = JSON.parse(rawText);
      console.log('\nParsed JSON object:');
      console.log(parsedData);

      console.log('\nAll keys in response:');
      Object.keys(parsedData).forEach(key => {
        console.log(`  ${key}: ${JSON.stringify(parsedData[key])} (${typeof parsedData[key]})`);
      });

      console.log('\nNumber of keys:', Object.keys(parsedData).length);
    } catch (e) {
      console.log('Failed to parse as JSON:', e.message);
    }

    return true;
  } catch (err) {
    console.error('❌ Full response test failed:', err.message);
    return false;
  }
}

testFullResponse()
  .then(success => {
    if (success) {
      console.log('\n🎉 Full response test passed!');
      process.exit(0);
    } else {
      console.log('\n❌ Full response test failed!');
      process.exit(1);
    }
  })
  .catch(err => {
    console.error('\n💥 Unexpected error during full response test:', err);
    process.exit(1);
  });