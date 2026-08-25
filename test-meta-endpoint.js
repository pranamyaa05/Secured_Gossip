// Import fetch for Node.js
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const API_BASE = 'http://localhost:3003';

async function testMetaEndpoint() {
  console.log('=== Testing Original Metadata Endpoint ===');

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

    // Now test the ORIGINAL metadata endpoint
    console.log(`\nTesting ORIGINAL metadata endpoint for ID: ${createData.id}`);
    const metaRes = await fetch(`${API_BASE}/pastes/${createData.id}/meta`);

    console.log('Original meta response status:', metaRes.status);

    // Get the full response text
    const rawText = await metaRes.text();
    console.log('Original meta response text:');
    console.log(rawText);

    // Try to parse as JSON and show all keys
    try {
      const parsedData = JSON.parse(rawText);
      console.log('\nParsed JSON object:');
      console.log(parsedData);

      console.log('\nAll keys in response:');
      Object.keys(parsedData).forEach(key => {
        console.log(`  ${key}: ${typeof parsedData[key] === 'object' ? JSON.stringify(parsedData[key]) : parsedData[key]}`);
      });

      console.log('\nNumber of keys:', Object.keys(parsedData).length);
    } catch (e) {
      console.log('Failed to parse as JSON:', e.message);
    }

    return true;
  } catch (err) {
    console.error('❌ Meta endpoint test failed:', err.message);
    return false;
  }
}

testMetaEndpoint()
  .then(success => {
    if (success) {
      console.log('\n🎉 Meta endpoint test passed!');
      process.exit(0);
    } else {
      console.log('\n❌ Meta endpoint test failed!');
      process.exit(1);
    }
  })
  .catch(err => {
    console.error('\n💥 Unexpected error during meta endpoint test:', err);
    process.exit(1);
  });