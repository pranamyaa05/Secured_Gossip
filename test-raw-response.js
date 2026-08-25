// Import fetch for Node.js
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const API_BASE = 'http://localhost:3001';

async function testRawResponse() {
  console.log('=== Testing Raw Response ===');

  // Create a simple paste
  const createPayload = {
    ciphertext: 'dGVzdCBkYXRh', // "test data" base64 encoded
    iv: 'aW5pdGlhbFY=', // "initialV" base64 encoded
    expiresInSeconds: 3600,
    burnAfterRead: false
  };

  try {
    console.log('Creating test paste...');
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

    // Now test the metadata endpoint and get raw text
    console.log(`\nTesting metadata endpoint for ID: ${createData.id}`);
    const metaRes = await fetch(`${API_BASE}/pastes/${createData.id}/meta`);

    console.log('Metadata response status:', metaRes.status);
    console.log('Metadata response headers:');
    for (const [key, value] of metaRes.headers.entries()) {
      console.log(`  ${key}: ${value}`);
    }

    // Get raw text
    const rawText = await metaRes.text();
    console.log('Raw response text:', rawText);

    // Try to parse as JSON
    try {
      const parsedData = JSON.parse(rawText);
      console.log('Parsed JSON:', JSON.stringify(parsedData, null, 2));
    } catch (e) {
      console.log('Failed to parse as JSON:', e.message);
    }

    return true;
  } catch (err) {
    console.error('❌ Raw response test failed:', err.message);
    return false;
  }
}

testRawResponse()
  .then(success => {
    if (success) {
      console.log('\n🎉 Raw response test passed!');
      process.exit(0);
    } else {
      console.log('\n❌ Raw response test failed!');
      process.exit(1);
    }
  })
  .catch(err => {
    console.error('\n💥 Unexpected error during raw response test:', err);
    process.exit(1);
  });