// Import fetch for Node.js
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const API_BASE = 'http://localhost:3001';

async function testDirectMeta() {
  console.log('=== Testing Direct Metadata Endpoint ===');

  // First create a simple paste
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

    // Now test the metadata endpoint directly
    console.log(`\nTesting metadata endpoint for ID: ${createData.id}`);
    const metaRes = await fetch(`${API_BASE}/pastes/${createData.id}/meta`);

    console.log('Metadata response status:', metaRes.status);
    console.log('Metadata response headers:', Object.fromEntries(metaRes.headers.entries()));

    if (!metaRes.ok) {
      const errorText = await metaRes.text();
      throw new Error(`HTTP ${metaRes.status}: ${errorText}`);
    }

    const metaData = await metaRes.json();
    console.log('Metadata response body:', JSON.stringify(metaData, null, 2));

    return true;
  } catch (err) {
    console.error('❌ Direct meta test failed:', err.message);
    return false;
  }
}

testDirectMeta()
  .then(success => {
    if (success) {
      console.log('\n🎉 Direct meta test passed!');
      process.exit(0);
    } else {
      console.log('\n❌ Direct meta test failed!');
      process.exit(1);
    }
  })
  .catch(err => {
    console.error('\n💥 Unexpected error during direct meta test:', err);
    process.exit(1);
  });