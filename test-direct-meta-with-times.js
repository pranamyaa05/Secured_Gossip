// Import fetch for Node.js
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const API_BASE = 'http://localhost:3001';

async function testDirectMetaWithTimes() {
  console.log('=== Testing Direct Metadata Endpoint WITH Time Constraints ===');

  // Create timestamps for testing
  const now = new Date();
  const futureTime = new Date(now.getTime() + (5 * 60 * 1000)); // 5 minutes from now
  const futureTimePlus10 = new Date(futureTime.getTime() + (10 * 60 * 1000)); // 10 minutes after futureTime

  // First create a paste with time constraints
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

    // Check if we got the time constraint fields
    console.log('\nField analysis:');
    console.log('  hasPin:', metaData.hasPin, '(expected: boolean)');
    console.log('  version:', metaData.version, '(expected: number)');
    console.log('  isMulti:', metaData.isMulti, '(expected: boolean)');
    console.log('  notBefore:', metaData.notBefore, '(expected: number or null)');
    console.log('  notAfter:', metaData.notAfter, '(expected: number or null)');

    return true;
  } catch (err) {
    console.error('❌ Direct meta test failed:', err.message);
    return false;
  }
}

testDirectMetaWithTimes()
  .then(success => {
    if (success) {
      console.log('\n🎉 Direct meta test with times passed!');
      process.exit(0);
    } else {
      console.log('\n❌ Direct meta test with times failed!');
      process.exit(1);
    }
  })
  .catch(err => {
    console.error('\n💥 Unexpected error during direct meta test:', err);
    process.exit(1);
  });