// Import fetch for Node.js
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const API_BASE = 'http://localhost:3001';

async function debugMetadata() {
  console.log('=== Debugging Metadata Response ===');

  const payload = {
    ciphertext: 'dGVzdCBkYXRh', // "test data" base64 encoded
    iv: 'aW5pdGlhbFY=', // "initialV" base64 encoded
    expiresInSeconds: 3600,
    burnAfterRead: false
  };

  try {
    console.log('Creating secret...');
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

    // Get metadata
    console.log('\nFetching metadata...');
    const metaRes = await fetch(`${API_BASE}/pastes/${data.id}/meta`);

    if (!metaRes.ok) {
      throw new Error(`HTTP ${metaRes.status}: ${await metaRes.text()}`);
    }

    const metaData = await metaRes.json();
    console.log('Full metadata received:', JSON.stringify(metaData, null, 2));
    console.log('Individual fields:');
    console.log('  hasPin:', metaData.hasPin);
    console.log('  version:', metaData.version);
    console.log('  isMulti:', metaData.isMulti);
    console.log('  notBefore:', metaData.notBefore);
    console.log('  notAfter:', metaData.notAfter);

    return true;
  } catch (err) {
    console.error('❌ Debug failed:', err.message);
    return false;
  }
}

debugMetadata()
  .then(success => {
    if (success) {
      console.log('\n🎉 Debug completed!');
      process.exit(0);
    } else {
      console.log('\n❌ Debug failed!');
      process.exit(1);
    }
  })
  .catch(err => {
    console.error('\n💥 Unexpected error during debug:', err);
    process.exit(1);
  });