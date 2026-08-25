// Import fetch for Node.js
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const API_BASE = 'http://localhost:3001';

async function testHealth() {
  console.log('=== Testing Health Endpoint ===');

  try {
    const res = await fetch(`${API_BASE}/health`);
    console.log('Health status:', res.status);
    if (res.ok) {
      const data = await res.json();
      console.log('Health data:', data);
      return true;
    } else {
      console.log('Health endpoint failed:', res.status);
      return false;
    }
  } catch (err) {
    console.error('❌ Health test failed:', err.message);
    return false;
  }
}

testHealth()
  .then(success => {
    if (success) {
      console.log('✅ Health test passed!');
      process.exit(0);
    } else {
      console.log('❌ Health test failed!');
      process.exit(1);
    }
  })
  .catch(err => {
    console.error('\n💥 Unexpected error during health test:', err);
    process.exit(1);
  });