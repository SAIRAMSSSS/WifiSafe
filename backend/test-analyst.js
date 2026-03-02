const fetch = require('node-fetch');

async function testAnalyst() {
    console.log('🧪 Testing AI Analyst via Backend API (Device Analysis)...');
    try {
        // Try to find a device
        const dbRes = await fetch('http://localhost:3001/api/scan/devices');
        const dbData = await dbRes.json();

        if (!dbData.devices || dbData.devices.length === 0) {
            console.log('⚠️ No devices found in DB, skipping AI analysis test.');
            return;
        }

        const testIp = dbData.devices[0].ip;
        console.log(`Analyzing device: ${testIp}...`);

        const res = await fetch('http://localhost:3001/api/scan/ai/analyze-device', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: testIp })
        });

        const data = await res.json();
        console.log('\n✅ Response received:');
        console.log('Summary:', data.summary);
        console.log('Prediction:', data.prediction);

        if (data.summary && data.summary.includes('has a risk score of')) {
            // Check if it's deterministic fallback
            console.log('\n⚠️  WARNING: Deterministic fallback was used.');
        } else {
            console.log('\n✨ SUCCESS: Real AI enhancement detected.');
        }
    } catch (err) {
        console.log('\n❌ ERROR:', err.message);
    }
}

testAnalyst();
