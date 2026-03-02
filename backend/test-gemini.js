// Quick test script to verify Gemini API is working
const fetch = require('node-fetch');

const GEMINI_API_KEY = 'AIzaSyBIZEgHtVsD2IszH2gOtJagd5sbDsl9aa0';
const GEMINI_API_URL = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${GEMINI_API_KEY}`;

async function testGemini() {
    console.log('🧪 Testing Gemini API connection...\n');

    try {
        const res = await fetch(GEMINI_API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: [{
                    parts: [{
                        text: 'Hello, respond with just "API Working" if you receive this.'
                    }]
                }]
            })
        });

        const data = await res.json();

        if (data.candidates && data.candidates[0]) {
            const response = data.candidates[0].content.parts[0].text;
            console.log('✅ SUCCESS! Gemini API Response:', response);
            console.log('\n📊 Full Response:', JSON.stringify(data, null, 2));
        } else if (data.error) {
            console.log('❌ ERROR from Gemini:', data.error.message);
            console.log('\n📊 Full Error:', JSON.stringify(data, null, 2));
        } else {
            console.log('⚠️  Unexpected response format');
            console.log('\n📊 Response:', JSON.stringify(data, null, 2));
        }
    } catch (err) {
        console.log('❌ NETWORK ERROR:', err.message);
    }
}

testGemini();
