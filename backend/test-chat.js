const fetch = require('node-fetch');

async function testChat() {
    console.log('🧪 Testing Chatbot AI via Backend API...');
    try {
        const res = await fetch('http://localhost:3001/api/ai/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message: 'Tell me about the security of my network',
                context: { securityScore: 65 }
            })
        });

        const data = await res.json();
        console.log('\n✅ Response received:');
        console.log('Bot:', data.message);
        console.log('Suggestions:', data.suggestions);

        if (data.message && data.message.includes('[SYSTEM NOTE:')) {
            console.log('\n⚠️  WARNING: System is still falling back to simulated analysis!');
        } else {
            console.log('\n✨ SUCCESS: Real AI response detected.');
        }
    } catch (err) {
        console.log('\n❌ ERROR:', err.message);
    }
}

testChat();
