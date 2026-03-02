const WebSocket = require('ws');
const fetch = global.fetch || require('node-fetch');

const API_BASE = process.env.API_BASE || 'http://localhost:3001/api';
const WS_BASE = process.env.WS_BASE || 'ws://localhost:3001/ws';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@blackcodex.local';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'ChangeMe123!';

async function run() {
  console.log('Full system check starting...');

  // Login
  const loginRes = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD })
  });

  if (!loginRes.ok) {
    console.error('Login failed:', await loginRes.text());
    process.exit(2);
  }

  const loginData = await loginRes.json();
  const token = loginData.token;
  console.log('Logged in, token length:', token ? token.length : 0);

  // Open WS and subscribe to multiple channels
  const wsUrl = `${WS_BASE}?token=${encodeURIComponent(token)}`;
  const ws = new WebSocket(wsUrl);

  const events = [];
  const channels = ['alerts', 'devices', 'scans', 'packets', 'system'];

  ws.on('open', () => {
    console.log('WS open, subscribing to channels:', channels.join(','));
    channels.forEach(ch => ws.send(JSON.stringify({ type: 'subscribe', channel: ch })));
  });

  ws.on('message', (msg) => {
    try {
      const parsed = JSON.parse(msg.toString());
      // store parsed message
      events.push(parsed);
    } catch (e) {
      console.warn('Invalid WS message', e);
    }
  });

  ws.on('error', (err) => console.error('WS error', err));

  // Hit key API endpoints
  const endpoints = ['/alerts', '/devices', '/scan/status', '/auth/me', '/settings'];
  const results = {};
  for (const ep of endpoints) {
    try {
      const res = await fetch(`${API_BASE}${ep}`, { headers: { Authorization: `Bearer ${token}` } });
      results[ep] = { status: res.status, ok: res.ok };
    } catch (e) {
      results[ep] = { error: e.message };
    }
  }

  console.log('API endpoint quick-check results:', results);

  // Wait for realtime messages
  await new Promise((r) => setTimeout(r, 15000));

  ws.close();

  const summary = {
    totalMessages: events.length,
    channelsObserved: Array.from(new Set(events.map(e => e.channel || e.type || (e.data && e.data.event))))
  };

  console.log('Realtime summary:', summary);

  // simple pass/fail
  const pass = events.length > 0 && Object.values(results).every(v => v && (v.ok || v.status === 200 || v.status === 204));

  if (pass) {
    console.log('Full system check PASSED');
    process.exit(0);
  } else {
    console.error('Full system check FAILED');
    process.exit(3);
  }
}

run().catch(err => { console.error('Check error:', err); process.exit(1); });
