const WebSocket = require('ws');
const fetch = global.fetch || require('node-fetch');

const API_BASE = process.env.API_BASE || 'http://localhost:3001/api';
const WS_BASE = process.env.WS_BASE || 'ws://localhost:3001/ws';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@blackcodex.local';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'ChangeMe123!';

async function run() {
  console.log('E2E scan test starting...');

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

  // Connect WebSocket
  const wsUrl = `${WS_BASE}?token=${encodeURIComponent(token)}`;
  const ws = new WebSocket(wsUrl);

  const events = [];
  let subscribed = false;

  ws.on('open', () => {
    console.log('WebSocket open, subscribing to channels');
    ws.send(JSON.stringify({ type: 'subscribe', channel: 'devices' }));
    ws.send(JSON.stringify({ type: 'subscribe', channel: 'scans' }));
    subscribed = true;
  });

  ws.on('message', (msg) => {
    try {
      const parsed = JSON.parse(msg.toString());
      console.log('WS:', parsed.type || parsed.channel || parsed);
      events.push(parsed);
    } catch (e) {
      console.warn('Invalid WS message', e);
    }
  });

  ws.on('error', (err) => console.error('WS error', err));

  // Start scan
  console.log('Triggering scan start...');
  const startRes = await fetch(`${API_BASE}/scan/start`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify({ type: 'full' }) });
  if (!startRes.ok) {
    console.error('Failed to start scan:', await startRes.text());
    ws.close();
    process.exit(3);
  }

  console.log('Scan started, waiting for events (20s)...');

  await new Promise((resolve) => setTimeout(resolve, 20000));

  ws.close();

  const deviceEvents = events.filter(e => e.channel === 'devices' || (e.data && e.data.event && e.data.event.includes('device')));
  const scanEvents = events.filter(e => e.channel === 'scans' || (e.data && e.data.event && e.data.event.includes('scan')));

  console.log(`Collected ${events.length} websocket messages, devices:${deviceEvents.length}, scans:${scanEvents.length}`);

  if (deviceEvents.length > 0 || scanEvents.length > 0) {
    console.log('E2E scan test succeeded');
    process.exit(0);
  } else {
    console.error('E2E scan test failed - no relevant events received');
    process.exit(4);
  }
}

run().catch(err => {
  console.error('E2E script error:', err);
  process.exit(1);
});
