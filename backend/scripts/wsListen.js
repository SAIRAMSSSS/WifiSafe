const WebSocket = require('ws');

const url = process.env.WS_URL || 'ws://localhost:3001/ws';
const ws = new WebSocket(url);

ws.on('open', () => {
  console.log('WS connected to', url);
  ws.send(JSON.stringify({ type: 'subscribe', channel: 'alerts' }));
});

ws.on('message', (msg) => {
  try {
    console.log('MSG', typeof msg === 'string' ? msg : msg.toString());
  } catch (e) {
    console.error('Failed to parse message', e);
  }
});

ws.on('close', () => console.log('WS closed'));
ws.on('error', (e) => console.error('WS error', e));

// keep process alive
process.stdin.resume();
