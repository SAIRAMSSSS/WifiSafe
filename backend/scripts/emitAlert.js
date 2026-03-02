const { v4: uuidv4 } = require('uuid');
const { getDatabase, initializeDatabase } = require('../src/database/init');
const { broadcast } = require('../src/websocket/server');

async function emitTestAlert() {
  // Ensure database initialized in this process
  const db = await initializeDatabase();
  const id = uuidv4();
  const now = new Date().toISOString();

  const alert = {
    id,
    type: 'manual_test',
    severity: 'high',
    device_id: null,
    device_ip: '127.0.0.1',
    device_mac: null,
    message: 'Test alert emitted from scripts/emitAlert.js',
    details: null,
    acknowledged: 0,
    acknowledged_by: null,
    acknowledged_at: null,
    created_at: now
  };

  // Insert into DB (alerts table schema expected)
  try {
    db.prepare(`INSERT INTO alerts (id, type, severity, device_id, device_ip, device_mac, message, details, acknowledged, acknowledged_by, acknowledged_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(id, alert.type, alert.severity, alert.device_id, alert.device_ip, alert.device_mac, alert.message, alert.details, alert.acknowledged, alert.acknowledged_by, alert.acknowledged_at, alert.created_at);

    console.log('Inserted alert into database:', id);

    // Broadcast via websocket server
    try {
      broadcast('alerts', { event: 'new_alert', alert });
      console.log('Broadcasted alert on channel "alerts"');
    } catch (bErr) {
      console.error('Failed to broadcast alert:', bErr);
    }
  } catch (err) {
    console.error('Failed to insert alert:', err);
    process.exit(1);
  }
}

emitTestAlert().then(() => process.exit(0));
