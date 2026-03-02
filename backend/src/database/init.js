const initSqlJs = require('sql.js');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const logger = require('../utils/logger');

let db = null;
let SQL = null;

// Wrapper to make sql.js compatible with better-sqlite3 API
function wrapDatabase(sqlJsDb) {
  return {
    prepare: (sql) => {
      return {
        run: (...params) => {
          try {
            sqlJsDb.run(sql, params);
            return { changes: sqlJsDb.getRowsModified() };
          } catch (err) {
            logger.error(`SQL Error: ${err.message}`, { sql, params });
            throw err;
          }
        },
        get: (...params) => {
          try {
            const stmt = sqlJsDb.prepare(sql);
            stmt.bind(params);
            if (stmt.step()) {
              const result = stmt.getAsObject();
              stmt.free();
              return result;
            }
            stmt.free();
            return undefined;
          } catch (err) {
            logger.error(`SQL Error: ${err.message}`, { sql, params });
            throw err;
          }
        },
        all: (...params) => {
          try {
            const results = [];
            const stmt = sqlJsDb.prepare(sql);
            stmt.bind(params);
            while (stmt.step()) {
              results.push(stmt.getAsObject());
            }
            stmt.free();
            return results;
          } catch (err) {
            logger.error(`SQL Error: ${err.message}`, { sql, params });
            throw err;
          }
        }
      };
    },
    exec: (sql) => {
      try {
        sqlJsDb.run(sql);
      } catch (err) {
        logger.error(`SQL Exec Error: ${err.message}`, { sql });
        throw err;
      }
    },
    pragma: () => { },
    _db: sqlJsDb,
    save: () => {
      const data = sqlJsDb.export();
      const buffer = Buffer.from(data);
      const dbPath = process.env.DATABASE_PATH || './data/codex.db';
      fs.writeFileSync(dbPath, buffer);
    }
  };
}

function getDatabase() {
  return db;
}

async function initializeDatabase() {
  const dbPath = process.env.DATABASE_PATH || './data/codex.db';
  const dbDir = path.dirname(dbPath);

  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
  }

  // Initialize SQL.js
  SQL = await initSqlJs();

  // Load existing database or create new one
  let sqlJsDb;
  if (fs.existsSync(dbPath)) {
    const fileBuffer = fs.readFileSync(dbPath);
    sqlJsDb = new SQL.Database(fileBuffer);
  } else {
    sqlJsDb = new SQL.Database();
  }

  db = wrapDatabase(sqlJsDb);

  // Create tables
  db.exec(`
    -- Users table
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      username TEXT,
      password_hash TEXT NOT NULL,
      name TEXT,
      role TEXT DEFAULT 'user',
      is_active INTEGER DEFAULT 1,
      preferences TEXT,
      last_login TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Devices table
    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      ip TEXT NOT NULL,
      mac TEXT,
      device_type TEXT DEFAULT 'unknown',
      manufacturer TEXT,
      model TEXT,
      status TEXT DEFAULT 'online',
      risk_score INTEGER DEFAULT 0,
      risk_level TEXT DEFAULT 'safe',
      first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
      last_seen TEXT,
      discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
      admin_url TEXT,
      quarantined_at TEXT,
      quarantine_reason TEXT,
      quarantine_release_at TEXT,
      previous_status TEXT,
      has_weak_credentials INTEGER DEFAULT 0,
      has_misconfigs INTEGER DEFAULT 0,
      credential_status TEXT,
      fingerprint_data TEXT,
      firmware_version TEXT,
      firmware_data TEXT,
      open_ports TEXT,
      services TEXT,
      notes TEXT,
      is_quarantined INTEGER DEFAULT 0,
      device_category TEXT DEFAULT 'Unknown',
      device_vendor TEXT,
      device_role TEXT DEFAULT 'Unknown',
      iot_device_type TEXT DEFAULT 'Unknown',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Vulnerabilities table
    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      title TEXT NOT NULL,
      severity TEXT NOT NULL,
      description TEXT,
      cve_id TEXT,
      cvss_score REAL,
      remediation TEXT,
      exploit_available INTEGER DEFAULT 0,
      patch_available INTEGER DEFAULT 0,
      status TEXT DEFAULT 'open',
      discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
      resolved_at TEXT,
      FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- Ports table
    CREATE TABLE IF NOT EXISTS ports (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      port_number INTEGER NOT NULL,
      protocol TEXT DEFAULT 'TCP',
      service_name TEXT,
      service_version TEXT,
      status TEXT DEFAULT 'open',
      risk_level TEXT DEFAULT 'safe',
      banner TEXT,
      FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- Alerts table
    CREATE TABLE IF NOT EXISTS alerts (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      severity TEXT NOT NULL,
      device_id TEXT,
      device_ip TEXT,
      device_mac TEXT,
      message TEXT NOT NULL,
      title TEXT,
      details TEXT,
      acknowledged INTEGER DEFAULT 0,
      acknowledged_by TEXT,
      acknowledged_at TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL
    );

    -- Scans table
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      type TEXT DEFAULT 'full',
      status TEXT DEFAULT 'pending',
      progress INTEGER DEFAULT 0,
      devices_scanned INTEGER DEFAULT 0,
      total_devices INTEGER DEFAULT 0,
      vulnerabilities_found INTEGER DEFAULT 0,
      critical_issues INTEGER DEFAULT 0,
      started_by TEXT,
      start_time TEXT,
      end_time TEXT,
      results TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Misconfigurations table
    CREATE TABLE IF NOT EXISTS misconfigurations (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      type TEXT NOT NULL,
      severity TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      port INTEGER,
      recommendation TEXT,
      can_auto_fix INTEGER DEFAULT 0,
      is_fixed INTEGER DEFAULT 0,
      discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- Anomalies table
    CREATE TABLE IF NOT EXISTS anomalies (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      type TEXT NOT NULL,
      severity TEXT NOT NULL,
      description TEXT,
      source_ip TEXT,
      dest_ip TEXT,
      dest_port INTEGER,
      protocol TEXT,
      bytes_transferred INTEGER,
      is_resolved INTEGER DEFAULT 0,
      resolved_at TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL
    );

    -- CVE Database cache
    CREATE TABLE IF NOT EXISTS cve_cache (
      id TEXT PRIMARY KEY,
      cve_id TEXT UNIQUE NOT NULL,
      description TEXT,
      severity TEXT,
      cvss_score REAL,
      cvss_vector TEXT,
      published_date TEXT,
      last_modified TEXT,
      affected_products TEXT,
      references_json TEXT,
      exploit_available INTEGER DEFAULT 0,
      patch_available INTEGER DEFAULT 0,
      cached_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Threat Intelligence
    CREATE TABLE IF NOT EXISTS threats (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      severity TEXT NOT NULL,
      description TEXT,
      indicators TEXT,
      affected_device_types TEXT,
      mitigation_steps TEXT,
      status TEXT DEFAULT 'active',
      first_seen TEXT,
      last_seen TEXT,
      last_active TEXT,
      source TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Packet captures
    CREATE TABLE IF NOT EXISTS packets (
      id TEXT PRIMARY KEY,
      source_ip TEXT,
      source_port INTEGER,
      dest_ip TEXT,
      dest_port INTEGER,
      protocol TEXT,
      size INTEGER,
      direction TEXT,
      is_suspicious INTEGER DEFAULT 0,
      flags TEXT,
      info TEXT,
      threat_type TEXT,
      captured_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Quarantine actions
    CREATE TABLE IF NOT EXISTS quarantine_actions (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      action TEXT NOT NULL,
      reason TEXT,
      performed_by TEXT,
      status TEXT DEFAULT 'active',
      started_at TEXT DEFAULT CURRENT_TIMESTAMP,
      ended_at TEXT,
      FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- AI Reports
    CREATE TABLE IF NOT EXISTS ai_reports (
      id TEXT PRIMARY KEY,
      device_id TEXT,
      ip TEXT,
      analysis_type TEXT,
      report_data TEXT,
      summary TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      resolved INTEGER DEFAULT 0,
      resolved_at TEXT,
      FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    );

    -- Settings
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT,
      category TEXT,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Audit logs
    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      action TEXT NOT NULL,
      resource_type TEXT,
      resource_id TEXT,
      details TEXT,
      ip_address TEXT,
      user_agent TEXT,
      timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Security reports
    CREATE TABLE IF NOT EXISTS security_reports (
      id TEXT PRIMARY KEY,
      title TEXT,
      type TEXT,
      summary TEXT,
      content TEXT,
      generated_by TEXT,
      file_path TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Default credentials database
    CREATE TABLE IF NOT EXISTS default_credentials (
      id TEXT PRIMARY KEY,
      vendor TEXT NOT NULL,
      product TEXT,
      username TEXT NOT NULL,
      password TEXT NOT NULL,
      service TEXT,
      port INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Packet captures (updated schema)
    CREATE TABLE IF NOT EXISTS packet_captures (
      id TEXT PRIMARY KEY,
      capture_id TEXT,
      timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
      protocol TEXT,
      source_ip TEXT,
      source_port INTEGER,
      destination_ip TEXT,
      destination_port INTEGER,
      size INTEGER,
      direction TEXT,
      info TEXT,
      payload TEXT
    );

    -- Capture sessions
    CREATE TABLE IF NOT EXISTS capture_sessions (
      id TEXT PRIMARY KEY,
      interface TEXT,
      filter TEXT,
      status TEXT DEFAULT 'running',
      started_at TEXT DEFAULT CURRENT_TIMESTAMP,
      stopped_at TEXT
    );

    -- Threat Intelligence (updated schema)
    CREATE TABLE IF NOT EXISTS threat_intelligence (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      severity TEXT NOT NULL,
      severity_score INTEGER,
      description TEXT,
      indicators TEXT,
      affected_device_types TEXT,
      mitigation_steps TEXT,
      source TEXT,
      status TEXT DEFAULT 'active',
      first_seen TEXT,
      last_seen TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- CVE Database (updated schema)
    CREATE TABLE IF NOT EXISTS cve_database (
      id TEXT PRIMARY KEY,
      cve_id TEXT UNIQUE NOT NULL,
      title TEXT,
      description TEXT,
      severity TEXT,
      cvss_score REAL,
      cvss_vector TEXT,
      vendor TEXT,
      affected_products TEXT,
      affected_versions TEXT,
      published_date TEXT,
      last_modified TEXT,
      exploit_available INTEGER DEFAULT 0,
      patch_available INTEGER DEFAULT 0,
      references_data TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- Security scores
    CREATE TABLE IF NOT EXISTS security_scores (
      id TEXT PRIMARY KEY,
      scan_id TEXT,
      device_id TEXT,
      score INTEGER,
      open_ports INTEGER,
      critical_cves INTEGER,
      high_cves INTEGER,
      medium_cves INTEGER,
      weak_password INTEGER,
      exposed_service INTEGER,
      timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
      network_score INTEGER,
      details TEXT
    );

    -- Create indexes
    CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);
    CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
    CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
    CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
    CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON alerts(acknowledged);
    CREATE INDEX IF NOT EXISTS idx_vulnerabilities_device ON vulnerabilities(device_id);
    CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
    CREATE INDEX IF NOT EXISTS idx_packets_captured ON packets(captured_at);
    CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
  `);

  // Seed default admin user if not exists
  const adminExists = db.prepare('SELECT id FROM users WHERE email = ?').get(process.env.ADMIN_EMAIL || 'admin@blackcodex.local');

  if (!adminExists) {
    const passwordHash = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'ChangeMe123!', 10);
    db.prepare(`
      INSERT INTO users (id, email, password_hash, name, role) 
      VALUES (?, ?, ?, ?, ?)
    `).run(uuidv4(), process.env.ADMIN_EMAIL || 'admin@blackcodex.local', passwordHash, 'Administrator', 'admin');
    logger.info('Default admin user created');
  }

  // Seed default credentials database
  const credentialsExist = db.prepare('SELECT COUNT(*) as count FROM default_credentials').get();
  if (credentialsExist.count === 0) {
    const defaultCreds = [
      { vendor: 'Nest', product: 'Thermostat', username: 'admin', password: 'admin', service: 'HTTP', port: 80 },
      { vendor: 'Hikvision', product: 'IP Camera', username: 'admin', password: '12345', service: 'HTTP', port: 80 },
      { vendor: 'Dahua', product: 'DVR', username: 'admin', password: 'admin', service: 'HTTP', port: 80 },
      { vendor: 'TP-Link', product: 'Router', username: 'admin', password: 'admin', service: 'HTTP', port: 80 },
      { vendor: 'D-Link', product: 'Router', username: 'admin', password: '', service: 'HTTP', port: 80 },
      { vendor: 'Netgear', product: 'Router', username: 'admin', password: 'password', service: 'HTTP', port: 80 },
      { vendor: 'Linksys', product: 'Router', username: 'admin', password: 'admin', service: 'HTTP', port: 80 },
      { vendor: 'Cisco', product: 'Router', username: 'cisco', password: 'cisco', service: 'SSH', port: 22 },
      { vendor: 'Ubiquiti', product: 'AP', username: 'ubnt', password: 'ubnt', service: 'SSH', port: 22 },
      { vendor: 'MikroTik', product: 'RouterOS', username: 'admin', password: '', service: 'SSH', port: 22 },
      { vendor: 'ZTE', product: 'Router', username: 'admin', password: 'admin', service: 'Telnet', port: 23 },
      { vendor: 'Huawei', product: 'Router', username: 'admin', password: 'admin', service: 'HTTP', port: 80 },
      { vendor: 'Samsung', product: 'SmartThings', username: 'admin', password: '1234', service: 'HTTP', port: 80 },
      { vendor: 'Ring', product: 'Doorbell', username: 'ring', password: 'ring123', service: 'HTTP', port: 80 },
      { vendor: 'Wyze', product: 'Camera', username: 'admin', password: 'wyze', service: 'HTTP', port: 80 }
    ];

    const insertCred = db.prepare(`
      INSERT INTO default_credentials (id, vendor, product, username, password, service, port)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    for (const cred of defaultCreds) {
      insertCred.run(uuidv4(), cred.vendor, cred.product, cred.username, cred.password, cred.service, cred.port);
    }
    logger.info('Default credentials database seeded');
  }

  // Seed default settings
  const settingsExist = db.prepare('SELECT COUNT(*) as count FROM settings').get();
  if (settingsExist.count === 0) {
    const defaultSettings = [
      { key: 'scan_interval', value: '300000', category: 'scanner' },
      { key: 'scan_timeout', value: '5000', category: 'scanner' },
      { key: 'scan_subnet', value: '192.168.1.0/24', category: 'scanner' },
      { key: 'auto_quarantine', value: 'false', category: 'security' },
      { key: 'quarantine_threshold', value: '80', category: 'security' },
      { key: 'alert_email', value: '', category: 'notifications' },
      { key: 'alert_webhook', value: '', category: 'notifications' },
      { key: 'dark_mode', value: 'true', category: 'ui' },
      { key: 'packet_capture_enabled', value: 'true', category: 'monitoring' },
      { key: 'packet_capture_limit', value: '1000', category: 'monitoring' }
    ];

    const insertSetting = db.prepare('INSERT INTO settings (key, value, category) VALUES (?, ?, ?)');
    for (const setting of defaultSettings) {
      insertSetting.run(setting.key, setting.value, setting.category);
    }
    logger.info('Default settings seeded');
  }

  // Save database to file
  db.save();
  logger.info('Database initialization complete');
  return db;
}

// Save database periodically and on shutdown
function saveDatabase() {
  if (db) {
    db.save();
    logger.info('Database saved to disk');
  }
}

module.exports = { getDatabase, initializeDatabase, saveDatabase };
