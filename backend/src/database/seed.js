const { v4: uuidv4 } = require('uuid');
const { getDatabase, saveDatabase } = require('./init');
const logger = require('../utils/logger');

function seedDemoData() {
  const db = getDatabase();

  // Check if demo data already exists
  const deviceCount = db.prepare('SELECT COUNT(*) as count FROM devices').get().count;
  if (deviceCount > 0) {
    logger.info('Demo data already exists, skipping seed');
    return;
  }

  logger.info('Seeding demo data...');

  // Seed demo devices
  const devices = [
    {
      id: uuidv4(),
      name: 'Smart Thermostat',
      ip: '192.168.1.10',
      mac: 'AA:BB:CC:DD:EE:01',
      device_type: 'thermostat',
      manufacturer: 'Nest',
      model: 'Learning Thermostat 3rd Gen',
      status: 'online',
      risk_score: 25,
      risk_level: 'low',
      firmware_version: '5.9.3-7'
    },
    {
      id: uuidv4(),
      name: 'IP Camera - Front Door',
      ip: '192.168.1.20',
      mac: 'AA:BB:CC:DD:EE:02',
      device_type: 'camera',
      manufacturer: 'Hikvision',
      model: 'DS-2CD2143G2-I',
      status: 'online',
      risk_score: 75,
      risk_level: 'high',
      firmware_version: '5.6.5'
    },
    {
      id: uuidv4(),
      name: 'Smart Lock - Main Entry',
      ip: '192.168.1.30',
      mac: 'AA:BB:CC:DD:EE:03',
      device_type: 'lock',
      manufacturer: 'August',
      model: 'Smart Lock Pro',
      status: 'online',
      risk_score: 45,
      risk_level: 'medium',
      firmware_version: '1.59.0'
    },
    {
      id: uuidv4(),
      name: 'Network Router',
      ip: '192.168.1.1',
      mac: 'AA:BB:CC:DD:EE:04',
      device_type: 'router',
      manufacturer: 'TP-Link',
      model: 'Archer AX6000',
      status: 'online',
      risk_score: 30,
      risk_level: 'low',
      firmware_version: '1.3.1'
    },
    {
      id: uuidv4(),
      name: 'Smart TV - Living Room',
      ip: '192.168.1.40',
      mac: 'AA:BB:CC:DD:EE:05',
      device_type: 'smart_tv',
      manufacturer: 'Samsung',
      model: 'QN65Q80A',
      status: 'online',
      risk_score: 20,
      risk_level: 'low',
      firmware_version: '1620.0'
    },
    {
      id: uuidv4(),
      name: 'Voice Assistant',
      ip: '192.168.1.50',
      mac: 'AA:BB:CC:DD:EE:06',
      device_type: 'voice_assistant',
      manufacturer: 'Amazon',
      model: 'Echo Dot 4th Gen',
      status: 'online',
      risk_score: 15,
      risk_level: 'low',
      firmware_version: '6736984172'
    },
    {
      id: uuidv4(),
      name: 'NAS Storage',
      ip: '192.168.1.100',
      mac: 'AA:BB:CC:DD:EE:07',
      device_type: 'nas',
      manufacturer: 'Synology',
      model: 'DS920+',
      status: 'online',
      risk_score: 55,
      risk_level: 'medium',
      firmware_version: 'DSM 7.1.1'
    },
    {
      id: uuidv4(),
      name: 'Smart Doorbell',
      ip: '192.168.1.60',
      mac: 'AA:BB:CC:DD:EE:08',
      device_type: 'doorbell',
      manufacturer: 'Ring',
      model: 'Video Doorbell Pro 2',
      status: 'online',
      risk_score: 35,
      risk_level: 'medium',
      firmware_version: '3.54.0'
    }
  ];

  const insertDevice = db.prepare(`
    INSERT INTO devices (id, name, ip, mac, device_type, manufacturer, model, status, risk_score, risk_level, firmware_version, discovered_at, last_seen)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const now = new Date().toISOString();
  for (const device of devices) {
    insertDevice.run(
      device.id, device.name, device.ip, device.mac, device.device_type,
      device.manufacturer, device.model, device.status, device.risk_score,
      device.risk_level, device.firmware_version, now, now
    );
  }

  // Seed some vulnerabilities
  const vulnerabilities = [
    {
      device_id: devices[1].id, // Camera
      title: 'Default Credentials Detected',
      severity: 'critical',
      description: 'Device is using factory default username and password',
      cve_id: null,
      cvss_score: 9.8
    },
    {
      device_id: devices[1].id, // Camera
      title: 'CVE-2021-36260 - Command Injection',
      severity: 'critical',
      description: 'Web server vulnerability allows remote code execution',
      cve_id: 'CVE-2021-36260',
      cvss_score: 9.8
    },
    {
      device_id: devices[6].id, // NAS
      title: 'Outdated SSL/TLS Configuration',
      severity: 'medium',
      description: 'Server supports deprecated TLS 1.0 protocol',
      cve_id: null,
      cvss_score: 5.3
    },
    {
      device_id: devices[3].id, // Router
      title: 'UPnP Enabled',
      severity: 'low',
      description: 'Universal Plug and Play is enabled, which can be exploited',
      cve_id: null,
      cvss_score: 3.5
    },
    {
      device_id: devices[2].id, // Smart Lock
      title: 'Bluetooth Vulnerability',
      severity: 'high',
      description: 'BLE implementation vulnerable to replay attacks',
      cve_id: 'CVE-2020-13587',
      cvss_score: 7.5
    }
  ];

  const insertVuln = db.prepare(`
    INSERT INTO vulnerabilities (id, device_id, title, severity, description, cve_id, cvss_score, status, discovered_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?)
  `);

  for (const vuln of vulnerabilities) {
    insertVuln.run(
      uuidv4(), vuln.device_id, vuln.title, vuln.severity,
      vuln.description, vuln.cve_id, vuln.cvss_score, now
    );
  }

  // Seed some alerts
  const alerts = [
    {
      type: 'vulnerability',
      severity: 'critical',
      device_id: devices[1].id,
      message: 'Critical vulnerability detected on IP Camera - Default credentials in use'
    },
    {
      type: 'anomaly',
      severity: 'high',
      device_id: devices[1].id,
      message: 'Unusual outbound traffic detected from IP Camera to unknown external IP'
    },
    {
      type: 'new_device',
      severity: 'info',
      device_id: devices[7].id,
      message: 'New device discovered on network: Smart Doorbell'
    },
    {
      type: 'credential',
      severity: 'high',
      device_id: devices[1].id,
      message: 'Device using default manufacturer credentials'
    }
  ];

  const insertAlert = db.prepare(`
    INSERT INTO alerts (id, type, severity, device_id, message, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  for (const alert of alerts) {
    insertAlert.run(
      uuidv4(), alert.type, alert.severity, alert.device_id, alert.message, now
    );
  }

  // Seed CVE database
  const cves = [
    {
      cve_id: 'CVE-2021-36260',
      title: 'Hikvision Web Server Command Injection',
      description: 'A command injection vulnerability exists in the web server of some Hikvision products due to insufficient input validation.',
      severity: 'critical',
      cvss_score: 9.8,
      vendor: 'Hikvision',
      affected_products: 'IP Cameras, NVRs, DVRs',
      exploit_available: 1
    },
    {
      cve_id: 'CVE-2020-13587',
      title: 'BLE Implementation Replay Attack',
      description: 'A vulnerability in Bluetooth Low Energy implementations allows attackers to replay captured authentication sequences.',
      severity: 'high',
      cvss_score: 7.5,
      vendor: 'Multiple',
      affected_products: 'Smart Locks, IoT Devices',
      exploit_available: 1
    },
    {
      cve_id: 'CVE-2022-27255',
      title: 'Realtek SDK Buffer Overflow',
      description: 'A stack-based buffer overflow vulnerability in Realtek SDK allows remote code execution.',
      severity: 'critical',
      cvss_score: 9.8,
      vendor: 'Realtek',
      affected_products: 'Routers, Access Points',
      exploit_available: 1
    },
    {
      cve_id: 'CVE-2023-20073',
      title: 'Cisco Small Business Router RCE',
      description: 'A vulnerability in the web-based management interface of Cisco Small Business RV Series Routers.',
      severity: 'critical',
      cvss_score: 9.8,
      vendor: 'Cisco',
      affected_products: 'RV160, RV260, RV340, RV345',
      exploit_available: 0
    }
  ];

  const insertCve = db.prepare(`
    INSERT INTO cve_database (id, cve_id, title, description, severity, cvss_score, vendor, affected_products, exploit_available, published_date)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const cve of cves) {
    insertCve.run(
      uuidv4(), cve.cve_id, cve.title, cve.description, cve.severity,
      cve.cvss_score, cve.vendor, cve.affected_products, cve.exploit_available, now
    );
  }

  // Seed threat intelligence
  const threats = [
    {
      name: 'Mirai Botnet Variant',
      type: 'malware',
      severity: 'critical',
      description: 'New variant of Mirai botnet targeting IoT devices with default credentials',
      indicators: JSON.stringify(['185.244.25.0/24', 'scan-mirai.net']),
      affected_device_types: JSON.stringify(['camera', 'router', 'dvr']),
      source: 'Threat Intelligence Feed'
    },
    {
      name: 'IoT Credential Stuffing Campaign',
      type: 'attack',
      severity: 'high',
      description: 'Large-scale credential stuffing attacks targeting IoT device management interfaces',
      indicators: JSON.stringify(['45.155.205.0/24']),
      affected_device_types: JSON.stringify(['camera', 'nas', 'router']),
      source: 'CISA Alert'
    }
  ];

  const insertThreat = db.prepare(`
    INSERT INTO threat_intelligence (id, name, type, severity, description, indicators, affected_device_types, source, status, first_seen, last_seen)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
  `);

  for (const threat of threats) {
    insertThreat.run(
      uuidv4(), threat.name, threat.type, threat.severity, threat.description,
      threat.indicators, threat.affected_device_types, threat.source, now, now
    );
  }

  // Seed some ports for devices
  const ports = [
    { device_id: devices[1].id, port: 80, service: 'HTTP', status: 'open' },
    { device_id: devices[1].id, port: 443, service: 'HTTPS', status: 'open' },
    { device_id: devices[1].id, port: 554, service: 'RTSP', status: 'open' },
    { device_id: devices[3].id, port: 80, service: 'HTTP', status: 'open' },
    { device_id: devices[3].id, port: 443, service: 'HTTPS', status: 'open' },
    { device_id: devices[3].id, port: 22, service: 'SSH', status: 'open' },
    { device_id: devices[6].id, port: 5000, service: 'Synology DSM', status: 'open' },
    { device_id: devices[6].id, port: 5001, service: 'Synology DSM SSL', status: 'open' }
  ];

  const insertPort = db.prepare(`
    INSERT INTO ports (id, device_id, port_number, service_name, status)
    VALUES (?, ?, ?, ?, ?)
  `);

  for (const port of ports) {
    insertPort.run(uuidv4(), port.device_id, port.port, port.service, port.status);
  }

  // Save database after seeding
  saveDatabase();
  logger.info('Demo data seeded successfully');
}

module.exports = { seedDemoData };
