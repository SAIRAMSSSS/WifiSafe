const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { getDatabase } = require('../database/init');
const { authenticate } = require('../middleware/auth');
const { logAudit } = require('../middleware/audit');
const logger = require('../utils/logger');

const router = express.Router();

// Get all default credentials from database
router.get('/', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { vendor, service, search, limit = 100, offset = 0 } = req.query;

    let query = 'SELECT * FROM default_credentials WHERE 1=1';
    const params = [];

    if (vendor) {
      query += ' AND vendor LIKE ?';
      params.push(`%${vendor}%`);
    }

    if (service) {
      query += ' AND service = ?';
      params.push(service);
    }

    if (search) {
      query += ' AND (vendor LIKE ? OR product LIKE ? OR username LIKE ?)';
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    query += ' ORDER BY vendor LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));

    const credentials = db.prepare(query).all(...params);
    const total = db.prepare('SELECT COUNT(*) as count FROM default_credentials').get().count;

    res.json({
      data: credentials,
      pagination: {
        total,
        limit: parseInt(limit),
        offset: parseInt(offset),
        hasMore: parseInt(offset) + credentials.length < total
      }
    });
  } catch (error) {
    logger.error('Get credentials error:', error);
    res.status(500).json({ error: 'Failed to fetch credentials database' });
  }
});

// Check device for default credentials
router.post('/check-device', authenticate, async (req, res) => {
  try {
    const { deviceId, manufacturer, deviceType, ip, ports } = req.body;
    const db = getDatabase();

    // Find matching credentials from database
    let query = 'SELECT * FROM default_credentials WHERE 1=1';
    const params = [];

    if (manufacturer) {
      query += ' AND (vendor LIKE ? OR vendor = ?)';
      params.push(`%${manufacturer}%`, 'Generic');
    }

    const matchingCredentials = db.prepare(query).all(...params);

    // Simulate credential check (in production, this would attempt actual connections)
    const vulnerableCredentials = matchingCredentials.map(cred => ({
      vendor: cred.vendor,
      product: cred.product,
      username: cred.username,
      password: cred.password,
      service: cred.service,
      port: cred.port,
      status: 'potential', // 'vulnerable', 'safe', 'potential'
      testedAt: new Date().toISOString()
    }));

    // Update device status if vulnerable
    if (deviceId && vulnerableCredentials.length > 0) {
      db.prepare(`
        UPDATE devices SET has_weak_credentials = 1, updated_at = ?
        WHERE id = ?
      `).run(new Date().toISOString(), deviceId);
    }

    logAudit(req.user?.id, 'CREDENTIAL_CHECK', 'device', deviceId, { 
      manufacturer, 
      credentialsFound: vulnerableCredentials.length 
    }, req);

    res.json({
      deviceId,
      manufacturer,
      deviceType,
      vulnerableCredentials,
      totalChecked: matchingCredentials.length,
      riskLevel: vulnerableCredentials.length > 0 ? 'high' : 'low'
    });
  } catch (error) {
    logger.error('Check credentials error:', error);
    res.status(500).json({ error: 'Failed to check device credentials' });
  }
});

// Scan network for devices with default credentials
router.post('/scan-network', authenticate, async (req, res) => {
  try {
    const db = getDatabase();

    // Get all online devices
    const devices = db.prepare(`
      SELECT * FROM devices WHERE status = 'online'
    `).all();

    // Get all credentials
    const allCredentials = db.prepare('SELECT * FROM default_credentials').all();

    const results = [];

    for (const device of devices) {
      const matchingCredentials = allCredentials.filter(cred => {
        if (device.manufacturer && cred.vendor.toLowerCase() !== 'generic') {
          return cred.vendor.toLowerCase().includes(device.manufacturer.toLowerCase());
        }
        return cred.vendor.toLowerCase() === 'generic';
      });

      if (matchingCredentials.length > 0) {
        results.push({
          deviceId: device.id,
          deviceName: device.name,
          ip: device.ip,
          manufacturer: device.manufacturer,
          deviceType: device.device_type,
          potentialCredentials: matchingCredentials.length,
          riskLevel: 'high',
          credentials: matchingCredentials.slice(0, 5)
        });

        // Update device
        db.prepare(`
          UPDATE devices SET has_weak_credentials = 1, updated_at = ?
          WHERE id = ?
        `).run(new Date().toISOString(), device.id);
      }
    }

    logAudit(req.user?.id, 'CREDENTIAL_NETWORK_SCAN', 'network', null, {
      devicesScanned: devices.length,
      vulnerableDevices: results.length
    }, req);

    res.json({
      scannedDevices: devices.length,
      vulnerableDevices: results.length,
      results,
      scanTime: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Network credential scan error:', error);
    res.status(500).json({ error: 'Failed to scan network for default credentials' });
  }
});

// Get devices with weak credentials
router.get('/vulnerable-devices', authenticate, (req, res) => {
  try {
    const db = getDatabase();

    const devices = db.prepare(`
      SELECT * FROM devices WHERE has_weak_credentials = 1
    `).all();

    const allCredentials = db.prepare('SELECT * FROM default_credentials').all();

    const devicesWithCredentials = devices.map(device => {
      const matchingCredentials = allCredentials.filter(cred => {
        if (device.manufacturer && cred.vendor.toLowerCase() !== 'generic') {
          return cred.vendor.toLowerCase().includes(device.manufacturer.toLowerCase());
        }
        return cred.vendor.toLowerCase() === 'generic';
      });

      return {
        ...device,
        potentialCredentials: matchingCredentials
      };
    });

    res.json(devicesWithCredentials);
  } catch (error) {
    logger.error('Get vulnerable devices error:', error);
    res.status(500).json({ error: 'Failed to fetch vulnerable devices' });
  }
});

// Add custom credential to database
router.post('/', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { vendor, product, username, password, service, port } = req.body;

    if (!vendor || !username) {
      return res.status(400).json({ error: 'Vendor and username are required' });
    }

    const id = uuidv4();
    db.prepare(`
      INSERT INTO default_credentials (id, vendor, product, username, password, service, port)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, vendor, product || '', username, password || '', service || 'HTTP', port || 80);

    logAudit(req.user?.id, 'CREDENTIAL_ADDED', 'credentials', id, { vendor, username }, req);

    const newCredential = db.prepare('SELECT * FROM default_credentials WHERE id = ?').get(id);
    res.status(201).json(newCredential);
  } catch (error) {
    logger.error('Add credential error:', error);
    res.status(500).json({ error: 'Failed to add credential' });
  }
});

// Get statistics
router.get('/stats', authenticate, (req, res) => {
  try {
    const db = getDatabase();

    const totalCredentials = db.prepare('SELECT COUNT(*) as count FROM default_credentials').get().count;
    
    const byVendor = db.prepare(`
      SELECT vendor, COUNT(*) as count 
      FROM default_credentials 
      GROUP BY vendor 
      ORDER BY count DESC
    `).all();

    const byService = db.prepare(`
      SELECT service, COUNT(*) as count 
      FROM default_credentials 
      GROUP BY service 
      ORDER BY count DESC
    `).all();

    const vulnerableDevices = db.prepare(
      'SELECT COUNT(*) as count FROM devices WHERE has_weak_credentials = 1'
    ).get().count;

    const totalDevices = db.prepare('SELECT COUNT(*) as count FROM devices').get().count;

    res.json({
      totalCredentials,
      byVendor: byVendor.reduce((acc, v) => ({ ...acc, [v.vendor]: v.count }), {}),
      byService: byService.reduce((acc, s) => ({ ...acc, [s.service]: s.count }), {}),
      vulnerableDevices,
      totalDevices,
      vulnerabilityRate: totalDevices > 0 ? ((vulnerableDevices / totalDevices) * 100).toFixed(2) : 0
    });
  } catch (error) {
    logger.error('Get credential stats error:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

module.exports = router;
