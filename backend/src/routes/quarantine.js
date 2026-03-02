const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { getDatabase } = require('../database/init');
const { authenticate } = require('../middleware/auth');
const { logAudit } = require('../middleware/audit');
const logger = require('../utils/logger');

const router = express.Router();

// Get all quarantined devices
router.get('/', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { limit = 50, offset = 0 } = req.query;

    const devices = db.prepare(`
      SELECT d.*, 
        (SELECT COUNT(*) FROM vulnerabilities WHERE device_id = d.id AND status = 'open') as open_vulnerabilities
      FROM devices d
      WHERE d.status = 'quarantined'
      ORDER BY d.quarantined_at DESC
      LIMIT ? OFFSET ?
    `).all(parseInt(limit), parseInt(offset));

    const total = db.prepare("SELECT COUNT(*) as count FROM devices WHERE status = 'quarantined'").get().count;

    res.json({
      data: devices,
      pagination: {
        total,
        limit: parseInt(limit),
        offset: parseInt(offset),
        hasMore: parseInt(offset) + devices.length < total
      }
    });
  } catch (error) {
    logger.error('Get quarantined devices error:', error);
    res.status(500).json({ error: 'Failed to fetch quarantined devices' });
  }
});

// Get quarantine details for a device
router.get('/:deviceId', authenticate, (req, res) => {
  try {
    const db = getDatabase();

    const device = db.prepare(`
      SELECT * FROM devices WHERE id = ? AND status = 'quarantined'
    `).get(req.params.deviceId);

    if (!device) {
      return res.status(404).json({ error: 'Quarantined device not found' });
    }

    // Get vulnerabilities
    const vulnerabilities = db.prepare(`
      SELECT * FROM vulnerabilities WHERE device_id = ? AND status = 'open'
    `).all(req.params.deviceId);

    // Get quarantine history from audit logs
    const quarantineHistory = db.prepare(`
      SELECT * FROM audit_logs 
      WHERE resource_type = 'device' AND resource_id = ?
      AND action IN ('DEVICE_QUARANTINED', 'DEVICE_UNQUARANTINED')
      ORDER BY timestamp DESC
    `).all(req.params.deviceId);

    res.json({
      device,
      vulnerabilities,
      quarantineHistory: quarantineHistory.map(log => ({
        ...log,
        details: log.details ? JSON.parse(log.details) : null
      }))
    });
  } catch (error) {
    logger.error('Get quarantine details error:', error);
    res.status(500).json({ error: 'Failed to fetch quarantine details' });
  }
});

// Quarantine a device
router.post('/:deviceId', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { reason, autoRelease, releaseAfter } = req.body;

    const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(req.params.deviceId);
    if (!device) {
      return res.status(404).json({ error: 'Device not found' });
    }

    if (device.status === 'quarantined') {
      return res.status(400).json({ error: 'Device is already quarantined' });
    }

    const now = new Date().toISOString();
    let releaseAt = null;
    if (autoRelease && releaseAfter) {
      const releaseDate = new Date();
      releaseDate.setHours(releaseDate.getHours() + parseInt(releaseAfter));
      releaseAt = releaseDate.toISOString();
    }

    db.prepare(`
      UPDATE devices SET 
        status = 'quarantined',
        quarantined_at = ?,
        quarantine_reason = ?,
        quarantine_release_at = ?,
        previous_status = ?,
        updated_at = ?
      WHERE id = ?
    `).run(now, reason || 'Manual quarantine', releaseAt, device.status, now, req.params.deviceId);

    // Create alert
    const alertId = uuidv4();
    db.prepare(`
      INSERT INTO alerts (id, device_id, type, severity, title, message, created_at)
      VALUES (?, ?, 'quarantine', 'high', ?, ?, ?)
    `).run(
      alertId,
      req.params.deviceId,
      `Device Quarantined: ${device.name}`,
      reason || 'Device has been quarantined',
      now
    );

    logAudit(req.user.id, 'DEVICE_QUARANTINED', 'device', req.params.deviceId, {
      reason,
      autoRelease,
      releaseAt,
      previousStatus: device.status
    }, req);

    const updated = db.prepare('SELECT * FROM devices WHERE id = ?').get(req.params.deviceId);
    res.json(updated);
  } catch (error) {
    logger.error('Quarantine device error:', error);
    res.status(500).json({ error: 'Failed to quarantine device' });
  }
});

// Release a device from quarantine
router.delete('/:deviceId', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { reason } = req.body;

    const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(req.params.deviceId);
    if (!device) {
      return res.status(404).json({ error: 'Device not found' });
    }

    if (device.status !== 'quarantined') {
      return res.status(400).json({ error: 'Device is not quarantined' });
    }

    const now = new Date().toISOString();
    const newStatus = device.previous_status || 'online';

    db.prepare(`
      UPDATE devices SET 
        status = ?,
        quarantined_at = NULL,
        quarantine_reason = NULL,
        quarantine_release_at = NULL,
        previous_status = NULL,
        updated_at = ?
      WHERE id = ?
    `).run(newStatus, now, req.params.deviceId);

    // Create alert
    const alertId = uuidv4();
    db.prepare(`
      INSERT INTO alerts (id, device_id, type, severity, title, message, created_at)
      VALUES (?, ?, 'quarantine', 'info', ?, ?, ?)
    `).run(
      alertId,
      req.params.deviceId,
      `Device Released: ${device.name}`,
      reason || 'Device has been released from quarantine',
      now
    );

    logAudit(req.user.id, 'DEVICE_UNQUARANTINED', 'device', req.params.deviceId, {
      reason,
      newStatus,
      quarantineDuration: device.quarantined_at ? 
        Math.round((new Date() - new Date(device.quarantined_at)) / 1000 / 60) + ' minutes' : 'unknown'
    }, req);

    const updated = db.prepare('SELECT * FROM devices WHERE id = ?').get(req.params.deviceId);
    res.json(updated);
  } catch (error) {
    logger.error('Release device error:', error);
    res.status(500).json({ error: 'Failed to release device from quarantine' });
  }
});

// Bulk quarantine devices
router.post('/bulk', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { deviceIds, reason } = req.body;

    if (!deviceIds || !Array.isArray(deviceIds) || deviceIds.length === 0) {
      return res.status(400).json({ error: 'Device IDs are required' });
    }

    const now = new Date().toISOString();
    const results = { success: [], failed: [] };

    for (const deviceId of deviceIds) {
      try {
        const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceId);
        if (!device) {
          results.failed.push({ deviceId, error: 'Device not found' });
          continue;
        }

        if (device.status === 'quarantined') {
          results.failed.push({ deviceId, error: 'Already quarantined' });
          continue;
        }

        db.prepare(`
          UPDATE devices SET 
            status = 'quarantined',
            quarantined_at = ?,
            quarantine_reason = ?,
            previous_status = ?,
            updated_at = ?
          WHERE id = ?
        `).run(now, reason || 'Bulk quarantine', device.status, now, deviceId);

        results.success.push(deviceId);

        logAudit(req.user.id, 'DEVICE_QUARANTINED', 'device', deviceId, {
          reason: reason || 'Bulk quarantine',
          bulkOperation: true
        }, req);
      } catch (err) {
        results.failed.push({ deviceId, error: err.message });
      }
    }

    res.json({
      message: `Quarantined ${results.success.length} devices`,
      results
    });
  } catch (error) {
    logger.error('Bulk quarantine error:', error);
    res.status(500).json({ error: 'Failed to perform bulk quarantine' });
  }
});

// Bulk release devices
router.delete('/bulk', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { deviceIds, reason } = req.body;

    if (!deviceIds || !Array.isArray(deviceIds) || deviceIds.length === 0) {
      return res.status(400).json({ error: 'Device IDs are required' });
    }

    const now = new Date().toISOString();
    const results = { success: [], failed: [] };

    for (const deviceId of deviceIds) {
      try {
        const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceId);
        if (!device) {
          results.failed.push({ deviceId, error: 'Device not found' });
          continue;
        }

        if (device.status !== 'quarantined') {
          results.failed.push({ deviceId, error: 'Not quarantined' });
          continue;
        }

        db.prepare(`
          UPDATE devices SET 
            status = ?,
            quarantined_at = NULL,
            quarantine_reason = NULL,
            previous_status = NULL,
            updated_at = ?
          WHERE id = ?
        `).run(device.previous_status || 'online', now, deviceId);

        results.success.push(deviceId);

        logAudit(req.user.id, 'DEVICE_UNQUARANTINED', 'device', deviceId, {
          reason: reason || 'Bulk release',
          bulkOperation: true
        }, req);
      } catch (err) {
        results.failed.push({ deviceId, error: err.message });
      }
    }

    res.json({
      message: `Released ${results.success.length} devices`,
      results
    });
  } catch (error) {
    logger.error('Bulk release error:', error);
    res.status(500).json({ error: 'Failed to perform bulk release' });
  }
});

// Get quarantine statistics
router.get('/stats/summary', authenticate, (req, res) => {
  try {
    const db = getDatabase();

    const total = db.prepare("SELECT COUNT(*) as count FROM devices WHERE status = 'quarantined'").get().count;

    const byReason = db.prepare(`
      SELECT quarantine_reason as reason, COUNT(*) as count 
      FROM devices 
      WHERE status = 'quarantined' AND quarantine_reason IS NOT NULL
      GROUP BY quarantine_reason
    `).all();

    const recentQuarantines = db.prepare(`
      SELECT * FROM devices 
      WHERE status = 'quarantined'
      ORDER BY quarantined_at DESC
      LIMIT 10
    `).all();

    const averageDuration = db.prepare(`
      SELECT AVG(
        CAST((julianday('now') - julianday(quarantined_at)) * 24 * 60 AS INTEGER)
      ) as avg_minutes
      FROM devices 
      WHERE status = 'quarantined' AND quarantined_at IS NOT NULL
    `).get()?.avg_minutes || 0;

    const autoReleaseScheduled = db.prepare(`
      SELECT COUNT(*) as count FROM devices 
      WHERE status = 'quarantined' AND quarantine_release_at IS NOT NULL
    `).get().count;

    res.json({
      total,
      byReason,
      recentQuarantines,
      averageDurationMinutes: Math.round(averageDuration),
      autoReleaseScheduled
    });
  } catch (error) {
    logger.error('Get quarantine stats error:', error);
    res.status(500).json({ error: 'Failed to fetch quarantine statistics' });
  }
});

module.exports = router;
