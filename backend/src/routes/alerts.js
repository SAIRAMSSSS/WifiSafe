const express = require('express');
const { body, validationResult } = require('express-validator');
const { v4: uuidv4 } = require('uuid');
const { getDatabase } = require('../database/init');
const { authenticate, optionalAuth } = require('../middleware/auth');
const { logAudit } = require('../middleware/audit');
const { broadcast } = require('../websocket/server');
const logger = require('../utils/logger');
const { sendCriticalAlert, getAlertEmail, saveAlertEmail, testEmailConnection } = require('../services/emailService');

const router = express.Router();

// Get all alerts (optionalAuth for dev mode)
router.get('/', optionalAuth, (req, res) => {
  try {
    const db = getDatabase();
    const { severity, type, acknowledged, limit = 100, offset = 0 } = req.query;

    let query = 'SELECT * FROM alerts WHERE 1=1';
    const params = [];

    if (severity) {
      query += ' AND severity = ?';
      params.push(severity);
    }
    if (type) {
      query += ' AND type = ?';
      params.push(type);
    }
    if (acknowledged !== undefined) {
      query += ' AND acknowledged = ?';
      params.push(acknowledged === 'true' ? 1 : 0);
    }

    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));

    const alerts = db.prepare(query).all(...params);

    // Get total count
    let countQuery = 'SELECT COUNT(*) as total FROM alerts WHERE 1=1';
    const countParams = [];
    if (severity) {
      countQuery += ' AND severity = ?';
      countParams.push(severity);
    }
    if (type) {
      countQuery += ' AND type = ?';
      countParams.push(type);
    }
    if (acknowledged !== undefined) {
      countQuery += ' AND acknowledged = ?';
      countParams.push(acknowledged === 'true' ? 1 : 0);
    }

    const total = db.prepare(countQuery).get(...countParams).total;

    res.json({
      alerts,
      pagination: {
        total,
        limit: parseInt(limit),
        offset: parseInt(offset)
      }
    });
  } catch (error) {
    logger.error('Get alerts error:', error);
    res.status(500).json({ error: 'Failed to fetch alerts' });
  }
});

// Get alert by ID
router.get('/:id', optionalAuth, (req, res) => {
  try {
    const db = getDatabase();
    const alert = db.prepare('SELECT * FROM alerts WHERE id = ?').get(req.params.id);

    if (!alert) {
      return res.status(404).json({ error: 'Alert not found' });
    }

    res.json(alert);
  } catch (error) {
    logger.error('Get alert error:', error);
    res.status(500).json({ error: 'Failed to fetch alert' });
  }
});

// Create alert (usually automated)
router.post('/', authenticate, [
  body('type').isLength({ min: 1 }),
  body('severity').isIn(['critical', 'high', 'medium', 'low']),
  body('message').isLength({ min: 1 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const db = getDatabase();
    const alertId = uuidv4();
    const { type, severity, device_id, device_ip, device_mac, message, details } = req.body;

    db.prepare(`
      INSERT INTO alerts (id, type, severity, device_id, device_ip, device_mac, message, details)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(alertId, type, severity, device_id || null, device_ip || null, device_mac || null, message, details ? JSON.stringify(details) : null);

    const alert = db.prepare('SELECT * FROM alerts WHERE id = ?').get(alertId);

    // Broadcast to WebSocket clients on the standardized 'alerts' channel
    broadcast('alerts', { event: 'new_alert', alert });

    // Send email alert for critical/high severity
    if (severity === 'critical' || severity === 'high') {
      const alertEmail = getAlertEmail(db);
      if (alertEmail) {
        sendCriticalAlert(alertEmail, {
          title: message,
          severity,
          description: details?.description || message,
          deviceIp: device_ip,
          deviceName: details?.deviceName || device_id,
          timestamp: new Date().toISOString(),
          type
        }).then(result => {
          if (result.success) {
            logger.info(`[Email] Alert email sent for ${alertId}`);
          }
        }).catch(err => {
          logger.error(`[Email] Failed to send alert email: ${err.message}`);
        });
      }
    }

    res.status(201).json(alert);
  } catch (error) {
    logger.error('Create alert error:', error);
    res.status(500).json({ error: 'Failed to create alert' });
  }
});

// Acknowledge alert
router.put('/:id/acknowledge', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const alert = db.prepare('SELECT * FROM alerts WHERE id = ?').get(req.params.id);

    if (!alert) {
      return res.status(404).json({ error: 'Alert not found' });
    }

    db.prepare(`
      UPDATE alerts SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = ?
      WHERE id = ?
    `).run(req.user.id, new Date().toISOString(), req.params.id);

    logAudit(req.user.id, 'ALERT_ACKNOWLEDGED', 'alert', req.params.id, {}, req);

    const updatedAlert = db.prepare('SELECT * FROM alerts WHERE id = ?').get(req.params.id);

    // Broadcast update on the 'alerts' channel
    broadcast('alerts', { event: 'alert_acknowledged', alert: updatedAlert, alertId: updatedAlert.id });

    res.json(updatedAlert);
  } catch (error) {
    logger.error('Acknowledge alert error:', error);
    res.status(500).json({ error: 'Failed to acknowledge alert' });
  }
});

// Acknowledge multiple alerts
router.post('/acknowledge-bulk', authenticate, [
  body('alertIds').isArray()
], (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const db = getDatabase();
    const { alertIds } = req.body;
    const now = new Date().toISOString();

    const stmt = db.prepare(`
      UPDATE alerts SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = ?
      WHERE id = ?
    `);

    const transaction = db.transaction(() => {
      for (const alertId of alertIds) {
        stmt.run(req.user.id, now, alertId);
      }
    });

    transaction();

    logAudit(req.user.id, 'ALERTS_BULK_ACKNOWLEDGED', 'alert', null, { count: alertIds.length }, req);

    // Broadcast bulk acknowledgement
    broadcast('alerts', { event: 'bulk_acknowledged', alertIds, count: alertIds.length });

    res.json({ message: `${alertIds.length} alerts acknowledged` });
  } catch (error) {
    logger.error('Bulk acknowledge error:', error);
    res.status(500).json({ error: 'Failed to acknowledge alerts' });
  }
});

// Delete alert
router.delete('/:id', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const alert = db.prepare('SELECT * FROM alerts WHERE id = ?').get(req.params.id);

    if (!alert) {
      return res.status(404).json({ error: 'Alert not found' });
    }

    db.prepare('DELETE FROM alerts WHERE id = ?').run(req.params.id);

    logAudit(req.user.id, 'ALERT_DELETED', 'alert', req.params.id, {}, req);

    res.json({ message: 'Alert deleted successfully' });
  } catch (error) {
    logger.error('Delete alert error:', error);
    res.status(500).json({ error: 'Failed to delete alert' });
  }
});

// Get alert statistics
router.get('/stats/summary', optionalAuth, (req, res) => {
  try {
    const db = getDatabase();

    const total = db.prepare('SELECT COUNT(*) as count FROM alerts').get().count;
    const unacknowledged = db.prepare('SELECT COUNT(*) as count FROM alerts WHERE acknowledged = 0').get().count;

    const bySeverity = db.prepare(`
      SELECT severity, COUNT(*) as count 
      FROM alerts 
      WHERE acknowledged = 0 
      GROUP BY severity
    `).all();

    const byType = db.prepare(`
      SELECT type, COUNT(*) as count 
      FROM alerts 
      GROUP BY type 
      ORDER BY count DESC
    `).all();

    const recent = db.prepare(`
      SELECT * FROM alerts 
      ORDER BY created_at DESC 
      LIMIT 5
    `).all();

    res.json({
      total,
      unacknowledged,
      bySeverity,
      byType,
      recent
    });
  } catch (error) {
    logger.error('Get alert stats error:', error);
    res.status(500).json({ error: 'Failed to fetch alert statistics' });
  }
});

// ============ EMAIL ALERT SETTINGS ============

// Get email alert settings
router.get('/settings/email', optionalAuth, (req, res) => {
  try {
    const db = getDatabase();
    const email = getAlertEmail(db);
    res.json({
      email: email || null,
      enabled: !!email
    });
  } catch (error) {
    logger.error('Get email settings error:', error);
    res.status(500).json({ error: 'Failed to fetch email settings' });
  }
});

// Save email alert settings
router.post('/settings/email', optionalAuth, [
  body('email').isEmail().withMessage('Valid email is required')
], (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const db = getDatabase();
    const { email } = req.body;

    const result = saveAlertEmail(db, email);

    if (req.user) {
      logAudit(req.user.id, 'ALERT_EMAIL_UPDATED', 'settings', 'alert_email', { email }, req);
    }

    logger.info(`[Email] Alert email set to: ${email}`);

    res.json({
      success: true,
      email,
      message: 'Email settings saved successfully'
    });
  } catch (error) {
    logger.error('Save email settings error:', error);
    res.status(500).json({ error: 'Failed to save email settings' });
  }
});

// Test email connection
router.post('/settings/email/test', optionalAuth, async (req, res) => {
  try {
    const db = getDatabase();
    const email = req.body.email || getAlertEmail(db);

    if (!email) {
      return res.status(400).json({ error: 'No email configured' });
    }

    const result = await testEmailConnection(email);

    if (result.success) {
      res.json({
        success: true,
        message: 'Test email sent successfully',
        messageId: result.messageId
      });
    } else {
      res.status(500).json({
        success: false,
        error: result.reason
      });
    }
  } catch (error) {
    logger.error('Test email error:', error);
    res.status(500).json({ error: 'Failed to test email' });
  }
});

// Delete email alert settings
router.delete('/settings/email', optionalAuth, (req, res) => {
  try {
    const db = getDatabase();
    db.prepare('DELETE FROM settings WHERE key = ?').run('alert_email');

    if (req.user) {
      logAudit(req.user.id, 'ALERT_EMAIL_DELETED', 'settings', 'alert_email', {}, req);
    }

    logger.info('[Email] Alert email cleared');

    res.json({ success: true, message: 'Email settings cleared' });
  } catch (error) {
    logger.error('Delete email settings error:', error);
    res.status(500).json({ error: 'Failed to delete email settings' });
  }
});

module.exports = router;
