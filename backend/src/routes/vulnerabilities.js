const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { getDatabase } = require('../database/init');
const { authenticate } = require('../middleware/auth');
const { logAudit } = require('../middleware/audit');
const logger = require('../utils/logger');

const router = express.Router();

// Get all vulnerabilities
router.get('/', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { severity, status, device_id, has_exploit, limit = 100, offset = 0 } = req.query;
    
    let query = `
      SELECT v.*, d.name as device_name, d.ip as device_ip 
      FROM vulnerabilities v
      LEFT JOIN devices d ON v.device_id = d.id
      WHERE 1=1
    `;
    const params = [];

    if (severity) {
      query += ' AND v.severity = ?';
      params.push(severity);
    }
    if (status) {
      query += ' AND v.status = ?';
      params.push(status);
    }
    if (device_id) {
      query += ' AND v.device_id = ?';
      params.push(device_id);
    }
    if (has_exploit === 'true') {
      query += ' AND v.exploit_available = 1';
    }

    query += ' ORDER BY v.cvss_score DESC, v.discovered_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));

    const vulnerabilities = db.prepare(query).all(...params);

    res.json(vulnerabilities);
  } catch (error) {
    logger.error('Get vulnerabilities error:', error);
    res.status(500).json({ error: 'Failed to fetch vulnerabilities' });
  }
});

// Get vulnerability by ID
router.get('/:id', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const vulnerability = db.prepare(`
      SELECT v.*, d.name as device_name, d.ip as device_ip 
      FROM vulnerabilities v
      LEFT JOIN devices d ON v.device_id = d.id
      WHERE v.id = ?
    `).get(req.params.id);
    
    if (!vulnerability) {
      return res.status(404).json({ error: 'Vulnerability not found' });
    }

    res.json(vulnerability);
  } catch (error) {
    logger.error('Get vulnerability error:', error);
    res.status(500).json({ error: 'Failed to fetch vulnerability' });
  }
});

// Update vulnerability status (mark as resolved, etc.)
router.put('/:id', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { status } = req.body;

    const vulnerability = db.prepare('SELECT * FROM vulnerabilities WHERE id = ?').get(req.params.id);
    if (!vulnerability) {
      return res.status(404).json({ error: 'Vulnerability not found' });
    }

    const resolvedAt = status === 'resolved' ? new Date().toISOString() : null;

    db.prepare(`
      UPDATE vulnerabilities SET status = ?, resolved_at = ?
      WHERE id = ?
    `).run(status, resolvedAt, req.params.id);

    logAudit(req.user.id, 'VULNERABILITY_UPDATED', 'vulnerability', req.params.id, { status }, req);

    // Recalculate device risk score
    if (vulnerability.device_id) {
      recalculateDeviceRisk(vulnerability.device_id);
    }

    const updated = db.prepare('SELECT * FROM vulnerabilities WHERE id = ?').get(req.params.id);
    res.json(updated);
  } catch (error) {
    logger.error('Update vulnerability error:', error);
    res.status(500).json({ error: 'Failed to update vulnerability' });
  }
});

// Get vulnerability statistics
router.get('/stats/summary', authenticate, (req, res) => {
  try {
    const db = getDatabase();

    const total = db.prepare('SELECT COUNT(*) as count FROM vulnerabilities').get().count;
    const open = db.prepare("SELECT COUNT(*) as count FROM vulnerabilities WHERE status = 'open'").get().count;
    const withExploit = db.prepare('SELECT COUNT(*) as count FROM vulnerabilities WHERE exploit_available = 1').get().count;

    const bySeverity = db.prepare(`
      SELECT severity, COUNT(*) as count 
      FROM vulnerabilities 
      WHERE status = 'open'
      GROUP BY severity
    `).all();

    const topVulnerable = db.prepare(`
      SELECT d.id, d.name, d.ip, COUNT(v.id) as vuln_count
      FROM devices d
      JOIN vulnerabilities v ON d.id = v.device_id
      WHERE v.status = 'open'
      GROUP BY d.id
      ORDER BY vuln_count DESC
      LIMIT 5
    `).all();

    const recentCritical = db.prepare(`
      SELECT v.*, d.name as device_name
      FROM vulnerabilities v
      LEFT JOIN devices d ON v.device_id = d.id
      WHERE v.severity = 'critical' AND v.status = 'open'
      ORDER BY v.discovered_at DESC
      LIMIT 10
    `).all();

    res.json({
      total,
      open,
      withExploit,
      bySeverity,
      topVulnerable,
      recentCritical
    });
  } catch (error) {
    logger.error('Get vulnerability stats error:', error);
    res.status(500).json({ error: 'Failed to fetch vulnerability statistics' });
  }
});

// Helper function to recalculate device risk
function recalculateDeviceRisk(deviceId) {
  const db = getDatabase();
  
  const vulnerabilities = db.prepare(`
    SELECT severity FROM vulnerabilities 
    WHERE device_id = ? AND status = 'open'
  `).all(deviceId);

  let riskScore = 0;
  const severityWeights = { critical: 40, high: 25, medium: 10, low: 5 };

  for (const vuln of vulnerabilities) {
    riskScore += severityWeights[vuln.severity] || 0;
  }

  // Cap at 100
  riskScore = Math.min(riskScore, 100);

  // Determine risk level
  let riskLevel = 'safe';
  if (riskScore >= 80) riskLevel = 'critical';
  else if (riskScore >= 60) riskLevel = 'high';
  else if (riskScore >= 30) riskLevel = 'medium';
  else if (riskScore > 0) riskLevel = 'low';

  db.prepare(`
    UPDATE devices SET risk_score = ?, risk_level = ?, updated_at = ?
    WHERE id = ?
  `).run(riskScore, riskLevel, new Date().toISOString(), deviceId);
}

module.exports = router;
