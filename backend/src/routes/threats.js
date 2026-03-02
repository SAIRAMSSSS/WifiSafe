const express = require('express');
const { getDatabase } = require('../database/init');
const { authenticate } = require('../middleware/auth');
const logger = require('../utils/logger');

const router = express.Router();

// Get all threat intelligence feeds
router.get('/', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { 
      type, 
      severity, 
      status,
      source,
      limit = 50, 
      offset = 0 
    } = req.query;

    let query = 'SELECT * FROM threat_intelligence WHERE 1=1';
    const params = [];

    if (type) {
      query += ' AND type = ?';
      params.push(type);
    }

    if (severity) {
      query += ' AND severity = ?';
      params.push(severity);
    }

    if (status) {
      query += ' AND status = ?';
      params.push(status);
    }

    if (source) {
      query += ' AND source LIKE ?';
      params.push(`%${source}%`);
    }

    query += ' ORDER BY last_seen DESC, severity_score DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));

    const threats = db.prepare(query).all(...params);

    // Parse JSON fields
    const parsedThreats = threats.map(threat => ({
      ...threat,
      indicators: threat.indicators ? JSON.parse(threat.indicators) : [],
      affected_device_types: threat.affected_device_types ? JSON.parse(threat.affected_device_types) : [],
      mitigation_steps: threat.mitigation_steps ? JSON.parse(threat.mitigation_steps) : []
    }));

    res.json(parsedThreats);
  } catch (error) {
    logger.error('Get threats error:', error);
    res.status(500).json({ error: 'Failed to fetch threat intelligence' });
  }
});

// Get threat by ID
router.get('/:id', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const threat = db.prepare('SELECT * FROM threat_intelligence WHERE id = ?').get(req.params.id);

    if (!threat) {
      return res.status(404).json({ error: 'Threat not found' });
    }

    // Parse JSON fields
    const parsedThreat = {
      ...threat,
      indicators: threat.indicators ? JSON.parse(threat.indicators) : [],
      affected_device_types: threat.affected_device_types ? JSON.parse(threat.affected_device_types) : [],
      mitigation_steps: threat.mitigation_steps ? JSON.parse(threat.mitigation_steps) : []
    };

    // Get related alerts
    const relatedAlerts = db.prepare(`
      SELECT * FROM alerts 
      WHERE type = 'threat' AND message LIKE ?
      ORDER BY created_at DESC
      LIMIT 10
    `).all(`%${threat.name}%`);

    res.json({
      ...parsedThreat,
      relatedAlerts
    });
  } catch (error) {
    logger.error('Get threat error:', error);
    res.status(500).json({ error: 'Failed to fetch threat' });
  }
});

// Get threat statistics
router.get('/stats/summary', authenticate, (req, res) => {
  try {
    const db = getDatabase();

    const total = db.prepare('SELECT COUNT(*) as count FROM threat_intelligence').get().count;
    const active = db.prepare("SELECT COUNT(*) as count FROM threat_intelligence WHERE status = 'active'").get().count;

    const byType = db.prepare(`
      SELECT type, COUNT(*) as count 
      FROM threat_intelligence 
      GROUP BY type
    `).all();

    const bySeverity = db.prepare(`
      SELECT severity, COUNT(*) as count 
      FROM threat_intelligence 
      GROUP BY severity
    `).all();

    const recentThreats = db.prepare(`
      SELECT * FROM threat_intelligence
      ORDER BY first_seen DESC
      LIMIT 10
    `).all().map(threat => ({
      ...threat,
      indicators: threat.indicators ? JSON.parse(threat.indicators) : [],
      affected_device_types: threat.affected_device_types ? JSON.parse(threat.affected_device_types) : []
    }));

    const topSources = db.prepare(`
      SELECT source, COUNT(*) as count
      FROM threat_intelligence
      GROUP BY source
      ORDER BY count DESC
      LIMIT 5
    `).all();

    res.json({
      total,
      active,
      byType,
      bySeverity,
      recentThreats,
      topSources
    });
  } catch (error) {
    logger.error('Get threat stats error:', error);
    res.status(500).json({ error: 'Failed to fetch threat statistics' });
  }
});

// Search threats by indicators (IOCs)
router.post('/search-ioc', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { ip, domain, hash, indicators } = req.body;

    const allIndicators = [...(indicators || [])];
    if (ip) allIndicators.push(ip);
    if (domain) allIndicators.push(domain);
    if (hash) allIndicators.push(hash);

    if (allIndicators.length === 0) {
      return res.status(400).json({ error: 'At least one indicator is required' });
    }

    // Search for threats containing any of the indicators
    const threats = db.prepare('SELECT * FROM threat_intelligence').all();
    
    const matchingThreats = threats.filter(threat => {
      const threatIndicators = threat.indicators ? JSON.parse(threat.indicators) : [];
      return allIndicators.some(ioc => 
        threatIndicators.some(ti => 
          ti.toLowerCase().includes(ioc.toLowerCase()) || 
          ioc.toLowerCase().includes(ti.toLowerCase())
        )
      );
    }).map(threat => ({
      ...threat,
      indicators: threat.indicators ? JSON.parse(threat.indicators) : [],
      affected_device_types: threat.affected_device_types ? JSON.parse(threat.affected_device_types) : [],
      mitigation_steps: threat.mitigation_steps ? JSON.parse(threat.mitigation_steps) : []
    }));

    res.json({
      searchedIndicators: allIndicators,
      matchingThreats,
      totalMatches: matchingThreats.length
    });
  } catch (error) {
    logger.error('Search IOC error:', error);
    res.status(500).json({ error: 'Failed to search indicators' });
  }
});

// Check device against threat intelligence
router.post('/check-device', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { deviceId, deviceType, ip, openPorts } = req.body;

    const threats = db.prepare(`
      SELECT * FROM threat_intelligence 
      WHERE status = 'active'
    `).all();

    const matchingThreats = threats.filter(threat => {
      const affectedTypes = threat.affected_device_types ? JSON.parse(threat.affected_device_types) : [];
      const indicators = threat.indicators ? JSON.parse(threat.indicators) : [];

      // Check device type
      if (affectedTypes.length > 0 && deviceType) {
        const typeMatch = affectedTypes.some(t => 
          t.toLowerCase() === deviceType.toLowerCase() ||
          t.toLowerCase() === 'all'
        );
        if (typeMatch) return true;
      }

      // Check IP against indicators
      if (ip && indicators.some(i => i.includes(ip))) {
        return true;
      }

      // Check for port-based threats
      if (openPorts && openPorts.length > 0) {
        const portIndicators = indicators.filter(i => /^\d+$/.test(i));
        if (portIndicators.some(p => openPorts.includes(parseInt(p)))) {
          return true;
        }
      }

      return false;
    }).map(threat => ({
      ...threat,
      indicators: threat.indicators ? JSON.parse(threat.indicators) : [],
      affected_device_types: threat.affected_device_types ? JSON.parse(threat.affected_device_types) : [],
      mitigation_steps: threat.mitigation_steps ? JSON.parse(threat.mitigation_steps) : []
    }));

    res.json({
      deviceId,
      deviceType,
      threatsFound: matchingThreats.length,
      criticalThreats: matchingThreats.filter(t => t.severity === 'critical').length,
      threats: matchingThreats
    });
  } catch (error) {
    logger.error('Check device threats error:', error);
    res.status(500).json({ error: 'Failed to check device against threats' });
  }
});

// Add new threat intelligence (admin only)
router.post('/', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const {
      name,
      type,
      severity,
      description,
      indicators,
      affected_device_types,
      mitigation_steps,
      source
    } = req.body;

    if (!name || !type || !severity) {
      return res.status(400).json({ error: 'Name, type, and severity are required' });
    }

    const id = require('uuid').v4();
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO threat_intelligence 
      (id, name, type, severity, description, indicators, affected_device_types, mitigation_steps, source, status, first_seen, last_seen, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
    `).run(
      id,
      name,
      type,
      severity,
      description || '',
      JSON.stringify(indicators || []),
      JSON.stringify(affected_device_types || []),
      JSON.stringify(mitigation_steps || []),
      source || 'manual',
      now,
      now,
      now
    );

    const threat = db.prepare('SELECT * FROM threat_intelligence WHERE id = ?').get(id);

    res.status(201).json({
      ...threat,
      indicators: JSON.parse(threat.indicators),
      affected_device_types: JSON.parse(threat.affected_device_types),
      mitigation_steps: JSON.parse(threat.mitigation_steps)
    });
  } catch (error) {
    logger.error('Add threat error:', error);
    res.status(500).json({ error: 'Failed to add threat intelligence' });
  }
});

// Update threat status
router.put('/:id/status', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { status } = req.body;

    if (!['active', 'inactive', 'resolved'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const threat = db.prepare('SELECT * FROM threat_intelligence WHERE id = ?').get(req.params.id);
    if (!threat) {
      return res.status(404).json({ error: 'Threat not found' });
    }

    db.prepare(`
      UPDATE threat_intelligence 
      SET status = ?, last_seen = ?
      WHERE id = ?
    `).run(status, new Date().toISOString(), req.params.id);

    const updated = db.prepare('SELECT * FROM threat_intelligence WHERE id = ?').get(req.params.id);

    res.json({
      ...updated,
      indicators: JSON.parse(updated.indicators || '[]'),
      affected_device_types: JSON.parse(updated.affected_device_types || '[]'),
      mitigation_steps: JSON.parse(updated.mitigation_steps || '[]')
    });
  } catch (error) {
    logger.error('Update threat status error:', error);
    res.status(500).json({ error: 'Failed to update threat status' });
  }
});

module.exports = router;
