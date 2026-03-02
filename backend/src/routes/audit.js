const express = require('express');
const { getDatabase } = require('../database/init');
const { authenticate, authorize } = require('../middleware/auth');
const logger = require('../utils/logger');

const router = express.Router();

// Get audit logs
router.get('/', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { 
      user_id, 
      action, 
      resource_type, 
      resource_id,
      start_date,
      end_date,
      limit = 100, 
      offset = 0 
    } = req.query;

    let query = `
      SELECT al.*, u.username, u.email
      FROM audit_logs al
      LEFT JOIN users u ON al.user_id = u.id
      WHERE 1=1
    `;
    const params = [];

    if (user_id) {
      query += ' AND al.user_id = ?';
      params.push(user_id);
    }

    if (action) {
      query += ' AND al.action = ?';
      params.push(action);
    }

    if (resource_type) {
      query += ' AND al.resource_type = ?';
      params.push(resource_type);
    }

    if (resource_id) {
      query += ' AND al.resource_id = ?';
      params.push(resource_id);
    }

    if (start_date) {
      query += ' AND al.timestamp >= ?';
      params.push(start_date);
    }

    if (end_date) {
      query += ' AND al.timestamp <= ?';
      params.push(end_date);
    }

    query += ' ORDER BY al.timestamp DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));

    const logs = db.prepare(query).all(...params);

    // Parse details JSON
    const parsedLogs = logs.map(log => ({
      ...log,
      details: log.details ? JSON.parse(log.details) : null
    }));

    // Get total count for pagination
    let countQuery = 'SELECT COUNT(*) as count FROM audit_logs al WHERE 1=1';
    const countParams = [];
    if (user_id) { countQuery += ' AND al.user_id = ?'; countParams.push(user_id); }
    if (action) { countQuery += ' AND al.action = ?'; countParams.push(action); }
    if (resource_type) { countQuery += ' AND al.resource_type = ?'; countParams.push(resource_type); }
    if (resource_id) { countQuery += ' AND al.resource_id = ?'; countParams.push(resource_id); }
    if (start_date) { countQuery += ' AND al.timestamp >= ?'; countParams.push(start_date); }
    if (end_date) { countQuery += ' AND al.timestamp <= ?'; countParams.push(end_date); }

    const totalCount = db.prepare(countQuery).get(...countParams)?.count || 0;

    res.json({
      data: parsedLogs,
      pagination: {
        total: totalCount,
        limit: parseInt(limit),
        offset: parseInt(offset),
        hasMore: parseInt(offset) + parsedLogs.length < totalCount
      }
    });
  } catch (error) {
    logger.error('Get audit logs error:', error);
    res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
});

// Get audit log by ID
router.get('/:id', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const log = db.prepare(`
      SELECT al.*, u.username, u.email
      FROM audit_logs al
      LEFT JOIN users u ON al.user_id = u.id
      WHERE al.id = ?
    `).get(req.params.id);

    if (!log) {
      return res.status(404).json({ error: 'Audit log not found' });
    }

    res.json({
      ...log,
      details: log.details ? JSON.parse(log.details) : null
    });
  } catch (error) {
    logger.error('Get audit log error:', error);
    res.status(500).json({ error: 'Failed to fetch audit log' });
  }
});

// Get audit log statistics
router.get('/stats/summary', authenticate, (req, res) => {
  try {
    const db = getDatabase();

    const total = db.prepare('SELECT COUNT(*) as count FROM audit_logs').get().count;

    const byAction = db.prepare(`
      SELECT action, COUNT(*) as count 
      FROM audit_logs 
      GROUP BY action
      ORDER BY count DESC
    `).all();

    const byResourceType = db.prepare(`
      SELECT resource_type, COUNT(*) as count 
      FROM audit_logs 
      WHERE resource_type IS NOT NULL
      GROUP BY resource_type
      ORDER BY count DESC
    `).all();

    const byUser = db.prepare(`
      SELECT u.username, COUNT(*) as count
      FROM audit_logs al
      JOIN users u ON al.user_id = u.id
      GROUP BY al.user_id
      ORDER BY count DESC
      LIMIT 10
    `).all();

    const recentActivity = db.prepare(`
      SELECT al.*, u.username
      FROM audit_logs al
      LEFT JOIN users u ON al.user_id = u.id
      ORDER BY al.timestamp DESC
      LIMIT 20
    `).all().map(log => ({
      ...log,
      details: log.details ? JSON.parse(log.details) : null
    }));

    const activityByHour = db.prepare(`
      SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
      FROM audit_logs
      WHERE timestamp >= datetime('now', '-24 hours')
      GROUP BY strftime('%H', timestamp)
      ORDER BY hour
    `).all();

    const activityByDay = db.prepare(`
      SELECT date(timestamp) as day, COUNT(*) as count
      FROM audit_logs
      WHERE timestamp >= datetime('now', '-30 days')
      GROUP BY date(timestamp)
      ORDER BY day DESC
    `).all();

    res.json({
      total,
      byAction,
      byResourceType,
      byUser,
      recentActivity,
      activityByHour,
      activityByDay
    });
  } catch (error) {
    logger.error('Get audit stats error:', error);
    res.status(500).json({ error: 'Failed to fetch audit statistics' });
  }
});

// Export audit logs as CSV
router.get('/export/csv', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { start_date, end_date, action, user_id } = req.query;

    let query = `
      SELECT al.*, u.username, u.email
      FROM audit_logs al
      LEFT JOIN users u ON al.user_id = u.id
      WHERE 1=1
    `;
    const params = [];

    if (start_date) {
      query += ' AND al.timestamp >= ?';
      params.push(start_date);
    }

    if (end_date) {
      query += ' AND al.timestamp <= ?';
      params.push(end_date);
    }

    if (action) {
      query += ' AND al.action = ?';
      params.push(action);
    }

    if (user_id) {
      query += ' AND al.user_id = ?';
      params.push(user_id);
    }

    query += ' ORDER BY al.timestamp DESC LIMIT 10000';

    const logs = db.prepare(query).all(...params);

    // Generate CSV
    const headers = ['ID', 'Timestamp', 'Username', 'Email', 'Action', 'Resource Type', 'Resource ID', 'IP Address', 'User Agent', 'Details'];
    const csvRows = [headers.join(',')];

    for (const log of logs) {
      const row = [
        log.id,
        log.timestamp,
        log.username || '',
        log.email || '',
        log.action,
        log.resource_type || '',
        log.resource_id || '',
        log.ip_address || '',
        `"${(log.user_agent || '').replace(/"/g, '""')}"`,
        `"${(log.details || '').replace(/"/g, '""')}"`
      ];
      csvRows.push(row.join(','));
    }

    const csv = csvRows.join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=audit_logs_${new Date().toISOString().split('T')[0]}.csv`);
    res.send(csv);
  } catch (error) {
    logger.error('Export audit logs error:', error);
    res.status(500).json({ error: 'Failed to export audit logs' });
  }
});

// Get user activity
router.get('/user/:userId', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { limit = 50, offset = 0 } = req.query;

    const logs = db.prepare(`
      SELECT al.*, u.username, u.email
      FROM audit_logs al
      LEFT JOIN users u ON al.user_id = u.id
      WHERE al.user_id = ?
      ORDER BY al.timestamp DESC
      LIMIT ? OFFSET ?
    `).all(req.params.userId, parseInt(limit), parseInt(offset));

    const parsedLogs = logs.map(log => ({
      ...log,
      details: log.details ? JSON.parse(log.details) : null
    }));

    const totalCount = db.prepare(
      'SELECT COUNT(*) as count FROM audit_logs WHERE user_id = ?'
    ).get(req.params.userId)?.count || 0;

    res.json({
      data: parsedLogs,
      pagination: {
        total: totalCount,
        limit: parseInt(limit),
        offset: parseInt(offset),
        hasMore: parseInt(offset) + parsedLogs.length < totalCount
      }
    });
  } catch (error) {
    logger.error('Get user activity error:', error);
    res.status(500).json({ error: 'Failed to fetch user activity' });
  }
});

// Search audit logs
router.post('/search', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { 
      searchTerm, 
      actions, 
      resourceTypes, 
      userIds,
      dateRange 
    } = req.body;

    let query = `
      SELECT al.*, u.username, u.email
      FROM audit_logs al
      LEFT JOIN users u ON al.user_id = u.id
      WHERE 1=1
    `;
    const params = [];

    if (searchTerm) {
      query += ' AND (al.action LIKE ? OR al.resource_id LIKE ? OR al.details LIKE ?)';
      params.push(`%${searchTerm}%`, `%${searchTerm}%`, `%${searchTerm}%`);
    }

    if (actions && actions.length > 0) {
      query += ` AND al.action IN (${actions.map(() => '?').join(',')})`;
      params.push(...actions);
    }

    if (resourceTypes && resourceTypes.length > 0) {
      query += ` AND al.resource_type IN (${resourceTypes.map(() => '?').join(',')})`;
      params.push(...resourceTypes);
    }

    if (userIds && userIds.length > 0) {
      query += ` AND al.user_id IN (${userIds.map(() => '?').join(',')})`;
      params.push(...userIds);
    }

    if (dateRange) {
      if (dateRange.start) {
        query += ' AND al.timestamp >= ?';
        params.push(dateRange.start);
      }
      if (dateRange.end) {
        query += ' AND al.timestamp <= ?';
        params.push(dateRange.end);
      }
    }

    query += ' ORDER BY al.timestamp DESC LIMIT 500';

    const logs = db.prepare(query).all(...params);

    const parsedLogs = logs.map(log => ({
      ...log,
      details: log.details ? JSON.parse(log.details) : null
    }));

    res.json(parsedLogs);
  } catch (error) {
    logger.error('Search audit logs error:', error);
    res.status(500).json({ error: 'Failed to search audit logs' });
  }
});

// Get available actions (for filtering)
router.get('/actions/list', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const actions = db.prepare(`
      SELECT DISTINCT action FROM audit_logs ORDER BY action
    `).all();

    res.json(actions.map(a => a.action));
  } catch (error) {
    logger.error('Get actions error:', error);
    res.status(500).json({ error: 'Failed to fetch actions' });
  }
});

module.exports = router;
