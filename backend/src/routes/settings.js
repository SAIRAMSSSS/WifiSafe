const express = require('express');
const { getDatabase } = require('../database/init');
const { authenticate, authorize } = require('../middleware/auth');
const { logAudit } = require('../middleware/audit');
const logger = require('../utils/logger');

const router = express.Router();

// Get all settings
router.get('/', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const settings = db.prepare('SELECT * FROM settings').all();

    // Convert to key-value object
    const settingsObj = {};
    for (const setting of settings) {
      try {
        settingsObj[setting.key] = JSON.parse(setting.value);
      } catch {
        settingsObj[setting.key] = setting.value;
      }
    }

    res.json(settingsObj);
  } catch (error) {
    logger.error('Get settings error:', error);
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

// Get setting by key
router.get('/:key', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const setting = db.prepare('SELECT * FROM settings WHERE key = ?').get(req.params.key);

    if (!setting) {
      return res.status(404).json({ error: 'Setting not found' });
    }

    let value;
    try {
      value = JSON.parse(setting.value);
    } catch {
      value = setting.value;
    }

    res.json({
      key: setting.key,
      value,
      category: setting.category,
      description: setting.description,
      updated_at: setting.updated_at
    });
  } catch (error) {
    logger.error('Get setting error:', error);
    res.status(500).json({ error: 'Failed to fetch setting' });
  }
});

// Update setting
router.put('/:key', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { value } = req.body;

    const setting = db.prepare('SELECT * FROM settings WHERE key = ?').get(req.params.key);

    const valueStr = typeof value === 'object' ? JSON.stringify(value) : String(value);
    const now = new Date().toISOString();

    if (setting) {
      db.prepare(`
        UPDATE settings SET value = ?, updated_at = ?
        WHERE key = ?
      `).run(valueStr, now, req.params.key);
    } else {
      db.prepare(`
        INSERT INTO settings (key, value, updated_at, created_at)
        VALUES (?, ?, ?, ?)
      `).run(req.params.key, valueStr, now, now);
    }

    logAudit(req.user.id, 'SETTING_UPDATED', 'settings', req.params.key, { value }, req);

    res.json({
      key: req.params.key,
      value,
      updated_at: now
    });
  } catch (error) {
    logger.error('Update setting error:', error);
    res.status(500).json({ error: 'Failed to update setting' });
  }
});

// Update multiple settings
router.put('/', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { settings } = req.body;

    if (!settings || typeof settings !== 'object') {
      return res.status(400).json({ error: 'Settings object is required' });
    }

    const now = new Date().toISOString();
    const updatedSettings = {};

    for (const [key, value] of Object.entries(settings)) {
      const valueStr = typeof value === 'object' ? JSON.stringify(value) : String(value);

      const existing = db.prepare('SELECT * FROM settings WHERE key = ?').get(key);

      if (existing) {
        db.prepare(`
          UPDATE settings SET value = ?, updated_at = ?
          WHERE key = ?
        `).run(valueStr, now, key);
      } else {
        db.prepare(`
          INSERT INTO settings (key, value, updated_at, created_at)
          VALUES (?, ?, ?, ?)
        `).run(key, valueStr, now, now);
      }

      updatedSettings[key] = value;
    }

    logAudit(req.user.id, 'SETTINGS_BULK_UPDATE', 'settings', null, { keys: Object.keys(settings) }, req);

    res.json(updatedSettings);
  } catch (error) {
    logger.error('Bulk update settings error:', error);
    res.status(500).json({ error: 'Failed to update settings' });
  }
});

// Delete setting
router.delete('/:key', authenticate, (req, res) => {
  try {
    const db = getDatabase();

    const setting = db.prepare('SELECT * FROM settings WHERE key = ?').get(req.params.key);
    if (!setting) {
      return res.status(404).json({ error: 'Setting not found' });
    }

    db.prepare('DELETE FROM settings WHERE key = ?').run(req.params.key);

    logAudit(req.user.id, 'SETTING_DELETED', 'settings', req.params.key, {}, req);

    res.json({ message: 'Setting deleted successfully' });
  } catch (error) {
    logger.error('Delete setting error:', error);
    res.status(500).json({ error: 'Failed to delete setting' });
  }
});

// Get settings by category
router.get('/category/:category', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const settings = db.prepare('SELECT * FROM settings WHERE category = ?').all(req.params.category);

    const settingsObj = {};
    for (const setting of settings) {
      try {
        settingsObj[setting.key] = JSON.parse(setting.value);
      } catch {
        settingsObj[setting.key] = setting.value;
      }
    }

    res.json(settingsObj);
  } catch (error) {
    logger.error('Get settings by category error:', error);
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

// Get user preferences
router.get('/user/preferences', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const user = db.prepare('SELECT preferences FROM users WHERE id = ?').get(req.user.id);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    let preferences = {};
    try {
      preferences = user.preferences ? JSON.parse(user.preferences) : {};
    } catch {
      preferences = {};
    }

    res.json(preferences);
  } catch (error) {
    logger.error('Get user preferences error:', error);
    res.status(500).json({ error: 'Failed to fetch user preferences' });
  }
});

// Update user preferences
router.put('/user/preferences', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { preferences } = req.body;

    if (!preferences || typeof preferences !== 'object') {
      return res.status(400).json({ error: 'Preferences object is required' });
    }

    // Get existing preferences and merge
    const user = db.prepare('SELECT preferences FROM users WHERE id = ?').get(req.user.id);
    let existingPrefs = {};
    try {
      existingPrefs = user?.preferences ? JSON.parse(user.preferences) : {};
    } catch {
      existingPrefs = {};
    }

    const mergedPrefs = { ...existingPrefs, ...preferences };

    db.prepare(`
      UPDATE users SET preferences = ?, updated_at = ?
      WHERE id = ?
    `).run(JSON.stringify(mergedPrefs), new Date().toISOString(), req.user.id);

    logAudit(req.user.id, 'USER_PREFERENCES_UPDATED', 'user', req.user.id, { keys: Object.keys(preferences) }, req);

    res.json(mergedPrefs);
  } catch (error) {
    logger.error('Update user preferences error:', error);
    res.status(500).json({ error: 'Failed to update user preferences' });
  }
});

// Get scan configuration
router.get('/scan/config', authenticate, (req, res) => {
  try {
    const db = getDatabase();

    const defaultConfig = {
      autoScanEnabled: false,
      autoScanInterval: 24, // hours
      scanTargets: '192.168.1.0/24',
      portScanRange: '1-1024',
      enableVulnerabilityDetection: true,
      enableCredentialCheck: true,
      maxConcurrentScans: 5,
      scanTimeout: 3600, // seconds
      excludedHosts: []
    };

    // Get stored config
    const settings = db.prepare("SELECT * FROM settings WHERE category = 'scan'").all();

    for (const setting of settings) {
      try {
        defaultConfig[setting.key] = JSON.parse(setting.value);
      } catch {
        defaultConfig[setting.key] = setting.value;
      }
    }

    res.json(defaultConfig);
  } catch (error) {
    logger.error('Get scan config error:', error);
    res.status(500).json({ error: 'Failed to fetch scan configuration' });
  }
});

// Update scan configuration
router.put('/scan/config', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const config = req.body;
    const now = new Date().toISOString();

    for (const [key, value] of Object.entries(config)) {
      const valueStr = typeof value === 'object' ? JSON.stringify(value) : String(value);

      const existing = db.prepare("SELECT * FROM settings WHERE key = ? AND category = 'scan'").get(key);

      if (existing) {
        db.prepare(`
          UPDATE settings SET value = ?, updated_at = ?
          WHERE key = ? AND category = 'scan'
        `).run(valueStr, now, key);
      } else {
        db.prepare(`
          INSERT INTO settings (key, value, category, updated_at, created_at)
          VALUES (?, ?, 'scan', ?, ?)
        `).run(key, valueStr, now, now);
      }
    }

    logAudit(req.user.id, 'SCAN_CONFIG_UPDATED', 'settings', null, config, req);

    res.json(config);
  } catch (error) {
    logger.error('Update scan config error:', error);
    res.status(500).json({ error: 'Failed to update scan configuration' });
  }
});

// Get notification settings
router.get('/notifications', authenticate, (req, res) => {
  try {
    const db = getDatabase();

    const defaultNotifications = {
      emailEnabled: false,
      emailAddress: '',
      slackEnabled: false,
      slackWebhook: '',
      alertOnCritical: true,
      alertOnHigh: true,
      alertOnMedium: false,
      alertOnNewDevice: true,
      alertOnScanComplete: true,
      digestEnabled: false,
      digestFrequency: 'daily'
    };

    const settings = db.prepare("SELECT * FROM settings WHERE category = 'notifications'").all();

    for (const setting of settings) {
      try {
        defaultNotifications[setting.key] = JSON.parse(setting.value);
      } catch {
        defaultNotifications[setting.key] = setting.value;
      }
    }

    res.json(defaultNotifications);
  } catch (error) {
    logger.error('Get notification settings error:', error);
    res.status(500).json({ error: 'Failed to fetch notification settings' });
  }
});

// Update notification settings
router.put('/notifications', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const config = req.body;
    const now = new Date().toISOString();

    for (const [key, value] of Object.entries(config)) {
      const valueStr = typeof value === 'object' ? JSON.stringify(value) : String(value);

      const existing = db.prepare("SELECT * FROM settings WHERE key = ? AND category = 'notifications'").get(key);

      if (existing) {
        db.prepare(`
          UPDATE settings SET value = ?, updated_at = ?
          WHERE key = ? AND category = 'notifications'
        `).run(valueStr, now, key);
      } else {
        db.prepare(`
          INSERT INTO settings (key, value, category, updated_at, created_at)
          VALUES (?, ?, 'notifications', ?, ?)
        `).run(key, valueStr, now, now);
      }
    }

    logAudit(req.user.id, 'NOTIFICATION_SETTINGS_UPDATED', 'settings', null, config, req);

    res.json(config);
  } catch (error) {
    logger.error('Update notification settings error:', error);
    res.status(500).json({ error: 'Failed to update notification settings' });
  }
});

// Reset settings to defaults
router.post('/reset', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { category } = req.body;

    if (category) {
      db.prepare('DELETE FROM settings WHERE category = ?').run(category);
    } else {
      db.prepare('DELETE FROM settings').run();
    }

    logAudit(req.user.id, 'SETTINGS_RESET', 'settings', null, { category: category || 'all' }, req);

    res.json({ message: `Settings${category ? ` for ${category}` : ''} reset to defaults` });
  } catch (error) {
    logger.error('Reset settings error:', error);
    res.status(500).json({ error: 'Failed to reset settings' });
  }
});

module.exports = router;
