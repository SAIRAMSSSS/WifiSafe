const express = require('express');
const { body, query, validationResult } = require('express-validator');
const { v4: uuidv4 } = require('uuid');
const { getDatabase, saveDatabase } = require('../database/init');
const { authenticate, optionalAuth } = require('../middleware/auth');
const { logAudit } = require('../middleware/audit');
const { refreshDevices, scanDevicePorts, scanPorts } = require('../services/realNetworkScanner');
const { checkCredentials, auditMisconfigurations } = require('../services/credentialChecker');
const { broadcast } = require('../websocket/server');
const logger = require('../utils/logger');
const { queryNVD, getDeviceCVEs } = require('../services/cveLookup');
const { calculateSecurityScore } = require('./security'); // reuse full score logic

const router = express.Router();

// Refresh devices from real network scan
router.post('/refresh', optionalAuth, async (req, res) => {
  try {
    logger.info('[API] Refreshing devices from network scan...');
    const result = await refreshDevices();
    res.json({
      success: true,
      message: 'Network scan complete',
      newDevices: result.newDevices,
      updatedDevices: result.updatedDevices
    });
  } catch (error) {
    logger.error('Refresh devices error:', error);
    res.status(500).json({ error: 'Failed to refresh devices' });
  }
});

// Get all devices (optionalAuth for dev mode)
router.get('/', optionalAuth, (req, res) => {
  try {
    const db = getDatabase();
    const { status, type, risk_level, search } = req.query;

    let query = 'SELECT * FROM devices WHERE 1=1';
    const params = [];

    if (status) {
      query += ' AND status = ?';
      params.push(status);
    }
    if (type) {
      query += ' AND type = ?';
      params.push(type);
    }
    if (risk_level) {
      query += ' AND risk_level = ?';
      params.push(risk_level);
    }
    if (search) {
      query += ' AND (name LIKE ? OR ip LIKE ? OR mac LIKE ? OR vendor LIKE ?)';
      const searchTerm = `%${search}%`;
      params.push(searchTerm, searchTerm, searchTerm, searchTerm);
    }

    query += ' ORDER BY risk_score DESC, last_seen DESC';

    const devices = db.prepare(query).all(...params);

    // Parse JSON fields
    const parsedDevices = devices.map(device => ({
      ...device,
      fingerprint: device.fingerprint_data ? JSON.parse(device.fingerprint_data) : null,
      firmware: device.firmware_data ? JSON.parse(device.firmware_data) : null,
      credentialStatus: device.credential_status ? JSON.parse(device.credential_status) : null
    }));

    res.json(parsedDevices);
  } catch (error) {
    logger.error('Get devices error:', error);
    res.status(500).json({ error: 'Failed to fetch devices' });
  }
});

// Get device by ID
router.get('/:id', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(req.params.id);

    if (!device) {
      return res.status(404).json({ error: 'Device not found' });
    }

    // Get vulnerabilities
    const vulnerabilities = db.prepare('SELECT * FROM vulnerabilities WHERE device_id = ?').all(req.params.id);

    // Get ports
    const ports = db.prepare('SELECT * FROM ports WHERE device_id = ?').all(req.params.id);

    // Get misconfigurations
    const misconfigurations = db.prepare('SELECT * FROM misconfigurations WHERE device_id = ?').all(req.params.id);

    // Get anomalies
    const anomalies = db.prepare('SELECT * FROM anomalies WHERE device_id = ? ORDER BY created_at DESC LIMIT 10').all(req.params.id);

    const result = {
      ...device,
      fingerprint: device.fingerprint_data ? JSON.parse(device.fingerprint_data) : null,
      firmware: device.firmware_data ? JSON.parse(device.firmware_data) : null,
      credentialStatus: device.credential_status ? JSON.parse(device.credential_status) : null,
      vulnerabilities,
      ports,
      misconfigurations,
      anomalies
    };

    res.json(result);
  } catch (error) {
    logger.error('Get device error:', error);
    res.status(500).json({ error: 'Failed to fetch device' });
  }
});

// Create device (usually done automatically by scanner)
router.post('/', authenticate, [
  body('name').isLength({ min: 1 }),
  body('ip').isIP(),
  body('mac').optional().isMACAddress()
], (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const db = getDatabase();
    const deviceId = uuidv4();
    const now = new Date().toISOString();

    const { name, ip, mac, type, vendor, status, adminUrl } = req.body;

    db.prepare(`
      INSERT INTO devices (id, name, ip, mac, type, vendor, status, admin_url, last_seen, first_seen)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(deviceId, name, ip, mac || null, type || 'unknown', vendor || 'Unknown', status || 'online', adminUrl || null, now, now);

    logAudit(req.user.id, 'DEVICE_CREATED', 'device', deviceId, { name, ip }, req);

    // Emit alert for new device
    const { emit } = require('../websocket/server');
    const alertId = uuidv4();
    db.prepare(`
      INSERT INTO alerts (id, type, severity, device_id, device_ip, message, details, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      alertId,
      'new_device',
      'medium',
      deviceId,
      ip,
      `New device discovered: ${name} (${ip})`,
      JSON.stringify({ name, ip }),
      now
    );
    emit.newAlert({
      id: alertId,
      severity: 'medium',
      deviceIp: ip,
      title: 'New Device Discovered',
      description: `Device ${name} (${ip}) was added to the network.`
    });

    const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceId);
    res.status(201).json(device);
  } catch (error) {
    logger.error('Create device error:', error);
    res.status(500).json({ error: 'Failed to create device' });
  }
});

// Update device
router.put('/:id', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(req.params.id);

    if (!device) {
      return res.status(404).json({ error: 'Device not found' });
    }

    const updates = [];
    const params = [];
    const allowedFields = ['name', 'type', 'vendor', 'status', 'admin_url', 'is_quarantined'];

    for (const field of allowedFields) {
      if (req.body[field] !== undefined) {
        updates.push(`${field} = ?`);
        params.push(req.body[field]);
      }
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }

    updates.push('updated_at = ?');
    params.push(new Date().toISOString());
    params.push(req.params.id);

    db.prepare(`UPDATE devices SET ${updates.join(', ')} WHERE id = ?`).run(...params);

    logAudit(req.user.id, 'DEVICE_UPDATED', 'device', req.params.id, req.body, req);

    const updatedDevice = db.prepare('SELECT * FROM devices WHERE id = ?').get(req.params.id);
    res.json(updatedDevice);
  } catch (error) {
    logger.error('Update device error:', error);
    res.status(500).json({ error: 'Failed to update device' });
  }
});

// Delete device
router.delete('/:id', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(req.params.id);

    if (!device) {
      return res.status(404).json({ error: 'Device not found' });
    }

    db.prepare('DELETE FROM devices WHERE id = ?').run(req.params.id);

    logAudit(req.user.id, 'DEVICE_DELETED', 'device', req.params.id, { name: device.name, ip: device.ip }, req);

    // Emit alert for quarantine
    if (device.status === 'quarantined') {
      const { emit } = require('../websocket/server');
      const alertId = uuidv4();
      db.prepare(`
        INSERT INTO alerts (id, type, severity, device_id, device_ip, message, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        alertId,
        'quarantine',
        'high',
        device.id,
        device.ip,
        `Device quarantined: ${device.name} (${device.ip})`,
        JSON.stringify({ name: device.name, ip: device.ip }),
        new Date().toISOString()
      );
      emit.newAlert({
        id: alertId,
        severity: 'high',
        deviceIp: device.ip,
        title: 'Device Quarantined',
        description: `Device ${device.name} (${device.ip}) was quarantined.`
      });
    }

    res.json({ message: 'Device deleted successfully' });
  } catch (error) {
    logger.error('Delete device error:', error);
    res.status(500).json({ error: 'Failed to delete device' });
  }
});

// Get device statistics
router.get('/stats/summary', optionalAuth, (req, res) => {
  try {
    const db = getDatabase();

    const total = db.prepare('SELECT COUNT(*) as count FROM devices').get().count;
    const online = db.prepare("SELECT COUNT(*) as count FROM devices WHERE status = 'online'").get().count;
    const offline = db.prepare("SELECT COUNT(*) as count FROM devices WHERE status = 'offline'").get().count;
    const quarantined = db.prepare("SELECT COUNT(*) as count FROM devices WHERE status = 'quarantined'").get().count;

    const byType = db.prepare('SELECT device_type as type, COUNT(*) as count FROM devices GROUP BY device_type').all();
    const byRiskLevel = db.prepare('SELECT risk_level, COUNT(*) as count FROM devices GROUP BY risk_level').all();

    const criticalDevices = db.prepare("SELECT COUNT(*) as count FROM devices WHERE risk_level = 'critical'").get().count;
    const highRiskDevices = db.prepare("SELECT COUNT(*) as count FROM devices WHERE risk_level = 'high'").get().count;
    const mediumRiskDevices = db.prepare("SELECT COUNT(*) as count FROM devices WHERE risk_level = 'medium'").get().count;
    const lowRiskDevices = db.prepare("SELECT COUNT(*) as count FROM devices WHERE risk_level = 'low' OR risk_level = 'safe' OR risk_level IS NULL").get().count;

    // Get threat/alert counts
    const criticalAlerts = db.prepare("SELECT COUNT(*) as count FROM alerts WHERE severity = 'critical' AND acknowledged = 0").get().count;
    const totalThreats = db.prepare("SELECT COUNT(*) as count FROM alerts WHERE type IN ('threat', 'intrusion', 'vulnerability', 'critical_cve', 'weak_credentials')").get().count;
    const totalVulnerabilities = db.prepare("SELECT COUNT(*) as count FROM vulnerabilities WHERE status = 'open'").get().count;

    // Use the full security score calculator for accuracy
    let securityScore = 100;
    let scoreStatus = 'ok';
    let scoreMessage = '';
    try {
      const fullScore = calculateSecurityScore(db);
      securityScore = fullScore.score ?? 100;
      scoreStatus = fullScore.status || 'ok';
      scoreMessage = fullScore.message || '';
    } catch (scoreErr) {
      // Fallback: basic device-risk calculation
      securityScore = Math.max(0, Math.min(100, 100 - (criticalDevices * 15) - (highRiskDevices * 10) - (mediumRiskDevices * 5)));
      scoreStatus = 'partial';
      scoreMessage = 'Score calculated from device risk levels';
    }

    res.json({
      total,
      online,
      offline,
      quarantined,
      byType,
      byRiskLevel,
      criticalDevices,
      highRiskDevices,
      mediumRiskDevices,
      lowRiskDevices,
      securityScore,
      scoreStatus,
      scoreMessage,
      criticalAlerts,
      totalThreats,
      totalVulnerabilities
    });
  } catch (error) {
    logger.error('Get device stats error:', error);
    res.status(500).json({ error: 'Failed to fetch device statistics' });
  }
});

/**
 * POST /devices/:ip/check-credentials
 * Run safe credential check on a device
 * WARNING: Only run on networks you control or with explicit authorization
 */
router.post('/:ip/check-credentials', optionalAuth, async (req, res) => {
  const { ip } = req.params;
  const { authorized = false } = req.body;

  // Validate IP
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
    return res.status(400).json({ error: 'Invalid IP address' });
  }

  // Require explicit authorization flag
  if (!authorized) {
    return res.status(403).json({
      error: 'Authorization required',
      message: 'Credential checks are intrusive. Set { authorized: true } to confirm you have permission to test this device.'
    });
  }

  try {
    const db = getDatabase();

    // Find device
    const device = db.prepare('SELECT * FROM devices WHERE ip = ?').get(ip);
    if (!device) {
      return res.status(404).json({ error: 'Device not found' });
    }

    // Log the audit attempt
    const auditUserId = req.user?.id || 'system';
    logAudit(auditUserId, 'CREDENTIAL_CHECK_STARTED', 'device', device.id, { ip, authorized }, req);

    logger.info(`[CREDENTIAL CHECK] Starting credential check on ${ip}`);

    // Broadcast start event
    broadcast('devices', {
      type: 'credential_check_started',
      ip,
      deviceId: device.id,
      timestamp: new Date().toISOString()
    });

    // Get open ports
    let openPorts = [];
    try {
      openPorts = device.open_ports ? JSON.parse(device.open_ports).map(p => p.port || p) : [];
    } catch {
      // Scan ports if not available
      const portScanResult = await scanPorts(ip, [21, 22, 23, 80, 443, 8080, 8443, 161]);
      openPorts = portScanResult.filter(p => p.open).map(p => p.port);
    }

    // Run credential check
    const results = await checkCredentials(ip, openPorts, device.device_type || 'unknown');

    // Log all findings
    for (const finding of results.findings) {
      logAudit(auditUserId, 'CREDENTIAL_FINDING', 'device', device.id, {
        ...finding,
        ip,
        severity: finding.severity
      }, req);
    }

    // Update device record
    const hasWeakCredentials = results.weakCredentialsFound || results.defaultCredentialsFound;

    db.prepare(`
      UPDATE devices 
      SET has_weak_credentials = ?, 
          credential_status = ?,
          updated_at = ?
      WHERE ip = ?
    `).run(
      hasWeakCredentials ? 1 : 0,
      JSON.stringify({
        lastChecked: results.timestamp,
        hasDefaultCredentials: results.defaultCredentialsFound,
        hasWeakCredentials: results.weakCredentialsFound,
        findings: results.findings,
        testedServices: results.testedServices
      }),
      new Date().toISOString(),
      ip
    );

    // If critical findings, create alert and broadcast
    if (hasWeakCredentials) {
      const alertId = uuidv4();
      const alertMessage = results.defaultCredentialsFound
        ? `Default credentials detected on ${device.name || ip}`
        : `Weak security configuration on ${device.name || ip}`;

      db.prepare(`
        INSERT INTO alerts (id, type, severity, device_id, device_ip, message, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        alertId,
        'weak_credentials',
        'critical',
        device.id,
        ip,
        alertMessage,
        JSON.stringify(results.findings),
        new Date().toISOString()
      );

      // Broadcast alert
      broadcast('alerts', {
        type: 'new_alert',
        alert: {
          id: alertId,
          type: 'weak_credentials',
          severity: 'critical',
          deviceId: device.id,
          ip,
          message: alertMessage,
          findings: results.findings.length,
          timestamp: new Date().toISOString()
        }
      });

      // Update device risk score
      const { calculateRiskScore, getRiskLevel } = require('../services/realNetworkScanner');
      const updatedDevice = { ...device, has_weak_credentials: hasWeakCredentials ? 1 : 0 };
      const newRiskScore = calculateRiskScore(updatedDevice);
      const newRiskLevel = getRiskLevel(newRiskScore);

      db.prepare(`
        UPDATE devices SET risk_score = ?, risk_level = ? WHERE ip = ?
      `).run(newRiskScore, newRiskLevel, ip);
    }

    saveDatabase();

    // Broadcast completion
    broadcast('devices', {
      type: 'credential_check_completed',
      ip,
      deviceId: device.id,
      hasWeakCredentials,
      findingsCount: results.findings.length,
      timestamp: new Date().toISOString()
    });

    logAudit(auditUserId, 'CREDENTIAL_CHECK_COMPLETED', 'device', device.id, {
      ip,
      hasWeakCredentials,
      findingsCount: results.findings.length
    }, req);

    logger.info(`[CREDENTIAL CHECK] Completed on ${ip}: ${results.findings.length} findings`);

    res.json({
      success: true,
      ip,
      deviceId: device.id,
      results
    });

  } catch (error) {
    logger.error('Credential check error:', error);
    res.status(500).json({ error: 'Failed to run credential check', details: error.message });
  }
});

/**
 * GET /devices/:ip/config-audit
 * Run misconfiguration audit on a device
 */
router.get('/:ip/config-audit', optionalAuth, async (req, res) => {
  const { ip } = req.params;

  // Validate IP
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
    return res.status(400).json({ error: 'Invalid IP address' });
  }

  try {
    const db = getDatabase();

    // Find device
    const device = db.prepare('SELECT * FROM devices WHERE ip = ?').get(ip);
    if (!device) {
      return res.status(404).json({ error: 'Device not found' });
    }

    logger.info(`[CONFIG AUDIT] Starting audit on ${ip}`);

    // Get open ports
    let openPorts = [];
    try {
      openPorts = device.open_ports ? JSON.parse(device.open_ports).map(p => p.port || p) : [];
    } catch {
      // Scan common ports if not available
      const portScanResult = await scanPorts(ip, [21, 22, 23, 80, 161, 443, 502, 1900, 5555, 7547, 8080, 8443, 37777]);
      openPorts = portScanResult.filter(p => p.open).map(p => p.port);
    }

    // Run audit
    const results = await auditMisconfigurations(ip, openPorts);

    // Save misconfigurations to database
    for (const misconfig of results.misconfigurations) {
      const existing = db.prepare(
        'SELECT id FROM misconfigurations WHERE device_id = ? AND type = ?'
      ).get(device.id, misconfig.type);

      if (!existing) {
        db.prepare(`
          INSERT INTO misconfigurations (id, device_id, type, severity, title, description, port, recommendation, discovered_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          uuidv4(),
          device.id,
          misconfig.type,
          misconfig.severity,
          misconfig.title,
          misconfig.description,
          misconfig.port || null,
          misconfig.recommendation,
          new Date().toISOString()
        );
      }
    }

    // Update device if critical/high misconfigs found
    const criticalCount = results.misconfigurations.filter(m => m.severity === 'critical').length;
    const highCount = results.misconfigurations.filter(m => m.severity === 'high').length;

    if (criticalCount > 0 || highCount > 0) {
      // Create alert for high-severity misconfigs
      const alertId = uuidv4();
      const alertMessage = `${criticalCount + highCount} security misconfiguration(s) found on ${device.name || ip}`;

      db.prepare(`
        INSERT INTO alerts (id, type, severity, device_id, device_ip, message, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        alertId,
        'misconfiguration',
        criticalCount > 0 ? 'critical' : 'high',
        device.id,
        ip,
        alertMessage,
        JSON.stringify(results.misconfigurations),
        new Date().toISOString()
      );

      // Broadcast alert
      broadcast('alerts', {
        type: 'new_alert',
        alert: {
          id: alertId,
          type: 'misconfiguration',
          severity: criticalCount > 0 ? 'critical' : 'high',
          deviceId: device.id,
          ip,
          message: alertMessage,
          misconfigurations: results.misconfigurations.length,
          timestamp: new Date().toISOString()
        }
      });
    }

    saveDatabase();

    logger.info(`[CONFIG AUDIT] Completed on ${ip}: ${results.misconfigurations.length} issues, score: ${results.score}`);

    res.json({
      success: true,
      ip,
      deviceId: device.id,
      results
    });

  } catch (error) {
    logger.error('Config audit error:', error);
    res.status(500).json({ error: 'Failed to run config audit', details: error.message });
  }
});

/**
 * GET /vulns/:vendor/:product
 * Returns CVEs and CVSS summary for vendor/product
 */
router.get('/vulns/:vendor/:product', optionalAuth, async (req, res) => {
  const { vendor, product } = req.params;
  try {
    const cves = await queryNVD(vendor, product);
    res.json({
      success: true,
      vendor,
      product,
      cve_count: cves.length,
      critical_count: cves.filter(c => c.cvssSeverity === 'CRITICAL').length,
      cves
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to query CVEs', details: error.message });
  }
});

/**
 * GET /devices/:ip/vulns
 * Returns mapped CVEs for a device
 */
router.get('/:ip/vulns', optionalAuth, async (req, res) => {
  const { ip } = req.params;
  try {
    const db = getDatabase();
    const device = db.prepare('SELECT * FROM devices WHERE ip = ?').get(ip);
    if (!device) {
      return res.status(404).json({ error: 'Device not found' });
    }
    const cves = await getDeviceCVEs(device);
    // Store in vulnerabilities table
    for (const cve of cves) {
      const exists = db.prepare('SELECT id FROM vulnerabilities WHERE device_id = ? AND cve_id = ?').get(device.id, cve.id);
      if (!exists) {
        db.prepare(`
          INSERT INTO vulnerabilities (id, device_id, title, severity, description, cve_id, cvss_score, remediation, exploit_available, patch_available, status, discovered_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          uuidv4(),
          device.id,
          cve.id,
          cve.cvssSeverity || 'unknown',
          cve.description,
          cve.id,
          cve.cvssScore || null,
          null,
          cve.exploitAvailable ? 1 : 0,
          cve.patchAvailable ? 1 : 0,
          'open',
          new Date().toISOString()
        );
      }
    }
    // Tag device with cve_count and critical_count
    db.prepare('UPDATE devices SET cve_count = ?, critical_count = ?, updated_at = ? WHERE id = ?')
      .run(cves.length, cves.filter(c => c.cvssSeverity === 'CRITICAL').length, new Date().toISOString(), device.id);
    saveDatabase();
    // Push alert for critical CVEs
    const criticalCVEs = cves.filter(c => c.cvssSeverity === 'CRITICAL');
    if (criticalCVEs.length > 0) {
      const alertId = uuidv4();
      db.prepare(`
        INSERT INTO alerts (id, type, severity, device_id, device_ip, message, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        alertId,
        'critical_cve',
        'critical',
        device.id,
        ip,
        `Critical CVEs detected for ${device.name || ip}`,
        JSON.stringify(criticalCVEs),
        new Date().toISOString()
      );
      broadcast('alerts', {
        type: 'new_alert',
        alert: {
          id: alertId,
          type: 'critical_cve',
          severity: 'critical',
          deviceId: device.id,
          ip,
          message: `Critical CVEs detected for ${device.name || ip}`,
          cveCount: criticalCVEs.length,
          timestamp: new Date().toISOString()
        }
      });
    }
    res.json({
      success: true,
      ip,
      deviceId: device.id,
      cve_count: cves.length,
      critical_count: criticalCVEs.length,
      cves
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get device CVEs', details: error.message });
  }
});

// Acknowledge alert
router.post('/alerts/:id/acknowledge', authenticate, (req, res) => {
  const { id } = req.params;
  try {
    const db = getDatabase();
    db.prepare('UPDATE alerts SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = ? WHERE id = ?')
      .run(req.user.id, new Date().toISOString(), id);
    const { emit } = require('../websocket/server');
    emit.alertAcknowledged(id);
    logAudit(req.user.id, 'ALERT_ACKNOWLEDGED', 'alert', id, {}, req);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to acknowledge alert', details: error.message });
  }
});

/**
 * POST /devices/:ip/quarantine { reason, duration }
 * Quarantine device via local firewall (iptables/ufw)
 */
router.post('/:ip/quarantine', authenticate, async (req, res) => {
  const { ip } = req.params;
  const { reason = 'Security risk', duration = null } = req.body;
  try {
    const db = getDatabase();
    const device = db.prepare('SELECT * FROM devices WHERE ip = ?').get(ip);
    if (!device) return res.status(404).json({ error: 'Device not found' });
    // Model A: Local firewall
    const exec = require('child_process').exec;
    const isWindows = process.platform === 'win32';

    if (isWindows) {
      // Windows Firewall (netsh)
      exec(`netsh advfirewall firewall add rule name="Block ${ip}" dir=in action=block remoteip=${ip}`, (err) => {
        if (err) logger.error(`Failed to add Windows firewall rule for ${ip}: ${err.message}`);
      });
      exec(`netsh advfirewall firewall add rule name="Block ${ip}" dir=out action=block remoteip=${ip}`, (err) => {
        if (err) logger.error(`Failed to add Windows firewall rule for ${ip}: ${err.message}`);
      });
    } else {
      // Linux (iptables/ufw)
      exec(`iptables -A INPUT -s ${ip} -j DROP`, (err) => {
        if (err) {
          // Try ufw
          exec(`ufw deny from ${ip} to any`, (ufwErr) => {
            if (ufwErr) logger.error(`Failed to add Linux firewall rule for ${ip}: ${ufwErr.message}`);
          });
        }
      });
    }
    // Mark device as quarantined
    db.prepare('UPDATE devices SET status = ?, is_quarantined = 1, quarantine_reason = ?, quarantined_at = ? WHERE ip = ?')
      .run('quarantined', reason, new Date().toISOString(), ip);
    // Log audit
    logAudit(req.user.id, 'DEVICE_QUARANTINED', 'device', device.id, { ip, reason, duration }, req);
    // WebSocket event
    const { emit } = require('../websocket/server');
    emit.deviceQuarantined({ ip, by: req.user.id, reason });
    res.json({ success: true, jobId: `quarantine-${device.id}`, ip, reason });
  } catch (error) {
    res.status(500).json({ error: 'Failed to quarantine device', details: error.message });
  }
});

/**
 * POST /devices/:ip/unquarantine
 * Remove quarantine firewall rule
 */
router.post('/:ip/unquarantine', authenticate, async (req, res) => {
  const { ip } = req.params;
  try {
    const db = getDatabase();
    const device = db.prepare('SELECT * FROM devices WHERE ip = ?').get(ip);
    if (!device) return res.status(404).json({ error: 'Device not found' });
    // Remove firewall rule
    const exec = require('child_process').exec;
    const isWindows = process.platform === 'win32';

    if (isWindows) {
      // Windows Firewall (netsh)
      exec(`netsh advfirewall firewall delete rule name="Block ${ip}"`, (err) => {
        if (err) logger.error(`Failed to remove Windows firewall rule for ${ip}: ${err.message}`);
      });
    } else {
      // Linux (iptables/ufw)
      exec(`iptables -D INPUT -s ${ip} -j DROP`, (err) => {
        // Remove ufw rule
        exec(`ufw delete deny from ${ip} to any`, () => { });
      });
    }
    db.prepare('UPDATE devices SET status = ?, is_quarantined = 0, quarantine_reason = NULL, quarantined_at = NULL WHERE ip = ?')
      .run('online', ip);
    logAudit(req.user.id, 'DEVICE_UNQUARANTINED', 'device', device.id, { ip }, req);
    res.json({ success: true, jobId: `unquarantine-${device.id}`, ip });
  } catch (error) {
    res.status(500).json({ error: 'Failed to unquarantine device', details: error.message });
  }
});

module.exports = router;
