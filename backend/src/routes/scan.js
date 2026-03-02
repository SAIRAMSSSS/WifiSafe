const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { getDatabase, saveDatabase } = require('../database/init');
const { authenticate, optionalAuth } = require('../middleware/auth');
const { logAudit } = require('../middleware/audit');
const { broadcast, emit } = require('../websocket/server');
const RealScanner = require('../services/realNetworkScanner');
const logger = require('../utils/logger');
const { getLatestNetworkScore, getScoreTrends, storeDeviceScore, storeNetworkScore, calculateDeviceScore } = require('../services/securityScore');
const { analyzeDevice, getReport } = require('../services/aiAnalysis');

const router = express.Router();

// Store active scan state
let activeScan = null;

/**
 * GET /scan/devices - Real device discovery (ARP + Ping)
 * Returns all devices currently on the network
 */
router.get('/devices', optionalAuth, async (req, res) => {
  try {
    logger.info('Starting quick device discovery...');

    // Use refreshDevices to ensuring DB and Topology stay in sync
    const result = await RealScanner.refreshDevices();

    logger.info(`Quick discovery found ${result.devices.length} devices`);

    res.json({
      success: true,
      count: result.devices.length,
      devices: result.devices, // Return the actual devices found
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Device discovery error:', error);
    res.status(500).json({ error: 'Failed to discover devices', details: error.message });
  }
});

/**
 * GET /scan/ports/:ip - Real port scan for specific IP
 */
router.get('/ports/:ip', optionalAuth, async (req, res) => {
  try {
    const { ip } = req.params;
    const { full } = req.query;

    // Validate IP
    if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
      return res.status(400).json({ error: 'Invalid IP address' });
    }

    logger.info(`Starting port scan on ${ip}...`);

    const ports = full === 'true'
      ? RealScanner.IOT_PORTS
      : RealScanner.QUICK_SCAN_PORTS;

    const results = await RealScanner.scanDevicePorts(ip, ports);

    // Get service banners for HTTP ports
    const enhancedResults = await Promise.all(results.map(async (portInfo) => {
      if ([80, 8080, 443, 8443].includes(portInfo.port)) {
        try {
          const banner = await RealScanner.grabBanner(ip, portInfo.port);
          return { ...portInfo, banner };
        } catch {
          return portInfo;
        }
      }
      return portInfo;
    }));

    logger.info(`Port scan found ${results.length} open ports on ${ip}`);

    res.json({
      success: true,
      ip,
      openPorts: enhancedResults,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Port scan error:', error);
    res.status(500).json({ error: 'Failed to scan ports', details: error.message });
  }
});

/**
 * POST /scan/ports/:ip - Ad-hoc port scan with WebSocket events
 * Supports custom port list via query param: ?ports=22,80,443
 */
router.post('/ports/:ip', optionalAuth, async (req, res) => {
  try {
    const { ip } = req.params;
    const { ports: portQuery } = req.query;
    const { ports: bodyPorts, full } = req.body;

    // Validate IP
    if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
      return res.status(400).json({ error: 'Invalid IP address' });
    }

    // Determine which ports to scan
    let portsToScan;
    if (portQuery) {
      portsToScan = portQuery.split(',').map(p => parseInt(p.trim(), 10)).filter(p => p > 0 && p <= 65535);
    } else if (bodyPorts && Array.isArray(bodyPorts)) {
      portsToScan = bodyPorts.filter(p => p > 0 && p <= 65535);
    } else if (full) {
      portsToScan = RealScanner.IOT_PORTS;
    } else {
      portsToScan = RealScanner.QUICK_SCAN_PORTS;
    }

    logger.info(`Starting ad-hoc port scan on ${ip} for ports: ${portsToScan.join(',')}`);

    // Broadcast scan started
    broadcast('devices', {
      type: 'port_scan_started',
      ip,
      ports: portsToScan,
      timestamp: new Date().toISOString()
    });

    // Send immediate response
    res.json({
      success: true,
      message: 'Port scan started',
      ip,
      ports: portsToScan
    });

    // Run scan asynchronously and broadcast results
    const openPorts = [];

    for (const port of portsToScan) {
      const isOpen = await RealScanner.checkPort(ip, port);

      if (isOpen) {
        const service = RealScanner.getServiceName(port);
        const portInfo = { port, service, open: true };

        // Grab banner for HTTP ports
        if ([80, 8080, 443, 8443].includes(port)) {
          try {
            portInfo.banner = await RealScanner.grabBanner(ip, port);
          } catch { }
        }

        // Check if risky port
        const riskyPorts = [23, 7547, 5555, 69, 161, 502, 37777, 5357];
        portInfo.risky = riskyPorts.includes(port);

        openPorts.push(portInfo);

        // Broadcast each open port found
        broadcast('devices', {
          type: 'port_open',
          ip,
          port: portInfo.port,
          service: portInfo.service,
          banner: portInfo.banner,
          risky: portInfo.risky,
          timestamp: new Date().toISOString()
        });
      }
    }

    // Update device in database with ports
    try {
      const db = getDatabase();
      const device = db.prepare('SELECT id FROM devices WHERE ip = ?').get(ip);

      if (device) {
        db.prepare(`
          UPDATE devices SET open_ports = ?, updated_at = ?
          WHERE ip = ?
        `).run(JSON.stringify(openPorts), new Date().toISOString(), ip);

        // Also insert into ports table
        for (const portInfo of openPorts) {
          const existingPort = db.prepare('SELECT id FROM ports WHERE device_id = ? AND port_number = ?').get(device.id, portInfo.port);

          if (!existingPort) {
            db.prepare(`
              INSERT INTO ports (id, device_id, port_number, protocol, service_name, banner, risk_level, status)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `).run(
              uuidv4(),
              device.id,
              portInfo.port,
              'TCP',
              portInfo.service,
              portInfo.banner || null,
              portInfo.risky ? 'high' : 'safe',
              'open'
            );
          }
        }
        saveDatabase();
      }
    } catch (dbErr) {
      logger.error('Error saving port scan results:', dbErr);
    }

    // Broadcast scan completed
    broadcast('devices', {
      type: 'port_scan_completed',
      ip,
      ports: openPorts,
      totalScanned: portsToScan.length,
      openCount: openPorts.length,
      timestamp: new Date().toISOString()
    });

    logger.info(`Port scan completed on ${ip}: ${openPorts.length} open ports`);

  } catch (error) {
    logger.error('Ad-hoc port scan error:', error);
    res.status(500).json({ error: 'Failed to start port scan', details: error.message });
  }
});

/**
 * GET /scan/network-info - Get local network information
 */
router.get('/network-info', optionalAuth, (req, res) => {
  try {
    const networkInfo = RealScanner.getNetworkInfo();

    const subnets = networkInfo.map(iface => ({
      ...iface,
      subnet: RealScanner.calculateSubnet(iface.ip, iface.netmask)
    }));

    res.json({
      success: true,
      interfaces: subnets,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Network info error:', error);
    res.status(500).json({ error: 'Failed to get network info' });
  }
});

/**
 * POST /scan/start - Start full network scan
 */
router.post('/start', optionalAuth, async (req, res) => {
  try {
    if (activeScan && activeScan.status === 'running') {
      return res.status(400).json({
        error: 'A scan is already in progress',
        scanId: activeScan.id
      });
    }

    const db = getDatabase();
    const scanId = uuidv4();
    const { subnet, type = 'full' } = req.body;
    const userId = req.user?.id || 'system';

    // Create scan record
    const startTime = new Date().toISOString();
    db.prepare(`
      INSERT INTO scans (id, type, status, progress, started_by, start_time)
      VALUES (?, ?, 'running', 0, ?, ?)
    `).run(scanId, type, userId, startTime);

    activeScan = {
      id: scanId,
      status: 'running',
      progress: 0,
      message: 'Initializing scan...',
      startTime
    };

    if (req.user) {
      logAudit(req.user.id, 'SCAN_STARTED', 'scan', scanId, { type, subnet }, req);
    }

    // Send initial response
    res.json({
      success: true,
      scanId,
      status: 'running',
      message: 'Scan started successfully'
    });

    // Run scan asynchronously
    runFullScan(scanId, subnet, userId);

  } catch (error) {
    logger.error('Start scan error:', error);
    res.status(500).json({ error: 'Failed to start scan' });
  }
});

/**
 * Run full network scan asynchronously
 */
async function runFullScan(scanId, subnet, userId) {
  const db = getDatabase();
  const startTime = Date.now();
  let devicesScanned = 0;
  let portsChecked = 0;
  let vulnsFound = 0;

  try {
    const result = await RealScanner.fullNetworkScan(subnet, (progress, message, stats = {}) => {
      // Update progress and track stats
      devicesScanned = stats.devicesScanned || devicesScanned;
      portsChecked = stats.portsChecked || portsChecked;
      vulnsFound = stats.vulnsFound || vulnsFound;

      // Calculate time estimate
      const elapsed = (Date.now() - startTime) / 1000;
      const estimatedTotal = progress > 5 ? (elapsed / progress) * 100 : 60;
      const remaining = Math.max(0, estimatedTotal - elapsed);
      const mins = Math.floor(remaining / 60);
      const secs = Math.floor(remaining % 60);
      const timeLeft = `${mins}:${secs.toString().padStart(2, '0')}`;

      activeScan.progress = progress;
      activeScan.message = message;
      activeScan.devicesScanned = devicesScanned;
      activeScan.portsChecked = portsChecked;
      activeScan.vulnsFound = vulnsFound;
      activeScan.timeLeft = timeLeft;

      db.prepare('UPDATE scans SET progress = ? WHERE id = ?').run(progress, scanId);

      // Broadcast detailed progress via WebSocket (channel-based)
      broadcast('scan', {
        type: 'scan_progress',
        scanId,
        progress,
        message,
        devicesScanned,
        portsChecked: portsChecked || (devicesScanned * 10),
        vulnsFound,
        timeLeft
      });

      // Also emit as direct scan_progress event for frontend socket.on('scan_progress') listeners
      if (emit && emit.scanProgress) {
        emit.scanProgress(scanId, {
          progress,
          message,
          devicesScanned,
          portsChecked: portsChecked || (devicesScanned * 10),
          vulnsFound,
          timeLeft
        });
      }
    });

    // Complete the scan
    const endTime = new Date().toISOString();

    db.prepare(`
      UPDATE scans SET 
        status = 'completed',
        progress = 100,
        devices_scanned = ?,
        vulnerabilities_found = ?,
        critical_issues = ?,
        end_time = ?,
        results = ?
      WHERE id = ?
    `).run(
      result.devices.length,
      result.summary.critical + result.summary.high,
      result.summary.critical,
      endTime,
      JSON.stringify({
        summary: result.summary,
        vulnerabilities: result.vulnerabilities || []
      }),
      scanId
    );

    saveDatabase();

    // Calculate and store security scores for all scanned devices
    try {
      logger.info(`[SECURITY SCORE] Calculating scores for ${result.devices.length} devices...`);

      for (const device of result.devices) {
        // Get device's vulnerabilities
        const deviceVulns = (result.vulnerabilities || []).filter(v => v.host === device.ip);

        // Store device score
        storeDeviceScore({
          id: device.id,
          open_ports: JSON.stringify(device.openPorts || []),
          has_weak_credentials: device.hasWeakCredentials || false
        }, deviceVulns, scanId);
      }

      // Store aggregate network score
      const networkScore = storeNetworkScore(scanId);
      logger.info(`[SECURITY SCORE] Network score calculated: ${networkScore.networkScore}/100`);

      // Broadcast the new security score
      broadcast('scan', {
        type: 'security_score_updated',
        score: networkScore.networkScore,
        scanId
      });
    } catch (scoreErr) {
      logger.error('[SECURITY SCORE] Error calculating scores:', scoreErr.message);
    }

    activeScan = {
      id: scanId,
      status: 'completed',
      progress: 100,
      message: 'Scan complete',
      result: {
        summary: result.summary,
        vulnerabilities: result.vulnerabilities || []
      }
    };

    // Stream discovered devices to websocket clients for real-time UI updates
    if (Array.isArray(result.devices) && result.devices.length > 0) {
      for (const dev of result.devices) {
        try {
          // Broadcast new_device event for each discovered device
          broadcast('devices', { event: 'new_device', device: dev });
          // small delay to simulate streaming arrival
          // eslint-disable-next-line no-await-in-loop
          await new Promise((r) => setTimeout(r, 150));
        } catch (e) {
          logger.error('Failed to broadcast discovered device', e);
        }
      }
    }

    // If scanner returned network/wifi info, broadcast it on scan channel
    if (result.networkInfo) {
      broadcast('scan', { type: 'network_info', scanId, network: result.networkInfo });
    }

    // Broadcast completion with vulnerabilities
    broadcast('scan', {
      type: 'scan_complete',
      scanId,
      result: result.summary,
      vulnerabilities: result.vulnerabilities || []
    });

    // Broadcast alert update
    broadcast('alerts', {
      type: 'alerts_updated'
    });

    logger.info(`Scan ${scanId} completed successfully`);

  } catch (error) {
    logger.error(`Scan ${scanId} failed:`, error);

    db.prepare(`
      UPDATE scans SET status = 'failed', end_time = ? WHERE id = ?
    `).run(new Date().toISOString(), scanId);

    activeScan = {
      id: scanId,
      status: 'failed',
      progress: 0,
      message: error.message
    };

    broadcast('scan', {
      type: 'scan_failed',
      scanId,
      error: error.message
    });
  }
}

/**
 * GET /scan/status - Get current scan status
 */
router.get('/status', optionalAuth, (req, res) => {
  try {
    if (activeScan) {
      return res.json({
        success: true,
        ...activeScan
      });
    }

    // Get most recent scan from database
    const db = getDatabase();
    const lastScan = db.prepare(`
      SELECT * FROM scans ORDER BY start_time DESC LIMIT 1
    `).get();

    if (lastScan) {
      let result = null;
      if (lastScan.results) {
        try {
          result = JSON.parse(lastScan.results);
        } catch { }
      }

      return res.json({
        success: true,
        ...lastScan,
        result: result // Normalize to 'result' to match activeScan structure
      });
    }

    res.json({
      success: true,
      status: 'idle',
      message: 'No scans performed yet'
    });
  } catch (error) {
    logger.error('Get status error:', error);
    res.status(500).json({ error: 'Failed to get scan status' });
  }
});

/**
 * POST /scan/stop - Stop current scan
 */
router.post('/stop', authenticate, (req, res) => {
  try {
    if (!activeScan || activeScan.status !== 'running') {
      return res.status(400).json({ error: 'No scan is currently running' });
    }

    const db = getDatabase();

    db.prepare(`
      UPDATE scans SET status = 'cancelled', end_time = ? WHERE id = ?
    `).run(new Date().toISOString(), activeScan.id);

    logAudit(req.user.id, 'SCAN_CANCELLED', 'scan', activeScan.id, {}, req);

    activeScan.status = 'cancelled';

    broadcast('scan', {
      type: 'scan_cancelled',
      scanId: activeScan.id
    });

    res.json({
      success: true,
      message: 'Scan cancelled'
    });
  } catch (error) {
    logger.error('Stop scan error:', error);
    res.status(500).json({ error: 'Failed to stop scan' });
  }
});

/**
 * GET /scan/history - Get scan history
 */
router.get('/history', authenticate, (req, res) => {
  try {
    const { limit = 20, offset = 0 } = req.query;
    const db = getDatabase();

    const scans = db.prepare(`
      SELECT * FROM scans 
      ORDER BY start_time DESC 
      LIMIT ? OFFSET ?
    `).all(parseInt(limit), parseInt(offset));

    const total = db.prepare('SELECT COUNT(*) as count FROM scans').get().count;

    // Parse results JSON
    for (const scan of scans) {
      if (scan.results) {
        try {
          scan.results = JSON.parse(scan.results);
        } catch { }
      }
    }

    res.json({
      success: true,
      scans,
      pagination: { total, limit: parseInt(limit), offset: parseInt(offset) }
    });
  } catch (error) {
    logger.error('Get history error:', error);
    res.status(500).json({ error: 'Failed to get scan history' });
  }
});

/**
 * GET /scan/:id - Get specific scan details
 */
router.get('/:id', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(req.params.id);

    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    if (scan.results) {
      try {
        scan.results = JSON.parse(scan.results);
      } catch { }
    }

    res.json({
      success: true,
      scan
    });
  } catch (error) {
    logger.error('Get scan error:', error);
    res.status(500).json({ error: 'Failed to get scan details' });
  }
});

/**
 * POST /scan/ping/:ip - Ping single IP
 */
router.post('/ping/:ip', optionalAuth, async (req, res) => {
  try {
    const { ip } = req.params;

    if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
      return res.status(400).json({ error: 'Invalid IP address' });
    }

    const alive = await RealScanner.pingHost(ip);

    res.json({
      success: true,
      ip,
      alive,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Ping error:', error);
    res.status(500).json({ error: 'Failed to ping host' });
  }
});

/**
 * GET /scan/arp - Get ARP table
 */
router.get('/arp', optionalAuth, async (req, res) => {
  try {
    const devices = await RealScanner.arpScan();

    // Enhance with vendor info
    const enhanced = devices.map(d => ({
      ...d,
      vendor: RealScanner.lookupVendor(d.mac)
    }));

    res.json({
      success: true,
      count: enhanced.length,
      devices: enhanced,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('ARP scan error:', error);
    res.status(500).json({ error: 'Failed to get ARP table' });
  }
});

/**
 * GET /security/score - Latest overall score + device contributions
 */
router.get('/security/score', optionalAuth, (req, res) => {
  try {
    const score = getLatestNetworkScore();
    res.json({ success: true, ...score });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get security score', details: error.message });
  }
});

/**
 * GET /security/trends - Historical scores
 */
router.get('/security/trends', optionalAuth, (req, res) => {
  try {
    const trends = getScoreTrends(20);
    res.json({ success: true, trends });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get security score trends', details: error.message });
  }
});

/**
 * POST /ai/analyze-device { ip }
 * Runs AI analysis and returns reportId and summary
 */
router.post('/ai/analyze-device', optionalAuth, async (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'Missing ip' });
  try {
    const result = await analyzeDevice(ip);
    res.json({ success: true, ...result });
  } catch (error) {
    res.status(500).json({ error: 'AI analysis failed', details: error.message });
  }
});

/**
 * GET /ai/reports/:id
 * Returns AI analysis report
 */
router.get('/ai/reports/:id', optionalAuth, (req, res) => {
  const { id } = req.params;
  try {
    const report = getReport(id);
    if (!report) return res.status(404).json({ error: 'Report not found' });

    // Parse the JSON report data for compatibility
    try {
      if (report.report_data) {
        report.report_data = JSON.parse(report.report_data);
      }
    } catch (e) {
      logger.warn('Failed to parse report_data for report', id);
    }

    res.json({ success: true, report });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get report', details: error.message });
  }
});

module.exports = router;
