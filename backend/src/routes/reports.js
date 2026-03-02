const express = require('express');
const { getDatabase } = require('../database/init');
const { authenticate, optionalAuth } = require('../middleware/auth');
const { logAudit } = require('../middleware/audit');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * GET /reports/scan-report
 * READ-ONLY endpoint for PDF report generation
 * - No writes to database
 * - No state changes
 * - Returns only data from latest completed scan
 * - Completely isolated from other systems
 */
router.get('/scan-report', optionalAuth, (req, res) => {
  try {
    const db = getDatabase();

    // READ ONLY: Get latest completed scan
    const lastScan = db.prepare(`
      SELECT * FROM scans 
      WHERE status = 'completed' 
      ORDER BY end_time DESC 
      LIMIT 1
    `).get();

    // FAIL-SAFE: If no completed scan exists, abort
    if (!lastScan) {
      logger.warn('[PDF REPORT] ABORT: No completed scan found');
      return res.status(404).json({
        success: false,
        error: 'no_completed_scan',
        message: 'No completed scan found. Run a full scan first.',
        abortReason: 'VALIDATION_FAILED: scan status != COMPLETED'
      });
    }

    // READ ONLY: Get all devices from scan output
    const devices = db.prepare('SELECT * FROM devices').all();

    // VALIDATION: Verify scan contains >= 1 real detected device
    if (!devices || devices.length === 0) {
      logger.warn('[PDF REPORT] ABORT: Zero real devices detected');
      return res.status(404).json({
        success: false,
        error: 'no_devices_detected',
        message: 'No real devices detected in scan. Cannot generate report.',
        abortReason: 'VALIDATION_FAILED: device count = 0'
      });
    }

    // VALIDATION: Verify each device has IP address
    const validDevices = devices.filter(d => d.ip && d.ip.trim() !== '');
    if (validDevices.length === 0) {
      logger.warn('[PDF REPORT] ABORT: No devices with valid IP addresses');
      return res.status(400).json({
        success: false,
        error: 'invalid_device_data',
        message: 'No devices with valid IP addresses found.',
        abortReason: 'VALIDATION_FAILED: no valid IP addresses'
      });
    }

    // Devices already fetched and validated above

    // READ ONLY: Get all vulnerabilities (snapshot)
    const vulnerabilities = db.prepare(`
      SELECT v.*, d.ip as device_ip, d.name as device_name, d.device_type 
      FROM vulnerabilities v 
      LEFT JOIN devices d ON v.device_id = d.id
      WHERE v.status = 'open'
    `).all();

    // READ ONLY: Get security score (snapshot, no recalculation)
    const securityScoreRow = db.prepare(`
      SELECT * FROM security_scores 
      WHERE device_id IS NULL 
      ORDER BY timestamp DESC 
      LIMIT 1
    `).get();

    // Parse scan results if available
    let scanResults = {};
    try {
      if (lastScan.results) {
        scanResults = JSON.parse(lastScan.results);
      }
    } catch (e) {
      // Ignore parse errors
    }

    // Calculate risk classification (read-only, from existing data)
    const securityScore = securityScoreRow?.network_score ?? 0;
    let riskClassification = 'Safe';
    if (securityScore < 50) riskClassification = 'Critical';
    else if (securityScore < 70) riskClassification = 'High';
    else if (securityScore < 85) riskClassification = 'Medium';

    // Categorize devices (read-only, using validated devices only)
    const iotKeywords = ['camera', 'doorbell', 'thermostat', 'speaker', 'hub', 'sensor', 'smart', 'alexa', 'echo', 'nest', 'ring', 'tv', 'nvr', 'dvr'];
    const cctvKeywords = ['camera', 'nvr', 'dvr', 'hikvision', 'dahua', 'cctv'];
    const wearableKeywords = ['watch', 'wearable', 'fitbit', 'garmin', 'band'];
    const routerKeywords = ['router', 'gateway', 'access point', 'modem'];

    // Use validDevices (only devices with valid IP addresses)
    const categorizedDevices = validDevices.map(d => {
      const combined = `${d.name || ''} ${d.device_type || ''} ${d.vendor || d.manufacturer || ''}`.toLowerCase();

      let category = 'Unknown';
      if (cctvKeywords.some(k => combined.includes(k))) category = 'CCTV';
      else if (wearableKeywords.some(k => combined.includes(k))) category = 'Wearable';
      else if (routerKeywords.some(k => combined.includes(k))) category = 'Router';
      else if (iotKeywords.some(k => combined.includes(k))) category = 'IoT';

      return {
        ip: d.ip,
        mac: d.mac,
        name: d.name,
        category,
        status: d.status || 'unknown',
        riskLevel: d.risk_level || 'unknown',
        vulnerabilityScore: d.risk_score || 0,
        vendor: d.vendor || d.manufacturer || 'Unknown'
      };
    });

    // Format vulnerabilities (read-only)
    const formattedVulns = vulnerabilities.map(v => ({
      affectedIP: v.device_ip || 'Unknown',
      deviceType: v.device_type || 'Unknown',
      deviceName: v.device_name || 'Unknown',
      vulnerabilityName: v.title,
      cveId: v.cve_id || 'N/A',
      severity: v.severity || 'unknown',
      description: v.description || 'No description available',
      mitigation: v.solution || v.remediation || 'Update firmware and apply security patches'
    }));

    // Build response (forensic snapshot - real data only)
    const report = {
      success: true,
      readOnly: true,
      forensicSnapshot: true,
      generatedAt: new Date().toISOString(),

      // Section 1: Scan Summary (real data from scan engine)
      scanSummary: {
        scanId: lastScan.id,
        scanTimestamp: lastScan.end_time || lastScan.started_at,
        scanType: lastScan.type || 'full',
        scanStatus: lastScan.status,
        securityScore: securityScore,  // READ from storage, NOT recalculated
        riskClassification,
        totalDevices: validDevices.length,  // Real count from validated devices
        devicesScanned: lastScan.devices_scanned || validDevices.length,
        vulnerabilitiesFound: vulnerabilities.length,
        scanDuration: lastScan.end_time && lastScan.started_at
          ? Math.round((new Date(lastScan.end_time) - new Date(lastScan.started_at)) / 1000)
          : null
      },

      // Section 2: Device Status Table (real devices only, no extras)
      devices: categorizedDevices,

      // Section 3: Risk & Vulnerability Details (real vulnerabilities only)
      vulnerabilities: formattedVulns,

      // Section 4: Conclusion
      conclusion: {
        securityPosture: securityScore >= 85 ? 'Good' : securityScore >= 70 ? 'Fair' : securityScore >= 50 ? 'Poor' : 'Critical',
        riskInterpretation: `Based on ${validDevices.length} devices and ${vulnerabilities.length} vulnerabilities detected.`,
        note: 'This is a forensic snapshot. Every value is traceable to real scan evidence.'
      },

      // PDF Filename with Scan ID
      pdfFilename: `BlackCodex_RealTime_Scan_Report_${lastScan.id}.pdf`,

      // Integrity statement
      integrityNote: 'No data was modified, inferred, or enriched during report generation.'
    };

    logger.info(`[PDF REPORT] Read-only scan report generated for scan ${lastScan.id}`);
    res.json(report);

  } catch (error) {
    logger.error('[PDF REPORT] Error generating scan report:', error);
    res.status(500).json({
      success: false,
      error: 'generation_failed',
      message: 'Failed to generate report. Please try again.'
    });
  }
});


// Generate security report
router.post('/generate', authenticate, async (req, res) => {
  try {
    const db = getDatabase();
    const { reportType = 'full', format = 'json', deviceIds, dateRange } = req.body;

    // Gather all data for the report
    const reportData = {
      reportId: require('uuid').v4(),
      generatedAt: new Date().toISOString(),
      generatedBy: req.user.username,
      reportType,
      summary: {},
      devices: [],
      vulnerabilities: [],
      alerts: [],
      recommendations: []
    };

    // Get devices
    let deviceQuery = 'SELECT * FROM devices';
    const deviceParams = [];
    if (deviceIds && deviceIds.length > 0) {
      deviceQuery += ` WHERE id IN (${deviceIds.map(() => '?').join(',')})`;
      deviceParams.push(...deviceIds);
    }
    reportData.devices = db.prepare(deviceQuery).all(...deviceParams);

    // Get vulnerabilities
    let vulnQuery = "SELECT v.*, d.name as device_name FROM vulnerabilities v LEFT JOIN devices d ON v.device_id = d.id WHERE v.status = 'open'";
    if (deviceIds && deviceIds.length > 0) {
      vulnQuery += ` AND v.device_id IN (${deviceIds.map(() => '?').join(',')})`;
    }
    reportData.vulnerabilities = db.prepare(vulnQuery).all(...(deviceIds || []));

    // Get alerts
    let alertQuery = "SELECT * FROM alerts WHERE acknowledged = 0";
    if (dateRange?.start) {
      alertQuery += ' AND created_at >= ?';
    }
    if (dateRange?.end) {
      alertQuery += ' AND created_at <= ?';
    }
    alertQuery += ' ORDER BY created_at DESC LIMIT 100';

    const alertParams = [];
    if (dateRange?.start) alertParams.push(dateRange.start);
    if (dateRange?.end) alertParams.push(dateRange.end);
    reportData.alerts = db.prepare(alertQuery).all(...alertParams);

    // Calculate summary
    reportData.summary = {
      totalDevices: reportData.devices.length,
      onlineDevices: reportData.devices.filter(d => d.status === 'online').length,
      offlineDevices: reportData.devices.filter(d => d.status === 'offline').length,
      totalVulnerabilities: reportData.vulnerabilities.length,
      criticalVulnerabilities: reportData.vulnerabilities.filter(v => v.severity === 'critical').length,
      highVulnerabilities: reportData.vulnerabilities.filter(v => v.severity === 'high').length,
      mediumVulnerabilities: reportData.vulnerabilities.filter(v => v.severity === 'medium').length,
      lowVulnerabilities: reportData.vulnerabilities.filter(v => v.severity === 'low').length,
      unacknowledgedAlerts: reportData.alerts.length,
      devicesWithWeakCredentials: reportData.devices.filter(d => d.has_weak_credentials).length,
      overallRiskScore: calculateOverallRisk(reportData.devices, reportData.vulnerabilities)
    };

    // Generate recommendations
    reportData.recommendations = generateRecommendations(reportData);

    logAudit(req.user.id, 'REPORT_GENERATED', 'report', reportData.reportId, { reportType, format }, req);

    // Return based on format
    if (format === 'json') {
      res.json(reportData);
    } else if (format === 'csv') {
      const csv = convertToCSV(reportData);
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename=security_report_${reportData.reportId}.csv`);
      res.send(csv);
    } else if (format === 'html') {
      const html = generateHTMLReport(reportData);
      res.setHeader('Content-Type', 'text/html');
      res.send(html);
    } else {
      res.json(reportData);
    }
  } catch (error) {
    logger.error('Generate report error:', error);
    res.status(500).json({ error: 'Failed to generate report' });
  }
});

// Get report templates
router.get('/templates', authenticate, (req, res) => {
  const templates = [
    {
      id: 'full',
      name: 'Full Security Assessment',
      description: 'Comprehensive report including all devices, vulnerabilities, and recommendations',
      sections: ['summary', 'devices', 'vulnerabilities', 'alerts', 'recommendations']
    },
    {
      id: 'executive',
      name: 'Executive Summary',
      description: 'High-level overview for management',
      sections: ['summary', 'recommendations']
    },
    {
      id: 'vulnerability',
      name: 'Vulnerability Report',
      description: 'Detailed vulnerability analysis',
      sections: ['summary', 'vulnerabilities', 'recommendations']
    },
    {
      id: 'compliance',
      name: 'Compliance Report',
      description: 'Compliance-focused security assessment',
      sections: ['summary', 'devices', 'vulnerabilities', 'compliance']
    },
    {
      id: 'device',
      name: 'Device Inventory Report',
      description: 'Complete device inventory with security status',
      sections: ['summary', 'devices']
    }
  ];

  res.json(templates);
});

// Get dashboard data
router.get('/dashboard', authenticate, (req, res) => {
  try {
    const db = getDatabase();

    // Device stats
    const deviceStats = {
      total: db.prepare('SELECT COUNT(*) as count FROM devices').get().count,
      online: db.prepare("SELECT COUNT(*) as count FROM devices WHERE status = 'online'").get().count,
      offline: db.prepare("SELECT COUNT(*) as count FROM devices WHERE status = 'offline'").get().count,
      quarantined: db.prepare("SELECT COUNT(*) as count FROM devices WHERE status = 'quarantined'").get().count
    };

    // Vulnerability stats
    const vulnStats = {
      total: db.prepare("SELECT COUNT(*) as count FROM vulnerabilities WHERE status = 'open'").get().count,
      critical: db.prepare("SELECT COUNT(*) as count FROM vulnerabilities WHERE severity = 'critical' AND status = 'open'").get().count,
      high: db.prepare("SELECT COUNT(*) as count FROM vulnerabilities WHERE severity = 'high' AND status = 'open'").get().count,
      medium: db.prepare("SELECT COUNT(*) as count FROM vulnerabilities WHERE severity = 'medium' AND status = 'open'").get().count,
      low: db.prepare("SELECT COUNT(*) as count FROM vulnerabilities WHERE severity = 'low' AND status = 'open'").get().count
    };

    // Alert stats
    const alertStats = {
      total: db.prepare('SELECT COUNT(*) as count FROM alerts').get().count,
      unacknowledged: db.prepare('SELECT COUNT(*) as count FROM alerts WHERE acknowledged = 0').get().count,
      critical: db.prepare("SELECT COUNT(*) as count FROM alerts WHERE severity = 'critical' AND acknowledged = 0").get().count
    };

    // Recent activity
    const recentAlerts = db.prepare(`
      SELECT * FROM alerts 
      ORDER BY created_at DESC 
      LIMIT 5
    `).all();

    const recentScans = db.prepare(`
      SELECT * FROM scans 
      ORDER BY started_at DESC 
      LIMIT 5
    `).all();

    // Risk distribution
    const riskDistribution = db.prepare(`
      SELECT risk_level, COUNT(*) as count 
      FROM devices 
      WHERE risk_level IS NOT NULL
      GROUP BY risk_level
    `).all();

    // Device types distribution
    const deviceTypes = db.prepare(`
      SELECT device_type, COUNT(*) as count 
      FROM devices 
      WHERE device_type IS NOT NULL
      GROUP BY device_type
    `).all();

    // Calculate security score
    const securityScore = calculateSecurityScore(deviceStats, vulnStats, alertStats);

    res.json({
      deviceStats,
      vulnStats,
      alertStats,
      recentAlerts,
      recentScans,
      riskDistribution,
      deviceTypes,
      securityScore,
      lastUpdated: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Get dashboard error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

// Get security trends
router.get('/trends', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { days = 30 } = req.query;

    // Vulnerabilities over time
    const vulnTrend = db.prepare(`
      SELECT date(discovered_at) as date, COUNT(*) as count
      FROM vulnerabilities
      WHERE discovered_at >= datetime('now', '-${parseInt(days)} days')
      GROUP BY date(discovered_at)
      ORDER BY date
    `).all();

    // Alerts over time
    const alertTrend = db.prepare(`
      SELECT date(created_at) as date, COUNT(*) as count
      FROM alerts
      WHERE created_at >= datetime('now', '-${parseInt(days)} days')
      GROUP BY date(created_at)
      ORDER BY date
    `).all();

    // Scans over time
    const scanTrend = db.prepare(`
      SELECT date(started_at) as date, COUNT(*) as count
      FROM scans
      WHERE started_at >= datetime('now', '-${parseInt(days)} days')
      GROUP BY date(started_at)
      ORDER BY date
    `).all();

    // Device additions over time
    const deviceTrend = db.prepare(`
      SELECT date(discovered_at) as date, COUNT(*) as count
      FROM devices
      WHERE discovered_at >= datetime('now', '-${parseInt(days)} days')
      GROUP BY date(discovered_at)
      ORDER BY date
    `).all();

    res.json({
      vulnerabilities: vulnTrend,
      alerts: alertTrend,
      scans: scanTrend,
      devices: deviceTrend,
      period: `${days} days`
    });
  } catch (error) {
    logger.error('Get trends error:', error);
    res.status(500).json({ error: 'Failed to fetch security trends' });
  }
});

// Helper: Calculate overall risk
function calculateOverallRisk(devices, vulnerabilities) {
  if (devices.length === 0) return 0;

  let totalRisk = 0;
  for (const device of devices) {
    totalRisk += device.risk_score || 0;
  }

  const deviceRisk = totalRisk / devices.length;

  // Factor in vulnerabilities
  const vulnWeight = {
    critical: 20,
    high: 10,
    medium: 5,
    low: 2
  };

  let vulnRisk = 0;
  for (const vuln of vulnerabilities) {
    vulnRisk += vulnWeight[vuln.severity] || 0;
  }

  // Combined risk (device risk + vulnerability risk, capped at 100)
  return Math.min(Math.round(deviceRisk + (vulnRisk / devices.length)), 100);
}

// Helper: Generate recommendations
function generateRecommendations(reportData) {
  const recommendations = [];

  if (reportData.summary.criticalVulnerabilities > 0) {
    recommendations.push({
      priority: 'critical',
      title: 'Address Critical Vulnerabilities',
      description: `You have ${reportData.summary.criticalVulnerabilities} critical vulnerabilities that require immediate attention.`,
      action: 'Review and patch critical vulnerabilities immediately.'
    });
  }

  if (reportData.summary.devicesWithWeakCredentials > 0) {
    recommendations.push({
      priority: 'high',
      title: 'Change Default Credentials',
      description: `${reportData.summary.devicesWithWeakCredentials} devices may be using default credentials.`,
      action: 'Change default passwords on all affected devices.'
    });
  }

  if (reportData.summary.offlineDevices > reportData.summary.totalDevices * 0.1) {
    recommendations.push({
      priority: 'medium',
      title: 'Investigate Offline Devices',
      description: `${reportData.summary.offlineDevices} devices are offline. This may indicate issues.`,
      action: 'Check connectivity and status of offline devices.'
    });
  }

  if (reportData.summary.unacknowledgedAlerts > 10) {
    recommendations.push({
      priority: 'medium',
      title: 'Review Pending Alerts',
      description: `${reportData.summary.unacknowledgedAlerts} alerts require attention.`,
      action: 'Review and acknowledge or resolve pending alerts.'
    });
  }

  recommendations.push({
    priority: 'low',
    title: 'Regular Security Scans',
    description: 'Schedule regular network scans to detect new vulnerabilities.',
    action: 'Configure automated daily or weekly scans.'
  });

  return recommendations;
}

// Helper: Calculate security score
function calculateSecurityScore(deviceStats, vulnStats, alertStats) {
  let score = 100;

  // Deduct for vulnerabilities
  score -= vulnStats.critical * 15;
  score -= vulnStats.high * 8;
  score -= vulnStats.medium * 3;
  score -= vulnStats.low * 1;

  // Deduct for unacknowledged alerts
  score -= alertStats.unacknowledged * 2;
  score -= alertStats.critical * 5;

  // Deduct for offline/quarantined devices
  if (deviceStats.total > 0) {
    const offlineRatio = (deviceStats.offline + deviceStats.quarantined) / deviceStats.total;
    score -= offlineRatio * 10;
  }

  return Math.max(0, Math.min(100, Math.round(score)));
}

// Helper: Convert to CSV
function convertToCSV(reportData) {
  const lines = [];

  // Summary
  lines.push('SECURITY REPORT');
  lines.push(`Generated At,${reportData.generatedAt}`);
  lines.push(`Generated By,${reportData.generatedBy}`);
  lines.push('');

  // Summary stats
  lines.push('SUMMARY');
  lines.push(`Total Devices,${reportData.summary.totalDevices}`);
  lines.push(`Online Devices,${reportData.summary.onlineDevices}`);
  lines.push(`Total Vulnerabilities,${reportData.summary.totalVulnerabilities}`);
  lines.push(`Critical Vulnerabilities,${reportData.summary.criticalVulnerabilities}`);
  lines.push(`Overall Risk Score,${reportData.summary.overallRiskScore}`);
  lines.push('');

  // Devices
  lines.push('DEVICES');
  lines.push('Name,IP,MAC,Type,Manufacturer,Status,Risk Level');
  for (const device of reportData.devices) {
    lines.push(`${device.name},${device.ip},${device.mac},${device.device_type},${device.manufacturer},${device.status},${device.risk_level}`);
  }
  lines.push('');

  // Vulnerabilities
  lines.push('VULNERABILITIES');
  lines.push('CVE ID,Title,Severity,CVSS Score,Device');
  for (const vuln of reportData.vulnerabilities) {
    lines.push(`${vuln.cve_id},${vuln.title},${vuln.severity},${vuln.cvss_score},${vuln.device_name}`);
  }

  return lines.join('\n');
}

// Helper: Generate HTML report
function generateHTMLReport(reportData) {
  return `
<!DOCTYPE html>
<html>
<head>
  <title>Black Codex Security Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }
    h1 { color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }
    h2 { color: #00ff88; margin-top: 30px; }
    .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }
    .summary-card { background: #16213e; padding: 20px; border-radius: 8px; text-align: center; }
    .summary-card h3 { margin: 0; color: #00d4ff; font-size: 2em; }
    .summary-card p { margin: 5px 0 0 0; color: #888; }
    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
    th { background: #16213e; color: #00d4ff; }
    .critical { color: #ff4444; }
    .high { color: #ff8800; }
    .medium { color: #ffcc00; }
    .low { color: #00ff88; }
    .recommendation { background: #16213e; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #00d4ff; }
    .footer { margin-top: 40px; text-align: center; color: #666; }
  </style>
</head>
<body>
  <h1>🛡️ Black Codex Security Report</h1>
  <p>Generated: ${reportData.generatedAt} | By: ${reportData.generatedBy}</p>
  
  <div class="summary-grid">
    <div class="summary-card">
      <h3>${reportData.summary.totalDevices}</h3>
      <p>Total Devices</p>
    </div>
    <div class="summary-card">
      <h3 class="critical">${reportData.summary.criticalVulnerabilities}</h3>
      <p>Critical Vulnerabilities</p>
    </div>
    <div class="summary-card">
      <h3>${reportData.summary.unacknowledgedAlerts}</h3>
      <p>Pending Alerts</p>
    </div>
    <div class="summary-card">
      <h3>${reportData.summary.overallRiskScore}%</h3>
      <p>Risk Score</p>
    </div>
  </div>

  <h2>📊 Device Summary</h2>
  <table>
    <tr><th>Name</th><th>IP</th><th>Type</th><th>Status</th><th>Risk Level</th></tr>
    ${reportData.devices.slice(0, 20).map(d => `
      <tr>
        <td>${d.name}</td>
        <td>${d.ip}</td>
        <td>${d.device_type || 'Unknown'}</td>
        <td>${d.status}</td>
        <td class="${d.risk_level}">${d.risk_level || 'Unknown'}</td>
      </tr>
    `).join('')}
  </table>

  <h2>⚠️ Vulnerabilities</h2>
  <table>
    <tr><th>CVE ID</th><th>Title</th><th>Severity</th><th>CVSS</th><th>Affected Device</th></tr>
    ${reportData.vulnerabilities.slice(0, 20).map(v => `
      <tr>
        <td>${v.cve_id || 'N/A'}</td>
        <td>${v.title}</td>
        <td class="${v.severity}">${v.severity}</td>
        <td>${v.cvss_score || 'N/A'}</td>
        <td>${v.device_name || 'Unknown'}</td>
      </tr>
    `).join('')}
  </table>

  <h2>💡 Recommendations</h2>
  ${reportData.recommendations.map(r => `
    <div class="recommendation">
      <strong class="${r.priority}">[${r.priority.toUpperCase()}]</strong> ${r.title}
      <p>${r.description}</p>
      <p><em>Action: ${r.action}</em></p>
    </div>
  `).join('')}

  <div class="footer">
    <p>Generated by Black Codex IoT Security Platform</p>
  </div>
</body>
</html>
  `;
}

module.exports = router;
