const express = require('express');
const { getDatabase } = require('../database/init');
const { optionalAuth } = require('../middleware/auth');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * Calculate REAL security score based on actual scanned data
 * RULES:
 * - Score = 0 if no scan has ever run
 * - Start from 100 after scan
 * - Subtract based on risk levels:
 *   - Low risk: -2 per issue
 *   - Medium risk: -5 per issue
 *   - High risk: -10 per issue
 *   - Critical risk: -20 per issue
 * - Minimum score = 0
 */
function calculateSecurityScore(db) {
  try {
    // Check if any scan has completed
    const lastScan = db.prepare("SELECT * FROM scans WHERE status = 'completed' ORDER BY end_time DESC LIMIT 1").get();

    // If no scan has ever run, return 0 with special status
    if (!lastScan) {
      return {
        score: 0,
        grade: 'N/A',
        status: 'no_scan_data',
        message: 'No scan data available',
        factors: {},
        breakdown: {}
      };
    }

    // Get all devices from the latest scan
    const devices = db.prepare('SELECT * FROM devices').all();
    const totalDevices = devices.length;

    if (totalDevices === 0) {
      return {
        score: 0,
        grade: 'N/A',
        status: 'no_devices',
        message: 'No devices found in last scan',
        factors: {},
        breakdown: {}
      };
    }

    // Get vulnerabilities
    const vulns = db.prepare('SELECT severity FROM vulnerabilities').all();
    const criticalVulns = vulns.filter(v => v.severity === 'critical').length;
    const highVulns = vulns.filter(v => v.severity === 'high').length;
    const mediumVulns = vulns.filter(v => v.severity === 'medium').length;
    const lowVulns = vulns.filter(v => v.severity === 'low').length;

    // Get alerts
    const alerts = db.prepare("SELECT severity FROM alerts WHERE acknowledged = 0").all();
    const criticalAlerts = alerts.filter(a => a.severity === 'critical').length;
    const highAlerts = alerts.filter(a => a.severity === 'high').length;
    const mediumAlerts = alerts.filter(a => a.severity === 'medium').length;
    const lowAlerts = alerts.filter(a => a.severity === 'low').length;

    // Get device risk levels
    const criticalDevices = devices.filter(d => d.risk_level === 'critical').length;
    const highRiskDevices = devices.filter(d => d.risk_level === 'high').length;
    const mediumRiskDevices = devices.filter(d => d.risk_level === 'medium').length;
    const lowRiskDevices = devices.filter(d => d.risk_level === 'low').length;

    // Calculate score using new formula
    // Start from 100, subtract based on risk levels
    let score = 100;

    // Vulnerability deductions
    const criticalVulnDeduction = criticalVulns * 20;
    const highVulnDeduction = highVulns * 10;
    const mediumVulnDeduction = mediumVulns * 5;
    const lowVulnDeduction = lowVulns * 2;

    // Alert deductions
    const criticalAlertDeduction = criticalAlerts * 20;
    const highAlertDeduction = highAlerts * 10;
    const mediumAlertDeduction = mediumAlerts * 5;
    const lowAlertDeduction = lowAlerts * 2;

    // Device risk deductions
    const criticalDeviceDeduction = criticalDevices * 20;
    const highDeviceDeduction = highRiskDevices * 10;
    const mediumDeviceDeduction = mediumRiskDevices * 5;
    const lowDeviceDeduction = lowRiskDevices * 2;

    // Apply deductions
    score -= criticalVulnDeduction + highVulnDeduction + mediumVulnDeduction + lowVulnDeduction;
    score -= criticalAlertDeduction + highAlertDeduction + mediumAlertDeduction + lowAlertDeduction;
    score -= criticalDeviceDeduction + highDeviceDeduction + mediumDeviceDeduction + lowDeviceDeduction;

    // Ensure score is between 0 and 100
    score = Math.max(0, Math.min(100, score));

    // Calculate grade
    let grade = 'F';
    if (score >= 90) grade = 'A';
    else if (score >= 80) grade = 'B';
    else if (score >= 70) grade = 'C';
    else if (score >= 60) grade = 'D';

    return {
      score: Math.round(score),
      grade,
      status: 'scan_complete',
      message: `Security score based on ${totalDevices} devices`,
      lastScanId: lastScan.id,
      lastScanTime: lastScan.end_time,
      factors: {
        totalDevices,
        criticalVulns,
        highVulns,
        mediumVulns,
        lowVulns,
        criticalAlerts,
        highAlerts,
        mediumAlerts,
        lowAlerts,
        criticalDevices,
        highRiskDevices,
        mediumRiskDevices,
        lowRiskDevices
      },
      breakdown: {
        criticalVulnDeduction,
        highVulnDeduction,
        mediumVulnDeduction,
        lowVulnDeduction,
        criticalAlertDeduction,
        highAlertDeduction,
        mediumAlertDeduction,
        lowAlertDeduction,
        criticalDeviceDeduction,
        highDeviceDeduction,
        mediumDeviceDeduction,
        lowDeviceDeduction
      }
    };
  } catch (error) {
    logger.error('Error calculating security score:', error);
    return { score: 0, grade: 'N/A', status: 'error', error: error.message };
  }
}

/**
 * GET /security/score - Get real-time security score
 */
router.get('/score', optionalAuth, (req, res) => {
  try {
    const db = getDatabase();
    const result = calculateSecurityScore(db);

    res.json({
      success: true,
      ...result,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Get security score error:', error);
    res.status(500).json({ error: 'Failed to calculate security score' });
  }
});

/**
 * GET /security/trends - Get security trends over time
 */
router.get('/trends', optionalAuth, (req, res) => {
  try {
    const db = getDatabase();
    const { days = 7 } = req.query;

    // Get current score
    const currentScore = calculateSecurityScore(db);

    // Get device count trend
    const deviceTrend = db.prepare(`
      SELECT DATE(discovered_at) as date, COUNT(*) as count
      FROM devices
      WHERE discovered_at >= datetime('now', '-${days} days')
      GROUP BY DATE(discovered_at)
      ORDER BY date
    `).all();

    // Get alert trend
    const alertTrend = db.prepare(`
      SELECT DATE(created_at) as date, COUNT(*) as count, severity
      FROM alerts
      WHERE created_at >= datetime('now', '-${days} days')
      GROUP BY DATE(created_at), severity
      ORDER BY date
    `).all();

    // Get vulnerability trend
    const vulnTrend = db.prepare(`
      SELECT DATE(discovered_at) as date, COUNT(*) as count, severity
      FROM vulnerabilities
      WHERE discovered_at >= datetime('now', '-${days} days')
      GROUP BY DATE(discovered_at), severity
      ORDER BY date
    `).all();

    res.json({
      success: true,
      currentScore: currentScore.score,
      grade: currentScore.grade,
      trends: {
        devices: deviceTrend,
        alerts: alertTrend,
        vulnerabilities: vulnTrend
      },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Get security trends error:', error);
    res.status(500).json({ error: 'Failed to get security trends' });
  }
});

/**
 * GET /security/summary - Get security summary
 */
router.get('/summary', optionalAuth, (req, res) => {
  try {
    const db = getDatabase();

    const devices = db.prepare('SELECT COUNT(*) as count FROM devices').get().count;
    const onlineDevices = db.prepare("SELECT COUNT(*) as count FROM devices WHERE status = 'online'").get().count;
    const criticalDevices = db.prepare("SELECT COUNT(*) as count FROM devices WHERE risk_level = 'critical'").get().count;
    const highRiskDevices = db.prepare("SELECT COUNT(*) as count FROM devices WHERE risk_level = 'high'").get().count;

    const alerts = db.prepare('SELECT COUNT(*) as count FROM alerts WHERE acknowledged = 0').get().count;
    const criticalAlerts = db.prepare("SELECT COUNT(*) as count FROM alerts WHERE severity = 'critical' AND acknowledged = 0").get().count;

    const vulnerabilities = db.prepare('SELECT COUNT(*) as count FROM vulnerabilities').get().count;
    const criticalVulns = db.prepare("SELECT COUNT(*) as count FROM vulnerabilities WHERE severity = 'critical'").get().count;

    const score = calculateSecurityScore(db);

    res.json({
      success: true,
      score: score.score,
      grade: score.grade,
      summary: {
        devices: {
          total: devices,
          online: onlineDevices,
          critical: criticalDevices,
          highRisk: highRiskDevices
        },
        alerts: {
          unacknowledged: alerts,
          critical: criticalAlerts
        },
        vulnerabilities: {
          total: vulnerabilities,
          critical: criticalVulns
        }
      },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Get security summary error:', error);
    res.status(500).json({ error: 'Failed to get security summary' });
  }
});

module.exports = router;
