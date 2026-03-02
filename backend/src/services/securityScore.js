/**
 * Security Score Calculation Service
 * Calculates device and network scores after scan, CVE, and credential audit
 */
const { getDatabase } = require('../database/init');
const { v4: uuidv4 } = require('uuid');

function calculateDeviceScore(device, vulns = [], scanId = null) {
  let score = 100;
  const openPorts = Array.isArray(device.open_ports) ? device.open_ports.length : (device.open_ports ? JSON.parse(device.open_ports).length : 0);
  const criticalCVEs = vulns.filter(v => v.severity === 'critical').length;
  const highCVEs = vulns.filter(v => v.severity === 'high').length;
  const mediumCVEs = vulns.filter(v => v.severity === 'medium').length;
  const weakPassword = device.has_weak_credentials ? 1 : 0;
  // Exposed service: risky ports open
  const riskyPorts = [23, 7547, 5555, 69, 161, 502, 37777, 5357];
  const exposedService = (device.open_ports ? JSON.parse(device.open_ports).some(p => riskyPorts.includes(p.port || p)) : false) ? 1 : 0;

  score -= (5 * openPorts);
  score -= (10 * criticalCVEs);
  score -= (6 * highCVEs);
  score -= (3 * mediumCVEs);
  score -= (weakPassword ? 15 : 0);
  score -= (exposedService ? 10 : 0);
  score = Math.max(0, score);

  return {
    score,
    openPorts,
    criticalCVEs,
    highCVEs,
    mediumCVEs,
    weakPassword,
    exposedService,
    scanId,
    deviceId: device.id
  };
}

function storeDeviceScore(device, vulns, scanId = null) {
  const db = getDatabase();
  const result = calculateDeviceScore(device, vulns, scanId);
  db.prepare(`
    INSERT INTO security_scores (id, scan_id, device_id, score, open_ports, critical_cves, high_cves, medium_cves, weak_password, exposed_service, timestamp, details)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    uuidv4(),
    scanId,
    device.id,
    result.score,
    result.openPorts,
    result.criticalCVEs,
    result.highCVEs,
    result.mediumCVEs,
    result.weakPassword,
    result.exposedService,
    new Date().toISOString(),
    JSON.stringify(result)
  );
  return result;
}

function calculateNetworkScore(scanId = null) {
  const db = getDatabase();
  const scores = db.prepare('SELECT * FROM security_scores WHERE scan_id = ?').all(scanId);
  const deviceScores = scores.filter(s => s.device_id !== null && s.score !== null);
  if (!deviceScores.length) return { networkScore: 100, deviceScores: [] };

  // Aggregate: weighted average based on device risk
  const networkScore = Math.round(deviceScores.reduce((sum, s) => sum + s.score, 0) / deviceScores.length);
  return {
    networkScore,
    deviceScores: scores
  };
}

function storeNetworkScore(scanId) {
  const agg = calculateNetworkScore(scanId);
  const db = getDatabase();
  db.prepare(`
    INSERT INTO security_scores (id, scan_id, device_id, score, network_score, timestamp, details)
    VALUES (?, ?, NULL, NULL, ?, ?, ?)
  `).run(
    uuidv4(),
    scanId,
    agg.networkScore,
    new Date().toISOString(),
    JSON.stringify(agg)
  );
  return agg;
}

function getLatestNetworkScore() {
  const db = getDatabase();
  const row = db.prepare('SELECT * FROM security_scores WHERE device_id IS NULL ORDER BY timestamp DESC LIMIT 1').get();
  if (!row) return { networkScore: 100, deviceScores: [] };
  return JSON.parse(row.details);
}

function getScoreTrends(limit = 20) {
  const db = getDatabase();
  const rows = db.prepare('SELECT * FROM security_scores WHERE device_id IS NULL ORDER BY timestamp DESC LIMIT ?').all(limit);
  return rows.map(r => ({ timestamp: r.timestamp, networkScore: r.network_score, details: JSON.parse(r.details) }));
}

module.exports = {
  calculateDeviceScore,
  storeDeviceScore,
  calculateNetworkScore,
  storeNetworkScore,
  getLatestNetworkScore,
  getScoreTrends
};
