const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { getDatabase, saveDatabase } = require('../database/init');
const { authenticate, optionalAuth } = require('../middleware/auth');
const { logAudit } = require('../middleware/audit');
const logger = require('../utils/logger');
const { scanPorts, getServiceName, grabBanner, checkPort, fullNetworkScan, arpScan, lookupVendor } = require('../services/realNetworkScanner');
const { getDeviceCVEs } = require('../services/cveLookup');
const { callAIEngine } = require('../services/aiAnalysis');
const { RISKY_PORTS } = require('../utils/constants');

const router = express.Router();

// Analyze device with AI - NOW WITH REAL-TIME SCANNING
router.post('/analyze', authenticate, async (req, res) => {
  try {
    const { deviceId, analysisType = 'full' } = req.body;
    const db = getDatabase();

    // Get device information
    const device = db.prepare(`
      SELECT * FROM devices WHERE id = ?
    `).get(deviceId);

    if (!device) {
      return res.status(404).json({ error: 'Device not found' });
    }

    logger.info(`[AI] Starting real-time analysis for device: ${device.name} (${device.ip})`);

    // REAL-TIME: Perform live port scan on the device
    let livePorts = [];
    let livePortDetails = [];
    try {
      logger.info(`[AI] Performing live port scan on ${device.ip}...`);
      const commonPorts = [21, 22, 23, 80, 443, 135, 139, 445, 554, 1433, 1883, 3306, 3389, 5000, 5001, 7547, 8080, 8443, 8554, 8883, 9100, 34567, 37777];
      livePorts = await scanPorts(device.ip, commonPorts, 15);

      // Get service details for each open port
      for (const port of livePorts) {
        const portInfo = {
          port_number: port,
          service_name: getServiceName(port),
          status: 'open',
          risk_level: RISKY_PORTS[port]?.risk || 'low'
        };
        livePortDetails.push(portInfo);

        // Save port to database if not exists
        const existingPort = db.prepare('SELECT id FROM ports WHERE device_id = ? AND port_number = ?').get(deviceId, port);
        if (!existingPort) {
          db.prepare(`
            INSERT INTO ports (id, device_id, port_number, protocol, service_name, status, risk_level)
            VALUES (?, ?, ?, ?, ?, ?, ?)
          `).run(uuidv4(), deviceId, port, 'TCP', portInfo.service_name, 'open', portInfo.risk_level);
        }
      }
      logger.info(`[AI] Live scan found ${livePorts.length} open ports on ${device.ip}`);
    } catch (scanError) {
      logger.warn(`[AI] Live port scan failed for ${device.ip}: ${scanError.message}`);
    }

    // REAL-TIME: Query CVE database for device vulnerabilities
    let liveCVEs = [];
    try {
      if (device.manufacturer || device.device_type) {
        logger.info(`[AI] Querying CVE database for ${device.manufacturer || device.device_type}...`);
        liveCVEs = await getDeviceCVEs({
          vendor: device.manufacturer,
          model: device.model,
          type: device.device_type
        });
        logger.info(`[AI] Found ${liveCVEs.length} CVEs for device`);

        // Save high-severity CVEs as vulnerabilities
        for (const cve of liveCVEs.slice(0, 10)) { // Top 10 CVEs
          if (cve.cvssScore >= 7.0) {
            const existingVuln = db.prepare('SELECT id FROM vulnerabilities WHERE device_id = ? AND cve_id = ?').get(deviceId, cve.id);
            if (!existingVuln) {
              const severity = cve.cvssScore >= 9.0 ? 'critical' : cve.cvssScore >= 7.0 ? 'high' : 'medium';
              db.prepare(`
                INSERT INTO vulnerabilities (id, device_id, title, severity, description, cve_id, cvss_score, status, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
              `).run(
                uuidv4(), deviceId,
                `${cve.id}: ${cve.description?.substring(0, 100) || 'Vulnerability'}...`,
                severity, cve.description, cve.id, cve.cvssScore, 'open', new Date().toISOString()
              );
            }
          }
        }
      }
    } catch (cveError) {
      logger.warn(`[AI] CVE lookup failed: ${cveError.message}`);
    }

    // Get all vulnerabilities (existing + newly discovered)
    const vulnerabilities = db.prepare(`
      SELECT * FROM vulnerabilities WHERE device_id = ? AND status = 'open'
    `).all(deviceId);

    // Get all ports (existing + newly discovered)
    const ports = db.prepare(`
      SELECT * FROM ports WHERE device_id = ?
    `).all(deviceId);

    // Perform comprehensive AI analysis with real-time data
    const analysis = performRealTimeAIAnalysis(device, vulnerabilities, ports, livePorts, liveCVEs, analysisType);

    // Update device risk score based on analysis
    const newRiskScore = calculateRiskScore(vulnerabilities, ports);
    const newRiskLevel = newRiskScore >= 80 ? 'critical' : newRiskScore >= 60 ? 'high' : newRiskScore >= 40 ? 'medium' : newRiskScore >= 20 ? 'low' : 'safe';

    db.prepare('UPDATE devices SET risk_score = ?, risk_level = ?, last_seen = ? WHERE id = ?')
      .run(newRiskScore, newRiskLevel, new Date().toISOString(), deviceId);

    // Store the analysis result
    const reportId = uuidv4();
    db.prepare(`
      INSERT INTO ai_reports (id, device_id, analysis_type, report_data, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(reportId, deviceId, analysisType, JSON.stringify(analysis), new Date().toISOString());

    // Save database changes
    saveDatabase();

    logAudit(req.user.id, 'AI_ANALYSIS_PERFORMED', 'device', deviceId, { analysisType, portsScanned: livePorts.length, cvesFound: liveCVEs.length }, req);

    logger.info(`[AI] Analysis complete for ${device.name}: Risk Score ${newRiskScore}, ${vulnerabilities.length} vulns, ${ports.length} ports`);

    res.json({
      reportId,
      deviceId,
      analysis
    });
  } catch (error) {
    logger.error('AI analysis error:', error);
    res.status(500).json({ error: 'Failed to perform AI analysis' });
  }
});

// Calculate risk score based on vulnerabilities and ports
function calculateRiskScore(vulnerabilities, ports) {
  let score = 0;

  // Add points for vulnerabilities
  for (const vuln of vulnerabilities) {
    if (vuln.severity === 'critical') score += 25;
    else if (vuln.severity === 'high') score += 15;
    else if (vuln.severity === 'medium') score += 8;
    else score += 3;
  }

  // Add points for risky open ports
  for (const port of ports) {
    const portNum = port.port_number || port;
    if (RISKY_PORTS[portNum]?.risk === 'critical') score += 15;
    else if (RISKY_PORTS[portNum]?.risk === 'high') score += 10;
    else if (RISKY_PORTS[portNum]?.risk === 'medium') score += 5;
  }

  return Math.min(100, score);
}

// Real-time AI Analysis with comprehensive threat detection
function performRealTimeAIAnalysis(device, vulnerabilities, ports, livePorts, liveCVEs, analysisType) {
  const analysis = {
    summary: '',
    riskAssessment: {
      score: device.risk_score || 0,
      level: device.risk_level || 'unknown',
      factors: [],
      trends: []
    },
    vulnerabilities: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      details: [],
      recentCVEs: liveCVEs.slice(0, 5).map(c => ({
        id: c.id,
        score: c.cvssScore,
        description: c.description?.substring(0, 150)
      }))
    },
    recommendations: [],
    portAnalysis: [],
    threatIntelligence: [],
    realTimeFindings: {
      scannedAt: new Date().toISOString(),
      openPortsDiscovered: livePorts.length,
      cvesMatched: liveCVEs.length,
      livePortList: livePorts
    },
    timestamp: new Date().toISOString()
  };

  // Count vulnerabilities by severity
  for (const vuln of vulnerabilities) {
    const sev = vuln.severity || 'low';
    if (analysis.vulnerabilities[sev] !== undefined) {
      analysis.vulnerabilities[sev]++;
    }
    analysis.vulnerabilities.details.push({
      cveId: vuln.cve_id,
      title: vuln.title,
      severity: vuln.severity,
      cvssScore: vuln.cvss_score
    });
  }

  // Analyze ports for threats
  for (const port of ports) {
    const portNum = port.port_number;
    const riskyPort = RISKY_PORTS[portNum];

    analysis.portAnalysis.push({
      port: portNum,
      service: port.service_name || getServiceName(portNum),
      status: port.status || 'open',
      risk: riskyPort?.risk || 'low',
      threat: riskyPort?.threat || null
    });

    if (riskyPort) {
      analysis.riskAssessment.factors.push(`${riskyPort.name} (port ${portNum}) is open - ${riskyPort.threat}`);

      // Add specific threat intelligence
      analysis.threatIntelligence.push({
        type: 'exposed_service',
        port: portNum,
        service: riskyPort.name,
        severity: riskyPort.risk,
        description: riskyPort.threat,
        recommendation: `Close port ${portNum} if not required, or secure with authentication and encryption`
      });
    }
  }

  // Generate comprehensive summary
  const criticalIssues = analysis.vulnerabilities.critical +
    ports.filter(p => RISKY_PORTS[p.port_number]?.risk === 'critical').length;
  const highIssues = analysis.vulnerabilities.high +
    ports.filter(p => RISKY_PORTS[p.port_number]?.risk === 'high').length;

  if (criticalIssues > 0) {
    analysis.summary = `CRITICAL: Device "${device.name}" (${device.ip}) has ${criticalIssues} critical security issues requiring immediate attention. ${analysis.vulnerabilities.critical} critical CVEs and ${ports.filter(p => RISKY_PORTS[p.port_number]?.risk === 'critical').length} critically risky ports detected.`;
    analysis.riskAssessment.level = 'critical';
  } else if (highIssues > 0) {
    analysis.summary = `HIGH RISK: Device "${device.name}" (${device.ip}) has ${highIssues} high-severity issues. Found ${livePorts.length} open ports and ${vulnerabilities.length} known vulnerabilities.`;
    analysis.riskAssessment.level = 'high';
  } else if (vulnerabilities.length > 0 || livePorts.length > 5) {
    analysis.summary = `MODERATE RISK: Device "${device.name}" (${device.ip}) has ${vulnerabilities.length} vulnerabilities and ${livePorts.length} open ports. Review recommended.`;
    analysis.riskAssessment.level = 'medium';
  } else {
    analysis.summary = `LOW RISK: Device "${device.name}" (${device.ip}) appears relatively secure with ${livePorts.length} open ports. Continue monitoring.`;
    analysis.riskAssessment.level = 'low';
  }

  // Generate prioritized recommendations
  if (analysis.vulnerabilities.critical > 0) {
    analysis.recommendations.push({
      priority: 'critical',
      action: `Patch ${analysis.vulnerabilities.critical} critical vulnerabilities immediately`,
      details: 'Critical vulnerabilities can be exploited remotely for complete system compromise. Check vendor security advisories.',
      howTo: 'Visit vendor website for firmware/software updates. Apply patches during maintenance window.'
    });
  }

  if (ports.some(p => p.port_number === 23)) {
    analysis.recommendations.push({
      priority: 'critical',
      action: 'Disable Telnet immediately and use SSH',
      details: 'Telnet transmits all data in plaintext. Any network observer can capture credentials.',
      howTo: 'Access device admin panel > Services > Disable Telnet > Enable SSH with key authentication'
    });
  }

  if (ports.some(p => p.port_number === 21)) {
    analysis.recommendations.push({
      priority: 'high',
      action: 'Disable FTP or switch to SFTP/FTPS',
      details: 'FTP credentials are transmitted unencrypted and can be easily intercepted.',
      howTo: 'Configure SFTP (SSH-based) or FTPS (TLS-encrypted) instead of plain FTP'
    });
  }

  if (ports.some(p => [3389, 5900].includes(p.port_number))) {
    analysis.recommendations.push({
      priority: 'critical',
      action: 'Secure remote access ports (RDP/VNC)',
      details: 'Remote desktop services are prime targets for brute-force attacks and exploits.',
      howTo: 'Enable Network Level Authentication, use VPN, implement account lockout policies'
    });
  }

  if (ports.some(p => [1883, 8883].includes(p.port_number))) {
    analysis.recommendations.push({
      priority: 'high',
      action: 'Secure MQTT broker with authentication',
      details: 'Open MQTT allows anyone to subscribe to IoT device messages and control devices.',
      howTo: 'Configure username/password auth, enable TLS, restrict topic access with ACLs'
    });
  }

  if (analysis.vulnerabilities.high > 0) {
    analysis.recommendations.push({
      priority: 'high',
      action: `Address ${analysis.vulnerabilities.high} high-severity vulnerabilities`,
      details: 'High-severity vulnerabilities may allow unauthorized access or code execution.',
      howTo: 'Prioritize based on CVSS score and exploitability. Check for available patches.'
    });
  }

  // Add device-specific recommendations
  if (device.device_type === 'camera' || device.device_type === 'doorbell') {
    analysis.recommendations.push({
      priority: 'high',
      action: 'Change default camera credentials',
      details: 'IP cameras are frequently targeted by botnets using default passwords.',
      howTo: 'Access camera web interface, navigate to Settings > Users, create strong admin password'
    });
  }

  if (device.device_type === 'router') {
    analysis.recommendations.push({
      priority: 'high',
      action: 'Update router firmware and disable UPnP',
      details: 'Router vulnerabilities can expose entire network. UPnP can be exploited for port forwarding.',
      howTo: 'Log into router admin > Firmware Update. Disable UPnP in Advanced Settings.'
    });
  }

  // Always add some baseline recommendations
  if (analysis.recommendations.length === 0) {
    analysis.recommendations.push({
      priority: 'low',
      action: 'Maintain regular security monitoring',
      details: 'Device appears secure but continuous monitoring is recommended.',
      howTo: 'Schedule periodic security scans and review access logs regularly.'
    });
  }

  analysis.recommendations.push({
    priority: 'medium',
    action: 'Implement network segmentation',
    details: 'Isolate IoT devices on separate VLAN to limit lateral movement if compromised.',
    howTo: 'Configure router/switch to create IoT VLAN, set up firewall rules between segments'
  });

  // Calculate updated risk score
  analysis.riskAssessment.score = calculateRiskScore(vulnerabilities, ports);

  return analysis;
}

// Get AI report for a device
router.get('/report/:deviceId', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const reports = db.prepare(`
      SELECT * FROM ai_reports 
      WHERE device_id = ? 
      ORDER BY created_at DESC 
      LIMIT 10
    `).all(req.params.deviceId);

    if (reports.length === 0) {
      return res.status(404).json({ error: 'No reports found for this device' });
    }

    // Parse the JSON report data
    const parsedReports = reports.map(r => ({
      ...r,
      report_data: JSON.parse(r.report_data)
    }));

    res.json(parsedReports);
  } catch (error) {
    logger.error('Get AI report error:', error);
    res.status(500).json({ error: 'Failed to fetch AI report' });
  }
});

// AI Chat endpoint
router.post('/chat', authenticate, async (req, res) => {
  try {
    const { message, context = {} } = req.body;

    const prompt = `You are CodeX AI, a senior cybersecurity architect. 
Current Network Context: Security Score ${context.securityScore || 'N/A'}/100.
User Question: "${message}"

Provide a professional, technical yet accessible answer. If the user asks to "run a scan" or "show threats", mention that they can use the dedicated buttons in the UI.
Keep the response under 150 words. Provide 3 short follow-up suggestions.
Format:
MESSAGE: [Your response]
SUGGESTIONS: [Suggestion 1], [Suggestion 2], [Suggestion 3]`;

    let aiResponse;
    try {
      const rawAi = await callAIEngine(prompt);
      if (rawAi.includes('MESSAGE:')) {
        const msgPart = rawAi.split('MESSAGE:')[1].split('SUGGESTIONS:')[0].trim();
        const sugPart = rawAi.split('SUGGESTIONS:')[1]?.trim() || '';
        aiResponse = {
          message: msgPart,
          suggestions: sugPart.split(',').map(s => s.trim()).filter(Boolean)
        };
      } else {
        aiResponse = { message: rawAi, suggestions: ['Security Status', 'Run Scan', 'View Threats'] };
      }
    } catch (err) {
      logger.warn(`[AI Chat] GPT Fallback used: ${err.message}`);
      aiResponse = generateChatResponse(message, context);
    }

    logAudit(req.user.id, 'AI_CHAT', 'chat', null, { messageLength: message.length }, req);

    res.json({
      message: aiResponse.message,
      suggestions: aiResponse.suggestions,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('AI chat error:', error);
    res.status(500).json({ error: 'Failed to process chat message' });
  }
});

// Get security recommendations
router.get('/recommendations', authenticate, (req, res) => {
  try {
    const db = getDatabase();

    // Get network statistics
    const deviceCount = db.prepare('SELECT COUNT(*) as count FROM devices').get().count;
    const criticalVulns = db.prepare("SELECT COUNT(*) as count FROM vulnerabilities WHERE severity = 'critical' AND status = 'open'").get().count;
    const openPorts = db.prepare('SELECT COUNT(*) as count FROM ports WHERE status = ?').get('open').count;

    // Generate recommendations based on network state
    const recommendations = generateRecommendations({
      deviceCount,
      criticalVulns,
      openPorts
    });

    res.json(recommendations);
  } catch (error) {
    logger.error('Get recommendations error:', error);
    res.status(500).json({ error: 'Failed to generate recommendations' });
  }
});

// Analyze network-wide security
router.post('/analyze-network', authenticate, async (req, res) => {
  try {
    const db = getDatabase();

    // Get all devices
    const devices = db.prepare('SELECT * FROM devices WHERE status != ?').all('offline');

    // Get all open vulnerabilities
    const vulnerabilities = db.prepare("SELECT * FROM vulnerabilities WHERE status = 'open'").all();

    // Get recent alerts
    const alerts = db.prepare(`
      SELECT * FROM alerts 
      WHERE created_at > datetime('now', '-7 days')
      ORDER BY created_at DESC
    `).all();

    // Perform network-wide analysis
    const networkAnalysis = performNetworkAnalysis(devices, vulnerabilities, alerts);

    // AI Enhancement for Network Analysis
    const prompt = `Network-Wide Security Assessment:
- Total Devices: ${devices.length}
- Risk Level: ${networkAnalysis.riskLevel}
- Overall Risk Score: ${networkAnalysis.overallRisk}/100
- Critical Vulnerabilities: ${networkAnalysis.devicesByRisk.critical}
- Total Alerts (7 days): ${alerts.length}

Provide a 3-sentence executive summary and one strategic recommendation for the network administrator.
Format:
SUMMARY: [Summary]
STRATEGY: [Strategy]`;

    try {
      const aiResult = await callAIEngine(prompt);
      if (aiResult.includes('SUMMARY:')) {
        networkAnalysis.aiSummary = aiResult.split('SUMMARY:')[1].split('STRATEGY:')[0].trim();
        networkAnalysis.aiStrategy = aiResult.split('STRATEGY:')[1].trim();
      }
    } catch (err) {
      logger.warn(`[AI Network] Enhancement failed: ${err.message}`);
    }

    logAudit(req.user.id, 'NETWORK_ANALYSIS_PERFORMED', 'network', null, {}, req);

    res.json(networkAnalysis);
  } catch (error) {
    logger.error('Network analysis error:', error);
    res.status(500).json({ error: 'Failed to analyze network' });
  }
});


// Helper function to generate chat responses
function generateChatResponse(message, context) {
  const lowerMessage = message.toLowerCase();
  let response = {
    message: '',
    suggestions: []
  };

  if (lowerMessage.includes('vulnerability') || lowerMessage.includes('cve')) {
    response.message = 'I can help you analyze vulnerabilities in your network. Based on the current scan data, I recommend focusing on critical and high-severity vulnerabilities first. Would you like me to generate a detailed vulnerability report?';
    response.suggestions = ['Show critical vulnerabilities', 'Generate vulnerability report', 'How to patch CVE-2023-1234'];
  } else if (lowerMessage.includes('scan') || lowerMessage.includes('network')) {
    response.message = 'I can help you with network scanning. You can start a full network scan to discover all devices and their security posture. Would you like to initiate a scan now?';
    response.suggestions = ['Start network scan', 'Show scan history', 'Configure scan settings'];
  } else if (lowerMessage.includes('device') || lowerMessage.includes('iot')) {
    response.message = 'I can provide information about devices in your network. This includes device types, manufacturers, firmware versions, and associated vulnerabilities. What would you like to know?';
    response.suggestions = ['List all devices', 'Show vulnerable devices', 'Device risk assessment'];
  } else if (lowerMessage.includes('risk') || lowerMessage.includes('security')) {
    response.message = 'I can assess the security posture of your network. This includes analyzing vulnerabilities, open ports, firmware versions, and compliance with security best practices.';
    response.suggestions = ['Show security score', 'Risk assessment', 'Security recommendations'];
  } else {
    response.message = "I'm your AI security assistant for the Black Codex platform. I can help you with vulnerability analysis, network scanning, device management, and security recommendations. How can I assist you today?";
    response.suggestions = ['Analyze network security', 'Show recent alerts', 'Generate security report'];
  }

  return response;
}

// Helper function to generate recommendations
function generateRecommendations(stats) {
  const recommendations = [];

  if (stats.criticalVulns > 0) {
    recommendations.push({
      id: 'rec-1',
      priority: 'critical',
      title: 'Address Critical Vulnerabilities',
      description: `You have ${stats.criticalVulns} critical vulnerabilities that require immediate attention.`,
      action: 'View Vulnerabilities',
      actionUrl: '/vulnerabilities?severity=critical'
    });
  }

  if (stats.openPorts > 50) {
    recommendations.push({
      id: 'rec-2',
      priority: 'high',
      title: 'Review Open Ports',
      description: `You have ${stats.openPorts} open ports across your network. Consider closing unnecessary ports.`,
      action: 'View Port Analysis',
      actionUrl: '/topology'
    });
  }

  recommendations.push({
    id: 'rec-3',
    priority: 'medium',
    title: 'Schedule Regular Scans',
    description: 'Set up automated network scans to continuously monitor for new vulnerabilities.',
    action: 'Configure Scans',
    actionUrl: '/scan-engine'
  });

  recommendations.push({
    id: 'rec-4',
    priority: 'low',
    title: 'Update Device Firmware',
    description: 'Regularly check and update firmware for all IoT devices to patch known vulnerabilities.',
    action: 'View Devices',
    actionUrl: '/inventory'
  });

  return recommendations;
}

// Helper function for network-wide analysis
function performNetworkAnalysis(devices, vulnerabilities, alerts) {
  const analysis = {
    overallRisk: 0,
    riskLevel: 'low',
    devicesByRisk: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      safe: 0
    },
    vulnerabilityTrends: [],
    topThreats: [],
    recommendations: [],
    timestamp: new Date().toISOString()
  };

  // Calculate device risk distribution
  for (const device of devices) {
    const level = device.risk_level || 'safe';
    if (analysis.devicesByRisk[level] !== undefined) {
      analysis.devicesByRisk[level]++;
    }
  }

  // Calculate overall risk
  const riskWeights = { critical: 100, high: 75, medium: 50, low: 25, safe: 0 };
  let totalWeight = 0;
  let totalDevices = devices.length || 1;

  for (const [level, count] of Object.entries(analysis.devicesByRisk)) {
    totalWeight += (riskWeights[level] || 0) * count;
  }

  analysis.overallRisk = Math.round(totalWeight / totalDevices);

  if (analysis.overallRisk >= 80) analysis.riskLevel = 'critical';
  else if (analysis.overallRisk >= 60) analysis.riskLevel = 'high';
  else if (analysis.overallRisk >= 40) analysis.riskLevel = 'medium';
  else if (analysis.overallRisk >= 20) analysis.riskLevel = 'low';
  else analysis.riskLevel = 'safe';

  // Generate top threats
  const vulnBySeverity = {};
  for (const vuln of vulnerabilities) {
    const key = vuln.cve_id || vuln.title;
    if (!vulnBySeverity[key]) {
      vulnBySeverity[key] = {
        id: vuln.cve_id || vuln.id,
        title: vuln.title,
        severity: vuln.severity,
        count: 0,
        cvssScore: vuln.cvss_score
      };
    }
    vulnBySeverity[key].count++;
  }

  analysis.topThreats = Object.values(vulnBySeverity)
    .sort((a, b) => (b.cvssScore || 0) - (a.cvssScore || 0))
    .slice(0, 10);

  // Network-wide recommendations
  if (analysis.devicesByRisk.critical > 0) {
    analysis.recommendations.push({
      priority: 'critical',
      message: `${analysis.devicesByRisk.critical} device(s) are at critical risk. Immediate action required.`
    });
  }

  if (vulnerabilities.length > 50) {
    analysis.recommendations.push({
      priority: 'high',
      message: 'High number of open vulnerabilities. Consider prioritizing remediation based on CVSS scores.'
    });
  }

  return analysis;
}

// IoT device type keywords for categorization
const IOT_KEYWORDS = ['camera', 'doorbell', 'thermostat', 'speaker', 'hub', 'sensor', 'smart', 'alexa', 'echo', 'nest', 'ring', 'hue', 'philips', 'wyze', 'arlo', 'ecobee', 'sonos', 'roku', 'chromecast', 'fire tv', 'apple tv', 'smarttv', 'tv', 'printer', 'nvr', 'dvr'];
const NORMAL_KEYWORDS = ['computer', 'laptop', 'desktop', 'phone', 'tablet', 'server', 'workstation', 'pc', 'mac', 'windows', 'linux'];

function categorizeDevice(device) {
  const name = (device.name || '').toLowerCase();
  const type = (device.device_type || device.type || '').toLowerCase();
  const vendor = (device.vendor || device.manufacturer || '').toLowerCase();
  const combined = `${name} ${type} ${vendor}`;

  if (IOT_KEYWORDS.some(k => combined.includes(k))) return 'iot';
  if (NORMAL_KEYWORDS.some(k => combined.includes(k))) return 'normal';

  // Default categorization based on device type
  if (['router', 'gateway', 'switch', 'access_point', 'nas'].includes(type)) return 'normal';

  return 'iot'; // Default to IoT for unknown devices
}

/**
 * POST /ai/gemini-scan-report
 * Full network scan with Gemini AI-powered security report
 * Used by the AI Bot for comprehensive scanning
 */
router.post('/gemini-scan-report', optionalAuth, async (req, res) => {
  try {
    logger.info('[GEMINI] Starting full network scan with AI report generation...');

    const db = getDatabase();
    const startTime = Date.now();

    // Step 1: Get all devices from database (or run quick discovery)
    let devices = db.prepare('SELECT * FROM devices WHERE status != ?').all('offline');

    // If no devices, try ARP scan first
    if (devices.length === 0) {
      logger.info('[GEMINI] No devices in DB, running ARP discovery...');
      try {
        const arpDevices = await arpScan();
        for (const arpDev of arpDevices) {
          const vendor = lookupVendor(arpDev.mac);
          devices.push({
            id: uuidv4(),
            ip: arpDev.ip,
            mac: arpDev.mac,
            vendor: vendor,
            name: `Device ${arpDev.ip}`,
            device_type: 'unknown',
            status: 'online'
          });
        }
      } catch (arpErr) {
        logger.warn('[GEMINI] ARP scan failed:', arpErr.message);
      }
    }

    // Step 2: Categorize devices as IoT or Normal
    const iotDevices = [];
    const normalDevices = [];

    for (const device of devices) {
      const category = categorizeDevice(device);
      if (category === 'iot') {
        iotDevices.push(device);
      } else {
        normalDevices.push(device);
      }
    }

    logger.info(`[GEMINI] Categorized: ${iotDevices.length} IoT, ${normalDevices.length} Normal devices`);

    // Step 3: Get all vulnerabilities
    const vulnerabilities = db.prepare("SELECT v.*, d.ip, d.name as device_name FROM vulnerabilities v LEFT JOIN devices d ON v.device_id = d.id WHERE v.status = 'open'").all();

    // Step 4: Get open ports for vulnerable devices
    const ports = db.prepare("SELECT p.*, d.ip FROM ports p LEFT JOIN devices d ON p.device_id = d.id WHERE p.status = 'open'").all();

    // Step 5: Build prompt for Gemini
    const iotList = iotDevices.map(d => `- ${d.name || d.ip} (${d.vendor || 'Unknown'}) [${d.ip}]`).join('\n');
    const normalList = normalDevices.map(d => `- ${d.name || d.ip} (${d.vendor || 'Unknown'}) [${d.ip}]`).join('\n');
    const vulnList = vulnerabilities.slice(0, 15).map(v => `- ${v.title || v.cve_id} (${v.severity}) on ${v.ip || 'Unknown'}`).join('\n');
    const openPortsList = ports.slice(0, 20).map(p => `- Port ${p.port_number} (${p.service_name || 'unknown'}) on ${p.ip || 'Unknown'}`).join('\n');

    const prompt = `You are a cybersecurity expert. Generate a comprehensive network security report based on the following scan results.

**NETWORK SCAN RESULTS:**

**IoT Devices Found (${iotDevices.length}):**
${iotList || 'None detected'}

**Normal Devices Found (${normalDevices.length}):**
${normalList || 'None detected'}

**Vulnerabilities Detected (${vulnerabilities.length}):**
${vulnList || 'None detected'}

**Open Ports (${ports.length}):**
${openPortsList || 'None detected'}

**REQUIRED OUTPUT FORMAT:**
Please provide a structured security report with:

# 🔐 Network Security Report

## 📊 Summary
[Overall assessment - 2-3 sentences about network health]

## 🌐 IoT Devices (${iotDevices.length})
[Brief analysis of IoT security posture]

## 💻 Normal Devices (${normalDevices.length})
[Brief analysis of regular devices]

## ⚠️ Vulnerabilities Found
[List top vulnerabilities with severity and which device they affect]

## 🔧 Remediation Steps
[Numbered list of specific actions to fix each issue, ordered by priority]

## 📋 Recommendations
[3-5 general security best practices for this network]

Use markdown formatting with emojis for visual appeal.`;

    // Step 6: Call Gemini AI
    logger.info('[GEMINI] Calling Gemini AI for report generation...');
    const aiReport = await callAIEngine(prompt);

    const scanDuration = ((Date.now() - startTime) / 1000).toFixed(1);
    logger.info(`[GEMINI] Report generated in ${scanDuration}s`);

    // Step 7: Save report to database
    const reportId = uuidv4();
    db.prepare(`
      INSERT INTO ai_reports (id, device_id, ip, analysis_type, report_data, summary, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      reportId,
      null,
      'network-wide',
      'gemini-full-scan',
      aiReport,
      `Network scan: ${devices.length} devices, ${vulnerabilities.length} vulnerabilities`,
      new Date().toISOString()
    );
    saveDatabase();

    // Step 8: Return structured response
    res.json({
      success: true,
      reportId,
      scanSummary: {
        totalDevices: devices.length,
        iotDevices: iotDevices.length,
        normalDevices: normalDevices.length,
        vulnerabilities: vulnerabilities.length,
        openPorts: ports.length,
        scanDuration: `${scanDuration}s`
      },
      devices: {
        iot: iotDevices.map(d => ({
          name: d.name,
          ip: d.ip,
          vendor: d.vendor || d.manufacturer,
          type: d.device_type || 'IoT Device',
          riskLevel: d.risk_level || 'unknown'
        })),
        normal: normalDevices.map(d => ({
          name: d.name,
          ip: d.ip,
          vendor: d.vendor || d.manufacturer,
          type: d.device_type || 'Device',
          riskLevel: d.risk_level || 'unknown'
        }))
      },
      vulnerabilities: vulnerabilities.slice(0, 10).map(v => ({
        title: v.title,
        severity: v.severity,
        cve: v.cve_id,
        device: v.device_name || v.ip
      })),
      aiReport,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('[GEMINI] Scan report error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to generate scan report',
      details: error.message
    });
  }
});

module.exports = router;
