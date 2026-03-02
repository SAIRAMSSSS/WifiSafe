/**
 * AI Analysis & Remediation Suggestion Service
 * Supports Local Ollama or OpenAI GPT-4
 */
const { getDatabase } = require('../database/init');
const { v4: uuidv4 } = require('uuid');
const fetch = require('node-fetch');
const logger = require('../utils/logger');
const { RISKY_PORTS } = require('../utils/constants');

// Provider Configuration
const AI_PROVIDER = process.env.AI_PROVIDER || 'ollama'; // 'ollama' or 'openai'

// Ollama Config
const OLLAMA_API_URL = process.env.OLLAMA_API_URL || 'http://127.0.0.1:11434/api/generate';
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || 'llama3';

// OpenAI Config
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const OPENAI_MODEL = process.env.AI_MODEL || 'gpt-4';

// Gemini Config
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_API_URL = process.env.GEMINI_API_URL || 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent';

/**
 * Call Local Ollama AI Engine
 */
async function callOllama(prompt) {
  logger.info(`[AI] Calling Ollama (${OLLAMA_MODEL})...`);
  const res = await fetch(OLLAMA_API_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: OLLAMA_MODEL,
      prompt: prompt,
      stream: false,
      options: { temperature: 0.7, num_predict: 1024 }
    })
  });

  if (!res.ok) throw new Error(`Ollama responded with status ${res.status}`);
  const data = await res.json();
  return data.response || data.error || 'No response from Ollama';
}

/**
 * Call OpenAI API
 */
async function callOpenAI(prompt) {
  if (!OPENAI_API_KEY || OPENAI_API_KEY.includes('your-openai-api-key')) {
    throw new Error('OpenAI API key not configured in .env');
  }

  logger.info(`[AI] Calling OpenAI (${OPENAI_MODEL})...`);
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${OPENAI_API_KEY}`
    },
    body: JSON.stringify({
      model: OPENAI_MODEL,
      messages: [
        { role: 'system', content: 'You are a senior cybersecurity analyst.' },
        { role: 'user', content: prompt }
      ],
      temperature: 0.7
    })
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(`OpenAI error: ${res.status} ${errorData.error?.message || ''}`);
  }

  const data = await res.json();
  return data.choices?.[0]?.message?.content || 'No response from OpenAI';
}

/**
 * Call Google Gemini API
 */
async function callGemini(prompt) {
  if (!GEMINI_API_KEY || GEMINI_API_KEY.includes('your-gemini-api-key')) {
    throw new Error('Gemini API key not configured in .env');
  }

  logger.info('[AI] Calling Gemini (gemini-2.5-flash)...');
  const url = `${GEMINI_API_URL}?key=${GEMINI_API_KEY}`;

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{
        parts: [{ text: prompt }]
      }],
      generationConfig: {
        temperature: 0.7,
        maxOutputTokens: 2048,
      }
    })
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(`Gemini error: ${res.status} ${errorData.error?.message || ''}`);
  }

  const data = await res.json();
  if (data.candidates && data.candidates[0]?.content?.parts?.[0]?.text) {
    return data.candidates[0].content.parts[0].text;
  }

  throw new Error('No valid response from Gemini');
}

/**
 * Unified AI Engine Interface
 */
async function callAIEngine(prompt) {
  try {
    if (AI_PROVIDER === 'gemini') {
      return await callGemini(prompt);
    } else if (AI_PROVIDER === 'openai') {
      return await callOpenAI(prompt);
    } else {
      return await callOllama(prompt);
    }
  } catch (err) {
    logger.error(`[AI] ${AI_PROVIDER} API call failed: ${err.message}`);

    // Dynamic Default Fallback for Development
    if (process.env.NODE_ENV === 'development') {
      logger.warn('[AI] Providing simulated security analysis (Fallback Active)');
      return `## 🎯 OVERALL RISK ASSESSMENT
The device shows evidence of security weaknesses that require attention.

## 🔍 DETAILED THREAT ANALYSIS
- **Service Exposure**: Multiple open ports detected which may increase the attack surface.
- **Unverified Identity**: Device vendor or type lacks specific confirmation, making it a potential rogue asset.
- **Protocol Weakness**: Use of unencrypted protocols (HTTP/Telnet) if present enables credential interception.

## ✅ IMMEDIATE ACTIONS (Do These FIRST)
1. **Verify Asset**: Confirm the physical identity and owner of this device.
2. **Access Control**: Ensure all management interfaces require strong, unique credentials.
3. **Segmentation**: Move legacy or high-risk IoT devices to a dedicated security VLAN.

## 💡 SUMMARY
The device poses a moderate risk to the local network. Hardening of management interfaces and physical verification are recommended.

[SYSTEM NOTE: This is a simulated analysis because the configured AI provider (${AI_PROVIDER}) was unreachable.]`;
    }

    throw new Error(`AI Analysis unavailable: ${err.message}`);
  }
}

/**
 * Analyze a device and generate AI-powered remediation suggestions
 * Returns structured JSON for frontend compatibility
 */
async function analyzeDevice(ip) {
  const db = getDatabase();
  const device = db.prepare('SELECT * FROM devices WHERE ip = ?').get(ip);
  if (!device) throw new Error('Device not found');

  const ports = db.prepare('SELECT * FROM ports WHERE device_id = ?').all(device.id);
  const vulns = db.prepare('SELECT * FROM vulnerabilities WHERE device_id = ?').all(device.id);
  const misconfigs = db.prepare('SELECT * FROM misconfigurations WHERE device_id = ?').all(device.id);

  // 1. Prepare structured base analysis (Deterministic Fallback)
  const analysis = {
    summary: '',
    riskAssessment: {
      score: device.risk_score || 0,
      level: device.risk_level || 'unknown',
      factors: []
    },
    threats: [],
    recommendations: [],
    portAnalysis: [],
    threatIntelligence: [],
    realTimeFindings: {
      scannedAt: new Date().toISOString(),
      openPortsDiscovered: ports.length,
      cvesMatched: vulns.length,
      livePortList: ports.map(p => p.port_number)
    },
    prediction: ''
  };

  // Add vulnerabilities to threads
  vulns.forEach(v => {
    analysis.threats.push(`${v.severity.toUpperCase()}: ${v.title}`);
  });

  // Analyze ports
  ports.forEach(p => {
    const riskyPort = RISKY_PORTS[p.port_number];
    analysis.portAnalysis.push({
      port: p.port_number,
      service: p.service_name || 'unknown',
      status: p.status || 'open',
      risk: riskyPort?.risk || 'low',
      threat: riskyPort?.threat || null
    });

    if (riskyPort) {
      analysis.riskAssessment.factors.push(`${riskyPort.name} (port ${p.port_number}) is open - ${riskyPort.threat}`);
      analysis.threatIntelligence.push({
        type: 'exposed_service',
        port: p.port_number,
        service: riskyPort.name,
        severity: riskyPort.risk,
        description: riskyPort.threat,
        recommendation: `Secure or close port ${p.port_number}`
      });
    }
  });

  // Base Recommendations with detailed resolution steps
  if (vulns.length > 0) {
    const criticalVulns = vulns.filter(v => v.severity === 'critical');
    const highVulns = vulns.filter(v => v.severity === 'high');
    analysis.recommendations.push({
      priority: criticalVulns.length > 0 ? 'critical' : 'high',
      action: 'Patch identified vulnerabilities',
      details: `Discovered ${vulns.length} CVE(s): ${criticalVulns.length} critical, ${highVulns.length} high. Immediate patching required.`,
      howTo: 'Download and apply latest firmware from the manufacturer support page.',
      steps: [
        'Open your browser and navigate to the device manufacturer\'s official support/downloads website.',
        `Search for "${device.device_vendor || device.manufacturer || 'your device model'}" firmware updates.`,
        'Download the latest stable firmware version released after the CVE publication date.',
        'Log into the device admin panel (check the device label or manual for default URL, e.g., 192.168.0.1).',
        'Go to Administration > Firmware / Software Update and upload the downloaded file.',
        'Wait for the device to reboot and verify the new firmware version is applied.',
        'After update, re-run a vulnerability scan to confirm the CVEs are resolved.'
      ]
    });
  }

  if (device.has_weak_credentials) {
    analysis.recommendations.push({
      priority: 'critical',
      action: 'Change default / weak credentials',
      details: 'Device is using weak or default login credentials — a primary attack vector for network compromise.',
      howTo: 'Access the device admin panel and update to a strong, unique password immediately.',
      steps: [
        `Open a browser and navigate to http://${device.ip} or https://${device.ip} (check device label for the correct port).`,
        'Log in using the current credentials (check device documentation for defaults if unknown).',
        'Go to Administration > Security > Change Password (exact menu varies by device).',
        'Set a new password: minimum 12 characters, include uppercase, lowercase, numbers, and symbols (e.g., Wf!k9$mX@2rT).',
        'Disable remote management or WAN-side admin access if not required.',
        'Enable two-factor authentication if the device firmware supports it.',
        'Save changes and log out — confirm you can log back in with the new password.',
        'Update your password manager or document the new credentials securely.'
      ]
    });
  }

  // Recommendation for unidentified/unknown device
  const isUnknown = !device.device_vendor || device.device_vendor === 'Unknown' || !device.device_type || device.device_type === 'unknown';
  if (isUnknown) {
    analysis.recommendations.push({
      priority: 'high',
      action: 'Identify and document this unknown device',
      details: 'This device has no known vendor or type — it may be a rogue asset, shadow IT, or a misconfigured device. Unknown assets are a major blind spot.',
      howTo: 'Physically trace the device using its IP and MAC address, then register it in your asset inventory.',
      steps: [
        `Open a command prompt or terminal and run: arp -a | findstr "${device.ip}" to confirm the MAC address.`,
        `The MAC address prefix (first 6 characters) identifies the manufacturer — look it up at https://maclookup.app`,
        'Physically locate the device by checking switch port assignments or using network management tools.',
        'If the device is known and authorized: update its name and type in the Device Inventory page of this dashboard.',
        'If the device is unknown/unauthorized: immediately isolate it using the Quarantine Kill Switch feature in this dashboard.',
        'Investigate what services the device is running by reviewing the Open Ports section above.',
        'Document the device in your network asset register with owner, purpose, and last review date.',
        'Set up alerts in this dashboard to notify you if a new unknown device appears on the network again.'
      ]
    });
  }

  // Recommendations for risky ports
  const criticalPorts = analysis.portAnalysis.filter(p => p.risk === 'critical' || p.risk === 'high');
  if (criticalPorts.length > 0) {
    criticalPorts.slice(0, 3).forEach(p => {
      const portSteps = {
        23: [ // Telnet
          'Log into the device admin panel.',
          'Navigate to Services or Administration > Remote Access.',
          'Disable Telnet service — it transmits data in plaintext.',
          'Enable SSH instead if remote access is required.',
          'Verify Telnet is closed by re-running a port scan.'
        ],
        21: [ // FTP
          'Log into the device admin panel.',
          'Navigate to Services > FTP and disable the FTP server.',
          'Use SFTP or SCP for secure file transfers instead.',
          'If FTP is required, restrict it to specific IP addresses only.'
        ],
        3389: [ // RDP
          'Open Windows Settings > System > Remote Desktop.',
          'If RDP is not needed, toggle "Enable Remote Desktop" to OFF.',
          'If RDP is needed: restrict access using Windows Firewall to allow only specific IPs.',
          'Ensure Network Level Authentication (NLA) is enabled.',
          'Use a VPN for remote access instead of exposing RDP directly.'
        ],
        7547: [ // TR-069
          'Log into your router/modem admin panel.',
          'Navigate to Administration or Management > Remote Management.',
          'Disable TR-069/CWMP if not required by your ISP.',
          'Contact your ISP to confirm if this port is needed for remote provisioning.'
        ]
      };
      analysis.recommendations.push({
        priority: p.risk === 'critical' ? 'critical' : 'high',
        action: `Secure or close port ${p.port} (${p.service})`,
        details: p.threat || `Port ${p.port} exposes the ${p.service} service which can be exploited if not properly secured.`,
        howTo: `Disable the ${p.service} service or restrict access to trusted IPs only.`,
        steps: portSteps[p.port] || [
          `Log into the device admin panel at http://${device.ip}.`,
          `Navigate to Services or Security settings and locate the ${p.service} service (port ${p.port}).`,
          'Disable the service if it is not required for normal operation.',
          `If required, configure a firewall rule to allow port ${p.port} only from trusted IP addresses.`,
          'Re-run the AI analyst scan to verify the port is no longer exposed.'
        ]
      });
    });
  }

  // Misconfigurations
  if (misconfigs.length > 0) {
    analysis.recommendations.push({
      priority: 'medium',
      action: 'Fix security misconfigurations',
      details: `${misconfigs.length} misconfiguration(s) found: ${misconfigs.map(m => m.title).join(', ')}.`,
      howTo: 'Review and correct each misconfiguration through the device admin interface.',
      steps: [
        `Log into the device admin panel at http://${device.ip}.`,
        ...misconfigs.slice(0, 3).map((m, i) => `Step ${i + 2}: Fix "${m.title}" — ${m.recommendation || m.description || 'Check device manual'}.`),
        'Save all changes and reboot the device if prompted.',
        'Run a configuration audit again to verify all issues are resolved.'
      ]
    });
  }

  // General hardening recommendation
  if (analysis.recommendations.length === 0) {
    analysis.recommendations.push({
      priority: 'low',
      action: 'Apply general security hardening',
      details: 'No critical issues detected. Apply preventive hardening to maintain security posture.',
      howTo: 'Follow device-specific hardening guides from the manufacturer.',
      steps: [
        'Ensure the device firmware is up to date — check the manufacturer website monthly.',
        'Disable all unused services and features in the admin panel.',
        'Enable logging and monitoring if supported — forward logs to a central system.',
        'Change the default admin username and set a strong password if not already done.',
        'Enable automatic security updates if the device supports it.',
        'Periodically re-run the AI analyst scan to detect new issues.'
      ]
    });
  }


  // 2. Enhance with AI if available
  const manufacturer = device.device_vendor || device.manufacturer || 'Unknown';
  const prompt = `Conduct a DETAILED security assessment for:
- IP: ${device.ip}
- Name: ${device.name || 'Unknown'}
- Type: ${device.iot_device_type || device.device_type || 'Unknown'}
- Vendor: ${manufacturer}
- Risk Score: ${analysis.riskAssessment.score}/100
- Open Ports: ${analysis.portAnalysis.map(p => p.port).join(', ')}
- Vulnerabilities: ${vulns.map(v => v.title).join(', ')}

Provide a concise security summary (2 sentences) and a security prediction (1 sentence) about future risk.
Format:
SUMMARY: [Summary]
PREDICTION: [Prediction]`;

  try {
    const aiResult = await callAIEngine(prompt);

    // Parse individual components from AI response - Robust Parsing
    if (aiResult.includes('SUMMARY:')) {
      analysis.summary = aiResult.split('SUMMARY:')[1].split('PREDICTION:')[0].trim();
    }
    if (aiResult.includes('PREDICTION:')) {
      analysis.prediction = aiResult.split('PREDICTION:')[1].trim();
    }

    // If parsing fails but we have a response, use intelligent fallbacks from the AI text
    if (!analysis.summary && aiResult) {
      // If AI didn't use the format, take the first two sentences or the whole thing
      const sentences = aiResult.split(/[.!?]/).filter(s => s.trim().length > 5);
      analysis.summary = sentences.length > 0 ? (sentences.slice(0, 2).join('.') + '.') : aiResult.substring(0, 300);
    }
    if (!analysis.prediction && aiResult) {
      const sentences = aiResult.split(/[.!?]/).filter(s => s.trim().length > 5);
      analysis.prediction = sentences.length > 2 ? sentences[sentences.length - 1] + '.' : "Monitoring recommended.";
    }
  } catch (err) {
    logger.warn(`[AI] AI Enhancement failed, using deterministic summary: ${err.message}`);
  }

  // Fallback if AI parsing failed
  if (!analysis.summary) {
    analysis.summary = `Device ${device.ip} (${manufacturer}) has a risk score of ${analysis.riskAssessment.score}. ` +
      `${vulns.length > 0 ? `It has ${vulns.length} active vulnerabilities.` : 'No critical CVEs detected currently.'}`;
  }
  if (!analysis.prediction) {
    analysis.prediction = analysis.riskAssessment.score > 50
      ? "High likelihood of targeted scans and potential exploitation if left unpatched."
      : "Standard network background noise expected; maintaining current patches should mitigate most risks.";
  }

  // Save report
  const reportId = uuidv4();
  db.prepare(`
    INSERT INTO ai_reports (id, device_id, ip, analysis_type, report_data, summary, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(reportId, device.id, ip, 'device', JSON.stringify(analysis), analysis.summary, new Date().toISOString());

  return { ...analysis, reportId };
}

function getReport(reportId) {
  const db = getDatabase();
  return db.prepare('SELECT * FROM ai_reports WHERE id = ?').get(reportId);
}

module.exports = { analyzeDevice, getReport, callAIEngine };
