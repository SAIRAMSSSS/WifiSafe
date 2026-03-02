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

  // ── Recommendations: each block embeds REAL device data for unique steps ──

  // 1. CVE / Vulnerability Patching — unique per device (CVE IDs + vendor + IP)
  if (vulns.length > 0) {
    const criticalVulns = vulns.filter(v => v.severity === 'critical');
    const highVulns = vulns.filter(v => v.severity === 'high');
    const cveIds = vulns.map(v => v.cve_id || v.title).filter(Boolean).slice(0, 5);
    const vendorName = device.device_vendor || device.manufacturer || 'your device manufacturer';
    const adminUrl = `http://${device.ip}`;

    analysis.recommendations.push({
      priority: criticalVulns.length > 0 ? 'critical' : 'high',
      action: `Patch ${vulns.length} CVE vulnerabilit${vulns.length > 1 ? 'ies' : 'y'} on ${device.ip}`,
      details: `Confirmed CVEs: ${cveIds.join(', ')}. ${criticalVulns.length} critical, ${highVulns.length} high severity. These can allow remote code execution or data theft if left unpatched.`,
      howTo: `Visit ${vendorName}'s official support page and download the latest security firmware for this device.`,
      steps: [
        `Search for the official firmware page: https://www.google.com/search?q=${encodeURIComponent(vendorName + ' security firmware update')}`,
        `Look for a firmware version that patches: ${cveIds.slice(0, 3).join(', ')}.`,
        `Download the firmware file (usually .bin, .img, or .zip) to your computer.`,
        `Open a browser and go to ${adminUrl} — log in with your admin credentials. (Default credentials are often on a label on the device itself.)`,
        `Navigate to Administration → Firmware / Software Update → upload the downloaded file.`,
        `Wait for the device to reboot automatically (takes 2–5 minutes). Do NOT power off during this.`,
        `After reboot, go back to ${adminUrl} and verify the new firmware version is displayed.`,
        `Return to the AI Analyst page and re-analyze ${device.ip} to confirm the CVEs are resolved.`
      ]
    });
  }

  // 2. Weak / Default Credentials — unique per device (IP + MAC + vendor)
  if (device.has_weak_credentials) {
    const adminUrl = `http://${device.ip}`;
    const macAddr = device.mac || 'check router DHCP table';
    analysis.recommendations.push({
      priority: 'critical',
      action: `Change weak credentials on ${device.ip} (${device.name || 'Unknown Device'})`,
      details: `Device ${device.ip} (MAC: ${macAddr}, Vendor: ${device.device_vendor || 'Unknown'}) is using weak or default credentials — the #1 cause of IoT device compromise.`,
      howTo: `Log into ${adminUrl} and immediately replace the admin password with a strong unique value.`,
      steps: [
        `Open a browser and navigate to ${adminUrl} (or check the device label for port variants like :8080 or :8443).`,
        `Log in with the current credentials. If using defaults, check the device label — common defaults: admin/admin, admin/password, root/root.`,
        `Go to Administration → Security → Change Password (may also be under Account, Users, or System Settings).`,
        `Set a new password with 12+ characters using uppercase, lowercase, numbers and symbols. Suggested format: ${device.ip.replace(/\./g, '')}-Secure@${new Date().getFullYear()}`,
        `If there is a separate admin username field, change it from "admin" to a custom name.`,
        `Disable remote management (WAN-side access) if you don't manage this device externally.`,
        `Click Save, then log out, clear your browser cache, and log back in with the new credentials to confirm.`,
        `Record the new credentials in a password manager. Device is at ${device.ip} (MAC: ${macAddr}).`
      ]
    });
  }

  // 3. Unknown/Unidentified Device — unique per device (IP + MAC prefix)
  const isUnknown = (!device.device_vendor || device.device_vendor === 'Unknown') ||
    (!device.device_type || device.device_type === 'unknown');
  if (isUnknown) {
    const macAddress = device.mac || 'unknown';
    const macPrefix = device.mac ? device.mac.substring(0, 8) : 'unknown';
    analysis.recommendations.push({
      priority: 'high',
      action: `Identify and verify unknown device at ${device.ip} (MAC: ${macAddress})`,
      details: `IP ${device.ip} (MAC: ${macAddress}) has no recognized vendor or device type. This could be a rogue device, shadow IT, or misconfigured endpoint. Unknown assets bypass all security policies.`,
      howTo: `Look up MAC prefix ${macPrefix} at https://maclookup.app to identify the manufacturer, then physically locate the device.`,
      steps: [
        `On Windows: Open Command Prompt → run: arp -a | findstr "${device.ip}" to confirm the MAC address for this IP.`,
        `Look up MAC prefix ${macPrefix} at https://maclookup.app to identify the device manufacturer.`,
        `Check your router's client list (usually at http://192.168.0.1 → Status → DHCP Clients) for the hostname registered to ${device.ip}.`,
        `Physically walk the network and look for a device labeled with ${device.ip} or showing recent network activity.`,
        `If the device is authorized: open Device Inventory in this dashboard, find ${device.ip}, and fill in the Name, Type, and Vendor fields.`,
        `If the device is NOT authorized or unrecognized: go to Quarantine Kill Switch in this dashboard and isolate ${device.ip} immediately.`,
        `After identifying the device, document it in your asset register: owner, purpose, date verified, MAC ${macAddress}.`,
        `Enable new-device detection alerts in this dashboard so you are notified the instant another unknown device joins the network.`
      ]
    });
  }

  // 4. Risky Open Ports — per-port unique steps with real IP embedded
  const criticalPorts = analysis.portAnalysis.filter(p => p.risk === 'critical' || p.risk === 'high');
  if (criticalPorts.length > 0) {
    const PORT_REMEDIATION = {
      23: (ip) => [`Open browser → http://${ip} → admin panel.`, 'Go to Services → Remote Access.', 'Set Telnet to Disabled — it transmits all data (including passwords) in plaintext.', 'Enable SSH instead: Services → SSH → Enable, Port 22.', `Add a firewall rule: allow SSH only from your PC's IP to ${ip}.`, `Re-analyze ${ip} in AI Analyst to confirm port 23 is closed.`],
      21: (ip) => [`Open browser → http://${ip} → admin panel.`, 'Go to Services → FTP Server → set to Disabled.', 'For secure file transfer, enable SFTP (SSH-based) instead.', `If FTP must stay on: add firewall rule allowing port 21 only from your specific IP to ${ip}.`, `Verify closure: re-run port scan on ${ip} from this dashboard.`],
      3389: (ip) => [`On the Windows machine at ${ip}: Press Win+I → System → Remote Desktop.`, 'If RDP is not needed: toggle "Enable Remote Desktop" to OFF.', 'If RDP IS needed: open Windows Firewall → Advanced Settings → Inbound Rules → Remote Desktop (TCP-In) → Properties → Scope → set Remote IP to only your admin PC.', 'Enable NLA: System Properties → Remote → check "Allow connections only from computers running Remote Desktop with NLA".', `Change the RDP port from 3389 to a non-standard port to reduce bot scanning on ${ip}.`, 'Use a VPN for RDP sessions — never expose port 3389 directly to the internet.'],
      7547: (ip) => [`Port 7547 on ${ip} is used by ISPs for TR-069/CWMP remote router management.`, `Open browser → http://${ip} → Administration → Remote Management.`, 'Look for TR-069, CWMP, or ACS settings.', 'If your ISP does NOT require it: set to Disabled.', 'If ISP requires it: call your ISP and confirm the official ACS server URL — reject any other value.', `Apply a firewall rule allowing port 7547 on ${ip} only from your ISP's official IP range.`],
      22: (ip) => [`SSH is open on ${ip} — harden it immediately.`, `SSH into ${ip} or access its admin panel.`, 'Disable password authentication: edit /etc/ssh/sshd_config → set PasswordAuthentication no.', 'Switch to SSH key-based authentication only.', `Change SSH port from 22 to a non-standard port (e.g., 2222) to reduce automated attacks.`, `Add a firewall rule: allow the new SSH port only from your IP to ${ip}.`],
      445: (ip) => [`SMB port 445 on ${ip} is critical — it is the attack vector used by WannaCry and EternalBlue.`, 'On Windows: open PowerShell as Admin → run: Set-SmbServerConfiguration -EnableSMB1Protocol $false', 'Disable SMBv1: Control Panel → Programs → Turn Windows features on/off → uncheck SMB 1.0/CIFS.', 'Apply all Windows Updates immediately to patch known SMB exploits.', `Block port 445 on the network firewall to prevent lateral movement from ${ip}.`, 'Ensure network segmentation so no IoT/guest devices can reach this SMB host.'],
    };

    criticalPorts.slice(0, 3).forEach(p => {
      const stepsFn = PORT_REMEDIATION[p.port];
      analysis.recommendations.push({
        priority: p.risk === 'critical' ? 'critical' : 'high',
        action: `Close/secure port ${p.port} (${p.service || 'Unknown Service'}) on ${device.ip}`,
        details: `${p.threat || `Port ${p.port} on ${device.ip} exposes ${p.service || 'a service'} to exploitation.`} Vendor: ${device.device_vendor || 'Unknown'}, MAC: ${device.mac || 'Unknown'}.`,
        howTo: `Disable the ${p.service || 'service on port ' + p.port} on ${device.ip} or restrict it to trusted IPs only.`,
        steps: stepsFn ? stepsFn(device.ip) : [
          `Open a browser and go to http://${device.ip} → admin panel.`,
          `Navigate to Services or Security Settings → find the service running on port ${p.port} ("${p.service || 'Unknown'}").`,
          `If this service is NOT required: disable/stop it immediately.`,
          `If it IS required: add a firewall rule restricting port ${p.port} to only your admin PC's IP.`,
          `Verify the fix: use a port scanner or this dashboard's scan feature to confirm port ${p.port} is closed on ${device.ip}.`,
          `Re-analyze ${device.ip} in the AI Analyst to confirm the threat is mitigated.`
        ]
      });
    });
  }

  // 5. Misconfigurations — one unique recommendation per misconfiguration
  if (misconfigs.length > 0) {
    misconfigs.slice(0, 3).forEach(m => {
      analysis.recommendations.push({
        priority: m.severity || 'medium',
        action: `Fix misconfiguration: "${m.title}" on ${device.ip}`,
        details: `${m.description || `Security misconfiguration "${m.title}" detected`} on ${device.ip} (${device.device_vendor || 'Unknown vendor'}, MAC: ${device.mac || 'Unknown'}).`,
        howTo: m.recommendation || `Correct this issue through the device admin panel at http://${device.ip}.`,
        steps: [
          `Open http://${device.ip} in your browser and log into the admin panel.`,
          m.port
            ? `This issue is on port ${m.port} — go to Services → find the service on port ${m.port}.`
            : `Go to Administration or Security Settings.`,
          `Fix: ${m.title} — ${m.recommendation || m.description || 'Follow the device manual for this setting'}.`,
          `Save the changes and reboot the device if prompted.`,
          `Re-run the Config Audit from Device Inventory for ${device.ip} to verify this misconfiguration is resolved.`
        ]
      });
    });
  }

  // 6. General hardening — only if zero other recommendations, unique steps per device
  if (analysis.recommendations.length === 0) {
    const vendorName = device.device_vendor || device.manufacturer || 'your device manufacturer';
    analysis.recommendations.push({
      priority: 'low',
      action: `Apply preventive security hardening on ${device.ip} (${device.name || 'Unknown Device'})`,
      details: `No critical issues currently detected on ${device.ip}. Proactive hardening keeps this ${vendorName} device resilient against future threats.`,
      howTo: `Follow the ${vendorName} security hardening guide on their official support website.`,
      steps: [
        `Go to http://${device.ip} → Administration → Firmware and verify the installed version matches the latest from ${vendorName}'s website.`,
        `Disable all services not in active use — fewer open ports means a smaller attack surface on ${device.ip}.`,
        `Enable logging: Administration → Logging → configure syslog or remote logging to your monitoring tool.`,
        `If the admin username is still "admin", rename it: Administration → Users → change to a custom name.`,
        `Set session timeout to 5–10 minutes: Administration → Security → Session Timeout.`,
        `Set a monthly calendar reminder to re-run the AI Analyst on ${device.ip} to detect new issues.`
      ]
    });
  }


  // 2. Enhance with AI — include CVE IDs explicitly so the summary names them
  const manufacturer = device.device_vendor || device.manufacturer || 'Unknown';
  const cveDetail = vulns.length > 0
    ? `\nKnown CVEs on this device:\n${vulns.map(v => `  - ${v.cve_id || v.title} (${v.severity?.toLowerCase() || 'unknown'} severity)${v.description ? ': ' + v.description.substring(0, 100) : ''}`).join('\n')}`
    : '\nNo CVE records found for this device in the database.';

  const prompt = `You are a cybersecurity expert writing a threat report. Be specific and direct.

Device under analysis:
- IP Address: ${device.ip}
- Device Name: ${device.name || 'Unknown'}
- Device Type: ${device.iot_device_type || device.device_type || 'Unknown'}
- Vendor/Manufacturer: ${manufacturer}
- MAC Address: ${device.mac || 'Unknown'}
- Risk Score: ${analysis.riskAssessment.score}/100
- Open Ports: ${analysis.portAnalysis.map(p => `${p.port} (${p.service})`).join(', ') || 'None detected'}
${cveDetail}

Write your response in EXACTLY this format (no extra text before or after):
SUMMARY: [2-3 sentences. If CVEs exist, explicitly name each CVE ID (e.g. CVE-2021-34527) and its impact. Mention the device IP ${device.ip} and vendor ${manufacturer}. If no CVEs, describe the key security concern based on open ports or unknown device status.]
PREDICTION: [1 sentence predicting the most likely attack scenario if the issues are not resolved within 30 days.]`;


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
