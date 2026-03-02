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

  // Base Recommendations
  if (vulns.length > 0) {
    analysis.recommendations.push({
      priority: 'high',
      action: 'Patch identified vulnerabilities',
      details: `Discovered ${vulns.length} CVEs. Visit vendor site for updates.`,
      howTo: 'Download and apply latest firmware from manufacturer.'
    });
  }

  if (device.has_weak_credentials) {
    analysis.recommendations.push({
      priority: 'critical',
      action: 'Change default credentials',
      details: 'Device is using weak or default login information.',
      howTo: 'Access the admin panel and update to a strong, unique password.'
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
