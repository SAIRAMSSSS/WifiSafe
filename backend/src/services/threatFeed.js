/**
 * Threat Feed Service
 * Fetches real-time threat intelligence from external sources (URLhaus, Abuse.ch, etc.)
 * Populates threat_intelligence table with live data
 */

const fetch = require('node-fetch');
const { v4: uuidv4 } = require('uuid');
const { getDatabase, saveDatabase } = require('../database/init');
const logger = require('../utils/logger');

// URLhaus API (Abuse.ch) - Recent Payloads (JSON)
const URLHAUS_API = 'https://urlhaus-api.abuse.ch/v1/payloads/recent/';

/**
 * Fetch latest threats from URLhaus
 */
async function fetchRecentThreats() {
  logger.info('[ThreatFeed] Fetching recent threats from URLhaus...');
  
  try {
    const response = await fetch(URLHAUS_API);
    if (!response.ok) {
      throw new Error(`API Error: ${response.status}`);
    }
    
    const data = await response.json();
    const payloads = data.payloads || [];
    
    logger.info(`[ThreatFeed] Retrieved ${payloads.length} recent payloads`);
    
    const db = getDatabase();
    const now = new Date().toISOString();
    let newCount = 0;
    
    // Process top 50 most recent to avoid overwhelming DB
    for (const item of payloads.slice(0, 50)) {
      // Check if signature already exists (using sha256 as unique id or just check URL)
      // URLhaus items have: sha256_hash, url, file_type, signature, firstseen, etc.
      
      const existing = db.prepare('SELECT id FROM threat_intelligence WHERE name = ? OR indicators LIKE ?').get(
        `Payload: ${item.signature || item.file_type}`, 
        `%${item.sha256_hash}%`
      );
      
      if (!existing) {
        // Map to our schema
        const threat = {
          id: uuidv4(),
          name: item.signature ? `Malware: ${item.signature}` : `Suspicious ${item.file_type}`,
          type: 'malware',
          severity: 'high', // Default to high for confirmed payloads
          description: `Recent malware payload detected by URLhaus. Type: ${item.file_type}. MD5: ${item.md5_hash}`,
          indicators: JSON.stringify([item.url, item.sha256_hash, item.md5_hash]),
          affected_device_types: JSON.stringify(['all']),
          mitigation_steps: JSON.stringify(['Block URL at firewall', 'Update antivirus definitions']),
          source: 'URLhaus (Abuse.ch)',
          status: 'active',
          first_seen: item.firstseen,
          last_seen: now,
          created_at: now
        };
        
        db.prepare(`
          INSERT INTO threat_intelligence (id, name, type, severity, description, indicators, affected_device_types, mitigation_steps, source, status, first_seen, last_seen, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          threat.id, threat.name, threat.type, threat.severity, threat.description,
          threat.indicators, threat.affected_device_types, threat.mitigation_steps,
          threat.source, threat.status, threat.first_seen, threat.last_seen, threat.created_at
        );
        
        newCount++;
      }
    }
    
    saveDatabase();
    logger.info(`[ThreatFeed] Added ${newCount} new threats to intelligence database`);
    
    return newCount;
    
  } catch (error) {
    logger.error(`[ThreatFeed] Failed to fetch threats: ${error.message}`);
    return 0;
  }
}

/**
 * Fetch latest vulnerabilities from CISA Known Exploited Vulnerabilities Catalog
 * (Simple JSON feed)
 */
async function fetchCISAExploits() {
  const CISA_CATALOG_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
  logger.info('[ThreatFeed] Fetching CISA Known Exploited Vulnerabilities...');
  
  try {
    const response = await fetch(CISA_CATALOG_URL);
    if (!response.ok) throw new Error(`API Error: ${response.status}`);
    
    const data = await response.json();
    const vulnerabilities = data.vulnerabilities || [];
    
    logger.info(`[ThreatFeed] Retrieved ${vulnerabilities.length} CISA records`);
    
    const db = getDatabase();
    const now = new Date().toISOString();
    let newCount = 0;
    
    // Process recent 20
    const recent = vulnerabilities.slice(0, 20); // They are usually sorted or we take top
    
    for (const item of recent) {
      // Map to Threat Intelligence (as these are active exploits)
      const existing = db.prepare('SELECT id FROM threat_intelligence WHERE name LIKE ?').get(`%${item.cveID}%`);
      
      if (!existing) {
        db.prepare(`
          INSERT INTO threat_intelligence (id, name, type, severity, description, indicators, affected_device_types, mitigation_steps, source, status, first_seen, last_seen, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          uuidv4(),
          `Active Exploit: ${item.cveID}`,
          'exploit',
          'critical',
          item.shortDescription,
          JSON.stringify([item.cveID, item.vendorProject, item.product]),
          JSON.stringify([item.product]),
          JSON.stringify([item.requiredAction]),
          'CISA KEV',
          'active',
          item.dateAdded,
          now,
          now
        );
        newCount++;
      }
    }
    
    saveDatabase();
    logger.info(`[ThreatFeed] Added ${newCount} CISA exploits`);
    return newCount;
    
  } catch (error) {
    logger.error(`[ThreatFeed] Failed to fetch CISA feed: ${error.message}`);
    return 0;
  }
}

module.exports = {
  fetchRecentThreats,
  fetchCISAExploits
};
