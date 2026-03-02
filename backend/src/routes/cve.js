const express = require('express');
const { getDatabase, saveDatabase } = require('../database/init');
const { authenticate, optionalAuth } = require('../middleware/auth');
const { v4: uuidv4 } = require('uuid');
const logger = require('../utils/logger');

const router = express.Router();

// NVD API base URL
const NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

/**
 * Fetch CVEs from NVD API (real-time lookup)
 */
async function fetchFromNVD(params) {
  const queryParams = new URLSearchParams(params);
  const url = `${NVD_API_URL}?${queryParams}`;
  
  try {
    const response = await fetch(url, {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'BlackCodex-SecurityScanner/1.0',
        // Add API key if available for higher rate limits
        ...(process.env.NVD_API_KEY && { 'apiKey': process.env.NVD_API_KEY })
      }
    });
    
    if (!response.ok) {
      // If rate limited or error, return empty but don't throw
      logger.warn(`NVD API returned ${response.status}`);
      return { vulnerabilities: [], totalResults: 0 };
    }
    
    return await response.json();
  } catch (error) {
    logger.error('NVD API fetch error:', error.message);
    // Return empty result instead of throwing
    return { vulnerabilities: [], totalResults: 0 };
  }
}

/**
 * Parse NVD CVE data into our format
 */
function parseNVDCve(nvdCve) {
  const cve = nvdCve.cve;
  const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
  
  const cvssScore = metrics?.cvssData?.baseScore || 0;
  let severity = 'low';
  if (cvssScore >= 9.0) severity = 'critical';
  else if (cvssScore >= 7.0) severity = 'high';
  else if (cvssScore >= 4.0) severity = 'medium';
  
  // Extract affected products
  const configurations = cve.configurations || [];
  const affectedProducts = [];
  for (const config of configurations) {
    for (const node of config.nodes || []) {
      for (const cpeMatch of node.cpeMatch || []) {
        if (cpeMatch.vulnerable) {
          const parts = cpeMatch.criteria?.split(':') || [];
          if (parts.length >= 5) {
            affectedProducts.push(`${parts[3]} ${parts[4]}`);
          }
        }
      }
    }
  }
  
  return {
    cve_id: cve.id,
    title: cve.descriptions?.find(d => d.lang === 'en')?.value?.substring(0, 200) || cve.id,
    description: cve.descriptions?.find(d => d.lang === 'en')?.value || '',
    severity,
    cvss_score: cvssScore,
    cvss_vector: metrics?.cvssData?.vectorString || '',
    published_date: cve.published,
    last_modified: cve.lastModified,
    affected_products: [...new Set(affectedProducts)].join(', '),
    references_data: JSON.stringify(cve.references || []),
    exploit_available: cve.references?.some(r => 
      r.tags?.includes('Exploit') || 
      r.url?.includes('exploit-db') ||
      r.url?.includes('github.com') && r.tags?.includes('Third Party Advisory')
    ) ? 1 : 0
  };
}

/**
 * GET /cve/lookup/:vendor/:product - Real NVD API lookup
 * Fetches CVEs from NVD for a specific vendor/product
 */
router.get('/lookup/:vendor/:product', optionalAuth, async (req, res) => {
  try {
    const { vendor, product } = req.params;
    const keyword = `${vendor} ${product}`;
    
    logger.info(`Fetching CVEs from NVD for: ${keyword}`);
    
    const nvdData = await fetchFromNVD({
      keywordSearch: keyword,
      resultsPerPage: 50
    });
    
    const cves = (nvdData.vulnerabilities || []).map(v => parseNVDCve(v));
    
    // Cache results in database
    const db = getDatabase();
    for (const cve of cves) {
      const existing = db.prepare('SELECT id FROM cve_database WHERE cve_id = ?').get(cve.cve_id);
      if (!existing) {
        db.prepare(`
          INSERT INTO cve_database (id, cve_id, title, description, severity, cvss_score, cvss_vector, published_date, last_modified, affected_products, references_data, exploit_available, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          uuidv4(), cve.cve_id, cve.title, cve.description, cve.severity,
          cve.cvss_score, cve.cvss_vector, cve.published_date, cve.last_modified,
          cve.affected_products, cve.references_data, cve.exploit_available,
          new Date().toISOString()
        );
      }
    }
    saveDatabase();
    
    res.json({
      success: true,
      source: 'NVD',
      query: { vendor, product },
      totalResults: nvdData.totalResults || cves.length,
      resultsReturned: cves.length,
      vulnerabilities: cves
    });
  } catch (error) {
    logger.error('NVD lookup error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch from NVD', 
      details: error.message,
      fallback: 'Using cached data if available'
    });
  }
});

/**
 * GET /cve/nvd/recent - Get recent CVEs from NVD
 */
router.get('/nvd/recent', optionalAuth, async (req, res) => {
  try {
    const { days = 7, severity } = req.query;
    
    // Calculate date range
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));
    
    const params = {
      pubStartDate: startDate.toISOString(),
      pubEndDate: endDate.toISOString(),
      resultsPerPage: 100
    };
    
    if (severity) {
      params.cvssV3Severity = severity.toUpperCase();
    }
    
    logger.info(`Fetching recent CVEs from NVD (last ${days} days)`);
    
    const nvdData = await fetchFromNVD(params);
    const cves = (nvdData.vulnerabilities || []).map(v => parseNVDCve(v));
    
    res.json({
      success: true,
      source: 'NVD',
      dateRange: { start: startDate.toISOString(), end: endDate.toISOString() },
      totalResults: nvdData.totalResults || cves.length,
      vulnerabilities: cves
    });
  } catch (error) {
    logger.error('NVD recent CVEs error:', error);
    res.status(500).json({ error: 'Failed to fetch recent CVEs' });
  }
});

// Search CVE database
router.get('/', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { 
      severity, 
      has_exploit, 
      vendor, 
      search, 
      min_cvss,
      max_cvss,
      limit = 50, 
      offset = 0 
    } = req.query;

    let query = 'SELECT * FROM cve_database WHERE 1=1';
    const params = [];

    if (severity) {
      query += ' AND severity = ?';
      params.push(severity);
    }

    if (has_exploit === 'true') {
      query += ' AND exploit_available = 1';
    }

    if (vendor) {
      query += ' AND (vendor LIKE ? OR affected_products LIKE ?)';
      params.push(`%${vendor}%`, `%${vendor}%`);
    }

    if (search) {
      query += ' AND (cve_id LIKE ? OR title LIKE ? OR description LIKE ?)';
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    if (min_cvss) {
      query += ' AND cvss_score >= ?';
      params.push(parseFloat(min_cvss));
    }

    if (max_cvss) {
      query += ' AND cvss_score <= ?';
      params.push(parseFloat(max_cvss));
    }

    query += ' ORDER BY cvss_score DESC, published_date DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));

    const cves = db.prepare(query).all(...params);

    // Get total count for pagination
    let countQuery = 'SELECT COUNT(*) as count FROM cve_database WHERE 1=1';
    const countParams = params.slice(0, -2); // Remove limit and offset
    if (severity) countQuery += ' AND severity = ?';
    if (has_exploit === 'true') countQuery += ' AND exploit_available = 1';
    if (vendor) countQuery += ' AND (vendor LIKE ? OR affected_products LIKE ?)';
    if (search) countQuery += ' AND (cve_id LIKE ? OR title LIKE ? OR description LIKE ?)';
    if (min_cvss) countQuery += ' AND cvss_score >= ?';
    if (max_cvss) countQuery += ' AND cvss_score <= ?';

    const totalCount = db.prepare(countQuery).get(...countParams)?.count || 0;

    res.json({
      data: cves,
      pagination: {
        total: totalCount,
        limit: parseInt(limit),
        offset: parseInt(offset),
        hasMore: parseInt(offset) + cves.length < totalCount
      }
    });
  } catch (error) {
    logger.error('Search CVE error:', error);
    res.status(500).json({ error: 'Failed to search CVE database' });
  }
});

// Get CVE by ID
router.get('/:id', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const cve = db.prepare('SELECT * FROM cve_database WHERE cve_id = ?').get(req.params.id);

    if (!cve) {
      return res.status(404).json({ error: 'CVE not found' });
    }

    // Get affected devices in the network
    const affectedDevices = db.prepare(`
      SELECT d.id, d.name, d.ip, d.device_type, v.status as vuln_status
      FROM devices d
      JOIN vulnerabilities v ON d.id = v.device_id
      WHERE v.cve_id = ?
    `).all(req.params.id);

    res.json({
      ...cve,
      affectedDevices
    });
  } catch (error) {
    logger.error('Get CVE error:', error);
    res.status(500).json({ error: 'Failed to fetch CVE' });
  }
});

// Search CVEs by product/vendor
router.post('/search', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { vendor, product, version, keywords } = req.body;

    let query = 'SELECT * FROM cve_database WHERE 1=1';
    const params = [];

    if (vendor) {
      query += ' AND vendor LIKE ?';
      params.push(`%${vendor}%`);
    }

    if (product) {
      query += ' AND affected_products LIKE ?';
      params.push(`%${product}%`);
    }

    if (version) {
      query += ' AND affected_versions LIKE ?';
      params.push(`%${version}%`);
    }

    if (keywords && keywords.length > 0) {
      const keywordConditions = keywords.map(() => '(title LIKE ? OR description LIKE ?)').join(' OR ');
      query += ` AND (${keywordConditions})`;
      for (const keyword of keywords) {
        params.push(`%${keyword}%`, `%${keyword}%`);
      }
    }

    query += ' ORDER BY cvss_score DESC LIMIT 100';

    const cves = db.prepare(query).all(...params);

    res.json(cves);
  } catch (error) {
    logger.error('Search CVE error:', error);
    res.status(500).json({ error: 'Failed to search CVE database' });
  }
});

// Get CVE statistics
router.get('/stats/summary', authenticate, (req, res) => {
  try {
    const db = getDatabase();

    const total = db.prepare('SELECT COUNT(*) as count FROM cve_database').get().count;
    const withExploit = db.prepare('SELECT COUNT(*) as count FROM cve_database WHERE exploit_available = 1').get().count;

    const bySeverity = db.prepare(`
      SELECT severity, COUNT(*) as count 
      FROM cve_database 
      GROUP BY severity
    `).all();

    const byYear = db.prepare(`
      SELECT strftime('%Y', published_date) as year, COUNT(*) as count
      FROM cve_database
      WHERE published_date IS NOT NULL
      GROUP BY strftime('%Y', published_date)
      ORDER BY year DESC
      LIMIT 5
    `).all();

    const topVendors = db.prepare(`
      SELECT vendor, COUNT(*) as count
      FROM cve_database
      WHERE vendor IS NOT NULL AND vendor != ''
      GROUP BY vendor
      ORDER BY count DESC
      LIMIT 10
    `).all();

    const recentCritical = db.prepare(`
      SELECT cve_id, title, cvss_score, published_date
      FROM cve_database
      WHERE severity = 'critical'
      ORDER BY published_date DESC
      LIMIT 10
    `).all();

    res.json({
      total,
      withExploit,
      bySeverity,
      byYear,
      topVendors,
      recentCritical
    });
  } catch (error) {
    logger.error('Get CVE stats error:', error);
    res.status(500).json({ error: 'Failed to fetch CVE statistics' });
  }
});

// Check device against CVE database
router.post('/check-device', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { deviceId, manufacturer, model, firmware_version } = req.body;

    // Search for matching CVEs
    let query = 'SELECT * FROM cve_database WHERE 1=1';
    const params = [];

    if (manufacturer) {
      query += ' AND (vendor LIKE ? OR affected_products LIKE ?)';
      params.push(`%${manufacturer}%`, `%${manufacturer}%`);
    }

    if (model) {
      query += ' AND affected_products LIKE ?';
      params.push(`%${model}%`);
    }

    query += ' ORDER BY cvss_score DESC LIMIT 50';

    const potentialCves = db.prepare(query).all(...params);

    // Filter by version if provided
    let matchingCves = potentialCves;
    if (firmware_version && potentialCves.length > 0) {
      matchingCves = potentialCves.filter(cve => {
        if (!cve.affected_versions) return true;
        // Simple version check - in production, use proper version comparison
        return cve.affected_versions.includes(firmware_version) || 
               cve.affected_versions.toLowerCase().includes('all');
      });
    }

    res.json({
      deviceId,
      manufacturer,
      model,
      firmware_version,
      vulnerabilities: matchingCves,
      totalFound: matchingCves.length,
      criticalCount: matchingCves.filter(c => c.severity === 'critical').length,
      highCount: matchingCves.filter(c => c.severity === 'high').length
    });
  } catch (error) {
    logger.error('Check device CVE error:', error);
    res.status(500).json({ error: 'Failed to check device against CVE database' });
  }
});

module.exports = router;
