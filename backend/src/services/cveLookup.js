/**
 * CVE & Vulnerability Mapping Service
 * Queries NVD API (or CIRCL) for vendor/product or service banner
 * Caches results to avoid API rate limits
 */

const fetch = require('node-fetch');
const path = require('path');
const fs = require('fs');
const logger = require('../utils/logger');

const NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const CACHE_PATH = path.join(__dirname, '../../data/cve_cache.json');

// Load or initialize cache
let cveCache = {};
try {
  if (fs.existsSync(CACHE_PATH)) {
    cveCache = JSON.parse(fs.readFileSync(CACHE_PATH, 'utf8'));
  }
} catch {
  cveCache = {};
}

function saveCache() {
  fs.writeFileSync(CACHE_PATH, JSON.stringify(cveCache, null, 2));
}

/**
 * Query NVD API for CVEs by vendor/product
 */
async function queryNVD(vendor, product) {
  if (!vendor || vendor.toLowerCase() === 'unknown' || vendor.toLowerCase() === 'unknown vendor') {
    return [];
  }
  if (!product || product.toLowerCase() === 'unknown') {
    return [];
  }
  const cacheKey = `${vendor.toLowerCase()}::${product.toLowerCase()}`;
  if (cveCache[cacheKey]) {
    logger.info(`[CVE] Cache hit for ${cacheKey}`);
    return cveCache[cacheKey];
  }

  const params = new URLSearchParams({
    keywordSearch: `${vendor} ${product}`,
    resultsPerPage: '20',
    startIndex: '0'
  });

  const url = `${NVD_API_URL}?${params.toString()}`;
  logger.info(`[CVE] Querying NVD: ${url}`);

  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`NVD API error: ${res.status}`);
    const data = await res.json();
    const cves = (data.vulnerabilities || []).map(v => {
      const cve = v.cve;
      const cvss = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV2?.[0]?.cvssData || {};
      return {
        id: cve.id,
        published: cve.published,
        lastModified: cve.lastModified,
        description: cve.descriptions?.[0]?.value || '',
        cvssScore: cvss.baseScore || null,
        cvssSeverity: cvss.baseSeverity || null,
        cvssVector: cvss.vectorString || null,
        references: cve.references?.map(r => r.url) || [],
        exploitAvailable: cve.exploitabilityScore > 0,
        patchAvailable: cve.impactScore > 0,
      };
    });
    cveCache[cacheKey] = cves;
    saveCache();
    return cves;
  } catch (err) {
    logger.error(`[CVE] NVD query failed: ${err.message}`);
    return [];
  }
}

/**
 * Get CVEs for a device (by vendor/product or service banner)
 */
async function getDeviceCVEs(device) {
  const vendor = device.vendor || device.manufacturer || 'unknown';
  const product = device.model || device.type || 'unknown';
  const cves = await queryNVD(vendor, product);
  return cves;
}

module.exports = {
  queryNVD,
  getDeviceCVEs
};
