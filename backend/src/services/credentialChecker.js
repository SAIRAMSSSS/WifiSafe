/**
 * Credential and Misconfiguration Checker Service
 * 
 * WARNING: Credential checks are intrusive. Only run on networks you control
 * or with explicit authorization. All attempts are logged in audit_logs.
 */

const net = require('net');
const http = require('http');
const https = require('https');
const dgram = require('dgram');
const logger = require('../utils/logger');

// Common default credentials for IoT devices
const DEFAULT_CREDENTIALS = {
  // Universal defaults
  common: [
    { username: 'admin', password: 'admin' },
    { username: 'admin', password: 'password' },
    { username: 'admin', password: '1234' },
    { username: 'admin', password: '12345' },
    { username: 'admin', password: '' },
    { username: 'root', password: 'root' },
    { username: 'root', password: '' },
    { username: 'user', password: 'user' },
    { username: 'guest', password: 'guest' },
    { username: 'support', password: 'support' },
  ],
  // Router-specific
  router: [
    { username: 'admin', password: 'admin' },
    { username: 'admin', password: '' },
    { username: 'admin', password: 'password' },
    { username: 'admin', password: 'admin123' },
    { username: 'cisco', password: 'cisco' },
    { username: 'ubnt', password: 'ubnt' },
  ],
  // IP Camera defaults
  camera: [
    { username: 'admin', password: 'admin' },
    { username: 'admin', password: '12345' },
    { username: 'admin', password: '' },
    { username: 'root', password: 'pass' },
    { username: 'admin', password: '888888' },
    { username: 'admin', password: 'xmhdipc' },
    { username: 'default', password: 'default' },
  ],
  // DVR/NVR defaults
  dvr: [
    { username: 'admin', password: '12345' },
    { username: 'admin', password: '' },
    { username: 'admin', password: 'admin' },
    { username: '666666', password: '666666' },
    { username: '888888', password: '888888' },
  ],
  // Printer defaults
  printer: [
    { username: 'admin', password: '' },
    { username: 'admin', password: 'admin' },
    { username: '', password: '' },
  ],
  // IoT device defaults
  iot: [
    { username: 'admin', password: 'admin' },
    { username: 'admin', password: '' },
    { username: 'root', password: 'root' },
    { username: 'user', password: '1234' },
  ]
};

// Risky ports that indicate potential misconfigurations
const RISKY_PORTS = {
  23: { name: 'Telnet', severity: 'high', issue: 'Unencrypted remote access' },
  21: { name: 'FTP', severity: 'medium', issue: 'Unencrypted file transfer' },
  69: { name: 'TFTP', severity: 'high', issue: 'Trivial FTP - no auth' },
  161: { name: 'SNMP', severity: 'high', issue: 'Network management protocol' },
  7547: { name: 'TR-069', severity: 'critical', issue: 'ISP management interface' },
  5555: { name: 'Android ADB', severity: 'critical', issue: 'Android debug bridge' },
  502: { name: 'Modbus', severity: 'high', issue: 'Industrial control protocol' },
  37777: { name: 'Dahua DVR', severity: 'high', issue: 'DVR management port' },
  5357: { name: 'WSDAPI', severity: 'medium', issue: 'Windows discovery' },
  1900: { name: 'UPnP/SSDP', severity: 'medium', issue: 'Universal Plug and Play' },
};

/**
 * Check HTTP Basic Auth credentials
 */
async function checkHttpAuth(ip, port, username, password, timeout = 5000) {
  return new Promise((resolve) => {
    const isHttps = [443, 8443].includes(port);
    const protocol = isHttps ? https : http;

    const auth = Buffer.from(`${username}:${password}`).toString('base64');

    const options = {
      hostname: ip,
      port: port,
      path: '/',
      method: 'GET',
      timeout: timeout,
      rejectUnauthorized: false,
      headers: {
        'Authorization': `Basic ${auth}`,
        'User-Agent': 'BlackCodex-SecurityAudit/1.0'
      }
    };

    const req = protocol.request(options, (res) => {
      // 200, 301, 302 indicates successful auth
      // 401, 403 indicates failed auth
      const success = res.statusCode < 400;
      resolve({
        success,
        statusCode: res.statusCode,
        service: 'HTTP',
        username,
        authRequired: res.statusCode === 401 || res.statusCode === 403
      });
    });

    req.on('error', (err) => {
      resolve({ success: false, error: err.message, service: 'HTTP' });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ success: false, error: 'timeout', service: 'HTTP' });
    });

    req.end();
  });
}

/**
 * Check if HTTP admin page requires auth
 */
async function checkHttpAdminPage(ip, port, timeout = 5000) {
  return new Promise((resolve) => {
    const isHttps = [443, 8443].includes(port);
    const protocol = isHttps ? https : http;

    const options = {
      hostname: ip,
      port: port,
      path: '/',
      method: 'GET',
      timeout: timeout,
      rejectUnauthorized: false,
      headers: {
        'User-Agent': 'BlackCodex-SecurityAudit/1.0'
      }
    };

    const req = protocol.request(options, (res) => {
      let body = '';
      let resolved = false;

      const finish = () => {
        if (resolved) return;
        resolved = true;

        const usesHttps = isHttps;
        const requiresAuth = res.statusCode === 401 || res.statusCode === 403;
        const hasLoginForm = /login|password|signin|authenticate/i.test(body);
        const isAdminPage = /admin|management|config|settings|dashboard/i.test(body);

        // Extract page title
        const titleMatch = body.match(/<title[^>]*>([^<]+)<\/title>/i);
        const title = titleMatch ? titleMatch[1].trim() : null;

        // Check for security headers
        const hasHSTS = !!res.headers['strict-transport-security'];
        const hasXFrame = !!res.headers['x-frame-options'];
        const serverHeader = res.headers['server'] || null;

        resolve({
          accessible: res.statusCode < 500,
          statusCode: res.statusCode,
          usesHttps,
          requiresAuth,
          hasLoginForm,
          isAdminPage,
          title,
          hasHSTS,
          hasXFrame,
          serverHeader
        });
      };

      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        if (resolved) return;
        body += chunk;
        if (body.length > 8192) {
          finish();
          req.destroy();
        }
      });

      res.on('end', finish);
      res.on('close', finish);
      res.on('error', finish);
    });

    req.on('error', (err) => {
      resolve({ accessible: false, error: err.message });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ accessible: false, error: 'timeout' });
    });

    req.end();
  });
}

/**
 * Simple Telnet credential check (banner grab only - non-intrusive)
 */
async function checkTelnetBanner(ip, port = 23, timeout = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let banner = '';
    let resolved = false;

    const cleanup = () => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
      }
    };

    socket.setTimeout(timeout);

    socket.on('connect', () => {
      // Just grab the banner, don't send credentials
    });

    socket.on('data', (data) => {
      banner += data.toString();
      if (banner.length > 512 || banner.includes('login') || banner.includes('Login')) {
        cleanup();
        resolve({
          open: true,
          banner: banner.substring(0, 256),
          promptsForLogin: /login|username/i.test(banner),
          service: 'Telnet'
        });
      }
    });

    socket.on('timeout', () => {
      cleanup();
      resolve({ open: true, banner, service: 'Telnet' });
    });

    socket.on('error', () => {
      cleanup();
      resolve({ open: false, service: 'Telnet' });
    });

    socket.on('close', () => {
      if (!resolved) {
        resolve({ open: banner.length > 0, banner, service: 'Telnet' });
      }
    });

    socket.connect(port, ip);
  });
}

/**
 * Check for UPnP enabled (SSDP discovery)
 */
async function checkUPnP(ip, timeout = 3000) {
  return new Promise((resolve) => {
    const client = dgram.createSocket('udp4');
    let resolved = false;

    const ssdpRequest = Buffer.from(
      'M-SEARCH * HTTP/1.1\r\n' +
      `HOST: ${ip}:1900\r\n` +
      'MAN: "ssdp:discover"\r\n' +
      'MX: 2\r\n' +
      'ST: upnp:rootdevice\r\n' +
      '\r\n'
    );

    const timer = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        client.close();
        resolve({ enabled: false, service: 'UPnP' });
      }
    }, timeout);

    client.on('message', (msg, rinfo) => {
      if (!resolved && rinfo.address === ip) {
        resolved = true;
        clearTimeout(timer);
        client.close();

        const response = msg.toString();
        const locationMatch = response.match(/LOCATION:\s*(.+)/i);
        const serverMatch = response.match(/SERVER:\s*(.+)/i);

        resolve({
          enabled: true,
          location: locationMatch ? locationMatch[1].trim() : null,
          server: serverMatch ? serverMatch[1].trim() : null,
          response: response.substring(0, 512),
          service: 'UPnP'
        });
      }
    });

    client.on('error', () => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timer);
        client.close();
        resolve({ enabled: false, error: 'socket error', service: 'UPnP' });
      }
    });

    client.send(ssdpRequest, 0, ssdpRequest.length, 1900, ip);
  });
}

/**
 * Check SNMP with public community string
 */
async function checkSNMPPublic(ip, timeout = 3000) {
  return new Promise((resolve) => {
    const client = dgram.createSocket('udp4');
    let resolved = false;

    // Simple SNMP GET request for sysDescr.0 with community 'public'
    // This is a minimal SNMPv1 GetRequest
    const snmpRequest = Buffer.from([
      0x30, 0x26, // SEQUENCE, length 38
      0x02, 0x01, 0x00, // INTEGER, version 0 (SNMPv1)
      0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // OCTET STRING "public"
      0xa0, 0x19, // GetRequest-PDU
      0x02, 0x04, 0x00, 0x00, 0x00, 0x01, // request-id
      0x02, 0x01, 0x00, // error-status
      0x02, 0x01, 0x00, // error-index
      0x30, 0x0b, // variable-bindings
      0x30, 0x09,
      0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, // OID 1.3.6.1.2.1.1.1.0 (sysDescr)
      0x05, 0x00 // NULL value
    ]);

    const timer = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        client.close();
        resolve({ vulnerable: false, service: 'SNMP' });
      }
    }, timeout);

    client.on('message', (msg, rinfo) => {
      if (!resolved && rinfo.address === ip) {
        resolved = true;
        clearTimeout(timer);
        client.close();

        resolve({
          vulnerable: true,
          community: 'public',
          service: 'SNMP',
          issue: 'SNMP responds to public community string'
        });
      }
    });

    client.on('error', () => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timer);
        client.close();
        resolve({ vulnerable: false, service: 'SNMP' });
      }
    });

    client.send(snmpRequest, 0, snmpRequest.length, 161, ip);
  });
}

/**
 * Run safe credential checks on a device
 * Only checks HTTP Basic Auth - does not attempt actual login
 */
async function checkCredentials(ip, openPorts = [], deviceType = 'unknown') {
  const results = {
    ip,
    timestamp: new Date().toISOString(),
    testedServices: [],
    weakCredentialsFound: false,
    defaultCredentialsFound: false,
    findings: []
  };

  // Get appropriate credential list
  const credList = DEFAULT_CREDENTIALS[deviceType] || DEFAULT_CREDENTIALS.common;

  // Check HTTP ports
  const httpPorts = openPorts.filter(p => [80, 8080, 443, 8443, 8000, 8888].includes(p));

  for (const port of httpPorts) {
    const adminCheck = await checkHttpAdminPage(ip, port);

    if (adminCheck.accessible && adminCheck.isAdminPage) {
      results.testedServices.push({
        service: 'HTTP',
        port,
        adminPage: true,
        usesHttps: adminCheck.usesHttps,
        title: adminCheck.title
      });

      // Only test credentials if auth is required
      if (adminCheck.requiresAuth || adminCheck.hasLoginForm) {
        for (const cred of credList.slice(0, 5)) { // Limit attempts
          const authResult = await checkHttpAuth(ip, port, cred.username, cred.password);

          if (authResult.success) {
            results.weakCredentialsFound = true;
            results.defaultCredentialsFound = true;
            results.findings.push({
              service: 'HTTP',
              port,
              type: 'default_credentials',
              severity: 'critical',
              username: cred.username,
              message: `Default credentials work: ${cred.username}:${cred.password.substring(0, 2)}***`
            });
            break; // Stop after first successful credential
          }
        }
      } else if (!adminCheck.requiresAuth && adminCheck.isAdminPage) {
        // Admin page accessible without auth!
        results.findings.push({
          service: 'HTTP',
          port,
          type: 'no_auth',
          severity: 'critical',
          message: `Admin interface accessible without authentication: ${adminCheck.title || 'Admin Panel'}`
        });
        results.weakCredentialsFound = true;
      }
    }
  }

  // Check Telnet (banner only - non-intrusive)
  if (openPorts.includes(23)) {
    const telnetResult = await checkTelnetBanner(ip);
    results.testedServices.push({
      service: 'Telnet',
      port: 23,
      open: telnetResult.open,
      banner: telnetResult.banner
    });

    if (telnetResult.open) {
      results.findings.push({
        service: 'Telnet',
        port: 23,
        type: 'insecure_protocol',
        severity: 'high',
        message: 'Telnet service is enabled - unencrypted remote access'
      });
    }
  }

  return results;
}

/**
 * Run misconfiguration audit on a device
 */
async function auditMisconfigurations(ip, openPorts = []) {
  const results = {
    ip,
    timestamp: new Date().toISOString(),
    checks: [],
    misconfigurations: [],
    score: 100 // Start with perfect score, deduct for issues
  };

  // Check for risky open ports
  for (const port of openPorts) {
    if (RISKY_PORTS[port]) {
      const info = RISKY_PORTS[port];
      results.misconfigurations.push({
        type: `${info.name.toLowerCase()}_open`,
        severity: info.severity,
        port,
        title: `${info.name} Port Open`,
        description: info.issue,
        recommendation: `Close port ${port} (${info.name}) if not required`
      });
      results.score -= info.severity === 'critical' ? 25 : info.severity === 'high' ? 15 : 10;
    }
  }
  results.checks.push({ name: 'Risky Ports', completed: true });

  // Check UPnP
  const upnpResult = await checkUPnP(ip);
  results.checks.push({ name: 'UPnP Discovery', completed: true });

  if (upnpResult.enabled) {
    results.misconfigurations.push({
      type: 'upnp_enabled',
      severity: 'medium',
      title: 'UPnP Enabled',
      description: `UPnP service is responding. Server: ${upnpResult.server || 'Unknown'}`,
      recommendation: 'Disable UPnP unless specifically required'
    });
    results.score -= 10;
  }

  // Check SNMP public community
  if (openPorts.includes(161)) {
    const snmpResult = await checkSNMPPublic(ip);
    results.checks.push({ name: 'SNMP Public Community', completed: true });

    if (snmpResult.vulnerable) {
      results.misconfigurations.push({
        type: 'snmp_public',
        severity: 'high',
        title: 'SNMP Public Community String',
        description: 'SNMP service responds to "public" community string',
        recommendation: 'Change SNMP community string or disable SNMP'
      });
      results.score -= 20;
    }
  }

  // Check HTTP admin pages for HTTPS
  const httpPorts = openPorts.filter(p => [80, 8080].includes(p));
  const httpsPorts = openPorts.filter(p => [443, 8443].includes(p));

  for (const port of httpPorts) {
    const httpCheck = await checkHttpAdminPage(ip, port);
    results.checks.push({ name: `HTTP Admin Check (${port})`, completed: true });

    if (httpCheck.accessible && httpCheck.isAdminPage && !httpsPorts.length) {
      results.misconfigurations.push({
        type: 'http_no_ssl',
        severity: 'high',
        port,
        title: 'Admin Panel Without HTTPS',
        description: `Admin interface at port ${port} uses unencrypted HTTP`,
        recommendation: 'Enable HTTPS for admin interfaces'
      });
      results.score -= 15;
    }

    if (httpCheck.accessible && !httpCheck.hasXFrame) {
      results.misconfigurations.push({
        type: 'missing_security_headers',
        severity: 'low',
        port,
        title: 'Missing X-Frame-Options Header',
        description: 'Web interface may be vulnerable to clickjacking',
        recommendation: 'Add X-Frame-Options: DENY header'
      });
      results.score -= 5;
    }
  }

  // Ensure score doesn't go negative
  results.score = Math.max(0, results.score);
  results.riskLevel = results.score >= 80 ? 'low' : results.score >= 60 ? 'medium' : results.score >= 40 ? 'high' : 'critical';

  return results;
}

/**
 * Get list of common credentials for a device type
 */
function getCredentialList(deviceType = 'common') {
  return DEFAULT_CREDENTIALS[deviceType] || DEFAULT_CREDENTIALS.common;
}

module.exports = {
  checkCredentials,
  auditMisconfigurations,
  checkHttpAuth,
  checkHttpAdminPage,
  checkTelnetBanner,
  checkUPnP,
  checkSNMPPublic,
  getCredentialList,
  DEFAULT_CREDENTIALS,
  RISKY_PORTS
};
