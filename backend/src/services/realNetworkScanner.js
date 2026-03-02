/**
 * Real Network Scanner Service
 * Cross-platform (Windows/Linux/Mac) implementation
 * Uses native OS commands for ARP, Ping, and Port scanning
 */

const { exec } = require('child_process');
const net = require('net');
const dns = require('dns');
const os = require('os');
const { promisify } = require('util');
const { v4: uuidv4 } = require('uuid');
const { checkCredentials, auditMisconfigurations } = require('./credentialChecker');
const { getDeviceCVEs } = require('./cveLookup');
const { getDatabase, saveDatabase } = require('../database/init');
const logger = require('../utils/logger');

const _execAsync = promisify(exec);
const execAsync = (command, options = {}) => _execAsync(command, { ...options, windowsHide: true });

// MAC Vendor database (common IoT vendors)
const MAC_VENDORS = {
  // Microsoft/Hyper-V
  '00:15:5D': 'Microsoft (Hyper-V)',
  // Intel
  'F8:3D:C6': 'Intel',
  '00:1E:67': 'Intel',
  '00:1F:3B': 'Intel',
  '00:21:6A': 'Intel',
  '00:22:FA': 'Intel',
  '00:24:D7': 'Intel',
  '00:26:C6': 'Intel',
  '00:27:10': 'Intel',
  '34:02:86': 'Intel',
  '64:80:99': 'Intel',
  '78:2B:CB': 'Intel',
  '84:3A:4B': 'Intel',
  '8C:EC:4B': 'Intel',
  'A0:88:69': 'Intel',
  'AC:7B:A1': 'Intel',
  'B4:6B:FC': 'Intel',
  'C8:0A:A9': 'Intel',
  'DC:53:60': 'Intel',
  'E4:70:B8': 'Intel',
  'F4:4D:30': 'Intel',
  // JioFi/Reliance (India)
  'A8:DA:0C': 'Jio (Reliance)',
  // Qualcomm/Mobile
  '28:E6:A9': 'ZTE',
  'F8:D4:78': 'Vivo Mobile',
  // More common vendors
  '00:1A:2B': 'Ayecom Technology',
  '00:50:56': 'VMware',
  'B8:27:EB': 'Raspberry Pi Foundation',
  'DC:A6:32': 'Raspberry Pi Trading',
  '18:B4:30': 'Nest Labs',
  '00:17:88': 'Philips Lighting',
  '94:10:3E': 'Belkin International',
  '68:A4:0E': 'BSH Hausgeräte',
  'AC:CF:85': 'HUAWEI',
  '00:0C:29': 'VMware',
  '00:1C:B3': 'Apple',
  // User's network MAC prefixes (added for accurate detection)
  'E4:3A:6E': 'Shenzhen Zeroone Technology',
  '20:15:DE': 'Samsung',
  'A8:1E:84': 'Quanta Computer',
  'B4:B5:2F': 'HP',
  '2C:58:B9': 'HP',
  'CC:28:AA': 'ASUS',
  'D0:AD:08': 'HP',
  '10:E7:C6': 'HP',
  '04:BF:1B': 'Dell',
  '64:6D:6C': 'Huawei',
  'C0:25:2F': 'Mercury (TP-Link)',
  '10:BD:18': 'Cisco',
  '00:0F:E0': 'NComputing',
  'A0:F8:49': 'ChangYang Tech',
  '00:8E:73': 'Cisco-Meraki',
  'C0:C9:E3': 'HP',
  '04:5F:B9': 'Liteon Technology',
  '00:17:88': 'Philips Lighting',
  '94:10:3E': 'Belkin International',
  '68:A4:0E': 'BSH Hausgeräte',
  'AC:CF:85': 'HUAWEI',
  '00:0C:29': 'VMware',
  '00:1C:B3': 'Apple',
  'F4:F5:D8': 'Google',
  '30:FD:38': 'Google',
  '00:04:4B': 'Nvidia',
  '00:1E:C9': 'Dell',
  '00:25:00': 'Apple',
  '3C:5A:B4': 'Google',
  'F0:EF:86': 'Google',
  '44:07:0B': 'Google',
  '00:1A:11': 'Google',
  '54:60:09': 'Google',
  'D4:F5:47': 'Google',
  '7C:2E:BD': 'Google',
  '20:DF:B9': 'Google',
  '78:4F:43': 'Apple',
  'A4:77:33': 'Google',
  'E4:F0:42': 'Google',
  '00:18:DD': 'Silicondust',
  '00:1D:C9': 'GainSpan',
  '70:EE:50': 'Netatmo',
  'B4:75:0E': 'Belkin',
  'C8:69:CD': 'Apple',
  '00:26:AB': 'Seiko Epson',
  'F4:5C:89': 'Apple',
  '10:40:F3': 'Apple',
  '00:23:12': 'Apple',
  '00:25:BC': 'Apple',
  '14:10:9F': 'Apple',
  'A8:66:7F': 'Apple',
  'D0:E1:40': 'Apple',
  'AC:BC:32': 'Apple',
  '70:56:81': 'Apple',
  'EC:35:86': 'Apple',
  'B0:34:95': 'Apple',
  '28:6A:BA': 'Apple',
  '38:C9:86': 'Apple',
  '00:1F:F3': 'Apple',
  '48:D7:05': 'Apple',
  '68:64:4B': 'Apple',
  '00:22:41': 'Apple',
  '00:1E:52': 'Apple',
  'AC:3C:0B': 'Apple',
  'BC:52:B7': 'Apple',
  'DC:86:D8': 'Apple',
  '84:FC:FE': 'Apple',
  '00:16:CB': 'Apple',
  '04:0C:CE': 'Apple',
  '98:01:A7': 'Apple',
  '00:11:24': 'Apple',
  '00:1D:4F': 'Apple',
  '28:E7:CF': 'Apple',
  'A4:D1:8C': 'Apple',
  'F0:24:75': 'Apple',
  '04:F1:3E': 'Apple',
  'C8:2A:14': 'Apple',
  '00:F7:6F': 'Apple',
  '90:72:40': 'Apple',
  '04:52:F3': 'Apple',
  '00:3E:E1': 'Apple',
  'C0:A5:3E': 'Apple',
  '50:32:75': 'Apple',
  'CC:08:E0': 'Apple',
  '34:36:3B': 'Apple',
  '98:FE:94': 'Apple',
  '68:5B:35': 'Apple',
  '60:03:08': 'Apple',
  '00:DB:70': 'Apple',
  '7C:D1:C3': 'Apple',
  'B8:E8:56': 'Apple',
  '24:A0:74': 'Apple',
  'AC:87:A3': 'Apple',
  '3C:15:C2': 'Apple',
  'CC:20:8C': 'Apple',
  '44:D8:84': 'Apple',
  '7C:6D:62': 'Apple',
  '94:94:26': 'Apple',
  'F0:DB:E2': 'Apple',
  '18:E7:F4': 'Apple',
  '88:C6:63': 'Apple',
  '1C:AB:A7': 'Apple',
  '84:78:8B': 'Apple',
  '88:66:A5': 'Apple',
  '90:8D:6C': 'Apple',
  '98:D6:BB': 'Apple',
  'C8:F6:50': 'Apple',
  '08:66:98': 'Apple',
  '4C:57:CA': 'Apple',
  '34:C0:59': 'Apple',
  '20:C9:D0': 'Apple',
  '84:85:06': 'Apple',
  '8C:7B:9D': 'Apple',
  'DC:2B:2A': 'Apple',
  'A4:5E:60': 'Apple',
  '28:F0:76': 'Apple',
  '40:B3:95': 'Apple',
  'B8:17:C2': 'Apple',
  '9C:8B:A0': 'Samsung',
  '00:26:37': 'Samsung',
  'D0:22:BE': 'Samsung',
  'FC:F1:36': 'Samsung',
  '14:49:E0': 'Samsung',
  '94:35:0A': 'Samsung',
  '6C:2F:2C': 'Samsung',
  'A0:21:B7': 'Samsung',
  '00:17:C9': 'Samsung',
  '00:23:39': 'Samsung',
  '00:24:54': 'Samsung',
  '5C:0A:5B': 'Samsung',
  '8C:71:F8': 'Samsung',
  'CC:07:AB': 'Samsung',
  'BC:14:EF': 'Samsung',
  '00:07:AB': 'Samsung',
  '10:D5:42': 'Samsung',
  'EC:1F:72': 'Samsung',
  '00:15:99': 'Samsung',
  '44:4E:1A': 'Samsung',
  '10:1D:C0': 'Samsung',
  '00:E0:4C': 'Realtek',
  '00:12:17': 'Cisco-Linksys',
  '00:18:39': 'Cisco-Linksys',
  '00:1A:70': 'Cisco-Linksys',
  '00:1C:10': 'Cisco-Linksys',
  '00:1E:E5': 'Cisco-Linksys',
  '00:21:29': 'Cisco-Linksys',
  '00:22:6B': 'Cisco-Linksys',
  '00:23:69': 'Cisco-Linksys',
  '00:25:9C': 'Cisco-Linksys',
  '20:AA:4B': 'Cisco-Linksys',
  '58:6D:8F': 'Cisco-Linksys',
  'C0:C1:C0': 'Cisco-Linksys',
  'E8:FC:AF': 'NETGEAR',
  '00:14:6C': 'NETGEAR',
  '00:1B:2F': 'NETGEAR',
  '00:1E:2A': 'NETGEAR',
  '00:1F:33': 'NETGEAR',
  '00:22:3F': 'NETGEAR',
  '00:24:B2': 'NETGEAR',
  '00:26:F2': 'NETGEAR',
  '20:4E:7F': 'NETGEAR',
  '30:46:9A': 'NETGEAR',
  '6C:B0:CE': 'NETGEAR',
  '84:1B:5E': 'NETGEAR',
  'A0:21:B7': 'NETGEAR',
  'A4:2B:8C': 'NETGEAR',
  'B0:7F:B9': 'NETGEAR',
  'C0:3F:0E': 'NETGEAR',
  'C4:04:15': 'NETGEAR',
  'E0:91:F5': 'NETGEAR',
  'E4:F4:C6': 'NETGEAR',
  '08:BD:43': 'NETGEAR',
  '9C:3D:CF': 'NETGEAR',
  '00:1D:7E': 'Cisco',
  '00:19:47': 'Cisco',
  '00:1A:A1': 'Cisco',
  '00:1B:53': 'Cisco',
  '00:24:C4': 'Cisco',
  '00:27:0D': 'Cisco',
  '64:00:F1': 'Cisco',
  'F8:4F:57': 'Hikvision',
  '68:D7:9A': 'Hikvision',
  'C0:56:E3': 'Hikvision',
  'BC:AD:28': 'Hikvision',
  '44:19:B6': 'Hikvision',
  '54:C4:15': 'Hikvision',
  '4C:BD:8F': 'Hikvision',
  'A0:CC:2B': 'Dahua',
  '3C:EF:8C': 'Dahua',
  '90:02:A9': 'Dahua',
  'E0:50:8B': 'Dahua',
  '4C:11:BF': 'Dahua',
  '38:AF:D7': 'Dahua',
  'DC:B7:2E': 'Dahua',
  '00:18:AE': 'TP-Link',
  '00:1D:0F': 'TP-Link',
  '00:21:27': 'TP-Link',
  '00:23:CD': 'TP-Link',
  '00:27:19': 'TP-Link',
  '14:CC:20': 'TP-Link',
  '14:CF:92': 'TP-Link',
  '18:A6:F7': 'TP-Link',
  '1C:FA:68': 'TP-Link',
  '30:B5:C2': 'TP-Link',
  '50:C7:BF': 'TP-Link',
  '54:C8:0F': 'TP-Link',
  '60:E3:27': 'TP-Link',
  '64:56:01': 'TP-Link',
  '64:66:B3': 'TP-Link',
  '64:70:02': 'TP-Link',
  '6C:5A:B0': 'TP-Link',
  '74:DA:38': 'TP-Link',
  '78:A1:06': 'TP-Link',
  '8C:21:0A': 'TP-Link',
  '90:F6:52': 'TP-Link',
  '94:0C:6D': 'TP-Link',
  '98:DE:D0': 'TP-Link',
  'A0:F3:C1': 'TP-Link',
  'AC:84:C6': 'TP-Link',
  'B0:4E:26': 'TP-Link',
  'B0:95:75': 'TP-Link',
  'B8:D5:26': 'TP-Link',
  'BC:46:99': 'TP-Link',
  'C0:25:E9': 'TP-Link',
  'C4:E9:84': 'TP-Link',
  'D4:6E:0E': 'TP-Link',
  'D8:07:B6': 'TP-Link',
  'E4:D3:32': 'TP-Link',
  'E8:94:F6': 'TP-Link',
  'EC:08:6B': 'TP-Link',
  'EC:17:2F': 'TP-Link',
  'F0:F3:36': 'TP-Link',
  'F4:EC:38': 'TP-Link',
  'F8:1A:67': 'TP-Link',
  '00:1E:58': 'D-Link',
  '00:22:B0': 'D-Link',
  '00:26:5A': 'D-Link',
  '14:D6:4D': 'D-Link',
  '1C:7E:E5': 'D-Link',
  '28:10:7B': 'D-Link',
  '34:08:04': 'D-Link',
  '84:C9:B2': 'D-Link',
  '90:94:E4': 'D-Link',
  'B8:A3:86': 'D-Link',
  'C8:BE:19': 'D-Link',
  'CC:B2:55': 'D-Link',
  'F0:7D:68': 'D-Link',
  '44:94:FC': 'Ring',
  '58:CB:52': 'Ring',
  '7C:64:56': 'Ring',
  '08:EC:A9': 'Ring',
  '00:62:6E': 'Amazon',
  '18:74:2E': 'Amazon',
  '34:D2:70': 'Amazon',
  '40:B4:CD': 'Amazon',
  '44:65:0D': 'Amazon',
  '50:DC:E7': 'Amazon',
  '68:37:E9': 'Amazon',
  '68:54:FD': 'Amazon',
  '74:75:48': 'Amazon',
  '78:E1:03': 'Amazon',
  'A0:02:DC': 'Amazon',
  'AC:63:BE': 'Amazon',
  'B4:7C:9C': 'Amazon',
  'CC:9E:A2': 'Amazon',
  'F0:81:73': 'Amazon',
  'FC:A1:83': 'Amazon',
  '00:04:20': 'Slim Devices (Logitech)',
  '00:09:B0': 'Onkyo',
  '00:0D:4B': 'Roku',
  '00:1F:5B': 'Sony',
  '00:EB:2D': 'Sony',
  '04:5D:4B': 'Sony',
  '10:4F:A8': 'Sony',
  '24:21:AB': 'Sony',
  '30:52:CB': 'Sony',
  '40:2B:A1': 'Sony',
  '54:42:49': 'Sony',
  '78:84:3C': 'Sony',
  '8C:64:22': 'Sony',
  '94:CE:2C': 'Sony',
  'AC:9B:0A': 'Sony',
  'B4:52:7E': 'Sony',
  'D8:D4:3C': 'Sony',
  'FC:F1:52': 'Sony',
  '00:04:A3': 'Microchip Technology',
  '00:08:DC': 'Wiznet',
  '00:1F:28': 'Espressif (ESP8266/ESP32)',
  '24:0A:C4': 'Espressif',
  '30:AE:A4': 'Espressif',
  '5C:CF:7F': 'Espressif',
  '60:01:94': 'Espressif',
  '68:C6:3A': 'Espressif',
  '84:F3:EB': 'Espressif',
  'A4:7B:9D': 'Espressif',
  'B4:E6:2D': 'Espressif',
  'BC:DD:C2': 'Espressif',
  'C4:4F:33': 'Espressif',
  'CC:50:E3': 'Espressif',
  'DC:4F:22': 'Espressif',
  'EC:FA:BC': 'Espressif',
  'F4:CF:A2': 'Espressif',
  '74:C6:3B': 'AzureWave',
  '80:1F:12': 'Microchip',
  'B8:F0:09': 'Espressif',
  '4C:11:AE': 'Espressif',
  'AC:67:B2': 'Espressif',
  '98:F4:AB': 'Espressif',
  '94:B9:7E': 'Espressif',
  '2C:F4:32': 'Espressif',
  'E0:98:06': 'Espressif',
  'A0:20:A6': 'Espressif',
  '48:3F:DA': 'Espressif'
};

// Device type signatures based on open ports
const DEVICE_SIGNATURES = {
  camera: [554, 8554, 8080, 80, 443, 37777, 37778, 34567],
  router: [80, 443, 8080, 23, 22, 53],
  nas: [5000, 5001, 139, 445, 548, 873, 9091],
  printer: [9100, 515, 631, 80],
  smart_tv: [8008, 8443, 9080, 1900, 7000, 8001],
  iot_hub: [1883, 8883, 5683, 8080],
  voice_assistant: [8008, 8443, 443, 4070],
  smart_speaker: [8008, 8443, 1400, 1443],
  game_console: [3074, 3478, 3479, 3480],
  media_player: [8060, 9080, 1900],
  thermostat: [80, 443, 9543],
  doorbell: [80, 443, 8080],
  lock: [80, 443, 8883],
  light: [80, 56700, 1982],
  plug: [80, 9999, 6668],
  switch: [80, 8080, 9999]
};

// Common IoT ports to scan
const IOT_PORTS = [
  20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445,
  515, 548, 554, 631, 873, 993, 995, 1433, 1521, 1883,
  1900, 2222, 3306, 3389, 5000, 5001, 5432, 5683, 6379,
  7547, 8000, 8008, 8080, 8081, 8443, 8554, 8883, 9000,
  9080, 9090, 9091, 9100, 9200, 9543, 27017, 34567, 37777
];

// Quick scan ports (most common IoT)
const QUICK_SCAN_PORTS = [22, 23, 80, 443, 554, 1883, 5000, 8080, 8443, 9100];

/**
 * Get local network interface info
 */
function getNetworkInfo() {
  const interfaces = os.networkInterfaces();
  const results = [];

  for (const [name, addrs] of Object.entries(interfaces)) {
    for (const addr of addrs) {
      if (addr.family === 'IPv4' && !addr.internal) {
        results.push({
          interface: name,
          ip: addr.address,
          netmask: addr.netmask,
          mac: addr.mac
        });
      }
    }
  }

  return results;
}

/**
 * Calculate subnet from IP and netmask
 */
function calculateSubnet(ip, netmask) {
  const ipParts = ip.split('.').map(Number);
  const maskParts = netmask.split('.').map(Number);

  const networkParts = ipParts.map((part, i) => part & maskParts[i]);
  const network = networkParts.join('.');

  // Calculate CIDR
  let cidr = 0;
  for (const part of maskParts) {
    let bits = part;
    while (bits) {
      cidr += bits & 1;
      bits >>= 1;
    }
  }

  return `${network}/${cidr}`;
}

function getIPRange(subnet) {
  const [baseIP, cidr] = subnet.split('/');
  const parts = baseIP.split('.').map(Number);
  const maskBits = parseInt(cidr, 10);
  const hostBits = 32 - maskBits;
  const numHosts = Math.pow(2, hostBits) - 2;

  const ips = [];
  const baseNum = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];

  for (let i = 1; i <= Math.min(numHosts, 254); i++) {
    const ipNum = baseNum + i;
    const ip = [
      (ipNum >> 24) & 255,
      (ipNum >> 16) & 255,
      (ipNum >> 8) & 255,
      ipNum & 255
    ].join('.');
    ips.push(ip);
  }

  return ips;
}

/**
 * Lookup MAC vendor from OUI
 */
function lookupVendor(mac) {
  if (!mac) return 'Unknown';
  const oui = mac.substring(0, 8).toUpperCase();
  return MAC_VENDORS[oui] || 'Unknown Vendor';
}

/**
 * Detect device type from vendor and open ports
 */
function detectDeviceType(vendor, openPorts) {
  const vendorLower = vendor.toLowerCase();

  // Vendor-based detection
  if (vendorLower.includes('hikvision') || vendorLower.includes('dahua') || vendorLower.includes('axis')) {
    return 'camera';
  }
  if (vendorLower.includes('ring')) return 'doorbell';
  if (vendorLower.includes('nest')) return 'thermostat';
  if (vendorLower.includes('philips') && vendorLower.includes('hue')) return 'light';
  if (vendorLower.includes('amazon') || vendorLower.includes('echo')) return 'voice_assistant';
  if (vendorLower.includes('google')) return 'smart_speaker';
  if (vendorLower.includes('roku') || vendorLower.includes('apple tv')) return 'media_player';
  if (vendorLower.includes('samsung') && openPorts.some(p => [8001, 8002].includes(p))) return 'smart_tv';
  if (vendorLower.includes('sony') && openPorts.some(p => [3478, 3479].includes(p))) return 'game_console';
  if (vendorLower.includes('synology') || vendorLower.includes('qnap')) return 'nas';
  if (vendorLower.includes('epson') || vendorLower.includes('hp') || vendorLower.includes('canon') || vendorLower.includes('brother')) {
    if (openPorts.includes(9100) || openPorts.includes(631)) return 'printer';
  }
  if (vendorLower.includes('espressif') || vendorLower.includes('esp')) return 'iot_device';

  // Port-based detection
  for (const [type, ports] of Object.entries(DEVICE_SIGNATURES)) {
    const matchCount = openPorts.filter(p => ports.includes(p)).length;
    if (matchCount >= 2) {
      return type;
    }
  }

  // Single port detection
  if (openPorts.includes(554) || openPorts.includes(8554)) return 'camera';

  // Mobile IP camera apps detection (IP Webcam, DroidCam, iVCam, etc.)
  // These typically use port 8080 or 4747 with few other ports open
  // Limit to devices with <= 4 ports to avoid misclassifying web servers/routers
  if (openPorts.includes(8080) && openPorts.length <= 4) {
    // Additional check: if it has typical mobile device ports (not router ports)
    const hasRouterPorts = openPorts.some(p => [53, 67, 7547].includes(p));
    if (!hasRouterPorts) return 'camera';
  }

  // DroidCam specific port
  if (openPorts.includes(4747)) return 'camera';

  if (openPorts.includes(9100)) return 'printer';
  if (openPorts.includes(5000) || openPorts.includes(5001)) return 'nas';
  if (openPorts.includes(1883) || openPorts.includes(8883)) return 'iot_hub';

  // Default based on common router ports at gateway
  if (openPorts.includes(80) && openPorts.includes(443)) {
    if (openPorts.includes(53) || openPorts.includes(67)) return 'router';
  }

  // Windows detection
  if (openPorts.includes(135) || openPorts.includes(445)) return 'workstation';

  return 'unknown';
}

/**
 * Real ARP scan using OS commands
 */
async function arpScan() {
  const platform = os.platform();
  const devices = [];

  try {
    let output;

    if (platform === 'win32') {
      // Windows: Use arp -a
      const { stdout } = await execAsync('arp -a', { encoding: 'utf8' });
      output = stdout;

      // Parse Windows ARP output
      const lines = output.split('\n');
      for (const line of lines) {
        // Match pattern: IP address MAC address type
        const match = line.match(/(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)/);
        if (match) {
          const ip = match[1];
          const mac = match[2].replace(/-/g, ':').toUpperCase();
          const type = match[3];

          if (type === 'dynamic' || type === 'static') {
            devices.push({ ip, mac, type });
          }
        }
      }
    } else if (platform === 'linux' || platform === 'darwin') {
      // Linux/Mac: Use arp -a or ip neighbor
      try {
        const { stdout } = await execAsync('arp -a', { encoding: 'utf8' });
        output = stdout;

        const lines = output.split('\n');
        for (const line of lines) {
          // Linux format: hostname (IP) at MAC [ether] on interface
          // Mac format: hostname (IP) at MAC on interface
          const match = line.match(/\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})/);
          if (match) {
            devices.push({
              ip: match[1],
              mac: match[2].toUpperCase(),
              type: 'dynamic'
            });
          }
        }
      } catch {
        // Try ip neighbor for Linux
        const { stdout } = await execAsync('ip neighbor', { encoding: 'utf8' });
        output = stdout;

        const lines = output.split('\n');
        for (const line of lines) {
          const match = line.match(/(\d+\.\d+\.\d+\.\d+)\s+dev\s+\w+\s+lladdr\s+([0-9a-fA-F:]{17})/);
          if (match) {
            devices.push({
              ip: match[1],
              mac: match[2].toUpperCase(),
              type: 'dynamic'
            });
          }
        }
      }
    }

    logger.info(`ARP scan found ${devices.length} devices`);
    return devices;
  } catch (error) {
    logger.error('ARP scan error:', error.message);
    return devices;
  }
}

/**
 * Ping a single IP address
 * Increased timeout to 2000ms for better accuracy with slow devices
 */
async function pingHost(ip, timeout = 2000) {
  const platform = os.platform();

  try {
    let cmd;
    if (platform === 'win32') {
      cmd = `ping -n 1 -w ${timeout} ${ip}`;
    } else {
      cmd = `ping -c 1 -W ${Math.ceil(timeout / 1000)} ${ip}`;
    }

    const { stdout } = await execAsync(cmd, { encoding: 'utf8', timeout: timeout + 1000 });

    // Check for successful ping
    if (platform === 'win32') {
      return stdout.includes('TTL=') || stdout.includes('ttl=');
    } else {
      return stdout.includes('1 received') || stdout.includes('1 packets received');
    }
  } catch {
    return false;
  }
}

/**
 * Check if device is alive using ping + TCP port probe fallback
 * Solves issue where devices block ICMP but are still online
 */
async function isDeviceAlive(ip, timeout = 3000) {
  // Try ping first (primary method)
  if (await pingHost(ip, timeout)) {
    return true;
  }

  // Fallback: Try TCP connection to common ports in parallel
  const probePorts = [80, 443, 22, 23, 8080, 554];
  const results = await Promise.all(probePorts.map(port =>
    new Promise(resolve => {
      const socket = new net.Socket();
      socket.setTimeout(timeout / 2); // Shorter timeout for port probe
      socket.on('connect', () => { socket.destroy(); resolve(true); });
      socket.on('timeout', () => { socket.destroy(); resolve(false); });
      socket.on('error', () => { socket.destroy(); resolve(false); });
      socket.connect(port, ip);
    })
  ));

  const anyOpen = results.some(r => r === true);
  if (anyOpen) {
    logger.info(`Device ${ip} alive via port probe (ping failed)`);
  }
  return anyOpen;
}

/**
 * Scan a single port on an IP
 */
function scanPort(ip, port, timeout = 1000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let resolved = false;

    const cleanup = () => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
      }
    };

    socket.setTimeout(timeout);

    socket.on('connect', () => {
      resolve({ port, open: true, ip });
      cleanup();
    });

    socket.on('timeout', () => {
      resolve({ port, open: false, ip });
      cleanup();
    });

    socket.on('error', () => {
      resolve({ port, open: false, ip });
      cleanup();
    });

    socket.connect(port, ip);
  });
}

/**
 * Scan multiple ports on an IP
 */
async function scanPorts(ip, ports = QUICK_SCAN_PORTS, concurrency = 10) {
  const openPorts = [];

  // Scan in batches for better performance
  for (let i = 0; i < ports.length; i += concurrency) {
    const batch = ports.slice(i, i + concurrency);
    const results = await Promise.all(batch.map(port => scanPort(ip, port)));

    for (const result of results) {
      if (result.open) {
        openPorts.push(result.port);
      }
    }
  }

  return openPorts;
}

/**
 * Get service name from port
 */
function getServiceName(port) {
  const services = {
    20: 'FTP-Data',
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    67: 'DHCP',
    68: 'DHCP',
    80: 'HTTP',
    110: 'POP3',
    139: 'NetBIOS',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    515: 'LPD',
    548: 'AFP',
    554: 'RTSP',
    631: 'IPP',
    873: 'rsync',
    993: 'IMAPS',
    995: 'POP3S',
    1433: 'MSSQL',
    1521: 'Oracle',
    1883: 'MQTT',
    1900: 'SSDP/UPnP',
    2222: 'SSH-Alt',
    3306: 'MySQL',
    3389: 'RDP',
    5000: 'UPnP/Synology',
    5001: 'Synology-SSL',
    5432: 'PostgreSQL',
    5683: 'CoAP',
    6379: 'Redis',
    7547: 'TR-069/CWMP',
    8000: 'HTTP-Alt',
    8008: 'HTTP/Cast',
    8080: 'HTTP-Proxy',
    8081: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    8554: 'RTSP-Alt',
    8883: 'MQTT-SSL',
    9000: 'HTTP-Alt',
    9080: 'HTTP-Alt',
    9090: 'HTTP-Alt',
    9091: 'Transmission',
    9100: 'Printer',
    9200: 'Elasticsearch',
    9543: 'Nest',
    27017: 'MongoDB',
    34567: 'DVR-HTTP',
    37777: 'Dahua-DVR',
    37778: 'Dahua-DVR'
  };

  return services[port] || `Port-${port}`;
}

/**
 * Check if a single port is open (for ad-hoc scanning)
 */
async function checkPort(ip, port, timeout = 2000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let resolved = false;

    const cleanup = () => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
      }
    };

    socket.setTimeout(timeout);

    socket.on('connect', () => {
      cleanup();
      resolve(true);
    });

    socket.on('timeout', () => {
      cleanup();
      resolve(false);
    });

    socket.on('error', () => {
      cleanup();
      resolve(false);
    });

    socket.connect(port, ip);
  });
}

/**
 * Grab HTTP banner from a web service
 */
async function grabBanner(ip, port, timeout = 3000) {
  return new Promise((resolve, reject) => {
    const isHttps = [443, 8443].includes(port);
    const protocol = isHttps ? require('https') : require('http');

    const options = {
      hostname: ip,
      port: port,
      path: '/',
      method: 'GET',
      timeout: timeout,
      rejectUnauthorized: false, // Allow self-signed certs
      headers: {
        'User-Agent': 'BlackCodex-Scanner/1.0'
      }
    };

    const req = protocol.request(options, (res) => {
      const banner = {
        statusCode: res.statusCode,
        server: res.headers['server'] || null,
        poweredBy: res.headers['x-powered-by'] || null,
        contentType: res.headers['content-type'] || null,
        headers: {}
      };

      // Capture interesting headers
      const interestingHeaders = ['www-authenticate', 'x-frame-options', 'x-aspnet-version', 'x-server'];
      for (const header of interestingHeaders) {
        if (res.headers[header]) {
          banner.headers[header] = res.headers[header];
        }
      }

      // Read small portion of body for title detection
      let body = '';
      let resolved = false;
      const finish = () => {
        if (resolved) return;
        resolved = true;
        const titleMatch = body.match(/<title[^>]*>([^<]+)<\/title>/i);
        if (titleMatch) {
          banner.title = titleMatch[1].trim();
        }
        resolve(banner);
      };

      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        if (resolved) return;
        body += chunk;
        if (body.length > 2048) {
          finish();
          req.destroy(); // Don't read too much
        }
      });

      res.on('end', finish);
      res.on('close', finish);
      res.on('error', finish);
    });

    req.on('error', (err) => {
      reject(err);
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Connection timeout'));
    });

    req.end();
  });
}

/**
 * Try to get hostname via reverse DNS
 */
async function getHostname(ip) {
  return new Promise((resolve) => {
    dns.reverse(ip, (err, hostnames) => {
      if (err || !hostnames || hostnames.length === 0) {
        resolve(null);
      } else {
        resolve(hostnames[0]);
      }
    });
  });
}

/**
 * Calculate risk score based on findings (0-100, higher is riskier)
 */
function calculateRiskScore(device, vulns = []) {
  let score = 0;

  // 1. CRITICAL: Weak or missing credentials (HIGHEST PRIORITY)
  if (device.hasWeakCredentials || device.has_weak_credentials) {
    score += 50;
  }

  // 2. Dangerous ports (Telnet, FTP, etc.)
  const dangerousPorts = {
    23: 30,    // Telnet (Critical)
    21: 15,    // FTP (High)
    7547: 25,  // TR-069 (Critical)
    37777: 25, // Dahua (Critical)
    34567: 25, // DVR (Critical)
    554: 15,   // RTSP (Medium/High for cameras)
    1900: 10,  // UPnP (Medium)
    161: 10,   // SNMP (Medium)
    5000: 5,   // Synology DSM (Low)
    8080: 5    // HTTP Alt (Low)
  };

  const openPorts = device.openPorts || (device.open_ports ? (typeof device.open_ports === 'string' ? JSON.parse(device.open_ports) : device.open_ports) : []);

  openPorts.forEach(p => {
    const portNum = typeof p === 'object' ? p.port || p.port_number : p;
    if (dangerousPorts[portNum]) {
      score += dangerousPorts[portNum];
    }
  });

  // 3. Vulnerability count weighting
  const criticalVulns = vulns.filter(v => (v.severity || '').toLowerCase() === 'critical').length;
  const highVulns = vulns.filter(v => (v.severity || '').toLowerCase() === 'high').length;
  const mediumVulns = vulns.filter(v => (v.severity || '').toLowerCase() === 'medium').length;

  score += (criticalVulns * 40);
  score += (highVulns * 20);
  score += (mediumVulns * 10);

  // 4. Unknown vendor / anomalous data
  if (device.vendor === 'Unknown' || device.vendor === 'Unknown Vendor' || !device.vendor) {
    score += 5;
  }

  // 5. Open management ports without encryption
  const portsList = openPorts.map(p => typeof p === 'object' ? p.port || p.port_number : p);
  if (portsList.includes(80) && !portsList.includes(443)) {
    score += 10;
  }

  // 6. Excessive attack surface
  if (portsList.length > 10) {
    score += 15;
  } else if (portsList.length > 5) {
    score += 5;
  }

  return Math.min(score, 100);
}

/**
 * Get risk level from score
 */
function getRiskLevel(score) {
  if (score >= 85) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  if (score >= 15) return 'low';
  return 'safe';
}

/**
 * Full network scan - discovers and analyzes all devices
 */
async function fullNetworkScan(subnet, progressCallback) {
  const db = getDatabase();
  const devices = [];
  const now = new Date().toISOString();

  logger.info(`Starting full network scan on ${subnet || 'auto-detected network'}`);

  // Get network info if subnet not specified
  if (!subnet) {
    const networkInfo = getNetworkInfo();
    if (networkInfo.length > 0) {
      // Prioritize interfaces that aren't VirtualBox or VMware
      const priorityIfaces = networkInfo.filter(iface =>
        !iface.interface.toLowerCase().includes('virtualbox') &&
        !iface.interface.toLowerCase().includes('vbox') &&
        !iface.interface.toLowerCase().includes('vmware') &&
        !iface.ip.startsWith('192.168.56.') // Common VirtualBox subnet
      );

      const targetIface = priorityIfaces.length > 0 ? priorityIfaces[0] : networkInfo[0];
      subnet = calculateSubnet(targetIface.ip, targetIface.netmask);
      logger.info(`Auto-detected subnet: ${subnet} on interface ${targetIface.interface}`);
    } else {
      subnet = '192.168.1.0/24';
      logger.info(`Using default subnet: ${subnet}`);
    }
  }

  // IMPORTANT: Mark ALL existing devices as offline before scanning
  // This ensures only currently-discovered devices are shown as online
  if (progressCallback) progressCallback(2, 'Preparing scan - clearing stale data...');
  try {
    db.prepare("UPDATE devices SET status = 'offline' WHERE status = 'online'").run();
    logger.info('Marked all existing devices as offline for fresh scan');
  } catch (err) {
    logger.error('Error marking devices offline:', err);
  }

  // Step 1: ARP scan for quick device discovery
  if (progressCallback) progressCallback(5, 'Running ARP scan...');
  const arpDevices = await arpScan();

  // Step 2: Ping sweep the subnet for devices not in ARP cache
  // Now scans ALL IPs in batches (removed 50 IP limit for accuracy)
  if (progressCallback) progressCallback(15, 'Running ping sweep...');
  const ipRange = getIPRange(subnet);
  const discoveredIPs = new Set(arpDevices.map(d => d.ip));

  // Get all unknown IPs (no limit - scan entire subnet for accuracy)
  const unknownIPs = ipRange.filter(ip => !discoveredIPs.has(ip));
  logger.info(`Ping sweeping ${unknownIPs.length} IPs not in ARP cache...`);

  // Process in batches of 50 for performance
  const batchSize = 50;
  for (let i = 0; i < unknownIPs.length; i += batchSize) {
    const batch = unknownIPs.slice(i, i + batchSize);
    const batchProgress = 15 + Math.floor((i / unknownIPs.length) * 5);
    if (progressCallback) progressCallback(batchProgress, `Ping sweep batch ${Math.floor(i / batchSize) + 1}...`);

    const pingResults = await Promise.all(
      batch.map(async (ip) => {
        const alive = await pingHost(ip);
        return alive ? ip : null;
      })
    );

    // Add discovered devices from this batch
    for (const ip of pingResults.filter(Boolean)) {
      if (!discoveredIPs.has(ip)) {
        arpDevices.push({ ip, mac: null, type: 'ping' });
        discoveredIPs.add(ip);
      }
    }
  }

  const totalDevices = arpDevices.length;
  let totalPortsChecked = 0;
  let totalVulnsFound = 0;
  const allVulnerabilities = []; // Collect all vulnerabilities with device info for frontend display
  logger.info(`Found ${totalDevices} potential devices`);

  // Step 3: Scan each device in parallel batches for speed
  const deviceBatchSize = 10; // Process 10 devices at a time
  for (let i = 0; i < arpDevices.length; i += deviceBatchSize) {
    const batch = arpDevices.slice(i, i + deviceBatchSize);

    await Promise.all(batch.map(async (arpDevice) => {
      const globalIndex = i + batch.indexOf(arpDevice);
      const progress = 20 + Math.floor((globalIndex / totalDevices) * 70);

      try {
        // Only verify if not already found via ping sweep (ping sweep already confirms they are alive)
        if (arpDevice.type !== 'ping') {
          const alive = await isDeviceAlive(arpDevice.ip, 1500);
          if (!alive) return;
        }

        if (progressCallback) {
          progressCallback(progress, `Scanning ${arpDevice.ip}...`, {
            devicesScanned: devices.length,
            portsChecked: totalPortsChecked,
            vulnsFound: totalVulnsFound
          });
        }

        // Port scan
        const openPorts = await scanPorts(arpDevice.ip, QUICK_SCAN_PORTS, 15);
        totalPortsChecked += QUICK_SCAN_PORTS.length;

        // Get vendor and device type
        const vendor = lookupVendor(arpDevice.mac);
        const deviceType = detectDeviceType(vendor, openPorts);
        const hostname = await getHostname(arpDevice.ip);

        const device = {
          id: uuidv4(),
          ip: arpDevice.ip,
          mac: arpDevice.mac,
          vendor,
          deviceType,
          hostname,
          openPorts,
          services: openPorts.map(p => ({ port: p, service: getServiceName(p) })),
          status: 'online',
          discoveredAt: now,
          lastSeen: now,
          hasWeakCredentials: false
        };

        // Check for weak credentials
        const httpPorts = openPorts.filter(p => [80, 443, 8080, 8443, 8000, 8888].includes(p));
        if (httpPorts.length > 0) {
          try {
            const credCheck = await checkCredentials(arpDevice.ip, openPorts, deviceType);
            if (credCheck.weakCredentialsFound || credCheck.defaultCredentialsFound) {
              device.hasWeakCredentials = true;
            }
          } catch (err) { }
        }

        device.riskScore = calculateRiskScore(device);
        device.riskLevel = getRiskLevel(device.riskScore);

        if (device.riskLevel !== 'safe') {
          totalVulnsFound++;
        }

        devices.push(device);

        // Save to database (synchronized access if needed, but sqlite3/better-sqlite3 handle this)
        const existing = db.prepare('SELECT id FROM devices WHERE ip = ?').get(device.ip);

        if (existing) {
          db.prepare(`
            UPDATE devices SET 
              mac = COALESCE(?, mac),
              manufacturer = ?,
              device_type = ?,
              name = COALESCE(name, ?),
              status = 'online',
              risk_score = ?,
              risk_level = ?,
              open_ports = ?,
              has_weak_credentials = ?,
              last_seen = ?,
              updated_at = ?
            WHERE ip = ?
          `).run(
            device.mac, device.vendor, device.deviceType,
            device.hostname || `Device ${device.ip}`,
            device.riskScore, device.riskLevel,
            JSON.stringify(device.services),
            device.hasWeakCredentials ? 1 : 0,
            now, now, device.ip
          );
          device.id = existing.id;
        } else {
          db.prepare(`
            INSERT INTO devices (id, name, ip, mac, device_type, manufacturer, status, risk_score, risk_level, open_ports, has_weak_credentials, discovered_at, last_seen, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 'online', ?, ?, ?, ?, ?, ?, ?, ?)
          `).run(
            device.id, device.hostname || `Device ${device.ip}`,
            device.ip, device.mac, device.deviceType, device.vendor,
            device.riskScore, device.riskLevel,
            JSON.stringify(device.services),
            device.hasWeakCredentials ? 1 : 0,
            now, now, now, now
          );

          db.prepare(`
            INSERT INTO alerts (id, type, severity, device_id, device_ip, device_mac, message, created_at)
            VALUES (?, 'new_device', 'info', ?, ?, ?, ?, ?)
          `).run(uuidv4(), device.id, device.ip, device.mac, `New device discovered: ${device.hostname || device.ip}`, now);
        }

        // Save ports
        for (const port of device.openPorts) {
          db.prepare(`INSERT OR REPLACE INTO ports (id, device_id, port_number, service_name, status) VALUES (?, ?, ?, ?, 'open')`).run(uuidv4(), device.id, port, getServiceName(port));
        }

        // Background classification
        (async () => {
          try {
            const { classifyDevice } = require('./nmapVendorClassifier');
            const classification = await classifyDevice(device.ip, device.vendor, device.deviceType, { openPorts: device.openPorts, ip: device.ip });
            db.prepare(`UPDATE devices SET device_category = ?, device_vendor = ?, device_role = ?, iot_device_type = ? WHERE ip = ?`).run(classification.category, classification.vendor || device.vendor, classification.device_role || 'Unknown', classification.iot_device_type || 'Unknown', device.ip);
          } catch (e) { }
        })();

        // Vulnerabilities
        const deviceVulns = await checkDeviceVulnerabilities(device);
        device.riskScore = calculateRiskScore(device, deviceVulns);
        device.riskLevel = getRiskLevel(device.riskScore);

        db.prepare(`UPDATE devices SET risk_score = ?, risk_level = ?, updated_at = ? WHERE ip = ?`).run(device.riskScore, device.riskLevel, now, device.ip);

        // Broadcast updates
        try {
          const { broadcast } = require('../websocket/server');
          broadcast('devices', { event: 'device_updated', device: { ...device, open_ports: JSON.stringify(device.services) } });
          if (deviceVulns.length > 0) {
            broadcast('scan', { type: 'vulnerability_found', totalVulns: totalVulnsFound });
          }
        } catch (e) { }

      } catch (error) {
        logger.error(`Error scanning ${arpDevice.ip}:`, error.message);
      }
    }));
  }

  if (progressCallback) progressCallback(95, 'Finalizing scan...');

  // Save database
  db.save();

  if (progressCallback) progressCallback(100, 'Scan complete');

  logger.info(`Scan complete. Found ${devices.length} devices.`);

  return {
    devices,
    vulnerabilities: allVulnerabilities, // Include all found vulnerabilities with IP info
    summary: {
      total: devices.length,
      online: devices.length,
      portsChecked: totalPortsChecked,
      critical: devices.filter(d => d.riskLevel === 'critical').length,
      high: devices.filter(d => d.riskLevel === 'high').length,
      medium: devices.filter(d => d.riskLevel === 'medium').length,
      low: devices.filter(d => d.riskLevel === 'low').length,
      safe: devices.filter(d => d.riskLevel === 'safe').length,
      vulnerabilitiesCount: allVulnerabilities.length
    }
  };
}

/**
 * Check device for common vulnerabilities
 */
async function checkDeviceVulnerabilities(device) {
  const db = getDatabase();
  const now = new Date().toISOString();
  const vulns = [];

  // Telnet open
  if (device.openPorts.includes(23)) {
    vulns.push({
      title: 'Telnet Service Enabled',
      severity: 'high',
      description: 'Telnet transmits data including passwords in plaintext. This is a serious security risk.',
      cve_id: null,
      cvss_score: 7.5,
      remediation: 'Disable Telnet and use SSH for secure remote access.'
    });
  }

  // FTP open
  if (device.openPorts.includes(21)) {
    vulns.push({
      title: 'FTP Service Detected',
      severity: 'medium',
      description: 'FTP transmits credentials in plaintext and is vulnerable to various attacks.',
      cve_id: null,
      cvss_score: 5.3,
      remediation: 'Use SFTP or SCP for secure file transfer.'
    });
  }

  // TR-069/CWMP (ISP remote management)
  if (device.openPorts.includes(7547)) {
    // Persist scan snapshot
    const scanId = uuidv4();
    db.prepare(`
      INSERT INTO scans (id, type, status, start_time, end_time, devices_scanned)
      VALUES (?, 'incremental', 'completed', ?, ?, ?)
    `).run(scanId, now, now, 1); // fixed: discoveredDevices.length not available in this scope, passed 1

  }

  // TP-Link router vulnerabilities
  if (device.vendor.includes('TP-Link') && device.deviceType === 'router') {
    vulns.push({
      title: 'TP-Link Router - Check for Known Vulnerabilities',
      severity: 'medium',
      description: 'Some TP-Link routers have known vulnerabilities. Ensure firmware is up to date.',
      cve_id: null,
      cvss_score: 6.5,
      remediation: 'Update router firmware to latest version.'
    });
  }

  // UPnP enabled
  if (device.openPorts.includes(1900)) {
    vulns.push({
      title: 'UPnP Service Enabled',
      severity: 'medium',
      description: 'Universal Plug and Play is enabled, which can be exploited for port forwarding and NAT traversal attacks.',
      cve_id: null,
      cvss_score: 5.3,
      remediation: 'Disable UPnP if not required.'
    });
  }

  // HTTP without HTTPS
  if (device.openPorts.includes(80) && !device.openPorts.includes(443)) {
    vulns.push({
      title: 'Unencrypted Web Interface',
      severity: 'low',
      description: 'Device web interface uses HTTP only. Credentials may be transmitted in plaintext.',
      cve_id: null,
      cvss_score: 4.3,
      remediation: 'Enable HTTPS on the device if supported.'
    });
  }

  // Unknown Vendor Warning
  if (device.vendor === 'Unknown' || device.vendor === 'Unknown Vendor') {
    vulns.push({
      title: 'Unknown Device Vendor',
      severity: 'low',
      description: 'Device manufacturer could not be identified via MAC address. This may indicate a randomized MAC or obscure IoT device.',
      cve_id: null,
      cvss_score: 2.0,
      remediation: 'Verify device identity manually.'
    });
  }

  // Excessive Open Ports
  if (device.openPorts.length > 5) {
    vulns.push({
      title: 'Excessive Open Ports',
      severity: 'low',
      description: `Device has ${device.openPorts.length} open ports, increasing attack surface.`,
      cve_id: null,
      cvss_score: 3.5,
      remediation: 'Close unnecessary ports and services.'
    });
  }

  // Save vulnerabilities to database
  for (const vuln of vulns) {
    const existing = db.prepare(
      'SELECT id FROM vulnerabilities WHERE device_id = ? AND title = ?'
    ).get(device.id, vuln.title);

    if (!existing) {
      db.prepare(`
        INSERT INTO vulnerabilities (id, device_id, title, severity, description, cve_id, cvss_score, remediation, status, discovered_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
      `).run(
        uuidv4(),
        device.id,
        vuln.title,
        vuln.severity,
        vuln.description,
        vuln.cve_id,
        vuln.cvss_score,
        vuln.remediation,
        now
      );

      // ...
      const { emit } = require('../websocket/server');

      // ... (inside checkDeviceVulnerabilities)

      // Create alert for critical/high vulns
      if (vuln.severity === 'critical' || vuln.severity === 'high') {
        const alertId = uuidv4();
        const alertMessage = `${vuln.severity.toUpperCase()}: ${vuln.title} on ${device.ip}`;

        db.prepare(`
          INSERT INTO alerts (id, type, severity, device_id, device_ip, message, created_at)
          VALUES (?, 'vulnerability', ?, ?, ?, ?, ?)
        `).run(
          alertId,
          vuln.severity,
          device.id,
          device.ip,
          alertMessage,
          now
        );

        // Emit real-time alert
        if (emit && emit.newAlert) {
          emit.newAlert({
            id: alertId,
            type: 'vulnerability',
            severity: vuln.severity,
            device_id: device.id,
            device_ip: device.ip,
            message: alertMessage,
            created_at: now,
            acknowledged: 0
          });
        }
      }
    }
  }

  // Lookup real CVEs from NVD
  try {
    const liveCves = await getDeviceCVEs(device);
    if (liveCves && liveCves.length > 0) {
      logger.info(`[NVD] Found ${liveCves.length} CVEs for ${device.vendor} ${device.deviceType}`);
      for (const cve of liveCves) {
        const existing = db.prepare('SELECT id FROM vulnerabilities WHERE device_id = ? AND cve_id = ?').get(device.id, cve.id);
        if (!existing) {
          db.prepare(`
                      INSERT INTO vulnerabilities (id, device_id, title, severity, description, cve_id, cvss_score, remediation, status, discovered_at)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
                  `).run(
            uuidv4(), device.id, cve.id,
            cve.cvssSeverity || 'medium',
            cve.description || `Vulnerability ${cve.id}`,
            cve.id,
            cve.cvssScore || 5.0,
            'Check vendor updates',
            now
          );
          vulns.push({ title: cve.id, severity: cve.cvssSeverity });
        }
      }
    }
  } catch (err) {
    logger.error(`[NVD] Failed during scan lookup: ${err.message}`);
  }

  return vulns;
}

/**
 * Quick device discovery (ARP only, no port scan)
 * Filters out broadcast and multicast addresses
 */
async function quickDiscovery() {
  // Try to find the most likely active subnet
  const info = getNetworkInfo();
  const priorityIfaces = info.filter(iface =>
    !iface.interface.toLowerCase().includes('virtualbox') &&
    !iface.interface.toLowerCase().includes('vbox') &&
    !iface.interface.toLowerCase().includes('vmware') &&
    !iface.ip.startsWith('192.168.56.')
  );
  const targetIface = priorityIfaces.length > 0 ? priorityIfaces[0] : info[0];

  // Proactive ping sweep of common IPs if we suspect empty cache
  // We'll ping common IPs (.1, .100-110, etc.) or just do a very fast sweep of the whole subnet
  if (targetIface) {
    const subnet = calculateSubnet(targetIface.ip, targetIface.netmask);
    const ipRange = getIPRange(subnet);

    // Very fast sweep of common IPs to seed ARP cache
    const commonIPs = ipRange.filter(ip => {
      const last = parseInt(ip.split('.')[3]);
      return last === 1 || (last >= 100 && last <= 120) || (last >= 1 && last <= 10);
    });

    await Promise.all(commonIPs.map(ip => pingHost(ip, 500)));
  }

  const arpDevices = await arpScan();

  // Filter out broadcast, multicast, and link-local addresses
  const filteredDevices = arpDevices.filter(d => {
    // Filter out broadcast MAC
    if (d.mac === 'FF:FF:FF:FF:FF:FF') return false;

    // Filter out multicast MAC (starts with 01:00:5E for IPv4 multicast)
    if (d.mac.startsWith('01:00:5E')) return false;

    // Filter out broadcast IPs
    if (d.ip.endsWith('.255')) return false;

    // Filter out multicast IPs (224.x.x.x - 239.x.x.x)
    const firstOctet = parseInt(d.ip.split('.')[0]);
    if (firstOctet >= 224 && firstOctet <= 239) return false;

    // Filter out link-local (169.254.x.x)
    if (d.ip.startsWith('169.254.')) return false;

    return true;
  });

  return filteredDevices.map(d => ({
    ip: d.ip,
    mac: d.mac,
    vendor: lookupVendor(d.mac),
    hostname: d.hostname || null,
    deviceType: detectDeviceType(lookupVendor(d.mac), []),
    isAlive: true,
    status: 'online'
  }));
}

/**
 * Scan specific ports on a single IP
 */
async function scanDevicePorts(ip, ports = IOT_PORTS) {
  const openPorts = await scanPorts(ip, ports, 20);

  return openPorts.map(port => ({
    port,
    service: getServiceName(port),
    open: true
  }));
}

/**
 * Perform initial scan and populate database with REAL devices
 * This replaces demo data - only real discovered devices are stored
 */
async function performInitialScan() {
  logger.info('[InitialScan] Starting real network discovery...');

  try {
    const db = getDatabase();
    if (!db) {
      logger.error('[InitialScan] Database not available');
      return { success: false, deviceCount: 0 };
    }

    // Clear existing devices (remove demo data)
    db.prepare('DELETE FROM devices').run();
    db.prepare('DELETE FROM ports').run();
    db.prepare('DELETE FROM vulnerabilities').run();
    db.prepare('DELETE FROM alerts').run();
    logger.info('[InitialScan] Cleared old data');

    // Perform real ARP scan
    const discoveredDevices = await quickDiscovery();
    logger.info(`[InitialScan] Discovered ${discoveredDevices.length} devices via ARP`);

    const now = new Date().toISOString();
    let insertedCount = 0;

    for (const device of discoveredDevices) {
      try {
        const deviceId = uuidv4();
        const deviceType = detectDeviceType(device.vendor, []);

        // Determine risk level based on device type
        let riskLevel = 'low';
        let riskScore = 20;

        if (device.vendor === 'Unknown Vendor' || device.vendor === 'Unknown') {
          riskLevel = 'medium';
          riskScore = 50;
        }

        // Insert real device into database
        db.prepare(`
          INSERT INTO devices (id, name, ip, mac, device_type, manufacturer, status, risk_score, risk_level, discovered_at, last_seen, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          deviceId,
          device.hostname || `${deviceType} (${device.ip})`,
          device.ip,
          device.mac,
          deviceType,
          device.vendor,
          'online',
          riskScore,
          riskLevel,
          now,
          now,
          now
        );

        // Create alert for new device discovery
        db.prepare(`
          INSERT INTO alerts (id, type, severity, device_id, device_ip, device_mac, message, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          uuidv4(),
          'new_device',
          'info',
          deviceId,
          device.ip,
          device.mac,
          `New device discovered: ${device.vendor} at ${device.ip}`,
          now
        );

        insertedCount++;
        logger.info(`[InitialScan] Added device: ${device.ip} (${device.vendor})`);

      } catch (err) {
        logger.error(`[InitialScan] Error inserting device ${device.ip}:`, err.message);
      }
    }

    // Save database
    if (typeof db.save === 'function') {
      db.save();
    }

    logger.info(`[InitialScan] Complete: ${insertedCount} real devices added to database`);

    return {
      success: true,
      deviceCount: insertedCount,
      devices: discoveredDevices
    };

  } catch (err) {
    logger.error('[InitialScan] Error:', err.message);
    return { success: false, deviceCount: 0, error: err.message };
  }
}

/**
 * Refresh devices - rescan network and update database
 */
async function refreshDevices() {
  logger.info('[RefreshDevices] Starting network refresh...');

  const db = getDatabase();
  if (!db) return { success: false };

  const discoveredDevices = await quickDiscovery();
  const now = new Date().toISOString();

  // Get existing devices
  const existingDevices = db.prepare('SELECT * FROM devices').all();
  const existingIPs = new Set(existingDevices.map(d => d.ip));

  let newCount = 0;
  let updatedCount = 0;

  for (const device of discoveredDevices) {
    if (existingIPs.has(device.ip)) {
      // Update existing device
      db.prepare(`
        UPDATE devices SET status = 'online', last_seen = ? WHERE ip = ?
      `).run(now, device.ip);
      updatedCount++;
    } else {
      // Insert new device
      const deviceId = uuidv4();
      db.prepare(`
        INSERT INTO devices (id, name, ip, mac, device_type, manufacturer, status, risk_score, risk_level, discovered_at, last_seen, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        deviceId,
        device.hostname || `${device.deviceType} (${device.ip})`,
        device.ip,
        device.mac,
        device.deviceType,
        device.vendor,
        'online',
        30,
        'low',
        now,
        now,
        now
      );

      // Alert for new device
      db.prepare(`
        INSERT INTO alerts (id, type, severity, device_id, device_ip, message, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        uuidv4(),
        'new_device',
        'warning',
        deviceId,
        device.ip,
        `NEW DEVICE DETECTED: ${device.vendor} at ${device.ip}`,
        now
      );

      newCount++;
    }
  }

  // Mark devices not seen as offline
  const discoveredIPs = new Set(discoveredDevices.map(d => d.ip));
  for (const existing of existingDevices) {
    if (!discoveredIPs.has(existing.ip) && existing.status === 'online') {
      db.prepare(`UPDATE devices SET status = 'offline' WHERE ip = ?`).run(existing.ip);

      // Alert for offline device
      db.prepare(`
        INSERT INTO alerts (id, type, severity, device_id, device_ip, message, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        uuidv4(),
        'device_offline',
        'warning',
        existing.id,
        existing.ip,
        `Device went OFFLINE: ${existing.name} (${existing.ip})`,
        now
      );
    }
  }

  if (typeof db.save === 'function') {
    db.save();
  }

  return { success: true, newDevices: newCount, updatedDevices: updatedCount, devices: discoveredDevices };
}


/**
 * Get real network traffic statistics from OS
 */
async function getNetworkTraffic() {
  const platform = os.platform();

  try {
    if (platform === 'win32') {
      // Windows: netstat -e gives interface stats
      const { stdout } = await execAsync('netstat -e', { encoding: 'utf8' });
      const lines = stdout.split('\n');

      for (const line of lines) {
        if (line.trim().startsWith('Bytes')) {
          const parts = line.trim().split(/\s+/);
          // Format: Bytes [Received] [Sent]
          // parts[0]="Bytes", parts[1]=Received, parts[2]=Sent
          return {
            received: parseInt(parts[1], 10) || 0,
            sent: parseInt(parts[2], 10) || 0
          };
        }
      }
    } else {
      // Linux/Mac: Read /proc/net/dev or use netstat -i
      try {
        const { stdout } = await execAsync('cat /proc/net/dev', { encoding: 'utf8' });
        const lines = stdout.split('\n');
        let totalRx = 0;
        let totalTx = 0;

        for (const line of lines) {
          if (line.includes(':')) {
            const parts = line.split(':')[1].trim().split(/\s+/);
            // parts[0] = Rx bytes, parts[8] = Tx bytes (usually)
            totalRx += parseInt(parts[0], 10) || 0;
            totalTx += parseInt(parts[8], 10) || 0;
          }
        }
        return { received: totalRx, sent: totalTx };
      } catch (e) {
        return { received: 0, sent: 0 };
      }
    }
  } catch (error) {
    logger.error('Failed to get network traffic:', error.message);
  }

  return { received: 0, sent: 0 };
}

module.exports = {
  getNetworkTraffic,
  fullNetworkScan,
  quickDiscovery,
  scanDevicePorts,
  performInitialScan,
  refreshDevices,
  arpScan,
  pingHost,
  isDeviceAlive,
  scanPorts,
  scanPort,
  checkPort,
  grabBanner,
  getServiceName,
  lookupVendor,
  detectDeviceType,
  calculateRiskScore,
  getRiskLevel,
  getNetworkInfo,
  calculateSubnet,
  getIPRange,
  IOT_PORTS,
  QUICK_SCAN_PORTS
};
