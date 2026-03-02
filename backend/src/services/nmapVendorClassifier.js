/**
 * Nmap-Enhanced Device Classification Service
 * Non-intrusive post-processing layer for IoT device categorization
 * 
 * Uses Nmap MAC vendor detection when available, gracefully falls back to existing data
 */

const { exec } = require('child_process');
const { promisify } = require('util');
const logger = require('../utils/logger');

const _execAsync = promisify(exec);
const execAsync = (command, options = {}) => _execAsync(command, { ...options, windowsHide: true });

// IoT device vendor patterns (comprehensive list)
const IOT_PATTERNS = [
    // IoT Chips & Modules
    /espressif/i, /esp32/i, /esp8266/i,
    // Security Cameras & DVR
    /hikvision/i, /dahua/i, /axis/i, /uniview/i, /avigilon/i,
    /amcrest/i, /lorex/i, /swann/i, /annke/i,
    // Smart Home Brands
    /ring/i, /nest/i, /arlo/i, /wyze/i, /eufy/i, /blink/i,
    /ecobee/i, /hive/i, /tado/i,
    // Network Equipment (IoT context) - Routers/Gateways
    /tp-?link/i, /d-?link/i, /netgear/i, /linksys/i,
    /shenzhen.*zero/i, /zeroone/i,
    // Smart Devices
    /sonos/i, /philips.*hue/i, /belkin/i, /wemo/i,
    /smartthings/i, /lifx/i, /sengled/i,
    // Media Devices & Digital Signage
    /roku/i, /chromecast/i, /fire.*tv/i, /apple.*tv/i,
    /changyang/i,  // Digital signage
    // Thin Clients & Terminals
    /ncomputing/i, /wyse/i,
    // Smart Power & Components
    /liteon/i, /lite-?on/i,
    // DIY / Maker
    /raspberry.*pi/i, /arduino/i,
    // Generic IoT indicators
    /\biot\b/i, /sensor/i, /cctv/i, /nvr/i, /dvr/i
];

// Normal computing device patterns
const NORMAL_PATTERNS = [
    // PC Manufacturers
    /intel/i, /amd/i, /dell/i, /hp/i, /lenovo/i, /asus/i,
    /acer/i, /msi/i, /gigabyte/i, /asrock/i,
    // Mobile Manufacturers
    /apple/i, /samsung/i, /xiaomi/i, /oppo/i, /vivo/i,
    /oneplus/i, /huawei/i, /lg/i, /sony/i, /motorola/i,
    /nokia/i, /google.*pixel/i,
    // Virtualization
    /microsoft/i, /vmware/i, /virtualbox/i, /parallels/i,
    // Networking (PC context)
    /realtek/i, /broadcom/i, /qualcomm/i, /mediatek/i
];

/**
 * Classify device based on vendor string
 * @param {string} vendor - Vendor name from MAC OUI
 * @returns {'IoT' | 'Normal' | 'Unknown'}
 */
function classifyVendor(vendor) {
    if (!vendor || vendor === 'Unknown' || vendor === 'Unknown Vendor') {
        return 'Unknown';
    }

    // Check IoT patterns first (higher priority)
    for (const pattern of IOT_PATTERNS) {
        if (pattern.test(vendor)) {
            logger.debug(`Vendor "${vendor}" matched IoT pattern`);
            return 'IoT';
        }
    }

    // Check normal device patterns
    for (const pattern of NORMAL_PATTERNS) {
        if (pattern.test(vendor)) {
            logger.debug(`Vendor "${vendor}" matched Normal pattern`);
            return 'Normal';
        }
    }

    // Default to unknown
    logger.debug(`Vendor "${vendor}" did not match any patterns`);
    return 'Unknown';
}

/**
 * Get MAC vendor using Nmap (optional enhancement)
 * @param {string} ip - IP address to scan
 * @returns {Promise<{mac: string, vendor: string} | null>}
 */
async function getVendorFromNmap(ip) {
    try {
        // OPTIMIZED Nmap for FAST vendor detection
        // -sn: Ping scan (no port scan for speed)
        // -n: No DNS resolution (MUCH faster)
        // -T4: Aggressive timing (faster)
        // --max-retries 1: Only retry once (faster)
        // Combined: 10x faster than default
        const { stdout } = await execAsync(`nmap -sn -n -T4 --max-retries 1 ${ip}`, {
            timeout: 2000,  // Reduced from 5000ms to 2000ms
            encoding: 'utf8',
            windowsHide: true
        });

        // Parse Nmap output for MAC address and vendor
        // Example: "MAC Address: AA:BB:CC:DD:EE:FF (Espressif Inc.)"
        const macMatch = stdout.match(/MAC Address: ([0-9A-F:]{17})\s+\((.+?)\)/i);

        if (macMatch) {
            const mac = macMatch[1];
            const vendor = macMatch[2].trim();

            logger.info(`[Nmap] Found vendor for ${ip}: ${vendor}`);
            return { mac, vendor };
        }

        logger.debug(`[Nmap] No MAC/vendor found for ${ip}`);
        return null;

    } catch (error) {
        // Graceful fallback - Nmap not available or command failed
        if (error.code === 'ENOENT') {
            logger.debug('[Nmap] Not installed, using existing vendor data');
        } else {
            logger.debug(`[Nmap] Lookup failed for ${ip}: ${error.message}`);
        }
        return null;
    }
}

/**
 * Identify device role based on network position and characteristics
 * @param {object} deviceData - {ip, openPorts, vendor, deviceType}
 * @returns {'Main' | 'Secondary' | 'Unknown'}
 */
function identifyDeviceRole(deviceData) {
    const { ip, openPorts = [], vendor = '', deviceType = '' } = deviceData;

    // Main device indicators:
    // 1. Gateway IP (usually .1, .254)
    const ipParts = ip.split('.');
    const lastOctet = parseInt(ipParts[3]);
    if (lastOctet === 1 || lastOctet === 254) {
        return 'Main';
    }

    // 2. Router/Gateway vendor with router type
    const routerVendors = /tp-?link|d-?link|netgear|linksys|asus.*router|cisco|ubiquiti|mikrotik|aruba/i;
    if (routerVendors.test(vendor) && deviceType === 'router') {
        return 'Main';
    }

    // 3. Has router/gateway ports (53=DNS, 67=DHCP)
    const hasRouterPorts = openPorts.includes(53) || openPorts.includes(67);
    if (hasRouterPorts) {
        return 'Main';
    }

    // 4. Access Point indicators
    if (deviceType === 'router' || /access.*point|unifi|aruba/i.test(vendor)) {
        return 'Main';
    }

    return 'Secondary';
}

/**
 * Identify specific IoT device type based on vendor and device characteristics
 * @param {string} vendor - Device vendor
 * @param {string} deviceType - Generic device type
 * @param {array} openPorts - Open ports
 * @returns {string} Specific IoT type or null for non-IoT
 */
function identifyIoTDeviceType(vendor, deviceType, openPorts = []) {
    const vendorLower = (vendor || '').toLowerCase();
    const typeLower = (deviceType || '').toLowerCase();

    // === CAMERAS ===
    if (typeLower.includes('camera') ||
        /hikvision|dahua|axis|ring.*cam|arlo|wyze|nest.*cam|amcrest|lorex|swann/i.test(vendorLower)) {
        return 'CCTV Camera';
    }

    // === ESP32/ESP8266 IoT Devices ===
    if (/espressif|esp32|esp8266/i.test(vendorLower)) {
        return 'ESP32/ESP8266 IoT Device';
    }

    // === SMART PLUGS ===
    if (typeLower.includes('plug') || /kasa|wemo|tuya|shelly|sonoff/i.test(vendorLower)) {
        return 'Smart Plug';
    }

    // === ROUTERS ===
    if (typeLower === 'router' || deviceType === 'router' || /shenzhen.*zero|zeroone/i.test(vendorLower)) {
        return 'Wi-Fi Router';
    }

    // === THIN CLIENTS / TERMINALS ===
    if (/ncomputing|wyse/i.test(vendorLower) || typeLower.includes('thin')) {
        return 'Thin Client Terminal';
    }

    // === DIGITAL SIGNAGE / MEDIA PLAYERS ===
    if (/changyang/i.test(vendorLower) || typeLower.includes('signage')) {
        return 'Digital Signage / Media Player';
    }

    // === SMART POWER / COMPONENTS ===
    if (/liteon|lite-?on/i.test(vendorLower)) {
        return 'Smart Power Component';
    }

    // === SMART TVs ===
    if (typeLower.includes('tv') || typeLower.includes('smart_tv') ||
        /samsung.*smart|lg.*webos|roku|fire.*tv|apple.*tv/i.test(vendorLower)) {
        return 'Smart TV';
    }

    // === SMART SPEAKERS / VOICE ASSISTANTS ===
    if (typeLower.includes('speaker') || typeLower.includes('assistant') ||
        typeLower.includes('voice_assistant') ||
        /sonos|echo|alexa|google.*home|google.*nest/i.test(vendorLower)) {
        return 'Smart Speaker';
    }

    // === THERMOSTATS ===
    if (typeLower.includes('thermostat') || /nest.*therm|ecobee|honeywell/i.test(vendorLower)) {
        return 'Smart Thermostat';
    }

    // === DOORBELLS ===
    if (typeLower.includes('doorbell') || /ring.*doorbell|nest.*doorbell/i.test(vendorLower)) {
        return 'Smart Doorbell';
    }

    // === SENSORS ===
    if (typeLower.includes('sensor')) {
        return 'IoT Sensor';
    }

    // === WEARABLES ===
    if (typeLower.includes('wearable') || /fitbit|apple.*watch/i.test(vendorLower)) {
        return 'Wearable Device';
    }

    // === ACCESS POINTS ===
    if (typeLower.includes('access') || /unifi|aruba.*ap/i.test(vendorLower)) {
        return 'Wi-Fi Access Point';
    }

    // === NAS / STORAGE ===
    if (typeLower === 'nas' || /synology|qnap/i.test(vendorLower)) {
        return 'Network Storage (NAS)';
    }

    // === PRINTERS === (Only if actually a printer, not just HP/Canon vendor)
    if (typeLower === 'printer' || typeLower.includes('print') || openPorts.includes(9100) || openPorts.includes(631)) {
        // Confirm it's actually a printer by checking vendor OR type OR ports
        if (/hp|canon|epson|brother|xerox|lexmark/i.test(vendorLower) || typeLower.includes('print')) {
            return 'Network Printer';
        }
    }

    // === SMART LIGHTS ===
    if (typeLower.includes('light') || /philips.*hue|lifx|sengled/i.test(vendorLower)) {
        return 'Smart Light';
    }

    // === SMART LOCKS ===
    if (typeLower.includes('lock') || /august|yale.*smart/i.test(vendorLower)) {
        return 'Smart Lock';
    }

    // === MEDIA PLAYERS ===
    if (typeLower.includes('media_player') || /chromecast/i.test(vendorLower)) {
        return 'Media Streaming Device';
    }

    // === RASPBERRY PI / ARDUINO ===
    if (/raspberry.*pi/i.test(vendorLower)) {
        return 'Raspberry Pi';
    }
    if (/arduino/i.test(vendorLower)) {
        return 'Arduino Device';
    }

    // Generic fallback - add IoT prefix to device type
    if (deviceType && deviceType !== 'unknown' && deviceType !== 'iot_device') {
        return `IoT ${deviceType.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}`;
    }

    return 'Unknown IoT Device';
}

/**
 * Classify device with optional Nmap enhancement
 * Non-intrusive: falls back to existing vendor if Nmap unavailable
 * 
 * @param {string} ip - IP address
 * @param {string} existingVendor - Current vendor from MAC lookup
 * @param {string} deviceType - Device type from scanner
 * @param {object} deviceData - Additional device data {openPorts, etc}
 * @returns {Promise<{category: string, vendor: string, device_role: string, iot_device_type: string|null}>}
 */
async function classifyDevice(ip, existingVendor, deviceType = null, deviceData = {}) {
    let vendor = existingVendor || 'Unknown';
    let nmapEnhanced = false;

    // Optional: Try Nmap for potentially better vendor data
    // This is completely optional - if it fails, we use existing data
    try {
        const nmapResult = await getVendorFromNmap(ip);
        if (nmapResult?.vendor) {
            vendor = nmapResult.vendor;
            nmapEnhanced = true;
            logger.info(`[Classification] Using Nmap vendor for ${ip}: ${vendor}`);
        }
    } catch (err) {
        // Silent fallback to existing vendor
        logger.debug(`[Classification] Nmap failed for ${ip}, using existing vendor`);
    }

    // Classify based on vendor (works with both Nmap and existing data)
    const category = classifyVendor(vendor);

    // Identify device role (Main/Secondary)
    const role = identifyDeviceRole({
        ip,
        openPorts: deviceData.openPorts || [],
        vendor,
        deviceType
    });

    // Identify specific IoT type (only for IoT devices)
    const iotType = category === 'IoT'
        ? identifyIoTDeviceType(vendor, deviceType, deviceData.openPorts || [])
        : null;

    logger.info(`[Classification] ${ip}: ${category}, Role: ${role}, IoT Type: ${iotType || 'N/A'}`);

    return {
        category,
        vendor,
        nmapEnhanced,
        device_role: role,
        iot_device_type: iotType
    };
}

module.exports = {
    classifyDevice,
    classifyVendor,
    getVendorFromNmap,
    identifyDeviceRole,
    identifyIoTDeviceType,
    IOT_PATTERNS,
    NORMAL_PATTERNS
};
