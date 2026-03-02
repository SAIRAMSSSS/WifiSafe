/**
 * Common risky ports and their threats
 */
const RISKY_PORTS = {
    21: { name: 'FTP', risk: 'high', threat: 'FTP allows unencrypted file transfer, credentials can be sniffed' },
    23: { name: 'Telnet', risk: 'critical', threat: 'Telnet transmits all data in plaintext including passwords' },
    135: { name: 'RPC', risk: 'high', threat: 'Windows RPC can be exploited for remote code execution' },
    139: { name: 'NetBIOS', risk: 'high', threat: 'NetBIOS can leak sensitive system information' },
    445: { name: 'SMB', risk: 'critical', threat: 'SMB vulnerabilities have been used in major ransomware attacks' },
    3389: { name: 'RDP', risk: 'critical', threat: 'RDP is frequently targeted by brute-force and exploit attacks' },
    7547: { name: 'TR-069', risk: 'critical', threat: 'TR-069 CWMP protocol has severe vulnerabilities in IoT devices' },
    1883: { name: 'MQTT', risk: 'medium', threat: 'Unencrypted MQTT can leak IoT device data' },
    554: { name: 'RTSP', risk: 'medium', threat: 'RTSP streams may be accessed without authentication' },
    37777: { name: 'Dahua', risk: 'high', threat: 'Dahua proprietary protocol, often has default credentials' },
    34567: { name: 'DVR', risk: 'high', threat: 'DVR admin port commonly targeted by botnets' }
};

module.exports = { RISKY_PORTS };
