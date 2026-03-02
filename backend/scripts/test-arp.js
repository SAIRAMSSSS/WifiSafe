const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

async function testArpScan() {
    console.log('=== Testing ARP Scan ===');

    try {
        const { stdout } = await execAsync('arp -a', { encoding: 'utf8' });

        console.log('=== Sample ARP lines (first 30) ===');
        const lines = stdout.split('\n');
        for (let i = 0; i < Math.min(lines.length, 30); i++) {
            const line = lines[i];
            // Check if line has IP address
            if (line.match(/\d+\.\d+\.\d+\.\d+/)) {
                console.log(`Line ${i}: "${line}"`);
                console.log(`  Chars: ${line.split('').map(c => c.charCodeAt(0)).slice(0, 20).join(',')}`);
            }
        }

        console.log('\n=== Parsing with original regex ===');
        const devices = [];

        for (const line of lines) {
            // Original regex - expects: IP  MAC  type
            const match = line.match(/(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)/);
            if (match) {
                const ip = match[1];
                const mac = match[2].replace(/-/g, ':').toUpperCase();
                const type = match[3];
                console.log(`FOUND: ${ip} | ${mac} | ${type}`);
                devices.push({ ip, mac, type });
            }
        }

        console.log(`\nTotal devices found: ${devices.length}`);

        // Show sample of non-matching lines with IPs
        if (devices.length < 5) {
            console.log('\n=== Lines with IPs that did NOT match ===');
            let count = 0;
            for (const line of lines) {
                if (line.match(/\d+\.\d+\.\d+\.\d+/) && !line.match(/(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)/)) {
                    console.log(`  "${line.trim()}"`);
                    if (count++ > 10) break;
                }
            }
        }

    } catch (error) {
        console.error('Error:', error.message);
    }
}

testArpScan();
