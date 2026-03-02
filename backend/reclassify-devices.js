/**
 * Reclassify existing devices with new IoT patterns
 * Run this ONCE to update old data without full rescan
 */

const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');
const { classifyVendor, identifyIoTDeviceType } = require('./src/services/nmapVendorClassifier');

async function reclassifyDevices() {
    const dbPath = path.join(__dirname, 'data', 'codex.db');

    if (!fs.existsSync(dbPath)) {
        console.log('❌ No database found.');
        return;
    }

    console.log('🔄 Reclassifying existing devices...\n');

    const SQL = await initSqlJs();
    const fileBuffer = fs.readFileSync(dbPath);
    const db = new SQL.Database(fileBuffer);

    // Get all devices
    const devicesResult = db.exec('SELECT id, ip, manufacturer, device_type, open_ports FROM devices');

    if (!devicesResult.length || !devicesResult[0].values.length) {
        console.log('No devices found in database.');
        db.close();
        return;
    }

    let updated = 0;
    let iotCount = 0;

    devicesResult[0].values.forEach((row) => {
        const [id, ip, manufacturer, deviceType, openPortsJson] = row;
        const vendor = manufacturer || 'Unknown';

        // Parse open ports
        let openPorts = [];
        try {
            if (openPortsJson) {
                const parsed = JSON.parse(openPortsJson);
                openPorts = Array.isArray(parsed) ? parsed.map(p => p.port || p) : [];
            }
        } catch (e) {
            // Ignore parse errors
        }

        // Classify using new patterns
        const category = classifyVendor(vendor);
        const iotType = category === 'IoT'
            ? identifyIoTDeviceType(vendor, deviceType, openPorts)
            : 'Unknown';

        // Update device
        db.run(
            'UPDATE devices SET device_category = ?, iot_device_type = ? WHERE id = ?',
            [category, iotType || 'Unknown', id]
        );

        updated++;
        if (category === 'IoT') {
            iotCount++;
            console.log(`✅ ${ip} → IoT: ${iotType} (${vendor})`);
        }
    });

    // Save database to disk - CRITICAL!
    try {
        const data = db.export();
        const buffer = Buffer.from(data);
        fs.writeFileSync(dbPath, buffer);
        console.log('💾 Database saved to disk successfully');
    } catch (saveErr) {
        console.error('❌ Failed to save database:', saveErr.message);
        db.close();
        return;
    }

    db.close();

    console.log(`\n📊 Summary:`);
    console.log(`   Total devices updated: ${updated}`);
    console.log(`   IoT devices found: ${iotCount}`);
    console.log(`\n✅ Database updated! Refresh your browser.\n`);
}

reclassifyDevices().catch(console.error);
