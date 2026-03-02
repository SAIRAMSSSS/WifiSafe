const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

async function checkIoTDevices() {
    const dbPath = path.join(__dirname, 'data', 'codex.db');

    if (!fs.existsSync(dbPath)) {
        console.log('❌ No database found. Run a scan first.');
        return;
    }

    const SQL = await initSqlJs();
    const fileBuffer = fs.readFileSync(dbPath);
    const db = new SQL.Database(fileBuffer);

    // Check total devices
    const totalResult = db.exec('SELECT COUNT(*) as count FROM devices');
    const total = totalResult[0]?.values[0][0] || 0;
    console.log(`\n📊 Total Devices in Database: ${total}\n`);

    // Check IoT devices with new classification
    const iotQuery = `
        SELECT ip, manufacturer, device_type, device_category, device_role, iot_device_type, risk_score
        FROM devices
        WHERE device_category = 'IoT'
        ORDER BY ip
    `;

    const iotResult = db.exec(iotQuery);

    if (iotResult.length > 0 && iotResult[0].values.length > 0) {
        console.log('🔴 IoT DEVICES DETECTED:\n');
        iotResult[0].values.forEach((row, index) => {
            const [ip, manufacturer, deviceType, category, role, iotType, riskScore] = row;
            console.log(`${index + 1}. IP: ${ip}`);
            console.log(`   Vendor: ${manufacturer || 'Unknown'}`);
            console.log(`   Type: ${iotType || deviceType || 'Unknown'}`);
            console.log(`   Role: ${role || 'Unknown'}`);
            console.log(`   Risk Score: ${riskScore || 0}`);
            console.log('');
        });
    } else {
        console.log('⚠️  No devices classified as IoT yet.\n');

        // Check if classification fields exist
        const checkFieldsQuery = `
            SELECT device_category, device_role, iot_device_type
            FROM devices
            LIMIT 1
        `;

        try {
            const fieldsResult = db.exec(checkFieldsQuery);
            console.log('✅ Classification fields exist in database.');
            console.log('💡 Run a new scan to classify devices as IoT/Normal.\n');
        } catch {
            console.log('❌ Classification fields missing - database needs migration.');
        }
    }

    db.close();
}

checkIoTDevices().catch(console.error);
