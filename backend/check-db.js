const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

async function checkDatabase() {
    const dbPath = path.join(__dirname, 'data', 'codex.db');

    if (!fs.existsSync(dbPath)) {
        console.log('❌ No database found');
        return;
    }

    const SQL = await initSqlJs();
    const fileBuffer = fs.readFileSync(dbPath);
    const db = new SQL.Database(fileBuffer);

    // Check if the new fields exist
    const tableInfo = db.exec("PRAGMA table_info(devices)");
    console.log('\n📋 Devices Table Columns:');
    if (tableInfo.length > 0) {
        tableInfo[0].values.forEach((col) => {
            const [cid, name, type, notnull, dflt_value, pk] = col;
            if (name.includes('category') || name.includes('role') || name.includes('iot') || name.includes('vendor')) {
                console.log(`   ✅ ${name}: ${type} (default: ${dflt_value})`);
            }
        });
    }

    // Count IoT devices
    const iotCount = db.exec("SELECT COUNT(*) as count FROM devices WHERE device_category = 'IoT'");
    const total = db.exec("SELECT COUNT(*) as count FROM devices");

    console.log(`\n📊 Device Classification:`);
    console.log(`   Total devices: ${total[0]?.values[0][0] || 0}`);
    console.log(`   IoT devices: ${iotCount[0]?.values[0][0] || 0}`);

    // Show sample IoT devices
    const iotDevices = db.exec(`
        SELECT ip, manufacturer, device_category, device_role, iot_device_type 
        FROM devices 
        WHERE device_category = 'IoT' 
        LIMIT 10
    `);

    if (iotDevices.length > 0 && iotDevices[0].values.length > 0) {
        console.log(`\n🔴 Sample IoT Devices:`);
        iotDevices[0].values.forEach((row, i) => {
            const [ip, vendor, category, role, iotType] = row;
            console.log(`   ${i + 1}. ${ip} - ${iotType} (${vendor})`);
        });
    } else {
        console.log(`\n⚠️ No devices with device_category='IoT' found!`);
        console.log(`   This means the reclassification didn't work or database wasn't saved.\n`);
    }

    db.close();
}

checkDatabase().catch(console.error);
