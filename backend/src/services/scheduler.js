const cron = require('node-cron');
const { getDatabase } = require('../database/init');
const logger = require('../utils/logger');
const { emit } = require('../websocket/server');

let scheduledTasks = [];

function startScheduledTasks() {
  // Check for auto-release quarantined devices every 5 minutes
  const quarantineCheck = cron.schedule('*/5 * * * *', () => {
    checkQuarantineReleases();
  });
  scheduledTasks.push(quarantineCheck);

  // Clean up old packet captures every hour
  const packetCleanup = cron.schedule('0 * * * *', () => {
    cleanOldPacketCaptures();
  });
  scheduledTasks.push(packetCleanup);

  // Update device online status every 2 minutes
  const deviceStatusCheck = cron.schedule('*/2 * * * *', () => {
    checkDeviceStatus();
  });
  scheduledTasks.push(deviceStatusCheck);

  // Incremental ping sweep every X minutes (default: 1 min)
  const incrementalSweep = cron.schedule('*/1 * * * *', async () => {
    try {
      const { refreshDevices, scanDevicePorts, grabBanner } = require('./realNetworkScanner');
      const result = await refreshDevices();
      if (result.newDevices > 0) {
        const { emit } = require('../websocket/server');
        const db = require('../database/init').getDatabase();
        const now = new Date().toISOString();
        // Get new devices discovered in the last minute
        const newDevices = db.prepare('SELECT * FROM devices WHERE discovered_at >= ?').all(now.slice(0, 16));
        for (const device of newDevices) {
          emit.newDevice({
            ip: device.ip,
            mac: device.mac,
            name: device.name,
            vendor: device.manufacturer,
            type: device.device_type,
            discovered_at: device.discovered_at
          });
          // Automatic light port scan
          const ports = [22, 23, 80, 443, 554, 1883, 8080, 8443, 9100];
          const openPorts = await scanDevicePorts(device.ip, ports);
          for (const portInfo of openPorts) {
            let banner = null;
            if ([80, 443, 8080, 8443].includes(portInfo.port)) {
              try {
                banner = await grabBanner(device.ip, portInfo.port);
              } catch { }
            }
            emit.portOpen({
              ip: device.ip,
              port: portInfo.port,
              service: portInfo.service,
              banner
            });
          }
        }
      }
    } catch (err) {
      logger.error('Incremental sweep error:', err);
    }
  });
  scheduledTasks.push(incrementalSweep);

  // Generate daily security digest at 8 AM
  const dailyDigest = cron.schedule('0 8 * * *', () => {
    generateDailyDigest();
  });
  scheduledTasks.push(dailyDigest);

  // Clean up old audit logs monthly
  const auditCleanup = cron.schedule('0 0 1 * *', () => {
    cleanOldAuditLogs();
  });
  scheduledTasks.push(auditCleanup);

  // Update threat intelligence every 6 hours
  const threatUpdate = cron.schedule('0 */6 * * *', async () => {
    try {
      const { fetchRecentThreats, fetchCISAExploits } = require('./threatFeed');
      logger.info('Starting scheduled threat feed update...');
      await fetchRecentThreats();
      await fetchCISAExploits();
    } catch (err) {
      logger.error('Threat feed update error:', err);
    }
  });
  scheduledTasks.push(threatUpdate);

  // Run immediately on startup (async)
  setTimeout(async () => {
    try {
      const { fetchRecentThreats, fetchCISAExploits } = require('./threatFeed');
      logger.info('Performing startup threat feed update...');
      await fetchRecentThreats();
      await fetchCISAExploits();
    } catch (err) {
      logger.error('Startup threat feed update error:', err);
    }
  }, 10000);

  logger.info('Scheduled tasks started');
}

function stopScheduledTasks() {
  scheduledTasks.forEach(task => task.stop());
  scheduledTasks = [];
  logger.info('Scheduled tasks stopped');
}

// Check and auto-release quarantined devices
function checkQuarantineReleases() {
  try {
    const db = getDatabase();
    const now = new Date().toISOString();

    const devicesToRelease = db.prepare(`
      SELECT * FROM devices 
      WHERE status = 'quarantined' 
      AND quarantine_release_at IS NOT NULL 
      AND quarantine_release_at <= ?
    `).all(now);

    for (const device of devicesToRelease) {
      const newStatus = device.previous_status || 'online';

      db.prepare(`
        UPDATE devices SET 
          status = ?,
          quarantined_at = NULL,
          quarantine_reason = NULL,
          quarantine_release_at = NULL,
          previous_status = NULL,
          updated_at = ?
        WHERE id = ?
      `).run(newStatus, now, device.id);

      logger.info(`Auto-released device ${device.name} from quarantine`);

      // Emit WebSocket event
      emit.deviceUpdated({
        ...device,
        status: newStatus
      });
    }

    if (devicesToRelease.length > 0) {
      logger.info(`Auto-released ${devicesToRelease.length} devices from quarantine`);
    }
  } catch (error) {
    logger.error('Quarantine release check error:', error);
  }
}

// Clean up old packet captures (older than 24 hours)
function cleanOldPacketCaptures() {
  try {
    const db = getDatabase();
    const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

    const result = db.prepare(`
      DELETE FROM packet_captures WHERE timestamp < ?
    `).run(cutoff);

    if (result.changes > 0) {
      logger.info(`Cleaned up ${result.changes} old packet captures`);
    }
  } catch (error) {
    logger.error('Packet cleanup error:', error);
  }
}

// Check device status (mark devices as offline if not seen recently)
function checkDeviceStatus() {
  try {
    const db = getDatabase();
    const cutoff = new Date(Date.now() - 10 * 60 * 1000).toISOString(); // 10 minutes
    const now = new Date().toISOString();

    const offlineDevices = db.prepare(`
      SELECT * FROM devices 
      WHERE status = 'online' AND last_seen < ?
    `).all(cutoff);

    for (const device of offlineDevices) {
      db.prepare(`
        UPDATE devices SET status = 'offline', updated_at = ?
        WHERE id = ?
      `).run(now, device.id);

      // Create alert
      db.prepare(`
        INSERT INTO alerts (id, device_id, device_ip, type, severity, message, created_at)
        VALUES (?, ?, ?, 'connectivity', 'medium', ?, ?)
      `).run(
        require('uuid').v4(),
        device.id,
        device.ip,
        `Device Offline: ${device.name} (${device.ip}) has not been seen since ${device.last_seen}`,
        now
      );

      emit.deviceOffline(device);
    }

    if (offlineDevices.length > 0) {
      logger.info(`Marked ${offlineDevices.length} devices as offline`);
    }
  } catch (error) {
    logger.error('Device status check error:', error);
  }
}

// Generate daily security digest
function generateDailyDigest() {
  try {
    const db = getDatabase();
    const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

    const stats = {
      newDevices: db.prepare(`
        SELECT COUNT(*) as count FROM devices WHERE discovered_at >= ?
      `).get(yesterday).count,

      newVulnerabilities: db.prepare(`
        SELECT COUNT(*) as count FROM vulnerabilities WHERE discovered_at >= ?
      `).get(yesterday).count,

      alertsCreated: db.prepare(`
        SELECT COUNT(*) as count FROM alerts WHERE created_at >= ?
      `).get(yesterday).count,

      scansCompleted: db.prepare(`
        SELECT COUNT(*) as count FROM scans WHERE started_at >= ? AND status = 'completed'
      `).get(yesterday).count,

      criticalAlerts: db.prepare(`
        SELECT COUNT(*) as count FROM alerts 
        WHERE created_at >= ? AND severity = 'critical' AND acknowledged = 0
      `).get(yesterday).count
    };

    logger.info('Daily security digest generated:', stats);

    // In production, this would send email notifications
    // For now, we just log it and emit to WebSocket
    emit.systemStatus({
      type: 'daily_digest',
      stats,
      generatedAt: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Daily digest generation error:', error);
  }
}

// Clean up old audit logs (older than 90 days)
function cleanOldAuditLogs() {
  try {
    const db = getDatabase();
    const cutoff = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();

    const result = db.prepare(`
      DELETE FROM audit_logs WHERE timestamp < ?
    `).run(cutoff);

    if (result.changes > 0) {
      logger.info(`Cleaned up ${result.changes} old audit logs`);
    }
  } catch (error) {
    logger.error('Audit log cleanup error:', error);
  }
}

module.exports = {
  startScheduledTasks,
  stopScheduledTasks,
  checkQuarantineReleases,
  cleanOldPacketCaptures,
  checkDeviceStatus,
  generateDailyDigest
};
