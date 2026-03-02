const express = require('express');
const { getDatabase } = require('../database/init');
const { authenticate } = require('../middleware/auth');
const logger = require('../utils/logger');

const { getNetworkTraffic } = require('../services/realNetworkScanner');

const router = express.Router();

// ... existing routes ...

// Get network topology
router.get('/topology', authenticate, (req, res) => {
  try {
    const db = getDatabase();

    // Get all devices
    const devices = db.prepare(`
      SELECT id, name, ip, mac, device_type, manufacturer, status, risk_level, risk_score
      FROM devices
    `).all();

    // Build topology nodes
    const nodes = devices.map(device => ({
      id: device.id,
      type: 'device',
      data: {
        label: device.name,
        ip: device.ip,
        mac: device.mac,
        deviceType: device.device_type,
        manufacturer: device.manufacturer,
        status: device.status,
        riskLevel: device.risk_level,
        riskScore: device.risk_score
      },
      position: calculateNodePosition(device, devices.indexOf(device), devices.length)
    }));

    // Add gateway/router as central node
    const gateway = {
      id: 'gateway',
      type: 'gateway',
      data: {
        label: 'Network Gateway',
        ip: '192.168.1.1',
        deviceType: 'router',
        status: 'online'
      },
      position: { x: 400, y: 300 }
    };
    nodes.unshift(gateway);

    // Build edges (connections)
    const edges = devices.map(device => ({
      id: `edge-${device.id}`,
      source: 'gateway',
      target: device.id,
      animated: device.status === 'online',
      style: {
        stroke: getEdgeColor(device.risk_level)
      }
    }));

    res.json({ nodes, edges });
  } catch (error) {
    logger.error('Get topology error:', error);
    res.status(500).json({ error: 'Failed to fetch network topology' });
  }
});

// Get network traffic data
router.get('/traffic', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { limit = 100 } = req.query;

    // Get recent packet captures
    const packets = db.prepare(`
      SELECT * FROM packet_captures
      ORDER BY timestamp DESC
      LIMIT ?
    `).all(parseInt(limit));

    // Calculate traffic statistics
    const stats = calculateTrafficStats(packets);

    res.json({
      packets,
      stats
    });
  } catch (error) {
    logger.error('Get traffic error:', error);
    res.status(500).json({ error: 'Failed to fetch network traffic' });
  }
});

// Get port statistics across network
router.get('/ports', authenticate, (req, res) => {
  try {
    const db = getDatabase();

    const portStats = db.prepare(`
      SELECT 
        port_number,
        service_name,
        COUNT(*) as device_count,
        SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open_count
      FROM ports
      GROUP BY port_number, service_name
      ORDER BY device_count DESC
    `).all();

    const totalPorts = db.prepare('SELECT COUNT(*) as count FROM ports').get().count;
    const openPorts = db.prepare("SELECT COUNT(*) as count FROM ports WHERE status = 'open'").get().count;

    res.json({
      portStats,
      summary: {
        total: totalPorts,
        open: openPorts,
        closed: totalPorts - openPorts
      }
    });
  } catch (error) {
    logger.error('Get port stats error:', error);
    res.status(500).json({ error: 'Failed to fetch port statistics' });
  }
});

// Get device connections
router.get('/connections', authenticate, (req, res) => {
  try {
    const db = getDatabase();

    // Get devices with their connection information
    const devices = db.prepare(`
      SELECT d.*, 
        (SELECT COUNT(*) FROM ports WHERE device_id = d.id AND status = 'open') as open_ports,
        (SELECT COUNT(*) FROM vulnerabilities WHERE device_id = d.id AND status = 'open') as open_vulns
      FROM devices d
      WHERE d.status = 'online'
    `).all();

    const connections = devices.map(device => ({
      deviceId: device.id,
      deviceName: device.name,
      ip: device.ip,
      mac: device.mac,
      openPorts: device.open_ports,
      openVulnerabilities: device.open_vulns,
      lastSeen: device.last_seen,
      connectionQuality: calculateConnectionQuality(device)
    }));

    res.json(connections);
  } catch (error) {
    logger.error('Get connections error:', error);
    res.status(500).json({ error: 'Failed to fetch device connections' });
  }
});

// Get network segments/subnets
router.get('/segments', authenticate, (req, res) => {
  try {
    const db = getDatabase();

    const devices = db.prepare('SELECT * FROM devices').all();

    // Group devices by subnet
    const segments = {};
    for (const device of devices) {
      if (device.ip) {
        const subnet = device.ip.split('.').slice(0, 3).join('.') + '.0/24';
        if (!segments[subnet]) {
          segments[subnet] = {
            subnet,
            devices: [],
            deviceCount: 0,
            onlineCount: 0,
            riskStats: { critical: 0, high: 0, medium: 0, low: 0, safe: 0 }
          };
        }
        segments[subnet].devices.push(device);
        segments[subnet].deviceCount++;
        if (device.status === 'online') segments[subnet].onlineCount++;
        if (device.risk_level) {
          segments[subnet].riskStats[device.risk_level]++;
        }
      }
    }

    res.json(Object.values(segments));
  } catch (error) {
    logger.error('Get segments error:', error);
    res.status(500).json({ error: 'Failed to fetch network segments' });
  }
});

// Get real real-time network traffic
router.get('/bandwidth', authenticate, async (req, res) => {
  try {
    const stats = await getNetworkTraffic();
    const db = getDatabase();
    // Get active connection count for context
    const activeCount = db.prepare("SELECT COUNT(*) as count FROM devices WHERE status = 'online'").get().count;

    res.json({
      devices: [], // Per-device traffic requires packet inspection driver
      summary: {
        totalDownload: (stats.received / 1024 / 1024).toFixed(2), // MB
        totalUpload: (stats.sent / 1024 / 1024).toFixed(2), // MB
        activeConnections: activeCount
      }
    });
  } catch (error) {
    logger.error('Get bandwidth error:', error);
    res.status(500).json({ error: 'Failed to fetch bandwidth data' });
  }
});

// Helper function to calculate node position in circular layout
function calculateNodePosition(device, index, total) {
  const radius = 250;
  const centerX = 400;
  const centerY = 300;
  const angle = (2 * Math.PI * index) / total;

  return {
    x: centerX + radius * Math.cos(angle),
    y: centerY + radius * Math.sin(angle)
  };
}

// Helper function to get edge color based on risk level
function getEdgeColor(riskLevel) {
  const colors = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#22c55e',
    safe: '#22c55e'
  };
  return colors[riskLevel] || '#6b7280';
}

// Helper function to calculate traffic statistics
function calculateTrafficStats(packets) {
  const stats = {
    totalPackets: packets.length,
    byProtocol: {},
    byDirection: { inbound: 0, outbound: 0, internal: 0 },
    avgPacketSize: 0,
    topSources: {},
    topDestinations: {}
  };

  let totalSize = 0;

  for (const packet of packets) {
    // Count by protocol
    if (!stats.byProtocol[packet.protocol]) {
      stats.byProtocol[packet.protocol] = 0;
    }
    stats.byProtocol[packet.protocol]++;

    // Count by direction
    if (packet.direction && stats.byDirection[packet.direction] !== undefined) {
      stats.byDirection[packet.direction]++;
    }

    // Track size
    totalSize += packet.size || 0;

    // Track sources
    if (packet.source_ip) {
      stats.topSources[packet.source_ip] = (stats.topSources[packet.source_ip] || 0) + 1;
    }

    // Track destinations
    if (packet.destination_ip) {
      stats.topDestinations[packet.destination_ip] = (stats.topDestinations[packet.destination_ip] || 0) + 1;
    }
  }

  stats.avgPacketSize = packets.length > 0 ? Math.round(totalSize / packets.length) : 0;

  // Sort and limit top sources/destinations
  stats.topSources = Object.entries(stats.topSources)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .reduce((obj, [k, v]) => ({ ...obj, [k]: v }), {});

  stats.topDestinations = Object.entries(stats.topDestinations)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .reduce((obj, [k, v]) => ({ ...obj, [k]: v }), {});

  return stats;
}


// Helper to calculate node position in a circle around gateway
function calculateNodePosition(device, index, total) {
  const centerX = 400;
  const centerY = 300;
  const radius = 250;
  const angle = (index / total) * 2 * Math.PI;

  return {
    x: centerX + radius * Math.cos(angle),
    y: centerY + radius * Math.sin(angle)
  };
}

// Helper to get edge color based on risk
function getEdgeColor(riskLevel) {
  switch (riskLevel) {
    case 'critical': return '#ef4444'; // red-500
    case 'high': return '#f97316'; // orange-500
    case 'medium': return '#eab308'; // yellow-500
    case 'low': return '#22c55e'; // green-500
    default: return '#3b82f6'; // blue-500
  }
}

// Helper function to calculate connection quality
function calculateConnectionQuality(device) {
  // Simple heuristic based on risk and status
  if (device.status !== 'online') return 'offline';
  if (device.risk_level === 'critical' || device.risk_level === 'high') return 'poor';
  if (device.risk_level === 'medium') return 'fair';
  return 'good';
}

module.exports = router;
