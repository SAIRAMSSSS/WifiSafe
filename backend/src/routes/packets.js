const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { getDatabase } = require('../database/init');
const { authenticate } = require('../middleware/auth');
const logger = require('../utils/logger');

const router = express.Router();

// Get packet captures
router.get('/', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const {
      protocol,
      source_ip,
      destination_ip,
      source_port,
      destination_port,
      direction,
      limit = 100,
      offset = 0
    } = req.query;

    let query = 'SELECT * FROM packet_captures WHERE 1=1';
    const params = [];

    if (protocol) {
      query += ' AND protocol = ?';
      params.push(protocol.toUpperCase());
    }

    if (source_ip) {
      query += ' AND source_ip = ?';
      params.push(source_ip);
    }

    if (destination_ip) {
      query += ' AND destination_ip = ?';
      params.push(destination_ip);
    }

    if (source_port) {
      query += ' AND source_port = ?';
      params.push(parseInt(source_port));
    }

    if (destination_port) {
      query += ' AND destination_port = ?';
      params.push(parseInt(destination_port));
    }

    if (direction) {
      query += ' AND direction = ?';
      params.push(direction);
    }

    query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));

    const packets = db.prepare(query).all(...params);

    res.json(packets);
  } catch (error) {
    logger.error('Get packets error:', error);
    res.status(500).json({ error: 'Failed to fetch packet captures' });
  }
});

// Get packet by ID
router.get('/:id', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const packet = db.prepare('SELECT * FROM packet_captures WHERE id = ?').get(req.params.id);

    if (!packet) {
      return res.status(404).json({ error: 'Packet not found' });
    }

    res.json(packet);
  } catch (error) {
    logger.error('Get packet error:', error);
    res.status(500).json({ error: 'Failed to fetch packet' });
  }
});

// Get packet statistics
router.get('/stats/summary', authenticate, (req, res) => {
  try {
    const db = getDatabase();

    const total = db.prepare('SELECT COUNT(*) as count FROM packet_captures').get().count;

    const byProtocol = db.prepare(`
      SELECT protocol, COUNT(*) as count 
      FROM packet_captures 
      GROUP BY protocol
      ORDER BY count DESC
    `).all();

    const byDirection = db.prepare(`
      SELECT direction, COUNT(*) as count 
      FROM packet_captures 
      GROUP BY direction
    `).all();

    const topSources = db.prepare(`
      SELECT source_ip, COUNT(*) as count 
      FROM packet_captures 
      GROUP BY source_ip
      ORDER BY count DESC
      LIMIT 10
    `).all();

    const topDestinations = db.prepare(`
      SELECT destination_ip, COUNT(*) as count 
      FROM packet_captures 
      GROUP BY destination_ip
      ORDER BY count DESC
      LIMIT 10
    `).all();

    const topPorts = db.prepare(`
      SELECT destination_port as port, COUNT(*) as count 
      FROM packet_captures 
      WHERE destination_port IS NOT NULL
      GROUP BY destination_port
      ORDER BY count DESC
      LIMIT 10
    `).all();

    const avgPacketSize = db.prepare(`
      SELECT AVG(size) as avg_size FROM packet_captures
    `).get()?.avg_size || 0;

    const recentActivity = db.prepare(`
      SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
      FROM packet_captures
      WHERE timestamp >= datetime('now', '-24 hours')
      GROUP BY strftime('%H', timestamp)
      ORDER BY hour
    `).all();

    res.json({
      total,
      byProtocol,
      byDirection,
      topSources,
      topDestinations,
      topPorts,
      avgPacketSize: Math.round(avgPacketSize),
      recentActivity
    });
  } catch (error) {
    logger.error('Get packet stats error:', error);
    res.status(500).json({ error: 'Failed to fetch packet statistics' });
  }
});

// Start packet capture (Real capture requires native drivers)
router.post('/capture/start', authenticate, (req, res) => {
  try {
    // Real packet capture requires 'cap' or 'pcap' libraries and system drivers (e.g. Npcap on Windows).
    // Since we cannot guarantee these are installed, and we are strictly avoiding simulated data,
    // we return a clear message.

    return res.status(501).json({
      error: 'Real-time packet capture requires Npcap driver installation',
      message: 'This feature requires low-level system drivers (Npcap/libpcap) to capture raw packets. Simulated data has been disabled as per request.'
    });

  } catch (error) {
    logger.error('Start capture error:', error);
    res.status(500).json({ error: 'Failed to start packet capture' });
  }
});

// Stop packet capture
router.post('/capture/stop/:id', authenticate, (req, res) => {
  res.status(501).json({ error: 'Packet capture not active' });
});

// Get live packet stream (WebSocket endpoint info)
router.get('/stream/info', authenticate, (req, res) => {
  res.json({
    websocketUrl: `ws://${req.headers.host}/ws/packets`,
    message: 'Connect to WebSocket for live packet stream'
  });
});

// Clear packet history
router.delete('/history', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const { before } = req.query;

    if (before) {
      db.prepare('DELETE FROM packet_captures WHERE timestamp < ?').run(before);
    } else {
      db.prepare('DELETE FROM packet_captures').run();
    }

    res.json({ message: 'Packet history cleared' });
  } catch (error) {
    logger.error('Clear history error:', error);
    res.status(500).json({ error: 'Failed to clear packet history' });
  }
});

// Search packets
router.post('/search', authenticate, (req, res) => {
  try {
    const db = getDatabase();
    const {
      protocols,
      ipAddresses,
      ports,
      dateRange,
      minSize,
      maxSize
    } = req.body;

    let query = 'SELECT * FROM packet_captures WHERE 1=1';
    const params = [];

    if (protocols && protocols.length > 0) {
      query += ` AND protocol IN (${protocols.map(() => '?').join(',')})`;
      params.push(...protocols);
    }

    if (ipAddresses && ipAddresses.length > 0) {
      const ipConditions = ipAddresses.map(() => '(source_ip = ? OR destination_ip = ?)').join(' OR ');
      query += ` AND (${ipConditions})`;
      for (const ip of ipAddresses) {
        params.push(ip, ip);
      }
    }

    if (ports && ports.length > 0) {
      const portConditions = ports.map(() => '(source_port = ? OR destination_port = ?)').join(' OR ');
      query += ` AND (${portConditions})`;
      for (const port of ports) {
        params.push(port, port);
      }
    }

    if (dateRange) {
      if (dateRange.start) {
        query += ' AND timestamp >= ?';
        params.push(dateRange.start);
      }
      if (dateRange.end) {
        query += ' AND timestamp <= ?';
        params.push(dateRange.end);
      }
    }

    if (minSize) {
      query += ' AND size >= ?';
      params.push(parseInt(minSize));
    }

    if (maxSize) {
      query += ' AND size <= ?';
      params.push(parseInt(maxSize));
    }

    query += ' ORDER BY timestamp DESC LIMIT 500';

    const packets = db.prepare(query).all(...params);

    res.json(packets);
  } catch (error) {
    logger.error('Search packets error:', error);
    res.status(500).json({ error: 'Failed to search packets' });
  }
});

module.exports = router;
