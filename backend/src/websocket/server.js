const { Server } = require('socket.io');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');

let io = null;
const clients = new Map();

function initializeWebSocket(server) {
  io = new Server(server, {
    cors: {
      origin: ['http://localhost:8080', 'http://localhost:5173', 'http://localhost:3000'],
      methods: ['GET', 'POST'],
      credentials: true
    }
  });

  io.on('connection', (socket) => {
    const clientId = uuidv4();
    clients.set(clientId, {
      socket,
      subscriptions: new Set(),
      authenticated: false,
      userId: null
    });

    logger.info(`WebSocket client connected: ${clientId}`);

    // Try authenticate from handshake auth token
    const token = socket.handshake.auth?.token;
    if (token) {
      handleAuthenticate(clientId, token);
    } else if (process.env.NODE_ENV === 'development') {
      // Auto-authenticate in dev mode if no token provided
      handleAuthenticate(clientId, 'dev-token');
    }

    // Send welcome message
    socket.emit('connected', {
      clientId,
      message: 'Connected to Black Codex WebSocket server'
    });

    // Handle authentication
    socket.on('authenticate', (data) => {
      handleAuthenticate(clientId, data?.token || data);
    });

    // Handle subscribe events (socket.io style)
    socket.on('subscribe:devices', () => handleSubscribe(clientId, 'devices'));
    socket.on('subscribe:alerts', () => handleSubscribe(clientId, 'alerts'));
    socket.on('subscribe:scan', () => handleSubscribe(clientId, 'scan'));
    socket.on('subscribe:scans', () => handleSubscribe(clientId, 'scans'));
    socket.on('subscribe:packets', () => handleSubscribe(clientId, 'packets'));
    socket.on('subscribe:system', () => handleSubscribe(clientId, 'system'));

    // Generic subscribe handler
    socket.on('subscribe', (data) => {
      handleSubscribe(clientId, data?.channel || data);
    });

    // Generic unsubscribe handler
    socket.on('unsubscribe', (data) => {
      handleUnsubscribe(clientId, data?.channel || data);
    });

    // Ping handler
    socket.on('ping', () => {
      socket.emit('pong', { timestamp: Date.now() });
    });

    socket.on('disconnect', () => {
      clients.delete(clientId);
      logger.info(`WebSocket client disconnected: ${clientId}`);
    });

    socket.on('error', (error) => {
      logger.error(`WebSocket error for client ${clientId}:`, error);
    });
  });

  logger.info('WebSocket server initialized');
  return io;
}

function handleAuthenticate(clientId, token) {
  const client = clients.get(clientId);
  if (!client) return;

  // Allow dev mode bypass (same as HTTP middleware)
  if (process.env.NODE_ENV === 'development' || token === 'dev-token') {
    client.authenticated = true;
    client.userId = 'dev';
    client.socket.emit('authenticated', {
      userId: 'dev',
      message: 'Authentication successful (dev mode)'
    });
    logger.info(`WebSocket client ${clientId} authenticated in dev mode`);
    return;
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    client.authenticated = true;
    client.userId = decoded.userId || decoded.id;

    client.socket.emit('authenticated', {
      userId: decoded.userId || decoded.id,
      message: 'Authentication successful'
    });

    logger.info(`WebSocket client ${clientId} authenticated as user ${decoded.userId || decoded.id}`);
  } catch (error) {
    // In dev mode, still allow connection but log the error
    if (process.env.NODE_ENV === 'development') {
      client.authenticated = true;
      client.userId = 'dev';
      logger.warn(`WebSocket auth failed in dev mode, allowing connection: ${error.message}`);
      return;
    }
    client.socket.emit('error', {
      message: 'Authentication failed'
    });
  }
}

function handleSubscribe(clientId, channel) {
  const client = clients.get(clientId);
  if (!client) return;

  const validChannels = ['alerts', 'devices', 'scan', 'scans', 'packets', 'system'];
  const protectedChannels = new Set(['devices', 'scans', 'packets', 'system']);

  if (!validChannels.includes(channel)) {
    client.socket.emit('error', { message: `Invalid channel: ${channel}` });
    return;
  }

  // Require authentication for protected channels
  if (protectedChannels.has(channel) && !client.authenticated) {
    client.socket.emit('error', { message: `Authentication required to subscribe to ${channel}` });
    logger.warn(`Client ${clientId} denied subscription to protected channel ${channel}`);
    return;
  }

  // Join the socket.io room for this channel
  client.socket.join(channel);
  client.subscriptions.add(channel);
  client.socket.emit('subscribed', { channel, message: `Subscribed to ${channel}` });
  logger.info(`Client ${clientId} subscribed to ${channel}`);
}

function handleUnsubscribe(clientId, channel) {
  const client = clients.get(clientId);
  if (!client) return;

  client.socket.leave(channel);
  client.subscriptions.delete(channel);
  client.socket.emit('unsubscribed', {
    channel,
    message: `Unsubscribed from ${channel}`
  });

  logger.info(`Client ${clientId} unsubscribed from ${channel}`);
}

// Broadcast to all clients subscribed to a channel
function broadcast(channel, data) {
  if (!io) return;

  const protectedChannels = new Set(['devices', 'scans', 'packets', 'system']);

  // For protected channels, we need to check authentication
  if (protectedChannels.has(channel)) {
    // Emit to authenticated clients in the room only
    clients.forEach((client) => {
      if (client.authenticated && client.subscriptions.has(channel)) {
        client.socket.emit(channel, data);
      }
    });
  } else {
    // For non-protected channels, emit to the room directly
    io.to(channel).emit(channel, data);
  }

  // Also emit as generic 'broadcast' event for backward compatibility
  io.to(channel).emit('broadcast', {
    channel,
    data,
    timestamp: new Date().toISOString()
  });
}

// Broadcast to all connected clients
function broadcastToAll(data) {
  if (!io) return;

  io.emit('broadcast', {
    channel: 'all',
    data,
    timestamp: new Date().toISOString()
  });
}

// Send to specific user
function sendToUser(userId, data) {
  clients.forEach((client) => {
    if (client.userId === userId) {
      client.socket.emit('direct', {
        data,
        timestamp: new Date().toISOString()
      });
    }
  });
}

// Emit events for different types of updates
const emit = {
  // Alert events
  newAlert: (alert) => {
    broadcast('alerts', { event: 'new_alert', alert });
    // Also emit specific event name for socket.io style listeners
    if (io) io.to('alerts').emit('alert_created', alert);
  },
  alertAcknowledged: (alertId) => {
    broadcast('alerts', { event: 'alert_acknowledged', alertId });
  },

  // Device events
  deviceOnline: (device) => {
    broadcast('devices', { event: 'device_online', device });
    if (io) io.to('devices').emit('device_connected', device);
  },
  deviceOffline: (device) => {
    broadcast('devices', { event: 'device_offline', device });
    if (io) io.to('devices').emit('device_disconnected', device);
  },
  deviceUpdated: (device) => {
    broadcast('devices', { event: 'device_updated', device });
    if (io) io.to('devices').emit('device_updated', device);
  },
  deviceQuarantined: (device) => {
    broadcast('devices', { event: 'device_quarantined', device });
  },
  newDevice: (device) => {
    broadcast('devices', { event: 'new_device', device });
    if (io) io.to('devices').emit('device_connected', device);
  },

  // Scan events
  scanStarted: (scan) => {
    broadcast('scans', { event: 'scan_started', scan });
    broadcast('scan', { event: 'scan_started', scan });
    if (io) {
      io.to('scans').emit('scan_started', scan);
      io.to('scan').emit('scan_started', scan);
    }
  },
  scanProgress: (scanId, progress) => {
    // Handle both simple progress and full data object
    const data = typeof progress === 'object' ? { scanId, ...progress } : { scanId, progress };
    broadcast('scans', { event: 'scan_progress', ...data });
    broadcast('scan', { event: 'scan_progress', ...data });
    if (io) {
      io.to('scans').emit('scan_progress', data);
      io.to('scan').emit('scan_progress', data);
    }
  },
  scanCompleted: (scan) => {
    broadcast('scans', { event: 'scan_completed', scan });
    broadcast('scan', { event: 'scan_completed', scan });
    if (io) {
      io.to('scans').emit('scan_completed', scan);
      io.to('scan').emit('scan_completed', scan);
    }
  },
  scanFailed: (scanId, error) => {
    broadcast('scans', { event: 'scan_failed', scanId, error });
    broadcast('scan', { event: 'scan_failed', scanId, error });
  },

  // Packet events
  packetCaptured: (packet) => {
    broadcast('packets', { event: 'packet_captured', packet });
  },

  // System events
  systemStatus: (status) => {
    broadcast('system', { event: 'system_status', status });
  },
  configUpdated: (config) => {
    broadcast('system', { event: 'config_updated', config });
  },

  // Custom discovery events
  portOpen: (data) => {
    broadcast('devices', { event: 'port_open', ...data });
    if (io) io.to('devices').emit('port_open', data);
  },
  vulnerabilityDiscovered: (vuln) => {
    broadcast('alerts', { event: 'vulnerability_discovered', vuln });
    if (io) io.to('alerts').emit('vulnerability_discovered', vuln);
  },
  trafficAnomaly: (anomaly) => {
    broadcast('alerts', { event: 'traffic_anomaly', anomaly });
    if (io) io.to('alerts').emit('traffic_anomaly', anomaly);
  }
};

function getConnectedClients() {
  return {
    total: clients.size,
    authenticated: Array.from(clients.values()).filter(c => c.authenticated).length,
    subscriptions: Array.from(clients.values()).reduce((acc, client) => {
      client.subscriptions.forEach(s => {
        acc[s] = (acc[s] || 0) + 1;
      });
      return acc;
    }, {})
  };
}

function emitDeviceQuarantined({ ip, by, reason }) {
  broadcast('device.quarantined', { ip, by, reason });
}

module.exports = {
  initializeWebSocket,
  broadcast,
  broadcastToAll,
  sendToUser,
  emit,
  getConnectedClients,
  emitDeviceQuarantined,
};
