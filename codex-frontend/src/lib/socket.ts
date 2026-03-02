import io, { Socket } from 'socket.io-client';
import { useDeviceStore, useAlertStore } from './store';

const WS_URL = import.meta.env.VITE_WS_URL || 'http://localhost:3001';

let socket: Socket | null = null;

export const connectSocket = (token: string) => {
  if (socket?.connected) {
    console.log('WebSocket already connected');
    return socket;
  }

  // Disconnect existing socket if any
  if (socket) {
    socket.removeAllListeners();
    socket.disconnect();
  }

  try {
    socket = io(WS_URL, {
      auth: { token: token || 'dev-token' },
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: 10,
      timeout: 20000,
      transports: ['websocket', 'polling'],
    });

    socket.on('connect', () => {
      console.log('✅ WebSocket connected to', WS_URL);
      // Subscribe to channels after connection
      socket?.emit('subscribe:devices');
      socket?.emit('subscribe:alerts');
      socket?.emit('subscribe:scan');
    });

    socket.on('connected', (data) => {
      console.log('WebSocket server welcome:', data);
    });

    socket.on('authenticated', (data) => {
      console.log('✅ WebSocket authenticated:', data);
    });

    socket.on('subscribed', (data) => {
      console.log('✅ Subscribed to channel:', data);
    });

    socket.on('connect_error', (error) => {
      console.error('❌ WebSocket connection error:', error.message);
      console.error('Connection details:', {
        url: WS_URL,
        token: token ? 'provided' : 'missing'
      });
    });

    socket.on('disconnect', (reason) => {
      console.warn('⚠️ WebSocket disconnected:', reason);
    });

    socket.on('error', (error) => {
      console.error('❌ WebSocket error:', error);
    });

    // Device events
    socket.on('device_connected', (device) => {
      console.log('📱 New device connected:', device);
      useDeviceStore.setState((state) => ({
        devices: [...state.devices.filter(d => d.id !== device.id), device]
      }));
    });

    socket.on('device_updated', (device) => {
      console.log('📱 Device updated:', device);
      useDeviceStore.setState((state) => ({
        devices: state.devices.map((d) => (d.id === device.id ? device : d)),
      }));
    });

    // Alert events
    socket.on('alert_created', (alert) => {
      console.log('🚨 New alert:', alert);
      (useAlertStore.getState() as any).addAlert(alert);
    });

  } catch (error) {
    console.error('❌ Failed to initialize WebSocket:', error);
  }

  return socket;
};

export const disconnectSocket = () => {
  socket?.disconnect();
  socket = null;
};

export const getSocket = () => socket;

// React hook for socket
export const useSocket = () => {
  return socket;
};
