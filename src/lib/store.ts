import { create } from 'zustand';
import { deviceAPI, alertAPI, quarantineAPI, auditAPI } from './api';

interface DeviceStore {
  devices: any[];
  selectedDevice: any | null;
  stats: any | null;
  filters: {
    status: string | null;
    type: string | null;
    riskLevel: string | null;
    search: string;
  };
  fetchDevices: () => Promise<void>;
  fetchDeviceStats: () => Promise<void>;
  selectDevice: (device: any) => void;
  setFilters: (filters: any) => void;
}

export const useDeviceStore = create<DeviceStore>((set) => ({
  devices: [],
  selectedDevice: null,
  stats: null,
  filters: {
    status: null,
    type: null,
    riskLevel: null,
    search: '',
  },

  fetchDevices: async () => {
    try {
      const { data } = await deviceAPI.getAll();
      set({ devices: data });
    } catch (error) {
      console.error('Failed to fetch devices:', error);
    }
  },

  fetchDeviceStats: async () => {
    try {
      const { data } = await deviceAPI.getStats();
      set({ stats: data });
    } catch (error) {
      console.error('Failed to fetch stats:', error);
    }
  },

  selectDevice: (device) => set({ selectedDevice: device }),

  setFilters: (filters) => set({ filters }),
}));

interface AlertStore {
  alerts: any[];
  unreadCount: number;
  fetchAlerts: () => Promise<void>;
  addAlert: (alert: any) => void;
  acknowledgeAlert: (id: string) => Promise<void>;
}

export const useAlertStore = create<AlertStore>((set) => ({
  alerts: [],
  unreadCount: 0,

  fetchAlerts: async () => {
    try {
      const { data } = await alertAPI.getAll();
      const alerts = data.alerts || [];
      const unreadCount = alerts.filter((a: any) => !a.acknowledged).length;
      set({ alerts: alerts, unreadCount });
    } catch (error) {
      console.error('Failed to fetch alerts:', error);
    }
  },

  addAlert: (alert) =>
    set((state) => ({
      alerts: [alert, ...state.alerts],
      unreadCount: state.unreadCount + 1,
    })),

  acknowledgeAlert: async (id: string) => {
    try {
      await alertAPI.acknowledge(id);
      set((state) => ({
        alerts: state.alerts.map((a: any) =>
          a.id === id ? { ...a, acknowledged: true } : a
        ),
        unreadCount: Math.max(0, state.unreadCount - 1),
      }));
    } catch (error) {
      console.error('Failed to acknowledge alert:', error);
    }
  },
}));

interface QuarantineStore {
  quarantinedDevices: any[];
  logs: any[];
  stats: any | null;
  fetchQuarantinedDevices: () => Promise<void>;
  fetchLogs: () => Promise<void>;
  quarantineDevice: (id: string, reason: string) => Promise<void>;
  releaseDevice: (id: string) => Promise<void>;
}

export const useQuarantineStore = create<QuarantineStore>((set) => ({
  quarantinedDevices: [],
  logs: [],
  stats: null,

  fetchQuarantinedDevices: async () => {
    try {
      const { data } = await quarantineAPI.getAll();
      set({ quarantinedDevices: data.data || [] });
    } catch (error) {
      console.error('Failed to fetch quarantined devices:', error);
    }
  },

  fetchLogs: async () => {
    try {
      const { data } = await auditAPI.getLogs({ limit: 10 });
      set({ logs: data.logs || [] });
    } catch (error) {
      console.error('Failed to fetch audit logs:', error);
    }
  },

  quarantineDevice: async (id: string, reason: string) => {
    try {
      await quarantineAPI.quarantineDevice(id, reason);
      const { data } = await quarantineAPI.getAll();
      set({ quarantinedDevices: data.data || [] });
    } catch (error) {
      console.error('Failed to quarantine device:', error);
      throw error;
    }
  },

  releaseDevice: async (id: string) => {
    try {
      await quarantineAPI.releaseDevice(id);
      const { data } = await quarantineAPI.getAll();
      set({ quarantinedDevices: data.data || [] });
    } catch (error) {
      console.error('Failed to release device:', error);
      throw error;
    }
  },
}));

