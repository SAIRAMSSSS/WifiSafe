import { useDeviceStore, useAlertStore } from './store';

export const useDevices = () => {
  const store = useDeviceStore();
  return {
    devices: store.devices,
    stats: store.stats,
    fetchDevices: store.fetchDevices,
    fetchDeviceStats: store.fetchDeviceStats,
  };
};

export const useAlerts = () => {
  const store = useAlertStore();
  return {
    alerts: store.alerts,
    unreadCount: store.unreadCount,
    fetchAlerts: store.fetchAlerts,
    addAlert: store.addAlert,
    acknowledgeAlert: store.acknowledgeAlert,
  };
};
