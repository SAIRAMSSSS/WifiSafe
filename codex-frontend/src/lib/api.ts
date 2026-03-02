import axios, { AxiosInstance } from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3001/api';

const api: AxiosInstance = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.code === 'ECONNREFUSED' || error.message === 'Network Error') {
      console.error('❌ Cannot connect to backend at', API_URL);
      console.error('Make sure the backend server is running on port 3001');
      return Promise.reject(new Error('Backend server is not reachable. Please check if it is running.'));
    }

    if (error.response?.status !== 401) {
      console.error('API Error:', error.message, error.response?.status);
    }
    return Promise.reject(error);
  }
);

export const deviceAPI = {
  getAll: () => api.get('/devices'),
  getById: (id: string) => api.get(`/devices/${id}`),
  create: (data: Record<string, unknown>) => api.post('/devices', data),
  update: (id: string, data: Record<string, unknown>) => api.put(`/devices/${id}`, data),
  delete: (id: string) => api.delete(`/devices/${id}`),
  getStats: () => api.get('/devices/stats/summary'),
  refresh: () => api.post('/devices/refresh'),
  checkCredentials: (ip: string, authorized: boolean) =>
    api.post(`/devices/${ip}/check-credentials`, { authorized }),
  configAudit: (ip: string) => api.get(`/devices/${ip}/config-audit`),
  getVulnerabilities: (ip: string) => api.get(`/devices/${ip}/vulns`),
  quarantine: (ip: string, reason: string) =>
    api.post(`/devices/${ip}/quarantine`, { reason }),
  unquarantine: (ip: string) => api.post(`/devices/${ip}/unquarantine`),
};

export const alertAPI = {
  getAll: () => api.get('/alerts'),
  acknowledge: (id: string) => api.post(`/alerts/${id}/acknowledge`),
};

export const vulnerabilityAPI = {
  getAll: () => api.get('/vulnerabilities'),
  queryCVE: (vendor: string, product: string) =>
    api.get(`/cve/${vendor}/${product}`),
};

export const reportAPI = {
  getReports: () => api.get('/reports'),
  getScanReport: () => api.get('/reports/scan-report'),
};

export const scanAPI = {
  startScan: (data: { subnet?: string; type?: string }) => api.post('/scan/start', data),
  getStatus: () => api.get('/scan/status'),
  stopScan: () => api.post('/scan/stop'),
  getHistory: (params?: { limit?: number; offset?: number }) => api.get('/scan/history', { params }),
  getScan: (id: string) => api.get(`/scan/${id}`),
  getDevices: () => api.get('/scan/devices'),
  getNetworkInfo: () => api.get('/scan/network-info'),
  pingHost: (ip: string) => api.post(`/scan/ping/${ip}`),
  getArpTable: () => api.get('/scan/arp'),
};

export const aiAPI = {
  analyze: (deviceIp: string, analysisType: string = 'full') =>
    api.post('/scan/ai/analyze-device', { ip: deviceIp }),
  getReport: (reportId: string) => api.get(`/scan/ai/reports/${reportId}`),
  chat: (message: string, context: Record<string, unknown> = {}) =>
    api.post('/ai/chat', { message, context }),
  getRecommendations: () => api.get('/ai/recommendations'),
  analyzeNetwork: () => api.post('/ai/analyze-network'),
  geminiScanReport: () => api.post('/ai/gemini-scan-report'),
};

export const pentestAPI = {
  run: () => api.post('/pentest/run'),
  getReports: (limit: number = 20) => api.get('/pentest/reports', { params: { limit } }),
  getReport: (id: string) => api.get(`/pentest/reports/${id}`),
  getRemediations: (reportId: string) => api.get(`/pentest/remediations/${reportId}`),
  applyRemediation: (id: string) => api.post(`/pentest/remediate/${id}`),
  rejectRemediation: (id: string, reason?: string) => api.post(`/pentest/remediate/${id}/reject`, { reason }),
};

export const networkAPI = {
  getTopology: () => api.get('/network/topology'),
  getTraffic: (limit: number = 100) => api.get('/network/traffic', { params: { limit } }),
  getPorts: () => api.get('/network/ports'),
  getConnections: () => api.get('/network/connections'),
  getSegments: () => api.get('/network/segments'),
  getBandwidth: () => api.get('/network/bandwidth'),
};

export const threatAPI = {
  getAll: (params?: any) => api.get('/threats', { params }),
  getById: (id: string) => api.get(`/threats/${id}`),
  getStats: () => api.get('/threats/stats/summary'),
  searchIOC: (data: { ip?: string; domain?: string; hash?: string; indicators?: string[] }) =>
    api.post('/threats/search-ioc', data),
  checkDevice: (data: { deviceId: string; deviceType?: string; ip?: string; openPorts?: number[] }) =>
    api.post('/threats/check-device', data),
};

export const packetAPI = {
  getRecent: (limit: number = 100) => api.get('/packets/recent', { params: { limit } }),
  startCapture: (data: any) => api.post('/packets/capture/start', data),
  stopCapture: () => api.post('/packets/capture/stop'),
  getStatus: () => api.get('/packets/capture/status'),
  analyze: (packetId: string) => api.post(`/packets/analyze/${packetId}`),
};

export const settingsAPI = {
  getAll: () => api.get('/settings'),
  update: (section: string, settings: any) => api.put(`/settings/${section}`, settings),
  reset: (section: string) => api.post(`/settings/${section}/reset`),
};

export const auditAPI = {
  getLogs: (params?: any) => api.get('/audit', { params }),
  getStats: () => api.get('/audit/stats'),
  export: (format: 'csv' | 'json') => api.get(`/audit/export/${format}`),
};

export const credentialsAPI = {
  checkDefault: (deviceId: string) => api.post('/credentials/check-default', { deviceId }),
  test: (deviceId: string, type: string) => api.post('/credentials/test', { deviceId, type }),
};

export const securityAPI = {
  getStatus: () => api.get('/security/status'),
  updatePolicy: (policy: any) => api.put('/security/policy', policy),
  getScore: () => api.get('/scan/security/score'),
};

export const quarantineAPI = {
  getAll: () => api.get('/quarantine'),
  quarantineDevice: (deviceId: string, reason: string) =>
    api.post(`/quarantine/${deviceId}`, { reason }),
  releaseDevice: (deviceId: string) => api.delete(`/quarantine/${deviceId}`),
  getLogs: () => api.get('/quarantine/logs'),
  killSwitch: () => api.post('/quarantine/killswitch'),
};

export default api;
