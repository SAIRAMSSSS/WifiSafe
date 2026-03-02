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
      return Promise.reject(new Error('Backend server is not reachable.'));
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
  getStats: () => api.get('/devices/stats/summary'),
  refresh: () => api.post('/devices/refresh'),
};

export const alertAPI = {
  getAll: () => api.get('/alerts'),
  acknowledge: (id: string) => api.post(`/alerts/${id}/acknowledge`),
};

export const securityAPI = {
  getScore: () => api.get('/security/score'),
};

export const networkAPI = {
  getTopology: () => api.get('/network/topology'),
  getBandwidth: () => api.get('/network/bandwidth'),
};

export const quarantineAPI = {
  getAll: () => api.get('/quarantine'),
  quarantineDevice: (deviceId: string, reason: string) =>
    api.post(`/quarantine/${deviceId}`, { reason }),
  releaseDevice: (deviceId: string) => api.delete(`/quarantine/${deviceId}`),
};

export const auditAPI = {
  getLogs: (params?: any) => api.get('/audit', { params }),
};

export default api;

