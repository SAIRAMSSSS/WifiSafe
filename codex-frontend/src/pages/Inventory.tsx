import { Layout } from "@/components/layout/Layout";
import { useState, useMemo, useEffect } from "react";
import { cn } from "@/lib/utils";
import { Search, Filter, ArrowUpDown, ChevronDown, Wifi, Monitor, Cpu, Router } from "lucide-react";
import { useDevices } from "@/lib/hooks";
import { useSocket } from "@/lib/socket";
import { DeviceCategoryBadge } from "@/components/ui/DeviceCategoryBadge";

interface Device {
  id: string;
  name: string;
  type: string;
  ip: string;
  mac: string;
  vendor: string;
  manufacturer: string;
  os: string;
  risk_level: number;
  risk_score: number;
  last_seen: string;
  status: "active" | "inactive" | "quarantined" | "online" | "offline";
  device_category?: "IoT" | "Normal" | "Unknown";
  device_vendor?: string;
  device_role?: "Main" | "Secondary" | "Unknown";
  iot_device_type?: string;
}

const IOT_DEVICE_TYPES = [
  'camera', 'smart_tv', 'thermostat', 'doorbell', 'lock', 'light', 'plug',
  'switch', 'voice_assistant', 'smart_speaker', 'iot_device', 'iot_hub',
  'media_player', 'game_console', 'printer', 'nas', 'sensor', 'wearable'
];

const NORMAL_DEVICE_TYPES = [
  'computer', 'laptop', 'desktop', 'workstation', 'server', 'phone',
  'tablet', 'router', 'unknown'
];

const Inventory = () => {
  const { devices, stats, fetchDevices } = useDevices();
  const socket = useSocket();
  const [activeTab, setActiveTab] = useState<'all' | 'iot' | 'normal'>('all');

  useEffect(() => {
    fetchDevices();
  }, [fetchDevices]);

  useEffect(() => {
    if (!socket) return;

    const handleScanComplete = () => {
      console.log('Scan completed - refreshing inventory...');
      fetchDevices();
    };

    const handleDeviceUpdate = (data: any) => {
      console.log('Device updated - refreshing inventory...', data);
      fetchDevices();
    };

    const handleNewDevice = (data: any) => {
      console.log('New device discovered - refreshing inventory...', data);
      fetchDevices();
    };

    socket.on('scan_complete', handleScanComplete);
    socket.on('device_updated', handleDeviceUpdate);
    socket.on('device_connected', handleNewDevice);
    socket.on('devices', (data: any) => {
      if (data.event === 'new_device' || data.event === 'device_updated') {
        fetchDevices();
      }
    });

    return () => {
      socket.off('scan_complete', handleScanComplete);
      socket.off('device_updated', handleDeviceUpdate);
      socket.off('device_connected', handleNewDevice);
      socket.off('devices');
    };
  }, [socket, fetchDevices]);

  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState<keyof Device>("risk_score");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
  const [statusFilter, setStatusFilter] = useState("all");

  const categorizeDevice = (device: Device): 'iot' | 'normal' => {
    if (device.device_category === 'IoT') return 'iot';
    if (device.device_category === 'Normal') return 'normal';

    const type = device.type?.toLowerCase() || '';
    const vendor = device.vendor?.toLowerCase() || '';
    const name = device.name?.toLowerCase() || '';

    if (IOT_DEVICE_TYPES.some(t => type.includes(t))) return 'iot';

    const iotVendors = ['ring', 'nest', 'philips', 'hue', 'samsung smartthings', 'wyze', 'arlo', 'ecobee', 'august', 'tp-link kasa', 'tuya', 'shelly', 'sonoff'];
    if (iotVendors.some(v => vendor.includes(v))) return 'iot';

    const iotKeywords = ['camera', 'doorbell', 'thermostat', 'speaker', 'alexa', 'echo', 'hub', 'sensor', 'smart'];
    if (iotKeywords.some(k => name.includes(k))) return 'iot';

    return 'normal';
  };

  const { iotDevices, normalDevices, allDevices } = useMemo(() => {
    const iot: Device[] = [];
    const normal: Device[] = [];

    devices.forEach(device => {
      if (categorizeDevice(device) === 'iot') {
        iot.push(device);
      } else {
        normal.push(device);
      }
    });

    return { iotDevices: iot, normalDevices: normal, allDevices: devices };
  }, [devices]);

  const getDevicesForTab = () => {
    switch (activeTab) {
      case 'iot': return iotDevices;
      case 'normal': return normalDevices;
      default: return allDevices;
    }
  };

  const filteredDevices = useMemo(() => {
    return getDevicesForTab()
      .filter((device) => {
        const matchesSearch =
          device.name?.toLowerCase().includes(search.toLowerCase()) ||
          device.ip?.includes(search) ||
          device.mac?.toLowerCase().includes(search.toLowerCase()) ||
          device.vendor?.toLowerCase().includes(search.toLowerCase());
        const matchesStatus = statusFilter === "all" || device.status === statusFilter;
        return matchesSearch && matchesStatus;
      })
      .sort((a, b) => {
        const aVal = a[sortBy];
        const bVal = b[sortBy];
        if (typeof aVal === "number" && typeof bVal === "number") {
          return sortOrder === "asc" ? aVal - bVal : bVal - aVal;
        }
        return sortOrder === "asc"
          ? String(aVal || '').localeCompare(String(bVal || ''))
          : String(bVal || '').localeCompare(String(aVal || ''));
      });
  }, [devices, search, sortBy, sortOrder, statusFilter, activeTab, iotDevices, normalDevices]);

  const getRiskBarColor = (score: number) => {
    if (score >= 80) return "bg-destructive";
    if (score >= 50) return "bg-orange-500";
    if (score >= 30) return "bg-warning";
    return "bg-success";
  };

  const getStatusStyle = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'online':
      case 'active':
        return "bg-success/20 text-success";
      case 'offline':
      case 'inactive':
        return "bg-muted text-muted-foreground";
      case 'quarantined':
        return "bg-destructive/20 text-destructive";
      default:
        return "bg-muted text-muted-foreground";
    }
  };

  const handleSort = (column: keyof Device) => {
    if (sortBy === column) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortBy(column);
      setSortOrder("desc");
    }
  };

  const formatDeviceName = (device: Device) => {
    if (device.name && !device.name.includes('unknown')) {
      return device.name;
    }
    const vendor = device.vendor || device.manufacturer || '';
    const type = device.type || '';
    if (vendor && vendor !== 'Unknown Vendor') {
      return `${vendor} ${type}`.trim();
    }
    return `Device ${device.ip}`;
  };

  return (
    <Layout>
      <div className="mb-6 animate-fade-in">
        <h1 className="text-3xl font-display font-bold text-foreground mb-2">
          Device Inventory
        </h1>
        <p className="text-muted-foreground">
          Complete asset database with risk assessment and vendor information
        </p>
      </div>

      <div className="mb-6 animate-fade-in" style={{ animationDelay: "50ms" }}>
        <div className="flex gap-2 p-1 bg-muted/30 rounded-lg w-fit">
          <button
            onClick={() => setActiveTab('all')}
            className={cn(
              "px-4 py-2 rounded-md text-sm font-medium transition-all flex items-center gap-2",
              activeTab === 'all'
                ? "bg-primary text-primary-foreground shadow-md"
                : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
            )}
          >
            <Monitor className="w-4 h-4" />
            All Devices
            <span className="ml-1 px-2 py-0.5 bg-background/50 rounded-full text-xs">
              {allDevices.length}
            </span>
          </button>
          <button
            onClick={() => setActiveTab('iot')}
            className={cn(
              "px-4 py-2 rounded-md text-sm font-medium transition-all flex items-center gap-2",
              activeTab === 'iot'
                ? "bg-secondary text-secondary-foreground shadow-md"
                : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
            )}
          >
            <Cpu className="w-4 h-4" />
            IoT Devices
            <span className="ml-1 px-2 py-0.5 bg-background/50 rounded-full text-xs">
              {iotDevices.length}
            </span>
          </button>
          <button
            onClick={() => setActiveTab('normal')}
            className={cn(
              "px-4 py-2 rounded-md text-sm font-medium transition-all flex items-center gap-2",
              activeTab === 'normal'
                ? "bg-accent text-accent-foreground shadow-md"
                : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
            )}
          >
            <Router className="w-4 h-4" />
            Normal Devices
            <span className="ml-1 px-2 py-0.5 bg-background/50 rounded-full text-xs">
              {normalDevices.length}
            </span>
          </button>
        </div>
      </div>

      <div className="glass-panel p-4 mb-6 animate-fade-in" style={{ animationDelay: "100ms" }}>
        <div className="flex flex-wrap gap-4">
          <div className="flex-1 min-w-[200px] relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search by name, IP, MAC, or vendor..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-input border border-border rounded-md text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
            />
          </div>

          <div className="relative">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="pl-4 pr-8 py-2 bg-input border border-border rounded-md text-foreground appearance-none focus:outline-none focus:ring-2 focus:ring-primary/50"
            >
              <option value="all">All Status</option>
              <option value="online">Online</option>
              <option value="offline">Offline</option>
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
              <option value="quarantined">Quarantined</option>
            </select>
            <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
          </div>
        </div>
      </div>

      <div className="glass-panel overflow-hidden animate-fade-in" style={{ animationDelay: "200ms" }}>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border/50 bg-muted/30">
                {[
                  { key: "name", label: "Device Name" },
                  { key: "ip", label: "IP Address" },
                  { key: "vendor", label: "Vendor" },
                  { key: "type", label: "Device Type" },
                  { key: "risk_score", label: "Risk Score" },
                  { key: "last_seen", label: "Last Seen" },
                  { key: "status", label: "Status" },
                ].map((col) => (
                  <th
                    key={col.key}
                    onClick={() => handleSort(col.key as keyof Device)}
                    className="px-4 py-3 text-left text-xs uppercase tracking-wider text-muted-foreground cursor-pointer hover:text-foreground transition-colors"
                  >
                    <div className="flex items-center gap-2">
                      {col.label}
                      <ArrowUpDown className="w-3 h-3" />
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filteredDevices.map((device, index) => (
                <tr
                  key={device.id || `${device.ip}-${index}`}
                  className="border-b border-border/30 hover:bg-muted/20 transition-colors animate-fade-in"
                  style={{ animationDelay: `${300 + index * 30}ms` }}
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      {categorizeDevice(device) === 'iot' ? (
                        <Cpu className="w-4 h-4 text-secondary" />
                      ) : (
                        <Monitor className="w-4 h-4 text-muted-foreground" />
                      )}
                      <span className="font-medium text-foreground">
                        {formatDeviceName(device)}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-sm text-secondary">{device.ip}</td>
                  <td className="px-4 py-3 text-muted-foreground">
                    <div className="flex items-center gap-2">
                      <span>{device.vendor || device.manufacturer || 'Unknown'}</span>
                      <DeviceCategoryBadge category={device.device_category} />
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    {device.device_category === 'IoT' && device.iot_device_type && device.iot_device_type !== 'Unknown' ? (
                      <div className="flex flex-col gap-1">
                        <span className="text-xs font-medium text-purple-400">{device.iot_device_type}</span>
                        <span className="text-xs text-muted-foreground">{device.type || 'unknown'}</span>
                      </div>
                    ) : (
                      <span className={cn(
                        "px-2 py-1 text-xs rounded-md",
                        categorizeDevice(device) === 'iot'
                          ? "bg-secondary/20 text-secondary"
                          : "bg-muted text-muted-foreground"
                      )}>
                        {device.type || 'unknown'}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-2 bg-muted rounded-full overflow-hidden">
                        <div
                          className={cn("h-full transition-all", getRiskBarColor(device.risk_score || device.risk_level || 0))}
                          style={{ width: `${device.risk_score || device.risk_level || 0}%` }}
                        />
                      </div>
                      <span className="text-xs font-mono w-6">{device.risk_score || device.risk_level || 0}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-muted-foreground text-sm">
                    {device.last_seen ? new Date(device.last_seen).toLocaleString() : '-'}
                  </td>
                  <td className="px-4 py-3">
                    <span className={cn(
                      "px-2 py-1 text-xs uppercase tracking-wider rounded-full",
                      getStatusStyle(device.status)
                    )}>
                      {device.status || 'unknown'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {filteredDevices.length === 0 && (
          <div className="text-center py-12 text-muted-foreground">
            <div className="mb-2">
              {activeTab === 'iot' ? (
                <Cpu className="w-12 h-12 mx-auto opacity-50" />
              ) : activeTab === 'normal' ? (
                <Monitor className="w-12 h-12 mx-auto opacity-50" />
              ) : (
                <Wifi className="w-12 h-12 mx-auto opacity-50" />
              )}
            </div>
            No {activeTab === 'iot' ? 'IoT' : activeTab === 'normal' ? 'normal' : ''} devices match your search criteria
          </div>
        )}
      </div>
    </Layout>
  );
};

export default Inventory;

