import { Layout } from "@/components/layout/Layout";
import { useState, useEffect } from "react";
import { cn } from "@/lib/utils";
import { Key, ExternalLink, Server, Router, Shield, Database, Wifi, Lock, Eye, EyeOff, AlertTriangle, Monitor, Camera, Printer, HardDrive, RefreshCw, Search } from "lucide-react";
import { useDevices } from "@/lib/hooks";

interface DeviceCredentials {
  lastChecked: string;
  hasDefaultCredentials: boolean;
  hasWeakCredentials: boolean;
  findings?: Array<{ port: number; service: string; message: string }>;
}

const AdminCenter = () => {
  const { devices, fetchDevices } = useDevices();
  const [showCredentials, setShowCredentials] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [isRefreshing, setIsRefreshing] = useState(false);

  useEffect(() => {
    fetchDevices();
  }, []);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    await fetchDevices();
    setTimeout(() => setIsRefreshing(false), 1000);
  };

  const filteredDevices = devices.filter(d => {
    const matchesSearch = searchTerm === "" ||
      d.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      d.ip?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      d.device_type?.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSearch;
  });

  const getDeviceIcon = (type: string) => {
    const t = (type || '').toLowerCase();
    if (t.includes('router') || t.includes('gateway')) return Router;
    if (t.includes('firewall')) return Shield;
    if (t.includes('server')) return Server;
    if (t.includes('database')) return Database;
    if (t.includes('camera') || t.includes('doorbell') || t.includes('nvr')) return Camera;
    if (t.includes('printer')) return Printer;
    if (t.includes('computer') || t.includes('desktop') || t.includes('laptop')) return Monitor;
    if (t.includes('nas') || t.includes('storage')) return HardDrive;
    return Wifi;
  };

  const getStatusStyles = (status: string) => {
    switch (status) {
      case "online": return "bg-success/20 text-success";
      case "offline": return "bg-muted text-muted-foreground";
      case "quarantined": return "bg-destructive/20 text-destructive";
      default: return "bg-warning/20 text-warning";
    }
  };

  const getRiskStyles = (riskLevel: string) => {
    switch (riskLevel) {
      case "critical": return "bg-destructive/20 text-destructive border-destructive/50";
      case "high": return "bg-orange-500/20 text-orange-500 border-orange-500/50";
      case "medium": return "bg-warning/20 text-warning border-warning/50";
      default: return "bg-success/20 text-success border-success/30";
    }
  };

  const getAdminUrl = (device: any) => {
    if (device.admin_url) return device.admin_url;

    let ports: number[] = [];
    try {
      if (device.open_ports) {
        const parsed = JSON.parse(device.open_ports);
        ports = parsed.map((p: any) => p.port || p);
      }
    } catch (e) {
      ports = [];
    }

    if (ports.includes(443)) return `https://${device.ip}`;
    if (ports.includes(8443)) return `https://${device.ip}:8443`;
    if (ports.includes(8080)) return `http://${device.ip}:8080`;
    if (ports.includes(80)) return `http://${device.ip}`;
    if (ports.includes(7547)) return `http://${device.ip}:7547`;
    if (ports.includes(554)) return `rtsp://${device.ip}:554`;

    return `https://${device.ip}`;
  };

  const getCredentialStatus = (device: any): DeviceCredentials | null => {
    if (!device.credential_status) return null;
    try {
      return JSON.parse(device.credential_status);
    } catch (e) {
      return null;
    }
  };

  return (
    <Layout>
      <div className="mb-6 animate-fade-in">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-display font-bold text-foreground mb-2">
              Admin Login Center
            </h1>
            <p className="text-muted-foreground">
              Centralized device administration portal with secure access
            </p>
          </div>
          <button
            onClick={handleRefresh}
            className={cn(
              "p-3 rounded-lg bg-primary/20 text-primary hover:bg-primary/30 transition-colors",
              isRefreshing && "animate-spin"
            )}
          >
            <RefreshCw className="w-5 h-5" />
          </button>
        </div>
      </div>

      <div className="glass-panel p-4 mb-6 animate-fade-in" style={{ animationDelay: "50ms" }}>
        <div className="flex items-center gap-3">
          <Search className="w-5 h-5 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search devices by name, IP, or type..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="flex-1 bg-transparent border-none outline-none text-foreground placeholder:text-muted-foreground"
          />
          <span className="text-sm text-muted-foreground">
            {filteredDevices.length} devices
          </span>
        </div>
      </div>

      <div className="glass-panel p-4 mb-6 border border-warning/30 animate-fade-in" style={{ animationDelay: "100ms" }}>
        <div className="flex items-center gap-3">
          <Lock className="w-5 h-5 text-warning" />
          <p className="text-sm text-warning">
            All admin access is logged and monitored. Use strong authentication and follow security protocols.
          </p>
        </div>
      </div>

      <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredDevices.length === 0 ? (
          <div className="col-span-full text-center py-12 text-muted-foreground glass-panel">
            {searchTerm ? "No devices match your search." : "No devices found. Run a network scan first."}
          </div>
        ) : (
          filteredDevices.map((device: any, index: number) => {
            const Icon = getDeviceIcon(device.device_type || device.type || 'unknown');
            const status = device.status === 'active' ? 'online' : device.status;
            const adminUrl = getAdminUrl(device);
            const credStatus = getCredentialStatus(device);
            const hasSecurityIssue = device.has_weak_credentials || credStatus?.hasDefaultCredentials;

            return (
              <div
                key={device.id}
                className={cn(
                  "glass-panel p-6 hover:border-primary/50 transition-all group animate-fade-in",
                  hasSecurityIssue && "border-destructive/30"
                )}
                style={{ animationDelay: `${200 + index * 50}ms` }}
              >
                <div className="flex items-start justify-between mb-4">
                  <div className={cn(
                    "p-3 rounded-lg",
                    status === "online" && "bg-primary/20 text-primary",
                    status !== "online" && "bg-muted text-muted-foreground"
                  )}>
                    <Icon className="w-6 h-6" />
                  </div>
                  <div className="flex items-center gap-2">
                    {hasSecurityIssue && (
                      <span className="px-2 py-0.5 text-[10px] uppercase tracking-wider rounded-full bg-destructive/20 text-destructive flex items-center gap-1">
                        <AlertTriangle className="w-3 h-3" />
                        Risk
                      </span>
                    )}
                    <span className={cn(
                      "px-2 py-0.5 text-[10px] uppercase tracking-wider rounded-full",
                      getStatusStyles(status)
                    )}>
                      {status}
                    </span>
                  </div>
                </div>

                <h3 className="text-lg font-display font-semibold text-foreground mb-1">
                  {device.name}
                </h3>
                <p className="text-sm font-mono text-secondary mb-4">{device.ip}</p>

                <div className="space-y-2 text-sm mb-4">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Type</span>
                    <span className="text-foreground capitalize">{device.device_type || device.type || 'Unknown'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Vendor</span>
                    <span className="text-foreground">{device.manufacturer || device.vendor || 'Unknown'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Risk Level</span>
                    <span className={cn(
                      "px-2 py-0.5 text-[10px] uppercase rounded-full border",
                      getRiskStyles(device.risk_level || 'low')
                    )}>
                      {device.risk_level || 'low'}
                    </span>
                  </div>
                </div>

                <div className={cn(
                  "p-3 rounded-lg mb-4",
                  hasSecurityIssue ? "bg-destructive/10" : "bg-muted/30"
                )}>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs text-muted-foreground uppercase tracking-wider">
                      Security Status
                    </span>
                    <button
                      onClick={() => setShowCredentials(showCredentials === device.id ? null : device.id)}
                      className="text-muted-foreground hover:text-foreground transition-colors"
                    >
                      {showCredentials === device.id ? (
                        <EyeOff className="w-4 h-4" />
                      ) : (
                        <Eye className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                  {showCredentials === device.id ? (
                    <div className="space-y-1 text-xs">
                      {credStatus ? (
                        <>
                          <p className={cn(
                            "flex items-center gap-1",
                            credStatus.hasDefaultCredentials ? "text-destructive" : "text-success"
                          )}>
                            <span className="text-muted-foreground">Default Creds:</span>
                            {credStatus.hasDefaultCredentials ? "DETECTED" : "Not found"}
                          </p>
                          <p className={cn(
                            "flex items-center gap-1",
                            credStatus.hasWeakCredentials ? "text-warning" : "text-success"
                          )}>
                            <span className="text-muted-foreground">Weak Config:</span>
                            {credStatus.hasWeakCredentials ? "YES" : "No"}
                          </p>
                          <p className="text-muted-foreground text-[10px]">
                            Last checked: {new Date(credStatus.lastChecked).toLocaleDateString()}
                          </p>
                        </>
                      ) : (
                        <p className="text-muted-foreground">
                          No security check performed yet.
                          <br />
                          <span className="text-[10px]">Run credential check on this device.</span>
                        </p>
                      )}
                    </div>
                  ) : (
                    <p className="text-xs text-muted-foreground">
                      {hasSecurityIssue ? (
                        <span className="text-destructive">⚠ Security issues detected</span>
                      ) : (
                        "Click eye to view status"
                      )}
                    </p>
                  )}
                </div>

                <a
                  href={adminUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className={cn(
                    "w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg font-display uppercase tracking-wider text-sm transition-all",
                    status === "online"
                      ? "bg-primary text-primary-foreground hover:bg-primary/90 neon-border"
                      : "bg-muted text-muted-foreground cursor-not-allowed"
                  )}
                  onClick={(e) => status !== "online" && e.preventDefault()}
                >
                  <Key className="w-4 h-4" />
                  Access Admin
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            );
          })
        )}
      </div>
    </Layout>
  );
};

export default AdminCenter;

