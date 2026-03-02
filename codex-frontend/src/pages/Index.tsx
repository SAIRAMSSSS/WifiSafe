
import { Layout } from "@/components/layout/Layout";
import { SecurityGauge } from "@/components/ui/SecurityGauge";
import { StatCard } from "@/components/ui/StatCard";
import { FeatureCard } from "@/components/ui/FeatureCard";
import { useEffect, useState } from "react";
import { useDeviceStore, useAlertStore, useQuarantineStore } from "@/lib/store";
import { useSocket } from "@/lib/socket";
import {
  Network,
  AlertTriangle,
  Scan,
  Brain,
  ShieldOff,
  Key,
  Shield,
  Wifi,
  HardDrive,
  Activity,
} from "lucide-react";

interface Stats {
  securityScore: number;
  scoreStatus: string;
  scoreMessage: string;
  criticalAlerts: number;
  totalThreats: number;
  totalVulnerabilities: number;
}

const Index = () => {
  const { devices, fetchDevices } = useDeviceStore();
  const { alerts, fetchAlerts } = useAlertStore();
  const { fetchQuarantinedDevices } = useQuarantineStore();
  const socket = useSocket();

  const [networkTraffic, setNetworkTraffic] = useState<string>("0 GB");
  const [stats, setStats] = useState<Stats>({
    securityScore: 0,
    scoreStatus: 'no_scan_data',
    scoreMessage: 'No scan data available',
    criticalAlerts: 0,
    totalThreats: 0,
    totalVulnerabilities: 0
  });

  useEffect(() => {
    if (!socket) return;

    const handleScanComplete = (data: any) => {
      console.log('[Dashboard] Scan complete, refreshing score...', data);
      const token = localStorage.getItem('token');
      fetch('http://localhost:3001/api/security/score', {
        headers: { Authorization: `Bearer ${token}` }
      })
        .then(res => res.json())
        .then(scoreData => {
          setStats(prev => ({
            ...prev,
            securityScore: scoreData.score ?? 0,
            scoreStatus: scoreData.status || 'scan_complete',
            scoreMessage: scoreData.message || 'Score updated'
          }));
        })
        .catch(err => console.error('Failed to refresh score:', err));
    };

    const handleScoreUpdate = (data: any) => {
      console.log('[Dashboard] Real-time score update:', data);
      if (data.score !== undefined) {
        setStats(prev => ({
          ...prev,
          securityScore: data.score,
          scoreStatus: 'scan_complete',
          scoreMessage: 'Score updated in real-time'
        }));
      }
    };

    socket.on('scan_complete', handleScanComplete);
    socket.on('security_score_updated', handleScoreUpdate);
    socket.on('scan', (msg: any) => {
      if (msg.type === 'scan_complete') handleScanComplete(msg);
      if (msg.type === 'security_score_updated') handleScoreUpdate(msg);
    });

    return () => {
      socket.off('scan_complete', handleScanComplete);
      socket.off('security_score_updated', handleScoreUpdate);
      socket.off('scan');
    };
  }, [socket]);

  useEffect(() => {
    fetchDevices();
    fetchAlerts();
    fetchQuarantinedDevices();

    const pollRealtimeData = async () => {
      try {
        const token = localStorage.getItem('token');
        const headers = { Authorization: `Bearer ${token}` };

        const trafficRes = await fetch('http://localhost:3001/api/network/bandwidth', { headers });
        const trafficData = await trafficRes.json();
        if (trafficData && trafficData.summary) {
          const totalMB = parseFloat(trafficData.summary.totalDownload) + parseFloat(trafficData.summary.totalUpload);
          if (totalMB > 1000000) {
            setNetworkTraffic(`${(totalMB / 1000000).toFixed(2)} TB`);
          } else if (totalMB > 1000) {
            setNetworkTraffic(`${(totalMB / 1000).toFixed(2)} GB`);
          } else {
            setNetworkTraffic(`${totalMB.toFixed(0)} MB`);
          }
        }

        const statsRes = await fetch('http://localhost:3001/api/devices/stats/summary', { headers });
        if (statsRes.ok) {
          const statsData = await statsRes.json();
          console.log('Stats data received:', statsData);

          let securityScore = statsData.securityScore;
          let scoreStatus = statsData.scoreStatus || 'unknown';
          let scoreMessage = statsData.scoreMessage || '';

          if (securityScore === undefined || securityScore === null) {
            try {
              const securityRes = await fetch('http://localhost:3001/api/security/score', { headers });
              if (securityRes.ok) {
                const securityData = await securityRes.json();
                securityScore = securityData.score ?? 0;
                scoreStatus = securityData.status || 'unknown';
                scoreMessage = securityData.message || '';
              }
            } catch (e) {
              console.warn('Failed to fetch security score from security endpoint:', e);
              scoreStatus = 'no_scan_data';
              scoreMessage = 'No scan data available';
            }
          }

          setStats({
            securityScore: securityScore ?? 0,
            scoreStatus: scoreStatus,
            scoreMessage: scoreMessage || 'Fetching data...',
            criticalAlerts: statsData.criticalAlerts ?? 0,
            totalThreats: statsData.totalThreats ?? 0,
            totalVulnerabilities: statsData.totalVulnerabilities ?? 0
          });
        } else {
          console.error('Failed to fetch stats:', statsRes.status, statsRes.statusText);
          const errorText = await statsRes.text();
          console.error('Error response:', errorText);

          try {
            const securityRes = await fetch('http://localhost:3001/api/security/score', { headers });
            if (securityRes.ok) {
              const securityData = await securityRes.json();
              setStats(prev => ({
                ...prev,
                securityScore: securityData.score ?? 0,
                scoreStatus: securityData.status || 'no_scan_data',
                scoreMessage: securityData.message || 'No scan data available'
              }));
            }
          } catch (e) {
            console.warn('Failed to fetch security score:', e);
          }
        }

        fetchAlerts();

      } catch (e) {
        console.error("Failed to fetch real-time data", e);
      }
    };

    pollRealtimeData();
    const interval = setInterval(pollRealtimeData, 5000);
    return () => clearInterval(interval);
  }, []);

  const activeDevices = devices.filter((d: any) => d.status === "online").length;
  const criticalAlerts = stats.criticalAlerts || alerts.filter((a: any) => a.severity === "critical" && !a.acknowledged).length;
  const recentThreats = stats.totalThreats + stats.totalVulnerabilities;

  return (
    <Layout>
      <section className="mb-12 animate-fade-in">
        <div className="glass-panel-glow p-8 relative overflow-hidden">
          <div className="scan-line" />

          <div className="flex flex-col lg:flex-row items-center gap-8">
            <div className="flex-1 text-center lg:text-left">
              <p className="text-xs uppercase tracking-[0.3em] text-primary mb-2">
                System Status: Online
              </p>
              <h1 className="text-4xl lg:text-5xl font-display font-bold text-foreground mb-4">
                Cyber Defense
                <br />
                <span className="neon-text text-primary">Command Center</span>
              </h1>
              <p className="text-muted-foreground max-w-md mx-auto lg:mx-0">
                Real-time network monitoring, threat detection, and automated
                security response for your digital infrastructure.
              </p>
            </div>

            <div className="flex-shrink-0">
              <SecurityGauge score={stats.securityScore ?? 0} size={220} />
            </div>
          </div>
        </div>
      </section>

      <section className="mb-12">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="animate-fade-in" style={{ animationDelay: "100ms" }}>
            <StatCard
              title="Active Devices"
              value={activeDevices}
              subtitle="Online now"
              icon={Wifi}
              trend="neutral"
              trendValue="Live"
              variant="success"
            />
          </div>
          <div className="animate-fade-in" style={{ animationDelay: "200ms" }}>
            <StatCard
              title="Network Traffic"
              value={networkTraffic}
              subtitle="Total Traffic"
              icon={Activity}
              trend="up"
              trendValue="Live"
            />
          </div>
          <div className="animate-fade-in" style={{ animationDelay: "300ms" }}>
            <StatCard
              title="Threats Detected"
              value={recentThreats}
              subtitle="All time"
              icon={Shield}
              trend="neutral"
              trendValue="Log"
              variant={recentThreats > 0 ? "warning" : "success"}
            />
          </div>
          <div className="animate-fade-in" style={{ animationDelay: "400ms" }}>
            <StatCard
              title="Critical Alerts"
              value={criticalAlerts}
              subtitle="Requires attention"
              icon={AlertTriangle}
              trend={criticalAlerts > 0 ? "up" : "neutral"}
              trendValue={criticalAlerts > 0 ? "Action Req" : "Safe"}
              variant={criticalAlerts > 0 ? "danger" : "success"}
            />
          </div>
        </div>
      </section>

      <section>
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-2xl font-display font-bold text-foreground">
              Security Modules
            </h2>
            <p className="text-sm text-muted-foreground">
              Access all defense systems and monitoring tools
            </p>
          </div>
          <Activity className="w-6 h-6 text-primary animate-pulse-slow" />
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          <div className="animate-fade-in" style={{ animationDelay: "100ms" }}>
            <FeatureCard
              title="Network Topology"
              description="Interactive visualization of all connected nodes and their security status"
              icon={Network}
              href="/topology"
              variant="primary"
            />
          </div>
          <div className="animate-fade-in" style={{ animationDelay: "150ms" }}>
            <FeatureCard
              title="Device Inventory"
              description="Complete database of hardware assets with risk assessment and vendor data"
              icon={HardDrive}
              href="/inventory"
              variant="secondary"
            />
          </div>
          <div className="animate-fade-in" style={{ animationDelay: "200ms" }}>
            <FeatureCard
              title="Intruder Alert Feed"
              description="Real-time threat timeline with severity filtering and incident tracking"
              icon={AlertTriangle}
              href="/intruder-feed"
              variant="danger"
              badge={`${criticalAlerts} Critical`}
            />
          </div>
          <div className="animate-fade-in" style={{ animationDelay: "250ms" }}>
            <FeatureCard
              title="Scan Engine"
              description="Automated vulnerability detection with customizable scan profiles"
              icon={Scan}
              href="/scan-engine"
              variant="primary"
            />
          </div>
          <div className="animate-fade-in" style={{ animationDelay: "300ms" }}>
            <FeatureCard
              title="AI Security Analyst"
              description="Machine learning powered threat analysis and recommendations"
              icon={Brain}
              href="/ai-report"
              variant="accent"
              badge="Beta"
            />
          </div>
          <div className="animate-fade-in" style={{ animationDelay: "350ms" }}>
            <FeatureCard
              title="Quarantine Kill Switch"
              description="Emergency network isolation with comprehensive audit logging"
              icon={ShieldOff}
              href="/quarantine"
              variant="danger"
            />
          </div>
          <div className="animate-fade-in" style={{ animationDelay: "400ms" }}>
            <FeatureCard
              title="Admin Login Center"
              description="Centralized device administration portal with secure access"
              icon={Key}
              href="/admin-center"
              variant="secondary"
            />
          </div>
        </div>
      </section>
    </Layout>
  );
};

export default Index;

