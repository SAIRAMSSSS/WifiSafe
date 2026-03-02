import { Layout } from "@/components/layout/Layout";
import { useState, useEffect } from "react";
import { cn } from "@/lib/utils";
import { Play, Pause, RotateCcw, AlertTriangle, Shield, Clock, Target, FileDown, Loader2, Scan as ScanIcon } from "lucide-react";
import { useSocket } from "@/lib/socket";
import { scanAPI, reportAPI } from "@/lib/api";
import { useDevices } from "@/lib/hooks";

interface Vulnerability {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low";
  cve?: string;
  host: string;
  port?: number;
  description: string;
}

const ScanEngine = () => {
  const { fetchDevices } = useDevices();
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanPhase, setScanPhase] = useState("Idle");
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [scanStats, setScanStats] = useState({
    devicesScanned: 0,
    vulnerabilitiesFound: 0,
    portsChecked: 0,
    estimatedTimeLeft: "0:00"
  });
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);
  const [scanComplete, setScanComplete] = useState(false);
  const [isGeneratingPDF, setIsGeneratingPDF] = useState(false);

  const socket = useSocket();

  const downloadPDF = async () => {
    if (isScanning || isGeneratingPDF) return;

    setIsGeneratingPDF(true);
    try {
      const { data } = await reportAPI.getScanReport();

      if (!data.success) {
        const errorMsg = data.abortReason
          ? `${data.message}\n\nReason: ${data.abortReason}`
          : data.message || 'No completed scan found. Run a full scan first.';
        alert(errorMsg);
        setIsGeneratingPDF(false);
        return;
      }

      const filename = data.pdfFilename || `BlackCodex_RealTime_Scan_Report_${data.scanSummary?.scanId || 'unknown'}.pdf`;

      const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <title>Black Codex Security Report</title>
  <style>
    @media print { body { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #e6edf3; padding: 40px; }
    .header { text-align: center; margin-bottom: 40px; border-bottom: 2px solid #ff3366; padding-bottom: 20px; }
    .header h1 { color: #ff3366; font-size: 28px; margin-bottom: 5px; }
    .header p { color: #8b949e; font-size: 12px; }
    .section { margin-bottom: 30px; page-break-inside: avoid; }
    .section h2 { color: #ff3366; font-size: 18px; margin-bottom: 15px; border-left: 4px solid #ff3366; padding-left: 10px; }
    .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px; }
    .summary-card { background: #161b22; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #30363d; }
    .summary-card h3 { font-size: 28px; color: #ff3366; }
    .summary-card p { font-size: 11px; color: #8b949e; margin-top: 5px; }
    table { width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 11px; }
    th { background: #161b22; color: #ff3366; padding: 10px; text-align: left; border: 1px solid #30363d; }
    td { padding: 8px 10px; border: 1px solid #30363d; background: #0d1117; }
    .critical { color: #ff4444; font-weight: bold; }
    .high { color: #ff8800; }
    .medium { color: #ffcc00; }
    .low { color: #00ff88; }
    .safe { color: #00ff88; }
    .footer { margin-top: 40px; text-align: center; color: #8b949e; font-size: 10px; border-top: 1px solid #30363d; padding-top: 20px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>🛡️ Black Codex Security Report</h1>
    <p>Generated: ${data.generatedAt} | Scan ID: ${data.scanSummary.scanId}</p>
  </div>
  
  <div class="section">
    <h2>📊 Scan Summary</h2>
    <div class="summary-grid">
      <div class="summary-card">
        <h3>${data.scanSummary.securityScore}</h3>
        <p>Security Score</p>
      </div>
      <div class="summary-card">
        <h3 class="${data.scanSummary.riskClassification.toLowerCase()}">${data.scanSummary.riskClassification}</h3>
        <p>Risk Level</p>
      </div>
      <div class="summary-card">
        <h3>${data.scanSummary.totalDevices}</h3>
        <p>Devices Found</p>
      </div>
      <div class="summary-card">
        <h3>${data.scanSummary.vulnerabilitiesFound}</h3>
        <p>Vulnerabilities</p>
      </div>
    </div>
  </div>
  
  <div class="section">
    <h2>📱 Device Status</h2>
    <table>
      <tr><th>IP Address</th><th>Name</th><th>Category</th><th>Status</th><th>Risk Level</th></tr>
      ${data.devices.map((d: any) => `
        <tr>
          <td>${d.ip || d.ipAddress}</td>
          <td>${d.name || d.deviceName || 'Unknown'}</td>
          <td>${d.category}</td>
          <td>${d.status}</td>
          <td class="${(d.riskLevel || 'unknown').toLowerCase()}">${d.riskLevel}</td>
        </tr>
      `).join('')}
    </table>
  </div>
  
  <div class="section">
    <h2>⚠️ Vulnerabilities</h2>
    ${data.vulnerabilities.length > 0 ? `
    <table>
      <tr><th>CVE ID</th><th>Name</th><th>Severity</th><th>Affected Device</th><th>Mitigation</th></tr>
      ${data.vulnerabilities.slice(0, 20).map((v: any) => `
        <tr>
          <td>${v.cveId}</td>
          <td>${v.vulnerabilityName || 'N/A'}</td>
          <td class="${v.severity}">${v.severity}</td>
          <td>${v.affectedIP}</td>
          <td>${v.mitigation?.slice(0, 50) || 'Update firmware'}...</td>
        </tr>
      `).join('')}
    </table>` : '<p style="color: #8b949e;">No vulnerabilities detected.</p>'}
  </div>
  
  <div class="section">
    <h2>📋 Conclusion</h2>
    <p><strong>Security Posture:</strong> ${data.conclusion.securityPosture}</p>
    <p style="margin-top: 10px; color: #8b949e;">${data.conclusion.riskInterpretation}</p>
    <p style="margin-top: 10px; font-style: italic; color: #8b949e;">${data.conclusion.note}</p>
  </div>
  
  <div class="footer">
    <p>Generated by Black Codex IoT Security Platform</p>
    <p>${data.integrityNote || 'This is a forensic snapshot. No data was modified during generation.'}</p>
    <p style="font-size: 9px; margin-top: 5px;">Scan ID: ${data.scanSummary?.scanId || 'N/A'}</p>
  </div>
</body>
</html>`;

      const printWindow = window.open('', '_blank');
      if (printWindow) {
        printWindow.document.write(htmlContent);
        printWindow.document.close();
        printWindow.focus();
        setTimeout(() => {
          printWindow.print();
        }, 500);
      }

    } catch (error: any) {
      console.error('PDF generation failed:', error);
      alert(error.response?.data?.message || 'Failed to generate PDF. Run a full scan first.');
    } finally {
      setIsGeneratingPDF(false);
    }
  };

  useEffect(() => {
    const loadScanStatus = async () => {
      try {
        const { data } = await scanAPI.getStatus();
        if (data.status === 'running') {
          setIsScanning(true);
          setScanProgress(data.progress || 0);
          setScanPhase(data.message || "Scanning...");
          setCurrentScanId(data.id);
          if (data.devicesScanned || data.portsChecked || data.vulnsFound) {
            setScanStats({
              devicesScanned: data.devicesScanned || 0,
              vulnerabilitiesFound: data.vulnsFound || 0,
              portsChecked: data.portsChecked || 0,
              estimatedTimeLeft: data.timeLeft || "0:00"
            });
          }
        }
      } catch (error) {
        console.error('Failed to load scan status:', error);
      }
    };

    loadScanStatus();
  }, []);

  useEffect(() => {
    if (!socket) return;

    const handleScanProgress = (data: {
      progress: number;
      message: string;
      devicesScanned?: number;
      portsChecked?: number;
      vulnsFound?: number;
      timeLeft?: string;
    }) => {
      console.log('[SCAN PROGRESS]', { progress: data.progress, devicesScanned: data.devicesScanned, portsChecked: data.portsChecked, vulnsFound: data.vulnsFound });
      setScanProgress(data.progress);
      setScanPhase(data.message);
      setScanStats(prev => ({
        ...prev,
        devicesScanned: data.devicesScanned ?? prev.devicesScanned,
        vulnerabilitiesFound: data.vulnsFound ?? prev.vulnerabilitiesFound,
        portsChecked: data.portsChecked ?? prev.portsChecked,
        estimatedTimeLeft: data.timeLeft ?? prev.estimatedTimeLeft
      }));
    };

    const handleScanComplete = (data: {
      result: {
        total?: number;
        online?: number;
        critical?: number;
        high?: number;
        medium?: number;
        low?: number;
        safe?: number;
        vulnerabilities?: Vulnerability[];
        summary?: any;
        portsChecked?: number;
      },
      vulnerabilities?: Vulnerability[]
    }) => {
      try {
        console.log("Scan Complete Data:", data);
        setIsScanning(false);
        setScanProgress(100);

        const vulns = data.vulnerabilities || (data.result && data.result.vulnerabilities) || [];
        setScanPhase(`Scan complete (${vulns.length} vulnerabilities)`);

        if (data.result) {
          const summary = data.result.summary || data.result;
          const devicesCount = summary.total || summary.online || 0;
          const vulnsCount = (summary.critical || 0) + (summary.high || 0) + (summary.medium || 0) + (summary.low || 0);
          const portsCount = summary.portsChecked || (devicesCount * 10);

          console.log("Setting stats:", { devicesCount, vulnsCount, portsCount });

          setScanStats({
            devicesScanned: devicesCount,
            vulnerabilitiesFound: vulnsCount || vulns.length,
            portsChecked: portsCount,
            estimatedTimeLeft: "0:00"
          });
        }

        setVulnerabilities(vulns);
        setCurrentScanId(null);
        fetchDevices();
      } catch (err: any) {
        console.error("Scan Complete Error:", err);
        setScanPhase(`Error: ${err.message}`);
        setIsScanning(false);
      }
    };

    const handleScanFailed = (data: { error: string }) => {
      setIsScanning(false);
      setScanPhase(`Scan failed: ${data.error}`);
      setCurrentScanId(null);
    };

    const handleScanCancelled = () => {
      setIsScanning(false);
      setScanPhase("Scan cancelled");
      setCurrentScanId(null);
    };

    const handleVulnerabilityFound = (data: {
      vulnerability: Vulnerability;
      totalVulns: number;
    }) => {
      console.log('[REAL-TIME] Vulnerability found:', data.vulnerability);
      setVulnerabilities(prev => {
        if (prev.some(v => v.id === data.vulnerability.id)) return prev;
        return [...prev, data.vulnerability];
      });
      setScanStats(prev => ({
        ...prev,
        vulnerabilitiesFound: data.totalVulns
      }));
    };

    socket.on('scan_progress', handleScanProgress);
    socket.on('scan_complete', handleScanComplete);
    socket.on('scan_failed', handleScanFailed);
    socket.on('scan_cancelled', handleScanCancelled);
    socket.on('vulnerability_found', handleVulnerabilityFound);

    const handleScanChannel = (data: any) => {
      if (data.type === 'scan_progress') {
        handleScanProgress(data);
      } else if (data.type === 'scan_complete') {
        handleScanComplete(data);
      } else if (data.type === 'vulnerability_found' && data.vulnerability) {
        handleVulnerabilityFound(data);
      }
    };
    socket.on('scan', handleScanChannel);

    return () => {
      socket.off('scan_progress', handleScanProgress);
      socket.off('scan_complete', handleScanComplete);
      socket.off('scan_failed', handleScanFailed);
      socket.off('scan_cancelled', handleScanCancelled);
      socket.off('vulnerability_found', handleVulnerabilityFound);
      socket.off('scan', handleScanChannel);
    };
  }, [socket]);

  const startScan = async () => {
    try {
      setIsScanning(true);
      setScanProgress(0);
      setVulnerabilities([]);
      setScanStats({
        devicesScanned: 0,
        vulnerabilitiesFound: 0,
        portsChecked: 0,
        estimatedTimeLeft: "0:00"
      });
      setScanPhase("Initializing scan engine...");

      const { data } = await scanAPI.startScan({ type: 'full' });
      setCurrentScanId(data.scanId);
      setScanPhase("Scan started successfully");
    } catch (error: any) {
      console.error('Failed to start scan:', error);
      const errorMessage = error.response?.data?.error || error.message || 'Unknown error';

      if (errorMessage.includes('already in progress')) {
        const scanId = error.response?.data?.scanId;
        if (scanId) {
          setCurrentScanId(scanId);
        }
        try {
          const { data: statusData } = await scanAPI.getStatus();
          if (statusData.status === 'running') {
            setScanProgress(statusData.progress || 0);
            setScanPhase(statusData.message || "Scanning...");
          } else {
            setIsScanning(false);
            setScanPhase("Previous scan completed. Click Start to begin a new scan.");
          }
        } catch {
          setIsScanning(false);
          setScanPhase(errorMessage);
        }
      } else {
        setIsScanning(false);
        setScanPhase(`Failed to start scan: ${errorMessage}`);
      }
    }
  };

  const pauseScan = () => {
    setIsScanning(false);
  };

  const resetScan = () => {
    setIsScanning(false);
    setScanProgress(0);
    setVulnerabilities([]);
    setScanPhase("Idle");
    setScanStats({
      devicesScanned: 0,
      vulnerabilitiesFound: 0,
      portsChecked: 0,
      estimatedTimeLeft: "0:00"
    });
    setCurrentScanId(null);
  };

  const getSeverityStyles = (severity: Vulnerability["severity"]) => {
    const styles = {
      critical: "bg-destructive/20 text-destructive border-destructive/50",
      high: "bg-orange-500/20 text-orange-500 border-orange-500/50",
      medium: "bg-warning/20 text-warning border-warning/50",
      low: "bg-secondary/20 text-secondary border-secondary/50",
    };
    return styles[severity];
  };

  const circumference = 2 * Math.PI * 90;
  const offset = circumference - (scanProgress / 100) * circumference;

  return (
    <Layout>
      <div className="mb-6 animate-fade-in">
        <h1 className="text-3xl font-display font-bold text-foreground mb-2">
          Vulnerability Scan Engine
        </h1>
        <p className="text-muted-foreground">
          Automated vulnerability detection with customizable scan profiles
        </p>
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        <div className="glass-panel-glow p-8 animate-fade-in" style={{ animationDelay: "100ms" }}>
          <div className="flex flex-col items-center">
            <div className="relative w-64 h-64 mb-8">
              <svg className="w-full h-full transform -rotate-90">
                <circle
                  cx="128"
                  cy="128"
                  r="90"
                  strokeWidth="12"
                  fill="none"
                  className="stroke-muted"
                />
                <circle
                  cx="128"
                  cy="128"
                  r="90"
                  strokeWidth="12"
                  fill="none"
                  className={cn(
                    "transition-all duration-300",
                    scanProgress >= 100 ? "stroke-success" : "stroke-primary"
                  )}
                  strokeLinecap="round"
                  strokeDasharray={circumference}
                  strokeDashoffset={offset}
                  style={{
                    filter: `drop-shadow(0 0 10px ${scanProgress >= 100 ? "hsl(160 100% 50% / 0.5)" : "hsl(160 100% 50% / 0.5)"})`,
                  }}
                />
                <circle
                  cx="128"
                  cy="128"
                  r="90"
                  strokeWidth="16"
                  fill="none"
                  className={cn(
                    "transition-all duration-300",
                    scanProgress >= 100 ? "stroke-success" : "stroke-primary"
                  )}
                  strokeLinecap="round"
                  strokeDasharray={circumference}
                  strokeDashoffset={offset}
                  opacity={0.2}
                />
              </svg>

              <div className="absolute inset-0 flex flex-col items-center justify-center">
                {isScanning ? (
                  <Target className="w-12 h-12 text-primary animate-spin-slow mb-2" />
                ) : scanProgress >= 100 ? (
                  <Shield className="w-12 h-12 text-success mb-2" />
                ) : (
                  <ScanIcon className="w-12 h-12 text-muted-foreground mb-2" />
                )}
                <span className="text-4xl font-display font-bold text-foreground">
                  {Math.round(scanProgress)}%
                </span>
              </div>
            </div>

            <div className="text-center mb-8">
              <p className="text-sm text-muted-foreground uppercase tracking-wider mb-2">
                Status
              </p>
              <p className={cn(
                "font-mono text-lg",
                isScanning ? "text-primary animate-pulse" : scanProgress >= 100 ? "text-success" : "text-muted-foreground"
              )}>
                {scanPhase}
              </p>
            </div>

            <div className="flex gap-4 flex-wrap justify-center">
              {!isScanning && scanProgress === 0 && (
                <button
                  onClick={startScan}
                  className="px-6 py-3 bg-primary text-primary-foreground rounded-lg font-display uppercase tracking-wider flex items-center gap-2 hover:bg-primary/90 transition-all neon-border"
                >
                  <Play className="w-5 h-5" />
                  Start Scan
                </button>
              )}
              {isScanning && (
                <button
                  onClick={pauseScan}
                  className="px-6 py-3 bg-warning text-warning-foreground rounded-lg font-display uppercase tracking-wider flex items-center gap-2 hover:bg-warning/90 transition-all"
                >
                  <Pause className="w-5 h-5" />
                  Pause
                </button>
              )}
              {!isScanning && scanProgress > 0 && scanProgress < 100 && (
                <button
                  onClick={() => setIsScanning(true)}
                  className="px-6 py-3 bg-primary text-primary-foreground rounded-lg font-display uppercase tracking-wider flex items-center gap-2 hover:bg-primary/90 transition-all"
                >
                  <Play className="w-5 h-5" />
                  Resume
                </button>
              )}
              {scanProgress > 0 && (
                <button
                  onClick={resetScan}
                  className="px-6 py-3 bg-muted text-muted-foreground rounded-lg font-display uppercase tracking-wider flex items-center gap-2 hover:bg-muted/80 transition-all"
                >
                  <RotateCcw className="w-5 h-5" />
                  Reset
                </button>
              )}
              <button
                onClick={downloadPDF}
                disabled={isScanning || isGeneratingPDF}
                className={cn(
                  "px-6 py-3 rounded-lg font-display uppercase tracking-wider flex items-center gap-2 transition-all",
                  isScanning || isGeneratingPDF
                    ? "bg-muted/50 text-muted-foreground cursor-not-allowed"
                    : "bg-secondary text-secondary-foreground hover:bg-secondary/90"
                )}
                title={isScanning ? "Wait for scan to complete" : "Download PDF Report"}
              >
                {isGeneratingPDF ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : (
                  <FileDown className="w-5 h-5" />
                )}
                {isGeneratingPDF ? "Generating..." : "Download PDF"}
              </button>
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-4">
            <div className="glass-panel p-4 animate-fade-in" style={{ animationDelay: "200ms" }}>
              <div className="flex items-center gap-3">
                <Target className="w-8 h-8 text-primary" />
                <div>
                  <p className="text-2xl font-display font-bold text-foreground">{scanStats.devicesScanned}</p>
                  <p className="text-xs text-muted-foreground uppercase">Hosts Scanned</p>
                </div>
              </div>
            </div>
            <div className="glass-panel p-4 animate-fade-in" style={{ animationDelay: "250ms" }}>
              <div className="flex items-center gap-3">
                <AlertTriangle className="w-8 h-8 text-destructive" />
                <div>
                  <p className="text-2xl font-display font-bold text-foreground">{scanStats.vulnerabilitiesFound}</p>
                  <p className="text-xs text-muted-foreground uppercase">Vulnerabilities</p>
                </div>
              </div>
            </div>
            <div className="glass-panel p-4 animate-fade-in" style={{ animationDelay: "300ms" }}>
              <div className="flex items-center gap-3">
                <Clock className="w-8 h-8 text-secondary" />
                <div>
                  <p className="text-2xl font-display font-bold text-foreground">{scanStats.estimatedTimeLeft}</p>
                  <p className="text-xs text-muted-foreground uppercase">Est. Time Left</p>
                </div>
              </div>
            </div>
            <div className="glass-panel p-4 animate-fade-in" style={{ animationDelay: "350ms" }}>
              <div className="flex items-center gap-3">
                <Shield className="w-8 h-8 text-success" />
                <div>
                  <p className="text-2xl font-display font-bold text-foreground">{scanStats.portsChecked.toLocaleString()}</p>
                  <p className="text-xs text-muted-foreground uppercase">Ports Checked</p>
                </div>
              </div>
            </div>
          </div>


          <div className="glass-panel p-6 animate-fade-in" style={{ animationDelay: "400ms" }}>
            <h3 className="text-lg font-display font-semibold text-foreground mb-4">
              Vulnerabilities Detected
            </h3>

            {vulnerabilities.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                {isScanning ? (
                  "Scanning for vulnerabilities..."
                ) : scanProgress >= 100 ? (
                  <div className="flex flex-col items-center gap-2">
                    <Shield className="w-8 h-8 text-success opacity-50" />
                    <p>No vulnerabilities detected</p>
                  </div>
                ) : (
                  "Start a scan to detect vulnerabilities"
                )}
              </div>
            ) : (
              <div className="space-y-3">
                {vulnerabilities.map((vuln, index) => (
                  <div
                    key={vuln.id}
                    className={cn(
                      "p-4 rounded-lg border animate-fade-in",
                      getSeverityStyles(vuln.severity)
                    )}
                    style={{ animationDelay: `${index * 100}ms` }}
                  >
                    <div className="flex items-start justify-between mb-2">
                      <h4 className="font-semibold">{vuln.name}</h4>
                      <span className="text-xs uppercase tracking-wider px-2 py-0.5 rounded-full bg-background/50">
                        {vuln.severity}
                      </span>
                    </div>
                    <p className="text-sm opacity-80 mb-2">{vuln.description}</p>
                    <div className="flex flex-wrap gap-4 text-xs opacity-70">
                      {vuln.cve && <span className="font-mono bg-background/30 px-1 rounded">{vuln.cve}</span>}
                      <span className="font-mono bg-background/30 px-1 rounded">
                        Host: {vuln.host}{vuln.port ? `:${vuln.port}` : ''}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
};

const Scan = ({ className }: { className?: string }) => (
  <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M3 7V5a2 2 0 0 1 2-2h2" />
    <path d="M17 3h2a2 2 0 0 1 2 2v2" />
    <path d="M21 17v2a2 2 0 0 1-2 2h-2" />
    <path d="M7 21H5a2 2 0 0 1-2-2v-2" />
    <line x1="7" y1="12" x2="17" y2="12" />
  </svg>
);

export default ScanEngine;

