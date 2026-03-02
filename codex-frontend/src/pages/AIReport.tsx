import { Layout } from "@/components/layout/Layout";
import { useState, useEffect } from "react";
import { cn } from "@/lib/utils";
import { Brain, ChevronDown, Sparkles, AlertTriangle, Shield, TrendingUp, Loader2, Network, Clock, Wifi, Info } from "lucide-react";
import { useDevices } from "@/lib/hooks";
import { aiAPI } from "@/lib/api";

interface Device {
  id: string;
  name: string;
  type: string;
  ip: string;
  riskScore: number;
}

interface PortAnalysis {
  port: number;
  service: string;
  status: string;
  risk: string;
  threat: string | null;
}

interface ThreatIntel {
  type: string;
  port: number;
  service: string;
  severity: string;
  description: string;
  recommendation: string;
}

interface Recommendation {
  priority: string;
  action: string;
  details: string;
  howTo?: string;
  steps?: string[];
}

interface RealTimeFindings {
  scannedAt: string;
  openPortsDiscovered: number;
  cvesMatched: number;
  livePortList: number[];
}

interface AIAnalysis {
  summary: string;
  riskAssessment: {
    score: number;
    level: string;
    factors: string[];
  };
  threats: string[];
  recommendations: Recommendation[];
  portAnalysis: PortAnalysis[];
  threatIntelligence: ThreatIntel[];
  realTimeFindings: RealTimeFindings | null;
  prediction: string;
}

const AIReport = () => {
  const { devices: storeDevices, fetchDevices } = useDevices();
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysis, setAnalysis] = useState<AIAnalysis | null>(null);
  const [dropdownOpen, setDropdownOpen] = useState(false);

  useEffect(() => {
    fetchDevices();
  }, [fetchDevices]);

  const devices: Device[] = storeDevices.map((d: any) => ({
    id: d.id,
    name: d.name,
    type: d.device_type || d.type || 'Unknown',
    ip: d.ip,
    riskScore: d.risk_score || 0
  }));

  const handleDeviceSelect = async (device: Device) => {
    setSelectedDevice(device);
    setDropdownOpen(false);
    setIsAnalyzing(true);
    setAnalysis(null);

    try {
      const { data } = await aiAPI.analyze(device.ip);
      const apiAnalysis = data;

      let prediction = "Based on current analysis:";
      if (apiAnalysis.realTimeFindings?.openPortsDiscovered > 5) {
        prediction += ` High attack surface with ${apiAnalysis.realTimeFindings.openPortsDiscovered} open ports detected.`;
      }
      if (apiAnalysis.vulnerabilities?.critical > 0) {
        prediction += ` Critical vulnerabilities present - likelihood of exploitation is HIGH.`;
      } else if (apiAnalysis.vulnerabilities?.high > 0) {
        prediction += ` High-severity vulnerabilities detected - elevated risk of compromise.`;
      } else {
        prediction += ` Device shows acceptable security posture. Continue monitoring.`;
      }

      setAnalysis({
        summary: apiAnalysis.summary,
        riskAssessment: {
          score: apiAnalysis.riskAssessment?.score || 0,
          level: apiAnalysis.riskAssessment?.level || 'unknown',
          factors: apiAnalysis.riskAssessment?.factors || []
        },
        threats: apiAnalysis.vulnerabilities?.details?.map((v: any) =>
          `${v.severity?.toUpperCase() || 'UNKNOWN'}: ${v.title || v.cveId || 'Unknown vulnerability'}`
        ) || [],
        recommendations: apiAnalysis.recommendations || [],
        portAnalysis: apiAnalysis.portAnalysis || [],
        threatIntelligence: apiAnalysis.threatIntelligence || [],
        realTimeFindings: apiAnalysis.realTimeFindings || null,
        prediction
      });

      setSelectedDevice({
        ...device,
        riskScore: apiAnalysis.riskAssessment?.score || device.riskScore
      });

    } catch (error) {
      console.error("Analysis failed:", error);
      setAnalysis({
        summary: "Failed to generate analysis.",
        riskAssessment: { score: 0, level: 'unknown', factors: ['Error connecting to analysis service'] },
        threats: [],
        recommendations: [{ priority: 'high', action: 'Retry analysis', details: 'The analysis service is temporarily unavailable.' }],
        portAnalysis: [],
        threatIntelligence: [],
        realTimeFindings: null,
        prediction: "Unable to generate prediction due to analysis failure."
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <Layout>
      <div className="mb-6 animate-fade-in">
        <div className="flex items-center gap-3 mb-2">
          <h1 className="text-3xl font-display font-bold text-foreground">
            AI Security Analyst
          </h1>
          <span className="px-2 py-0.5 text-[10px] uppercase tracking-wider bg-accent/20 text-accent rounded-full border border-accent/30">
            Beta
          </span>
        </div>
        <p className="text-muted-foreground">
          Machine learning powered threat analysis and security recommendations
        </p>
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1 space-y-6">
          <div className="glass-panel p-6 animate-fade-in relative z-20" style={{ animationDelay: "100ms" }}>
            <div className="flex items-center gap-3 mb-4">
              <Brain className="w-6 h-6 text-accent" />
              <h2 className="text-lg font-display font-semibold text-foreground">
                Select Device
              </h2>
            </div>

            <div className="relative">
              <button
                onClick={() => setDropdownOpen(!dropdownOpen)}
                className="w-full px-4 py-3 bg-input border border-border rounded-lg text-left flex items-center justify-between hover:border-primary/50 transition-colors"
              >
                <span className={cn(
                  selectedDevice ? "text-foreground" : "text-muted-foreground"
                )}>
                  {selectedDevice ? selectedDevice.name : "Choose a device..."}
                </span>
                <ChevronDown className={cn(
                  "w-5 h-5 text-muted-foreground transition-transform",
                  dropdownOpen && "rotate-180"
                )} />
              </button>

              {dropdownOpen && (
                <div className="absolute top-full left-0 right-0 mt-2 glass-panel border border-border rounded-lg overflow-hidden z-50 animate-fade-in max-h-80 overflow-y-auto shadow-xl">
                  {devices.map((device) => (
                    <button
                      key={device.id}
                      onClick={() => handleDeviceSelect(device)}
                      className="w-full px-4 py-3 text-left hover:bg-muted/50 transition-colors border-b border-border/30 last:border-0"
                    >
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-foreground font-medium">{device.name}</p>
                          <p className="text-xs text-muted-foreground font-mono">{device.ip}</p>
                        </div>
                        <span className={cn(
                          "text-xs font-mono px-2 py-0.5 rounded-full",
                          device.riskScore >= 80 && "bg-destructive/20 text-destructive",
                          device.riskScore >= 50 && device.riskScore < 80 && "bg-warning/20 text-warning",
                          device.riskScore < 50 && "bg-success/20 text-success"
                        )}>
                          {device.riskScore}
                        </span>
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {selectedDevice && !dropdownOpen && (
            <div className="glass-panel p-6 animate-fade-in relative z-10" style={{ animationDelay: "200ms" }}>
              <h3 className="text-sm font-display uppercase tracking-wider text-muted-foreground mb-4">
                Device Overview
              </h3>
              <div className="space-y-3">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Type</span>
                  <span className="text-foreground">{selectedDevice.type}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">IP Address</span>
                  <span className="text-foreground font-mono">{selectedDevice.ip}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Risk Score</span>
                  <span className={cn(
                    "font-bold",
                    selectedDevice.riskScore >= 80 && "text-destructive",
                    selectedDevice.riskScore >= 50 && selectedDevice.riskScore < 80 && "text-warning",
                    selectedDevice.riskScore < 50 && "text-success"
                  )}>
                    {selectedDevice.riskScore}/100
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="lg:col-span-2">
          {!selectedDevice && (
            <div className="glass-panel p-12 text-center animate-fade-in" style={{ animationDelay: "100ms" }}>
              <Brain className="w-16 h-16 text-accent/50 mx-auto mb-4" />
              {devices.length === 0 ? (
                <>
                  <h3 className="text-xl font-display font-semibold text-foreground mb-2">
                    No Devices Analyzed Yet
                  </h3>
                  <p className="text-muted-foreground max-w-md mx-auto mb-4">
                    Run a full scan to discover devices on your network before using the AI Analyst.
                  </p>
                  <a
                    href="/scan-engine"
                    className="inline-flex items-center gap-2 px-4 py-2 bg-primary/20 text-primary rounded-lg hover:bg-primary/30 transition-colors"
                  >
                    Go to Scan Engine →
                  </a>
                </>
              ) : (
                <>
                  <h3 className="text-xl font-display font-semibold text-foreground mb-2">
                    AI Analysis Ready
                  </h3>
                  <p className="text-muted-foreground max-w-md mx-auto">
                    Select a device from the list to generate an AI-powered security analysis with threat predictions and recommendations.
                  </p>
                </>
              )}
            </div>
          )}

          {isAnalyzing && (
            <div className="glass-panel-glow p-12 text-center animate-fade-in">
              <div className="relative w-20 h-20 mx-auto mb-6">
                <Loader2 className="w-20 h-20 text-accent animate-spin" />
                <Sparkles className="w-8 h-8 text-accent absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2" />
              </div>
              <h3 className="text-xl font-display font-semibold text-foreground mb-2">
                Analyzing Device
              </h3>
              <p className="text-muted-foreground">
                Running neural network analysis on {selectedDevice?.name}...
              </p>
            </div>
          )}

          {analysis && !isAnalyzing && (
            <div className="space-y-6 animate-fade-in">
              {analysis.realTimeFindings && (
                <div className="flex items-center gap-2 text-xs text-muted-foreground bg-muted/30 px-3 py-2 rounded-lg">
                  <Clock className="w-4 h-4 text-accent" />
                  <span>Live scan completed at {new Date(analysis.realTimeFindings.scannedAt).toLocaleTimeString()}</span>
                  <span className="text-accent font-mono">• {analysis.realTimeFindings.openPortsDiscovered} ports • {analysis.realTimeFindings.cvesMatched} CVEs matched</span>
                </div>
              )}

              <div className="glass-panel-glow p-6">
                <div className="flex items-start gap-4">
                  <div className={cn(
                    "p-3 rounded-lg",
                    analysis.riskAssessment.level === 'critical' && "bg-destructive/20 text-destructive",
                    analysis.riskAssessment.level === 'high' && "bg-orange-500/20 text-orange-500",
                    analysis.riskAssessment.level === 'medium' && "bg-warning/20 text-warning",
                    (analysis.riskAssessment.level === 'low' || analysis.riskAssessment.level === 'safe') && "bg-success/20 text-success",
                    analysis.riskAssessment.level === 'unknown' && "bg-accent/20 text-accent"
                  )}>
                    <Sparkles className="w-6 h-6" />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <h3 className="text-lg font-display font-semibold text-foreground">
                        AI Summary
                      </h3>
                      <span className={cn(
                        "px-2 py-0.5 text-[10px] uppercase tracking-wider rounded-full border font-bold",
                        analysis.riskAssessment.level === 'critical' && "bg-destructive/20 text-destructive border-destructive/30",
                        analysis.riskAssessment.level === 'high' && "bg-orange-500/20 text-orange-500 border-orange-500/30",
                        analysis.riskAssessment.level === 'medium' && "bg-warning/20 text-warning border-warning/30",
                        (analysis.riskAssessment.level === 'low' || analysis.riskAssessment.level === 'safe') && "bg-success/20 text-success border-success/30",
                        analysis.riskAssessment.level === 'unknown' && "bg-muted/20 text-muted-foreground border-muted-foreground/30"
                      )}>
                        {analysis.riskAssessment.level} risk
                      </span>
                      <span className="text-xs font-mono text-muted-foreground">
                        Score: {analysis.riskAssessment.score}/100
                      </span>
                    </div>
                    <p className="text-foreground leading-relaxed">
                      {analysis.summary}
                    </p>
                  </div>
                </div>
              </div>

              {analysis.riskAssessment.factors.length > 0 && (
                <div className="glass-panel p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <Shield className="w-5 h-5 text-secondary" />
                    <h3 className="text-lg font-display font-semibold text-foreground">
                      Risk Factors
                    </h3>
                  </div>
                  <ul className="space-y-2">
                    {analysis.riskAssessment.factors.map((factor, index) => (
                      <li key={index} className="flex items-start gap-2 text-muted-foreground text-sm">
                        <AlertTriangle className="w-4 h-4 text-warning mt-0.5 flex-shrink-0" />
                        {factor}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {analysis.portAnalysis.length > 0 && (
                <div className="glass-panel p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <Network className="w-5 h-5 text-accent" />
                    <h3 className="text-lg font-display font-semibold text-foreground">
                      Open Ports ({analysis.portAnalysis.length})
                    </h3>
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                    {analysis.portAnalysis.map((port, index) => (
                      <div key={index} className={cn(
                        "px-3 py-2 rounded-lg border text-sm",
                        port.risk === 'critical' && "bg-destructive/10 border-destructive/30",
                        port.risk === 'high' && "bg-orange-500/10 border-orange-500/30",
                        port.risk === 'medium' && "bg-warning/10 border-warning/30",
                        port.risk === 'low' && "bg-muted/30 border-border"
                      )}>
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-foreground">{port.port}</span>
                          <span className={cn(
                            "text-[10px] uppercase px-1.5 py-0.5 rounded",
                            port.risk === 'critical' && "bg-destructive/20 text-destructive",
                            port.risk === 'high' && "bg-orange-500/20 text-orange-500",
                            port.risk === 'medium' && "bg-warning/20 text-warning",
                            port.risk === 'low' && "bg-muted/50 text-muted-foreground"
                          )}>
                            {port.risk}
                          </span>
                        </div>
                        <div className="text-xs text-muted-foreground">{port.service}</div>
                        {port.threat && (
                          <div className="text-[11px] text-warning/80 mt-1 flex items-start gap-1">
                            <Info className="w-3 h-3 mt-0.5 flex-shrink-0" />
                            {port.threat.substring(0, 60)}...
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {analysis.threats.length > 0 && (
                <div className="glass-panel p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <AlertTriangle className="w-5 h-5 text-destructive" />
                    <h3 className="text-lg font-display font-semibold text-foreground">
                      Identified Vulnerabilities ({analysis.threats.length})
                    </h3>
                  </div>
                  <ul className="space-y-2">
                    {analysis.threats.map((threat, index) => (
                      <li key={index} className="flex items-start gap-2 text-muted-foreground">
                        <span className="text-destructive mt-1">•</span>
                        {threat}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="glass-panel p-6">
                <div className="flex items-center gap-3 mb-4">
                  <TrendingUp className="w-5 h-5 text-success" />
                  <h3 className="text-lg font-display font-semibold text-foreground">
                    Security Recommendations
                  </h3>
                </div>
                <div className="space-y-4">
                  {analysis.recommendations.map((rec, index) => (
                    <div key={index} className={cn(
                      "p-4 rounded-lg border-l-4",
                      rec.priority === 'critical' && "bg-destructive/5 border-destructive",
                      rec.priority === 'high' && "bg-orange-500/5 border-orange-500",
                      rec.priority === 'medium' && "bg-warning/5 border-warning",
                      rec.priority === 'low' && "bg-muted/30 border-muted-foreground"
                    )}>
                      <div className="flex items-center gap-2 mb-1">
                        <span className={cn(
                          "text-[10px] uppercase px-1.5 py-0.5 rounded font-bold",
                          rec.priority === 'critical' && "bg-destructive/20 text-destructive",
                          rec.priority === 'high' && "bg-orange-500/20 text-orange-500",
                          rec.priority === 'medium' && "bg-warning/20 text-warning",
                          rec.priority === 'low' && "bg-muted/50 text-muted-foreground"
                        )}>
                          {rec.priority}
                        </span>
                        <span className="text-foreground font-medium">{rec.action}</span>
                      </div>
                      <p className="text-sm text-muted-foreground mb-2">{rec.details}</p>
                      {rec.howTo && (
                        <div className="text-xs text-accent/80 bg-accent/5 px-3 py-2 rounded flex items-start gap-2 mb-3">
                          <Wifi className="w-3 h-3 mt-0.5 flex-shrink-0" />
                          <span><strong>Quick tip:</strong> {rec.howTo}</span>
                        </div>
                      )}
                      {rec.steps && rec.steps.length > 0 && (
                        <div className="mt-3">
                          <p className="text-xs font-semibold uppercase tracking-wider text-success mb-2 flex items-center gap-1">
                            <Shield className="w-3 h-3" />
                            Step-by-Step Resolution
                          </p>
                          <ol className="space-y-1.5">
                            {rec.steps.map((step, i) => (
                              <li key={i} className="flex items-start gap-2 text-xs text-muted-foreground">
                                <span className="flex-shrink-0 w-5 h-5 rounded-full bg-success/20 text-success text-[10px] font-bold flex items-center justify-center mt-0.5">
                                  {i + 1}
                                </span>
                                <span className="leading-relaxed">{step}</span>
                              </li>
                            ))}
                          </ol>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              <div className="glass-panel p-6 border-l-4 border-accent">
                <div className="flex items-center gap-3 mb-2">
                  <Brain className="w-5 h-5 text-accent" />
                  <h3 className="text-sm font-display uppercase tracking-wider text-accent">
                    AI Prediction
                  </h3>
                </div>
                <p className="text-foreground italic">
                  "{analysis.prediction}"
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
};

export default AIReport;

