import { Layout } from "@/components/layout/Layout";
import { useState, useMemo, useEffect } from "react";
import { cn } from "@/lib/utils";
import { AlertTriangle, AlertCircle, Info, Shield, Clock, MapPin, Monitor, Mail, Save, X, CheckCircle, Bell } from "lucide-react";
import { useAlerts } from "@/lib/hooks";

interface Alert {
  id: string;
  timestamp: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  source: string;
  source_ip: string;
  target_ip: string;
  location: string;
  acknowledged: boolean;
}

const IntruderFeed = () => {
  const { alerts } = useAlerts();
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");

  const [alertEmail, setAlertEmail] = useState("");
  const [emailInput, setEmailInput] = useState("");
  const [emailSaving, setEmailSaving] = useState(false);
  const [emailMessage, setEmailMessage] = useState<{ type: 'success' | 'error', text: string } | null>(null);
  const [showEmailSettings, setShowEmailSettings] = useState(false);

  useEffect(() => {
    fetchEmailSettings();
  }, []);

  const fetchEmailSettings = async () => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch('http://localhost:3001/api/alerts/settings/email', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setAlertEmail(data.email || '');
        setEmailInput(data.email || '');
      }
    } catch (e) {
      console.error('Failed to fetch email settings', e);
    }
  };

  const saveEmailSettings = async () => {
    if (!emailInput || !emailInput.includes('@')) {
      setEmailMessage({ type: 'error', text: 'Please enter a valid email address' });
      return;
    }

    setEmailSaving(true);
    setEmailMessage(null);

    try {
      const token = localStorage.getItem('token');
      const res = await fetch('http://localhost:3001/api/alerts/settings/email', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ email: emailInput })
      });

      if (res.ok) {
        setAlertEmail(emailInput);
        setEmailMessage({ type: 'success', text: 'Email saved! You will receive alerts for critical vulnerabilities.' });
      } else {
        const error = await res.json();
        setEmailMessage({ type: 'error', text: error.error || 'Failed to save email' });
      }
    } catch (e) {
      setEmailMessage({ type: 'error', text: 'Failed to connect to server' });
    } finally {
      setEmailSaving(false);
    }
  };

  const clearEmailSettings = async () => {
    try {
      const token = localStorage.getItem('token');
      await fetch('http://localhost:3001/api/alerts/settings/email', {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` }
      });
      setAlertEmail('');
      setEmailInput('');
      setEmailMessage({ type: 'success', text: 'Email alerts disabled' });
    } catch (e) {
      setEmailMessage({ type: 'error', text: 'Failed to clear email' });
    }
  };

  const filteredAlerts = useMemo(() => {
    if (!Array.isArray(alerts)) return [];
    return alerts.filter((alert) => {
      const matchesSeverity = severityFilter === "all" || alert.severity === severityFilter;
      const matchesStatus = statusFilter === "all" || (alert.acknowledged ? "resolved" : "active") === statusFilter;
      return matchesSeverity && matchesStatus;
    });
  }, [alerts, severityFilter, statusFilter]);

  const getSeverityIcon = (severity: Alert["severity"]) => {
    const icons = {
      critical: AlertTriangle,
      high: AlertTriangle,
      medium: AlertCircle,
      low: Info,
      info: Info,
    };
    return icons[severity] || Info;
  };

  const getSeverityStyles = (severity: Alert["severity"]) => {
    const styles = {
      critical: "bg-destructive/20 text-destructive border-destructive/50",
      high: "bg-red-500/20 text-red-500 border-red-500/50",
      medium: "bg-warning/20 text-warning border-warning/50",
      low: "bg-secondary/20 text-secondary border-secondary/50",
      info: "bg-muted text-muted-foreground border-border",
    };
    return styles[severity] || styles.info;
  };

  const getStatusStyles = (status: string) => {
    const styles = {
      active: "bg-destructive/20 text-destructive",
      investigating: "bg-warning/20 text-warning",
      resolved: "bg-success/20 text-success",
    };
    return styles[status] || styles.active;
  };

  const severityCounts = useMemo(() => {
    if (!Array.isArray(alerts)) return { critical: 0, high: 0, medium: 0, low: 0 };
    return {
      critical: alerts.filter((a) => a.severity === "critical" && !a.acknowledged).length,
      high: alerts.filter((a) => a.severity === "high" && !a.acknowledged).length,
      medium: alerts.filter((a) => a.severity === "medium" && !a.acknowledged).length,
      low: alerts.filter((a) => a.severity === "low" && !a.acknowledged).length,
    };
  }, [alerts]);

  return (
    <Layout>
      <div className="mb-6 animate-fade-in">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-display font-bold text-foreground mb-2">
              Intruder Alert Feed
            </h1>
            <p className="text-muted-foreground">
              Real-time threat timeline with severity filtering and incident tracking
            </p>
          </div>
          <button
            onClick={() => setShowEmailSettings(!showEmailSettings)}
            className={cn(
              "flex items-center gap-2 px-4 py-2 rounded-lg transition-all",
              alertEmail
                ? "bg-success/20 text-success border border-success/30"
                : "bg-muted/50 text-muted-foreground hover:bg-muted border border-border"
            )}
          >
            <Bell className="w-4 h-4" />
            <span className="text-sm">
              {alertEmail ? 'Alerts Enabled' : 'Enable Email Alerts'}
            </span>
          </button>
        </div>
      </div>

      {showEmailSettings && (
        <div className="glass-panel-glow p-6 mb-6 animate-fade-in border border-primary/30">
          <div className="flex items-center gap-3 mb-4">
            <Mail className="w-5 h-5 text-primary" />
            <h3 className="text-lg font-display font-semibold text-foreground">
              Email Alert Settings
            </h3>
          </div>

          <p className="text-sm text-muted-foreground mb-4">
            Get notified instantly when critical or high-severity vulnerabilities are detected on your network.
          </p>

          <div className="flex flex-wrap gap-3 items-center">
            <input
              type="email"
              placeholder="Enter your email address"
              value={emailInput}
              onChange={(e) => setEmailInput(e.target.value)}
              className="flex-1 min-w-[250px] px-4 py-3 bg-muted/50 border border-border rounded-lg text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary transition-colors"
            />
            <button
              onClick={saveEmailSettings}
              disabled={emailSaving}
              className={cn(
                "flex items-center gap-2 px-5 py-3 rounded-lg font-display uppercase tracking-wider text-sm transition-all",
                emailSaving
                  ? "bg-muted text-muted-foreground"
                  : "bg-primary text-primary-foreground hover:bg-primary/90"
              )}
            >
              <Save className="w-4 h-4" />
              {emailSaving ? 'Saving...' : 'Save'}
            </button>
            {alertEmail && (
              <button
                onClick={clearEmailSettings}
                className="flex items-center gap-2 px-4 py-3 rounded-lg bg-destructive/20 text-destructive hover:bg-destructive/30 transition-colors"
              >
                <X className="w-4 h-4" />
                Disable
              </button>
            )}
          </div>

          {emailMessage && (
            <div className={cn(
              "mt-4 px-4 py-3 rounded-lg flex items-center gap-2 text-sm",
              emailMessage.type === 'success'
                ? "bg-success/20 text-success border border-success/30"
                : "bg-destructive/20 text-destructive border border-destructive/30"
            )}>
              {emailMessage.type === 'success' ? <CheckCircle className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
              {emailMessage.text}
            </div>
          )}

          {alertEmail && (
            <div className="mt-4 pt-4 border-t border-border">
              <div className="flex items-center gap-2 text-sm text-success">
                <CheckCircle className="w-4 h-4" />
                <span>Email alerts active for: <strong className="font-mono">{alertEmail}</strong></span>
              </div>
            </div>
          )}
        </div>
      )}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {[
          { label: "Critical", count: severityCounts.critical, color: "text-destructive bg-destructive/10 border-destructive/30" },
          { label: "High", count: severityCounts.high, color: "text-red-500 bg-red-500/10 border-red-500/30" },
          { label: "Medium", count: severityCounts.medium, color: "text-warning bg-warning/10 border-warning/30" },
          { label: "Low", count: severityCounts.low, color: "text-secondary bg-secondary/10 border-secondary/30" },
        ].map((stat, i) => (
          <div
            key={stat.label}
            className={cn("glass-panel p-4 border animate-fade-in", stat.color)}
            style={{ animationDelay: `${i * 50}ms` }}
          >
            <div className="flex items-center justify-between">
              <span className="text-sm uppercase tracking-wider">{stat.label}</span>
              <span className="text-2xl font-display font-bold">{stat.count}</span>
            </div>
          </div>
        ))}
      </div>

      <div className="glass-panel p-4 mb-6 flex flex-wrap gap-2 animate-fade-in" style={{ animationDelay: "200ms" }}>
        <div className="flex flex-wrap gap-2 mr-4">
          {["all", "critical", "high", "medium", "low", "info"].map((filter) => (
            <button
              key={filter}
              onClick={() => setSeverityFilter(filter)}
              className={cn(
                "px-3 py-1.5 text-xs uppercase tracking-wider rounded-md transition-all",
                severityFilter === filter
                  ? "bg-primary text-primary-foreground"
                  : "bg-muted/50 text-muted-foreground hover:bg-muted"
              )}
            >
              {filter}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap gap-2">
          {["all", "active", "investigating", "resolved"].map((filter) => (
            <button
              key={filter}
              onClick={() => setStatusFilter(filter)}
              className={cn(
                "px-3 py-1.5 text-xs uppercase tracking-wider rounded-md transition-all border",
                statusFilter === filter
                  ? "border-primary text-primary"
                  : "border-border text-muted-foreground hover:border-muted-foreground"
              )}
            >
              {filter}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-4">
        {filteredAlerts.map((alert, index) => {
          const Icon = getSeverityIcon(alert.severity);
          return (
            <div
              key={alert.id || index}
              className={cn(
                "glass-panel p-5 border-l-4 transition-all hover:translate-x-1 animate-fade-in",
                getSeverityStyles(alert.severity)
              )}
              style={{ animationDelay: `${300 + index * 100}ms` }}
            >
              <div className="flex flex-wrap items-start gap-4">
                <div className={cn("p-3 rounded-lg", getSeverityStyles(alert.severity))}>
                  {Icon && <Icon className="w-6 h-6" />}
                </div>

                <div className="flex-1 min-w-[200px]">
                  <div className="flex flex-wrap items-center gap-2 mb-2">
                    <h3 className="text-lg font-display font-semibold text-foreground">
                      {alert.title || 'Unknown Alert'}
                    </h3>
                    <span className={cn(
                      "px-2 py-0.5 text-[10px] uppercase tracking-wider rounded-full",
                      getStatusStyles(alert.acknowledged ? "resolved" : "active")
                    )}>
                      {alert.acknowledged ? "resolved" : "active"}
                    </span>
                  </div>

                  <p className="text-sm text-muted-foreground mb-4">
                    {alert.description || 'No description available'}
                  </p>

                  <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
                    <div className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      <span>{alert.timestamp || 'Unknown'}</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <Monitor className="w-3 h-3" />
                      <span>{alert.source || 'Unknown'}</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <MapPin className="w-3 h-3" />
                      <span>{alert.location || 'Unknown'}</span>
                    </div>
                  </div>
                </div>

                <div className="text-right text-xs space-y-1">
                  <div>
                    <span className="text-muted-foreground">Source: </span>
                    <span className="font-mono text-destructive">{alert.source_ip || 'N/A'}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Target: </span>
                    <span className="font-mono text-secondary">{alert.target_ip || 'N/A'}</span>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {filteredAlerts.length === 0 && (
        <div className="glass-panel p-12 text-center">
          <Shield className="w-12 h-12 text-success mx-auto mb-4" />
          <p className="text-muted-foreground">No alerts match your filter criteria</p>
        </div>
      )}
    </Layout>
  );
};

export default IntruderFeed;

