import { Shield, Bell, Settings, User, Menu, X, CheckCircle, AlertTriangle, Clock, LogOut, Wrench, Activity, RefreshCw } from "lucide-react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { cn } from "@/lib/utils";
import { useState, useEffect, useRef } from "react";
import { useAlerts } from "@/lib/hooks";

const navItems = [
  { href: "/", label: "Dashboard" },
  { href: "/topology", label: "Topology" },
];

export const Header = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [notificationOpen, setNotificationOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [isFixing, setIsFixing] = useState(false);
  const [fixResult, setFixResult] = useState<{ success: boolean; message: string } | null>(null);

  const { alerts, fetchAlerts } = useAlerts();
  const notificationRef = useRef<HTMLDivElement>(null);
  const settingsRef = useRef<HTMLDivElement>(null);
  const userRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 10000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (notificationRef.current && !notificationRef.current.contains(e.target as Node)) {
        setNotificationOpen(false);
      }
      if (settingsRef.current && !settingsRef.current.contains(e.target as Node)) {
        setSettingsOpen(false);
      }
      if (userRef.current && !userRef.current.contains(e.target as Node)) {
        setUserMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const unreadAlerts = alerts.filter((a: any) => !a.acknowledged);
  const recentAlerts = alerts.slice(0, 5);

  const runDiagnostics = async () => {
    setIsFixing(true);
    setFixResult(null);

    try {
      const issues: string[] = [];
      const fixes: string[] = [];

      try {
        const res = await fetch('http://localhost:3001/api/health');
        if (!res.ok) {
          issues.push('Backend health check failed');
        }
      } catch {
        issues.push('Cannot connect to backend');
      }

      try {
        const res = await fetch('http://localhost:3001/api/devices');
        if (res.ok) {
          fixes.push('Devices API: OK');
        } else {
          issues.push('Devices API error');
        }
      } catch {
        issues.push('Devices API unreachable');
      }

      try {
        const res = await fetch('http://localhost:3001/api/alerts');
        if (res.ok) {
          fixes.push('Alerts API: OK');
        } else {
          issues.push('Alerts API error');
        }
      } catch {
        issues.push('Alerts API unreachable');
      }

      await fetchAlerts();
      fixes.push('Alert data refreshed');

      window.dispatchEvent(new Event('storage'));
      fixes.push('Local state synchronized');

      if (issues.length === 0) {
        setFixResult({
          success: true,
          message: `All systems operational! ${fixes.length} checks passed.`
        });
      } else {
        setFixResult({
          success: false,
          message: `Found ${issues.length} issue(s): ${issues.join(', ')}`
        });
      }
    } catch (error) {
      setFixResult({
        success: false,
        message: 'Diagnostics failed - please check server connection'
      });
    } finally {
      setIsFixing(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    navigate('/login');
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-destructive bg-destructive/10';
      case 'high': return 'text-red-500 bg-red-500/10';
      case 'medium': return 'text-warning bg-warning/10';
      default: return 'text-muted-foreground bg-muted/30';
    }
  };

  return (
    <header className="fixed top-0 left-0 right-0 z-50 glass-panel border-b border-border/50 rounded-none">
      <div className="container mx-auto px-4">
        <div className="flex items-center justify-between h-16">
          <Link to="/" className="flex items-center gap-3 group">
            <div className="relative">
              <Shield className="w-8 h-8 text-primary transition-all duration-300 group-hover:scale-110" />
              <div className="absolute inset-0 bg-primary/20 blur-xl opacity-0 group-hover:opacity-100 transition-opacity" />
            </div>
            <div className="hidden sm:block">
              <h1 className="text-lg font-display font-bold tracking-wider text-foreground">
                BLACK CODEX
              </h1>
              <p className="text-[10px] uppercase tracking-[0.3em] text-muted-foreground -mt-0.5">
                Cyber Defense
              </p>
            </div>
          </Link>

          <nav className="hidden lg:flex items-center gap-1">
            {navItems.map((item) => (
              <Link
                key={item.href}
                to={item.href}
                className={cn(
                  "px-3 py-2 text-xs uppercase tracking-wider transition-all duration-300 rounded-md",
                  location.pathname === item.href
                    ? "text-primary bg-primary/10 neon-text"
                    : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
                )}
              >
                {item.label}
              </Link>
            ))}
          </nav>

          <div className="flex items-center gap-2">
            <div className="relative" ref={notificationRef}>
              <button
                className="relative p-2 rounded-lg transition-colors hover:bg-muted/50 group"
                onClick={() => {
                  setNotificationOpen(!notificationOpen);
                  setSettingsOpen(false);
                  setUserMenuOpen(false);
                }}
              >
                <Bell className="w-5 h-5 text-muted-foreground group-hover:text-foreground" />
                {unreadAlerts.length > 0 && (
                  <span className="absolute top-1 right-1 min-w-[18px] h-[18px] flex items-center justify-center text-[10px] font-bold bg-destructive text-white rounded-full">
                    {unreadAlerts.length > 9 ? '9+' : unreadAlerts.length}
                  </span>
                )}
              </button>

              {notificationOpen && (
                <div className="absolute right-0 top-full mt-2 w-80 glass-panel-glow border border-border rounded-lg shadow-xl animate-fade-in overflow-hidden">
                  <div className="p-4 border-b border-border">
                    <div className="flex items-center justify-between">
                      <h3 className="font-display font-semibold text-foreground">Notifications</h3>
                      <span className="text-xs text-muted-foreground">{unreadAlerts.length} unread</span>
                    </div>
                  </div>
                  <div className="max-h-80 overflow-y-auto">
                    {recentAlerts.length === 0 ? (
                      <div className="p-8 text-center">
                        <CheckCircle className="w-8 h-8 text-success mx-auto mb-2" />
                        <p className="text-sm text-muted-foreground">No alerts</p>
                      </div>
                    ) : (
                      recentAlerts.map((alert: any) => (
                        <div
                          key={alert.id}
                          className={cn(
                            "p-3 border-b border-border/50 hover:bg-muted/30 cursor-pointer transition-colors",
                            !alert.acknowledged && "bg-primary/5"
                          )}
                        >
                          <div className="flex items-start gap-3">
                            <div className={cn("p-1.5 rounded", getSeverityColor(alert.severity))}>
                              <AlertTriangle className="w-3 h-3" />
                            </div>
                            <div className="flex-1 min-w-0">
                              <p className="text-sm font-medium text-foreground truncate">
                                {alert.message || alert.title || 'Alert'}
                              </p>
                              <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                                <Clock className="w-3 h-3" />
                                <span>{new Date(alert.created_at).toLocaleTimeString()}</span>
                              </div>
                            </div>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>

            <div className="relative hidden sm:block" ref={settingsRef}>
              <button
                className="p-2 rounded-lg transition-colors hover:bg-muted/50 group"
                onClick={() => {
                  setSettingsOpen(!settingsOpen);
                  setNotificationOpen(false);
                  setUserMenuOpen(false);
                }}
              >
                <Settings className="w-5 h-5 text-muted-foreground group-hover:text-foreground" />
              </button>

              {settingsOpen && (
                <div className="absolute right-0 top-full mt-2 w-72 glass-panel-glow border border-border rounded-lg shadow-xl animate-fade-in overflow-hidden">
                  <div className="p-4 border-b border-border">
                    <h3 className="font-display font-semibold text-foreground">Quick Settings</h3>
                  </div>
                  <div className="p-2">
                    <button
                      onClick={runDiagnostics}
                      disabled={isFixing}
                      className="w-full flex items-center gap-3 p-3 rounded-lg hover:bg-muted/30 transition-colors text-left"
                    >
                      <Wrench className={cn("w-4 h-4 text-warning", isFixing && "animate-spin")} />
                      <div>
                        <p className="text-sm font-medium text-foreground">
                          {isFixing ? 'Running Diagnostics...' : 'Auto-Fix & Diagnostics'}
                        </p>
                        <p className="text-xs text-muted-foreground">Check and repair issues</p>
                      </div>
                    </button>
                    {fixResult && (
                      <div className={cn(
                        "mx-3 my-2 p-3 rounded-lg text-xs",
                        fixResult.success ? "bg-success/20 text-success" : "bg-destructive/20 text-destructive"
                      )}>
                        {fixResult.success ? <CheckCircle className="w-4 h-4 inline mr-2" /> : <AlertTriangle className="w-4 h-4 inline mr-2" />}
                        {fixResult.message}
                      </div>
                    )}
                    <button
                      onClick={() => window.location.reload()}
                      className="w-full flex items-center gap-3 p-3 rounded-lg hover:bg-muted/30 transition-colors text-left"
                    >
                      <RefreshCw className="w-4 h-4 text-accent" />
                      <div>
                        <p className="text-sm font-medium text-foreground">Refresh App</p>
                        <p className="text-xs text-muted-foreground">Reload the application</p>
                      </div>
                    </button>
                  </div>
                </div>
              )}
            </div>

            <div className="relative hidden sm:block" ref={userRef}>
              <button
                className="p-2 rounded-lg transition-colors hover:bg-muted/50 group"
                onClick={() => {
                  setUserMenuOpen(!userMenuOpen);
                  setNotificationOpen(false);
                  setSettingsOpen(false);
                }}
              >
                <User className="w-5 h-5 text-muted-foreground group-hover:text-foreground" />
              </button>

              {userMenuOpen && (
                <div className="absolute right-0 top-full mt-2 w-56 glass-panel-glow border border-border rounded-lg shadow-xl animate-fade-in overflow-hidden">
                  <div className="p-4 border-b border-border">
                    <p className="font-medium text-foreground">Administrator</p>
                    <p className="text-xs text-muted-foreground">admin@blackcodex.local</p>
                  </div>
                  <div className="p-2">
                    <button
                      onClick={handleLogout}
                      className="w-full flex items-center gap-3 p-3 rounded-lg hover:bg-destructive/10 transition-colors text-destructive"
                    >
                      <LogOut className="w-4 h-4" />
                      <span className="text-sm">Logout</span>
                    </button>
                  </div>
                </div>
              )}
            </div>

            <button
              className="lg:hidden p-2 rounded-lg transition-colors hover:bg-muted/50"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            >
              <Menu className="w-5 h-5 text-muted-foreground" />
            </button>
          </div>
        </div>

        {mobileMenuOpen && (
          <nav className="lg:hidden py-4 border-t border-border/50 animate-fade-in">
            <div className="grid grid-cols-2 gap-2">
              {navItems.map((item) => (
                <Link
                  key={item.href}
                  to={item.href}
                  onClick={() => setMobileMenuOpen(false)}
                  className={cn(
                    "px-4 py-3 text-xs uppercase tracking-wider transition-all duration-300 rounded-md text-center",
                    location.pathname === item.href
                      ? "text-primary bg-primary/10"
                      : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
                  )}
                >
                  {item.label}
                </Link>
              ))}
            </div>
          </nav>
        )}
      </div>
    </header>
  );
};

