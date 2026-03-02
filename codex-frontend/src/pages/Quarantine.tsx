import { Layout } from "@/components/layout/Layout";
import { useState, useEffect } from "react";
import { cn } from "@/lib/utils";
import { ShieldOff, Clock, User, CheckCircle, XCircle, Power } from "lucide-react";
import { useQuarantineStore } from "@/lib/store";

const Quarantine = () => {
  const { quarantinedDevices, logs, fetchQuarantinedDevices, fetchLogs, releaseDevice, quarantineDevice } = useQuarantineStore();
  const [showModal, setShowModal] = useState(false);
  const [modalAction, setModalAction] = useState<"quarantine" | "release" | "killswitch" | "isolation">("quarantine");
  const [selectedDevice, setSelectedDevice] = useState<any | null>(null);
  const [killSwitchConfirm, setKillSwitchConfirm] = useState("");

  useEffect(() => {
    fetchQuarantinedDevices();
    fetchLogs();
  }, []);

  const handleAction = (action: "quarantine" | "release" | "killswitch" | "isolation", device?: any) => {
    setModalAction(action);
    setSelectedDevice(device || null);
    setShowModal(true);
    setKillSwitchConfirm("");
  };

  const confirmAction = async () => {
    try {
      if (modalAction === "release" && selectedDevice) {
        await releaseDevice(selectedDevice.id);
      } else if (modalAction === "killswitch") {
        console.warn("Kill switch activated (demo/API pending)");
      }
      setShowModal(false);
      setKillSwitchConfirm("");
    } catch (error) {
      console.error("Action failed:", error);
    }
  };

  return (
    <Layout>
      <div className="mb-6 animate-fade-in">
        <h1 className="text-3xl font-display font-bold text-foreground mb-2">
          Quarantine Kill Switch
        </h1>
        <p className="text-muted-foreground">
          Emergency network isolation with comprehensive audit logging
        </p>
      </div>

      <div className="glass-panel border-2 border-destructive/50 p-6 mb-6 animate-fade-in" style={{ animationDelay: "100ms" }}>
        <div className="flex flex-col lg:flex-row items-center justify-between gap-6">
          <div className="flex items-center gap-4">
            <div className="p-4 rounded-lg bg-destructive/20 text-destructive animate-pulse">
              <Power className="w-10 h-10" />
            </div>
            <div>
              <h2 className="text-xl font-display font-bold text-destructive">
                Network Kill Switch
              </h2>
              <p className="text-muted-foreground">
                Immediately isolate all non-critical systems from the network
              </p>
            </div>
          </div>
          <button
            onClick={() => handleAction("killswitch")}
            className="px-8 py-4 bg-destructive text-destructive-foreground rounded-lg font-display uppercase tracking-wider hover:bg-destructive/90 transition-all shadow-[0_0_30px_hsl(0_85%_60%/0.3)] hover:shadow-[0_0_40px_hsl(0_85%_60%/0.5)]"
          >
            Activate Kill Switch
          </button>
        </div>
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        <div className="glass-panel p-6 animate-fade-in" style={{ animationDelay: "200ms" }}>
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <ShieldOff className="w-6 h-6 text-destructive" />
              <h2 className="text-lg font-display font-semibold text-foreground">
                Quarantined Devices
              </h2>
            </div>
            <span className="px-2 py-0.5 text-xs bg-destructive/20 text-destructive rounded-full">
              {quarantinedDevices.length} isolated
            </span>
          </div>

          {quarantinedDevices.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <CheckCircle className="w-12 h-12 text-success mx-auto mb-2" />
              <p>No devices currently quarantined</p>
            </div>
          ) : (
            <div className="space-y-4">
              {quarantinedDevices.map((device: any) => (
                <div
                  key={device.id}
                  className="p-4 rounded-lg bg-destructive/10 border border-destructive/30"
                >
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <h3 className="font-semibold text-foreground">{device.name}</h3>
                      <p className="text-sm font-mono text-destructive">{device.ip}</p>
                    </div>
                    <button
                      onClick={() => handleAction("release", device)}
                      className="px-3 py-1.5 text-xs uppercase tracking-wider bg-success/20 text-success rounded-md hover:bg-success/30 transition-colors"
                    >
                      Release
                    </button>
                  </div>
                  <p className="text-sm text-muted-foreground mb-3">
                    {device.quarantine_reason || "Manual Quarantine"}
                  </p>
                  <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
                    <div className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {new Date(device.quarantined_at).toLocaleString()}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="glass-panel p-6 animate-fade-in" style={{ animationDelay: "300ms" }}>
          <div className="flex items-center gap-3 mb-6">
            <Clock className="w-6 h-6 text-secondary" />
            <h2 className="text-lg font-display font-semibold text-foreground">
              Audit Log
            </h2>
          </div>

          <div className="space-y-3 max-h-[400px] overflow-y-auto">
            {logs.length === 0 ? (
              <p className="text-center text-muted-foreground text-sm">No recent activity logs.</p>
            ) : logs.map((log: any) => (
              <div
                key={log.id}
                className="p-3 rounded-lg bg-muted/30 border border-border/30"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className={cn(
                    "text-xs font-mono px-2 py-0.5 rounded-full",
                    (log.action?.includes("QUARANTINE") || log.action?.includes("DELETE")) && "bg-destructive/20 text-destructive",
                    (log.action?.includes("RELEASE") || log.action?.includes("CREATE")) && "bg-success/20 text-success",
                    log.action?.includes("THREAT") && "bg-warning/20 text-warning"
                  )}>
                    {log.action}
                  </span>
                  <span className="flex items-center gap-1 text-xs">
                    {log.status === "success" || !log.status ? (
                      <CheckCircle className="w-3 h-3 text-success" />
                    ) : (
                      <XCircle className="w-3 h-3 text-destructive" />
                    )}
                  </span>
                </div>
                <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
                  <span className="font-mono text-secondary">{log.resource_id}</span>
                  <span>{log.user_id}</span>
                  <span>{new Date(log.timestamp).toLocaleString()}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm animate-fade-in">
          <div className="glass-panel-glow p-8 max-w-md w-full animate-scale-in">
            <div className="text-center mb-6">
              {modalAction === "killswitch" ? (
                <>
                  <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-destructive/20 flex items-center justify-center">
                    <Power className="w-8 h-8 text-destructive" />
                  </div>
                  <h3 className="text-xl font-display font-bold text-destructive mb-2">
                    CRITICAL ACTION
                  </h3>
                  <p className="text-muted-foreground">
                    This will immediately disconnect all non-critical systems from the network. This action will be logged and cannot be undone automatically.
                  </p>
                </>
              ) : modalAction === "release" ? (
                <>
                  <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-success/20 flex items-center justify-center">
                    <CheckCircle className="w-8 h-8 text-success" />
                  </div>
                  <h3 className="text-xl font-display font-bold text-foreground mb-2">
                    Release Device
                  </h3>
                  <p className="text-muted-foreground">
                    Release <strong className="text-foreground">{selectedDevice?.name}</strong> from quarantine?
                  </p>
                </>
              ) : null}
            </div>

            {modalAction === "killswitch" && (
              <div className="mb-6">
                <label className="block text-sm text-muted-foreground mb-2">
                  Type "CONFIRM" to proceed:
                </label>
                <input
                  type="text"
                  value={killSwitchConfirm}
                  onChange={(e) => setKillSwitchConfirm(e.target.value)}
                  className="w-full px-4 py-2 bg-input border border-destructive/50 rounded-lg text-foreground font-mono focus:outline-none focus:ring-2 focus:ring-destructive/50"
                  placeholder="CONFIRM"
                />
              </div>
            )}

            <div className="flex gap-4">
              <button
                onClick={() => setShowModal(false)}
                className="flex-1 px-4 py-3 bg-muted text-muted-foreground rounded-lg font-display uppercase tracking-wider hover:bg-muted/80 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={confirmAction}
                disabled={modalAction === "killswitch" && killSwitchConfirm !== "CONFIRM"}
                className={cn(
                  "flex-1 px-4 py-3 rounded-lg font-display uppercase tracking-wider transition-colors disabled:opacity-50 disabled:cursor-not-allowed",
                  modalAction === "killswitch"
                    ? "bg-destructive text-destructive-foreground hover:bg-destructive/90"
                    : "bg-success text-success-foreground hover:bg-success/90"
                )}
              >
                {modalAction === "killswitch" ? "Activate" : "Confirm"}
              </button>
            </div>
          </div>
        </div>
      )}
    </Layout>
  );
};

export default Quarantine;

