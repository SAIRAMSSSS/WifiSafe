import { Layout } from "@/components/layout/Layout";
import { useState, useMemo, useEffect } from "react";
import { cn } from "@/lib/utils";
import { Server, Router, Monitor, Smartphone, Printer, Database, Shield } from "lucide-react";
import { networkAPI } from "@/lib/api";
import { useSocket } from "@/lib/socket";

interface NetworkNode {
  id: string;
  name: string;
  type: "server" | "router" | "workstation" | "mobile" | "printer" | "database" | "firewall" | "gateway" | "iot";
  risk: "low" | "medium" | "high" | "critical";
  ip: string;
  status: "online" | "offline" | "warning";
  x: number;
  y: number;
  connections: string[];
}

const Topology = () => {
  const [nodes, setNodes] = useState<NetworkNode[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState<NetworkNode | null>(null);
  const [riskFilter, setRiskFilter] = useState<string>("all");
  const socket = useSocket();

  const fetchTopology = async () => {
    try {
      const { data } = await networkAPI.getTopology();
      const backendNodes = data.nodes || [];
      const backendEdges = data.edges || [];

      const connectionsMap: Record<string, string[]> = {};
      backendEdges.forEach((edge: any) => {
        if (!connectionsMap[edge.source]) connectionsMap[edge.source] = [];
        connectionsMap[edge.source].push(edge.target);
      });

      const transformedNodes: NetworkNode[] = backendNodes.map((n: any) => ({
        id: n.id,
        name: n.data.label || n.id,
        type: (n.data.deviceType || n.type || 'server').toLowerCase(),
        risk: (n.data.riskLevel || 'low').toLowerCase(),
        ip: n.data.ip || '0.0.0.0',
        status: (n.data.status || 'offline').toLowerCase(),
        x: (n.position.x / 800) * 100,
        y: (n.position.y / 600) * 100,
        connections: connectionsMap[n.id] || []
      }));

      setNodes(transformedNodes);
    } catch (error) {
      console.error("Failed to fetch topology:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTopology();
  }, []);

  useEffect(() => {
    if (!socket) return;

    const handleRefresh = () => {
      fetchTopology();
    };

    socket.on('scan_complete', handleRefresh);
    socket.on('device_updated', handleRefresh);
    socket.on('device_connected', handleRefresh);

    socket.on('devices', (data: any) => {
      if (data.event === 'new_device' || data.event === 'device_updated') {
        fetchTopology();
      }
    });

    return () => {
      socket.off('scan_complete', handleRefresh);
      socket.off('device_updated', handleRefresh);
      socket.off('device_connected', handleRefresh);
      socket.off('devices');
    };
  }, [socket]);

  const getNodeIcon = (type: string) => {
    const icons: Record<string, any> = {
      server: Server,
      router: Router,
      workstation: Monitor,
      mobile: Smartphone,
      printer: Printer,
      database: Database,
      firewall: Shield,
      gateway: Router,
      iot: Monitor,
    };
    return icons[type] || Server;
  };

  const getRiskColor = (risk: string) => {
    const colors: Record<string, string> = {
      low: "text-success border-success/50 bg-success/10",
      medium: "text-warning border-warning/50 bg-warning/10",
      high: "text-orange-500 border-orange-500/50 bg-orange-500/10",
      critical: "text-destructive border-destructive/50 bg-destructive/10",
    };
    return colors[risk] || colors.low;
  };

  const getConnectionColor = (node1: NetworkNode, node2: NetworkNode) => {
    const risks = ["low", "medium", "high", "critical"];
    const maxRisk = Math.max(
      risks.indexOf(node1.risk),
      risks.indexOf(node2.risk)
    );
    const colors = ["stroke-success/40", "stroke-warning/40", "stroke-orange-500/40", "stroke-destructive/40"];
    return colors[maxRisk] || colors[0];
  };

  const filteredNodes = useMemo(() => {
    if (riskFilter === "all") return nodes;
    return nodes.filter((n) => n.risk === riskFilter);
  }, [riskFilter, nodes]);

  const connections = useMemo(() => {
    const lines: { from: NetworkNode; to: NetworkNode }[] = [];
    nodes.forEach((node) => {
      node.connections.forEach((targetId) => {
        const target = nodes.find((n) => n.id === targetId);
        if (target) {
          lines.push({ from: node, to: target });
        }
      });
    });
    return lines;
  }, [nodes]);

  return (
    <Layout>
      <div className="mb-6 animate-fade-in">
        <h1 className="text-3xl font-display font-bold text-foreground mb-2">
          Network Topology
        </h1>
        <p className="text-muted-foreground">
          Interactive visualization of network infrastructure and security status
        </p>
      </div>

      <div className="glass-panel p-4 mb-6 flex flex-wrap gap-2 animate-fade-in">
        {["all", "low", "medium", "high", "critical"].map((filter) => (
          <button
            key={filter}
            onClick={() => setRiskFilter(filter)}
            className={cn(
              "px-4 py-2 text-xs uppercase tracking-wider rounded-md transition-all",
              riskFilter === filter
                ? "bg-primary text-primary-foreground"
                : "bg-muted/50 text-muted-foreground hover:bg-muted"
            )}
          >
            {filter === "all" ? "All Nodes" : `${filter} Risk`}
          </button>
        ))}
      </div>

      <div className="grid lg:grid-cols-4 gap-6">
        <div className="lg:col-span-3 glass-panel-glow p-6 animate-fade-in">
          <div className="relative w-full aspect-[16/10] bg-background/50 rounded-lg overflow-hidden">
            <svg className="absolute inset-0 w-full h-full">
              {connections.map((conn, i) => (
                <line
                  key={i}
                  x1={`${conn.from.x}%`}
                  y1={`${conn.from.y}%`}
                  x2={`${conn.to.x}%`}
                  y2={`${conn.to.y}%`}
                  className={cn("stroke-2", getConnectionColor(conn.from, conn.to))}
                  strokeDasharray="5,5"
                >
                  <animate
                    attributeName="stroke-dashoffset"
                    values="10;0"
                    dur="1s"
                    repeatCount="indefinite"
                  />
                </line>
              ))}
            </svg>

            {filteredNodes.map((node) => {
              const Icon = getNodeIcon(node.type);
              return (
                <button
                  key={node.id}
                  onClick={() => setSelectedNode(node)}
                  className={cn(
                    "absolute transform -translate-x-1/2 -translate-y-1/2 p-3 rounded-lg border-2 transition-all duration-300 hover:scale-110",
                    getRiskColor(node.risk),
                    selectedNode?.id === node.id && "ring-2 ring-primary scale-110"
                  )}
                  style={{ left: `${node.x}%`, top: `${node.y}%` }}
                >
                  <Icon className="w-6 h-6" />
                  {node.status === "offline" && (
                    <span className="absolute -top-1 -right-1 w-3 h-3 bg-muted rounded-full" />
                  )}
                  {node.status === "warning" && (
                    <span className="absolute -top-1 -right-1 w-3 h-3 bg-warning rounded-full animate-pulse" />
                  )}
                </button>
              );
            })}
          </div>

          <div className="mt-4 flex flex-wrap gap-4 text-xs">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-success" />
              <span className="text-muted-foreground">Low Risk</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-warning" />
              <span className="text-muted-foreground">Medium Risk</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-orange-500" />
              <span className="text-muted-foreground">High Risk</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-destructive" />
              <span className="text-muted-foreground">Critical Risk</span>
            </div>
          </div>
        </div>

        <div className="glass-panel p-6 animate-fade-in">
          <h3 className="text-lg font-display font-semibold text-foreground mb-4">
            Node Details
          </h3>

          {selectedNode ? (
            <div className="space-y-4">
              <div className={cn("p-4 rounded-lg border-2", getRiskColor(selectedNode.risk))}>
                {(() => {
                  const Icon = getNodeIcon(selectedNode.type);
                  return <Icon className="w-10 h-10 mx-auto" />;
                })()}
              </div>

              <div className="space-y-3">
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider">Name</p>
                  <p className="text-foreground font-medium">{selectedNode.name}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider">IP Address</p>
                  <p className="text-foreground font-mono">{selectedNode.ip}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider">Type</p>
                  <p className="text-foreground capitalize">{selectedNode.type}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider">Status</p>
                  <p className={cn(
                    "capitalize",
                    selectedNode.status === "online" && "text-success",
                    selectedNode.status === "offline" && "text-muted-foreground",
                    selectedNode.status === "warning" && "text-warning"
                  )}>
                    {selectedNode.status}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider">Risk Level</p>
                  <p className={cn(
                    "capitalize font-semibold",
                    getRiskColor(selectedNode.risk).split(" ")[0]
                  )}>
                    {selectedNode.risk}
                  </p>
                </div>
              </div>
            </div>
          ) : (
            <p className="text-muted-foreground text-sm text-center py-8">
              Click on a node to view details
            </p>
          )}
        </div>
      </div>
    </Layout>
  );
};

export default Topology;

