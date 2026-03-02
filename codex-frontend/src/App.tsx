import { useEffect } from "react";
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Index from "./pages/Index";
import Topology from "./pages/Topology";
import Inventory from "./pages/Inventory";
import IntruderFeed from "./pages/IntruderFeed";
import ScanEngine from "./pages/ScanEngine";
import AIReport from "./pages/AIReport";
import Quarantine from "./pages/Quarantine";
import AdminCenter from "./pages/AdminCenter";
import PentestReports from "./pages/PentestReports";
import NotFound from "./pages/NotFound";
import AIBot from "./components/AIBot/AIBot";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { connectSocket, disconnectSocket } from "@/lib/socket";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

const App = () => {
  useEffect(() => {
    try {
      connectSocket("dev-token");
    } catch (error) {
      console.warn("Failed to connect WebSocket:", error);
    }

    return () => {
      disconnectSocket();
    };
  }, []);

  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <Toaster />
          <Sonner />
          <BrowserRouter>
            <Routes>
              <Route path="/" element={<Index />} />
              <Route path="/topology" element={<Topology />} />
              <Route path="/inventory" element={<Inventory />} />
              <Route path="/intruder-feed" element={<IntruderFeed />} />
              <Route path="/scan-engine" element={<ScanEngine />} />
              <Route path="/ai-report" element={<AIReport />} />
              <Route path="/quarantine" element={<Quarantine />} />
              <Route path="/admin-center" element={<AdminCenter />} />
              <Route path="/pentest" element={<PentestReports />} />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </BrowserRouter>
          <AIBot />
        </TooltipProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  );
};

export default App;

