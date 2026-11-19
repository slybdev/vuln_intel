import { useEffect, useRef, useState } from "react";
import {
  Activity,
  Bell,
  Boxes,
  CalendarClock,
  LayoutDashboard,
  Menu,
  Network,
  Radar,
  RefreshCw,
  Shield,
  Target,
} from "lucide-react";
import { Button } from "@/src/components/ui/primitives";
import {
  apiFetch,
  formatDate,
  RepositoryList,
  ScanList,
  SecurityEvent,
  SecurityEventPage,
  VulnerabilitySummary,
} from "@/src/lib/vuln-intel-api";
import CommandCenterPage from "@/src/components/CommandCenterPage";
import AgentNetworkPage from "@/src/components/AgentNetworkPage";
import OperationsPage from "@/src/components/OperationsPage";
import IntelligencePage from "@/src/components/IntelligencePage";
import SystemsPage from "@/src/components/SystemsPage";
import SecurityLogsPage from "@/src/components/SecurityLogsPage";
import ScheduledScansPage from "@/src/components/ScheduledScansPage";

type NavSection =
  | "overview"
  | "agents"
  | "operations"
  | "intelligence"
  | "systems"
  | "logs"
  | "scans";

const NAV_ITEMS: {
  id: NavSection;
  icon: typeof LayoutDashboard;
  label: string;
}[] = [
  { id: "overview", icon: LayoutDashboard, label: "OVERVIEW" },
  { id: "agents", icon: Boxes, label: "APPLICATIONS" },
  { id: "operations", icon: Target, label: "APPLICATION SCANS" },
  { id: "intelligence", icon: Radar, label: "INTELLIGENCE" },
  { id: "systems", icon: Network, label: "ASSET INVENTORY" },
  { id: "logs", icon: Activity, label: "SECURITY LOGS" },
  { id: "scans", icon: CalendarClock, label: "FEED SCHEDULE" },
];

const SECTION_LABELS: Record<NavSection, string> = {
  overview: "OVERVIEW",
  agents: "APPLICATIONS",
  operations: "APPLICATION SCANS",
  intelligence: "INTELLIGENCE",
  systems: "ASSET INVENTORY",
  logs: "SECURITY LOGS",
  scans: "FEED SCHEDULE",
};

function eventSection(category: SecurityEvent["category"]): NavSection {
  if (category === "asset") return "systems";
  if (category === "feed") return "scans";
  if (category === "repository") return "agents";
  if (category === "scan" || category === "finding") return "operations";
  return "logs";
}

export default function App() {
  const [activeTab, setActiveTab] = useState<NavSection>("overview");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [refreshTick, setRefreshTick] = useState(0);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [systemMetrics, setSystemMetrics] = useState({
    status: "checking" as "checking" | "online" | "offline",
    advisories: 0,
    repositories: 0,
    activeScans: 0,
  });
  const [notifications, setNotifications] = useState<SecurityEvent[]>([]);
  const [notificationsError, setNotificationsError] = useState("");
  const hoverTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    let active = true;

    async function loadSystemMetrics() {
      try {
        const [summary, repositories, scans] = await Promise.all([
          apiFetch<VulnerabilitySummary>("/api/summary"),
          apiFetch<RepositoryList>("/api/repositories"),
          apiFetch<ScanList>("/api/scans?limit=100"),
        ]);
        if (active) {
          setSystemMetrics({
            status: "online",
            advisories: summary.total,
            repositories: repositories.items.length,
            activeScans: scans.items.filter(
              (scan) => scan.status === "queued" || scan.status === "running"
            ).length,
          });
        }
      } catch {
        if (active) setSystemMetrics((metrics) => ({ ...metrics, status: "offline" }));
      }

      try {
        const result = await apiFetch<SecurityEventPage>(
          "/api/security-events?page=1&page_size=5"
        );
        if (active) {
          setNotifications(result.items);
          setNotificationsError("");
        }
      } catch {
        if (active) setNotificationsError("Recent security events are unavailable.");
      }
    }

    void loadSystemMetrics();
    return () => {
      active = false;
    };
  }, [refreshTick]);

  useEffect(() => {
    const syncResponsive = () => {
      if (window.matchMedia("(max-width: 767px)").matches) {
        setSidebarCollapsed(true);
      }
    };
    syncResponsive();
    window.addEventListener("resize", syncResponsive);
    return () => window.removeEventListener("resize", syncResponsive);
  }, []);

  function handleNavigate(tab: string) {
    if (tab in SECTION_LABELS) {
      setActiveTab(tab as NavSection);
    }
  }

  function handleRefresh() {
    setIsRefreshing(true);
    setRefreshTick((t) => t + 1);
    window.setTimeout(() => setIsRefreshing(false), 450);
  }

  return (
    <div className="flex h-screen">
      <aside
        onMouseEnter={() => {
          if (
            sidebarCollapsed &&
            !window.matchMedia("(max-width: 767px)").matches
          ) {
            hoverTimerRef.current = setTimeout(
              () => setSidebarCollapsed(false),
              300
            );
          }
        }}
        onMouseLeave={() => {
          if (hoverTimerRef.current) {
            clearTimeout(hoverTimerRef.current);
            hoverTimerRef.current = null;
          }
          if (!window.matchMedia("(max-width: 767px)").matches) {
            setSidebarCollapsed(true);
          }
        }}
        className={`${
          sidebarCollapsed ? "hidden md:block md:w-16" : "w-[248px]"
        } bg-[#0d0e0d] border-r border-border/70 transition-all duration-300 fixed md:relative z-50 md:z-auto h-full md:h-auto shrink-0`}
      >
        <div className="p-4">
          <div
            className={`flex items-center ${
              sidebarCollapsed ? "justify-center" : "justify-between"
            } mb-8`}
          >
            <div className={sidebarCollapsed ? "hidden" : "block"}>
              <h1 className="text-orange-500 font-bold text-lg tracking-wider">
                TACTICAL OPS
              </h1>
              <p className="text-muted-foreground text-xs">
                v2.1.7 CLASSIFIED
              </p>
            </div>
          </div>

          <nav className="space-y-2" aria-label="Primary navigation">
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon;
              const active = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  aria-current={active ? "page" : undefined}
                  onClick={() => {
                    setActiveTab(item.id);
                    if (window.matchMedia("(max-width: 767px)").matches) {
                      setSidebarCollapsed(true);
                    }
                  }}
                  className={`w-full flex items-center gap-3 p-3 rounded transition-colors cursor-pointer ${
                    active
                      ? "bg-orange-400/10 text-orange-200"
                      : "text-muted-foreground hover:text-white hover:bg-neutral-800"
                  }`}
                >
                  <Icon
                    className={`${
                      sidebarCollapsed ? "mx-auto" : ""
                    } size-5 shrink-0`}
                  />
                  {!sidebarCollapsed && (
                    <span className="text-sm font-medium whitespace-nowrap">
                      {item.label}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>

          {!sidebarCollapsed && (
            <div className="mt-8 p-4 bg-neutral-800 border border-neutral-700 rounded">
              <div className="flex items-center gap-2 mb-2">
                <div
                  className={`w-2 h-2 rounded-full ${
                    systemMetrics.status === "online"
                      ? "bg-emerald-400"
                      : systemMetrics.status === "offline"
                        ? "bg-rose-400"
                        : "bg-amber-400 animate-pulse"
                  }`}
                />
                <span className="text-xs text-white">
                  {systemMetrics.status === "online"
                    ? "SYSTEM ONLINE"
                    : systemMetrics.status === "offline"
                      ? "API OFFLINE"
                      : "CHECKING API"}
                </span>
              </div>
              <div className="text-xs text-muted-foreground space-y-0.5 tabular-nums">
                <div>ADVISORIES: {systemMetrics.advisories.toLocaleString()}</div>
                <div>REPOSITORIES: {systemMetrics.repositories}</div>
                <div>ACTIVE SCANS: {systemMetrics.activeScans}</div>
              </div>
            </div>
          )}
        </div>
      </aside>

      {!sidebarCollapsed && (
        <div
          className="fixed inset-0 bg-black/50 z-40 md:hidden"
          onClick={() => setSidebarCollapsed(true)}
          aria-hidden="true"
        />
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="relative flex h-16 items-center justify-between border-b border-border/70 bg-card/80 px-4 backdrop-blur-xl sm:px-6">
          <div className="flex min-w-0 items-center gap-2 sm:gap-4">
            <Button
              variant="ghost"
              size="icon"
              aria-label="Open navigation"
              onClick={() => setSidebarCollapsed(false)}
              className="shrink-0 text-muted-foreground hover:text-orange-500 md:hidden"
            >
              <Menu className="size-4" />
            </Button>
            <div className="truncate text-xs text-muted-foreground sm:text-sm">
              TACTICAL COMMAND /{" "}
              <span className="text-orange-500">
                {SECTION_LABELS[activeTab]}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="hidden items-center gap-2 text-[10px] font-medium uppercase tracking-[.16em] text-muted-foreground lg:flex">
              <span className="size-1.5 animate-pulse rounded-full bg-orange-400" />
              Live telemetry · UTC
            </div>
            <div className="relative">
              <Button
                variant="ghost"
                size="icon"
                aria-label="Notifications"
                onClick={() => setNotificationsOpen((v) => !v)}
                className="text-muted-foreground hover:text-orange-300"
              >
                <Bell className="w-4 h-4" />
              </Button>
              {notificationsOpen && (
                <div className="absolute right-0 top-12 z-50 w-72 rounded-lg border border-border bg-card p-3 shadow-xl">
                  <div className="mb-2 flex items-center justify-between text-[10px] font-semibold uppercase tracking-wider text-orange-300">
                    <span>Recent Security Events</span>
                    <button
                      type="button"
                      onClick={() => setNotificationsOpen(false)}
                      className="text-muted-foreground hover:text-foreground cursor-pointer"
                    >
                      ✕
                    </button>
                  </div>
                  <div className="space-y-2 text-xs">
                    {notificationsError ? (
                      <p role="alert" className="p-2 text-muted-foreground">
                        {notificationsError}
                      </p>
                    ) : notifications.length ? (
                      notifications.map((event) => (
                        <button
                          key={event.event_id}
                          type="button"
                          onClick={() => {
                            setNotificationsOpen(false);
                            setActiveTab(eventSection(event.category));
                          }}
                          className="w-full rounded border border-border/60 bg-background/50 p-2 text-left hover:border-orange-400/30 cursor-pointer"
                        >
                          <div className="font-medium text-foreground">
                            {event.message}
                          </div>
                          <div className="mt-0.5 text-[10px] text-muted-foreground">
                            {event.severity} · {event.category} ·{" "}
                            {formatDate(event.occurred_at)}
                          </div>
                        </button>
                      ))
                    ) : (
                      <p className="p-2 text-muted-foreground">
                        No recent security events.
                      </p>
                    )}
                  </div>
                </div>
              )}
            </div>
            <Button
              variant="ghost"
              size="icon"
              aria-label="Refresh dashboard"
              onClick={handleRefresh}
              className="text-muted-foreground hover:text-orange-300"
            >
              <RefreshCw
                className={`w-4 h-4 ${isRefreshing ? "animate-spin" : ""}`}
              />
            </Button>
          </div>
        </header>

        <div key={refreshTick} className="flex-1 overflow-auto">
          {activeTab === "overview" && (
            <CommandCenterPage onNavigate={handleNavigate} />
          )}
          {activeTab === "agents" && (
            <AgentNetworkPage onNavigate={handleNavigate} />
          )}
          {activeTab === "operations" && <OperationsPage />}
          {activeTab === "intelligence" && <IntelligencePage />}
          {activeTab === "systems" && <SystemsPage />}
          {activeTab === "logs" && <SecurityLogsPage />}
          {activeTab === "scans" && <ScheduledScansPage />}
        </div>
      </div>
    </div>
  );
}
