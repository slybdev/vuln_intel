import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowUpRight,
  Clock3,
  Crosshair,
  Download,
  Earth,
  Lightbulb,
  Radio,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Wifi,
  type LucideIcon,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  Radar,
  RadarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Badge } from "@/src/components/ui/primitives";
import { Button } from "@/src/components/ui/primitives";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/src/components/ui/primitives";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/src/components/ui/primitives";
import {
  apiFetch,
  ApplicationFinding,
  FindingList,
  formatDate,
  Repository,
  RepositoryList,
  ScanList,
  ScanRun,
  VulnerabilitySummary,
} from "@/src/lib/vuln-intel-api";

type Severity = "critical" | "high" | "medium" | "low" | "unknown";

interface DetectionRecord {
  id: string;
  time: string;
  severity: Severity;
  source: string;
  message: string;
  repository: string;
  packageName: string;
  ecosystem: string;
  vulnerabilityId: string;
  installedVersion: string;
  fixedVersion: string;
  status: string;
  firstSeen: string;
  lastSeen: string;
}

interface InventoryFinding extends ApplicationFinding {
  repository: Repository;
}

interface DashboardData {
  vulnerabilitySummary: VulnerabilitySummary;
  repositories: Repository[];
  scans: ScanRun[];
  activeFindings: InventoryFinding[];
  resolvedFindings: InventoryFinding[];
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "unknown"];
const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#fb7185",
  high: "#f7a66a",
  medium: "#f2d27b",
  low: "#7dd3fc",
  unknown: "#a3a3a3",
};
const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  unknown: "Unrated",
};

async function loadDashboardData(): Promise<DashboardData> {
  const [vulnerabilitySummary, repositoryResult, scanResult] =
    await Promise.all([
      apiFetch<VulnerabilitySummary>("/api/summary"),
      apiFetch<RepositoryList>("/api/repositories"),
      apiFetch<ScanList>("/api/scans?limit=100"),
    ]);

  const findingResults = await Promise.all(
    repositoryResult.items.map(async (repository) => {
      const basePath = `/api/applications/${encodeURIComponent(repository.application_id)}/findings`;
      const [active, resolved] = await Promise.all([
        apiFetch<FindingList>(`${basePath}?status=active`),
        apiFetch<FindingList>(`${basePath}?status=resolved`),
      ]);
      return {
        repository,
        active: active.items,
        resolved: resolved.items,
      };
    })
  );

  return {
    vulnerabilitySummary,
    repositories: repositoryResult.items,
    scans: scanResult.items,
    activeFindings: findingResults.flatMap(({ repository, active }) =>
      active.map((finding) => ({ ...finding, repository }))
    ),
    resolvedFindings: findingResults.flatMap(({ repository, resolved }) =>
      resolved.map((finding) => ({ ...finding, repository }))
    ),
  };
}

function severityCounts(findings: InventoryFinding[]) {
  return SEVERITIES.reduce(
    (counts, severity) => {
      counts[severity] = findings.filter(
        (finding) => finding.severity.toLowerCase() === severity
      ).length;
      return counts;
    },
    {} as Record<Severity, number>
  );
}

function findingsByRepository(findings: InventoryFinding[]) {
  const counts = new Map<string, number>();
  for (const finding of findings) {
    counts.set(
      finding.repository.application_id,
      (counts.get(finding.repository.application_id) ?? 0) + 1
    );
  }
  return counts;
}

function activityForScans(scans: ScanRun[], timeWindow: string) {
  const now = Date.now();
  const isDaily = timeWindow === "Last 7 days";
  const bucketDuration = isDaily ? 24 * 60 * 60 * 1000 : 2 * 60 * 60 * 1000;
  const bucketCount = isDaily ? 7 : 12;
  const start = now - bucketDuration * bucketCount;
  const buckets = Array.from({ length: bucketCount }, (_, index) => {
    const bucketStart = start + index * bucketDuration;
    const date = new Date(bucketStart);
    return {
      time: isDaily
        ? new Intl.DateTimeFormat(undefined, {
            month: "short",
            day: "numeric",
          }).format(date)
        : new Intl.DateTimeFormat(undefined, {
            hour: "2-digit",
            hour12: false,
          }).format(date),
      components: 0,
      findings: 0,
      scans: 0,
    };
  });

  for (const scan of scans) {
    const timestamp = scan.requested_at ? Date.parse(scan.requested_at) : NaN;
    if (!Number.isFinite(timestamp) || timestamp < start || timestamp > now) {
      continue;
    }
    const index = Math.min(
      bucketCount - 1,
      Math.floor((timestamp - start) / bucketDuration)
    );
    buckets[index].components += scan.component_count ?? 0;
    buckets[index].findings += scan.finding_count ?? 0;
    buckets[index].scans += 1;
  }
  return buckets;
}

const SEVERITY_BADGE_CLASSES: Record<Severity, string> = {
  critical: "border-rose-400/20 bg-rose-400/10 text-rose-300",
  high: "border-orange-400/20 bg-orange-400/10 text-orange-300",
  medium: "border-amber-300/20 bg-amber-300/10 text-amber-200",
  low: "border-sky-300/20 bg-sky-300/10 text-sky-200",
  unknown: "border-neutral-400/20 bg-neutral-400/10 text-neutral-300",
};

function KpiSparkCard({
  title,
  value,
  caption,
  icon: Icon,
  tone,
  trend,
  lineColor,
}: {
  title: string;
  value: string;
  caption: string;
  icon: LucideIcon;
  tone: string;
  trend: number[];
  lineColor: string;
}) {
  const data = trend.map((count, index) => ({ index, count }));
  return (
    <Card className="siem-card overflow-hidden">
      <CardContent className="p-4 sm:p-5">
        <div className="flex items-start justify-between">
          <div className="text-[11px] font-medium uppercase tracking-[.14em] text-muted-foreground">
            {title}
          </div>
          <span className={`rounded-md p-2 ${tone}`}>
            <Icon className="size-4" />
          </span>
        </div>
        <div className="mt-4 flex items-end justify-between gap-2">
          <div className="font-mono text-3xl font-semibold tracking-tight text-foreground tabular-nums">
            {value}
          </div>
          <div className="h-9 w-[76px] shrink-0" aria-hidden="true">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={data}>
                <Line
                  type="monotone"
                  dataKey="count"
                  stroke={lineColor}
                  strokeWidth={1.8}
                  dot={false}
                  isAnimationActive={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="mt-2 text-[11px] text-muted-foreground">
          {caption}
        </div>
      </CardContent>
    </Card>
  );
}

function ThreatSurfaceScan({
  repositoryCount,
  openFindingCount,
  packageCount,
  scanning,
  onScan,
  disabled,
}: {
  repositoryCount: number;
  openFindingCount: number;
  packageCount: number;
  scanning: boolean;
  onScan: () => void;
  disabled: boolean;
}) {
  return (
    <Card className="siem-card h-full">
      <CardHeader className="flex-row items-center justify-between space-y-0 pb-2">
        <div>
          <CardTitle className="text-sm">Inventory scan status</CardTitle>
          <p className="mt-1 text-xs text-muted-foreground">
            {repositoryCount} connected repositories
          </p>
        </div>
        <Badge
          variant="outline"
          className="border-orange-400/20 bg-orange-400/5 text-orange-300"
        >
          <span className="mr-1.5 size-1.5 animate-pulse rounded-full bg-orange-400" />
          {scanning ? "SCANNING" : "READY"}
        </Badge>
      </CardHeader>
      <CardContent className="flex flex-col items-center pb-5">
        <button
          type="button"
          onClick={onScan}
          disabled={disabled}
          className="radar relative my-3 aspect-square w-full max-w-[260px] overflow-hidden rounded-full border border-orange-400/15 enabled:cursor-pointer disabled:cursor-not-allowed disabled:opacity-60"
          aria-label={scanning ? "Repository scan in progress" : "Scan all connected repositories"}
        >
          <div className="radar-grid absolute inset-0 rounded-full" />
          <div className="absolute inset-[18%] rounded-full border border-orange-300/15" />
          <div className="absolute inset-[38%] rounded-full border border-orange-300/15" />
          <div className="absolute inset-[58%] rounded-full border border-orange-300/15" />
          <div className="absolute left-1/2 top-0 h-full w-px -translate-x-1/2 bg-orange-200/10" />
          <div className="absolute left-0 top-1/2 h-px w-full -translate-y-1/2 bg-orange-200/10" />
          <div
            className={`radar-sweep absolute inset-0 rounded-full ${
              scanning ? "" : "opacity-0"
            }`}
          />
          {Array.from({ length: Math.min(openFindingCount, 8) }, (_, index) => {
            const angle = (index / Math.max(1, Math.min(openFindingCount, 8))) * Math.PI * 2;
            const radius = 18 + ((index * 17) % 29);
            return (
              <span
                key={index}
                className={`radar-dot ${index % 2 ? "radar-dot-delay" : ""}`}
                style={{
                  left: `${50 + Math.cos(angle) * radius}%`,
                  top: `${50 + Math.sin(angle) * radius}%`,
                }}
              />
            );
          })}
          <span className="absolute bottom-3 left-0 right-0 text-center font-mono text-[9px] tracking-[.22em] text-orange-200/50">
            {scanning ? "SCAN IN PROGRESS" : "SCAN ALL REPOSITORIES"}
          </span>
        </button>

        <div className="grid w-full grid-cols-3 gap-2 border-t border-border/70 pt-4 text-center">
          <div>
            <div className="font-mono text-lg text-foreground tabular-nums">
              {repositoryCount}
            </div>
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
              Repositories
            </div>
          </div>
          <div>
            <div className="font-mono text-lg text-amber-200 tabular-nums">
              {openFindingCount}
            </div>
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
              Open findings
            </div>
          </div>
          <div>
            <div className="font-mono text-lg text-orange-300 tabular-nums">
              {packageCount}
            </div>
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
              Packages scanned
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function PostureOverviewCard({
  findings,
}: {
  findings: InventoryFinding[];
}) {
  const counts = severityCounts(findings);
  const total = findings.length;
  const severityData = SEVERITIES.map((severity, index) => ({
    axis: String(index + 1),
    metric: SEVERITY_LABELS[severity],
    value: total ? (counts[severity] / total) * 100 : 0,
    count: counts[severity],
    color: SEVERITY_COLORS[severity],
  }));

  return (
    <Card className="siem-card h-full w-full">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Open findings by severity</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col items-center gap-4">
        <div
          className="h-[260px] w-full max-w-[360px]"
          role="img"
          aria-label="Radar chart showing the severity distribution of open inventory findings"
        >
          <ResponsiveContainer width="100%" height="100%">
            <RadarChart data={severityData} cx="50%" cy="50%" outerRadius="66%">
              <PolarGrid stroke="hsl(var(--border))" strokeOpacity={0.8} />
              <PolarAngleAxis
                dataKey="axis"
                tick={{ fill: "hsl(var(--foreground))", fontSize: 10 }}
              />
              <PolarRadiusAxis
                angle={90}
                domain={[0, 100]}
                tick={false}
                axisLine={false}
              />
              <Radar
                dataKey="value"
                stroke="#34d399"
                strokeWidth={2}
                fill="#34d399"
                fillOpacity={0.18}
                dot={{ r: 2.5, fill: "#34d399", strokeWidth: 0 }}
                isAnimationActive={true}
                animationDuration={900}
              />
            </RadarChart>
          </ResponsiveContainer>
        </div>

        <div
          className="flex w-full max-w-[760px] flex-col gap-3"
          aria-label="Open inventory findings by severity"
        >
          {severityData.map((item, idx) => (
            <div
              key={item.metric}
              className="flex min-w-0 items-center gap-3 text-xs"
            >
              <span className="w-4 shrink-0 font-mono text-muted-foreground tabular-nums">
                {idx + 1}
              </span>
              <span className="min-w-0 flex-1 truncate text-foreground">
                {item.metric}
              </span>
              <span className="h-1.5 w-20 shrink-0 overflow-hidden rounded-full bg-muted">
                <span
                  className="block h-full rounded-full"
                  style={{ width: `${item.value}%`, backgroundColor: item.color }}
                />
              </span>
              <span className="w-16 shrink-0 text-right font-mono text-muted-foreground tabular-nums">
                {item.count} ({Math.round(item.value)}%)
              </span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function PerformanceReadoutCard({
  activeFindings,
  resolvedFindings,
}: {
  activeFindings: InventoryFinding[];
  resolvedFindings: InventoryFinding[];
}) {
  const criticalCount = severityCounts(activeFindings).critical;
  const totalFindings = activeFindings.length + resolvedFindings.length;
  const fixRate = totalFindings
    ? Math.round((resolvedFindings.length / totalFindings) * 100)
    : 0;

  return (
    <Card className="siem-card flex h-full flex-col">
      <CardHeader className="flex-row items-start justify-between space-y-0">
        <div>
          <CardTitle className="text-sm">Remediation readout</CardTitle>
          <p className="mt-1 text-xs text-muted-foreground">
            Resolved findings across the scanned inventory
          </p>
        </div>
        <span className="rounded-md bg-orange-400/10 p-2 text-orange-300">
          <Lightbulb className="size-4" aria-hidden="true" />
        </span>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col justify-between gap-6">
        <div>
          <div className="flex items-end gap-2">
            <span className="font-mono text-5xl font-semibold tracking-tight text-foreground tabular-nums">
              {fixRate}
            </span>
            <span className="pb-1.5 text-sm text-muted-foreground">
              % fixed
            </span>
          </div>
          <div className="mt-4 h-2 overflow-hidden rounded-full bg-muted">
            <div
              className="h-full rounded-full bg-gradient-to-r from-orange-400 via-amber-300 to-emerald-400"
              style={{ width: `${fixRate}%` }}
            />
          </div>
          <p className="mt-2 text-xs text-muted-foreground">
            {resolvedFindings.length} fixed out of {totalFindings} findings tracked in the inventory.
          </p>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <div className="rounded-lg border border-emerald-400/15 bg-emerald-400/[0.04] p-4">
            <div className="text-[10px] font-medium uppercase tracking-[.14em] text-muted-foreground">
              Fixed findings
            </div>
            <div className="mt-3 flex items-end justify-between gap-2">
              <span className="text-sm font-medium text-foreground">
                Resolved
              </span>
              <span className="font-mono text-sm text-emerald-300 tabular-nums">
                {resolvedFindings.length}
              </span>
            </div>
          </div>
          <div className="rounded-lg border border-orange-400/15 bg-orange-400/[0.04] p-4">
            <div className="text-[10px] font-medium uppercase tracking-[.14em] text-muted-foreground">
              Critical open findings
            </div>
            <div className="mt-3 flex items-end justify-between gap-2">
              <span className="text-sm font-medium text-foreground">
                Unresolved
              </span>
              <span className="font-mono text-sm text-orange-300 tabular-nums">
                {criticalCount}
              </span>
            </div>
          </div>
        </div>

        <div className="rounded-lg border border-border/70 bg-muted/20 p-4">
          <div className="mb-2 flex items-center gap-2 text-xs font-medium text-foreground">
            <Lightbulb className="size-3.5 text-amber-200" aria-hidden="true" />
            Recommended focus
          </div>
          <p className="text-xs leading-relaxed text-muted-foreground">
            {criticalCount
              ? `Prioritize remediation of ${criticalCount} critical package finding${criticalCount === 1 ? "" : "s"} across the connected repositories.`
              : "No active critical package findings are recorded. Continue scanning repositories to keep the inventory current."}
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

export default function CommandCenterPage({
  onNavigate,
}: {
  onNavigate?: (tab: string) => void;
}) {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [scanError, setScanError] = useState("");
  const [scanSubmitting, setScanSubmitting] = useState(false);
  const [refreshVersion, setRefreshVersion] = useState(0);
  const [selectedDetection, setSelectedDetection] =
    useState<DetectionRecord | null>(null);
  const [timeWindow, setTimeWindow] = useState<"Last 24 hours" | "Last 7 days">(
    "Last 7 days"
  );

  useEffect(() => {
    let active = true;
    setLoading(true);
    setLoadError("");
    loadDashboardData()
      .then((result) => {
        if (active) setData(result);
      })
      .catch((error: unknown) => {
        if (active) {
          setLoadError(
            error instanceof Error
              ? error.message
              : "Dashboard data could not be loaded."
          );
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [refreshVersion]);

  const hasQueuedScans =
    data?.scans.some((scan) => scan.status === "queued" || scan.status === "running") ??
    false;
  useEffect(() => {
    if (!hasQueuedScans) return;
    const timer = window.setInterval(
      () => setRefreshVersion((version) => version + 1),
      5000
    );
    return () => window.clearInterval(timer);
  }, [hasQueuedScans]);

  const repositories = data?.repositories ?? [];
  const scans = data?.scans ?? [];
  const activeFindings = data?.activeFindings ?? [];
  const resolvedFindings = data?.resolvedFindings ?? [];
  const activeSeverityCounts = severityCounts(activeFindings);
  const activeCountsByRepository = findingsByRepository(activeFindings);
  const resolvedCountsByRepository = findingsByRepository(resolvedFindings);
  const activityData = useMemo(
    () => activityForScans(scans, timeWindow),
    [scans, timeWindow]
  );
  const latestScanByRepository = new Map<string, ScanRun>();
  for (const scan of scans) {
    if (!latestScanByRepository.has(scan.application_id)) {
      latestScanByRepository.set(scan.application_id, scan);
    }
  }
  const latestScannedPackageCount = [...latestScanByRepository.values()]
    .filter((scan) => scan.status === "succeeded")
    .reduce((total, scan) => total + (scan.component_count ?? 0), 0);
  const scansInWindow = activityData.reduce(
    (total, bucket) => total + bucket.scans,
    0
  );
  const packageFindings = new Map<
    string,
    {
      label: string;
      critical: number;
      high: number;
      medium: number;
      low: number;
      unknown: number;
      total: number;
    }
  >();
  for (const finding of activeFindings) {
    const repositoryName =
      finding.repository.name.split("/").pop() || finding.repository.name;
    const key = [
      finding.repository.application_id,
      finding.ecosystem,
      finding.package_name,
    ].join(":");
    const row = packageFindings.get(key) ?? {
      label: `${finding.package_name} — ${finding.repository.name}`,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0,
      total: 0,
    };
    const severity = SEVERITIES.find(
      (item) => item === finding.severity.toLowerCase()
    ) ?? "unknown";
    row[severity] += 1;
    row.total += 1;
    packageFindings.set(key, row);
  }
  const packageSeverityData = [...packageFindings.values()]
    .sort((left, right) => right.total - left.total)
    .slice(0, 6);
  const repositoryCoverageData = repositories
    .map((repository) => {
      const scan = latestScanByRepository.get(repository.application_id);
      return {
        name: repository.name,
        packages:
          scan?.status === "succeeded" ? scan.component_count ?? 0 : 0,
        findings: activeCountsByRepository.get(repository.application_id) ?? 0,
        status: scan?.status ?? "not scanned",
      };
    })
    .sort((left, right) => right.packages - left.packages)
    .slice(0, 3);
  const maxRepositoryPackageCount = Math.max(
    1,
    ...repositoryCoverageData.map((repository) => repository.packages)
  );
  const recentDetections = activeFindings
    .map((finding): DetectionRecord => ({
      id: [
        finding.repository.application_id,
        finding.ref,
        finding.package_name,
        finding.vulnerability_id,
      ].join(":"),
      time: formatDate(finding.last_seen || finding.first_seen),
      severity: SEVERITIES.find(
        (severity) => severity === finding.severity.toLowerCase()
      ) ?? "unknown",
      source: `${finding.repository.name} · ${finding.ecosystem || "package"}`,
      message: `${finding.vulnerability_id} · ${finding.package_name}`,
      repository: finding.repository.name,
      packageName: finding.package_name,
      ecosystem: finding.ecosystem || "—",
      vulnerabilityId: finding.vulnerability_id,
      installedVersion: finding.installed_version || "—",
      fixedVersion: finding.fixed_version || "No fixed version reported",
      status: finding.status,
      firstSeen: finding.first_seen || "",
      lastSeen: finding.last_seen || "",
    }))
    .sort((left, right) => {
      const latestFirst = Date.parse(right.lastSeen) - Date.parse(left.lastSeen);
      if (Number.isFinite(latestFirst) && latestFirst !== 0) return latestFirst;
      return SEVERITIES.indexOf(left.severity) - SEVERITIES.indexOf(right.severity);
    })
    .slice(0, 8);

  async function handleScanAll() {
    if (scanSubmitting || hasQueuedScans || repositories.length === 0) return;
    setScanError("");
    setScanSubmitting(true);
    try {
      const results = await Promise.allSettled(
        repositories.map((repository) =>
          apiFetch<{ scan: ScanRun }>(
            `/api/repositories/${encodeURIComponent(repository.application_id)}/scan`,
            { method: "POST" }
          )
        )
      );
      const failures = results.flatMap((result, index) =>
        result.status === "rejected"
          ? [
              `${repositories[index].name}: ${
                result.reason instanceof Error
                  ? result.reason.message
                  : "Scan could not be queued."
              }`,
            ]
          : []
      );
      if (failures.length) {
        setScanError(failures.join(" "));
      }
      setRefreshVersion((version) => version + 1);
    } finally {
      setScanSubmitting(false);
    }
  }

  function handleExportReport() {
    const criticalFindings = activeFindings.filter(
      (finding) => finding.severity === "CRITICAL"
    ).length;
    const payload = {
      generatedAt: new Date().toISOString(),
      window: timeWindow,
      metrics: {
        advisoriesTracked: data?.vulnerabilitySummary.total ?? 0,
        activePackageFindings: activeFindings.length,
        fixedPackageFindings: resolvedFindings.length,
        criticalOpenFindings: criticalFindings,
        connectedRepositories: repositories.length,
        latestPackagesScanned: latestScannedPackageCount,
      },
      recentFindings: recentDetections,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "tactical-ops-overview-report.json";
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <Sheet
      open={selectedDetection !== null}
      onOpenChange={(open) => {
        if (!open) setSelectedDetection(null);
      }}
    >
      <main className="mx-auto flex w-full min-w-0 max-w-[1600px] flex-col gap-5 p-4 sm:p-6 lg:p-8">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <div className="mb-2 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[.2em] text-orange-300">
              <span className="size-1.5 animate-pulse rounded-full bg-orange-400" />
              Repository vulnerability posture
            </div>
            <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">
              Security overview
            </h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Vulnerability exposure, scan coverage, and remediation across your connected repositories.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                setTimeWindow((w) =>
                  w === "Last 7 days" ? "Last 24 hours" : "Last 7 days"
                )
              }
              className="border-border/80 bg-card/70 text-muted-foreground"
            >
              <Clock3 className="mr-2 size-3.5" />
              {timeWindow}
            </Button>
            <Button
              size="sm"
              onClick={handleExportReport}
              className="bg-orange-400 text-[#09120f] hover:bg-orange-300"
            >
              <Download className="mr-2 size-3.5" />
              Export report
            </Button>
          </div>
        </div>

        <section
          className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4"
          aria-label="Inventory vulnerability metrics"
        >
          <KpiSparkCard
            title="Advisories tracked"
            value={data ? data.vulnerabilitySummary.total.toLocaleString() : "—"}
            caption="Across connected vulnerability feeds"
            icon={Activity}
            tone="bg-orange-400/10 text-orange-300"
            lineColor="#fb923c"
            trend={(data?.vulnerabilitySummary.sources ?? []).map(
              (source) => source.count
            )}
          />
          <KpiSparkCard
            title="Active package findings"
            value={data ? activeFindings.length.toLocaleString() : "—"}
            caption="Across the scanned inventory"
            icon={ShieldAlert}
            tone="bg-amber-300/10 text-amber-200"
            lineColor="#fcd34d"
            trend={repositories.map(
              (repository) =>
                activeCountsByRepository.get(repository.application_id) ?? 0
            )}
          />
          <KpiSparkCard
            title="Fixed package findings"
            value={data ? resolvedFindings.length.toLocaleString() : "—"}
            caption="Resolved by follow-up scans"
            icon={ShieldCheck}
            tone="bg-sky-300/10 text-sky-200"
            lineColor="#7dd3fc"
            trend={repositories.map(
              (repository) =>
                resolvedCountsByRepository.get(repository.application_id) ?? 0
            )}
          />
          <KpiSparkCard
            title="Critical open findings"
            value={data ? activeSeverityCounts.critical.toLocaleString() : "—"}
            caption="Unfixed critical package findings"
            icon={Siren}
            tone="bg-rose-400/10 text-rose-300"
            lineColor="#fb7185"
            trend={repositories.map(
              (repository) =>
                activeFindings.filter(
                  (finding) =>
                    finding.repository.application_id ===
                      repository.application_id &&
                    finding.severity === "CRITICAL"
                ).length
            )}
          />
        </section>
        {(loadError || scanError) && (
          <div
            role="alert"
            className="rounded-lg border border-rose-400/30 bg-rose-400/10 px-4 py-3 text-sm text-rose-200"
          >
            {loadError || scanError}
          </div>
        )}

        <section className="grid gap-4 xl:grid-cols-[minmax(0,1.8fr)_minmax(330px,1fr)]">
          <Card className="siem-card min-w-0">
            <CardHeader className="flex-row items-start justify-between space-y-0 pb-1">
              <div>
                <CardTitle className="text-sm">Scan activity</CardTitle>
                <p className="mt-1 text-xs text-muted-foreground">
                  {scansInWindow} scans · packages and findings over time
                </p>
              </div>
              <div className="flex gap-4 text-[10px] text-muted-foreground">
                <span className="flex items-center gap-1.5">
                  <i className="size-1.5 rounded-full bg-orange-300" />
                  Packages scanned
                </span>
                <span className="flex items-center gap-1.5">
                  <i className="size-1.5 rounded-full bg-sky-300" />
                  Findings
                </span>
              </div>
            </CardHeader>
            <CardContent className="pt-4">
              <div className="h-[230px] w-full sm:h-[275px]">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart
                    data={activityData}
                    margin={{ top: 6, right: 4, left: -18, bottom: 0 }}
                  >
                    <defs>
                      <linearGradient id="packagesFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#f97316" stopOpacity={0.22} />
                        <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="findingsFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#7dd3fc" stopOpacity={0.18} />
                        <stop offset="95%" stopColor="#7dd3fc" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid
                      stroke="hsl(var(--border))"
                      strokeOpacity={0.55}
                      vertical={false}
                    />
                    <XAxis
                      dataKey="time"
                      tickLine={false}
                      axisLine={false}
                      tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 10 }}
                      tickMargin={10}
                    />
                    <YAxis
                      tickLine={false}
                      axisLine={false}
                      tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 10 }}
                    />
                    <Tooltip
                      contentStyle={{
                        background: "hsl(var(--card))",
                        border: "1px solid hsl(var(--border))",
                        borderRadius: 8,
                        fontSize: 11,
                      }}
                    />
                    <Area
                      isAnimationActive={true}
                      type="monotone"
                      dataKey="components"
                      stroke="#f97316"
                      strokeWidth={2}
                      fill="url(#packagesFill)"
                      animationDuration={1100}
                    />
                    <Area
                      isAnimationActive={true}
                      type="monotone"
                      dataKey="findings"
                      stroke="#7dd3fc"
                      strokeWidth={1.5}
                      fill="url(#findingsFill)"
                      animationDuration={1400}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>

          <ThreatSurfaceScan
            repositoryCount={repositories.length}
            openFindingCount={activeFindings.length}
            packageCount={latestScannedPackageCount}
            scanning={scanSubmitting || hasQueuedScans}
            disabled={
              loading ||
              scanSubmitting ||
              hasQueuedScans ||
              repositories.length === 0
            }
            onScan={() => void handleScanAll()}
          />
        </section>

        <section
          className="grid items-stretch gap-4 xl:grid-cols-2"
          aria-label="Inventory severity and remediation readout"
        >
          <PostureOverviewCard findings={activeFindings} />
          <PerformanceReadoutCard
            activeFindings={activeFindings}
            resolvedFindings={resolvedFindings}
          />
        </section>

        <section className="grid gap-4 xl:grid-cols-2">
          <Card className="siem-card">
            <CardHeader className="flex-row items-center justify-between space-y-0">
              <div>
                <CardTitle className="text-sm">Top vulnerable packages</CardTitle>
                <p className="mt-1 text-xs text-muted-foreground">
                  Active vulnerabilities by severity · top six packages
                </p>
              </div>
              <Crosshair className="size-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="h-[220px] w-full">
                {packageSeverityData.length ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      data={packageSeverityData}
                      layout="vertical"
                      margin={{ top: 4, right: 12, left: 0, bottom: 0 }}
                      barCategoryGap="22%"
                    >
                      <CartesianGrid
                        stroke="hsl(var(--border))"
                        strokeOpacity={0.45}
                        horizontal={false}
                      />
                      <XAxis
                        type="number"
                        allowDecimals={false}
                        tickLine={false}
                        axisLine={false}
                        tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 10 }}
                      />
                      <YAxis
                        type="category"
                        dataKey="label"
                        width={130}
                        tickLine={false}
                        axisLine={false}
                        tickFormatter={(label: string) => {
                          const packageName = label.split(" — ")[0];
                          return packageName.length > 18
                            ? `${packageName.slice(0, 17)}…`
                            : packageName;
                        }}
                        tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 10 }}
                      />
                      <Tooltip
                        labelFormatter={(label) => String(label)}
                        contentStyle={{
                          background: "hsl(var(--card))",
                          border: "1px solid hsl(var(--border))",
                          borderRadius: 8,
                          fontSize: 11,
                        }}
                      />
                      <Bar
                        dataKey="critical"
                        stackId="severity"
                        fill={SEVERITY_COLORS.critical}
                        isAnimationActive
                        animationDuration={700}
                      />
                      <Bar
                        dataKey="high"
                        stackId="severity"
                        fill={SEVERITY_COLORS.high}
                        isAnimationActive
                        animationDuration={850}
                      />
                      <Bar
                        dataKey="medium"
                        stackId="severity"
                        fill={SEVERITY_COLORS.medium}
                        isAnimationActive
                        animationDuration={1000}
                      />
                      <Bar
                        dataKey="low"
                        stackId="severity"
                        fill={SEVERITY_COLORS.low}
                        isAnimationActive
                        animationDuration={1150}
                      />
                      <Bar
                        dataKey="unknown"
                        stackId="severity"
                        fill={SEVERITY_COLORS.unknown}
                        radius={[0, 3, 3, 0]}
                        isAnimationActive
                        animationDuration={1300}
                      />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
                    {loading
                      ? "Loading package findings…"
                      : "No active package findings to chart."}
                  </div>
                )}
              </div>
              <div className="mt-2 flex flex-wrap gap-4 text-[10px] text-muted-foreground">
                <span className="flex items-center gap-1.5">
                  <i className="size-1.5 rounded-full bg-rose-400" />
                  Critical
                </span>
                <span className="flex items-center gap-1.5">
                  <i className="size-1.5 rounded-full bg-orange-300" />
                  High
                </span>
                <span className="flex items-center gap-1.5">
                  <i className="size-1.5 rounded-full bg-amber-200" />
                  Medium
                </span>
                <span className="flex items-center gap-1.5">
                  <i className="size-1.5 rounded-full bg-sky-300" />
                  Low
                </span>
                <span className="flex items-center gap-1.5">
                  <i className="size-1.5 rounded-full bg-neutral-400" />
                  Unrated
                </span>
              </div>
            </CardContent>
          </Card>

          <Card className="siem-card">
            <CardHeader className="flex-row items-center justify-between space-y-0">
              <div>
                <CardTitle className="text-sm">Repository scan coverage</CardTitle>
                <p className="mt-1 text-xs text-muted-foreground">
                  Latest completed scan per repository
                </p>
              </div>
              <Earth className="size-4 text-muted-foreground" />
            </CardHeader>
            <CardContent className="flex flex-col gap-4 pt-1">
              {repositoryCoverageData.length === 0 && (
                <p className="text-xs text-muted-foreground">
                  {loading
                    ? "Loading connected repositories…"
                    : "No repositories have been connected yet."}
                </p>
              )}
              {repositoryCoverageData.map((repository, index) => {
                const Icon = [Crosshair, Wifi, Radio][index] ?? Crosshair;
                return (
                <div key={repository.name}>
                  <div className="mb-2 flex items-center justify-between text-xs">
                    <span className="flex items-center gap-2 text-foreground">
                      <Icon className="size-3.5 text-muted-foreground" />
                      <span className="truncate">{repository.name}</span>
                    </span>
                    <span className="shrink-0 font-mono text-muted-foreground tabular-nums">
                      {repository.packages}{" "}
                      <span className="text-[10px]">packages</span>
                    </span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-muted">
                    <div
                      className={`h-full rounded-full ${
                        index === 0
                          ? "bg-orange-300"
                          : index === 1
                            ? "bg-sky-300"
                            : "bg-amber-200"
                      } progress-grow`}
                      style={{
                        width: `${(repository.packages / maxRepositoryPackageCount) * 100}%`,
                      }}
                    />
                  </div>
                  <p className="mt-1 text-[10px] text-muted-foreground">
                    {repository.findings} active findings · {repository.status}
                  </p>
                </div>
                );
              })}
            </CardContent>
          </Card>
        </section>

        <Card className="siem-card overflow-hidden">
          <CardHeader className="flex-row items-center justify-between space-y-0 border-b border-border/70 px-4 py-4 sm:px-5">
            <div>
              <CardTitle className="text-sm">Latest open findings</CardTitle>
              <p className="mt-1 text-xs text-muted-foreground">
                Vulnerabilities matched to packages in your scanned repositories
              </p>
            </div>
            <Button
              onClick={() => onNavigate?.("operations")}
              variant="ghost"
              size="sm"
              className="text-orange-400 hover:text-orange-300"
            >
              View applications <ArrowUpRight className="ml-1 size-3.5" />
            </Button>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y divide-border/60">
              {!recentDetections.length && (
                <p className="px-5 py-8 text-center text-xs text-muted-foreground">
                  {loading
                    ? "Loading package findings…"
                    : "No active package findings are recorded."}
                </p>
              )}
              {recentDetections.map((det) => (
                <button
                  key={det.id}
                  type="button"
                  onClick={() => setSelectedDetection(det)}
                  aria-label={`View ${det.severity} package finding: ${det.message}`}
                  className="grid w-full gap-2 px-4 py-3 text-left transition-colors hover:bg-muted/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-orange-300 sm:grid-cols-[90px_92px_minmax(0,1fr)_minmax(120px,180px)_110px] sm:items-center sm:px-5 cursor-pointer"
                >
                  <span className="font-mono text-[10px] text-muted-foreground tabular-nums">
                    {det.time}
                  </span>
                  <Badge
                    variant="outline"
                    className={`w-fit text-[9px] uppercase ${
                      SEVERITY_BADGE_CLASSES[det.severity]
                    }`}
                  >
                    {det.severity}
                  </Badge>
                  <div className="min-w-0">
                    <div className="truncate text-xs font-medium text-foreground">
                      {det.message}
                    </div>
                    <div className="mt-1 text-[10px] text-muted-foreground">
                      {det.source}
                    </div>
                  </div>
                  <span className="truncate font-mono text-[10px] text-muted-foreground">
                    {det.ecosystem}
                  </span>
                  <span className="font-mono text-[10px] text-muted-foreground tabular-nums">
                    {det.installedVersion}
                  </span>
                </button>
              ))}
            </div>
          </CardContent>
          <div className="border-t border-border/70 px-4 py-2.5 text-[10px] text-muted-foreground sm:px-5">
            <span className="text-orange-300">●</span>{" "}
            {loading ? "Refreshing inventory data…" : "Connected to vulnerability inventory"}{" "}
            <span className="mx-2 text-border">|</span>
            {repositories.length} repositories · {scans.length} recent scans
          </div>
        </Card>
      </main>

      <SheetContent
        open={selectedDetection !== null}
        onClose={() => setSelectedDetection(null)}
        className="flex w-full flex-col gap-6 border-l border-orange-400/15 bg-card sm:max-w-md"
      >
        <SheetHeader className="pr-8">
          <div className="mb-2 flex items-center gap-2">
            <span className="size-1.5 animate-pulse rounded-full bg-orange-400" />
            <span className="text-[10px] font-semibold uppercase tracking-[.18em] text-orange-300">
              Package vulnerability
            </span>
          </div>
          <SheetTitle className="text-left text-xl leading-snug">
            {selectedDetection?.message ?? "Detection details"}
          </SheetTitle>
          <SheetDescription className="text-left">
            Review the affected repository package, installed version, and
            available fixed version.
          </SheetDescription>
        </SheetHeader>

        {selectedDetection && (
          <div className="flex flex-col gap-5">
            <div className="flex items-center gap-3">
              <Badge
                variant="outline"
                className={`uppercase ${
                  SEVERITY_BADGE_CLASSES[selectedDetection.severity]
                }`}
              >
                {SEVERITY_LABELS[selectedDetection.severity]} severity
              </Badge>
              <span className="font-mono text-xs text-muted-foreground tabular-nums">
                {selectedDetection.time}
              </span>
            </div>

            <div className="grid gap-3">
              {[
                { label: "Repository", value: selectedDetection.repository },
                { label: "Package", value: selectedDetection.packageName },
                { label: "Ecosystem", value: selectedDetection.ecosystem },
                { label: "Vulnerability", value: selectedDetection.vulnerabilityId },
                { label: "Installed version", value: selectedDetection.installedVersion },
                { label: "Fixed version", value: selectedDetection.fixedVersion },
                { label: "Status", value: selectedDetection.status },
                { label: "First seen", value: formatDate(selectedDetection.firstSeen) },
                { label: "Last seen", value: formatDate(selectedDetection.lastSeen) },
              ].map((row) => (
                <div
                  key={row.label}
                  className="flex items-center justify-between gap-4 border-b border-border/60 py-3"
                >
                  <span className="text-xs text-muted-foreground">
                    {row.label}
                  </span>
                  <span className="text-right font-mono text-xs text-foreground">
                    {row.value}
                  </span>
                </div>
              ))}
            </div>

            <div className="rounded-lg border border-orange-400/15 bg-orange-400/[0.04] p-4">
              <div className="mb-2 text-[10px] font-semibold uppercase tracking-[.14em] text-orange-300">
                Remediation note
              </div>
              <p className="text-xs leading-relaxed text-muted-foreground">
                {selectedDetection.fixedVersion === "No fixed version reported"
                  ? `No fixed version is currently reported for ${selectedDetection.vulnerabilityId}. Review vendor guidance and monitor the package for updates.`
                  : `Update ${selectedDetection.packageName} from ${selectedDetection.installedVersion} to a fixed version (${selectedDetection.fixedVersion}) and run a new repository scan to verify remediation.`}
              </p>
            </div>

            <Button
              onClick={() => {
                setSelectedDetection(null);
                onNavigate?.("operations");
              }}
              className="mt-1 bg-orange-400 text-[#09120f] hover:bg-orange-300"
            >
              Open application scans <ArrowUpRight className="ml-2 size-4" />
            </Button>
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}
