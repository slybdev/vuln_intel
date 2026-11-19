import { useEffect, useState } from "react";
import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Download,
  Eye,
  FileText,
  Filter,
  Globe,
  Search,
  Shield,
} from "lucide-react";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Input,
} from "@/src/components/ui/primitives";
import {
  apiFetch,
  formatDate,
  Severity,
  severityLabel,
  Vulnerability,
  VulnerabilityPage,
  VulnerabilitySummary,
} from "@/src/lib/vuln-intel-api";

interface IntelReport {
  id: string;
  title: string;
  classification: Severity;
  source: string;
  location: string;
  date: string;
  status: "exploited" | "high EPSS" | "tracked";
  threat: string;
  summary: string;
  tags: string[];
  vulnerability: Vulnerability;
}

const PAGE_SIZE = 25;

function toReport(vulnerability: Vulnerability): IntelReport {
  const score = vulnerability.exploitation?.epss?.score;
  const status = vulnerability.exploitation?.in_kev
    ? "exploited"
    : score != null && score >= 0.7
      ? "high EPSS"
      : "tracked";
  const affected = (vulnerability.affected ?? [])
    .map(({ package: packageName, ecosystem }) => {
      if (!packageName) return ecosystem ?? "";
      return ecosystem ? `${packageName} (${ecosystem})` : packageName;
    })
    .filter(Boolean);

  return {
    id: vulnerability.id,
    title: vulnerability.title || vulnerability.id,
    classification: vulnerability.severity || "UNKNOWN",
    source: vulnerability.sources?.join(", ") || "Unknown source",
    location:
      affected.join(", ") ||
      vulnerability.exploitation?.kev?.product ||
      "Package details unavailable",
    date: vulnerability.published
      ? formatDate(vulnerability.published)
      : vulnerability.exploitation?.kev?.date_added
        ? `KEV added ${formatDate(vulnerability.exploitation.kev.date_added)}`
        : "Date unavailable",
    status,
    threat: (vulnerability.severity || "UNKNOWN").toLowerCase(),
    summary:
      vulnerability.description ||
      "No description was provided by the source feeds.",
    tags: [...(vulnerability.sources ?? []), ...(vulnerability.cwes ?? [])],
    vulnerability,
  };
}

export default function IntelligencePage() {
  const [searchTerm, setSearchTerm] = useState("");
  const [threatFilter, setThreatFilter] = useState<string>("all");
  const [reports, setReports] = useState<IntelReport[]>([]);
  const [summary, setSummary] = useState<VulnerabilitySummary | null>(null);
  const [total, setTotal] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedReport, setSelectedReport] = useState<IntelReport | null>(
    null
  );
  const [modalNotice, setModalNotice] = useState("");
  const [refreshTick, setRefreshTick] = useState(0);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    const timer = window.setTimeout(() => {
      const params = new URLSearchParams({
        q: searchTerm.trim(),
        severity: threatFilter === "all" ? "" : threatFilter,
        page: String(currentPage),
        page_size: String(PAGE_SIZE),
      });
      setIsLoading(true);
      Promise.all([
        apiFetch<VulnerabilityPage>(`/api/vulnerabilities?${params}`),
        apiFetch<VulnerabilitySummary>("/api/summary"),
      ])
        .then(([page, nextSummary]) => {
          if (!active) return;
          setReports(page.items.map(toReport));
          setTotal(page.total);
          setSummary(nextSummary);
          setError("");
          setIsLoading(false);
        })
        .catch((reason: unknown) => {
          if (active) {
            setError(
              reason instanceof Error
                ? reason.message
                : "Vulnerability intelligence could not be loaded."
            );
            setIsLoading(false);
          }
        });
    }, searchTerm ? 200 : 0);

    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [searchTerm, threatFilter, currentPage, refreshTick]);

  async function openReport(report: IntelReport) {
    setSelectedReport(report);
    setModalNotice("");
    try {
      const detail = await apiFetch<Vulnerability>(
        `/api/vulnerabilities/${encodeURIComponent(report.id)}`
      );
      setSelectedReport(toReport(detail));
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Vulnerability details could not be loaded."
      );
    }
  }

  const classificationBadge = (cls: string) => {
    switch (cls) {
      case "CRITICAL":
        return "bg-red-500/20 text-red-500";
      case "HIGH":
        return "bg-orange-500/20 text-orange-500";
      case "LOW":
        return "bg-sky-500/20 text-sky-300";
      case "MEDIUM":
        return "bg-neutral-500/20 text-foreground";
      default:
        return "bg-white/20 text-foreground";
    }
  };

  const threatBadge = (threat: string) => {
    switch (threat) {
      case "critical":
        return "bg-red-500/20 text-red-500";
      case "high":
        return "bg-orange-500/20 text-orange-500";
      case "low":
        return "bg-white/20 text-foreground";
      case "medium":
      default:
        return "bg-neutral-500/20 text-foreground";
    }
  };

  const statusBadge = (status: string) => {
    switch (status) {
      case "tracked":
        return "bg-white/20 text-foreground";
      case "high EPSS":
        return "bg-orange-500/20 text-orange-500";
      case "exploited":
        return "bg-red-500/20 text-red-500";
      default:
        return "bg-neutral-500/20 text-foreground";
    }
  };

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const firstItem = total === 0 ? 0 : (currentPage - 1) * PAGE_SIZE + 1;
  const lastItem = Math.min(currentPage * PAGE_SIZE, total);
  const rawEpssScore = selectedReport?.vulnerability.exploitation?.epss?.score;
  const epssScore =
    typeof rawEpssScore === "number" && Number.isFinite(rawEpssScore)
      ? Math.min(1, Math.max(0, rawEpssScore))
      : null;

  function cycleThreatFilter() {
    const order = ["all", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
    setCurrentPage(1);
    setThreatFilter(order[(order.indexOf(threatFilter) + 1) % order.length]);
  }

  return (
    <main className="mx-auto flex w-full min-w-0 max-w-[1500px] flex-col gap-5 p-4 sm:p-6 lg:p-8">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <div className="mb-2 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[.2em] text-orange-300">
            <span className="size-1.5 animate-pulse rounded-full bg-orange-400" />
            Vulnerability feeds · {summary?.sources.length ?? "—"} sources
          </div>
          <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">
            Vulnerability intelligence
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Search and investigate advisories from connected feeds.
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            onClick={() => setRefreshTick((value) => value + 1)}
            className="bg-orange-400 text-[#09120f] hover:bg-orange-300"
          >
            Refresh Feeds
          </Button>
          <Button
            onClick={cycleThreatFilter}
            className="bg-orange-400 text-[#09120f] hover:bg-orange-300"
          >
            <Filter className="w-4 h-4 mr-2" />
            {threatFilter === "all" ? "Filter" : `Threat: ${threatFilter}`}
          </Button>
        </div>
      </div>
      {error && (
        <p
          role="alert"
          className="rounded-lg border border-rose-400/20 bg-rose-400/5 p-3 text-xs text-rose-300"
        >
          Backend data unavailable: {error}
        </p>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        <Card className="lg:col-span-2 siem-card">
          <CardContent className="p-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search CVE, GHSA, title, source, or description..."
                value={searchTerm}
                onChange={(e) => {
                  setCurrentPage(1);
                  setSearchTerm(e.target.value);
                }}
                className="pl-10 bg-muted border-neutral-600 text-foreground placeholder-neutral-400"
              />
            </div>
          </CardContent>
        </Card>

        <Card className="siem-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground tracking-wider">
                  TRACKED VULNERABILITIES
                </p>
                <p className="text-2xl font-bold text-foreground font-mono tabular-nums">
                  {summary?.total.toLocaleString() ?? "—"}
                </p>
              </div>
              <FileText className="w-8 h-8 text-foreground" />
            </div>
          </CardContent>
        </Card>

        <Card className="siem-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground tracking-wider">
                  CRITICAL SEVERITY
                </p>
                <p className="text-2xl font-bold text-red-500 font-mono tabular-nums">
                  {summary?.critical.toLocaleString() ?? "—"}
                </p>
              </div>
              <AlertTriangle className="w-8 h-8 text-red-500" />
            </div>
          </CardContent>
        </Card>

        <Card className="siem-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground tracking-wider">
                  CONNECTED FEEDS
                </p>
                <p className="text-2xl font-bold text-foreground font-mono tabular-nums">
                  {summary?.sources.length.toLocaleString() ?? "—"}
                </p>
              </div>
              <Globe className="w-8 h-8 text-foreground" />
            </div>
          </CardContent>
        </Card>
      </div>

      <Card className="siem-card">
        <CardHeader>
          <CardTitle className="text-sm font-medium text-foreground tracking-wider">
            VULNERABILITY RECORDS · {total.toLocaleString()}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {reports.map((report) => (
              <div
                key={report.id}
                className="border border-border/70 rounded p-4 hover:border-orange-500/50 transition-colors cursor-pointer"
                role="button"
                tabIndex={0}
                onClick={() => void openReport(report)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    void openReport(report);
                  }
                }}
              >
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                  <div className="flex-1 space-y-2">
                    <div className="flex items-start gap-3">
                      <FileText className="w-5 h-5 text-muted-foreground mt-0.5" />
                      <div className="flex-1">
                        <h3 className="text-sm font-bold text-foreground tracking-wider">
                          {report.title}
                        </h3>
                        <p className="text-xs text-muted-foreground font-mono">
                          {report.id}
                        </p>
                      </div>
                    </div>
                    <p className="text-sm text-foreground ml-8">
                      {report.summary}
                    </p>
                    <div className="flex flex-wrap gap-2 ml-8">
                      {report.tags.map((tag) => (
                        <Badge
                          key={tag}
                          className="bg-muted text-foreground text-xs"
                        >
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  <div className="flex flex-col sm:items-end gap-2">
                    <div className="flex flex-wrap gap-2">
                      <Badge className={classificationBadge(report.classification)}>
                        {severityLabel(report.classification)}
                      </Badge>
                      <Badge className={threatBadge(report.threat)}>
                        {report.threat.toUpperCase()}
                      </Badge>
                      <Badge className={statusBadge(report.status)}>
                        {report.status.toUpperCase()}
                      </Badge>
                    </div>
                    <div className="text-xs text-muted-foreground space-y-1">
                      <div className="flex items-center gap-2">
                        <Globe className="w-3 h-3" />
                        <span>{report.location}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Shield className="w-3 h-3" />
                        <span>{report.source}</span>
                      </div>
                      <div className="font-mono">{report.date}</div>
                    </div>
                  </div>
                </div>
              </div>
            ))}
            {!reports.length && (
              <p className="py-8 text-center text-sm text-muted-foreground">
                {error
                  ? "Vulnerability records could not be loaded."
                  : isLoading
                    ? "Loading vulnerability records..."
                    : "No vulnerabilities match this search."}
              </p>
            )}
          </div>
          <div className="mt-5 flex flex-col gap-3 border-t border-border/70 pt-4 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-xs text-muted-foreground" aria-live="polite">
              Showing {firstItem.toLocaleString()}–{lastItem.toLocaleString()} of{" "}
              {total.toLocaleString()} vulnerabilities · Page {currentPage} of{" "}
              {totalPages.toLocaleString()}
            </p>
            <div className="flex items-center gap-2">
              <Button
                size="sm"
                variant="outline"
                aria-label="Previous vulnerability page"
                disabled={currentPage <= 1 || isLoading}
                onClick={() => setCurrentPage((page) => Math.max(1, page - 1))}
                className="border-border/70 bg-transparent text-muted-foreground hover:bg-muted hover:text-foreground"
              >
                <ChevronLeft />
                Previous
              </Button>
              <Button
                size="sm"
                variant="outline"
                aria-label="Next vulnerability page"
                disabled={currentPage >= totalPages || isLoading}
                onClick={() =>
                  setCurrentPage((page) => Math.min(totalPages, page + 1))
                }
                className="border-border/70 bg-transparent text-muted-foreground hover:bg-muted hover:text-foreground"
              >
                Next
                <ChevronRight />
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {selectedReport && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
          <Card className="siem-card w-full max-w-4xl max-h-[90vh] overflow-y-auto">
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle className="text-xl font-bold text-foreground tracking-wider">
                  {selectedReport.title}
                </CardTitle>
                <p className="text-sm text-muted-foreground font-mono">
                  {selectedReport.id}
                </p>
              </div>
              <Button
                variant="ghost"
                onClick={() => setSelectedReport(null)}
                className="text-muted-foreground hover:text-foreground"
              >
                ✕
              </Button>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <div>
                    <h3 className="text-sm font-medium text-foreground tracking-wider mb-2">
                      CLASSIFICATION
                    </h3>
                    <div className="flex gap-2">
                      <Badge
                        className={classificationBadge(
                          selectedReport.classification
                        )}
                      >
                        {severityLabel(selectedReport.classification)}
                      </Badge>
                      <Badge className={threatBadge(selectedReport.threat)}>
                        THREAT: {severityLabel(selectedReport.threat.toUpperCase())}
                      </Badge>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-sm font-medium text-foreground tracking-wider mb-2">
                      SOURCE DETAILS
                    </h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">
                          Source Type:
                        </span>
                        <span className="text-foreground font-mono">
                          {selectedReport.source}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Location:</span>
                        <span className="text-foreground">
                          {selectedReport.location}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Date:</span>
                        <span className="text-foreground font-mono">
                          {selectedReport.date}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Status:</span>
                        <Badge className={statusBadge(selectedReport.status)}>
                          {selectedReport.status.toUpperCase()}
                        </Badge>
                      </div>
                      {selectedReport.vulnerability.exploitation?.kev?.date_added && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">CISA KEV added:</span>
                          <span className="text-foreground font-mono">
                            {formatDate(
                              selectedReport.vulnerability.exploitation.kev.date_added
                            )}
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                <div className="space-y-4">
                  <div>
                    <h3 className="text-sm font-medium text-foreground tracking-wider mb-2">
                      TAGS
                    </h3>
                    <div className="flex flex-wrap gap-2">
                      {selectedReport.tags.map((tag) => (
                        <Badge
                          key={tag}
                          className="bg-muted text-foreground"
                        >
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  <div>
                    <h3 className="text-sm font-medium text-foreground tracking-wider mb-2">
                      THREAT ASSESSMENT
                    </h3>
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className="text-muted-foreground">
                          EPSS Probability
                        </span>
                        <Badge className={threatBadge(selectedReport.threat)}>
                          {epssScore === null
                            ? "Unavailable"
                            : `${(epssScore * 100).toFixed(1)}%`}
                        </Badge>
                      </div>
                      {epssScore !== null ? (
                        <div className="w-full bg-muted rounded-full h-2">
                          <div
                            className="h-2 rounded-full bg-orange-400 transition-all duration-300"
                            style={{ width: `${epssScore * 100}%` }}
                          />
                        </div>
                      ) : (
                        <p className="text-xs text-muted-foreground">
                          No EPSS probability is available for this record.
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              <div>
                <h3 className="text-sm font-medium text-foreground tracking-wider mb-2">
                  ADVISORY DESCRIPTION
                </h3>
                <p className="text-sm text-foreground leading-relaxed">
                  {selectedReport.summary}
                </p>
                <div className="mt-4 grid grid-cols-1 gap-2 text-xs sm:grid-cols-2">
                  <div className="text-muted-foreground">
                    CVSS:{" "}
                    <span className="text-foreground">
                      {selectedReport.vulnerability.cvss_best?.score ?? "—"}
                    </span>
                  </div>
                  <div className="text-muted-foreground">
                    EPSS:{" "}
                    <span className="text-foreground">
                      {epssScore === null
                        ? "—"
                        : `${(epssScore * 100).toFixed(1)}%`}
                    </span>
                  </div>
                  <div className="text-muted-foreground">
                    CISA KEV:{" "}
                    <span className="text-foreground">
                      {selectedReport.vulnerability.exploitation?.in_kev
                        ? "Listed"
                        : "Not listed"}
                    </span>
                  </div>
                  <div className="text-muted-foreground">
                    Published:{" "}
                    <span className="text-foreground">
                      {formatDate(selectedReport.vulnerability.published)}
                    </span>
                  </div>
                  {selectedReport.vulnerability.exploitation?.kev?.required_action && (
                    <div className="text-muted-foreground sm:col-span-2">
                      CISA required action:{" "}
                      <span className="text-foreground">
                        {selectedReport.vulnerability.exploitation.kev.required_action}
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {modalNotice && (
                <p className="text-xs text-orange-300 font-mono">
                  {modalNotice}
                </p>
              )}

              <div className="flex gap-2 pt-4 border-t border-border/70">
                <Button
                  onClick={() => {
                    const advisory =
                      selectedReport.vulnerability.references?.[0] ??
                      selectedReport.vulnerability.exploitation?.kev?.notes
                        ?.split(";")[0]
                        ?.trim();
                    if (advisory) {
                      window.open(advisory, "_blank", "noopener,noreferrer");
                    } else {
                      setModalNotice("No advisory URL is available for this record.");
                    }
                  }}
                  className="bg-orange-400 text-[#09120f] hover:bg-orange-300"
                >
                  <Eye className="w-4 h-4 mr-2" />
                  View Advisory
                </Button>
                <Button
                  variant="outline"
                  onClick={() => {
                    const blob = new Blob(
                      [JSON.stringify(selectedReport.vulnerability, null, 2)],
                      { type: "application/json" }
                    );
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = `${selectedReport.id}.json`;
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                  className="border-border/70 text-muted-foreground hover:bg-muted hover:text-foreground bg-transparent"
                >
                  <Download className="w-4 h-4 mr-2" />
                  Download
                </Button>
                <Button
                  variant="outline"
                  onClick={async () => {
                    try {
                      await navigator.clipboard.writeText(
                        `${window.location.origin}/api/vulnerabilities/${encodeURIComponent(selectedReport.id)}`
                      );
                      setModalNotice("Vulnerability API link copied.");
                    } catch {
                      setModalNotice("Could not copy the API link to the clipboard.");
                    }
                  }}
                  className="border-border/70 text-muted-foreground hover:bg-muted hover:text-foreground bg-transparent"
                >
                  Share Intel
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </main>
  );
}
