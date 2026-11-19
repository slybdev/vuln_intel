import { useEffect, useMemo, useState } from "react";
import {
  Boxes,
  CheckCircle2,
  Clock3,
  ExternalLink,
  Filter,
  MoreHorizontal,
  Package,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  X,
} from "lucide-react";
import {
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Input,
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
} from "@/src/lib/vuln-intel-api";

interface ApplicationRecord {
  repository: Repository;
  scan?: ScanRun;
  findings: ApplicationFinding[];
}

type ScanStatusFilter =
  | "all"
  | "succeeded"
  | "running"
  | "queued"
  | "failed"
  | "not-scanned";

const SCAN_FILTERS: ScanStatusFilter[] = [
  "all",
  "succeeded",
  "running",
  "queued",
  "failed",
  "not-scanned",
];

function scanStatus(application: ApplicationRecord): string {
  return application.scan?.status ?? "not scanned";
}

function statusBadgeClass(status: string): string {
  switch (status) {
    case "succeeded":
      return "bg-white/20 text-foreground";
    case "running":
      return "bg-sky-400/20 text-sky-300";
    case "queued":
      return "bg-orange-500/20 text-orange-300";
    case "failed":
      return "bg-red-500/20 text-red-400";
    default:
      return "bg-neutral-500/20 text-muted-foreground";
  }
}

function severityOf(findings: ApplicationFinding[]): string {
  const priority = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  return (
    priority.find((severity) =>
      findings.some((finding) => finding.severity === severity)
    ) ?? (findings.length ? "UNKNOWN" : "NONE")
  );
}

function severityBadgeClass(severity: string): string {
  switch (severity) {
    case "CRITICAL":
      return "bg-red-500/20 text-red-400";
    case "HIGH":
      return "bg-orange-500/20 text-orange-300";
    case "MEDIUM":
      return "bg-amber-300/20 text-amber-200";
    case "LOW":
      return "bg-sky-300/20 text-sky-200";
    default:
      return "bg-neutral-500/20 text-muted-foreground";
  }
}

export default function AgentNetworkPage({
  onNavigate,
}: {
  onNavigate?: (tab: string) => void;
}) {
  const [applications, setApplications] = useState<ApplicationRecord[]>([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState<ScanStatusFilter>("all");
  const [selectedApplication, setSelectedApplication] =
    useState<ApplicationRecord | null>(null);
  const [refreshTick, setRefreshTick] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");

    apiFetch<RepositoryList>("/api/repositories")
      .then(async (repositoryResult) => {
        const applicationsWithFindings = await Promise.all(
          repositoryResult.items.map(async (repository) => {
            const applicationId = encodeURIComponent(
              repository.application_id
            );
            const [findings, scans] = await Promise.all([
              apiFetch<FindingList>(
                `/api/applications/${applicationId}/findings?status=active`
              ),
              apiFetch<ScanList>(
                `/api/scans?application_id=${applicationId}&limit=1`
              ),
            ]);
            return {
              repository,
              scan: scans.items[0],
              findings: findings.items,
            };
          })
        );
        if (active) setApplications(applicationsWithFindings);
      })
      .catch((reason: unknown) => {
        if (active) {
          setError(
            reason instanceof Error
              ? reason.message
              : "Connected applications could not be loaded."
          );
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [refreshTick]);

  const filteredApplications = useMemo(
    () =>
      applications.filter((application) => {
        const query = searchTerm.trim().toLowerCase();
        const matchesSearch =
          !query ||
          application.repository.name.toLowerCase().includes(query) ||
          application.repository.application_id.toLowerCase().includes(query) ||
          application.repository.repository_url.toLowerCase().includes(query);
        const matchesStatus =
          statusFilter === "all" ||
          (statusFilter === "not-scanned"
            ? !application.scan
            : application.scan?.status === statusFilter);
        return matchesSearch && matchesStatus;
      }),
    [applications, searchTerm, statusFilter]
  );

  const allFindings = applications.flatMap((application) => application.findings);
  const criticalFindings = allFindings.filter(
    (finding) => finding.severity === "CRITICAL"
  ).length;
  const successfullyScanned = applications.filter(
    (application) => application.scan?.status === "succeeded"
  ).length;
  const packagesScanned = applications.reduce(
    (total, application) =>
      total +
      (application.scan?.status === "succeeded"
        ? application.scan.component_count ?? 0
        : 0),
    0
  );

  function cycleFilter() {
    const next = (SCAN_FILTERS.indexOf(statusFilter) + 1) % SCAN_FILTERS.length;
    setStatusFilter(SCAN_FILTERS[next]);
  }

  function openApplication(application: ApplicationRecord) {
    setSelectedApplication(application);
  }

  function refreshApplications() {
    setRefreshTick((tick) => tick + 1);
  }

  return (
    <main className="mx-auto flex w-full min-w-0 max-w-[1500px] flex-col gap-5 p-4 sm:p-6 lg:p-8">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <div className="mb-2 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[.2em] text-orange-300">
            <span className="size-1.5 animate-pulse rounded-full bg-orange-400" />
            Application inventory · {applications.length} connected ·{" "}
            {successfullyScanned} scanned
          </div>
          <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">
            Connected applications
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Latest scan status and dependency findings · {packagesScanned} packages scanned
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={refreshApplications}
            className="border-border/70 text-muted-foreground hover:bg-muted hover:text-foreground bg-transparent"
          >
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
          <Button
            onClick={() => onNavigate?.("operations")}
            className="bg-orange-400 text-[#09120f] hover:bg-orange-300"
          >
            Manage scans
          </Button>
          <Button
            onClick={cycleFilter}
            className="bg-orange-400 text-[#09120f] hover:bg-orange-300"
          >
            <Filter className="w-4 h-4 mr-2" />
            {statusFilter === "all"
              ? "Filter"
              : `Filter: ${statusFilter.replace("-", " ")}`}
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <Card className="lg:col-span-1 siem-card">
          <CardContent className="p-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search applications or repositories..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
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
                  CONNECTED APPLICATIONS
                </p>
                <p className="text-2xl font-bold text-foreground font-mono tabular-nums">
                  {applications.length}
                </p>
              </div>
              <Boxes className="w-8 h-8 text-foreground" />
            </div>
          </CardContent>
        </Card>

        <Card className="siem-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground tracking-wider">
                  ACTIVE VULNERABILITIES
                </p>
                <p className="text-2xl font-bold text-orange-300 font-mono tabular-nums">
                  {allFindings.length}
                </p>
              </div>
              <ShieldCheck className="w-8 h-8 text-orange-300" />
            </div>
          </CardContent>
        </Card>

        <Card className="siem-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground tracking-wider">
                  CRITICAL FINDINGS
                </p>
                <p className="text-2xl font-bold text-orange-500 font-mono tabular-nums">
                  {criticalFindings}
                </p>
              </div>
              <ShieldAlert className="w-8 h-8 text-red-400" />
            </div>
          </CardContent>
        </Card>
      </div>

      <Card className="siem-card">
        <CardHeader>
          <CardTitle className="text-sm font-medium text-foreground tracking-wider">
            CONNECTED APPLICATIONS
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[980px]">
              <thead>
                <tr className="border-b border-border/70">
                  <th className="text-left py-3 px-4 text-xs font-medium text-muted-foreground tracking-wider">
                    APPLICATION ID
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-muted-foreground tracking-wider">
                    REPOSITORY
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-muted-foreground tracking-wider">
                    SCAN STATUS
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-muted-foreground tracking-wider">
                    PACKAGES
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-muted-foreground tracking-wider">
                    ACTIVE VULNERABILITIES
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-muted-foreground tracking-wider">
                    LAST SCAN
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-muted-foreground tracking-wider">
                    HIGHEST SEVERITY
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-muted-foreground tracking-wider">
                    DETAILS
                  </th>
                </tr>
              </thead>
              <tbody>
                {loading && applications.length === 0 && (
                  <tr>
                    <td
                      colSpan={8}
                      className="px-4 py-8 text-center text-sm text-muted-foreground"
                    >
                      Loading connected applications…
                    </td>
                  </tr>
                )}
                {!loading && !error && filteredApplications.length === 0 && (
                  <tr>
                    <td
                      colSpan={8}
                      className="px-4 py-8 text-center text-sm text-muted-foreground"
                    >
                      {applications.length
                        ? "No applications match this search or filter."
                        : "No repositories are connected yet. Add one from Manage scans."}
                    </td>
                  </tr>
                )}
                {filteredApplications.map((application, index) => {
                  const status = scanStatus(application);
                  const severity = severityOf(application.findings);
                  const scanDate = formatDate(
                    application.scan?.completed_at ??
                      application.scan?.requested_at
                  );
                  return (
                    <tr
                      key={application.repository.application_id}
                      className={`border-b border-neutral-800 hover:bg-muted transition-colors cursor-pointer ${
                        index % 2 === 0 ? "bg-neutral-900" : "bg-neutral-850"
                      }`}
                      onClick={() => openApplication(application)}
                    >
                      <td className="py-3 px-4 text-xs text-muted-foreground font-mono">
                        {application.repository.application_id}
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex min-w-0 flex-col gap-1">
                          <span className="text-sm font-medium text-foreground">
                            {application.repository.name}
                          </span>
                          <a
                            href={application.repository.repository_url}
                            target="_blank"
                            rel="noreferrer"
                            onClick={(event) => event.stopPropagation()}
                            className="flex items-center gap-1 truncate text-xs text-muted-foreground hover:text-orange-300"
                          >
                            {application.repository.repository_url}
                            <ExternalLink className="size-3 shrink-0" />
                          </a>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`inline-flex items-center gap-1.5 rounded px-2 py-1 text-[10px] uppercase tracking-wider ${statusBadgeClass(status)}`}
                        >
                          {status === "succeeded" && (
                            <CheckCircle2 className="size-3" />
                          )}
                          {status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-sm font-mono tabular-nums text-foreground">
                        <span className="inline-flex items-center gap-1.5">
                          <Package className="size-3 text-muted-foreground" />
                          {application.scan?.component_count ?? "—"}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-sm font-mono tabular-nums text-foreground">
                        {application.findings.length}
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2 text-sm text-foreground font-mono">
                          <Clock3 className="size-3 text-muted-foreground" />
                          {scanDate}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`rounded px-2 py-1 text-[10px] uppercase tracking-wider ${severityBadgeClass(severity)}`}
                        >
                          {severity}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label={`Inspect ${application.repository.name}`}
                          onClick={(event) => {
                            event.stopPropagation();
                            openApplication(application);
                          }}
                          className="text-muted-foreground hover:text-orange-500"
                        >
                          <MoreHorizontal className="w-4 h-4" />
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {error && (
            <p role="alert" className="mt-4 text-sm text-red-400">
              {error}
            </p>
          )}
        </CardContent>
      </Card>

      {selectedApplication && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
          role="dialog"
          aria-modal="true"
          aria-labelledby="application-details-title"
        >
          <Card className="siem-card max-h-[90vh] w-full max-w-2xl overflow-y-auto">
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle
                  id="application-details-title"
                  className="text-lg font-bold text-foreground tracking-wider"
                >
                  {selectedApplication.repository.name}
                </CardTitle>
                <p className="text-sm text-muted-foreground font-mono">
                  {selectedApplication.repository.application_id}
                </p>
              </div>
              <Button
                variant="ghost"
                aria-label="Close application details"
                onClick={() => setSelectedApplication(null)}
                className="text-muted-foreground hover:text-foreground"
              >
                <X className="size-4" />
              </Button>
            </CardHeader>
            <CardContent className="space-y-4">
              <a
                href={selectedApplication.repository.repository_url}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-2 text-sm text-orange-300 hover:text-orange-200"
              >
                {selectedApplication.repository.repository_url}
                <ExternalLink className="size-3.5" />
              </a>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-xs text-muted-foreground tracking-wider mb-1">
                    LATEST SCAN
                  </p>
                  <span
                    className={`rounded px-2 py-1 text-xs uppercase tracking-wider ${statusBadgeClass(scanStatus(selectedApplication))}`}
                  >
                    {scanStatus(selectedApplication)}
                  </span>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground tracking-wider mb-1">
                    HIGHEST SEVERITY
                  </p>
                  <span
                    className={`rounded px-2 py-1 text-xs uppercase tracking-wider ${severityBadgeClass(severityOf(selectedApplication.findings))}`}
                  >
                    {severityOf(selectedApplication.findings)}
                  </span>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground tracking-wider mb-1">
                    PACKAGES SCANNED
                  </p>
                  <p className="text-sm text-foreground font-mono tabular-nums">
                    {selectedApplication.scan?.component_count ?? "—"}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground tracking-wider mb-1">
                    ACTIVE VULNERABILITIES
                  </p>
                  <p className="text-sm text-foreground font-mono tabular-nums">
                    {selectedApplication.findings.length}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground tracking-wider mb-1">
                    BRANCH / REF
                  </p>
                  <p className="break-all text-sm text-foreground font-mono">
                    {selectedApplication.scan?.ref ?? "No scan recorded"}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground tracking-wider mb-1">
                    LAST SCAN
                  </p>
                  <p className="text-sm text-foreground font-mono">
                    {formatDate(
                      selectedApplication.scan?.completed_at ??
                        selectedApplication.scan?.requested_at
                    )}
                  </p>
                </div>
              </div>

              <div>
                <div className="mb-3 flex items-center justify-between">
                  <h3 className="text-xs font-medium tracking-wider text-foreground">
                    ACTIVE PACKAGE FINDINGS
                  </h3>
                  <span className="font-mono text-xs text-muted-foreground">
                    {selectedApplication.findings.length}
                  </span>
                </div>
                {selectedApplication.findings.length ? (
                  <div className="max-h-64 space-y-2 overflow-y-auto">
                    {selectedApplication.findings.slice(0, 8).map((finding) => (
                      <div
                        key={`${finding.vulnerability_id}:${finding.package_name}:${finding.purl}`}
                        className="flex items-start justify-between gap-3 rounded border border-border/70 bg-background/40 p-3"
                      >
                        <div className="min-w-0">
                          <p className="truncate text-sm font-medium text-foreground">
                            {finding.vulnerability_id} · {finding.package_name}
                          </p>
                          <p className="mt-1 text-xs text-muted-foreground">
                            {finding.ecosystem || "Package"}{" "}
                            {finding.installed_version
                              ? `· ${finding.installed_version}`
                              : ""}
                            {finding.fixed_version
                              ? ` · Fix: ${finding.fixed_version}`
                              : ""}
                          </p>
                        </div>
                        <span
                          className={`shrink-0 rounded px-2 py-1 text-[10px] uppercase ${severityBadgeClass(finding.severity)}`}
                        >
                          {finding.severity}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="rounded border border-border/70 bg-background/40 p-4 text-sm text-muted-foreground">
                    No active package findings are recorded for this application.
                  </p>
                )}
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <Button
                  variant="outline"
                  onClick={() => setSelectedApplication(null)}
                  className="border-border/70 text-muted-foreground hover:bg-muted hover:text-foreground bg-transparent"
                >
                  Close
                </Button>
                <Button
                  onClick={() => {
                    setSelectedApplication(null);
                    onNavigate?.("operations");
                  }}
                  className="bg-orange-400 text-[#09120f] hover:bg-orange-300"
                >
                  Manage scans
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </main>
  );
}
