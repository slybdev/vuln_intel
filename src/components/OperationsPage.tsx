import { useEffect, useMemo, useState, type FormEvent } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Clock,
  ExternalLink,
  MapPin,
  Target,
  Users,
  XCircle,
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
  ApplicationFinding,
  CredentialList,
  FindingList,
  formatDate,
  ProviderCredential,
  Repository,
  RepositoryList,
  ScanList,
  ScanRun,
  Severity,
} from "@/src/lib/vuln-intel-api";

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function stringValues(value: unknown): string[] {
  if (typeof value === "string") return value.trim() ? [value] : [];
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string" && !!item.trim())
    : [];
}

function safeWebUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:";
  } catch {
    return false;
  }
}

interface OperationRecord {
  id: string;
  name: string;
  status: "active" | "planning" | "completed" | "compromised";
  priority: "critical" | "high" | "medium" | "low";
  location: string;
  agents: number;
  progress: number;
  startDate: string;
  estimatedCompletion: string;
  description: string;
  repository: Repository;
  run?: ScanRun;
  findings: ApplicationFinding[];
}

export default function OperationsPage() {
  const [operations, setOperations] = useState<OperationRecord[]>([]);
  const [runs, setRuns] = useState<ScanRun[]>([]);
  const [credentials, setCredentials] = useState<ProviderCredential[]>([]);
  const [selectedOp, setSelectedOp] = useState<OperationRecord | null>(null);
  const [selectedFinding, setSelectedFinding] =
    useState<ApplicationFinding | null>(null);
  const [findingDetails, setFindingDetails] =
    useState<ApplicationFinding | null>(null);
  const [findingDetailsLoading, setFindingDetailsLoading] = useState(false);
  const [findingDetailsError, setFindingDetailsError] = useState("");
  const [findingDetailRequest, setFindingDetailRequest] = useState(0);
  const [showFullFindingDetails, setShowFullFindingDetails] = useState(false);
  const [statusFeedback, setStatusFeedback] = useState("");
  const [formMode, setFormMode] = useState<"repository" | "credentials" | null>(
    null
  );
  const [repositoryUrl, setRepositoryUrl] = useState("");
  const [githubUsername, setGithubUsername] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [refreshTick, setRefreshTick] = useState(0);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!selectedOp) return;

    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      setSelectedOp(null);
      setSelectedFinding(null);
      setShowFullFindingDetails(false);
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [selectedOp]);

  useEffect(() => {
    let active = true;
    setLoading(true);
    Promise.all([
      apiFetch<RepositoryList>("/api/repositories"),
      apiFetch<ScanList>("/api/scans?limit=100"),
      apiFetch<CredentialList>("/api/git-credentials"),
    ])
      .then(async ([repositoryResult, scanResult, credentialResult]) => {
        const findingResults = await Promise.all(
          repositoryResult.items.map(async (repository) => {
            const result = await apiFetch<FindingList>(
              `/api/applications/${encodeURIComponent(repository.application_id)}/findings?status=active`
            );
            return [repository.application_id, result.items] as const;
          })
        );
        if (!active) return;

        const findingsByApplication = new Map(findingResults);
        const nextOperations = repositoryResult.items.map((repository) => {
          const applicationRuns = scanResult.items.filter(
            (run) => run.application_id === repository.application_id
          );
          const run = applicationRuns[0];
          const findings = findingsByApplication.get(repository.application_id) ?? [];
          const severityOrder: Severity[] = [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "UNKNOWN",
          ];
          const highestSeverity = severityOrder.find((severity) =>
            findings.some((finding) => finding.severity === severity)
          );
          const status: OperationRecord["status"] =
            run?.status === "succeeded"
              ? "completed"
              : run?.status === "failed"
                ? "compromised"
                : run?.status === "running"
                  ? "active"
                  : "planning";
          const progress =
            run?.status === "succeeded" || run?.status === "failed"
              ? 100
              : run?.status === "running"
                ? 65
                : run?.status === "queued"
                  ? 20
                  : 0;
          return {
            id: repository.application_id,
            name: repository.name,
            status,
            priority: highestSeverity?.toLowerCase() as OperationRecord["priority"] | undefined ?? "low",
            location: repository.repository_url,
            agents: run?.component_count ?? 0,
            progress,
            startDate: formatDate(run?.requested_at),
            estimatedCompletion:
              run?.status === "running"
                ? "Scan in progress"
                : run?.status === "queued"
                  ? "Waiting for worker"
                  : "—",
            description: run
              ? `${findings.length.toLocaleString()} vulnerabilities · commit ${
                  run.commit_sha === "HEAD"
                    ? run.ref
                    : run.commit_sha.slice(0, 12)
                }`
              : "No scan has been requested for this repository.",
            repository,
            run,
            findings,
          } satisfies OperationRecord;
        });

        setOperations(nextOperations);
        setRuns(scanResult.items);
        setCredentials(credentialResult.items);
        setError("");
      })
      .catch((reason: unknown) => {
        if (active) {
          setError(
            reason instanceof Error
              ? reason.message
              : "Application scan data could not be loaded."
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

  useEffect(() => {
    if (!selectedOp || !selectedFinding) {
      setFindingDetails(null);
      setFindingDetailsLoading(false);
      setFindingDetailsError("");
      return;
    }

    let active = true;
    setFindingDetails(null);
    setFindingDetailsError("");
    setFindingDetailsLoading(true);
    const query = new URLSearchParams({
      ref: selectedFinding.ref ?? "",
      vulnerability_id: selectedFinding.vulnerability_id,
      package_name: selectedFinding.package_name,
      installed_version: selectedFinding.installed_version ?? "",
    });

    apiFetch<ApplicationFinding>(
      `/api/applications/${encodeURIComponent(selectedOp.repository.application_id)}/finding-details?${query}`
    )
      .then((details) => {
        if (active) setFindingDetails(details);
      })
      .catch((reason: unknown) => {
        if (active) {
          setFindingDetailsError(
            reason instanceof Error
              ? reason.message
              : "Additional vulnerability evidence could not be loaded."
          );
        }
      })
      .finally(() => {
        if (active) setFindingDetailsLoading(false);
      });

    return () => {
      active = false;
    };
  }, [findingDetailRequest, selectedFinding, selectedOp]);

  const findingTotals = useMemo(
    () => operations.flatMap((operation) => operation.findings),
    [operations]
  );
  const completedScans = runs.filter((run) => run.status === "succeeded").length;
  const criticalAndHigh = findingTotals.filter(
    (finding) => finding.severity === "CRITICAL" || finding.severity === "HIGH"
  ).length;
  const successRate = runs.length
    ? Math.round((completedScans / runs.length) * 100)
    : null;
  const detailFinding = findingDetails ?? selectedFinding;
  const selectedEvidence = findingDetails?.evidence ?? {};
  const trivyEvidence = Array.isArray(selectedEvidence.trivy)
    ? selectedEvidence.trivy.filter(isRecord)
    : [];
  const internalEvidence = Array.isArray(selectedEvidence.vuln_intel)
    ? selectedEvidence.vuln_intel.filter(isRecord)
    : [];
  const trivyDetails = trivyEvidence[0] ?? {};
  const advisoryDetails =
    internalEvidence
      .map((item) => item.advisory)
      .find(isRecord) ?? {};
  const findingTitle =
    stringValue(advisoryDetails.title) ??
    stringValue(trivyDetails.Title) ??
    detailFinding?.vulnerability_id ??
    "";
  const findingDescription =
    stringValue(advisoryDetails.description) ??
    stringValue(trivyDetails.Description);
  const findingReferences = [
    ...new Set([
      ...stringValues(advisoryDetails.references),
      ...stringValues(trivyDetails.References),
      ...stringValues(trivyDetails.PrimaryURL),
    ]),
  ].filter(safeWebUrl);
  const findingCwes = [
    ...new Set([
      ...stringValues(advisoryDetails.cwes),
      ...stringValues(trivyDetails.CweIDs),
    ]),
  ];
  const advisoryCvss = isRecord(advisoryDetails.cvss_best)
    ? advisoryDetails.cvss_best
    : {};
  const trivyCvss = isRecord(trivyDetails.CVSS) ? trivyDetails.CVSS : {};
  const findingCvss =
    typeof advisoryCvss.score === "number"
      ? [
          `${stringValue(advisoryCvss.version) ?? "CVSS"} ${advisoryCvss.score.toFixed(1)}${
            stringValue(advisoryCvss.vector)
              ? ` · ${stringValue(advisoryCvss.vector)}`
              : ""
          }`,
        ]
      : Object.entries(trivyCvss).flatMap(([provider, metrics]) => {
          if (!isRecord(metrics)) return [];
          const scoreKey = ["V4Score", "V3Score", "V2Score"].find(
            (key) => typeof metrics[key] === "number"
          );
          if (!scoreKey || typeof metrics[scoreKey] !== "number") return [];
          const vector = stringValue(metrics[scoreKey.replace("Score", "Vector")]);
          return [
            `${provider.toUpperCase()} ${metrics[scoreKey].toFixed(1)}${
              vector ? ` · ${vector}` : ""
            }`,
          ];
        });
  const exploitation = isRecord(advisoryDetails.exploitation)
    ? advisoryDetails.exploitation
    : {};
  const epss = isRecord(exploitation.epss) ? exploitation.epss : {};
  const hasFindingEvidence =
    trivyEvidence.length > 0 || internalEvidence.length > 0;

  function refreshData() {
    setRefreshTick((value) => value + 1);
  }

  async function submitRepository(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setStatusFeedback("");
    try {
      const result = await apiFetch<{
        repository: Repository;
        scan: ScanRun;
        created: boolean;
      }>("/api/repositories/scan", {
        method: "POST",
        body: JSON.stringify({ repository_url: repositoryUrl.trim() }),
      });
      setRepositoryUrl("");
      setFormMode(null);
      setStatusFeedback(
        result.created
          ? `Scan queued for ${result.repository.name}.`
          : `A scan is already queued for ${result.repository.name}.`
      );
      refreshData();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Repository could not be added.");
    } finally {
      setBusy(false);
    }
  }

  async function submitCredentials(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setStatusFeedback("");
    try {
      const result = await apiFetch<{
        credentials: ProviderCredential & {
          verification?: { status?: string };
        };
      }>("/api/git-credentials", {
        method: "POST",
        body: JSON.stringify({
          provider: "github",
          username: githubUsername.trim(),
          token: githubToken,
        }),
      });
      setGithubToken("");
      setFormMode(null);
      setStatusFeedback(
        result.credentials.verification?.status === "verified"
          ? "GitHub credentials verified and saved."
          : "GitHub credentials saved."
      );
      refreshData();
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "GitHub credentials could not be saved."
      );
    } finally {
      setBusy(false);
    }
  }

  async function scanLatest(operation: OperationRecord) {
    setBusy(true);
    setError("");
    setStatusFeedback("");
    try {
      await apiFetch(
        `/api/repositories/${encodeURIComponent(operation.repository.application_id)}/scan`,
        { method: "POST" }
      );
      setStatusFeedback(`Latest commit scan queued for ${operation.name}.`);
      setSelectedOp(null);
      setSelectedFinding(null);
      refreshData();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Scan could not be queued.");
    } finally {
      setBusy(false);
    }
  }

  async function removeRepository(operation: OperationRecord) {
    if (!window.confirm(`Remove ${operation.name} from connected applications?`)) {
      return;
    }
    setBusy(true);
    setError("");
    try {
      await apiFetch(
        `/api/repositories/${encodeURIComponent(operation.repository.application_id)}`,
        { method: "DELETE" }
      );
      setSelectedOp(null);
      setSelectedFinding(null);
      setStatusFeedback(`${operation.name} was removed.`);
      refreshData();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Repository could not be removed.");
    } finally {
      setBusy(false);
    }
  }

  const statusBadgeClass = (status: string) => {
    switch (status) {
      case "active":
      case "completed":
        return "bg-white/20 text-foreground";
      case "planning":
        return "bg-orange-500/20 text-orange-500";
      case "compromised":
        return "bg-red-500/20 text-red-500";
      default:
        return "bg-neutral-500/20 text-foreground";
    }
  };

  const priorityBadgeClass = (priority: string) => {
    switch (priority) {
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

  const renderStatusIcon = (status: string) => {
    switch (status) {
      case "active":
        return <Target className="w-4 h-4" />;
      case "planning":
        return <Clock className="w-4 h-4" />;
      case "completed":
        return <CheckCircle2 className="w-4 h-4" />;
      case "compromised":
        return <XCircle className="w-4 h-4" />;
      default:
        return <AlertTriangle className="w-4 h-4" />;
    }
  };

  return (
    <main className="mx-auto flex w-full min-w-0 max-w-[1500px] flex-col gap-5 p-4 sm:p-6 lg:p-8">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <div className="mb-2 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[.2em] text-orange-300">
            <span className="size-1.5 animate-pulse rounded-full bg-orange-400" />
            Repository scans · {operations.length} connected
          </div>
          <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">
            Application scans
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Repository inventory, scan status, and dependency findings
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            onClick={() => setFormMode("repository")}
            className="bg-orange-400 text-[#09120f] hover:bg-orange-300"
          >
            Add Repository
          </Button>
          <Button
            onClick={() => setFormMode("credentials")}
            className="bg-orange-400 text-[#09120f] hover:bg-orange-300"
          >
            GitHub Access
          </Button>
        </div>
      </div>

      {error && (
        <p
          role="alert"
          className="rounded-lg border border-rose-400/20 bg-rose-400/5 p-3 text-xs text-rose-300"
        >
          {error}
        </p>
      )}
      {statusFeedback && !selectedOp && (
        <p
          role="status"
          className="rounded-lg border border-orange-400/20 bg-orange-400/5 p-3 text-xs text-orange-200"
        >
          {statusFeedback}
        </p>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="siem-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground tracking-wider">
                  CONNECTED REPOSITORIES
                </p>
                <p className="text-2xl font-bold text-foreground font-mono tabular-nums">
                  {operations.length.toLocaleString()}
                </p>
              </div>
              <Target className="w-8 h-8 text-foreground" />
            </div>
          </CardContent>
        </Card>

        <Card className="siem-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground tracking-wider">
                  SUCCESSFUL SCANS
                </p>
                <p className="text-2xl font-bold text-foreground font-mono tabular-nums">
                  {completedScans.toLocaleString()}
                </p>
              </div>
              <CheckCircle2 className="w-8 h-8 text-foreground" />
            </div>
          </CardContent>
        </Card>

        <Card className="siem-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground tracking-wider">
                  CRITICAL + HIGH
                </p>
                <p className="text-2xl font-bold text-red-500 font-mono tabular-nums">
                  {criticalAndHigh.toLocaleString()}
                </p>
              </div>
              <XCircle className="w-8 h-8 text-red-500" />
            </div>
          </CardContent>
        </Card>

        <Card className="siem-card">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground tracking-wider">
                  SUCCESS RATE
                </p>
                <p className="text-2xl font-bold text-foreground font-mono tabular-nums">
                  {successRate === null ? "—" : `${successRate}%`}
                </p>
              </div>
              <AlertTriangle className="w-8 h-8 text-foreground" />
            </div>
          </CardContent>
        </Card>
      </div>

      {formMode && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <Card className="siem-card w-full max-w-xl">
            <CardHeader className="flex flex-row items-start justify-between">
              <div>
                <CardTitle className="text-base tracking-wider">
                  {formMode === "repository"
                    ? "ADD GITHUB REPOSITORY"
                    : "VERIFY GITHUB ACCESS"}
                </CardTitle>
                <p className="mt-2 text-xs text-muted-foreground">
                  {formMode === "repository"
                    ? "Add a repository and queue a scan of its latest default-branch commit."
                    : "Credentials are verified before being saved encrypted by the backend."}
                </p>
              </div>
              <Button
                variant="ghost"
                aria-label="Close dialog"
                onClick={() => setFormMode(null)}
                className="text-muted-foreground hover:text-foreground"
              >
                ✕
              </Button>
            </CardHeader>
            <CardContent>
              {formMode === "repository" ? (
                <form onSubmit={submitRepository} className="space-y-4">
                  <label className="block text-xs text-muted-foreground">
                    GitHub repository URL
                    <Input
                      required
                      type="url"
                      autoComplete="url"
                      placeholder="https://github.com/company/service"
                      value={repositoryUrl}
                      onChange={(event) => setRepositoryUrl(event.target.value)}
                      className="mt-1.5 bg-muted text-foreground"
                    />
                  </label>
                  <div className="flex justify-end gap-2">
                    <Button
                      variant="ghost"
                      onClick={() => setFormMode(null)}
                    >
                      Cancel
                    </Button>
                    <Button
                      type="submit"
                      disabled={busy}
                      className="bg-orange-400 text-[#09120f] hover:bg-orange-300"
                    >
                      Add and scan
                    </Button>
                  </div>
                </form>
              ) : (
                <form onSubmit={submitCredentials} className="space-y-4">
                  <label className="block text-xs text-muted-foreground">
                    GitHub username
                    <Input
                      required
                      autoComplete="username"
                      value={githubUsername}
                      onChange={(event) => setGithubUsername(event.target.value)}
                      className="mt-1.5 bg-muted text-foreground"
                    />
                  </label>
                  <label className="block text-xs text-muted-foreground">
                    Personal access token
                    <Input
                      required
                      type="password"
                      autoComplete="new-password"
                      value={githubToken}
                      onChange={(event) => setGithubToken(event.target.value)}
                      className="mt-1.5 bg-muted text-foreground"
                    />
                  </label>
                  <p className="text-xs text-muted-foreground">
                    GitHub access:{" "}
                    {credentials.find((item) => item.provider === "github")
                      ?.configured
                      ? "configured"
                      : "not configured"}
                    . Public repositories do not require a token.
                  </p>
                  <div className="flex justify-end gap-2">
                    <Button
                      variant="ghost"
                      onClick={() => setFormMode(null)}
                    >
                      Cancel
                    </Button>
                    <Button
                      type="submit"
                      disabled={busy}
                      className="bg-orange-400 text-[#09120f] hover:bg-orange-300"
                    >
                      Verify and save
                    </Button>
                  </div>
                </form>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
        {operations.map((op) => (
          <Card
            key={op.id}
            className="siem-card hover:border-orange-500/50 transition-colors cursor-pointer"
            onClick={() => {
              setSelectedOp(op);
              setSelectedFinding(null);
              setShowFullFindingDetails(false);
              setStatusFeedback("");
            }}
          >
            <CardHeader className="pb-3">
              <div className="flex items-start justify-between">
                <div>
                  <CardTitle className="text-sm font-bold text-foreground tracking-wider">
                    {op.name}
                  </CardTitle>
                  <p className="text-xs text-muted-foreground font-mono">
                    {op.id}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  {renderStatusIcon(op.status)}
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-2">
                <Badge className={statusBadgeClass(op.status)}>
                  {op.status.toUpperCase()}
                </Badge>
                <Badge className={priorityBadgeClass(op.priority)}>
                  {op.priority.toUpperCase()}
                </Badge>
              </div>

              <p className="text-sm text-foreground">{op.description}</p>

              <div className="space-y-2">
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <MapPin className="w-3 h-3" />
                  <span>{op.location}</span>
                </div>
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <Users className="w-3 h-3" />
                  <span>{op.agents.toLocaleString()} components scanned</span>
                </div>
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <Clock className="w-3 h-3" />
                  <span>Last scan requested: {op.startDate}</span>
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex justify-between text-xs">
                  <span className="text-muted-foreground">Progress</span>
                  <span className="text-foreground font-mono tabular-nums">
                    {op.progress}%
                  </span>
                </div>
                <div className="w-full bg-muted rounded-full h-2">
                  <div
                    className="bg-orange-500 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${op.progress}%` }}
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
        {!operations.length && (
          <div className="col-span-full rounded-lg border border-border/70 p-8 text-center text-sm text-muted-foreground">
            {loading
              ? "Loading connected repositories…"
              : error
                ? "Repository scan data is unavailable."
                : "No repositories connected yet. Add a GitHub repository to start its first scan."}
          </div>
        )}
      </div>

      {selectedOp && (
        <div
          className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50"
          onClick={() => {
            setSelectedOp(null);
            setSelectedFinding(null);
            setShowFullFindingDetails(false);
          }}
        >
          <Card
            role="dialog"
            aria-modal="true"
            aria-labelledby="selected-operation-title"
            onClick={(event) => event.stopPropagation()}
            className="siem-card flex w-full max-w-4xl max-h-[90vh] flex-col overflow-hidden"
          >
            <CardHeader className="flex shrink-0 flex-row items-center justify-between">
              <div>
                <CardTitle
                  id="selected-operation-title"
                  className="text-xl font-bold text-foreground tracking-wider"
                >
                  {selectedOp.name}
                </CardTitle>
                <p className="text-sm text-muted-foreground font-mono">
                  {selectedOp.id}
                </p>
              </div>
              <Button
                variant="ghost"
                onClick={() => {
                  setSelectedOp(null);
                  setSelectedFinding(null);
                  setShowFullFindingDetails(false);
                }}
                aria-label="Close application scan details"
                className="text-muted-foreground hover:text-foreground"
              >
                ✕
              </Button>
            </CardHeader>
            <CardContent className="min-h-0 flex-1 overflow-y-auto space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <div>
                    <h3 className="text-sm font-medium text-foreground tracking-wider mb-2">
                      SCAN STATUS
                    </h3>
                    <div className="flex gap-2">
                      <Badge className={statusBadgeClass(selectedOp.status)}>
                        {selectedOp.status.toUpperCase()}
                      </Badge>
                      <Badge
                        className={priorityBadgeClass(selectedOp.priority)}
                      >
                        {selectedOp.priority.toUpperCase()}
                      </Badge>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-sm font-medium text-foreground tracking-wider mb-2">
                      REPOSITORY DETAILS
                    </h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Repository:</span>
                        <span className="max-w-[65%] break-all text-right text-foreground">
                          {selectedOp.repository.repository_url}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">                        Components scanned:</span>
                        <span className="text-foreground font-mono tabular-nums">
                          {selectedOp.agents.toLocaleString()}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">
                          Requested:
                        </span>
                        <span className="text-foreground font-mono">
                          {selectedOp.startDate}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">
                          Scan status:
                        </span>
                        <span className="text-foreground font-mono">
                          {selectedOp.run?.status ?? "not scanned"}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="space-y-4">
                  <div>
                    <h3 className="text-sm font-medium text-foreground tracking-wider mb-2">
                      PROGRESS
                    </h3>
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className="text-muted-foreground">Scan progress</span>
                        <span className="text-foreground font-mono tabular-nums">
                          {selectedOp.progress}%
                        </span>
                      </div>
                      <div className="w-full bg-muted rounded-full h-3">
                        <div
                          className="bg-orange-500 h-3 rounded-full transition-all duration-300"
                          style={{ width: `${selectedOp.progress}%` }}
                        />
                      </div>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-sm font-medium text-foreground tracking-wider mb-2">
                      ACTIVE VULNERABILITIES · {selectedOp.findings.length}
                    </h3>
                    <div className="max-h-64 space-y-2 overflow-y-auto pr-1">
                      {selectedOp.findings.map((finding, index) => (
                        <button
                          key={`${finding.vulnerability_id}:${finding.package_name}:${finding.installed_version ?? ""}:${index}`}
                          type="button"
                          aria-pressed={selectedFinding === finding}
                          onClick={() => {
                            if (selectedFinding === finding) {
                              setSelectedFinding(null);
                              setFindingDetails(null);
                              setFindingDetailsError("");
                              setFindingDetailsLoading(false);
                              setShowFullFindingDetails(false);
                              return;
                            }
                            setSelectedFinding(finding);
                            setFindingDetailRequest((request) => request + 1);
                            setFindingDetails(null);
                            setFindingDetailsError("");
                            setFindingDetailsLoading(true);
                            setShowFullFindingDetails(false);
                          }}
                          className={`w-full rounded-md border p-2 text-left transition-colors ${
                            selectedFinding === finding
                              ? "border-orange-400/60 bg-orange-400/10"
                              : "border-border/70 bg-background/40 hover:border-orange-400/40"
                          }`}
                        >
                          <span className="flex items-center justify-between gap-2">
                            <span className="min-w-0 break-all font-mono text-xs text-foreground">
                              {finding.vulnerability_id}
                            </span>
                            <Badge className={priorityBadgeClass(finding.severity.toLowerCase())}>
                              {finding.severity}
                            </Badge>
                          </span>
                          <span className="mt-1 block break-words text-xs text-muted-foreground">
                            {finding.package_name}
                            {finding.installed_version
                              ? ` · ${finding.installed_version}`
                              : ""}
                            {finding.fixed_version
                              ? ` → ${finding.fixed_version}`
                              : ""}
                          </span>
                        </button>
                      ))}
                      {!selectedOp.findings.length && (
                        <p className="text-xs text-muted-foreground">
                          No active vulnerabilities for this repository.
                        </p>
                      )}
                    </div>
                    {selectedFinding && detailFinding && (
                      <section
                        aria-label={`Details for ${detailFinding.vulnerability_id}`}
                        className="mt-4 space-y-3 rounded-lg border border-border/70 bg-background/50 p-3"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <h4 className="break-words text-sm font-semibold text-foreground">
                              {findingTitle}
                            </h4>
                            <p className="mt-1 break-all font-mono text-xs text-orange-300">
                              {detailFinding.vulnerability_id}
                            </p>
                          </div>
                          <Badge className={priorityBadgeClass(detailFinding.severity.toLowerCase())}>
                            {detailFinding.severity}
                          </Badge>
                        </div>

                        {findingDetailsLoading ? (
                          <p role="status" className="text-xs text-muted-foreground">
                            Loading complete advisory details…
                          </p>
                        ) : findingDetailsError ? (
                          <p role="alert" className="text-xs text-rose-300">
                            {findingDetailsError}
                          </p>
                        ) : (
                          <p className="whitespace-pre-wrap break-words text-xs leading-relaxed text-muted-foreground">
                            {findingDescription ??
                              "No description was included in the available scan evidence."}
                          </p>
                        )}

                        <dl className="grid grid-cols-1 gap-2 text-xs sm:grid-cols-2">
                          {[
                            ["Package", detailFinding.package_name],
                            ["Ecosystem", detailFinding.ecosystem ?? undefined],
                            ["Installed version", detailFinding.installed_version ?? undefined],
                            ["Fixed version", detailFinding.fixed_version ?? undefined],
                            ["Package URL", detailFinding.purl ?? undefined],
                            ["First detected", formatDate(detailFinding.first_seen)],
                            ["Last detected", formatDate(detailFinding.last_seen)],
                            ["Data sources", detailFinding.sources.join(", ")],
                          ].map(([label, value]) => (
                            <div key={label} className="min-w-0">
                              <dt className="text-muted-foreground">{label}</dt>
                              <dd className="break-all text-foreground">{value || "—"}</dd>
                            </div>
                          ))}
                        </dl>

                        {findingCvss.length > 0 && (
                          <div className="space-y-1 text-xs">
                            <p className="text-muted-foreground">CVSS assessment</p>
                            {findingCvss.map((assessment) => (
                              <p key={assessment} className="break-all text-foreground">
                                {assessment}
                              </p>
                            ))}
                          </div>
                        )}
                        {findingCwes.length > 0 && (
                          <div className="text-xs">
                            <span className="text-muted-foreground">Weaknesses: </span>
                            <span className="text-foreground">{findingCwes.join(", ")}</span>
                          </div>
                        )}
                        {exploitation.in_kev === true && (
                          <p className="text-xs font-medium text-rose-300">
                            Listed in CISA Known Exploited Vulnerabilities.
                          </p>
                        )}
                        {typeof epss.score === "number" && (
                          <p className="text-xs text-muted-foreground">
                            EPSS exploitation probability: {(epss.score * 100).toFixed(2)}%
                            {typeof epss.percentile === "number"
                              ? ` · percentile ${(epss.percentile * 100).toFixed(2)}%`
                              : ""}
                          </p>
                        )}

                        {findingReferences.length > 0 && (
                          <div className="space-y-1 text-xs">
                            <p className="text-muted-foreground">References</p>
                            {findingReferences.map((reference) => (
                              <a
                                key={reference}
                                href={reference}
                                target="_blank"
                                rel="noreferrer"
                                className="flex items-center gap-1 break-all text-orange-300 hover:text-orange-200"
                              >
                                {reference}
                                <ExternalLink className="size-3 shrink-0" />
                              </a>
                            ))}
                          </div>
                        )}

                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          aria-expanded={showFullFindingDetails}
                          disabled={findingDetailsLoading || !!findingDetailsError}
                          onClick={() =>
                            setShowFullFindingDetails((expanded) => !expanded)
                          }
                          className="border-border/70 bg-transparent text-foreground"
                        >
                          {showFullFindingDetails ? (
                            <>
                              <ChevronUp />
                              Show less
                            </>
                          ) : (
                            <>
                              <ChevronDown />
                              View more details
                            </>
                          )}
                        </Button>

                        {showFullFindingDetails && (
                          <div className="space-y-2 border-t border-border/70 pt-3">
                            <h5 className="text-xs font-semibold uppercase tracking-wider text-foreground">
                              Complete stored scan evidence
                            </h5>
                            {hasFindingEvidence ? (
                              <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-md bg-black/30 p-3 text-[11px] leading-relaxed text-muted-foreground">
                                {JSON.stringify(selectedEvidence, null, 2)}
                              </pre>
                            ) : (
                              <p className="text-xs text-muted-foreground">
                                The scan did not store additional advisory evidence for this finding.
                              </p>
                            )}
                          </div>
                        )}
                      </section>
                    )}
                  </div>
                </div>
              </div>

              <div>
                <h3 className="text-sm font-medium text-foreground tracking-wider mb-2">
                  LATEST SCAN
                </h3>
                <p className="text-sm text-foreground">
                  {selectedOp.run?.error ?? selectedOp.description}
                </p>
              </div>

              {statusFeedback && (
                <p className="text-xs text-orange-300 font-mono">
                  {statusFeedback}
                </p>
              )}

              <div className="flex gap-2 pt-4 border-t border-border/70">
                <Button
                  disabled={busy}
                  onClick={() => void scanLatest(selectedOp)}
                  className="bg-orange-400 text-[#09120f] hover:bg-orange-300"
                >
                  Scan latest commit
                </Button>
                <Button
                  variant="outline"
                  onClick={() =>
                    window.open(
                      selectedOp.repository.repository_url,
                      "_blank",
                      "noopener,noreferrer"
                    )
                  }
                  className="border-border/70 text-muted-foreground hover:bg-muted hover:text-foreground bg-transparent"
                >
                  View Repository
                </Button>
                <Button
                  variant="outline"
                  disabled={busy}
                  onClick={() => void removeRepository(selectedOp)}
                  className="border-rose-400/20 bg-rose-400/5 text-rose-300 hover:bg-rose-400/10"
                >
                  Remove Repository
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </main>
  );
}
