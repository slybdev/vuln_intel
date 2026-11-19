import { useEffect, useState } from "react";
import {
  Activity,
  ArrowDownToLine,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Filter,
  RefreshCw,
  Search,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
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
  EventCategory,
  EventSeverity,
  SecurityEvent,
  SecurityEventPage,
  SecurityEventSummary,
} from "@/src/lib/vuln-intel-api";

const PAGE_SIZE = 25;

const CATEGORIES: { value: EventCategory; label: string }[] = [
  { value: "asset", label: "Assets" },
  { value: "repository", label: "Repositories" },
  { value: "scan", label: "Scans" },
  { value: "finding", label: "Findings" },
  { value: "feed", label: "Vulnerability feeds" },
  { value: "settings", label: "Settings" },
  { value: "system", label: "System" },
];

const SEVERITIES: { value: EventSeverity; label: string }[] = [
  { value: "CRITICAL", label: "Critical" },
  { value: "HIGH", label: "High" },
  { value: "MEDIUM", label: "Medium" },
  { value: "LOW", label: "Low" },
  { value: "INFO", label: "Info" },
];

const SEVERITY_STYLES: Record<EventSeverity, string> = {
  CRITICAL: "border-red-400/25 bg-red-500/10 text-red-300",
  HIGH: "border-orange-400/25 bg-orange-500/10 text-orange-300",
  MEDIUM: "border-amber-300/25 bg-amber-400/10 text-amber-200",
  LOW: "border-sky-300/25 bg-sky-400/10 text-sky-200",
  INFO: "border-neutral-400/25 bg-neutral-400/10 text-neutral-300",
};

function formatTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: "UTC",
  }).format(date);
}

function outcomeStyle(outcome: string): string {
  switch (outcome) {
    case "failed":
      return "border-rose-400/25 bg-rose-400/10 text-rose-300";
    case "detected":
    case "partial":
      return "border-orange-400/25 bg-orange-400/10 text-orange-200";
    case "resolved":
    case "succeeded":
      return "border-emerald-400/25 bg-emerald-400/10 text-emerald-300";
    default:
      return "border-border/80 bg-muted/40 text-muted-foreground";
  }
}

function csvCell(value: unknown): string {
  const text =
    typeof value === "string"
      ? value
      : JSON.stringify(value ?? "") ?? "";
  return `"${text.replace(/"/g, '""')}"`;
}

function isEventSeverity(value: string): value is EventSeverity {
  return SEVERITIES.some((severity) => severity.value === value);
}

function isEventCategory(value: string): value is EventCategory {
  return CATEGORIES.some((category) => category.value === value);
}

export default function SecurityLogsPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [summary, setSummary] = useState<SecurityEventSummary | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState<EventSeverity | "all">(
    "all"
  );
  const [categoryFilter, setCategoryFilter] = useState<EventCategory | "all">(
    "all"
  );
  const [page, setPage] = useState(1);
  const [refreshTick, setRefreshTick] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [total, setTotal] = useState(0);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");

    const timer = window.setTimeout(() => {
      const params = new URLSearchParams({
        q: searchTerm.trim(),
        severity: severityFilter === "all" ? "" : severityFilter,
        category: categoryFilter === "all" ? "" : categoryFilter,
        page: String(page),
        page_size: String(PAGE_SIZE),
      });
      Promise.all([
        apiFetch<SecurityEventPage>(`/api/security-events?${params}`),
        apiFetch<SecurityEventSummary>("/api/security-events/summary"),
      ])
        .then(([result, nextSummary]) => {
          if (!active) return;
          setEvents(result.items);
          setTotal(result.total);
          setSummary(nextSummary);
          const lastPage = Math.max(1, Math.ceil(result.total / PAGE_SIZE));
          if (page > lastPage) setPage(lastPage);
        })
        .catch((reason: unknown) => {
          if (active) {
            setError(
              reason instanceof Error
                ? reason.message
                : "Security events could not be loaded."
            );
          }
        })
        .finally(() => {
          if (active) setLoading(false);
        });
    }, searchTerm ? 180 : 0);

    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [searchTerm, severityFilter, categoryFilter, page, refreshTick]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const firstItem = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1;
  const lastItem = Math.min(page * PAGE_SIZE, total);

  function exportEvents() {
    const columns = [
      "Timestamp UTC",
      "Severity",
      "Category",
      "Event type",
      "Source",
      "Event",
      "Target type",
      "Target ID",
      "Outcome",
      "Actor",
      "Details",
    ];
    const rows = events.map((event) =>
      [
        event.occurred_at,
        event.severity,
        event.category,
        event.event_type,
        event.source,
        event.message,
        event.target_type,
        event.target_id,
        event.outcome,
        event.actor,
        event.details,
      ]
        .map(csvCell)
        .join(",")
    );
    const blob = new Blob([[columns.map(csvCell).join(","), ...rows].join("\n")], {
      type: "text/csv;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `tactical-ops-events-page-${page}.csv`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <main className="mx-auto flex w-full min-w-0 max-w-[1600px] flex-col gap-5 p-4 sm:p-6 lg:p-8">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="mb-2 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[.2em] text-orange-400">
            <Activity className="size-3.5" />
            Platform activity · database-backed audit trail
          </div>
          <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">
            Security logs
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Review repository, scan, finding, feed, asset, and settings events.
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setRefreshTick((value) => value + 1)}
            disabled={loading}
            className="border-border/70 bg-transparent text-muted-foreground hover:bg-muted hover:text-foreground"
          >
            <RefreshCw className={`mr-2 size-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          <Button
            size="sm"
            onClick={exportEvents}
            disabled={!events.length}
            className="bg-orange-500 text-white hover:bg-orange-400"
          >
            <ArrowDownToLine className="mr-2 size-3.5" />
            Export page
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

      <section
        aria-label="Security event metrics"
        className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4"
      >
        <MetricCard
          label="Total events"
          value={summary?.total}
          icon={Activity}
          accent="text-orange-300"
        />
        <MetricCard
          label="Last 24 hours"
          value={summary?.last_24_hours}
          icon={RefreshCw}
          accent="text-sky-200"
        />
        <MetricCard
          label="High / critical"
          value={summary?.high_severity}
          icon={Filter}
          accent="text-rose-300"
        />
        <MetricCard
          label="Failed actions"
          value={summary?.failed}
          icon={Activity}
          accent="text-amber-200"
        />
      </section>

      <Card className="siem-card overflow-hidden">
        <CardHeader className="gap-4 border-b border-border/70 p-4 sm:flex-row sm:items-center sm:justify-between sm:p-5">
          <div>
            <CardTitle className="text-sm">Platform event stream</CardTitle>
            <p className="mt-1 text-xs text-muted-foreground" aria-live="polite">
              Showing {firstItem.toLocaleString()}–{lastItem.toLocaleString()} of{" "}
              {total.toLocaleString()} events · Page {page} of {totalPages}
            </p>
          </div>
          <div className="grid gap-2 sm:grid-cols-[minmax(220px,1fr)_170px_190px]">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={searchTerm}
                onChange={(event) => {
                  setPage(1);
                  setSearchTerm(event.target.value);
                }}
                placeholder="Search events, sources, targets…"
                aria-label="Search security events"
                className="h-9 pl-9 text-xs"
              />
            </div>
            <FilterSelect
              label="Filter by severity"
              allLabel="All severities"
              value={severityFilter}
              onChange={(value) => {
                setPage(1);
                if (value === "all") setSeverityFilter("all");
                else if (isEventSeverity(value)) setSeverityFilter(value);
              }}
              options={SEVERITIES.map(({ value, label }) => ({ value, label }))}
            />
            <FilterSelect
              label="Filter by category"
              allLabel="All categories"
              value={categoryFilter}
              onChange={(value) => {
                setPage(1);
                if (value === "all") setCategoryFilter("all");
                else if (isEventCategory(value)) setCategoryFilter(value);
              }}
              options={CATEGORIES}
            />
          </div>
        </CardHeader>

        <CardContent className="p-0">
          <div className="hidden grid-cols-[150px_82px_145px_minmax(220px,1fr)_115px] gap-3 border-b border-border/60 bg-muted/20 px-5 py-3 text-[9px] font-semibold uppercase tracking-[.16em] text-muted-foreground lg:grid">
            <span>Timestamp · UTC</span>
            <span>Severity</span>
            <span>Category / source</span>
            <span>Event</span>
            <span>Outcome</span>
          </div>
          <div className="divide-y divide-border/50">
            {events.map((event) => (
              <article
                key={event.event_id}
                className="grid gap-2 px-4 py-3.5 transition-colors hover:bg-muted/20 sm:px-5 lg:grid-cols-[150px_82px_145px_minmax(220px,1fr)_115px] lg:items-start lg:gap-3"
              >
                <time
                  dateTime={event.occurred_at}
                  className="font-mono text-[10px] text-muted-foreground tabular-nums"
                >
                  {formatTimestamp(event.occurred_at)}
                </time>
                <Badge
                  variant="outline"
                  className={`w-fit text-[9px] uppercase ${SEVERITY_STYLES[event.severity]}`}
                >
                  {event.severity}
                </Badge>
                <div>
                  <div className="text-[10px] font-medium capitalize text-foreground">
                    {event.category}
                  </div>
                  <div className="mt-1 break-words text-[10px] text-muted-foreground">
                    {event.source}
                  </div>
                </div>
                <div className="min-w-0">
                  <div className="break-words text-xs font-medium text-foreground">
                    {event.message}
                  </div>
                  <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-muted-foreground">
                    <span className="font-mono">{event.event_type}</span>
                    {event.target_id && (
                      <span>
                        Target: {event.target_type} ·{" "}
                        <span className="font-mono">{event.target_id}</span>
                      </span>
                    )}
                    <span>Actor: {event.actor.replace(/_/g, " ")}</span>
                  </div>
                  {Object.keys(event.details).length > 0 && (
                    <details className="mt-2 text-[10px] text-muted-foreground">
                      <summary className="w-fit cursor-pointer hover:text-foreground">
                        Event context
                      </summary>
                      <pre className="mt-2 max-h-40 overflow-auto rounded border border-border/60 bg-background/60 p-2 font-mono text-[10px]">
                        {JSON.stringify(event.details, null, 2)}
                      </pre>
                    </details>
                  )}
                </div>
                <Badge
                  variant="outline"
                  className={`w-fit text-[9px] font-normal uppercase ${outcomeStyle(event.outcome)}`}
                >
                  {event.outcome.replace(/_/g, " ")}
                </Badge>
              </article>
            ))}
            {!events.length && (
              <div className="p-12 text-center">
                <Activity className="mx-auto mb-3 size-8 text-muted-foreground/70" />
                <p className="text-sm font-medium text-foreground">
                  {loading
                    ? "Loading platform events…"
                    : error
                      ? "Security events are unavailable."
                      : searchTerm || severityFilter !== "all" || categoryFilter !== "all"
                        ? "No events match those filters."
                        : "No platform activity recorded yet."}
                </p>
                {!loading && !error && !total && (
                  <p className="mx-auto mt-1 max-w-lg text-xs text-muted-foreground">
                    Events will appear when repositories are connected, scans
                    run, vulnerability feeds update, or assets are changed.
                  </p>
                )}
              </div>
            )}
          </div>
        </CardContent>

        <div className="flex flex-col gap-3 border-t border-border/70 px-4 py-3 text-[10px] text-muted-foreground sm:flex-row sm:items-center sm:justify-between sm:px-5">
          <span>Export downloads the events on this page.</span>
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              aria-label="Previous event page"
              disabled={page <= 1 || loading}
              onClick={() => setPage((value) => Math.max(1, value - 1))}
              className="border-border/70 bg-transparent text-muted-foreground hover:bg-muted hover:text-foreground"
            >
              <ChevronLeft />
              Previous
            </Button>
            <span className="min-w-20 text-center">
              Page {page} of {totalPages}
            </span>
            <Button
              size="sm"
              variant="outline"
              aria-label="Next event page"
              disabled={page >= totalPages || loading}
              onClick={() => setPage((value) => Math.min(totalPages, value + 1))}
              className="border-border/70 bg-transparent text-muted-foreground hover:bg-muted hover:text-foreground"
            >
              Next
              <ChevronRight />
            </Button>
          </div>
        </div>
      </Card>
    </main>
  );
}

function FilterSelect({
  label,
  allLabel,
  value,
  onChange,
  options,
}: {
  label: string;
  allLabel: string;
  value: string;
  onChange: (value: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <div className="relative">
      <Filter className="pointer-events-none absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        aria-label={label}
        className="h-9 w-full appearance-none rounded-md border border-border/80 bg-background/60 pl-9 pr-8 text-xs text-foreground"
      >
        <option value="all">{allLabel}</option>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
      <ChevronDown className="pointer-events-none absolute right-3 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
    </div>
  );
}

function MetricCard({
  label,
  value,
  icon: Icon,
  accent,
}: {
  label: string;
  value?: number;
  icon: LucideIcon;
  accent: string;
}) {
  return (
    <Card className="siem-card">
      <CardContent className="flex items-center justify-between p-4">
        <div>
          <p className="text-[10px] uppercase tracking-[.16em] text-muted-foreground">
            {label}
          </p>
          <p className={`mt-2 font-mono text-2xl font-semibold tabular-nums ${accent}`}>
            {value?.toLocaleString() ?? "—"}
          </p>
        </div>
        <Icon className={`size-4 ${accent}`} />
      </CardContent>
    </Card>
  );
}
