export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

export interface Vulnerability {
  id: string;
  ids?: string[];
  title?: string | null;
  description?: string | null;
  published?: string | null;
  modified?: string | null;
  severity?: Severity | null;
  cvss_best?: {
    score?: number | null;
    vector?: string | null;
    version?: string | null;
    provider?: string | null;
  } | null;
  sources?: string[];
  cwes?: string[];
  affected?: Array<{
    ecosystem?: string;
    package?: string;
    versions?: string[];
    patched?: string[];
  }>;
  references?: string[];
  exploitation?: {
    in_kev?: boolean;
    kev?: {
      date_added?: string;
      due_date?: string;
      required_action?: string;
      notes?: string;
      product?: string;
    } | null;
    epss?: { score?: number; percentile?: number; date?: string } | null;
  };
}

export interface VulnerabilitySummary {
  total: number;
  kev: number;
  critical: number;
  high_epss: number;
  severity: Record<Severity, number>;
  sources: Array<{ name: string; count: number }>;
  top_risk: Vulnerability[];
}

export interface VulnerabilityPage {
  items: Vulnerability[];
  total: number;
  page: number;
  page_size: number;
}

export interface Repository {
  application_id: string;
  name: string;
  repository_url: string;
  updated_at?: string;
}

export interface RepositoryList {
  items: Repository[];
}

export interface ProviderCredential {
  provider: "github" | "gitlab";
  configured: boolean;
  updated_at?: string | null;
}

export interface CredentialList {
  items: ProviderCredential[];
}

export interface ScanRun {
  run_id: string;
  application_id: string;
  commit_sha: string;
  ref: string;
  status: "queued" | "running" | "succeeded" | "failed" | string;
  requested_at?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  component_count?: number;
  finding_count?: number;
  unevaluated_count?: number;
  scanner_version?: string | null;
  error?: string | null;
}

export interface ScanList {
  items: ScanRun[];
}

export interface ApplicationFinding {
  ref?: string;
  canonical_id?: string | null;
  vulnerability_id: string;
  ecosystem?: string | null;
  package_name: string;
  purl?: string | null;
  installed_version?: string | null;
  fixed_version?: string | null;
  severity: Severity;
  status: "active" | "resolved" | string;
  first_seen?: string | null;
  last_seen?: string | null;
  sources: string[];
  evidence?: Record<string, unknown> | null;
}

export interface FindingList {
  items: ApplicationFinding[];
}

export type AssetType =
  | "endpoint"
  | "server"
  | "network_device"
  | "operating_system"
  | "third_party_application"
  | "cloud_resource";

export type AssetStatus = "active" | "maintenance" | "retired" | "unknown";
export type AssetCriticality = "critical" | "high" | "medium" | "low" | "unknown";

export interface AssetRecord {
  asset_id: string;
  asset_type: AssetType;
  name: string;
  identifier: string;
  status: AssetStatus;
  environment: string;
  owner: string;
  location: string;
  vendor: string;
  model: string;
  operating_system: string;
  version: string;
  ip_address: string;
  mac_address: string;
  criticality: AssetCriticality;
  notes: string;
  created_at: string;
  updated_at: string;
}

export interface AssetPage {
  items: AssetRecord[];
  total: number;
  page: number;
  page_size: number;
}

export interface AssetSummary {
  total: number;
  active: number;
  attention: number;
  types: number;
}

export interface FeedUpdateSchedule {
  enabled: boolean;
  time: string;
  next_run_at: string | null;
  last_run_at: string | null;
  last_run_status: "running" | "succeeded" | "partial" | "failed" | null;
  last_run_error: string | null;
  last_run_summary: {
    run_id?: string | null;
    feed_count?: number;
  };
}

export type EventSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type EventCategory =
  | "asset"
  | "repository"
  | "scan"
  | "finding"
  | "feed"
  | "settings"
  | "system";
export type EventOutcome =
  | "info"
  | "queued"
  | "running"
  | "succeeded"
  | "failed"
  | "detected"
  | "resolved"
  | "updated"
  | "deleted"
  | "partial";

export interface SecurityEvent {
  event_id: number;
  occurred_at: string;
  severity: EventSeverity;
  category: EventCategory;
  event_type: string;
  source: string;
  message: string;
  target_type: string;
  target_id: string;
  outcome: EventOutcome;
  actor: string;
  details: Record<string, unknown>;
}

export interface SecurityEventPage {
  items: SecurityEvent[];
  total: number;
  page: number;
  page_size: number;
}

export interface SecurityEventSummary {
  total: number;
  last_24_hours: number;
  high_severity: number;
  failed: number;
}

export async function apiFetch<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const response = await fetch(path, {
    ...init,
    cache: "no-store",
    headers: {
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...init?.headers,
    },
  });

  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const message =
      payload && typeof payload === "object" && "error" in payload
        ? String(payload.error)
        : `Request failed (${response.status})`;
    throw new Error(message);
  }
  return payload as T;
}

export function formatDate(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeZone: "UTC",
      }).format(date);
}

export function severityLabel(severity?: string | null): string {
  return !severity || severity === "UNKNOWN" ? "UNRATED" : severity;
}
