import { useEffect, useState, type FormEvent } from "react";
import {
  Boxes,
  Building2,
  Check,
  ChevronLeft,
  ChevronRight,
  Cloud,
  Computer,
  Database,
  HardDrive,
  Laptop,
  Network,
  Pencil,
  Plus,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  Trash2,
  X,
  type LucideIcon,
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
  AssetCriticality,
  AssetPage,
  AssetRecord,
  AssetStatus,
  AssetSummary,
  AssetType,
} from "@/src/lib/vuln-intel-api";

type AssetDraft = Pick<
  AssetRecord,
  | "asset_type"
  | "name"
  | "identifier"
  | "status"
  | "environment"
  | "owner"
  | "location"
  | "vendor"
  | "model"
  | "operating_system"
  | "version"
  | "ip_address"
  | "mac_address"
  | "criticality"
  | "notes"
>;
type TextFieldName = Exclude<
  keyof AssetDraft,
  "asset_type" | "status" | "criticality" | "notes"
>;

const PAGE_SIZE = 25;

const ASSET_TYPES: { value: AssetType; label: string; icon: LucideIcon }[] = [
  { value: "endpoint", label: "Endpoint", icon: Laptop },
  { value: "server", label: "Server", icon: Server },
  { value: "network_device", label: "Network device", icon: Network },
  { value: "operating_system", label: "Operating system", icon: Computer },
  {
    value: "third_party_application",
    label: "Third-party application",
    icon: Boxes,
  },
  { value: "cloud_resource", label: "Cloud resource", icon: Cloud },
];

const ASSET_STATUSES: { value: AssetStatus; label: string }[] = [
  { value: "active", label: "Active" },
  { value: "maintenance", label: "Maintenance" },
  { value: "retired", label: "Retired" },
  { value: "unknown", label: "Unknown" },
];

const CRITICALITIES: { value: AssetCriticality; label: string }[] = [
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
  { value: "unknown", label: "Unrated" },
];

const TEXT_FIELDS: {
  key: TextFieldName;
  label: string;
  placeholder: string;
  maxLength: number;
}[] = [
  { key: "name", label: "Asset name", placeholder: "e.g. Finance laptop 01", maxLength: 200 },
  { key: "identifier", label: "Unique identifier", placeholder: "Hostname, serial, package ID, or cloud resource ID", maxLength: 255 },
  { key: "environment", label: "Environment", placeholder: "Production, staging, development…", maxLength: 100 },
  { key: "owner", label: "Owner / team", placeholder: "Team or responsible person", maxLength: 200 },
  { key: "location", label: "Location", placeholder: "Office, region, data center…", maxLength: 200 },
  { key: "vendor", label: "Vendor", placeholder: "Manufacturer or publisher", maxLength: 120 },
  { key: "model", label: "Model", placeholder: "Model or product line", maxLength: 120 },
  { key: "operating_system", label: "Operating system", placeholder: "Windows Server, Ubuntu, iOS…", maxLength: 160 },
  { key: "version", label: "Version", placeholder: "OS, firmware, or application version", maxLength: 120 },
  { key: "ip_address", label: "IP address", placeholder: "IPv4 or IPv6 address", maxLength: 45 },
  { key: "mac_address", label: "MAC address", placeholder: "Hardware address", maxLength: 32 },
];

const EMPTY_DRAFT: AssetDraft = {
  asset_type: "endpoint",
  name: "",
  identifier: "",
  status: "active",
  environment: "",
  owner: "",
  location: "",
  vendor: "",
  model: "",
  operating_system: "",
  version: "",
  ip_address: "",
  mac_address: "",
  criticality: "unknown",
  notes: "",
};

const TYPE_LABELS = Object.fromEntries(
  ASSET_TYPES.map(({ value, label }) => [value, label])
) as Record<AssetType, string>;

function isAssetType(value: string): value is AssetType {
  return ASSET_TYPES.some((item) => item.value === value);
}

function isAssetStatus(value: string): value is AssetStatus {
  return ASSET_STATUSES.some((item) => item.value === value);
}

function isAssetCriticality(value: string): value is AssetCriticality {
  return CRITICALITIES.some((item) => item.value === value);
}

function statusStyle(status: AssetStatus): string {
  switch (status) {
    case "active":
      return "border-emerald-400/25 bg-emerald-400/10 text-emerald-300";
    case "maintenance":
      return "border-amber-400/25 bg-amber-400/10 text-amber-200";
    case "retired":
      return "border-neutral-500/30 bg-neutral-500/10 text-muted-foreground";
    case "unknown":
      return "border-rose-400/25 bg-rose-400/10 text-rose-300";
  }
}

function criticalityStyle(criticality: AssetCriticality): string {
  if (criticality === "critical") return "text-rose-300";
  if (criticality === "high") return "text-orange-300";
  if (criticality === "medium") return "text-amber-200";
  return "text-muted-foreground";
}

function formatUpdated(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(date);
}

export default function SystemsPage() {
  const [assets, setAssets] = useState<AssetRecord[]>([]);
  const [summary, setSummary] = useState<AssetSummary | null>(null);
  const [resultTotal, setResultTotal] = useState(0);
  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<AssetType | "all">("all");
  const [statusFilter, setStatusFilter] = useState<AssetStatus | "all">("all");
  const [page, setPage] = useState(1);
  const [refreshTick, setRefreshTick] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedAsset, setSelectedAsset] = useState<AssetRecord | null>(null);
  const [formOpen, setFormOpen] = useState(false);
  const [editingAsset, setEditingAsset] = useState<AssetRecord | null>(null);
  const [draft, setDraft] = useState<AssetDraft>(EMPTY_DRAFT);
  const [saving, setSaving] = useState(false);
  const [deletingId, setDeletingId] = useState("");

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError("");

    const timer = window.setTimeout(() => {
      const params = new URLSearchParams({
        q: query.trim(),
        type: typeFilter === "all" ? "" : typeFilter,
        status: statusFilter === "all" ? "" : statusFilter,
        page: String(page),
        page_size: String(PAGE_SIZE),
      });
      Promise.all([
        apiFetch<AssetPage>(`/api/assets?${params}`),
        apiFetch<AssetSummary>("/api/assets/summary"),
      ])
        .then(([result, nextSummary]) => {
          if (!active) return;
          setAssets(result.items);
          setResultTotal(result.total);
          setSummary(nextSummary);
          const lastPage = Math.max(1, Math.ceil(result.total / PAGE_SIZE));
          if (page > lastPage) setPage(lastPage);
        })
        .catch((reason: unknown) => {
          if (active) {
            setError(
              reason instanceof Error
                ? reason.message
                : "Asset inventory could not be loaded."
            );
          }
        })
        .finally(() => {
          if (active) setLoading(false);
        });
    }, query ? 180 : 0);

    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [query, typeFilter, statusFilter, page, refreshTick]);

  const total = summary?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(resultTotal / PAGE_SIZE));

  function updateDraft<K extends keyof AssetDraft>(
    key: K,
    value: AssetDraft[K]
  ) {
    setDraft((current) => ({ ...current, [key]: value }));
  }

  function openCreateForm() {
    setEditingAsset(null);
    setDraft(EMPTY_DRAFT);
    setFormOpen(true);
  }

  function openEditForm(asset: AssetRecord) {
    setEditingAsset(asset);
    setDraft({
      asset_type: asset.asset_type,
      name: asset.name,
      identifier: asset.identifier,
      status: asset.status,
      environment: asset.environment,
      owner: asset.owner,
      location: asset.location,
      vendor: asset.vendor,
      model: asset.model,
      operating_system: asset.operating_system,
      version: asset.version,
      ip_address: asset.ip_address,
      mac_address: asset.mac_address,
      criticality: asset.criticality,
      notes: asset.notes,
    });
    setSelectedAsset(null);
    setFormOpen(true);
  }

  async function saveAsset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      if (editingAsset) {
        await apiFetch<{ asset: AssetRecord }>(
          `/api/assets/${encodeURIComponent(editingAsset.asset_id)}`,
          { method: "PATCH", body: JSON.stringify(draft) }
        );
      } else {
        await apiFetch<{ asset: AssetRecord }>("/api/assets", {
          method: "POST",
          body: JSON.stringify(draft),
        });
      }
      setFormOpen(false);
      setRefreshTick((value) => value + 1);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Asset could not be saved."
      );
    } finally {
      setSaving(false);
    }
  }

  async function deleteAsset(asset: AssetRecord) {
    if (!window.confirm(`Remove "${asset.name}" from the asset inventory?`)) {
      return;
    }
    setDeletingId(asset.asset_id);
    setError("");
    try {
      await apiFetch<{ deleted: boolean }>(
        `/api/assets/${encodeURIComponent(asset.asset_id)}`,
        { method: "DELETE" }
      );
      setSelectedAsset(null);
      setRefreshTick((value) => value + 1);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Asset could not be deleted."
      );
    } finally {
      setDeletingId("");
    }
  }

  function changeType(value: string) {
    setPage(1);
    if (value === "all") setTypeFilter("all");
    else if (isAssetType(value)) setTypeFilter(value);
  }

  function changeStatus(value: string) {
    setPage(1);
    if (value === "all") setStatusFilter("all");
    else if (isAssetStatus(value)) setStatusFilter(value);
  }

  return (
    <main className="mx-auto flex w-full min-w-0 max-w-[1600px] flex-col gap-5 p-4 sm:p-6 lg:p-8">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="mb-2 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[.2em] text-orange-300">
            <span className="size-1.5 animate-pulse rounded-full bg-orange-400" />
            Asset inventory · {total.toLocaleString()} tracked
          </div>
          <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">
            Devices &amp; assets
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            A single inventory for endpoints, infrastructure, operating systems,
            applications, and cloud resources.
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={() => setRefreshTick((value) => value + 1)}
            disabled={loading}
            className="border-border/70 bg-transparent text-muted-foreground hover:bg-muted hover:text-foreground"
          >
            <RefreshCw className={`mr-2 size-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          <Button
            onClick={openCreateForm}
            className="bg-orange-400 text-[#09120f] hover:bg-orange-300"
          >
            <Plus className="mr-2 size-4" />
            Add asset
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

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Total assets" value={summary?.total} icon={Boxes} />
        <MetricCard
          label="Active"
          value={summary?.active}
          icon={Check}
          accent="text-emerald-300"
        />
        <MetricCard
          label="Needs review"
          value={summary?.attention}
          icon={ShieldAlert}
          accent="text-amber-200"
        />
        <MetricCard
          label="Asset categories"
          value={summary?.types}
          icon={Database}
        />
      </section>

      <Card className="siem-card overflow-hidden">
        <CardHeader className="gap-4 border-b border-border/70 p-4 sm:flex-row sm:items-center sm:justify-between sm:p-5">
          <div>
            <CardTitle className="text-sm">Inventory records</CardTitle>
            <p className="mt-1 text-xs text-muted-foreground">
              Search and filter your registered technology assets.
            </p>
          </div>
          <div className="grid gap-2 sm:grid-cols-[minmax(220px,1fr)_190px_160px]">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input
                aria-label="Search assets"
                placeholder="Search name, ID, owner, OS…"
                value={query}
                onChange={(event) => {
                  setPage(1);
                  setQuery(event.target.value);
                }}
                className="h-9 pl-9"
              />
            </div>
            <select
              aria-label="Filter by asset type"
              value={typeFilter}
              onChange={(event) => changeType(event.target.value)}
              className="h-9 rounded-md border border-input bg-background px-3 text-xs text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <option value="all">All asset types</option>
              {ASSET_TYPES.map((type) => (
                <option key={type.value} value={type.value}>
                  {type.label}
                </option>
              ))}
            </select>
            <select
              aria-label="Filter by asset status"
              value={statusFilter}
              onChange={(event) => changeStatus(event.target.value)}
              className="h-9 rounded-md border border-input bg-background px-3 text-xs text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <option value="all">All statuses</option>
              {ASSET_STATUSES.map((status) => (
                <option key={status.value} value={status.value}>
                  {status.label}
                </option>
              ))}
            </select>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1050px] text-left text-xs">
              <thead className="border-b border-border/70 text-[10px] uppercase tracking-[.13em] text-muted-foreground">
                <tr>
                  <th className="px-5 py-3 font-medium">Asset</th>
                  <th className="px-4 py-3 font-medium">Type</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                  <th className="px-4 py-3 font-medium">Environment</th>
                  <th className="px-4 py-3 font-medium">Owner</th>
                  <th className="px-4 py-3 font-medium">Location</th>
                  <th className="px-4 py-3 font-medium">Criticality</th>
                  <th className="px-5 py-3 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {assets.map((asset) => {
                  const type = ASSET_TYPES.find(
                    (item) => item.value === asset.asset_type
                  );
                  const TypeIcon = type?.icon ?? HardDrive;
                  return (
                    <tr
                      key={asset.asset_id}
                      className="transition-colors hover:bg-white/[.025]"
                    >
                      <td className="px-5 py-3.5">
                        <button
                          type="button"
                          onClick={() => setSelectedAsset(asset)}
                          className="group flex items-center gap-3 text-left"
                        >
                          <span className="flex size-8 shrink-0 items-center justify-center rounded border border-border/70 bg-background text-orange-300">
                            <TypeIcon className="size-4" />
                          </span>
                          <span className="min-w-0">
                            <span className="block max-w-[240px] truncate font-medium text-foreground group-hover:text-orange-200">
                              {asset.name}
                            </span>
                            <span className="mt-0.5 block max-w-[240px] truncate font-mono text-[10px] text-muted-foreground">
                              {asset.identifier}
                            </span>
                          </span>
                        </button>
                      </td>
                      <td className="px-4 py-3.5 text-muted-foreground">
                        {TYPE_LABELS[asset.asset_type]}
                      </td>
                      <td className="px-4 py-3.5">
                        <Badge className={statusStyle(asset.status)}>
                          {asset.status.toUpperCase()}
                        </Badge>
                      </td>
                      <td className="px-4 py-3.5 text-muted-foreground">
                        {asset.environment || "—"}
                      </td>
                      <td className="px-4 py-3.5 text-muted-foreground">
                        {asset.owner || "—"}
                      </td>
                      <td className="px-4 py-3.5 text-muted-foreground">
                        {asset.location || "—"}
                      </td>
                      <td
                        className={`px-4 py-3.5 font-semibold uppercase ${criticalityStyle(
                          asset.criticality
                        )}`}
                      >
                        {asset.criticality}
                      </td>
                      <td className="px-5 py-3.5">
                        <div className="flex justify-end gap-1">
                          <Button
                            size="icon"
                            variant="ghost"
                            aria-label={`View ${asset.name}`}
                            onClick={() => setSelectedAsset(asset)}
                            className="size-8 text-muted-foreground hover:text-foreground"
                          >
                            <Search />
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            aria-label={`Edit ${asset.name}`}
                            onClick={() => openEditForm(asset)}
                            className="size-8 text-muted-foreground hover:text-orange-200"
                          >
                            <Pencil />
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            aria-label={`Delete ${asset.name}`}
                            disabled={deletingId === asset.asset_id}
                            onClick={() => void deleteAsset(asset)}
                            className="size-8 text-muted-foreground hover:text-rose-300"
                          >
                            <Trash2 />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {!assets.length && (
            <div className="px-5 py-14 text-center">
              <Building2 className="mx-auto mb-3 size-8 text-muted-foreground/70" />
              <p className="text-sm font-medium text-foreground">
                {loading
                  ? "Loading asset inventory…"
                  : error
                    ? "Asset records are unavailable."
                    : query || typeFilter !== "all" || statusFilter !== "all"
                      ? "No assets match these filters."
                      : "No assets registered yet."}
              </p>
              {!loading && !error && !total && (
                <>
                  <p className="mx-auto mt-1 max-w-md text-xs text-muted-foreground">
                    Add your first asset to start tracking devices, network
                    equipment, software, and cloud resources.
                  </p>
                  <Button
                    onClick={openCreateForm}
                    className="mt-4 bg-orange-400 text-[#09120f] hover:bg-orange-300"
                  >
                    <Plus className="mr-2 size-4" />
                    Register an asset
                  </Button>
                </>
              )}
            </div>
          )}

          <div className="flex flex-col gap-3 border-t border-border/70 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-xs text-muted-foreground" aria-live="polite">
              {typeFilter === "all" && statusFilter === "all" && !query.trim()
                ? `Showing ${resultTotal ? (page - 1) * PAGE_SIZE + 1 : 0}–${Math.min(
                    page * PAGE_SIZE,
                    resultTotal
                  )} of ${total.toLocaleString()} assets`
                : `Showing ${resultTotal ? (page - 1) * PAGE_SIZE + 1 : 0}–${Math.min(
                    page * PAGE_SIZE,
                    resultTotal
                  )} of ${resultTotal.toLocaleString()} matching assets`}
            </p>
            <div className="flex items-center gap-2">
              <Button
                size="sm"
                variant="outline"
                aria-label="Previous asset page"
                disabled={page <= 1 || loading}
                onClick={() => setPage((value) => Math.max(1, value - 1))}
                className="border-border/70 bg-transparent text-muted-foreground hover:bg-muted hover:text-foreground"
              >
                <ChevronLeft />
                Previous
              </Button>
              <span className="min-w-20 text-center text-xs text-muted-foreground">
                Page {page}
              </span>
              <Button
                size="sm"
                variant="outline"
                aria-label="Next asset page"
                disabled={page >= totalPages || loading}
                onClick={() =>
                  setPage((value) => Math.min(totalPages, value + 1))
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

      {selectedAsset && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <Card
            role="dialog"
            aria-modal="true"
            aria-labelledby="asset-details-title"
            className="siem-card max-h-[90vh] w-full max-w-3xl overflow-y-auto"
          >
            <CardHeader className="flex flex-row items-start justify-between border-b border-border/70">
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-[.18em] text-orange-300">
                  Asset details · {TYPE_LABELS[selectedAsset.asset_type]}
                </p>
                <CardTitle id="asset-details-title" className="mt-2 text-xl">
                  {selectedAsset.name}
                </CardTitle>
                <p className="mt-1 font-mono text-xs text-muted-foreground">
                  {selectedAsset.identifier}
                </p>
              </div>
              <Button
                variant="ghost"
                size="icon"
                aria-label="Close asset details"
                onClick={() => setSelectedAsset(null)}
                className="text-muted-foreground"
              >
                <X />
              </Button>
            </CardHeader>
            <CardContent className="space-y-5 p-5">
              <div className="flex flex-wrap gap-2">
                <Badge className={statusStyle(selectedAsset.status)}>
                  {selectedAsset.status.toUpperCase()}
                </Badge>
                <Badge
                  className={`${criticalityStyle(selectedAsset.criticality)} border-border/70 bg-muted/40`}
                >
                  {selectedAsset.criticality.toUpperCase()} CRITICALITY
                </Badge>
              </div>
              <div className="grid gap-x-8 gap-y-4 sm:grid-cols-2">
                {[
                  ["Environment", selectedAsset.environment],
                  ["Owner / team", selectedAsset.owner],
                  ["Location", selectedAsset.location],
                  ["Vendor", selectedAsset.vendor],
                  ["Model", selectedAsset.model],
                  ["Operating system", selectedAsset.operating_system],
                  ["Version", selectedAsset.version],
                  ["IP address", selectedAsset.ip_address],
                  ["MAC address", selectedAsset.mac_address],
                  ["Last updated", formatUpdated(selectedAsset.updated_at)],
                ].map(([label, value]) => (
                  <div key={label} className="border-b border-border/50 pb-2">
                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                      {label}
                    </p>
                    <p className="mt-1 break-words text-sm text-foreground">
                      {value || "—"}
                    </p>
                  </div>
                ))}
              </div>
              {selectedAsset.notes && (
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                    Notes
                  </p>
                  <p className="mt-1 whitespace-pre-wrap text-sm text-foreground">
                    {selectedAsset.notes}
                  </p>
                </div>
              )}
              <div className="flex justify-end gap-2 border-t border-border/70 pt-4">
                <Button
                  variant="outline"
                  onClick={() => void deleteAsset(selectedAsset)}
                  className="border-rose-400/30 bg-transparent text-rose-300 hover:bg-rose-400/10"
                >
                  <Trash2 className="mr-2 size-4" />
                  Delete
                </Button>
                <Button
                  onClick={() => openEditForm(selectedAsset)}
                  className="bg-orange-400 text-[#09120f] hover:bg-orange-300"
                >
                  <Pencil className="mr-2 size-4" />
                  Edit asset
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {formOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <Card
            role="dialog"
            aria-modal="true"
            aria-labelledby="asset-form-title"
            className="siem-card max-h-[92vh] w-full max-w-3xl overflow-y-auto"
          >
            <CardHeader className="flex flex-row items-start justify-between border-b border-border/70">
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-[.18em] text-orange-300">
                  Inventory management
                </p>
                <CardTitle id="asset-form-title" className="mt-2 text-xl">
                  {editingAsset ? "Edit asset" : "Register an asset"}
                </CardTitle>
                <p className="mt-1 text-xs text-muted-foreground">
                  The identifier must be unique within its asset type.
                </p>
              </div>
              <Button
                variant="ghost"
                size="icon"
                aria-label="Close asset form"
                onClick={() => setFormOpen(false)}
                className="text-muted-foreground"
              >
                <X />
              </Button>
            </CardHeader>
            <form onSubmit={saveAsset}>
              <CardContent className="space-y-5 p-5">
                {error && (
                  <p
                    role="alert"
                    className="rounded-lg border border-rose-400/20 bg-rose-400/5 p-3 text-xs text-rose-300"
                  >
                    {error}
                  </p>
                )}
                <div className="grid gap-4 sm:grid-cols-2">
                  <label className="space-y-1.5 text-xs text-muted-foreground">
                    Asset type
                    <select
                      required
                      value={draft.asset_type}
                      onChange={(event) => {
                        if (isAssetType(event.target.value)) {
                          updateDraft("asset_type", event.target.value);
                        }
                      }}
                      className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground"
                    >
                      {ASSET_TYPES.map((type) => (
                        <option key={type.value} value={type.value}>
                          {type.label}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="space-y-1.5 text-xs text-muted-foreground">
                    Status
                    <select
                      value={draft.status}
                      onChange={(event) => {
                        if (isAssetStatus(event.target.value)) {
                          updateDraft("status", event.target.value);
                        }
                      }}
                      className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground"
                    >
                      {ASSET_STATUSES.map((status) => (
                        <option key={status.value} value={status.value}>
                          {status.label}
                        </option>
                      ))}
                    </select>
                  </label>
                  {TEXT_FIELDS.map((field) => (
                    <label
                      key={field.key}
                      htmlFor={`asset-${field.key}`}
                      className="space-y-1.5 text-xs text-muted-foreground"
                    >
                      {field.label}
                      <Input
                        id={`asset-${field.key}`}
                        required={
                          field.key === "name" || field.key === "identifier"
                        }
                        maxLength={field.maxLength}
                        placeholder={field.placeholder}
                        value={draft[field.key]}
                        onChange={(event) =>
                          updateDraft(field.key, event.target.value)
                        }
                        className="h-10"
                      />
                    </label>
                  ))}
                  <label className="space-y-1.5 text-xs text-muted-foreground">
                    Criticality
                    <select
                      value={draft.criticality}
                      onChange={(event) => {
                        if (isAssetCriticality(event.target.value)) {
                          updateDraft("criticality", event.target.value);
                        }
                      }}
                      className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground"
                    >
                      {CRITICALITIES.map((criticality) => (
                        <option
                          key={criticality.value}
                          value={criticality.value}
                        >
                          {criticality.label}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="space-y-1.5 text-xs text-muted-foreground sm:col-span-2">
                    Notes
                    <textarea
                      value={draft.notes}
                      maxLength={4000}
                      onChange={(event) =>
                        updateDraft("notes", event.target.value)
                      }
                      rows={3}
                      placeholder="Additional asset context"
                      className="w-full resize-y rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    />
                  </label>
                </div>
                <div className="flex justify-end gap-2 border-t border-border/70 pt-4">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setFormOpen(false)}
                    disabled={saving}
                    className="border-border/70 bg-transparent text-muted-foreground"
                  >
                    Cancel
                  </Button>
                  <Button
                    type="submit"
                    disabled={saving}
                    className="bg-orange-400 text-[#09120f] hover:bg-orange-300"
                  >
                    {saving ? "Saving…" : editingAsset ? "Save changes" : "Add asset"}
                  </Button>
                </div>
              </CardContent>
            </form>
          </Card>
        </div>
      )}
    </main>
  );
}

function MetricCard({
  label,
  value,
  icon: Icon,
  accent = "text-orange-300",
}: {
  label: string;
  value?: number;
  icon: LucideIcon;
  accent?: string;
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
        <Icon className={`size-5 ${accent}`} />
      </CardContent>
    </Card>
  );
}
