(() => {
  const PAGE_SIZE = 20;
  const severityColors = {
    CRITICAL: "#c65e57",
    HIGH: "#c47a3f",
    MEDIUM: "#aa8b35",
    LOW: "#39805c",
    UNKNOWN: "#a4aaa0",
  };
  const sourceNames = {
    nvd: "NVD",
    osv: "OSV",
    ghsa: "GHSA",
    cisa_kev: "KEV",
    epss: "EPSS",
  };
  const sourceClass = {
    nvd: "nvd",
    osv: "osv",
    ghsa: "ghsa",
    cisa_kev: "kev",
    epss: "epss",
  };
  const sourceStateKey = { cisa_kev: "kev" };
  const trendSeverities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
  const state = { page: 1, total: 0, query: "", severity: "", exploited: false, timer: null, scanApplicationId: "", scanRepositories: [], scanRuns: [], scanFindingStatus: "active", scanFindings: [], scanResolvedFindings: [], scanFindingDetails: new Map(), scanFindingQuery: "", scanFindingSeverity: "", trendPayload: null, trendResizeFrame: 0, publicationMetric: "all" };
  const $ = (selector) => document.querySelector(selector);
  const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
  const fmtNumber = (value) => Number(value || 0).toLocaleString();
  const score = (value, digits = 2) => Number.isFinite(Number(value)) ? Number(value).toFixed(digits) : "—";

  async function getJson(url) {
    const response = await fetch(url, { headers: { Accept: "application/json" } });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
    return body;
  }

  async function repositoryRequest(url, options = {}) {
    const headers = {
      Accept: "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {}),
    };
    const response = await fetch(url, { ...options, headers });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
    return body;
  }

  function showError(message) {
    const toast = $("#toast");
    toast.textContent = message;
    toast.classList.remove("success");
    toast.classList.add("show");
    window.clearTimeout(showError.timer);
    showError.timer = window.setTimeout(() => toast.classList.remove("show"), 4200);
  }

  function showSuccess(message) {
    const toast = $("#toast");
    toast.textContent = message;
    toast.classList.add("show", "success");
    window.clearTimeout(showError.timer);
    showError.timer = window.setTimeout(() => toast.classList.remove("show", "success"), 3200);
  }

  function timeAgo(value) {
    if (!value) return "Not synced yet";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    const minutes = Math.max(0, Math.floor((Date.now() - date.getTime()) / 60000));
    if (minutes < 1) return "Just now";
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  }

  function fmtDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return escapeHtml(value);
    return date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  }

  function severityName(value) {
    const severity = String(value || "UNKNOWN").toUpperCase();
    return ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(severity) ? severity : "UNKNOWN";
  }

  function renderSeverity(severity, total) {
    const entries = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
    const circumference = 2 * Math.PI * 60;
    let offset = 0;
    const arcs = [];
    for (const name of entries) {
      const count = Number(severity[name] || 0);
      if (!count || !total) continue;
      const segment = circumference * count / total;
      const gap = Math.min(2.5, segment * 0.18);
      const length = Math.max(0, segment - gap);
      arcs.push(`<circle class="donut-arc" cx="80" cy="80" r="60" stroke="${severityColors[name]}" stroke-dasharray="${length} ${circumference - length}" stroke-dashoffset="${-(offset + gap / 2)}"><title>${name}: ${fmtNumber(count)} (${score(count / total * 100, 1)}%)</title></circle>`);
      offset += segment;
    }
    $("#severity-arcs").innerHTML = arcs.join("");
    $("#donut-total").textContent = fmtNumber(total);
    $("#severity-legend").innerHTML = entries.map((name) =>
      `<div class="legend-row" role="button" tabindex="0" data-severity="${name}">
        <span class="legend-swatch" style="background:${severityColors[name]}"></span>
        <span>${name === "UNKNOWN" ? "Unrated" : name[0] + name.slice(1).toLowerCase()}</span>
        <span class="legend-count"><span>${fmtNumber(severity[name])}</span><span class="legend-percent">${total ? Math.round((severity[name] / total) * 100) : 0}%</span></span>
      </div>`).join("");
    $("#severity-legend").querySelectorAll("[data-severity]").forEach((item) => {
      item.addEventListener("click", () => selectSeverity(item.dataset.severity));
      item.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          selectSeverity(item.dataset.severity);
        }
      });
    });
  }

  function renderPublicationTrend(payload) {
    state.trendPayload = payload;
    const months = Array.isArray(payload.months) ? payload.months : [];
    const chart = $("#publication-chart");
    const chartState = $("#publication-chart-state");
    const series = Object.fromEntries((payload.series || []).map((item) => [item.name, item.values]));
    const values = Object.fromEntries(trendSeverities.map((name) => [
      name,
      months.map((_, index) => Math.max(0, Number(series[name]?.[index]) || 0)),
    ]));
    const totals = months.map((_, index) => trendSeverities.reduce((total, name) => total + values[name][index], 0));
    const priorityTotals = months.map((_, index) => values.CRITICAL[index] + values.HIGH[index]);
    const periodTotal = (items) => items.reduce((total, value) => total + value, 0);

    if (!months.length) {
      chart.hidden = true;
      chartState.hidden = false;
      chartState.textContent = "No published vulnerability records in the selected period.";
      $("#publication-total-all").textContent = "0";
      $("#publication-total-priority").textContent = "0";
      $("#publication-data-rows").replaceChildren();
      return;
    }

    chart.hidden = false;
    chartState.hidden = true;
    const chartWidth = Math.max(260, Math.round(chart.parentElement.getBoundingClientRect().width));
    chart.setAttribute("viewBox", `0 0 ${chartWidth} 260`);
    const metrics = {
      all: { label: "All advisories", values: totals },
      priority: { label: "Critical + High advisories", values: priorityTotals },
    };
    if (!metrics[state.publicationMetric]) state.publicationMetric = "all";
    const activeMetric = metrics[state.publicationMetric];
    const activeValues = activeMetric.values;
    document.querySelectorAll("[data-publication-metric]").forEach((button) => {
      const active = button.dataset.publicationMetric === state.publicationMetric;
      button.setAttribute("aria-pressed", String(active));
      button.classList.toggle("is-active", active);
    });
    $("#publication-total-all").textContent = fmtNumber(periodTotal(totals));
    $("#publication-total-priority").textContent = fmtNumber(periodTotal(priorityTotals));
    $("#publication-chart-title").textContent = activeMetric.label;
    $("#publication-chart-description").textContent = `${activeMetric.label} by month. Focus or hover over a column to see its severity breakdown.`;

    const plot = { left: 52, right: chartWidth - 12, top: 14, bottom: 208 };
    const plotHeight = plot.bottom - plot.top;
    const maximum = Math.max(1, ...activeValues);
    const rawStep = Math.max(1, maximum / 4);
    const magnitude = 10 ** Math.floor(Math.log10(rawStep));
    const normalized = rawStep / magnitude;
    const step = (normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10) * magnitude;
    const axisMaximum = Math.ceil(maximum / step) * step;
    const cellWidth = (plot.right - plot.left) / months.length;
    const barWidth = Math.min(38, cellWidth * 0.58);
    const grid = [];

    for (let tick = 0; tick <= axisMaximum; tick += step) {
      const y = plot.bottom - (tick / axisMaximum) * plotHeight;
      grid.push(`<line class="chart-grid-line" x1="${plot.left}" y1="${y.toFixed(2)}" x2="${plot.right}" y2="${y.toFixed(2)}"></line>
        <text class="chart-axis-label" x="${plot.left - 10}" y="${(y + 4).toFixed(2)}" text-anchor="end">${fmtNumber(tick)}</text>`);
    }
    $("#publication-grid").innerHTML = grid.join("");

    const bars = [];
    const labels = [];
    for (let index = 0; index < months.length; index += 1) {
      const centerX = plot.left + cellWidth * (index + 0.5);
      const total = activeValues[index];
      const height = total ? Math.max(1, total / axisMaximum * plotHeight) : 0;
      const y = plot.bottom - height;
      const breakdown = trendSeverities.map((severity) =>
        `${severity === "UNKNOWN" ? "Unrated" : severity[0] + severity.slice(1).toLowerCase()}: ${fmtNumber(values[severity][index])}`).join(" · ");
      const advisoryLabel = state.publicationMetric === "priority"
        ? `critical or high ${total === 1 ? "advisory" : "advisories"}`
        : total === 1 ? "advisory" : "advisories";
      const barLabel = `${months[index]} · ${fmtNumber(total)} ${advisoryLabel} · ${breakdown}`;
      const barClass = state.publicationMetric === "priority" ? "chart-bar chart-bar-priority" : "chart-bar";
      bars.push(`<rect class="${barClass}" x="${(centerX - barWidth / 2).toFixed(2)}" y="${y.toFixed(2)}" width="${barWidth.toFixed(2)}" height="${height.toFixed(2)}" rx="3" tabindex="0" aria-label="${escapeHtml(barLabel)}"><title>${escapeHtml(barLabel)}</title></rect>`);
      const parsedMonth = /^(\d{4})-(0[1-9]|1[0-2])$/.exec(months[index]);
      const monthLabel = parsedMonth
        ? new Date(`${months[index]}-01T00:00:00Z`).toLocaleDateString(undefined, { month: "short", year: "2-digit", timeZone: "UTC" })
        : "—";
      labels.push(`<text class="chart-month-label" x="${centerX.toFixed(2)}" y="240">${escapeHtml(monthLabel)}</text>`);
    }
    $("#publication-bars").innerHTML = bars.join("");
    $("#publication-x-axis").innerHTML = labels.join("");
    $("#publication-data-rows").innerHTML = months.map((month, index) =>
      `<tr><th scope="row">${escapeHtml(month)}</th><td>${fmtNumber(totals[index])}</td>${trendSeverities.map((name) => `<td>${fmtNumber(values[name][index])}</td>`).join("")}</tr>`).join("");
  }

  function renderPublicationTrendError(error) {
    state.trendPayload = null;
    $("#publication-chart").hidden = true;
    $("#publication-chart-state").hidden = false;
    $("#publication-chart-state").textContent = `Could not load publication trend: ${error.message}`;
    $("#publication-total-all").textContent = "Unavailable";
    $("#publication-total-priority").textContent = "Unavailable";
    $("#publication-data-rows").replaceChildren();
  }

  function selectSeverity(severity) {
    state.severity = state.severity === severity ? "" : severity;
    $("#severity-filter").value = state.severity;
    state.page = 1;
    setView("vulnerabilities");
    loadVulnerabilities();
  }

  function renderWatchlist(items) {
    if (!items.length) {
      $("#watchlist").innerHTML = '<div class="empty-state">No KEV-listed or high-EPSS vulnerabilities found.</div>';
      return;
    }
    $("#watchlist").innerHTML = items.map((item) => {
      const exploit = item.exploitation || {};
      const epss = exploit.epss?.score;
      const isKev = Boolean(exploit.in_kev);
      return `<div class="watch-item" data-id="${escapeHtml(item.id)}" tabindex="0" role="button">
        <div class="watch-main"><span class="risk-flag ${isKev ? "" : "high"}"></span><span class="watch-title"><strong>${escapeHtml(item.id)}</strong><small>${escapeHtml(item.title || item.description || "No summary available")}</small></span></div>
        <div class="watch-stats">${epss != null ? `<span class="watch-score">${score(epss * 100, 1)}% EPSS</span>` : ""}<span class="watch-risk ${isKev ? "" : "high"}">${isKev ? "IN KEV" : "HIGH EPSS"}</span></div>
      </div>`;
    }).join("");
    $("#watchlist").querySelectorAll("[data-id]").forEach((item) => {
      item.addEventListener("click", () => openDetails(item.dataset.id));
      item.addEventListener("keydown", (event) => {
        if (event.key === "Enter") openDetails(item.dataset.id);
      });
    });
  }

  function renderSources(items, pipelineStatus) {
    const ordered = ["nvd", "osv", "ghsa", "cisa_kev", "epss"];
    const counts = Object.fromEntries(items.map(({ name, count }) => [name, count]));
    const maximum = Math.max(1, ...Object.values(counts));
    $("#source-cards").innerHTML = ordered.map((name) => {
      const sourceState = pipelineStatus[sourceStateKey[name] || name] || {};
      const count = Number(counts[name] || 0);
      const lastSuccess = sourceState.last_success;
      const width = count ? Math.max(1, count / maximum * 100) : 0;
      return `<div class="source-card">
        <div class="source-card-top">
          <span class="source-dot ${sourceClass[name]}"></span>
          <span class="source-name">${sourceNames[name]}</span>
          <span class="source-foot">${lastSuccess ? `SYNCED ${escapeHtml(timeAgo(lastSuccess).toUpperCase())}` : "AWAITING FIRST SYNC"}</span>
        </div>
        <div class="source-bar-track" role="img" aria-label="${escapeHtml(sourceNames[name])}: ${fmtNumber(count)} canonical vulnerabilities"><span class="source-bar" style="width:${width.toFixed(1)}%"></span></div>
        <div class="source-bar-value">${fmtNumber(count)}</div>
      </div>`;
    }).join("");
    const synced = Object.values(pipelineStatus).map((source) => source.last_success).filter(Boolean);
    const latest = synced.sort().at(-1);
    $("#last-sync").textContent = latest ? `Last feed sync ${timeAgo(latest)}` : "No completed feed sync";
  }

  async function loadOverview() {
    const [summary, pipelineStatus] = await Promise.all([getJson("/api/summary"), getJson("/api/status")]);
    $("#database-state").textContent = "Database online";
    $("#database-dot").classList.remove("offline");
    $("#metric-total").textContent = fmtNumber(summary.total);
    $("#metric-kev").textContent = fmtNumber(summary.kev);
    $("#metric-critical").textContent = fmtNumber(summary.critical);
    $("#metric-epss").textContent = fmtNumber(summary.high_epss);
    $("#nav-total").textContent = fmtNumber(summary.total);
    $("#as-of").textContent = `${Object.keys(pipelineStatus).length} FEEDS MONITORED`;
    $("#footer-updated").textContent = `UPDATED ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
    renderSeverity(summary.severity, summary.total);
    renderWatchlist(summary.top_risk || []);
    renderSources(summary.sources || [], pipelineStatus);
    try {
      renderPublicationTrend(await getJson("/api/trends"));
    } catch (error) {
      renderPublicationTrendError(error);
    }
  }

  function sourceTags(sources) {
    const list = (sources || []).slice(0, 3);
    if (!list.length) return "—";
    return `<span class="source-tags">${list.map((source) => `<span class="source-tag">${escapeHtml(sourceNames[source] || source)}</span>`).join("")}${sources.length > 3 ? `<span class="source-tag">+${sources.length - 3}</span>` : ""}</span>`;
  }

  function renderTable(result) {
    state.total = result.total;
    const body = $("#vulnerability-rows");
    if (!result.items.length) {
      body.innerHTML = '<tr><td colspan="7" class="empty-state">No vulnerabilities match these filters.</td></tr>';
    } else {
      body.innerHTML = result.items.map((item) => {
        const severity = severityName(item.severity);
        const cvss = item.cvss_best?.score;
        const epss = item.exploitation?.epss?.score;
        const exploited = item.exploitation?.in_kev;
        return `<tr data-id="${escapeHtml(item.id)}" tabindex="0">
          <td><div class="vuln-cell"><span class="vuln-id">${escapeHtml(item.id)}${exploited ? ' <span class="kev-inline">↗ KEV</span>' : ""}</span><span class="vuln-title">${escapeHtml(item.title || item.description || "No description")}</span></div></td>
          <td><span class="sev-pill sev-${severity.toLowerCase()}">${severity === "UNKNOWN" ? "UNRATED" : severity}</span></td>
          <td class="numeric">${cvss == null ? "—" : score(cvss, 1)}</td>
          <td class="epss-value">${epss == null ? "—" : `${score(epss * 100, 2)}%`}</td>
          <td>${sourceTags(item.sources)}</td>
          <td class="modified">${fmtDate(item.modified || item.last_changed)}</td>
          <td class="row-arrow">›</td>
        </tr>`;
      }).join("");
      body.querySelectorAll("tr[data-id]").forEach((row) => {
        row.addEventListener("click", () => openDetails(row.dataset.id));
        row.addEventListener("keydown", (event) => {
          if (event.key === "Enter") openDetails(row.dataset.id);
        });
      });
    }
    const start = result.total ? ((result.page - 1) * result.page_size) + 1 : 0;
    const end = Math.min(result.page * result.page_size, result.total);
    $("#result-count").textContent = result.total ? `Showing ${fmtNumber(start)}–${fmtNumber(end)} of ${fmtNumber(result.total)} vulnerabilities` : "0 vulnerabilities";
    $("#page-label").textContent = `Page ${result.page} of ${Math.max(1, Math.ceil(result.total / result.page_size))}`;
    $("#previous-page").disabled = result.page <= 1;
    $("#next-page").disabled = end >= result.total;
  }

  async function loadVulnerabilities() {
    const params = new URLSearchParams({ page: String(state.page), page_size: String(PAGE_SIZE) });
    if (state.query) params.set("q", state.query);
    if (state.severity) params.set("severity", state.severity);
    if (state.exploited) params.set("exploited", "true");
    try {
      renderTable(await getJson(`/api/vulnerabilities?${params}`));
    } catch (error) {
      $("#vulnerability-rows").innerHTML = '<tr><td colspan="7" class="empty-state">Could not load vulnerability data. Check that the dashboard can reach PostgreSQL.</td></tr>';
      showError(error.message);
    }
  }

  function renderDetails(item) {
    const exploit = item.exploitation || {};
    const cvss = item.cvss_best || {};
    const epss = exploit.epss || {};
    const affected = item.affected || [];
    const references = (item.references || []).map((reference) => {
      try {
        const url = new URL(reference);
        if (!["http:", "https:"].includes(url.protocol)) return "";
        return `<a class="reference-link" href="${escapeHtml(url.href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(url.hostname)}</a>`;
      } catch {
        return "";
      }
    }).filter(Boolean).join("");
    $("#detail-content").innerHTML = `<div class="detail-body">
      <div class="detail-eyebrow">${escapeHtml(item.id)} · VULNERABILITY RECORD</div>
      <h2 class="detail-title">${escapeHtml(item.title || "Untitled vulnerability")}</h2>
      <p class="detail-description">${escapeHtml(item.description || "No description is available from the connected sources.")}</p>
      <div class="detail-pills"><span class="sev-pill sev-${severityName(item.severity).toLowerCase()}">${severityName(item.severity)}</span>${exploit.in_kev ? '<span class="watch-risk">LISTED IN CISA KEV</span>' : ""}${cvss.score != null ? `<span class="identifier-chip">CVSS ${escapeHtml(cvss.version || "")} · ${score(cvss.score, 1)}</span>` : ""}${epss.score != null ? `<span class="identifier-chip">EPSS · ${score(epss.score * 100, 2)}%</span>` : ""}</div>
      <section class="detail-section"><h3>Record details</h3><div class="detail-grid">
        <div class="detail-field"><small>Published</small><span>${fmtDate(item.published)}</span></div>
        <div class="detail-field"><small>Last modified</small><span>${fmtDate(item.modified || item.last_changed)}</span></div>
        <div class="detail-field"><small>EPSS percentile</small><span>${epss.percentile == null ? "—" : `${score(epss.percentile * 100, 2)}%`}</span></div>
        <div class="detail-field"><small>EPSS score date</small><span>${fmtDate(epss.date)}</span></div>
        <div class="detail-field"><small>Sources</small><span>${(item.sources || []).map((source) => sourceNames[source] || source).map(escapeHtml).join(", ") || "—"}</span></div>
        <div class="detail-field"><small>Weaknesses</small><span>${(item.cwes || []).map(escapeHtml).join(", ") || "—"}</span></div>
      </div></section>
      <section class="detail-section"><h3>Known identifiers</h3><div class="identifier-list">${(item.ids || []).map((identifier) => `<span class="identifier-chip">${escapeHtml(identifier)}</span>`).join("") || "—"}</div></section>
      <section class="detail-section"><h3>Affected packages · ${affected.length}</h3><div class="affected-list">${affected.length ? affected.map((entry) => `<div class="affected-card"><strong>${escapeHtml(entry.ecosystem)} · ${escapeHtml(entry.package)}</strong><p>${(entry.ranges || []).map((range) => escapeHtml(range.expr)).join(" · ") || "Version range not provided"}${entry.patched?.length ? `<br>Patched: ${entry.patched.map(escapeHtml).join(", ")}` : ""}</p></div>`).join("") : '<span class="detail-field">Affected package details unavailable from current source mappings.</span>'}</div></section>
      <section class="detail-section"><h3>References</h3><div class="reference-list">${references || '<span class="detail-field">No external references recorded.</span>'}</div></section>
    </div>`;
    $("#detail-dialog").showModal();
  }

  async function openDetails(identifier) {
    try {
      renderDetails(await getJson(`/api/vulnerabilities/${encodeURIComponent(identifier)}`));
    } catch (error) {
      showError(error.message);
    }
  }

  const scanSeverityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
  const scanSeverityColors = { CRITICAL: "#bd343c", HIGH: "#e2784c", MEDIUM: "#d4a044", LOW: "#5c9b78", UNKNOWN: "#9da5ae" };
  const shortCommit = (sha) => String(sha || "").slice(0, 12);
  const findingKey = (finding) => [
    finding.vulnerability_id || finding.canonical_id || "",
    finding.purl || "",
    finding.package_name || "",
    finding.installed_version || "",
  ].join("|").toLowerCase();
  const scanSourceNames = {
    trivy: "Trivy",
    vuln_intel: "Internal feeds",
    nvd: "NVD",
    osv: "OSV",
    ghsa: "GHSA",
    kev: "CISA KEV",
    cisa_kev: "CISA KEV",
  };
  const sourceLabel = (source) => scanSourceNames[String(source || "").toLowerCase()] || String(source || "Unknown");
  const severityClass = (severity) => severityName(severity).toLowerCase();
  const severityLabel = (severity) => severity === "UNKNOWN" ? "Unrated" : severity[0] + severity.slice(1).toLowerCase();

  function renderScanHistory(runs) {
    const body = $("#scan-history-rows");
    $("#scan-history-count").textContent = `${fmtNumber(runs.length)} ${runs.length === 1 ? "run" : "runs"}`;
    if (!runs.length) {
      body.innerHTML = '<tr><td colspan="6" class="empty-state">No scan history is available yet.</td></tr>';
      return;
    }
    body.innerHTML = runs.map((run) => `<tr>
      <td><span class="scan-history-status ${escapeHtml(run.status)}"><i aria-hidden="true"></i>${escapeHtml(run.status)}</span></td>
      <td class="scan-commit" title="${escapeHtml(run.commit_sha)}">${escapeHtml(shortCommit(run.commit_sha) || "—")}</td>
      <td>${escapeHtml(String(run.ref || "").replace(/^refs\/heads\//, "") || "—")}</td>
      <td class="numeric">${fmtNumber(run.component_count)}</td>
      <td class="numeric">${fmtNumber(run.finding_count)}${run.unevaluated_count ? ` <span class="history-review-count">+${fmtNumber(run.unevaluated_count)} review</span>` : ""}</td>
      <td>${escapeHtml(fmtDate(run.requested_at))}</td>
    </tr>`).join("");
  }

  function renderScanTrend(runs) {
    const svg = $("#scan-trend-chart");
    const note = $("#scan-trend-note");
    const successful = runs.filter((run) => run.status === "succeeded").slice(0, 8).reverse();
    note.classList.remove("scan-chart-baseline");
    if (!successful.length) {
      svg.innerHTML = "";
      svg.hidden = true;
      svg.setAttribute("aria-label", "No successful scans yet");
      note.hidden = false;
      note.textContent = "A trend will appear after the first successful scan.";
      return;
    }
    if (successful.length === 1) {
      const run = successful[0];
      svg.innerHTML = "";
      svg.hidden = true;
      svg.setAttribute("aria-label", "A baseline scan is available; another successful scan is needed to show a trend");
      note.hidden = false;
      note.classList.add("scan-chart-baseline");
      note.innerHTML = `<span class="scan-baseline-mark" aria-hidden="true">01</span><span class="scan-baseline-copy"><strong>Baseline scan recorded</strong><small>${fmtNumber(run.finding_count)} findings · ${escapeHtml(fmtDate(run.completed_at || run.requested_at))} · ${escapeHtml(shortCommit(run.commit_sha))}</small><em>Run another scan to reveal exposure movement over time.</em></span>`;
      return;
    }
    svg.hidden = false;
    note.hidden = true;
    const width = 640, height = 190, left = 38, right = 18, top = 14, bottom = 35;
    const max = Math.max(1, ...successful.map((run) => Number(run.finding_count || 0)));
    const x = (index) => successful.length === 1 ? (width + left - right) / 2 : left + index * (width - left - right) / (successful.length - 1);
    const y = (value) => height - bottom - (Number(value || 0) / max) * (height - top - bottom);
    const points = successful.map((run, index) => `${x(index)},${y(run.finding_count)}`).join(" ");
    const baseline = height - bottom;
    const area = successful.length > 1 ? `${x(0)},${baseline} ${points} ${x(successful.length - 1)},${baseline}` : "";
    const grid = [0, .5, 1].map((fraction) => {
      const value = Math.round(max * fraction);
      const yy = y(value);
      return `<line class="scan-chart-gridline" x1="${left}" y1="${yy}" x2="${width - right}" y2="${yy}"></line><text class="scan-chart-axis" x="${left - 8}" y="${yy + 4}" text-anchor="end">${fmtNumber(value)}</text>`;
    }).join("");
    const labels = successful.map((run, index) => {
      const date = run.completed_at || run.requested_at;
      const label = date ? new Date(date).toLocaleDateString(undefined, { month: "short", day: "numeric" }) : shortCommit(run.commit_sha);
      return `<text class="scan-chart-date" x="${x(index)}" y="${height - 10}" text-anchor="middle">${escapeHtml(label)}</text>`;
    }).join("");
    const dots = successful.map((run, index) => `<circle class="scan-trend-dot" cx="${x(index)}" cy="${y(run.finding_count)}" r="4"><title>${escapeHtml(fmtDate(run.completed_at || run.requested_at))}: ${fmtNumber(run.finding_count)} findings · ${escapeHtml(shortCommit(run.commit_sha))}</title></circle>`).join("");
    svg.setAttribute("aria-label", `Findings across ${successful.length} successful scans, from ${successful[0].finding_count} to ${successful[successful.length - 1].finding_count}`);
    svg.innerHTML = `${grid}${area ? `<polygon class="scan-trend-area" points="${area}"></polygon>` : ""}${successful.length > 1 ? `<polyline class="scan-trend-line" points="${points}"></polyline>` : ""}${dots}${labels}`;
  }

  function renderScanSeverity(findings) {
    const counts = Object.fromEntries(scanSeverityOrder.map((severity) => [severity, 0]));
    findings.forEach((finding) => { counts[severityName(finding.severity)] += 1; });
    const total = findings.length;
    const chart = $("#scan-severity-chart");
    const radius = 48, center = 70, circumference = 2 * Math.PI * radius;
    let offset = 0;
    const circles = scanSeverityOrder.filter((severity) => counts[severity]).map((severity) => {
      const segment = circumference * counts[severity] / Math.max(1, total);
      const circle = `<circle class="scan-donut-segment" cx="${center}" cy="${center}" r="${radius}" stroke="${scanSeverityColors[severity]}" stroke-dasharray="${segment} ${circumference - segment}" stroke-dashoffset="${-offset}"><title>${severity}: ${fmtNumber(counts[severity])}</title></circle>`;
      offset += segment;
      return circle;
    });
    chart.innerHTML = `<circle class="scan-donut-track" cx="${center}" cy="${center}" r="${radius}"></circle>${circles.join("")}<text class="scan-donut-total" x="${center}" y="${center - 2}">${fmtNumber(total)}</text><text class="scan-donut-caption" x="${center}" y="${center + 16}">FINDINGS</text>`;
    chart.setAttribute("aria-label", `${total} active findings. ${scanSeverityOrder.map((name) => `${name}: ${counts[name]}`).join(", ")}`);
    $("#scan-severity-legend").innerHTML = scanSeverityOrder.map((severity) => `<div class="scan-legend-row"><span><i style="--severity-color:${scanSeverityColors[severity]}"></i>${severity === "UNKNOWN" ? "Unrated" : severity[0] + severity.slice(1).toLowerCase()}</span><strong>${fmtNumber(counts[severity])}</strong></div>`).join("");
  }

  function renderScanBreakdowns(findings) {
    const packages = new Map(), sources = new Map();
    findings.forEach((finding) => {
      const packageName = finding.package_name || "Unknown package";
      if (!packages.has(packageName)) {
        packages.set(packageName, { total: 0, counts: Object.fromEntries(scanSeverityOrder.map((severity) => [severity, 0])) });
      }
      const packageCounts = packages.get(packageName);
      packageCounts.total += 1;
      packageCounts.counts[severityName(finding.severity)] += 1;
      (finding.sources || []).forEach((source) => {
        const label = sourceLabel(source);
        sources.set(label, (sources.get(label) || 0) + 1);
      });
    });
    const topPackages = [...packages.entries()].sort((a, b) => b[1].total - a[1].total || a[0].localeCompare(b[0])).slice(0, 6);
    const maxPackages = Math.max(1, ...topPackages.map(([, data]) => data.total));
    const packageLegend = `<div class="scan-package-legend" aria-label="Package severity legend">${scanSeverityOrder.map((severity) => `<span><i style="background:${scanSeverityColors[severity]}"></i>${severityLabel(severity)}</span>`).join("")}</div>`;
    $("#scan-package-chart").innerHTML = topPackages.length ? `${packageLegend}${topPackages.map(([name, data]) => {
      const segments = scanSeverityOrder.filter((severity) => data.counts[severity]).map((severity) => `<i class="scan-package-segment ${severityClass(severity)}" style="width:${data.counts[severity] / data.total * 100}%;background:${scanSeverityColors[severity]}"></i>`).join("");
      const summary = scanSeverityOrder.filter((severity) => data.counts[severity]).map((severity) => `${severityLabel(severity)} ${fmtNumber(data.counts[severity])}`).join(", ");
      return `<div class="scan-package-row"><div class="scan-breakdown-label"><span title="${escapeHtml(name)}">${escapeHtml(name)}</span><strong>${fmtNumber(data.total)}</strong></div><div class="scan-package-track" role="img" aria-label="${escapeHtml(name)}: ${escapeHtml(summary)}"><span class="scan-package-stack" style="width:${Math.max(4, data.total / maxPackages * 100)}%">${segments}</span></div></div>`;
    }).join("")}` : '<p class="scan-breakdown-empty">No active package findings.</p>';
    const sourceEntries = [...sources.entries()].sort((a, b) => b[1] - a[1]);
    const maxSources = Math.max(1, ...sourceEntries.map(([, count]) => count));
    $("#scan-source-chart").innerHTML = sourceEntries.length ? sourceEntries.map(([name, count], index) => `<div class="scan-breakdown-row"><div class="scan-breakdown-label"><span>${escapeHtml(name)}</span><strong>${fmtNumber(count)}</strong></div><div class="scan-breakdown-track source-track source-${index % 2}"><i style="width:${Math.max(4, count / maxSources * 100)}%"></i></div></div>`).join("") : '<p class="scan-breakdown-empty">No detection evidence to summarize.</p>';
  }

  function cvssForFinding(finding) {
    const records = finding.evidence?.trivy || [];
    for (const record of records) {
      const scores = Object.values(record.CVSS || {}).map((entry) => Number(entry.V3Score ?? entry.V2Score)).filter(Number.isFinite);
      if (scores.length) return Math.max(...scores);
    }
    return null;
  }

  function renderApplicationFindings() {
    const resolved = state.scanFindingStatus === "resolved";
    const items = resolved ? state.scanResolvedFindings : state.scanFindings;
    const query = state.scanFindingQuery.toLowerCase();
    const filtered = items.filter((finding) => {
      if (state.scanFindingSeverity && severityName(finding.severity) !== state.scanFindingSeverity) return false;
      const haystack = [finding.vulnerability_id, finding.canonical_id, finding.package_name, finding.purl, finding.installed_version, finding.fixed_version].join(" ").toLowerCase();
      return !query || haystack.includes(query);
    });
    $("#scan-finding-count").textContent = `${fmtNumber(filtered.length)} of ${fmtNumber(items.length)} findings`;
    const body = $("#application-finding-rows");
    if (!filtered.length) {
      body.innerHTML = `<tr><td colspan="7" class="empty-state">${items.length ? "No findings match these filters." : resolved ? "No resolved findings are recorded for this application." : "No active vulnerabilities were found in the latest successful scan."}</td></tr>`;
      return;
    }
    body.innerHTML = filtered.map((finding) => {
      const key = findingKey(finding);
      const cvss = cvssForFinding(state.scanFindingDetails.get(key) || finding);
      const sources = [...new Set(finding.sources || [])];
      return `<tr class="scan-finding-row" data-finding-key="${escapeHtml(key)}" tabindex="0" aria-label="View ${escapeHtml(finding.vulnerability_id || finding.canonical_id)} details">
        <td><span class="finding-severity-pill ${severityClass(finding.severity)}">${escapeHtml(severityName(finding.severity))}</span><small>${cvss === null ? "CVSS —" : `CVSS ${score(cvss, 1)}`}</small></td>
        <td><strong class="finding-cve">${escapeHtml(finding.vulnerability_id || finding.canonical_id || "Unidentified advisory")}</strong><small>${escapeHtml(finding.status || (resolved ? "resolved" : "active"))}</small></td>
        <td><strong class="finding-package">${escapeHtml(finding.package_name || "Unknown package")}</strong><small>${escapeHtml(finding.ecosystem || "Package")} · ${escapeHtml(finding.installed_version || "version unknown")}</small></td>
        <td>${finding.fixed_version ? `<span class="finding-fix">${escapeHtml(finding.fixed_version)}</span>` : '<span class="finding-no-fix">No fix listed</span>'}</td>
        <td>${sources.map((source) => `<span class="finding-source">${escapeHtml(sourceLabel(source))}</span>`).join(" ") || "—"}</td>
        <td>${escapeHtml(fmtDate(finding.first_seen || finding.last_seen))}</td>
        <td><button class="finding-open-button" type="button" aria-label="Open finding details">↗</button></td>
      </tr>`;
    }).join("");
    body.querySelectorAll("[data-finding-key]").forEach((row) => {
      const open = () => openFindingDetails(row.dataset.findingKey);
      row.addEventListener("click", open);
      row.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") { event.preventDefault(); open(); }
      });
      row.querySelector("button").addEventListener("click", (event) => { event.stopPropagation(); open(); });
    });
  }

  function renderFindingDetails(finding) {
    const identifier = finding.vulnerability_id || finding.canonical_id || "Unidentified advisory";
    const detail = state.scanFindingDetails.get(findingKey(finding)) || finding;
    const trivy = detail.evidence?.trivy || [];
    const record = trivy[0] || {};
    const scoreEntries = Object.entries(record.CVSS || {}).map(([source, data]) => ({
      source,
      score: Number(data.V3Score ?? data.V2Score),
      vector: data.V3Vector || data.V2Vector || "",
    })).filter((entry) => Number.isFinite(entry.score));
    const description = record.Description || record.Title || "The scanner did not return a vulnerability description.";
    const references = [...new Set([record.PrimaryURL, ...(record.References || [])].filter((value) => typeof value === "string" && /^https:\/\//i.test(value)))].slice(0, 12);
    const cwes = record.CweIDs || [];
    const sourceValues = [...(finding.sources || []), ...(record.SeveritySource ? [record.SeveritySource] : [])];
    const sources = [...new Set(sourceValues)];
    $("#scan-finding-title").textContent = identifier;
    $("#scan-finding-subtitle").textContent = `${finding.package_name || "Unknown package"} · ${finding.ecosystem || "Package"} · ${finding.installed_version || "version unknown"}`;
    $("#scan-finding-detail-content").innerHTML = `
      <section class="finding-risk-banner ${severityClass(finding.severity)}">
        <div><span class="detail-label">SEVERITY</span><strong>${escapeHtml(severityName(finding.severity))}</strong></div>
        <div><span class="detail-label">CVSS</span><strong>${scoreEntries.length ? score(scoreEntries[0].score, 1) : "—"}</strong></div>
        <div><span class="detail-label">STATUS</span><strong>${escapeHtml(finding.status || state.scanFindingStatus)}</strong></div>
        <div><span class="detail-label">DETECTED BY</span><strong>${escapeHtml(sources.map(sourceLabel).join(", ") || "—")}</strong></div>
      </section>
      <section class="finding-detail-section"><h3>What was detected</h3><p>${escapeHtml(description)}</p></section>
      <section class="finding-detail-section"><h3>Affected component</h3><dl class="finding-detail-grid">
        <div><dt>Package</dt><dd>${escapeHtml(finding.package_name || "Unknown")}</dd></div><div><dt>Installed version</dt><dd>${escapeHtml(finding.installed_version || "Unknown")}</dd></div>
        <div><dt>Ecosystem</dt><dd>${escapeHtml(finding.ecosystem || "—")}</dd></div><div><dt>Package URL</dt><dd class="finding-purl">${escapeHtml(finding.purl || "—")}</dd></div>
        <div><dt>First detected</dt><dd>${escapeHtml(fmtDate(finding.first_seen || finding.last_seen))}</dd></div><div><dt>Remediation</dt><dd>${finding.fixed_version ? `Upgrade to ${escapeHtml(finding.fixed_version)}` : "No fixed version was provided"}</dd></div>
      </dl></section>
      ${scoreEntries.length ? `<section class="finding-detail-section"><h3>Risk scoring evidence</h3><div class="finding-score-list">${scoreEntries.map((entry) => `<div><strong>${escapeHtml(sourceLabel(entry.source))}</strong><span>CVSS ${score(entry.score, 1)}</span><code>${escapeHtml(entry.vector || "Vector unavailable")}</code></div>`).join("")}</div></section>` : ""}
      ${cwes.length ? `<section class="finding-detail-section"><h3>Weakness classification</h3><div class="finding-tag-list">${cwes.map((cwe) => `<span>${escapeHtml(cwe)}</span>`).join("")}</div></section>` : ""}
      ${references.length ? `<section class="finding-detail-section"><h3>References</h3><ul class="finding-reference-list">${references.map((url) => `<li><a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(url)}</a></li>`).join("")}</ul></section>` : ""}
      <section class="finding-detail-section finding-action-section"><div><span class="section-kicker">RECOMMENDED ACTION</span><strong>${finding.fixed_version ? "Plan an upgrade to a listed fixed version, then run a fresh scan to confirm remediation." : "Review the upstream advisory and monitor for a vendor fix; the scan did not identify a fixed version."}</strong></div></section>`;
    $("#scan-finding-dialog").showModal();
  }

  function openFindingDetails(key) {
    const finding = [...state.scanFindings, ...state.scanResolvedFindings].find((item) => findingKey(item) === key);
    if (finding) renderFindingDetails(finding);
  }

  async function loadApplicationDashboard(applicationId) {
    state.scanApplicationId = applicationId;
    const runs = state.scanRuns.filter((run) => run.application_id === applicationId);
    const repository = state.scanRepositories.find((item) => item.application_id === applicationId);
    const latestAttempt = runs[0] || null;
    const latestSuccessful = runs.find((run) => run.status === "succeeded") || null;
    $("#scan-application-dashboard").hidden = false;
    $("#scan-empty-state").hidden = true;
    $("#scan-app-name").textContent = repository?.name || applicationId;
    $("#scan-app-id").textContent = applicationId;
    $("#scan-app-url").textContent = repository?.repository_url || "";
    $("#scan-app-url").href = repository?.repository_url || "#";
    $("#scan-app-url").hidden = !repository?.repository_url;
    $("#scan-app-ref").textContent = String(latestSuccessful?.ref || latestAttempt?.ref || "No branch recorded").replace(/^refs\/heads\//, "");
    $("#scan-app-commit").textContent = latestSuccessful ? `commit ${shortCommit(latestSuccessful.commit_sha)}` : "No successful commit yet";
    $("#scan-latest-status").className = `scan-status ${escapeHtml(latestAttempt?.status || "unknown")}`;
    $("#scan-latest-status").textContent = latestAttempt?.status || "not scanned";
    $("#scan-last-scanned").textContent = latestSuccessful ? fmtDate(latestSuccessful.completed_at || latestSuccessful.requested_at) : "No successful scan";
    $("#scan-run-message").textContent = latestAttempt && latestAttempt.status !== "succeeded"
      ? `Most recent attempt ${latestAttempt.status} · ${fmtDate(latestAttempt.requested_at)}`
      : latestSuccessful ? `Completed in ${Math.max(0, Math.round((new Date(latestSuccessful.completed_at) - new Date(latestSuccessful.started_at || latestSuccessful.requested_at)) / 1000))} seconds` : "Queue a scan to build the application posture.";
    $("#scan-latest-scanner").textContent = latestSuccessful ? `Trivy ${latestSuccessful.scanner_version || "—"}` : "";
    $("#scan-app-ref").title = latestSuccessful?.ref || latestAttempt?.ref || "";
    $("#scan-app-commit").title = latestSuccessful?.commit_sha || "";
    $("#scan-history-details").open = false;
    renderScanHistory(runs);
    renderScanTrend(runs);

    const attemptNotice = $("#scan-attempt-notice");
    if (latestAttempt && latestAttempt.status !== "succeeded") {
      attemptNotice.hidden = false;
      attemptNotice.textContent = latestAttempt.status === "queued" || latestAttempt.status === "running"
        ? `A scan is ${latestAttempt.status}. The dashboard is showing the latest successful scan while it runs. Refresh data to check progress.`
        : `The most recent scan ${latestAttempt.status}. Any prior successful results remain available below.`;
    } else {
      attemptNotice.hidden = true;
    }

    const findingsUrl = `/api/applications/${encodeURIComponent(applicationId)}/findings`;
    const [activeResult, resolvedResult, latestDetail] = await Promise.all([
      getJson(`${findingsUrl}?status=active`),
      getJson(`${findingsUrl}?status=resolved`),
      latestSuccessful ? getJson(`/api/scans/${encodeURIComponent(latestSuccessful.run_id)}`) : Promise.resolve(null),
    ]);
    state.scanFindings = activeResult.items || [];
    state.scanResolvedFindings = resolvedResult.items || [];
    state.scanFindingDetails = new Map((latestDetail?.findings || []).map((finding) => [findingKey(finding), finding]));
    const counts = Object.fromEntries(scanSeverityOrder.map((severity) => [severity, 0]));
    state.scanFindings.forEach((finding) => { counts[severityName(finding.severity)] += 1; });
    const priority = counts.CRITICAL + counts.HIGH;
    const fixable = state.scanFindings.filter((finding) => Boolean(finding.fixed_version)).length;
    $("#app-kpi-active").textContent = fmtNumber(state.scanFindings.length);
    $("#app-kpi-priority").textContent = fmtNumber(priority);
    $("#app-kpi-fix").textContent = fmtNumber(fixable);
    $("#app-kpi-components").textContent = latestSuccessful ? fmtNumber(latestSuccessful.component_count) : "—";
    $("#app-kpi-components-note").textContent = latestSuccessful ? "latest successful run" : "no successful scan yet";
    const previousSuccess = latestSuccessful ? runs.find((run) => run.status === "succeeded" && run.run_id !== latestSuccessful.run_id) : null;
    const netChange = latestSuccessful && previousSuccess
      ? Number(latestSuccessful.finding_count || 0) - Number(previousSuccess.finding_count || 0)
      : null;
    $("#app-kpi-new").textContent = netChange === null ? (latestSuccessful ? "Baseline" : "—") : `${netChange > 0 ? "+" : ""}${fmtNumber(netChange)}`;
    $("#app-kpi-new").classList.toggle("metric-negative", netChange !== null && netChange < 0);
    $("#app-kpi-new").classList.toggle("metric-positive", netChange !== null && netChange > 0);
    $("#app-kpi-new-note").textContent = netChange === null ? "change appears after next scan" : "net change vs previous scan";
    $("#scan-active-tab-count").textContent = fmtNumber(state.scanFindings.length);
    $("#scan-resolved-tab-count").textContent = fmtNumber(state.scanResolvedFindings.length);
    renderScanSeverity(state.scanFindings);
    renderScanBreakdowns(state.scanFindings);
    renderApplicationFindings();
  }

  async function loadScans() {
    try {
      const [scanResponse, repositoryResponse] = await Promise.all([
        getJson("/api/scans?limit=100"),
        getJson("/api/repositories"),
      ]);
      state.scanRuns = scanResponse.items || [];
      state.scanRepositories = repositoryResponse.items || [];
      const applicationIds = new Set([
        ...state.scanRepositories.map((item) => item.application_id),
        ...state.scanRuns.map((run) => run.application_id),
      ]);
      const select = $("#scan-app-select");
      const oldValue = select.value || state.scanApplicationId;
      const repositoryById = new Map(state.scanRepositories.map((item) => [item.application_id, item]));
      select.innerHTML = [...applicationIds].sort((a, b) => {
        const aName = repositoryById.get(a)?.name || a;
        const bName = repositoryById.get(b)?.name || b;
        return aName.localeCompare(bName);
      }).map((id) => {
        const name = repositoryById.get(id)?.name || id;
        return `<option value="${escapeHtml(id)}">${escapeHtml(name)}</option>`;
      }).join("");
      if (!applicationIds.size) {
        select.innerHTML = "";
        $("#scan-empty-state").hidden = false;
        $("#scan-application-dashboard").hidden = true;
        $("#scan-attempt-notice").hidden = true;
        return;
      }
      const selectedId = applicationIds.has(oldValue) ? oldValue : (state.scanRuns[0]?.application_id || [...applicationIds][0]);
      select.value = selectedId;
      await loadApplicationDashboard(selectedId);
    } catch (error) {
      $("#scan-application-dashboard").hidden = true;
      $("#scan-empty-state").hidden = false;
      $("#scan-empty-state").querySelector("p").textContent = "Application scan data could not be loaded. Refresh and try again.";
      showError(error.message);
    }
  }

  async function scanGitHubRepository(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      const result = await repositoryRequest("/api/repositories/scan", {
        method: "POST",
        body: JSON.stringify({ repository_url: $("#scan-github-url").value.trim() }),
      });
      form.reset();
      state.scanApplicationId = result.repository.application_id;
      $("#scan-github-panel").hidden = true;
      $("#scan-add-app-toggle").setAttribute("aria-expanded", "false");
      showSuccess(result.created ? `Scan queued for ${result.repository.name}.` : `A scan is already queued for ${result.repository.name}.`);
      await loadScans();
    } catch (error) {
      showError(error.message);
    } finally {
      button.disabled = false;
    }
  }

  async function queueLatestApplicationScan() {
    if (!state.scanApplicationId) return;
    const button = $("#scan-run-again");
    button.disabled = true;
    try {
      const result = await repositoryRequest(`/api/repositories/${encodeURIComponent(state.scanApplicationId)}/scan`, { method: "POST" });
      showSuccess(result.created ? "Latest-commit scan queued." : "A scan is already queued for this application.");
      await loadScans();
    } catch (error) {
      showError(error.message);
    } finally {
      button.disabled = false;
    }
  }

  function renderRepositoryConnections(items) {
    const rows = $("#repository-rows");
    if (!items.length) {
      rows.innerHTML = '<tr><td colspan="5" class="empty-state">No repository connections are configured.</td></tr>';
      $("#repository-result-count").textContent = "0 connected repositories";
      return;
    }
    rows.innerHTML = items.map((item) => `<tr>
      <td>${escapeHtml(item.name)}<br><small>${escapeHtml(item.application_id)}${item.external_inventory_id ? ` · Inventory: ${escapeHtml(item.external_inventory_id)}` : ""}</small></td>
      <td class="repository-url">${escapeHtml(item.repository_url)}</td>
      <td>${escapeHtml(providerForUrl(item.repository_url))}</td>
      <td class="modified">${fmtDate(item.updated_at)}</td>
      <td><button class="text-button repository-scan" type="button" data-application-id="${escapeHtml(item.application_id)}">Scan now</button> <button class="text-button repository-delete" type="button" data-application-id="${escapeHtml(item.application_id)}">Remove</button></td>
    </tr>`).join("");
    rows.querySelectorAll(".repository-delete").forEach((button) => {
      button.addEventListener("click", async () => {
        if (!window.confirm(`Remove the repository connection for ${button.dataset.applicationId}?`)) return;
        try {
          await repositoryRequest(`/api/repositories/${encodeURIComponent(button.dataset.applicationId)}`, {
            method: "DELETE",
          });
          await loadRepositories();
        } catch (error) {
          showError(error.message);
        }
      });
    });
    rows.querySelectorAll(".repository-scan").forEach((button) => {
      button.addEventListener("click", async () => {
        try {
          await repositoryRequest(`/api/repositories/${encodeURIComponent(button.dataset.applicationId)}/scan`, {
            method: "POST",
          });
          state.scanApplicationId = button.dataset.applicationId;
          setView("scans");
          showSuccess("Scan queued for the repository's latest default-branch commit.");
          await loadScans();
        } catch (error) {
          showError(error.message);
        }
      });
    });
    $("#repository-result-count").textContent = `${fmtNumber(items.length)} connected repositories`;
  }

  function providerForUrl(repositoryUrl) {
    try {
      const hostname = new URL(repositoryUrl).hostname.toLowerCase();
      if (hostname === "github.com") return "GitHub";
      return `GitLab · ${hostname}`;
    } catch (error) {
      return "Unknown";
    }
  }

  function renderProviderCredentials(items) {
    const rows = $("#provider-rows");
    if (!items.length) {
      rows.innerHTML = '<tr><td colspan="4" class="empty-state">No provider credentials are configured.</td></tr>';
      return;
    }
    rows.innerHTML = items.map((item) => `<tr>
      <td>${item.provider === "github" ? "GitHub" : "GitLab"}</td>
      <td>${item.configured ? "Credentials saved" : "Not configured"}</td>
      <td class="modified">${fmtDate(item.updated_at)}</td>
      <td>${item.configured ? `<button class="text-button provider-delete" type="button" data-provider="${escapeHtml(item.provider)}">Remove</button>` : ""}</td>
    </tr>`).join("");
    rows.querySelectorAll(".provider-delete").forEach((button) => {
      button.addEventListener("click", async () => {
        if (!window.confirm(`Remove the saved ${button.dataset.provider} credentials?`)) return;
        try {
          await repositoryRequest(`/api/git-credentials/${encodeURIComponent(button.dataset.provider)}`, {
            method: "DELETE",
          });
          await loadRepositories();
        } catch (error) {
          showError(error.message);
        }
      });
    });
  }

  async function loadRepositories() {
    try {
      const [repositories, providers] = await Promise.all([
        repositoryRequest("/api/repositories"),
        repositoryRequest("/api/git-credentials"),
      ]);
      renderRepositoryConnections(repositories.items || []);
      renderProviderCredentials(providers.items || []);
    } catch (error) {
      $("#repository-rows").innerHTML = '<tr><td colspan="5" class="empty-state">Could not load repository connections.</td></tr>';
      $("#repository-result-count").textContent = "Repository settings unavailable";
      $("#provider-rows").innerHTML = '<tr><td colspan="4" class="empty-state">Could not load provider credentials.</td></tr>';
      showError(error.message);
    }
  }

  async function saveProviderCredentials(event) {
    event.preventDefault();
    const payload = {
      provider: $("#provider-name").value,
      username: $("#provider-username").value.trim(),
      token: $("#provider-token").value,
    };
    try {
      const result = await repositoryRequest("/api/git-credentials", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      const verification = result.credentials?.verification;
      if (payload.provider === "github" && verification?.status !== "verified") {
        throw new Error("GitHub did not confirm these credentials. They were not saved.");
      }
      $("#provider-token").value = "";
      showSuccess(payload.provider === "github"
        ? "GitHub token verified; credentials saved."
        : "GitLab credentials saved.");
      await loadRepositories();
    } catch (error) {
      showError(error.message);
    }
  }

  async function saveRepositoryConnection(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const payload = {
      application_id: $("#repository-application-id").value.trim(),
      name: $("#repository-name").value.trim(),
      repository_url: $("#repository-url").value.trim(),
    };
    try {
      await repositoryRequest("/api/repositories", { method: "POST", body: JSON.stringify(payload) });
      form.reset();
      showSuccess("Repository connection saved.");
      await loadRepositories();
    } catch (error) {
      showError(error.message);
    }
  }

  function scheduleSearch(query) {
    state.query = query.trim();
    state.page = 1;
    window.clearTimeout(state.timer);
    state.timer = window.setTimeout(loadVulnerabilities, 230);
  }

  function setView(view) {
    const selected = ["vulnerabilities", "scans", "repositories"].includes(view) ? view : "overview";
    document.body.classList.toggle("scan-workspace-active", selected === "scans");
    const isList = selected === "vulnerabilities";
    const activeView = selected === "scans" ? "application-scans-view"
      : selected === "repositories" ? "repository-settings-view" : `${selected}-view`;
    document.querySelectorAll(".view-page").forEach((page) => {
      page.hidden = page.id !== activeView;
    });
    document.querySelectorAll(".nav-item[data-view]").forEach((item) => {
      const active = item.dataset.view === selected;
      item.classList.toggle("active", active);
      if (active) item.setAttribute("aria-current", "page");
      else item.removeAttribute("aria-current");
    });
    const isScans = selected === "scans";
    const isRepositories = selected === "repositories";
    $("#page-eyebrow").textContent = isList ? "VULNERABILITY INTELLIGENCE" : isScans ? "APPLICATION SECURITY" : isRepositories ? "REPOSITORY ACCESS" : "THREAT LANDSCAPE";
    $("#page-eyebrow-line").hidden = isList || isScans || isRepositories;
    $("#as-of").hidden = isList || isScans || isRepositories;
    $("#page-title").textContent = isList ? "Vulnerability explorer" : isScans ? "Application scans" : isRepositories ? "Repository settings" : "Security overview";
    $("#page-description").textContent = isList
      ? "Search, filter, and inspect normalized vulnerability intelligence."
      : isScans
        ? "Application exposure, prioritized findings, and remediation status."
        : isRepositories
          ? "Connect repositories and grant Vuln Intel read-only access for scanning."
          : "A clear view of the vulnerabilities that matter across your intelligence sources.";
    $("#global-search-control").hidden = !isList;
    document.title = `${isList ? "Vulnerabilities" : isScans ? "Application scans" : isRepositories ? "Repository settings" : "Overview"} · Vuln Intel`;
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function setSidebarExpanded(expanded) {
    document.body.classList.toggle("sidebar-collapsed", !expanded);
    $("#sidebar-toggle").setAttribute("aria-expanded", String(expanded));
  }

  function bindEvents() {
    const sidebarToggle = $("#sidebar-toggle");
    sidebarToggle.addEventListener("click", () => {
      const expanded = document.body.classList.contains("sidebar-collapsed");
      setSidebarExpanded(expanded);
      sidebarToggle.setAttribute("aria-label", expanded ? "Collapse sidebar" : "Expand sidebar");
      sidebarToggle.title = expanded ? "Collapse sidebar" : "Expand sidebar";
    });
    document.querySelectorAll(".nav-item[data-view]").forEach((item) => item.addEventListener("click", () => {
      setView(item.dataset.view);
      if (item.dataset.view === "scans") loadScans();
      if (item.dataset.view === "repositories") loadRepositories();
    }));
    document.querySelectorAll("[data-open-list]").forEach((item) => item.addEventListener("click", () => setView("vulnerabilities")));
    $("#publication-metrics").addEventListener("click", (event) => {
      const button = event.target.closest("[data-publication-metric]");
      if (!button || !state.trendPayload) return;
      state.publicationMetric = button.dataset.publicationMetric;
      renderPublicationTrend(state.trendPayload);
    });
    $("#global-search").addEventListener("input", (event) => {
      scheduleSearch(event.target.value);
    });
    $("#severity-filter").addEventListener("change", (event) => {
      state.severity = event.target.value;
      state.page = 1;
      loadVulnerabilities();
    });
    $("#kev-filter").addEventListener("change", (event) => {
      state.exploited = event.target.checked;
      state.page = 1;
      loadVulnerabilities();
    });
    $("#previous-page").addEventListener("click", () => {
      if (state.page > 1) {
        state.page -= 1;
        loadVulnerabilities();
      }
    });
    $("#next-page").addEventListener("click", () => {
      if (state.page * PAGE_SIZE < state.total) {
        state.page += 1;
        loadVulnerabilities();
      }
    });
    $("#scan-app-select").addEventListener("change", (event) => loadApplicationDashboard(event.target.value));
    $("#scan-refresh-button").addEventListener("click", loadScans);
    $("#scan-add-app-toggle").addEventListener("click", () => {
      const panel = $("#scan-github-panel");
      panel.hidden = !panel.hidden;
      $("#scan-add-app-toggle").setAttribute("aria-expanded", String(!panel.hidden));
      if (!panel.hidden) $("#scan-github-url").focus();
    });
    $("#scan-empty-add").addEventListener("click", () => {
      $("#scan-github-panel").hidden = false;
      $("#scan-add-app-toggle").setAttribute("aria-expanded", "true");
      $("#scan-github-url").focus();
    });
    $("#scan-run-again").addEventListener("click", queueLatestApplicationScan);
    $("#scan-github-form").addEventListener("submit", scanGitHubRepository);
    document.querySelectorAll(".scan-finding-tab").forEach((tab) => tab.addEventListener("click", () => {
      state.scanFindingStatus = tab.dataset.status;
      document.querySelectorAll(".scan-finding-tab").forEach((item) => {
        const selected = item === tab;
        item.classList.toggle("active", selected);
        item.setAttribute("aria-selected", String(selected));
      });
      renderApplicationFindings();
    }));
    $("#scan-finding-search").addEventListener("input", (event) => {
      state.scanFindingQuery = event.target.value.trim();
      renderApplicationFindings();
    });
    $("#scan-finding-severity").addEventListener("change", (event) => {
      state.scanFindingSeverity = event.target.value;
      renderApplicationFindings();
    });
    $("#scan-finding-close").addEventListener("click", () => {
      $("#scan-finding-dialog").close();
    });
    $("#scan-finding-dialog").addEventListener("click", (event) => {
      if (event.target === $("#scan-finding-dialog")) $("#scan-finding-dialog").close();
    });
    $("#provider-credentials-form").addEventListener("submit", saveProviderCredentials);
    $("#repository-form").addEventListener("submit", saveRepositoryConnection);
    $("#refresh-button").addEventListener("click", () => {
      Promise.all([loadOverview(), loadVulnerabilities(), loadScans()]).catch((error) => {
        $("#database-state").textContent = "Database unavailable";
        $("#database-dot").classList.add("offline");
        showError(error.message);
      });
    });
    const trendChartContainer = $("#publication-chart").parentElement;
    let trendChartWidth = 0;
    const resizeTrendChart = () => {
      const width = trendChartContainer.clientWidth;
      if (!width || width === trendChartWidth) return;
      trendChartWidth = width;
      if (!state.trendPayload || state.trendResizeFrame) return;
      state.trendResizeFrame = window.requestAnimationFrame(() => {
        state.trendResizeFrame = 0;
        renderPublicationTrend(state.trendPayload);
      });
    };
    if ("ResizeObserver" in window) {
      new ResizeObserver(resizeTrendChart).observe(trendChartContainer);
    } else {
      window.addEventListener("resize", resizeTrendChart);
    }
    document.addEventListener("keydown", (event) => {
      if (event.key === "/" && !["INPUT", "TEXTAREA"].includes(document.activeElement.tagName)) {
        event.preventDefault();
        setView("vulnerabilities");
        $("#global-search").focus();
      }
    });
  }

  bindEvents();
  Promise.all([loadOverview(), loadVulnerabilities()]).catch((error) => showError(error.message));
})();
