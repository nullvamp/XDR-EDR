const pages = {
  dashboard: "Dashboard",
  endpoints: "Endpoints",
  processes: "Process search",
  files: "File activity",
  quarantines: "File quarantine",
  "persistence-backups": "Persistence remediation backups",
  registry: "Registry activity",
  network: "Network activity",
  dns: "DNS activity",
  modules: "Module and image loads",
  drivers: "Driver loads",
  services: "Windows services",
  tasks: "Scheduled tasks",
  "persistence-configurations": "Persistence configurations",
  "wmi-subscriptions": "WMI subscriptions",
  "persistence-policies": "Persistence policies",
  identity: "Identity and logon telemetry",
  "identity-policies": "Identity policies",
  execution: "Low-level execution telemetry",
  "execution-policies": "Execution policies",
  detections: "Detection rules",
  "detection-content": "Production detection content",
  findings: "Detection findings",
  "detection-replay": "Detection replay",
  "detection-health": "Detection engine health",
  "correlation-rules": "Correlation rules and packs",
  "correlated-findings": "Correlated findings",
  "correlation-replay": "Correlation replay",
  "correlation-health": "Correlation engine health",
  "mitre-coverage": "MITRE coverage",
  "entity-graph": "Entity relationship graph",
  "attack-stories": "Evidence-backed attack stories",
  "threat-hunting": "Threat hunting workspace",
  "saved-hunts": "Saved hunts",
  "investigation-health": "Investigation health",
  alerts: "Analyst alert queue",
  incidents: "Incident queue",
  "triage-health": "Triage lifecycle health",
  "response-actions": "Endpoint response actions",
  approvals: "Security approval center",
  "response-health": "Response engine health",
  "live-response": "Secure Live Response",
  "live-response-health": "Live Response health",
  "forensic-collections": "Remote forensic collections",
  "forensic-collection-health": "Forensic collection health",
  "forensic-tools": "Approved forensic tools",
  "dfir-workspace": "Forensic investigation workspace",
  intelligence: "Threat intelligence",
  "intelligence-matches": "IOC matches",
  "intelligence-health": "Intelligence health",
  tunnels: "Tunnel and covert-channel analytics",
  "tunnel-rules": "Tunnel analytic rules",
  "tunnel-health": "Tunnel analytics health",
  playbooks: "Response playbooks",
  "playbook-executions": "Playbook executions",
  "playbook-approvals": "Playbook approvals",
  "playbook-health": "Playbook health",
  "self-protection": "Agent self-protection",
  fleet: "Fleet management",
  resilience: "Platform resilience and recovery",
  capacity: "Capacity engineering",
  "administration-governance": "Enterprise administration",
  retention: "Retention and storage lifecycle",
  "ai-investigation": "AI investigation assistant",
  "detection-engineering": "AI-assisted hunting and detection engineering",
  "agent-update-packages": "Agent update packages",
  "update-rollouts": "Agent update rollouts",
  "update-policies": "Update policies and rings",
  "module-policies": "Module policies",
  "dns-policies": "DNS policies",
  "network-listeners": "Network listeners",
  "network-policies": "Network policies",
  "registry-policies": "Registry policies",
  "file-policies": "File policies",
  administration: "Enrollment tokens",
  policies: "Process policies",
  operations: "Process operations",
  login: "Login",
  search: "Unified search",
};
const nav = [
  ["dashboard", "Dashboard"],
  ["endpoints", "Endpoints"],
  ["processes", "Processes"],
  ["files", "Files"],
  ["quarantines", "Quarantine"],
  ["persistence-backups", "Persistence backups"],
  ["registry", "Registry"],
  ["network", "Network"],
  ["dns", "DNS"],
  ["modules", "Modules"],
  ["drivers", "Drivers"],
  ["services", "Services"],
  ["tasks", "Scheduled tasks"],
  ["persistence-configurations", "Persistence configurations"],
  ["wmi-subscriptions", "WMI subscriptions"],
  ["persistence-policies", "Persistence policies"],
  ["identity", "Identity and logons"],
  ["identity-policies", "Identity policies"],
  ["execution", "Low-level execution"],
  ["execution-policies", "Execution policies"],
  ["detections", "Detection rules"],
  ["detection-content", "Production content"],
  ["findings", "Findings"],
  ["detection-replay", "Detection replay"],
  ["detection-health", "Detection health"],
  ["correlation-rules", "Correlation rules"],
  ["correlated-findings", "Correlated findings"],
  ["correlation-replay", "Correlation replay"],
  ["correlation-health", "Correlation health"],
  ["mitre-coverage", "MITRE coverage"],
  ["entity-graph", "Entity graph"],
  ["attack-stories", "Attack stories"],
  ["threat-hunting", "Threat hunting"],
  ["saved-hunts", "Saved hunts"],
  ["investigation-health", "Investigation health"],
  ["alerts", "Alert triage"],
  ["incidents", "Incidents"],
  ["triage-health", "Triage health"],
  ["response-actions", "Response actions"],
  ["response-health", "Response health"],
  ["live-response", "Live Response"],
  ["live-response-health", "Live Response health"],
  ["forensic-collections", "Forensic collections"],
  ["forensic-collection-health", "Collection health"],
  ["forensic-tools", "Forensic tools"],
  ["dfir-workspace", "DFIR workspace"],
  ["intelligence", "Threat intelligence"],
  ["intelligence-matches", "IOC matches"],
  ["intelligence-health", "Intelligence health"],
  ["tunnels", "Tunnel analytics"],
  ["tunnel-rules", "Tunnel rules"],
  ["tunnel-health", "Tunnel health"],
  ["playbooks", "Playbooks"],
  ["playbook-executions", "Playbook executions"],
  ["playbook-approvals", "Playbook approvals"],
  ["playbook-health", "Playbook health"],
  ["self-protection", "Self-protection"],
  ["fleet", "Fleet"],
  ["resilience", "Resilience"],
  ["capacity", "Capacity"],
  ["administration-governance", "Enterprise administration"],
  ["retention", "Retention"],
  ["ai-investigation", "AI investigation"],
  ["detection-engineering", "Detection engineering"],
  ["agent-update-packages", "Update packages"],
  ["update-rollouts", "Update rollouts"],
  ["update-policies", "Update policies"],
  ["module-policies", "Module policies"],
  ["dns-policies", "DNS policies"],
  ["network-listeners", "Network listeners"],
  ["network-policies", "Network policies"],
  ["registry-policies", "Registry policies"],
  ["file-policies", "File policies"],
  ["policies", "Process policies"],
  ["operations", "Operations"],
  ["administration", "Enrollment tokens"],
];
const navGroups = [
  ["Monitor", [["dashboard", "SOC Overview"], ["alerts", "Alerts"], ["incidents", "Incidents"], ["dfir-workspace", "Investigations"]]],
  ["Investigate", [["entity-graph", "Entity graph"], ["attack-stories", "Attack stories"], ["threat-hunting", "Hunt"], ["ai-investigation", "AI Assistant"]]],
  ["Assets & intelligence", [["endpoints", "Endpoints"], ["intelligence", "Threat intelligence"], ["tunnels", "Tunnel analytics"], ["forensic-collections", "Forensics"]]],
  ["Detection & response", [["detection-content", "Detections"], ["detection-engineering", "Detection engineering"], ["response-actions", "Response center"], ["approvals", "Approvals"], ["live-response", "Live Response"], ["playbooks", "Playbooks"]]],
  ["Operations", [["fleet", "Fleet"], ["agent-update-packages", "Updates"], ["self-protection", "Self-protection"], ["resilience", "Platform health"], ["administration-governance", "Administration"]]],
];
const pageFamilies = new Map(navGroups.flatMap(([group, items]) => items.map(([id]) => [id, group])));
function jwtContext() {
  try {
    const segment = (token() || "").split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    const payload = JSON.parse(atob(segment.padEnd(Math.ceil(segment.length / 4) * 4, "=")));
    const homeTenant = payload.tid || "Unknown tenant";
    return { subject: payload.sub || "Analyst", tenant: sessionStorage.getItem("platform_client_id") || homeTenant, homeTenant, permissions: payload.per || [] };
  } catch { return { subject: "Signed out", tenant: "No tenant", permissions: [] }; }
}
function statusClass(value, kind = "status") { return `${kind}-${String(value ?? "unknown").replace(/([a-z])([A-Z])/g, "$1-$2").toLowerCase().replace(/[^a-z0-9-]/g, "-")}`; }
function statusBadge(value, kind = "status") { return `<span class="badge ${statusClass(value, kind)}">${esc(value ?? "Unknown")}</span>`; }
function relativeTime(value) { const date = new Date(value), seconds = Math.round((date.getTime() - Date.now()) / 1000), abs = Math.abs(seconds); const [amount, unit] = abs < 60 ? [seconds, "second"] : abs < 3600 ? [Math.round(seconds / 60), "minute"] : abs < 86400 ? [Math.round(seconds / 3600), "hour"] : [Math.round(seconds / 86400), "day"]; return `<time datetime="${esc(date.toISOString())}" title="${esc(date.toLocaleString())}; ${esc(date.toISOString())}">${new Intl.RelativeTimeFormat(undefined, { numeric: "auto" }).format(amount, unit)}</time>`; }
function loadingState(label = "Loading workspace") { return `<div role="status" aria-live="polite" aria-label="${esc(label)}"><div class="skeleton" style="width:32%;height:18px"></div><div class="skeleton" style="width:100%;height:72px;margin-top:16px"></div><div class="skeleton" style="width:84%;height:72px;margin-top:10px"></div></div>`; }
function notify(message, kind = "info") { const host = document.querySelector("#toast-region"); if (!host) return; const item = document.createElement("div"); item.className = `toast ${statusClass(kind)}`; item.role = kind === "error" ? "alert" : "status"; item.textContent = message; host.append(item); setTimeout(() => item.remove(), 5000); }
function boundedSavedViews() {
  const context = jwtContext();
  const key = `soc.saved-views.${context.tenant}.${context.subject}`;
  return {
    list: () => { try { return JSON.parse(localStorage.getItem(key) || "[]").filter(x => pages[x?.route]).slice(0, 20); } catch { return []; } },
    save: (name, route, filters) => { if (!pages[route]) throw Error("This workspace cannot be saved."); const safe = Object.fromEntries([...filters].filter(([k, v]) => /^[a-zA-Z][a-zA-Z0-9]*$/.test(k) && String(v).length <= 256).slice(0, 20)); const values = boundedSavedViews().list().filter(x => x.name !== name); values.unshift({ name: String(name).slice(0, 80), route, filters: safe }); localStorage.setItem(key, JSON.stringify(values.slice(0, 20))); },
  };
}
let dark = localStorage.getItem("theme") !== "light";
const token = () => sessionStorage.getItem("access_token");
const refreshToken = () => sessionStorage.getItem("refresh_token");
const auth = () => ({ Authorization: `Bearer ${token()}`, ...(sessionStorage.getItem("platform_client_id") ? { "X-Platform-Client": sessionStorage.getItem("platform_client_id") } : {}) });
const AUTHENTICATION_REQUIRED = "__authentication_required__";
let authenticationRefresh = null;
function jwtPayload(value) {
  try {
    const segment = String(value || "").split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(segment.padEnd(Math.ceil(segment.length / 4) * 4, "=")));
  } catch { return null; }
}
function tokenIsCurrent(value, leewaySeconds = 5) {
  const payload = jwtPayload(value);
  return Boolean(payload?.exp && payload.exp > Math.floor(Date.now() / 1000) + leewaySeconds);
}
function clearAuthentication() {
  sessionStorage.removeItem("access_token");
  sessionStorage.removeItem("refresh_token");
  sessionStorage.removeItem("platform_client_id");
  managedClients = [];
}
async function refreshAuthentication() {
  if (authenticationRefresh) return authenticationRefresh;
  authenticationRefresh = (async () => {
    const currentRefreshToken = refreshToken();
    if (!tokenIsCurrent(currentRefreshToken, 10)) { clearAuthentication(); return false; }
    try {
      const response = await fetch("/api/v1/auth/refresh", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refreshToken: currentRefreshToken }),
      });
      if (!response.ok) { clearAuthentication(); return false; }
      const body = await response.json();
      if (!tokenIsCurrent(body.access_token)) { clearAuthentication(); return false; }
      sessionStorage.setItem("access_token", body.access_token);
      return true;
    } catch { return false; }
    finally { authenticationRefresh = null; }
  })();
  return authenticationRefresh;
}
async function ensureAuthentication() {
  if (tokenIsCurrent(token())) return true;
  return refreshAuthentication();
}
let managedClients = [];
async function loadManagedClients() {
  if (!token()) { managedClients = []; return; }
  const response = await api("/api/v1/platform/clients");
  managedClients = response.data.items || [];
  const selected = sessionStorage.getItem("platform_client_id");
  if (!selected || !managedClients.some(x => x.clientId === selected)) {
    sessionStorage.setItem("platform_client_id", managedClients.find(x => x.selected)?.clientId || jwtContext().homeTenant);
  }
}
let activeReadController = new AbortController();
let routeSequence = 0;
let queueContext = null;
let endpointDetailContext = null;
const navigationContext = [];
let pendingScrollRestore = null;
let lastRenderedHash = "";
const liveClientInstanceId = crypto.randomUUID();
let livePresenceSessionId = null;
let livePresenceTimer = null;
let livePollTimer = null;
let livePresenceTerminal = false;
const CANCELLED_NAVIGATION = "__obsolete_navigation__";
const esc = (v) =>
  String(v ?? "").replace(
    /[&<>'"]/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[
        c
      ],
  );
function state(title, message, action = "") {
  if (message === CANCELLED_NAVIGATION) throw new DOMException("Obsolete navigation", "AbortError");
  const kind = /error|failed|unavailable|permission|authentication/i.test(`${title} ${message}`)
    ? "error"
    : /degraded|partial|unknown|not observable/i.test(`${title} ${message}`)
      ? "degraded"
      : /loading|retrieving/i.test(`${title} ${message}`)
        ? "loading"
        : "empty";
  const detail = kind === "error"
    ? " Existing data has not been changed. Retry only when it is safe to do so."
    : "";
  return `<div class="empty state-${kind}" role="status" aria-live="polite"><h2>${esc(title)}</h2><p>${esc(message)}${esc(detail)}</p>${action}</div>`;
}
async function api(path, options = {}) {
  const { _authenticationRetried = false, ...requestOptions } = options;
  const method = String(options.method || "GET").toUpperCase();
  let r;
  try {
    r = await fetch(path, {
      ...requestOptions,
      signal: requestOptions.signal || (["GET", "HEAD"].includes(method) ? activeReadController.signal : undefined),
      headers: { ...auth(), ...(requestOptions.headers || {}) },
    });
  } catch (error) {
    if (error?.name === "AbortError") throw Error(CANCELLED_NAVIGATION);
    throw Error("The gateway could not be reached. Existing data remains unchanged; retry after connectivity is restored.");
  }
  if (r.status === 401) {
    if (!_authenticationRetried && await refreshAuthentication())
      return api(path, { ...requestOptions, _authenticationRetried: true });
    clearAuthentication();
    rememberAuthenticationDestination();
    renderAuthenticationGate("Your session expired. Sign in to continue where you left off.");
    throw Error(AUTHENTICATION_REQUIRED);
  }
  let problem = null;
  if (!r.ok) {
    try { problem = await r.clone().json(); } catch { /* non-JSON failure */ }
  }
  const requestId = problem?.requestId || problem?.correlationId || r.headers.get("x-request-id");
  if (r.status === 403)
    throw Error(`You do not have permission to perform this action.${requestId ? ` Request ${requestId}.` : ""}`);
  if (!r.ok) {
    const uncertain = !["GET", "HEAD", "OPTIONS"].includes(method) && r.status >= 500;
    const reason = problem?.detail || problem?.message || problem?.title || `Request failed with status ${r.status}.`;
    const guidance = r.status === 404 ? " The object may have moved or the link may be stale." : r.status === 409 ? " Refresh the current state before deciding whether to retry." : r.status === 429 ? ` Retry after ${r.headers.get("retry-after") || "the server-advised delay"}.` : r.status >= 500 ? " The service is temporarily unavailable." : "";
    throw Error(`${reason}${requestId ? ` Request ${requestId}.` : ""}${guidance}${uncertain ? " Execution may be uncertain; inspect the audit trail and target state before retrying." : ""}`);
  }
  return r.status === 204 ? null : r.json();
}
async function endpointList() {
  if (!token())
    return state(
      "Authentication required",
      "Sign in to view tenant-scoped endpoints.",
      '<a class="button" href="#/login">Sign in</a>',
    );
  try {
    const b = await api("/api/v1/endpoints?pageSize=100"),
      items = b.data.items;
    if (!items.length)
      return state(
        "No enrolled endpoints",
        "Create an enrollment token and start an agent.",
      );
    return `<div class="endpoint-grid">${items.map((x) => `<a class="card" href="#/endpoints/${x.id}"><span class="badge ${esc(x.status)}">${esc(x.status)}</span><h2>${esc(x.hostname || "Unknown host")}</h2><p>${esc(x.platform)} · ${esc(x.osVersion)}</p><small>Agent ${esc(x.agentVersion)} · ${x.lastSeenAt ? new Date(x.lastSeenAt).toLocaleString() : "never seen"}</small></a>`).join("")}</div>`;
  } catch (e) {
    return state("Endpoints unavailable", e.message);
  }
}
function processTable(items) {
  if (!items.length)
    return '<p class="muted">No process events in this time range.</p>';
  return `<div class="table-wrap"><table><caption class="sr-only">Endpoint process timeline</caption><thead><tr><th>Started</th><th>Process</th><th>PID</th><th>Parent</th><th>User</th><th>State</th><th>Actions</th></tr></thead><tbody>${items.map((x) => { const name = x.executableName || x.name || x.executableMetadata?.fileName, path = x.executablePath || x.path || x.executableMetadata?.path, pid = x.processId ?? x.pid, parentPid = x.parentProcessId ?? x.parentPid, quality = x.dataQualityFlags || []; return `<tr><td>${new Date(x.startTime).toLocaleString()}</td><td title="${esc(path || "")}"><strong>${esc(name || `PID ${pid} · image not observed`)}</strong><br><small>${esc(path || (quality.includes("start-not-observed") ? "Start event was not observed" : "Executable path not collected"))}</small></td><td>${pid ?? "Not collected"}</td><td>${parentPid ?? "—"}</td><td>${esc(x.userName || x.userId || "Not collected")}</td><td>${x.exitTime ? "Exited" : "Running"}</td><td><a href="#/processes/${x.endpointId}/${x.processEntityId}">Inspect</a></td></tr>`; }).join("")}</tbody></table></div>`;
}
function fileHealthPanel(endpoint, health, effective) {
  const lost = health
      ? (health.etwLostEvents || 0) + (health.falcoLostEvents || 0)
      : 0,
    stale =
      health?.lastEventAt &&
      Date.now() - new Date(health.lastEventAt).getTime() > 300000,
    stateName = !health
      ? endpoint.status === "offline"
        ? "Offline"
        : "Unsupported"
      : !health.enabled
        ? "Disabled"
        : endpoint.status === "offline"
          ? "Offline"
          : /disk/i.test(health.lastUploadResult || "")
            ? "Disk full"
            : /corrupt/i.test(health.lastUploadResult || "")
              ? "Queue corrupted"
              : /unavailable/i.test(health.lastUploadResult || "")
                ? "Source unavailable"
                : stale
                  ? "Stale"
                  : health.queueDepth > 0
                    ? "Recovering"
                    : health.droppedEvents ||
                        health.sourceGaps ||
                        lost ||
                        health.hashFailures ||
                        health.signatureFailures
                      ? "Degraded"
                      : "Healthy";
  if (!health)
    return `<article aria-labelledby="file-health-title"><div class="detail-head"><h3 id="file-health-title">File telemetry health</h3><span class="badge">${esc(stateName)}</span></div><p class="muted">No file telemetry health report received.</p><p><a href="#/files?endpointId=${endpoint.id}">Endpoint file timeline</a> · <a href="#/files?endpointId=${endpoint.id}">Endpoint-scoped file search</a></p></article>`;
  const when = health.lastEventAt
    ? new Date(health.lastEventAt).toLocaleString()
    : "None";
  return `<article aria-labelledby="file-health-title"><div class="detail-head"><h3 id="file-health-title">File telemetry health</h3><span class="badge">${esc(stateName)}</span></div><dl><dt>Collector enabled</dt><dd>${health.enabled ? "Yes" : "No"}</dd><dt>Collector source</dt><dd>${esc(health.collectorType)}</dd><dt>Collector version</dt><dd>${esc(health.collectorVersion)}</dd><dt>Collector state</dt><dd>${esc(stateName)}</dd><dt>Last source event</dt><dd>${when}</dd><dt>Last accepted event</dt><dd>${when}</dd><dt>Event count</dt><dd>${health.lastSequence}</dd><dt>Queue depth</dt><dd>${health.queueDepth}</dd><dt>Oldest queue item</dt><dd>${health.oldestQueuedSeconds}s</dd><dt>Dropped events</dt><dd>${health.droppedEvents}</dd><dt>Excluded events</dt><dd>${health.excludedEvents}</dd><dt>Source gaps</dt><dd>${health.sourceGaps}</dd><dt>Native lost events</dt><dd>${lost}</dd><dt>Hash queue depth</dt><dd>Not reported</dd><dt>Hash failures</dt><dd>${health.hashFailures}</dd><dt>Signature failures</dt><dd>${health.signatureFailures}</dd><dt>Policy version</dt><dd>${esc(health.policyVersion || "Unknown")}</dd><dt>Applied version</dt><dd>${effective?.appliedVersion ?? "Unknown"}</dd><dt>Drift</dt><dd>${effective ? (effective.drift ? "Yes" : "No") : "Unknown"}</dd><dt>Last upload</dt><dd>${esc(health.lastUploadResult || "Unknown")}</dd><dt>Projection delay</dt><dd>Not reported</dd><dt>Known gaps</dt><dd>${health.watchErrors + health.journalResets + health.sourceGaps + lost}</dd></dl><p><a href="#/files?endpointId=${endpoint.id}">Endpoint file timeline</a> · <a href="#/files?endpointId=${endpoint.id}">Endpoint-scoped file search</a>${effective?.policy?.id ? ` · <a href="#/file-policies/${effective.policy.id}">Effective file policy</a>` : ""}</p></article>`;
}
async function endpointDetail(id) {
  try {
    const [ep, timeline, health] = await Promise.all([
        api(`/api/v1/endpoints/${id}`),
        api(`/api/v1/endpoints/${id}/process-timeline?pageSize=100`),
        api(`/api/v1/endpoints/${id}/process-telemetry-health`).catch(
          () => null,
        ),
      ]),
      x = ep.data,
      h = health?.data;
    endpointDetailContext = { id, endpoint: x };
    return `<a href="#/endpoints">← Back to endpoints</a><div class="detail-head"><div><h2>${esc(x.hostname)}</h2><p class="muted">${esc(x.id)}</p></div><span class="badge ${esc(x.status)}">${esc(x.status)}</span></div><div class="panels"><article><h3>Endpoint</h3><dl><dt>Last seen</dt><dd>${x.lastSeenAt ? new Date(x.lastSeenAt).toLocaleString() : "Never"}</dd><dt>Agent</dt><dd>${esc(x.agentVersion)}</dd><dt>Platform</dt><dd>${esc(x.platform)} ${esc(x.osVersion)}</dd></dl></article><article><h3>Telemetry health</h3>${h ? `<dl><dt>Queue depth</dt><dd>${h.queueDepth}</dd><dt>Dropped</dt><dd>${h.droppedEvents}</dd><dt>Sequence gaps</dt><dd>${h.sequenceGaps}</dd><dt>Last event</dt><dd>${h.lastEventAt ? new Date(h.lastEventAt).toLocaleString() : "None"}</dd><dt>Upload</dt><dd>${esc(h.lastUploadResult || "unknown")}</dd></dl>` : '<p class="muted">No report received.</p>'}</article></div><section><h2>Process timeline</h2>${processTable(timeline.data.items || [])}</section><div class="danger"><button onclick="endpointAction('${x.id}','disable')">Disable endpoint</button><button onclick="endpointAction('${x.id}','revoke')">Revoke credential</button></div>`;
  } catch (e) {
    return state("Endpoint unavailable", e.message);
  }
}
function isolationStateClass(value) {
  return String(value || "unknown")
    .replace(/([a-z])([A-Z])/g, "$1-$2")
    .toLowerCase();
}

async function hydrateIsolationPanel(endpoint) {
  const host = document.querySelector("#content");
  if (!host) return;
  try {
    const [status, history] = await Promise.all([
      api(`/api/v1/endpoints/${endpoint.id}/isolation`),
      api(`/api/v1/endpoints/${endpoint.id}/isolation/history`),
    ]);
    const x = status.data,
      actions = history.data || [],
      isolated = x.effectiveState === "Isolated",
      pending = ["IsolationPending", "Isolating", "UnisolationPending", "Unisolating"].includes(x.requestedState),
      destinations = x.managementExceptions || [],
      query = new URLSearchParams(location.hash.split("?")[1] || "");
    host.insertAdjacentHTML(
      "beforeend",
      `<section class="containment" aria-labelledby="containment-title"><div class="detail-head"><div><h2 id="containment-title">Endpoint containment</h2><p class="muted">Safe, reversible, policy-bound Windows network isolation.</p></div><span class="badge isolation-${isolationStateClass(x.effectiveState)}" role="status" aria-live="polite">${esc(x.effectiveState)}</span></div>${x.failureReason ? `<p class="containment-error" role="alert"><strong>Enforcement warning:</strong> ${esc(x.failureReason)}</p>` : ""}<div class="panels"><article><h3>Effective enforcement</h3><dl><dt>Requested state</dt><dd>${esc(x.requestedState)}</dd><dt>Effective state</dt><dd>${esc(x.effectiveState)}</dd><dt>Mechanism</dt><dd>${esc(x.enforcementMechanism)}</dd><dt>Policy</dt><dd>${esc(x.policyVersion)}</dd><dt>Effective since</dt><dd>${x.effectiveSince ? new Date(x.effectiveSince).toLocaleString() : "Not established"}</dd><dt>Last verification</dt><dd>${x.lastVerificationTime ? new Date(x.lastVerificationTime).toLocaleString() : "Never"}</dd><dt>Drift</dt><dd>${esc(x.driftState)}</dd></dl></article><article><h3>Management exceptions</h3>${destinations.length ? `<ul>${destinations.map((d) => `<li><code>${esc(d.protocol.toUpperCase())} ${esc(d.address)}:${d.port}</code> — ${esc(d.direction)} — ${esc(d.purpose)}</li>`).join("")}</ul>` : '<p class="muted">No trusted destinations reported. Isolation cannot safely proceed.</p>'}<p>Exceptions come only from versioned server policy; analysts cannot enter an allowlist.</p></article><article><h3>Containment action</h3><p class="containment-warning"><strong>Warning:</strong> Isolation blocks non-management endpoint communications. Approval may be required.</p><button id="containment-open" ${pending ? "disabled" : ""}>${isolated ? "Unisolate endpoint" : "Isolate endpoint"}</button> <button id="containment-verify">Verify effective state</button><p id="containment-status" role="status" aria-live="assertive" tabindex="-1"></p></article></div><section><h3>Immutable containment history</h3>${actions.length ? `<ol class="timeline">${actions.map((a) => `<li><time>${new Date(a.requestedAt).toLocaleString()}</time> <a href="#/response-actions/${a.responseActionId}">${esc(a.actionType)}</a> — ${esc(a.state)} by ${esc(a.analystId)}<p>${esc(a.parameters?.reason || "No reason")}</p></li>`).join("")}</ol>` : '<p class="muted">No containment actions recorded.</p>'}</section><dialog id="containment-dialog" aria-labelledby="containment-dialog-title"><form id="containment-form"><h2 id="containment-dialog-title">Confirm endpoint ${isolated ? "unisolation" : "isolation"}</h2><p>${isolated ? "Only platform-owned controls will be removed. Unrelated firewall rules remain unchanged." : "Non-management inbound and outbound connections will be blocked after management-channel verification."}</p><label>Required reason <textarea name="reason" required maxlength="1024"></textarea></label><input type="hidden" name="sourceAlertId" value="${esc(query.get("alertId") || "")}"><input type="hidden" name="sourceIncidentId" value="${esc(query.get("incidentId") || "")}"><input type="hidden" name="sourceEntityId" value="${esc(query.get("entityId") || "")}"><div class="danger"><button type="submit">Confirm ${isolated ? "unisolation" : "isolation"}</button><button type="button" id="containment-close">Cancel</button></div></form></dialog></section>`,
    );
    const dialog = document.querySelector("#containment-dialog"),
      opener = document.querySelector("#containment-open"),
      output = document.querySelector("#containment-status");
    opener?.addEventListener("click", () => {
      dialog.showModal();
      dialog.querySelector("textarea").focus();
    });
    document.querySelector("#containment-close")?.addEventListener("click", () => {
      dialog.close();
      opener?.focus();
    });
    document.querySelector("#containment-verify")?.addEventListener("click", async () => {
      output.textContent = "Verification requested…";
      try {
        const result = await api(`/api/v1/endpoints/${endpoint.id}/isolation:verify`, { method: "POST" });
        output.textContent = `Verification action ${result.data.responseActionId} created.`;
      } catch (error) {
        output.textContent = error.message;
      }
      output.focus();
    });
    document.querySelector("#containment-form")?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const data = new FormData(event.target),
        operation = isolated ? "unisolate" : "isolate";
      output.textContent = `${operation === "isolate" ? "Isolation" : "Unisolation"} request is being validated…`;
      try {
        const body = { endpointId: endpoint.id, reason: data.get("reason"), expiresInSeconds: 900 };
        for (const field of ["sourceAlertId", "sourceIncidentId", "sourceEntityId"])
          if (data.get(field)) body[field] = data.get(field);
        const result = await api(`/api/v1/endpoints/${endpoint.id}:${operation}`, {
          method: "POST",
          body: JSON.stringify(body),
        });
        dialog.close();
        output.textContent = `Request accepted as action ${result.data.responseActionId || "existing state"}. Review and approve it in the action history.`;
      } catch (error) {
        output.textContent = error.message;
      }
      output.focus();
    });
  } catch (error) {
    host.insertAdjacentHTML(
      "beforeend",
      `<section class="containment">${state("Containment state unavailable", error.message)}</section>`,
    );
  }
}

async function hydrateFileHealth(endpoint) {
  const [health, effective] = await Promise.all([
    api(`/api/v1/endpoints/${endpoint.id}/file-telemetry-health`).catch(
      () => null,
    ),
    api(`/api/v1/endpoints/${endpoint.id}/file-policy`).catch(() => null),
  ]);
  document
    .querySelector(".panels")
    ?.insertAdjacentHTML(
      "beforeend",
      fileHealthPanel(endpoint, health?.data, effective?.data),
    );
}
async function hydrateRegistryHealth(endpoint) {
  const [health, effective] = await Promise.all([
    api(`/api/v1/endpoints/${endpoint.id}/registry-telemetry-health`).catch(
      () => null,
    ),
    api(`/api/v1/endpoints/${endpoint.id}/registry-policy`).catch(() => null),
  ]);
  const h = health?.data;
  const status = !h
    ? "Unavailable"
    : !h.enabled
      ? "Disabled"
      : h.droppedEvents ||
          h.sourceLosses ||
          h.sequenceGaps ||
          h.pathResolutionFailures
        ? "Degraded"
        : h.queueDepth
          ? "Recovering"
          : "Healthy";
  document
    .querySelector(".panels")
    ?.insertAdjacentHTML(
      "beforeend",
      `<article aria-labelledby="registry-health-title"><div class="detail-head"><h3 id="registry-health-title">Registry telemetry health</h3><span class="badge">${esc(status)}</span></div>${h ? `<dl><dt>Collector enabled</dt><dd>${h.enabled ? "Yes" : "No"}</dd><dt>Collector source</dt><dd>${esc(h.collectorSource)}</dd><dt>Collector version</dt><dd>${esc(h.collectorVersion)}</dd><dt>Last source event</dt><dd>${h.lastSourceEvent ? new Date(h.lastSourceEvent).toLocaleString() : "Unavailable"}</dd><dt>Last accepted event</dt><dd>${h.lastAcceptedEvent ? new Date(h.lastAcceptedEvent).toLocaleString() : "Unavailable"}</dd><dt>Queue depth</dt><dd>${h.queueDepth}</dd><dt>Queue age</dt><dd>${h.oldestQueuedSeconds}s</dd><dt>Drops</dt><dd>${h.droppedEvents}</dd><dt>Exclusions</dt><dd>${h.excludedEvents}</dd><dt>Source losses</dt><dd>${h.sourceLosses}</dd><dt>Sequence gaps</dt><dd>${h.sequenceGaps}</dd><dt>Handle resolution failures</dt><dd>${h.handleResolutionFailures}</dd><dt>Path resolution failures</dt><dd>${h.pathResolutionFailures}</dd><dt>Capture skips/failures</dt><dd>${h.captureSkips}/${h.captureFailures}</dd><dt>Policy version</dt><dd>${esc(h.policyVersion)}</dd><dt>Applied version</dt><dd>${h.appliedVersion ?? "Unknown"}</dd><dt>Drift</dt><dd>${effective?.data?.drift ? "Yes" : "No"}</dd><dt>Known gaps</dt><dd>${h.sourceLosses + h.sequenceGaps + h.pathResolutionFailures}</dd></dl>` : '<p class="muted">No registry health report has been accepted.</p>'}<p><a href="#/registry?endpointId=${endpoint.id}">Endpoint registry timeline</a>${effective?.data?.policy?.id ? ` · <a href="#/registry-policies/${effective.data.policy.id}">Effective policy</a>` : ""}</p></article>`,
    );
}
async function processSearch() {
  try {
    const q = new URLSearchParams(location.hash.split("?")[1] || ""),
      b = await api(`/api/v1/processes?${q}`);
    return `<form id="process-search" class="toolbar"><label>Name <input name="name" value="${esc(q.get("name") || "")}"></label><label>PID <input name="pid" type="number" min="1" value="${esc(q.get("pid") || "")}"></label><label>Path <input name="path" value="${esc(q.get("path") || "")}"></label><button>Search</button><button type="button" id="process-export">Export JSONL</button></form><p id="export-status" role="status" aria-live="polite"></p>${processTable(b.data.items || [])}`;
  } catch (e) {
    return state("Process search unavailable", e.message);
  }
}
async function processDetail(endpointId, entityId) {
  try {
    const [d, p, tp, h] = await Promise.all([
        api(`/api/v1/endpoints/${endpointId}/processes/${entityId}`),
        api(`/api/v1/endpoints/${endpointId}/processes/${entityId}/response-preview`),
        api(`/api/v1/endpoints/${endpointId}/processes/${entityId}/tree-response-preview?maximumDepth=4&maximumProcessCount=64`),
        api(`/api/v1/endpoints/${endpointId}/process-response-history`),
      ]),
      x = d.data,
      preview = p.data,
      treePreview = tp.data,
      responseHistory = h.data.items || [];
    const responsePanel = `<section aria-labelledby="process-response-title"><div class="detail-head"><div><h2 id="process-response-title">Safe process response</h2><p>Signed actions bind the process entity, PID, native start identity, endpoint installation, and immutable preview.</p></div><span class="badge">${preview.protectedTargets?.length ? "Protected" : "Preview verified"}</span></div><div class="panels"><article><h3>Exact target preview</h3><dl><dt>Endpoint</dt><dd><code>${esc(preview.endpointId)}</code></dd><dt>PID / start</dt><dd>${preview.root.processId} / ${new Date(preview.root.processStartTime).toLocaleString()}</dd><dt>Image</dt><dd>${esc(preview.root.imagePath || "Unavailable")}</dd><dt>User / session</dt><dd>${esc(preview.user || "Unavailable")} / ${esc(preview.session || "Unavailable")}</dd><dt>Integrity</dt><dd>${esc(preview.integrity || "Unavailable")}</dd><dt>Signer / hash</dt><dd>${esc(preview.signer || "Unavailable")} / <code>${esc(preview.hash || "Unavailable")}</code></dd></dl></article><article><h3>Bounded tree preview</h3><dl><dt>Snapshot</dt><dd><code>${esc(treePreview.graphSnapshotVersion)}</code></dd><dt>Captured</dt><dd>${new Date(treePreview.capturedAt).toLocaleString()}</dd><dt>Exact targets</dt><dd>${treePreview.targets.length}</dd><dt>Protected/skipped</dt><dd>${treePreview.protectedTargets.length}</dd><dt>Order</dt><dd>${esc(treePreview.plannedOrder)}</dd></dl></article><article><h3>Analyst controls</h3><p class="containment-warning"><strong>Warning:</strong> Termination cannot be undone. Resume removes only response-owned suspension.</p><button id="process-response-open" ${x.exitTime || preview.protectedTargets?.length ? "disabled" : ""}>Open response dialog</button><p id="process-response-status" role="status" aria-live="assertive" tabindex="-1"></p></article></div><dialog id="process-response-dialog" aria-labelledby="process-response-dialog-title"><form id="process-response-form"><h2 id="process-response-dialog-title">Confirm exact process response</h2><p><code>${esc(x.processEntityId)}</code></p><label>Action <select name="action"><option value="terminate">Terminate exact process</option><option value="suspend">Suspend exact process</option><option value="resume">Resume response-owned suspension</option><option value="tree">Terminate pinned tree (${treePreview.targets.length} targets)</option></select></label><label>Required reason <textarea name="reason" required maxlength="1024"></textarea></label><p>Destructive actions require separated approval. The target snapshot cannot be edited.</p><div class="danger"><button type="submit">Request structured action</button><button type="button" id="process-response-close">Cancel</button></div></form></dialog><h3>Immutable process-response history</h3>${responseHistory.length ? `<ol class="timeline">${responseHistory.map((a) => `<li><time>${new Date(a.requestedAt).toLocaleString()}</time> <a href="#/response-actions/${a.responseActionId}">${esc(a.actionType)}</a> — ${esc(a.state)} by ${esc(a.analystId)}</li>`).join("")}</ol>` : '<p class="muted">No process response has been requested for this endpoint.</p>'}</section>`;
    return `<a href="#/processes">← Back to search</a><div class="detail-head"><div><h2>${esc(x.name || x.executableName || "Process image not collected")}</h2><p class="muted">${esc(x.processEntityId)}</p></div><span class="badge">${x.exitTime ? "Exited" : "Running"}</span></div><div class="panels"><article><h3>Identity</h3><dl><dt>PID</dt><dd>${x.pid ?? x.processId}</dd><dt>Parent PID</dt><dd>${x.parentPid ?? x.parentProcessId ?? "Not collected"}</dd><dt>Lineage</dt><dd>${esc(x.lineageState)}</dd><dt>Start</dt><dd>${new Date(x.startTime).toLocaleString()}</dd><dt>Exit</dt><dd>${x.exitTime ? new Date(x.exitTime).toLocaleString() : "Not observed"}</dd></dl></article><article><h3>Evidence</h3><dl><dt>Path</dt><dd>${esc(x.path || x.executablePath || "Not collected")}</dd><dt>Command line</dt><dd><code>${esc(x.commandLine || "Not collected")}</code></dd><dt>SHA-256</dt><dd>${esc(x.executable?.sha256 || x.executableMetadata?.sha256 || "Not collected")}</dd><dt>Signature</dt><dd>${esc(x.executable?.signatureState || x.executableMetadata?.signatureState || "Not checked")}</dd><dt>Collector</dt><dd>${esc(x.collectorType)}</dd></dl></article><article><h3>Data quality</h3><p>${esc((x.dataQualityFlags || []).join(", ") || "No flags")}</p><p>Schema ${esc(x.schemaVersion)} · normalization ${esc(x.normalizationVersion)}</p></article></div>${responsePanel}`;
  } catch (e) {
    return state("Process details unavailable", e.message);
  }
}
async function submitProcessResponse(e, endpointId, entityId) {
  e.preventDefault();
  const form = new FormData(e.target), action = form.get("action"), status = document.querySelector("#process-response-status");
  status.textContent = "Creating signed structured action…";
  try {
    const route = action === "tree" ? `/api/v1/endpoints/${endpointId}/processes/${entityId}/tree:terminate` : `/api/v1/endpoints/${endpointId}/processes/${entityId}:${action}`;
    const query = new URLSearchParams(location.hash.split("?")[1] || ""), context = { sourceAlertId: query.get("alertId") || null, sourceIncidentId: query.get("incidentId") || null, sourceEntityId: entityId };
    const body = action === "tree" ? { reason: form.get("reason"), maximumDepth: 4, maximumProcessCount: 64, ...context } : { reason: form.get("reason"), ...context };
    const result = await api(route, { method: "POST", body: JSON.stringify(body) });
    document.querySelector("#process-response-dialog")?.close();
    status.textContent = `Action ${result.data.action?.responseActionId || result.data.responseActionId} is pending policy approval.`;
  } catch (error) { status.textContent = `Request rejected safely: ${error.message}`; }
  status.focus();
}
function registryEventTable(items) {
  if (!items.length)
    return '<p class="muted">No registry activity matches this bounded query.</p>';
  return `<div class="table-wrap"><table><thead><tr><th>Observed</th><th>Operation</th><th>Hive</th><th>Key path</th><th>Value</th><th>Type</th><th>Process</th><th>User</th><th>Capture</th><th>Quality</th></tr></thead><tbody>${items.map((x) => `<tr><td><a href="#/registry/${x.eventId}">${new Date(x.observedAt).toLocaleString()}</a></td><td>${esc(x.kind)}</td><td>${esc(x.hive)}</td><td><code>${esc(x.keyPath || "Unresolved")}</code></td><td>${esc(x.valueName ?? "Not applicable")}</td><td>${esc(x.value?.valueType || "Unavailable")}</td><td>${esc(x.process?.image || x.process?.processEntityId || "Unavailable")}</td><td>${esc(x.userSid || "Unknown")}</td><td>${esc(x.value?.captureMode || "MetadataOnly")}${x.value?.redacted ? " (redacted)" : ""}</td><td>${esc((x.dataQualityFlags || []).join(", ") || "No flags")}</td></tr>`).join("")}</tbody></table></div>`;
}
async function registrySearch() {
  try {
    const q = new URLSearchParams(location.hash.split("?")[1] || ""),
      b = await api(`/api/v1/registry-events?${q}`);
    return `<form id="registry-search" class="toolbar"><label>Hive <select name="hive"><option value="">Any</option>${["HKLM", "HKCU", "HKU", "HKCR", "HKCC", "UNRESOLVED"].map((v) => `<option ${q.get("hive") === v ? "selected" : ""}>${v}</option>`).join("")}</select></label><label>Key path <input name="path" value="${esc(q.get("path") || "")}"></label><label>Value name <input name="valueName" value="${esc(q.get("valueName") || "")}"></label><label>Operation <select name="operation"><option value="">Any</option>${["KeyCreated", "KeyDeleted", "KeyRenamed", "ValueSet", "ValueDeleted", "KeySecurityChanged"].map((v) => `<option ${q.get("operation") === v ? "selected" : ""}>${v}</option>`).join("")}</select></label><label>Process <input name="process" value="${esc(q.get("process") || "")}"></label><label>User <input name="user" value="${esc(q.get("user") || "")}"></label><label>Value type <input name="valueType" value="${esc(q.get("valueType") || "")}"></label><button>Search</button><button type="button" id="registry-export">Export JSONL</button></form><p id="registry-export-status" role="status" aria-live="polite"></p>${registryEventTable(b.data.items || [])}${b.data.nextCursor ? `<button id="registry-next" data-cursor="${esc(b.data.nextCursor)}">Next page</button>` : ""}`;
  } catch (e) {
    return state("Registry search unavailable", e.message);
  }
}
async function registryDetail(eventId) {
  try {
    const x = (await api(`/api/v1/registry-events/${eventId}`)).data;
    const history = x.registryValueEntityId
      ? await api(
          `/api/v1/endpoints/${x.endpointId}/registry-values/${x.registryValueEntityId}/history`,
        )
      : await api(
          `/api/v1/endpoints/${x.endpointId}/registry-keys/${x.registryKeyEntityId}/history`,
        );
    return `<a href="#/registry">← Back to registry search</a><div class="detail-head"><div><h2>${esc(x.hive)}\\${esc(x.keyPath || "Unresolved path")}</h2><p class="muted">${esc(x.eventId)}</p></div><span class="badge">${esc(x.kind)}</span></div><div class="panels"><article><h3>Registry identity</h3><dl><dt>Key entity</dt><dd><code>${esc(x.registryKeyEntityId)}</code></dd><dt>Value entity</dt><dd><code>${esc(x.registryValueEntityId || "Not applicable")}</code></dd><dt>Previous path</dt><dd>${esc(x.previousKeyPath || "Unavailable")}</dd><dt>Value name</dt><dd>${esc(x.valueName ?? "Not applicable")}</dd><dt>View</dt><dd>${esc(x.registryView)}</dd><dt>Native handle</dt><dd>${esc(x.nativeKeyHandle ?? "Unavailable")}</dd></dl></article><article><h3>Value metadata</h3><dl><dt>Type</dt><dd>${esc(x.value?.valueType || "Unavailable")}</dd><dt>Data length</dt><dd>${x.value?.dataLength ?? "Unavailable"}</dd><dt>SHA-256</dt><dd><code>${esc(x.value?.sha256 || "Not collected")}</code></dd><dt>Preview</dt><dd>${x.value?.redacted ? "Redacted" : esc(x.value?.preview || "Not collected")}</dd><dt>Truncated</dt><dd>${x.value?.truncated ? "Yes" : "No"}</dd><dt>Capture failure</dt><dd>${esc(x.value?.failureReason || "None")}</dd></dl></article><article><h3>Provenance</h3><dl><dt>Native operation</dt><dd>${esc(x.nativeOperation)}</dd><dt>Native status</dt><dd>${esc(x.nativeStatus ?? "Unavailable")}</dd><dt>Collector</dt><dd>${esc(x.collectorSource)} ${esc(x.collectorVersion)}</dd><dt>Process</dt><dd>${esc(x.process?.image || x.process?.processEntityId || "Unavailable")}</dd><dt>User</dt><dd>${esc(x.userSid || "Unknown")}</dd><dt>Source confidence</dt><dd>${esc(x.sourceConfidence)}</dd><dt>Raw evidence hash</dt><dd><code>${esc(x.rawSha256 || "Unavailable")}</code></dd><dt>Quality</dt><dd>${esc((x.dataQualityFlags || []).join(", ") || "No flags")}</dd></dl></article></div><section><h2>${x.registryValueEntityId ? "Value" : "Key"} history</h2>${registryEventTable(history.data.items || [])}</section>`;
  } catch (e) {
    return state("Registry event unavailable", e.message);
  }
}
async function exportRegistry() {
  const s = document.querySelector("#registry-export-status");
  s.textContent = "Export pending…";
  try {
    const r = await fetch(
      `/api/v1/registry-events:export?${new URLSearchParams(location.hash.split("?")[1] || "")}`,
      { headers: auth() },
    );
    if (!r.ok) throw Error(`status ${r.status}`);
    const u = URL.createObjectURL(await r.blob()),
      a = document.createElement("a");
    a.href = u;
    a.download = "registry-telemetry.jsonl";
    a.click();
    URL.revokeObjectURL(u);
    s.textContent = "Export complete.";
  } catch (e) {
    s.textContent = `Export failed: ${e.message}`;
  }
}
async function registryPolicyList() {
  try {
    const items = (await api("/api/v1/registry-telemetry/policies")).data || [],
      latest = [...new Map(items.map((x) => [x.name, x])).values()];
    return `<div class="toolbar"><p>Immutable metadata-first Registry collection policies.</p><a class="button" href="#/registry-policies/new">Create policy</a></div>${latest.length ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Version</th><th>Collector</th><th>Capture</th><th>Enabled</th><th>Exclusions</th></tr></thead><tbody>${latest.map((x) => `<tr><td><a href="#/registry-policies/${x.id}">${esc(x.name)}</a></td><td>${x.version}</td><td>${esc(x.policy.collectorSource)}</td><td>${esc(x.policy.captureMode)}</td><td>${x.policy.enabled ? "On" : "Off"}</td><td>${(x.policy.exclusionRules || []).length}</td></tr>`).join("")}</tbody></table></div>` : state("No registry policies", "The safe implicit policy remains metadata-only and bounded.")}`;
  } catch (e) {
    return state("Registry policies unavailable", e.message);
  }
}
async function hydrateProcessRegistry(endpointId, entityId) {
  try {
    const b = await api(
      `/api/v1/endpoints/${endpointId}/processes/${entityId}/registry`,
    );
    document
      .querySelector("#content")
      ?.insertAdjacentHTML(
        "beforeend",
        `<section><h2>Registry activity</h2>${registryEventTable(b.data.items || [])}</section>`,
      );
  } catch (e) {
    document
      .querySelector("#content")
      ?.insertAdjacentHTML(
        "beforeend",
        `<section>${state("Registry relationship unavailable", e.message)}</section>`,
      );
  }
}
async function registryPolicyPage(id) {
  if (id === "new")
    return `<form id="registry-policy-editor" class="admin-grid"><fieldset><legend>Registry policy</legend><label>Name <input name="name" required maxlength="100"></label><label><input type="checkbox" name="enabled" checked> Registry telemetry enabled</label><label>Capture mode <select name="captureMode"><option>MetadataOnly</option><option>ContentHash</option><option>BoundedPreview</option></select></label><label>Maximum captured bytes <input type="number" name="maximumCapturedBytes" min="0" max="4096" value="256"></label><label>Included paths, one per line <textarea name="includedPaths">\\Software\\OpenSecurityPlatform\\Sprint4</textarea></label><label>Excluded paths, one per line <textarea name="excludedPaths"></textarea></label><p id="registry-policy-error" role="alert" tabindex="-1"></p><button>Save immutable version</button></fieldset></form>`;
  try {
    const x = (
      (await api("/api/v1/registry-telemetry/policies")).data || []
    ).find((v) => v.id === id);
    if (!x)
      return state(
        "Registry policy unavailable",
        "The policy is not in this tenant.",
      );
    return `<a href="#/registry-policies">← Back</a><div class="detail-head"><h2>${esc(x.name)}</h2><span class="badge">Version ${x.version}</span></div><div class="panels"><article><h3>Collection</h3><dl><dt>Enabled</dt><dd>${x.policy.enabled ? "Yes" : "No"}</dd><dt>Collector</dt><dd>${esc(x.policy.collectorSource)}</dd><dt>Capture</dt><dd>${esc(x.policy.captureMode)}</dd><dt>Maximum captured bytes</dt><dd>${x.policy.maximumCapturedBytes}</dd><dt>Hashing</dt><dd>${x.policy.contentHashingEnabled ? "Yes" : "No"}</dd></dl></article><article><h3>Exclusions</h3>${(x.policy.exclusionRules || []).length ? `<ul>${x.policy.exclusionRules.map((r) => `<li>${esc(r.category)}: <code>${esc(r.pattern)}</code> (${r.matchCount || 0} matches)</li>`).join("")}</ul>` : '<p class="muted">No exclusions.</p>'}</article></div>`;
  } catch (e) {
    return state("Registry policy unavailable", e.message);
  }
}
async function saveRegistryPolicy(e) {
  e.preventDefault();
  const f = new FormData(e.target),
    lines = (n) =>
      String(f.get(n) || "")
        .split(/\r?\n/)
        .map((x) => x.trim())
        .filter(Boolean);
  try {
    const result = await api("/api/v1/registry-telemetry/policies", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: f.get("name"),
        policy: {
          enabled: f.has("enabled"),
          captureMode: f.get("captureMode"),
          maximumCapturedBytes: Number(f.get("maximumCapturedBytes")),
          includedPaths: lines("includedPaths"),
          excludedPaths: lines("excludedPaths"),
          collectorSource: "windows.etw-registry",
        },
      }),
    });
    location.hash = `#/registry-policies/${result.data.id}`;
  } catch (error) {
    const out = document.querySelector("#registry-policy-error");
    out.textContent = error.message;
    out.focus();
  }
}
async function registryPolicyEditorPage(id) {
  if (id === "new")
    return `<form id="registry-policy-editor" class="admin-grid"><fieldset><legend>Registry policy</legend><label>Name <input name="name" required maxlength="100"></label><label><input type="checkbox" name="enabled" checked> Registry telemetry enabled</label><label>Capture mode <select name="captureMode"><option>MetadataOnly</option><option>None</option><option>ContentHash</option><option>BoundedPreview</option><option>ApprovedFullContent</option></select></label><label>Maximum captured bytes <input type="number" name="maximumCapturedBytes" min="0" max="4096" value="256"></label><label>Included paths, one per line <textarea name="includedPaths">\\Software\\OpenSecurityPlatform\\Sprint4</textarea></label><label>Excluded paths, one per line <textarea name="excludedPaths"></textarea></label><label>Capture-approved full paths, one per line <textarea name="allowedCapturePaths" aria-describedby="capture-help"></textarea></label><p id="capture-help" class="muted">Required for hashing or content capture. Protected paths are always rejected.</p><label>Included value types, one per line <textarea name="includedValueTypes">String</textarea></label><label>Redaction text patterns, one per line <textarea name="redactionPatterns"></textarea></label><p id="registry-policy-error" role="alert" tabindex="-1"></p><button>Save immutable version</button></fieldset></form>`;
  try {
    const x = (
      (await api("/api/v1/registry-telemetry/policies")).data || []
    ).find((v) => v.id === id);
    if (!x)
      return state(
        "Registry policy unavailable",
        "The policy is not in this tenant.",
      );
    const rules = x.policy.exclusionRules || [];
    return `<a href="#/registry-policies">← Back</a><div class="detail-head"><h2>${esc(x.name)}</h2><span class="badge">Version ${x.version}</span></div><div class="panels"><article><h3>Collection</h3><dl><dt>Enabled</dt><dd>${x.policy.enabled ? "Yes" : "No"}</dd><dt>Collector</dt><dd>${esc(x.policy.collectorSource)}</dd><dt>Capture</dt><dd>${esc(x.policy.captureMode)}</dd><dt>Maximum captured bytes</dt><dd>${x.policy.maximumCapturedBytes}</dd><dt>Hashing</dt><dd>${x.policy.contentHashingEnabled ? "Yes" : "No"}</dd></dl><form id="registry-policy-assign"><label>Endpoint ID <input name="endpointId" required pattern="[0-9a-fA-F-]{36}" aria-describedby="assign-help"></label><p id="assign-help" class="muted">Assignment is tenant-bound and acknowledged by the agent.</p><button>Assign policy</button><p role="status" aria-live="polite"></p></form></article><article><h3>Audited exclusions</h3>${rules.length ? `<div class="table-wrap"><table><thead><tr><th>Category</th><th>Pattern</th><th>Reason</th><th>Enabled</th><th>Action</th></tr></thead><tbody>${rules.map((r) => `<tr><td>${esc(r.category)}</td><td><code>${esc(r.pattern)}</code></td><td>${esc(r.reason || "Not supplied")}</td><td>${r.enabled ? "Yes" : "No"}</td><td><button type="button" class="registry-exclusion-delete" data-rule="${r.id}">Delete in new version</button></td></tr>`).join("")}</tbody></table></div>` : '<p class="muted">No exclusions.</p>'}<form id="registry-exclusion-editor"><fieldset><legend>Add exclusion in a new immutable version</legend><label>Category <select name="category"><option value="key-exact">Exact key</option><option value="key-prefix">Key prefix</option><option value="value">Value pattern</option><option value="hive">Hive</option><option value="process">Process</option><option value="user">User</option><option value="value-type">Value type</option></select></label><label>Pattern <input name="pattern" required maxlength="512"></label><label>Reason <input name="reason" required maxlength="256"></label><label><input type="checkbox" name="enabled" checked> Enabled</label><button>Add exclusion</button><p id="registry-exclusion-error" role="alert" tabindex="-1"></p></fieldset></form></article></div>`;
  } catch (e) {
    return state("Registry policy unavailable", e.message);
  }
}
async function saveRegistryPolicyEditor(e) {
  e.preventDefault();
  const f = new FormData(e.target),
    lines = (n) =>
      String(f.get(n) || "")
        .split(/\r?\n/)
        .map((x) => x.trim())
        .filter(Boolean);
  try {
    const result = await api("/api/v1/registry-telemetry/policies", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: f.get("name"),
        policy: {
          enabled: f.has("enabled"),
          captureMode: f.get("captureMode"),
          maximumCapturedBytes: Number(f.get("maximumCapturedBytes")),
          includedPaths: lines("includedPaths"),
          excludedPaths: lines("excludedPaths"),
          allowedCapturePaths: lines("allowedCapturePaths"),
          includedValueTypes: lines("includedValueTypes"),
          redactionPatterns: lines("redactionPatterns"),
          collectorSource: "windows.etw-registry",
        },
      }),
    });
    location.hash = `#/registry-policies/${result.data.id}`;
  } catch (error) {
    const out = document.querySelector("#registry-policy-error");
    out.textContent = error.message;
    out.focus();
  }
}
async function saveRegistryExclusion(e, id) {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    const result = await api(
      `/api/v1/registry-telemetry/policies/${id}/exclusions`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          category: f.get("category"),
          pattern: f.get("pattern"),
          reason: f.get("reason"),
          enabled: f.has("enabled"),
        }),
      },
    );
    location.hash = `#/registry-policies/${result.data.id}`;
  } catch (error) {
    const out = document.querySelector("#registry-exclusion-error");
    out.textContent = error.message;
    out.focus();
  }
}
async function deleteRegistryExclusion(id, ruleId) {
  const result = await api(
    `/api/v1/registry-telemetry/policies/${id}/exclusions/${ruleId}`,
    { method: "DELETE" },
  );
  location.hash = `#/registry-policies/${result.data.id}`;
}
async function assignRegistryPolicy(e, id) {
  e.preventDefault();
  const f = new FormData(e.target),
    out = e.target.querySelector('[role="status"]');
  try {
    await api(`/api/v1/registry-telemetry/policies/${id}:assign`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ endpointId: f.get("endpointId") }),
    });
    out.textContent =
      "Policy assignment accepted; agent acknowledgement pending.";
  } catch (error) {
    out.textContent = `Assignment failed: ${error.message}`;
  }
}
function fileEventTable(items) {
  if (!items.length)
    return '<p class="muted">No file activity in this range.</p>';
  return `<div class="table-wrap"><table><thead><tr><th>Observed</th><th>Operation</th><th>Path</th><th>Process</th><th>User</th><th>Quality</th></tr></thead><tbody>${items.map((x) => `<tr><td>${new Date(x.observedAt || x.lastObserved).toLocaleString()}</td><td>${esc(x.kind || x.state || "Unknown")}</td><td><code>${esc(x.path || x.currentPath || "Unavailable")}</code></td><td>${esc(x.process?.path || x.latestProcess?.path || "Unavailable")}</td><td>${esc(x.userName || "Unavailable")}</td><td>${esc((x.dataQualityFlags || []).join(", ") || "No flags")}</td></tr>`).join("")}</tbody></table></div>`;
}
function fileEntityTable(items) {
  if (!items.length)
    return '<p class="muted">No file entities match these filters.</p>';
  return `<div class="table-wrap"><table><thead><tr><th>Last observed</th><th>State</th><th>Path</th><th>Endpoint</th><th>Process</th><th>Size</th><th>Hash</th><th>Quality</th></tr></thead><tbody>${items.map((x) => `<tr><td>${new Date(x.lastObserved).toLocaleString()}</td><td>${esc(x.state)}</td><td><a href="#/files/${x.endpointId}/${x.fileEntityId}"><code>${esc(x.currentPath)}</code></a></td><td><code>${esc(x.endpointId)}</code></td><td>${esc(x.latestProcess?.path || "Unavailable")}</td><td>${x.metadata?.size ?? "Unavailable"}</td><td>${esc(x.hash?.state || "Unavailable")}</td><td>${esc((x.dataQualityFlags || []).join(", ") || "No flags")}</td></tr>`).join("")}</tbody></table></div>`;
}
async function fileSearch() {
  try {
    const q = new URLSearchParams(location.hash.split("?")[1] || ""),
      b = await api(`/api/v1/files?${q}`);
    return `<form id="file-search" class="toolbar"><label>Path <input name="path" value="${esc(q.get("path") || "")}"></label><label>Filename <input name="fileName" value="${esc(q.get("fileName") || "")}"></label><label>Extension <input name="extension" value="${esc(q.get("extension") || "")}"></label><label>Operation <select name="operation"><option value="">Any</option>${["Created", "Modified", "Deleted", "Renamed", "Moved", "MetadataChanged"].map((v) => `<option ${q.get("operation") === v ? "selected" : ""}>${v}</option>`).join("")}</select></label><label>User <input name="user" value="${esc(q.get("user") || "")}"></label><label>Process <input name="process" value="${esc(q.get("process") || "")}"></label><label>SHA-256 <input name="sha256" minlength="64" maxlength="64" value="${esc(q.get("sha256") || "")}"></label><button>Search</button><button type="button" id="file-export">Export JSONL</button></form><p id="file-export-status" role="status" aria-live="polite"></p>${fileEntityTable(b.data.items || [])}${b.data.nextCursor ? `<button id="file-next" data-cursor="${esc(b.data.nextCursor)}">Next page</button>` : ""}`;
  } catch (e) {
    return state("File search unavailable", e.message);
  }
}
async function fileDetail(endpointId, entityId) {
  try {
    const [d, h] = await Promise.all([
        api(`/api/v1/endpoints/${endpointId}/files/${entityId}`),
        api(`/api/v1/endpoints/${endpointId}/files/${entityId}/history`),
      ]),
      x = d.data;
    return `<a href="#/files">← Back to file activity</a><div class="detail-head"><div><h2>${esc(x.currentPath || "Unknown file")}</h2><p class="muted">${esc(x.fileEntityId)}</p></div><span class="badge">${esc(x.state)}</span></div><div class="panels"><article><h3>Identity</h3><dl><dt>Native identity</dt><dd><code>${esc(JSON.stringify(x.nativeIdentity))}</code></dd><dt>First observed</dt><dd>${new Date(x.firstObserved).toLocaleString()}</dd><dt>Last observed</dt><dd>${new Date(x.lastObserved).toLocaleString()}</dd><dt>Previous paths</dt><dd>${(x.previousPaths || []).map(esc).join("<br>") || "Unavailable"}</dd></dl></article><article><h3>Metadata</h3><dl><dt>Size</dt><dd>${x.metadata?.size ?? "Unavailable"}</dd><dt>Owner</dt><dd>${esc(x.metadata?.owner || "Unavailable")}</dd><dt>Permissions</dt><dd>${esc(x.metadata?.permissions || "Unavailable")}</dd><dt>SHA-256</dt><dd><code>${esc(x.hash?.sha256 || "Unavailable")}</code></dd><dt>Hash state</dt><dd>${esc(x.hash?.state || "Unavailable")}</dd></dl></article><article><h3>Provenance</h3><dl><dt>Collector</dt><dd>${esc(x.collectorType)} ${esc(x.collectorVersion)}</dd><dt>Process</dt><dd>${esc(x.latestProcess?.path || "Unavailable")}</dd><dt>User</dt><dd>${esc(x.userName || "Unavailable")}</dd><dt>Confidence</dt><dd>${esc(x.sourceConfidence)}</dd><dt>Quality</dt><dd>${esc((x.dataQualityFlags || []).join(", ") || "No flags")}</dd></dl></article></div><section><h2>File history</h2>${fileEventTable(h.data.items || [])}</section>`;
  } catch (e) {
    return state("File details unavailable", e.message);
  }
}
async function hydrateFileResponse(endpointId, entityId) {
  try {
    const [previewResult, historyResult] = await Promise.all([
        api(`/api/v1/endpoints/${endpointId}/files/${entityId}/response-preview`),
        api(`/api/v1/endpoints/${endpointId}/file-response-history`),
      ]),
      preview = previewResult.data,
      history = (historyResult.data.items || []).filter((a) => a.sourceEntityId === entityId);
    document.querySelector("#content")?.insertAdjacentHTML("beforeend", `<section aria-labelledby="file-response-title"><div class="detail-head"><div><h2 id="file-response-title">Safe file response</h2><p>Signed actions pin the canonical entity, native volume/file identity, size, hash, endpoint, and installation.</p></div><span class="badge">${preview.protectedPath ? "Protected" : "Preview verified"}</span></div><div class="panels"><article><h3>Exact target preview</h3><dl><dt>Path</dt><dd><code>${esc(preview.target.canonicalPath)}</code></dd><dt>Entity</dt><dd><code>${esc(preview.target.fileEntityId)}</code></dd><dt>Size</dt><dd>${preview.target.size}</dd><dt>SHA-256</dt><dd><code>${esc(preview.target.sha256 || "Endpoint verification required")}</code></dd><dt>Process relationships</dt><dd>${preview.processRelationshipCount}</dd><dt>File-in-use state</dt><dd>${esc(preview.fileInUseState)}</dd></dl></article><article><h3>Analyst controls</h3><p class="containment-warning"><strong>Warning:</strong> permanent deletion is normal filesystem deletion, not secure erase. Restore never overwrites an occupied destination.</p><button id="file-response-open" ${preview.protectedPath ? "disabled" : ""}>Open response dialog</button><p id="file-response-status" role="status" aria-live="assertive" tabindex="-1"></p></article></div><dialog id="file-response-dialog" aria-labelledby="file-response-dialog-title"><form id="file-response-form"><h2 id="file-response-dialog-title">Confirm exact file response</h2><p><code>${esc(entityId)}</code></p><label>Action <select name="action"><option value="quarantine">Quarantine exact file (reversible)</option><option value="delete">Permanently delete exact file</option></select></label><label>Required reason <textarea name="reason" required maxlength="1024"></textarea></label><p>The immutable target cannot be edited. A separate approver must approve the exact parameter hash.</p><div class="danger"><button type="submit">Request structured action</button><button type="button" id="file-response-close">Cancel</button></div></form></dialog><h3>Immutable file-response history</h3>${history.length ? `<ol class="timeline">${history.map((a) => `<li><time>${new Date(a.requestedAt).toLocaleString()}</time> <a href="#/response-actions/${a.responseActionId}">${esc(a.actionType)}</a> — ${esc(a.state)} by ${esc(a.analystId)}</li>`).join("")}</ol>` : '<p class="muted">No file response has been requested for this entity.</p>'}</section>`);
    const dialog = document.querySelector("#file-response-dialog"), opener = document.querySelector("#file-response-open");
    opener?.addEventListener("click", () => dialog.showModal());
    document.querySelector("#file-response-close")?.addEventListener("click", () => { dialog.close(); opener?.focus(); });
    document.querySelector("#file-response-form")?.addEventListener("submit", (event) => submitFileResponse(event, endpointId, entityId));
  } catch (error) {
    document.querySelector("#content")?.insertAdjacentHTML("beforeend", `<section>${state("File response unavailable", error.message)}</section>`);
  }
}
async function submitFileResponse(event, endpointId, entityId) {
  event.preventDefault(); const form = new FormData(event.currentTarget), status = document.querySelector("#file-response-status"), query = new URLSearchParams(location.hash.split("?")[1] || "");
  try {
    const body = { reason: form.get("reason"), sourceAlertId: query.get("alertId") || null, sourceIncidentId: query.get("incidentId") || null, sourceEntityId: entityId };
    const result = await api(`/api/v1/endpoints/${endpointId}/files/${entityId}:${form.get("action")}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    status.textContent = `Action ${result.data.action.responseActionId} is ${result.data.action.state}.`; document.querySelector("#file-response-dialog")?.close(); status.focus();
  } catch (error) { status.textContent = error.message; status.focus(); }
}
async function quarantineList() {
  try {
    const items = (await api("/api/v1/quarantines")).data.items || [];
    return items.length ? `<div class="table-wrap"><table><thead><tr><th>Quarantined</th><th>Original path</th><th>Endpoint</th><th>Identity</th><th>Hash</th><th>State</th><th>Retention</th><th>Action</th></tr></thead><tbody>${items.map(({record, action}) => `<tr><td>${new Date(record.quarantinedAt).toLocaleString()}</td><td><code>${esc(record.originalPath)}</code></td><td><code>${esc(record.endpointId)}</code></td><td><code>${esc(record.fileEntityId)}</code></td><td><code>${esc(record.sha256)}</code></td><td>${esc(record.state)}</td><td>${new Date(record.retainUntil).toLocaleString()}</td><td><a href="#/quarantines/${record.quarantineId}">Inspect</a> · <a href="#/response-actions/${action.responseActionId}">Audit</a></td></tr>`).join("")}</tbody></table></div>` : state("No quarantined files", "No tenant-bound quarantine records are available.");
  } catch (error) { return state("Quarantine unavailable", error.message); }
}
async function quarantineDetail(id) {
  try {
    const {record, action} = (await api(`/api/v1/quarantines/${id}`)).data;
    return `<a href="#/quarantines">← Quarantine records</a><div class="detail-head"><div><h2>${esc(record.originalFileName)}</h2><p><code>${esc(record.quarantineId)}</code></p></div><span class="badge">${esc(record.state)}</span></div><div class="panels"><article><h3>Original identity</h3><dl><dt>Path</dt><dd><code>${esc(record.originalPath)}</code></dd><dt>File entity</dt><dd><code>${esc(record.fileEntityId)}</code></dd><dt>Native identity</dt><dd><code>${esc(JSON.stringify(record.originalNativeIdentity))}</code></dd><dt>Size</dt><dd>${record.originalSize}</dd><dt>SHA-256</dt><dd><code>${esc(record.sha256)}</code></dd></dl></article><article><h3>Protection and lifecycle</h3><dl><dt>Storage</dt><dd>${esc(record.storageLocation)}</dd><dt>Integrity</dt><dd>${esc(record.integrityState)}</dd><dt>Race state</dt><dd>${esc(record.raceState)}</dd><dt>Metadata</dt><dd>${esc(record.metadataState)}</dd><dt>Retain until</dt><dd>${new Date(record.retainUntil).toLocaleString()}</dd></dl></article><article><h3>Controls</h3><p>Restore is explicit, hash-verified, and never overwrites an occupied path.</p>${record.restoreEligible ? `<form id="quarantine-restore"><label>Required reason <textarea name="reason" required maxlength="1024"></textarea></label><button>Request restore</button></form>` : '<p class="muted">This record is not restore eligible.</p>'}<p><a href="#/response-actions/${action.responseActionId}">Open audit and evidence download</a></p><p id="quarantine-status" role="status" aria-live="assertive" tabindex="-1"></p></article></div><section><h2>Immutable action audit</h2><ol class="timeline">${action.auditHistory.map((event) => `<li><time>${new Date(event.occurredAt).toLocaleString()}</time> ${esc(event.action)} by ${esc(event.actor)} — ${esc(event.reason)}</li>`).join("")}</ol></section>`;
  } catch (error) { return state("Quarantine record unavailable", error.message); }
}
async function restoreQuarantine(event, id) {
  event.preventDefault(); const out = document.querySelector("#quarantine-status");
  try { const result = await api(`/api/v1/quarantines/${id}:restore`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(Object.fromEntries(new FormData(event.currentTarget))) }); out.textContent = `Restore action ${result.data.action.responseActionId} is ${result.data.action.state}.`; out.focus(); }
  catch (error) { out.textContent = error.message; out.focus(); }
}
async function exportFiles() {
  const s = document.querySelector("#file-export-status");
  s.textContent = "Export pending…";
  try {
    const r = await fetch(
      `/api/v1/files:export?${new URLSearchParams(location.hash.split("?")[1] || "")}`,
      { headers: auth() },
    );
    if (!r.ok) throw Error(`status ${r.status}`);
    const u = URL.createObjectURL(await r.blob()),
      a = document.createElement("a");
    a.href = u;
    a.download = "file-telemetry.jsonl";
    a.click();
    URL.revokeObjectURL(u);
    s.textContent = "Export complete.";
  } catch (e) {
    s.textContent = `Export failed: ${e.message}`;
  }
}
async function filePolicyList() {
  try {
    const items = (await api("/api/v1/file-telemetry/policies")).data || [],
      latest = [...new Map(items.map((x) => [x.name, x])).values()];
    return `<div class="toolbar"><p>Immutable, server-validated file collection policies.</p><a class="button" href="#/file-policies/new">Create policy</a></div>${latest.length ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>ID</th><th>Version</th><th>Collector</th><th>Enabled</th><th>Hashing</th><th>Exclusions</th><th>Audit</th></tr></thead><tbody>${latest.map((x) => `<tr><td><a href="#/file-policies/${x.id}">${esc(x.name)}</a></td><td><code>${esc(x.id)}</code></td><td>${x.version}</td><td>${esc(x.policy.collectorSource)}</td><td>${x.policy.enabled ? "On" : "Off"}</td><td>${x.policy.hashingEnabled ? "On" : "Off"}</td><td>${(x.policy.exclusionRules || []).length}</td><td>${new Date(x.createdAt).toLocaleString()} · ${esc(x.createdBy)}</td></tr>`).join("")}</tbody></table></div>` : state("No file policies", "Create a policy to replace the safe implicit default.")}`;
  } catch (e) {
    return state("File policies unavailable", e.message);
  }
}
function fileExclusionRow(x = {}) {
  return `<fieldset class="file-exclusion-row"><legend>File exclusion</legend><input type="hidden" name="ruleId" value="${x.id || crypto.randomUUID()}"><label>Category <select name="ruleCategory">${["path", "directory", "filename", "extension", "process", "user", "container", "filesystem"].map((v) => `<option ${x.category === v ? "selected" : ""}>${v}</option>`).join("")}</select></label><label>Pattern <input name="rulePattern" maxlength="256" value="${esc(x.pattern || "")}" required aria-describedby="exclusion-warning"></label><label><input type="checkbox" name="ruleEnabled" ${x.enabled !== false ? "checked" : ""}> Enabled</label><button type="button" onclick="this.closest('fieldset').remove()">Remove</button></fieldset>`;
}
function filePolicyFields(p = {}) {
  const t = (n, l, v) =>
    `<label><input type="checkbox" name="${n}" ${v ? "checked" : ""}> ${l}</label>`;
  return `<fieldset><legend>Operations</legend>${t("enabled", "File telemetry enabled", p.enabled ?? true)}${t("createEnabled", "Create", p.createEnabled ?? true)}${t("modifyEnabled", "Modify", p.modifyEnabled ?? true)}${t("deleteEnabled", "Delete", p.deleteEnabled ?? true)}${t("renameEnabled", "Rename", p.renameEnabled ?? true)}${t("moveEnabled", "Move", p.moveEnabled ?? true)}${t("openEnabled", "Open", p.openEnabled)}${t("metadataChangeEnabled", "Metadata", p.metadataChangeEnabled ?? true)}</fieldset><fieldset><legend>Collector and enrichment</legend><label>Collector <select name="collectorSource">${["auto", "windows.etw", "linux.falco-json"].map((v) => `<option ${p.collectorSource === v ? "selected" : ""}>${v}</option>`).join("")}</select></label>${t("hashingEnabled", "SHA-256 hashing", p.hashingEnabled)}${t("signatureEnabled", "Signature verification", p.signatureEnabled)}<label>Maximum hash bytes <input name="maximumHashBytes" type="number" min="1" value="${p.maximumHashBytes || 16777216}" required></label><label>Hashes per minute <input name="hashesPerMinute" type="number" min="1" value="${p.hashesPerMinute || 30}" required></label></fieldset><fieldset><legend>Paths and transport</legend><label>Included paths, one per line <textarea name="includedPaths">${esc((p.includedPaths || []).join("\n"))}</textarea></label><label>Excluded paths, one per line <textarea name="excludedPaths">${esc((p.excludedPaths || []).join("\n"))}</textarea></label><label>Included extensions <input name="includedExtensions" value="${esc((p.includedExtensions || []).join(","))}"></label><label>Excluded extensions <input name="excludedExtensions" value="${esc((p.excludedExtensions || []).join(","))}"></label><label>Queue bytes <input name="maximumQueueBytes" type="number" min="1048576" value="${p.maximumQueueBytes || 134217728}" required></label><label>Batch events <input name="maximumBatchEvents" type="number" min="1" max="1000" value="${p.maximumBatchEvents || 200}" required></label><label>Batch bytes <input name="maximumBatchBytes" type="number" min="1024" value="${p.maximumBatchBytes || 1048576}" required></label><label>Flush seconds <input name="flushSeconds" type="number" min="1" max="300" value="${p.flushSeconds || 5}" required></label>${t("networkShares", "Network shares", p.networkShares)}${t("temporaryDirectories", "Temporary directories", p.temporaryDirectories)}</fieldset>`;
}
async function filePolicyEditor(id) {
  try {
    const versions = id
        ? (await api("/api/v1/file-telemetry/policies")).data
        : [],
      source = versions.find((x) => x.id === id);
    return `<a href="${id ? `#/file-policies/${id}` : "#/file-policies"}">← Cancel</a><form id="file-policy-editor" class="admin-grid"><div><h2>${source ? "Create new version" : "Create file policy"}</h2><label>Name <input name="name" maxlength="120" value="${esc(source?.name || "")}" required></label>${filePolicyFields(source?.policy)}</div><fieldset><legend>Exclusions</legend><p id="exclusion-warning">Exclusions reduce evidence visibility. Match-all and unsupported rules are rejected by the server.</p><div id="file-exclusion-rows">${(source?.policy.exclusionRules || []).map(fileExclusionRow).join("")}</div><button type="button" id="add-file-exclusion">Add exclusion</button></fieldset><div><button>Validate and save</button> <a class="button" href="${id ? `#/file-policies/${id}` : "#/file-policies"}">Cancel</a><p id="file-policy-error" role="alert" tabindex="-1"></p></div></form>`;
  } catch (e) {
    return state("File policy editor unavailable", e.message);
  }
}
async function filePolicyDetail(id) {
  try {
    const [pb, eb] = await Promise.all([
        api("/api/v1/file-telemetry/policies"),
        api("/api/v1/endpoints?pageSize=100"),
      ]),
      selected = pb.data.find((x) => x.id === id);
    if (!selected)
      return state(
        "Policy not found",
        "This policy is unavailable in the current tenant.",
      );
    const history = pb.data
        .filter((x) => x.name === selected.name)
        .sort((a, b) => b.version - a.version),
      effective = await Promise.all(
        (eb.data.items || []).map(async (endpoint) => ({
          endpoint,
          value: (await api(`/api/v1/endpoints/${endpoint.id}/file-policy`))
            .data,
        })),
      );
    return `<a href="#/file-policies">← File policies</a><div class="detail-head"><div><h2>${esc(selected.name)}</h2><p><code>${esc(selected.id)}</code></p></div><span class="badge">Version ${selected.version}</span></div><div class="panels"><article><h3>Effective settings</h3><dl><dt>Collector</dt><dd>${esc(selected.policy.collectorSource)}</dd><dt>Operations</dt><dd>${["create", "modify", "delete", "rename", "move", "open", "metadataChange"].filter((v) => selected.policy[v + "Enabled"]).join(", ")}</dd><dt>Hashing</dt><dd>${selected.policy.hashingEnabled ? `On, ${selected.policy.maximumHashBytes} bytes, ${selected.policy.hashesPerMinute}/min` : "Off"}</dd><dt>Queue/batch</dt><dd>${selected.policy.maximumQueueBytes} / ${selected.policy.maximumBatchEvents} events</dd><dt>Included paths</dt><dd>${esc((selected.policy.includedPaths || []).join(", ") || "All policy-approved paths")}</dd></dl><a class="button" href="#/file-policies/${id}/edit">Create new version</a></article><article><h3>Assignments, acknowledgment and drift</h3>${effective.map((x) => `<p>${esc(x.endpoint.hostname)} — ${x.value.policy.id === selected.id ? (x.value.drift ? "Drift" : "Applied v" + x.value.appliedVersion) : "Different policy"}</p>`).join("")}<form id="file-policy-assign"><label>Endpoint <select name="endpointId" required><option value="">Select</option>${(eb.data.items || []).map((x) => `<option value="${x.id}">${esc(x.hostname)}</option>`).join("")}</select></label><button>Assign</button></form></article></div><section><h2>Exclusions</h2>${(selected.policy.exclusionRules || []).length ? `<table><thead><tr><th>ID</th><th>Category</th><th>Pattern</th><th>Enabled</th><th>Validation</th></tr></thead><tbody>${selected.policy.exclusionRules.map((x) => `<tr><td><code>${x.id}</code></td><td>${esc(x.category)}</td><td><code>${esc(x.pattern)}</code></td><td>${x.enabled ? "On" : "Off"}</td><td>Server validated</td></tr>`).join("")}</tbody></table>` : '<p class="muted">No exclusions.</p>'}</section><section><h2>Version and audit history</h2><table><thead><tr><th>Version</th><th>Created</th><th>Creator</th><th>Status</th><th>Action</th></tr></thead><tbody>${history.map((x) => `<tr><td>${x.version}</td><td>${new Date(x.createdAt).toLocaleString()}</td><td>${esc(x.createdBy)}</td><td>${esc(x.status)}</td><td><button class="file-rollback" data-id="${x.id}" data-version="${x.version}">Roll back</button></td></tr>`).join("")}</tbody></table></section><dialog id="file-rollback-dialog" aria-labelledby="file-rollback-title"><h2 id="file-rollback-title">Confirm file-policy rollback</h2><p>Rollback creates a new immutable version.</p><button id="file-rollback-confirm">Confirm rollback</button><button id="file-rollback-cancel">Cancel</button><p id="file-rollback-status" role="status" aria-live="polite"></p></dialog>`;
  } catch (e) {
    return state("File policy details unavailable", e.message);
  }
}
const lines = (v) =>
  (v || "")
    .split(/[\n,]/)
    .map((x) => x.trim())
    .filter(Boolean);
async function saveFilePolicy(e) {
  e.preventDefault();
  const f = new FormData(e.target),
    rules = [...e.target.querySelectorAll(".file-exclusion-row")].map((r) => ({
      id: r.querySelector('[name="ruleId"]').value,
      category: r.querySelector('[name="ruleCategory"]').value,
      pattern: r.querySelector('[name="rulePattern"]').value.trim(),
      enabled: r.querySelector('[name="ruleEnabled"]').checked,
    })),
    broad = rules.some(
      (x) =>
        x.pattern.startsWith("*") || x.pattern === "/" || x.pattern === "\\",
    );
  if (
    broad &&
    !confirm(
      "This broad exclusion can substantially reduce visibility. Continue to server validation?",
    )
  )
    return;
  const policy = {
    enabled: f.has("enabled"),
    createEnabled: f.has("createEnabled"),
    modifyEnabled: f.has("modifyEnabled"),
    deleteEnabled: f.has("deleteEnabled"),
    renameEnabled: f.has("renameEnabled"),
    moveEnabled: f.has("moveEnabled"),
    openEnabled: f.has("openEnabled"),
    metadataChangeEnabled: f.has("metadataChangeEnabled"),
    hashingEnabled: f.has("hashingEnabled"),
    signatureEnabled: f.has("signatureEnabled"),
    maximumHashBytes: Number(f.get("maximumHashBytes")),
    hashesPerMinute: Number(f.get("hashesPerMinute")),
    includedPaths: lines(f.get("includedPaths")),
    excludedPaths: lines(f.get("excludedPaths")),
    includedExtensions: lines(f.get("includedExtensions")),
    excludedExtensions: lines(f.get("excludedExtensions")),
    maximumQueueBytes: Number(f.get("maximumQueueBytes")),
    maximumBatchEvents: Number(f.get("maximumBatchEvents")),
    maximumBatchBytes: Number(f.get("maximumBatchBytes")),
    flushSeconds: Number(f.get("flushSeconds")),
    collectorSource: f.get("collectorSource"),
    networkShares: f.has("networkShares"),
    temporaryDirectories: f.has("temporaryDirectories"),
    exclusionRules: rules,
  };
  const error = document.querySelector("#file-policy-error");
  try {
    const result = await api("/api/v1/file-telemetry/policies", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: f.get("name").trim(), policy }),
    });
    location.hash = `#/file-policies/${result.data.id}`;
  } catch (ex) {
    error.textContent = ex.message;
    error.focus();
  }
}
async function assignFilePolicy(e, id) {
  e.preventDefault();
  await api(`/api/v1/file-telemetry/policies/${id}:assign`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      endpointId: new FormData(e.target).get("endpointId"),
    }),
  });
  route();
}
function openFileRollback(button) {
  const d = document.querySelector("#file-rollback-dialog");
  d.dataset.id = button.dataset.id;
  d.dataset.version = button.dataset.version;
  d._trigger = button;
  d.showModal();
  document.querySelector("#file-rollback-confirm").focus();
}
async function executeFileRollback() {
  const d = document.querySelector("#file-rollback-dialog"),
    s = document.querySelector("#file-rollback-status");
  s.textContent = "Rollback running…";
  try {
    const b = await api(
      `/api/v1/file-telemetry/policies/${d.dataset.id}:rollback`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ version: Number(d.dataset.version) }),
      },
    );
    s.textContent = `Rollback created version ${b.data.version}.`;
    setTimeout(() => {
      d.close();
      location.hash = `#/file-policies/${b.data.id}`;
    }, 400);
  } catch (e) {
    s.textContent = `Rollback failed: ${e.message}`;
  }
}

function policySettings(p = {}) {
  const toggle = (name, label, value = false) =>
    `<label><input type="checkbox" name="${name}" ${value ? "checked" : ""}> ${label}</label>`;
  return `<fieldset><legend>Collection</legend>${toggle("telemetryEnabled", "Enable process telemetry", p.telemetryEnabled ?? true)}${toggle("startEnabled", "Collect starts", p.startEnabled ?? true)}${toggle("exitEnabled", "Collect exits", p.exitEnabled ?? true)}${toggle("commandLineEnabled", "Collect command lines", p.commandLineEnabled ?? true)}${toggle("userEnabled", "Collect user identity", p.userEnabled ?? true)}${toggle("hashingEnabled", "Hash executables", p.hashingEnabled)}${toggle("signatureEnabled", "Verify signatures", p.signatureEnabled)}<label>Collector source <select name="collectorSource">${["auto", "windows.etw", "linux.falco-json", "linux.procfs", "macos.endpoint-security"].map((x) => `<option ${p.collectorSource === x ? "selected" : ""}>${x}</option>`).join("")}</select></label></fieldset><fieldset><legend>Transport limits</legend><label>Queue bytes <input name="maximumQueueBytes" type="number" min="1048576" value="${p.maximumQueueBytes || 67108864}" required></label><label>Batch events <input name="maximumBatchEvents" type="number" min="1" max="1000" value="${p.maximumBatchEvents || 200}" required></label><label>Flush seconds <input name="flushSeconds" type="number" min="1" max="300" value="${p.flushSeconds || 5}" required></label></fieldset>`;
}
async function policyList() {
  try {
    const b = await api("/api/v1/process-telemetry/policies"),
      versions = b.data || [],
      latest = [...new Map(versions.map((x) => [x.name, x])).values()];
    if (!latest.length)
      return `${state("No process policies", "Create a policy to manage existing process telemetry.")}<a class="button" href="#/policies/new">Create policy</a>`;
    return `<div class="toolbar"><label>Search <input id="policy-filter" type="search"></label><a class="button" href="#/policies/new">Create policy</a></div><div class="table-wrap"><table id="policy-table"><thead><tr><th>Name</th><th>ID</th><th>Version</th><th>Source</th><th>Enabled</th><th>Starts</th><th>Exits</th><th>Hashing</th><th>Signatures</th><th>Updated</th><th>Author</th><th>Status</th></tr></thead><tbody>${latest.map((x) => `<tr data-search="${esc(x.name).toLowerCase()}"><td><a href="#/policies/${x.id}">${esc(x.name)}</a></td><td><code>${esc(x.id)}</code></td><td>${x.version}</td><td>${esc(x.policy.collectorSource)}</td><td>${x.policy.telemetryEnabled ? "On" : "Off"}</td><td>${x.policy.startEnabled ? "On" : "Off"}</td><td>${x.policy.exitEnabled ? "On" : "Off"}</td><td>${x.policy.hashingEnabled ? "On" : "Off"}</td><td>${x.policy.signatureEnabled ? "On" : "Off"}</td><td>${new Date(x.createdAt).toLocaleString()}</td><td>${esc(x.createdBy)}</td><td>${esc(x.status)}</td></tr>`).join("")}</tbody></table></div>`;
  } catch (e) {
    return state("Policies unavailable", e.message);
  }
}
async function policyDetail(id) {
  try {
    const [pb, eb] = await Promise.all([
      api("/api/v1/process-telemetry/policies"),
      api("/api/v1/endpoints?pageSize=100"),
    ]);
    const selected = pb.data.find((x) => x.id === id);
    if (!selected)
      return state(
        "Policy not found",
        "The policy is unavailable in this tenant.",
      );
    const history = pb.data
      .filter((x) => x.name === selected.name)
      .sort((a, b) => b.version - a.version);
    const assignments = await Promise.all(
      (eb.data.items || []).map(async (x) => {
        const e = await api(`/api/v1/endpoints/${x.id}/process-policy`);
        return { endpoint: x, effective: e.data };
      }),
    );
    const assigned = assignments.filter(
      (x) => x.effective.policy.name === selected.name,
    );
    const exclusions = selected.policy.exclusionRules || [];
    return `<a href="#/policies">← Back to policies</a><div class="detail-head"><div><h2>${esc(selected.name)}</h2><p class="muted">${esc(selected.id)}</p></div><span class="badge">Version ${selected.version}</span></div><div class="panels"><article><h3>Effective settings</h3><dl><dt>Collector</dt><dd>${esc(selected.policy.collectorSource)}</dd><dt>Telemetry</dt><dd>${selected.policy.telemetryEnabled ? "Enabled" : "Policy disabled"}</dd><dt>Queue limit</dt><dd>${selected.policy.maximumQueueBytes} bytes</dd><dt>Batch limit</dt><dd>${selected.policy.maximumBatchEvents} events</dd><dt>Command line</dt><dd>${selected.policy.commandLineEnabled ? "Enabled" : "Disabled"}</dd><dt>Metadata cache</dt><dd>${selected.policy.metadataCacheSeconds}s</dd></dl><a class="button" href="#/policies/${id}/edit">Create new version</a></article><article><h3>Assignments and acknowledgments</h3>${assigned.length ? `<ul>${assigned.map((x) => `<li>${esc(x.endpoint.hostname)} — ${x.effective.drift ? "Drift" : "Acknowledged v" + x.effective.appliedVersion}</li>`).join("")}</ul>` : '<p class="muted">No endpoints assigned.</p>'}<form id="policy-assign"><label>Assign endpoint <select name="endpointId" required><option value="">Select endpoint</option>${(eb.data.items || []).map((x) => `<option value="${x.id}">${esc(x.hostname)}</option>`).join("")}</select></label><button>Assign</button></form></article></div><section><h2>Exclusions</h2>${exclusions.length ? `<table><thead><tr><th>Rule ID</th><th>Category</th><th>Pattern</th><th>Enabled</th><th>Validation</th></tr></thead><tbody>${exclusions.map((x) => `<tr><td>${x.id}</td><td>${esc(x.category)}</td><td><code>${esc(x.pattern)}</code></td><td>${x.enabled ? "On" : "Off"}</td><td>Valid</td></tr>`).join("")}</tbody></table>` : '<p class="muted">No exclusions.</p>'}<a class="button" href="#/policies/${id}/edit#exclusions">Manage exclusions</a></section><section><h2>Version history</h2><table><thead><tr><th>Version</th><th>Created</th><th>Creator</th><th>Status</th><th>Rollback</th></tr></thead><tbody>${history.map((x) => `<tr><td>${x.version}</td><td>${new Date(x.createdAt).toLocaleString()}</td><td>${esc(x.createdBy)}</td><td>${esc(x.status)}</td><td><button onclick="rollbackPolicy('${x.id}',${x.version},'${esc(x.name)}',this)">Rollback to this version</button></td></tr>`).join("")}</tbody></table></section><dialog id="rollback-dialog" aria-labelledby="rollback-title"><h2 id="rollback-title">Confirm policy rollback</h2><p id="rollback-description">Rollback creates a new immutable version; it never overwrites history.</p><div class="danger"><button id="rollback-confirm">Create rollback version</button><button id="rollback-cancel">Cancel</button></div><p id="rollback-status" role="status" aria-live="polite"></p></dialog>`;
  } catch (e) {
    return state("Policy details unavailable", e.message);
  }
}
async function policyEditor(id) {
  try {
    const versions = id
        ? (await api("/api/v1/process-telemetry/policies")).data
        : [],
      source = versions.find((x) => x.id === id);
    return `<a href="${id ? `#/policies/${id}` : "#/policies"}">← Cancel</a><form id="policy-editor" class="admin-grid"><div><h2>${source ? "Create a new version" : "Create policy"}</h2><p>Saving creates an immutable version. Existing versions are not overwritten.</p><label>Name <input name="name" maxlength="120" value="${esc(source?.name || "")}" required></label>${policySettings(source?.policy)}</div><fieldset><legend>Process exclusions</legend><p>Excluded events reduce visibility. Match-all patterns are rejected.</p><div id="exclusion-rows">${(source?.policy.exclusionRules || []).map((x) => exclusionRow(x)).join("")}</div><button type="button" id="add-exclusion">Add exclusion</button></fieldset><div><button>Validate and save</button> <a class="button" href="${id ? `#/policies/${id}` : "#/policies"}">Cancel</a><p id="policy-error" role="alert"></p></div></form>`;
  } catch (e) {
    return state("Policy editor unavailable", e.message);
  }
}
function exclusionRow(x = {}) {
  return `<fieldset class="exclusion-row"><legend>Exclusion rule</legend><input type="hidden" name="ruleId" value="${x.id || crypto.randomUUID()}"><label>Category <select name="ruleCategory">${["name", "path", "user", "container"].map((v) => `<option ${x.category === v ? "selected" : ""}>${v}</option>`).join("")}</select></label><label>Pattern <input name="rulePattern" maxlength="256" value="${esc(x.pattern || "")}" required></label><label><input type="checkbox" name="ruleEnabled" ${x.enabled !== false ? "checked" : ""}> Enabled</label><button type="button" onclick="this.closest('fieldset').remove()">Remove</button></fieldset>`;
}
async function endpointAction(id, action) {
  const reason = prompt(`Reason to ${action} this endpoint:`);
  if (!reason) return;
  await api(`/api/v1/endpoints/${id}:${action}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reason }),
  });
  route();
}
async function administration() {
  try {
    const b = await api("/api/v1/enrollment-tokens"),
      rows = b.data.items
        .map(
          (x) =>
            `<tr><td>${esc(x.id)}</td><td>${new Date(x.expiresAt).toLocaleString()}</td><td>${x.uses}/${x.maximumUses}</td><td>${x.revoked ? "Revoked" : "Active"}</td><td><button ${x.revoked ? "disabled" : ""} onclick="revokeToken('${x.id}')">Revoke</button></td></tr>`,
        )
        .join("");
    return `<div class="admin-grid"><form id="token-create"><h2>Create enrollment token</h2><label>Expires <input name="expiresAt" type="datetime-local" required></label><label>Maximum uses <input name="maximumUses" type="number" min="1" max="100000" value="1" required></label><fieldset><legend>Allowed platforms</legend>${["windows", "linux", "macos"].map((x) => `<label><input type="checkbox" name="platform" value="${x}" checked> ${x}</label>`).join("")}</fieldset><button>Create one-time secret</button><div id="secret" role="status"></div></form><div class="table-wrap"><h2>Token metadata</h2><table><thead><tr><th>ID</th><th>Expires</th><th>Uses</th><th>Status</th><th>Action</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
  } catch (e) {
    return state("Token administration unavailable", e.message);
  }
}
async function createToken(e) {
  e.preventDefault();
  const f = new FormData(e.target),
    platforms = f.getAll("platform");
  if (!platforms.length) return;
  const b = await api("/api/v1/enrollment-tokens", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      expiresAt: new Date(f.get("expiresAt")).toISOString(),
      maximumUses: Number(f.get("maximumUses")),
      allowedPlatforms: platforms,
      endpointGroupId: null,
      policyId: null,
    }),
  });
  document.querySelector("#secret").innerHTML =
    `<strong>Copy this secret now.</strong><code>${esc(b.data.secret)}</code>`;
}
async function revokeToken(id) {
  if (confirm("Revoke this enrollment token?")) {
    await api(`/api/v1/enrollment-tokens/${id}:revoke`, { method: "POST" });
    route();
  }
}
async function savePolicy(e) {
  e.preventDefault();
  const f = new FormData(e.target),
    rows = [...e.target.querySelectorAll(".exclusion-row")];
  const exclusions = rows.map((r) => ({
    id: r.querySelector('[name="ruleId"]').value,
    category: r.querySelector('[name="ruleCategory"]').value,
    pattern: r.querySelector('[name="rulePattern"]').value.trim(),
    enabled: r.querySelector('[name="ruleEnabled"]').checked,
  }));
  const broad = exclusions.some(
    (x) => x.pattern.startsWith("*") || x.pattern.endsWith("*"),
  );
  if (
    broad &&
    !confirm(
      "This broad exclusion can reduce process visibility. Save it explicitly?",
    )
  )
    return;
  const policy = {
    telemetryEnabled: f.has("telemetryEnabled"),
    startEnabled: f.has("startEnabled"),
    exitEnabled: f.has("exitEnabled"),
    commandLineEnabled: f.has("commandLineEnabled"),
    userEnabled: f.has("userEnabled"),
    hashingEnabled: f.has("hashingEnabled"),
    signatureEnabled: f.has("signatureEnabled"),
    collectorSource: f.get("collectorSource"),
    maximumQueueBytes: Number(f.get("maximumQueueBytes")),
    maximumBatchEvents: Number(f.get("maximumBatchEvents")),
    flushSeconds: Number(f.get("flushSeconds")),
    exclusionRules: exclusions,
  };
  const error = document.querySelector("#policy-error");
  try {
    for (const rule of exclusions)
      await api("/api/v1/process-telemetry/exclusions:preview", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(rule),
      });
    const result = await api("/api/v1/process-telemetry/policies", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: f.get("name").trim(), policy }),
    });
    location.hash = `#/policies/${result.data.id}`;
  } catch (e) {
    error.textContent = e.message;
    error.focus();
  }
}
async function assignPolicy(e, id) {
  e.preventDefault();
  const endpointId = new FormData(e.target).get("endpointId");
  await api(`/api/v1/process-telemetry/policies/${id}:assign`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ endpointId }),
  });
  route();
}
function rollbackPolicy(id, version, name, trigger) {
  const dialog = document.querySelector("#rollback-dialog");
  dialog.dataset.id = id;
  dialog.dataset.version = version;
  dialog.dataset.name = name;
  dialog._trigger = trigger;
  dialog.showModal();
  document.querySelector("#rollback-confirm").focus();
}
async function executeRollback() {
  const dialog = document.querySelector("#rollback-dialog"),
    status = document.querySelector("#rollback-status");
  status.textContent = "Rollback running…";
  try {
    const b = await api(
      `/api/v1/process-telemetry/policies/${dialog.dataset.id}:rollback`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ version: Number(dialog.dataset.version) }),
      },
    );
    status.textContent = `Rollback succeeded. Created version ${b.data.version}; audit ${b.meta?.requestId || "recorded"}.`;
    setTimeout(() => {
      dialog.close();
      location.hash = `#/policies/${b.data.id}`;
    }, 500);
  } catch (e) {
    status.textContent = `Rollback failed: ${e.message}`;
  }
}
async function exportProcesses() {
  const status = document.querySelector("#export-status");
  status.textContent = "Export pending…";
  try {
    const r = await fetch("/api/v1/processes:export", { headers: auth() });
    if (!r.ok) throw Error(`Export failed with status ${r.status}.`);
    const blob = await r.blob(),
      url = URL.createObjectURL(blob),
      a = document.createElement("a");
    a.href = url;
    a.download = "process-export.jsonl";
    a.click();
    URL.revokeObjectURL(url);
    status.textContent = "Export complete.";
  } catch (e) {
    status.textContent = `Export failed: ${e.message}`;
  }
}
function operations() {
  return `<div class="panels"><article><h2>Projection rebuild</h2><p>Rebuilds the existing process projection and atomically switches its alias.</p><button id="projection-rebuild">Start rebuild</button><div id="rebuild-status" role="status" aria-live="polite"></div></article><article><h2>Export workflow</h2><p>Exports are available from Process search and remain tenant-scoped.</p><a class="button" href="#/processes">Open process export</a></article></div>`;
}
async function rebuildProjection() {
  const status = document.querySelector("#rebuild-status"),
    button = document.querySelector("#projection-rebuild");
  button.disabled = true;
  status.textContent = "Rebuild running…";
  try {
    const b = await api("/api/v1/processes/projections:rebuild", {
      method: "POST",
    });
    status.textContent = `Rebuild complete: ${b.data.documents} documents in ${b.data.indexName}.`;
  } catch (e) {
    status.textContent = `Rebuild failed: ${e.message}`;
  } finally {
    button.disabled = false;
  }
}
function enableTreeKeyboard() {
  const root = document.querySelector("ul.tree");
  if (!root) return;
  root.setAttribute("role", "tree");
  root.setAttribute("aria-label", "Process tree");
  const visible = () =>
    [...root.querySelectorAll('[role="treeitem"]')].filter(
      (x) => x.offsetParent !== null,
    );
  const items = visible();
  if (items[0]) items[0].tabIndex = 0;
  root.addEventListener("keydown", (e) => {
    const item = e.target.closest('[role="treeitem"]');
    if (!item) return;
    const all = visible(),
      index = all.indexOf(item);
    let next;
    if (e.key === "ArrowDown") next = all[index + 1];
    if (e.key === "ArrowUp") next = all[index - 1];
    if (e.key === "Home") next = all[0];
    if (e.key === "End") next = all.at(-1);
    if (e.key === "ArrowRight" && item.hasAttribute("aria-expanded")) {
      item.setAttribute("aria-expanded", "true");
      item.querySelector(':scope > [role="group"]')?.removeAttribute("hidden");
      next = item.querySelector(':scope > [role="group"] > [role="treeitem"]');
    }
    if (
      e.key === "ArrowLeft" &&
      item.getAttribute("aria-expanded") === "true"
    ) {
      item.setAttribute("aria-expanded", "false");
      item.querySelector(':scope > [role="group"]')?.setAttribute("hidden", "");
    } else if (e.key === "ArrowLeft")
      next = item.parentElement?.closest('[role="treeitem"]');
    if (next) {
      item.tabIndex = -1;
      next.tabIndex = 0;
      next.focus();
    }
    if (next || ["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key))
      e.preventDefault();
  });
}
function dnsTable(items) {
  if (!items.length)
    return '<p class="muted">No DNS evidence matches this bounded query.</p>';
  return `<div class="table-wrap"><table><thead><tr><th>Observed</th><th>State</th><th>Query</th><th>Type</th><th>Response</th><th>Answers</th><th>Resolver</th><th>Process</th><th>Quality</th></tr></thead><tbody>${items.map((x) => `<tr><td><a href="#/dns/${x.eventId}">${new Date(x.observedAt).toLocaleString()}</a></td><td>${esc(x.state)}</td><td>${esc(x.originalQueryName)}</td><td>${esc(x.recordType || "Unknown")}</td><td>${esc(x.responseCode || "Unknown")}</td><td>${esc((x.answers || []).map((a) => a.value).join(", ") || "Unavailable")}</td><td>${esc(x.resolverAddress || "NOT OBSERVABLE BY SOURCE")}</td><td>${esc(x.process?.image || x.process?.processEntityId || "Unattributed")}</td><td>${esc((x.dataQualityFlags || []).join(", ") || "No flags")}</td></tr>`).join("")}</tbody></table></div>`;
}
async function dnsSearch() {
  try {
    const q = new URLSearchParams(location.hash.split("?")[1] || "");
    const b = await api(`/api/v1/dns-events?${q}`);
    return `<form id="dns-search" class="toolbar"><label>Endpoint ID <input name="endpointId" value="${esc(q.get("endpointId") || "")}"></label><label>Query name <input name="queryName" value="${esc(q.get("queryName") || "")}"></label><label>Suffix <input name="suffix" value="${esc(q.get("suffix") || "")}"></label><label>Record type <select name="recordType"><option value="">Any</option>${["A", "AAAA", "CNAME", "MX", "SRV", "TXT", "PTR"].map((v) => `<option ${q.get("recordType") === v ? "selected" : ""}>${v}</option>`).join("")}</select></label><label>Response code <input name="responseCode" value="${esc(q.get("responseCode") || "")}"></label><label>Resolved IP <input name="resolvedIp" value="${esc(q.get("resolvedIp") || "")}"></label><label>Resolver <input name="resolver" value="${esc(q.get("resolver") || "")}"></label><label>Process <input name="process" value="${esc(q.get("process") || "")}"></label><label>User <input name="user" value="${esc(q.get("user") || "")}"></label><label>From <input name="from" type="datetime-local" value="${esc(q.get("from") || "")}"></label><label>To <input name="to" type="datetime-local" value="${esc(q.get("to") || "")}"></label><button>Search</button><button type="button" id="dns-export">Export JSONL</button></form><p id="dns-export-status" role="status" aria-live="polite"></p>${dnsTable(b.data.items || [])}`;
  } catch (e) {
    return state("DNS search unavailable", e.message);
  }
}
async function dnsDetail(id) {
  try {
    const x = (await api(`/api/v1/dns-events/${id}`)).data;
    let history = { items: [] };
    if (x.transactionEntityId)
      history = (
        await api(
          `/api/v1/endpoints/${x.endpointId}/dns-transactions/${x.transactionEntityId}/history`,
        )
      ).data;
    return `<a href="#/dns">← Back to DNS search</a><div class="detail-head"><div><h2>${esc(x.originalQueryName)}</h2><p class="muted">${esc(x.eventId)}</p></div><span class="badge">${esc(x.state)}</span></div><div class="panels"><article><h3>Native evidence</h3><dl><dt>Provider</dt><dd>${esc(x.nativeProvider)}</dd><dt>Native event</dt><dd>${esc(x.nativeEventId || "Unavailable")}</dd><dt>Collector</dt><dd>${esc(x.collectorSource)} ${esc(x.collectorVersion)}</dd><dt>Raw evidence hash</dt><dd><code>${esc(x.rawSha256 || "Unavailable")}</code></dd></dl></article><article><h3>Normalized DNS</h3><dl><dt>Original name</dt><dd>${esc(x.originalQueryName)}</dd><dt>Canonical name</dt><dd>${esc(x.canonicalQueryName)}</dd><dt>Type / class</dt><dd>${esc(x.recordType || "Unknown")} / ${esc(x.recordClass || "Unknown")}</dd><dt>Response code</dt><dd>${esc(x.responseCode || "Unknown")}</dd><dt>Resolver</dt><dd>${esc(x.resolverAddress || "NOT OBSERVABLE BY SOURCE")}</dd><dt>Answers</dt><dd>${esc((x.answers || []).map((a) => `${a.recordType} ${a.value} TTL ${a.ttl ?? "NOT OBSERVABLE"}`).join("; ") || "Unavailable")}</dd></dl></article><article><h3>Attribution</h3><dl><dt>Process entity</dt><dd><code>${esc(x.process?.processEntityId || "Unattributed")}</code></dd><dt>PID / start</dt><dd>${x.process?.processId ?? "Unavailable"} / ${x.process?.processStartTime ? new Date(x.process.processStartTime).toLocaleString() : "Unavailable"}</dd><dt>User</dt><dd>${esc(x.user || "Unknown")}</dd><dt>Confidence</dt><dd>${esc(x.process?.confidence || "Unavailable")}</dd></dl></article><article><h3>Correlation honesty</h3><dl><dt>Transaction</dt><dd>${esc(x.transactionEntityId || "Incomplete transaction — no reliable native identity")}</dd><dt>Confidence</dt><dd>${esc(x.transactionConfidence)}</dd><dt>Late / out of order</dt><dd>${x.late ? "Late" : "No"} / ${x.outOfOrder ? "Out of order" : "No"}</dd><dt>Quality</dt><dd>${esc((x.dataQualityFlags || []).join(", ") || "No flags")}</dd><dt>DNS/network context</dt><dd>${(x.networkRelationships || []).length ? "Supporting, ambiguous relationship evidence" : "No relationship asserted"}</dd></dl></article></div><section><h2>Transaction/history evidence</h2>${x.transactionEntityId ? dnsTable(history.items || []) : '<p class="muted">Separate event preserved; pairing was not fabricated.</p>'}</section>`;
  } catch (e) {
    return state("DNS event unavailable", e.message);
  }
}
async function exportDns() {
  const s = document.querySelector("#dns-export-status");
  s.textContent = "Export pending…";
  try {
    const r = await fetch(
      `/api/v1/dns-events:export?${new URLSearchParams(location.hash.split("?")[1] || "")}`,
      { headers: auth() },
    );
    if (!r.ok) throw Error(`status ${r.status}`);
    const u = URL.createObjectURL(await r.blob()),
      a = document.createElement("a");
    a.href = u;
    a.download = "dns-telemetry.jsonl";
    a.click();
    URL.revokeObjectURL(u);
    s.textContent = "Export complete.";
  } catch (e) {
    s.textContent = `Export failed: ${e.message}`;
  }
}
async function dnsPolicyList() {
  try {
    const items = (await api("/api/v1/dns-telemetry/policies")).data || [],
      latest = [...new Map(items.map((x) => [x.name, x])).values()];
    return `<div class="toolbar"><p>Versioned DNS collection policy. Packet payload capture is never enabled.</p><a class="button" href="#/dns-policies/new">Create policy</a></div>${latest.length ? `<table><thead><tr><th>Name</th><th>Version</th><th>Collector</th><th>Enabled</th><th>Exclusions</th></tr></thead><tbody>${latest.map((x) => `<tr><td><a href="#/dns-policies/${x.id}">${esc(x.name)}</a></td><td>${x.version}</td><td>${esc(x.policy.collectorSource)}</td><td>${x.policy.enabled ? "On" : "Off"}</td><td>${(x.policy.exclusionRules || []).length}</td></tr>`).join("")}</tbody></table>` : state("No DNS policies", "The safe bounded default is effective.")}`;
  } catch (e) {
    return state("DNS policies unavailable", e.message);
  }
}
async function dnsPolicyPage(id) {
  if (id === "new")
    return `<form id="dns-policy-editor" class="admin-grid"><fieldset><legend>DNS telemetry policy</legend><label>Name <input name="name" required maxlength="100"></label><label><input type="checkbox" name="enabled" checked> Collection enabled</label><label><input type="checkbox" name="queryCollection" checked> Queries</label><label><input type="checkbox" name="responseCollection" checked> Responses where observable</label><label><input type="checkbox" name="failedQueryCollection" checked> Failed queries</label><label><input type="checkbox" name="processAttribution" checked> Process attribution</label><label><input type="checkbox" name="answerMetadata" checked> Answer metadata</label><label>Included record types <input name="includedRecordTypes" placeholder="A,AAAA,CNAME"></label><label>Excluded domains, one per line <textarea name="excludedDomains"></textarea></label><label>Collector <select name="collectorSource"><option>auto</option><option>windows.dns-client-etw</option><option>linux.unsupported</option></select></label><button>Validate and save</button><p id="dns-policy-error" role="alert" tabindex="-1"></p></fieldset></form>`;
  try {
    const x = ((await api("/api/v1/dns-telemetry/policies")).data || []).find(
      (v) => v.id === id,
    );
    if (!x) return state("DNS policy not found", "Unavailable in this tenant.");
    const rules = x.policy.exclusionRules || [];
    return `<a href="#/dns-policies">← DNS policies</a><h2>${esc(x.name)} <span class="badge">Version ${x.version}</span></h2><div class="panels"><article><h3>Collection</h3><dl><dt>Collector</dt><dd>${esc(x.policy.collectorSource)}</dd><dt>Queries / responses / failures</dt><dd>${x.policy.queryCollection ? "On" : "Off"} / ${x.policy.responseCollection ? "On" : "Off"} / ${x.policy.failedQueryCollection ? "On" : "Off"}</dd><dt>Queue bound</dt><dd>${x.policy.maximumQueueBytes} bytes</dd></dl></article><article><h3>Privacy boundary</h3><p>No packets or DNS payloads are stored. Match-all and malformed exclusions are rejected.</p></article></div><section><h2>Exclusions</h2>${rules.length ? `<table><thead><tr><th>Category</th><th>Pattern</th><th>Reason</th><th>Action</th></tr></thead><tbody>${rules.map((r) => `<tr><td>${esc(r.category)}</td><td><code>${esc(r.pattern)}</code></td><td>${esc(r.reason || "Not provided")}</td><td><button class="dns-exclusion-delete" data-rule="${r.id}">Delete in new version</button></td></tr>`).join("")}</tbody></table>` : '<p class="muted">No exclusions.</p>'}<form id="dns-exclusion-editor"><label>Category <select name="category"><option>suffix</option><option>domain</option><option>recordType</option><option>process</option><option>user</option></select></label><label>Pattern <input name="pattern" required maxlength="253"></label><label>Reason <input name="reason" required maxlength="200"></label><button>Add validated exclusion</button><p id="dns-exclusion-error" role="alert" tabindex="-1"></p></form></section>`;
  } catch (e) {
    return state("DNS policy unavailable", e.message);
  }
}
async function saveDnsPolicy(e) {
  e.preventDefault();
  const f = new FormData(e.target),
    policy = {
      enabled: f.has("enabled"),
      queryCollection: f.has("queryCollection"),
      responseCollection: f.has("responseCollection"),
      failedQueryCollection: f.has("failedQueryCollection"),
      processAttribution: f.has("processAttribution"),
      answerMetadata: f.has("answerMetadata"),
      includedRecordTypes: lines(f.get("includedRecordTypes")),
      excludedDomains: lines(f.get("excludedDomains")),
      collectorSource: f.get("collectorSource"),
    };
  try {
    const b = await api("/api/v1/dns-telemetry/policies", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: f.get("name").trim(), policy }),
    });
    location.hash = `#/dns-policies/${b.data.id}`;
  } catch (x) {
    const p = document.querySelector("#dns-policy-error");
    p.textContent = x.message;
    p.focus();
  }
}
async function saveDnsExclusion(e, id) {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    const b = await api(`/api/v1/dns-telemetry/policies/${id}/exclusions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        category: f.get("category"),
        pattern: f.get("pattern").trim(),
        enabled: true,
        reason: f.get("reason").trim(),
      }),
    });
    location.hash = `#/dns-policies/${b.data.id}`;
  } catch (x) {
    const p = document.querySelector("#dns-exclusion-error");
    p.textContent = x.message;
    p.focus();
  }
}
async function deleteDnsExclusion(id, rule) {
  const b = await api(
    `/api/v1/dns-telemetry/policies/${id}/exclusions/${rule}`,
    { method: "DELETE" },
  );
  location.hash = `#/dns-policies/${b.data.id}`;
}
async function hydrateDnsHealth(endpoint) {
  try {
    const h = (
      await api(`/api/v1/endpoints/${endpoint.id}/dns-telemetry-health`)
    ).data;
    document
      .querySelector(".panels")
      ?.insertAdjacentHTML(
        "beforeend",
        `<article aria-labelledby="dns-health-title"><h3 id="dns-health-title">DNS telemetry health</h3><dl><dt>Collector</dt><dd>${esc(h.collectorSource)} ${esc(h.collectorVersion)}</dd><dt>Queries / responses / failures</dt><dd>${h.queries} / ${h.responses} / ${h.failures}</dd><dt>Unanswered / unpaired</dt><dd>${h.unansweredQueries} / ${h.unpairedResponses}</dd><dt>Attribution / correlation failures</dt><dd>${h.attributionFailures} / ${h.correlationFailures}</dd><dt>Queue depth / age</dt><dd>${h.queueDepth} / ${h.oldestQueuedSeconds}s</dd><dt>Drops / exclusions</dt><dd>${h.queueDrops} / ${h.excludedEvents}</dd><dt>Known limitations</dt><dd>${esc((h.knownLimitations || []).join("; ") || "None reported")}</dd></dl><p><a href="#/dns?endpointId=${endpoint.id}">Endpoint DNS timeline</a></p></article>`,
      );
  } catch {
    document
      .querySelector(".panels")
      ?.insertAdjacentHTML(
        "beforeend",
        '<article><h3>DNS telemetry health</h3><p class="muted">No accepted DNS health report.</p></article>',
      );
  }
}
async function hydrateProcessDns(endpointId, entityId) {
  try {
    const b = await api(
      `/api/v1/endpoints/${endpointId}/processes/${entityId}/dns`,
    );
    document
      .querySelector("#content")
      ?.insertAdjacentHTML(
        "beforeend",
        `<section><h2>DNS activity</h2>${dnsTable(b.data.items || [])}</section>`,
      );
  } catch (e) {
    document
      .querySelector("#content")
      ?.insertAdjacentHTML(
        "beforeend",
        `<section>${state("DNS relationship unavailable", e.message)}</section>`,
      );
  }
}

function networkTable(items) {
  if (!items.length)
    return '<p class="muted">No network evidence matches this bounded query.</p>';
  return `<div class="table-wrap"><table><thead><tr><th>Observed</th><th>Operation</th><th>Direction</th><th>Protocol</th><th>Local endpoint</th><th>Remote endpoint</th><th>Process</th><th>User</th><th>State</th><th>Quality</th></tr></thead><tbody>${items.map((x) => `<tr><td><a href="#/network/${x.eventId}">${new Date(x.observedAt).toLocaleString()}</a></td><td>${esc(x.kind)}</td><td>${esc(x.direction)}</td><td>${esc(x.protocol)} ${esc(x.local?.addressFamily)}</td><td><code>${esc(x.local?.address ?? "Unavailable")}:${x.local?.port ?? "—"}</code></td><td><code>${esc(x.remote?.address ?? "Unavailable")}:${x.remote?.port ?? "—"}</code></td><td>${esc(x.process?.image || x.process?.processEntityId || "Unattributed")}</td><td>${esc(x.user || "Unavailable")}</td><td>${esc(x.state)}</td><td>${esc((x.dataQualityFlags || []).join(", ") || "No flags")}</td></tr>`).join("")}</tbody></table></div>`;
}
async function networkSearch(listener = false) {
  try {
    const q = new URLSearchParams(location.hash.split("?")[1] || "");
    if (listener) q.set("listener", "true");
    const b = await api(`/api/v1/network-events?${q}`);
    return `<form id="network-search" class="toolbar"><label>Endpoint ID <input name="endpointId" value="${esc(q.get("endpointId") || "")}"></label><label>Local address <input name="localAddress" value="${esc(q.get("localAddress") || "")}"></label><label>Remote address <input name="remoteAddress" value="${esc(q.get("remoteAddress") || "")}"></label><label>Local port <input name="localPort" type="number" min="0" max="65535" value="${esc(q.get("localPort") || "")}"></label><label>Remote port <input name="remotePort" type="number" min="0" max="65535" value="${esc(q.get("remotePort") || "")}"></label><label>Protocol <select name="protocol"><option value="">Any</option>${["TCP", "UDP"].map((v) => `<option ${q.get("protocol") === v ? "selected" : ""}>${v}</option>`).join("")}</select></label><label>Address family <select name="addressFamily"><option value="">Any</option>${["IPv4", "IPv6"].map((v) => `<option ${q.get("addressFamily") === v ? "selected" : ""}>${v}</option>`).join("")}</select></label><label>Direction <select name="direction"><option value="">Any</option>${["Outbound", "Inbound", "Local", "Unknown"].map((v) => `<option ${q.get("direction") === v ? "selected" : ""}>${v}</option>`).join("")}</select></label><label>State <select name="state"><option value="">Any</option>${["Attempted", "Established", "Failed", "Closed", "Listening", "Unknown"].map((v) => `<option ${q.get("state") === v ? "selected" : ""}>${v}</option>`).join("")}</select></label><label>Process <input name="process" value="${esc(q.get("process") || "")}"></label><label>User <input name="user" value="${esc(q.get("user") || "")}"></label><label>From <input name="from" type="datetime-local" value="${esc(q.get("from") || "")}"></label><label>To <input name="to" type="datetime-local" value="${esc(q.get("to") || "")}"></label>${listener ? '<input type="hidden" name="listener" value="true">' : ""}<button>Search</button><button type="button" id="network-export">Export JSONL</button></form><p id="network-export-status" role="status" aria-live="polite"></p>${networkTable(b.data.items || [])}${b.data.nextCursor ? `<button id="network-next" data-cursor="${esc(b.data.nextCursor)}">Next page</button>` : ""}`;
  } catch (e) {
    return state(
      listener ? "Listener view unavailable" : "Network search unavailable",
      e.message,
    );
  }
}
async function networkDetail(eventId) {
  try {
    const x = (await api(`/api/v1/network-events/${eventId}`)).data,
      h = (
        await api(
          `/api/v1/endpoints/${x.endpointId}/network-connections/${x.connectionEntityId}/history`,
        )
      ).data;
    return `<a href="#/network">← Back to network search</a><div class="detail-head"><div><h2>${esc(x.protocol)} ${esc(x.local.address)}:${x.local.port} → ${esc(x.remote?.address || "Unavailable")}:${x.remote?.port ?? "—"}</h2><p class="muted">${esc(x.eventId)}</p></div><span class="badge">${esc(x.state)}</span></div><div class="panels"><article><h3>Observed socket evidence</h3><dl><dt>Operation</dt><dd>${esc(x.kind)}</dd><dt>Direction</dt><dd>${esc(x.direction)}</dd><dt>Address family</dt><dd>${esc(x.local.addressFamily)}</dd><dt>Local native address</dt><dd><code>${esc(x.local.nativeAddress)}</code></dd><dt>Remote native address</dt><dd><code>${esc(x.remote?.nativeAddress || "Unavailable")}</code></dd><dt>Loopback / multicast / wildcard</dt><dd>${x.local.loopback ? "Loopback" : "No"} / ${x.local.multicast ? "Multicast" : "No"} / ${x.local.wildcard ? "Wildcard" : "No"}</dd></dl></article><article><h3>Native provenance</h3><dl><dt>Provider</dt><dd>${esc(x.nativeProvider)}</dd><dt>Native event</dt><dd>${esc(x.nativeEventId || "Unavailable")}</dd><dt>Native operation</dt><dd>${esc(x.nativeOperation)}</dd><dt>Native status</dt><dd>${x.nativeStatus ?? "Unavailable"}</dd><dt>Collector</dt><dd>${esc(x.collectorSource)} ${esc(x.collectorVersion)}</dd><dt>Raw evidence hash</dt><dd><code>${esc(x.rawSha256 || "Unavailable")}</code></dd></dl></article><article><h3>Attribution and context</h3><dl><dt>Process entity</dt><dd><code>${esc(x.process?.processEntityId || "Unattributed")}</code></dd><dt>PID / start</dt><dd>${x.process?.processId ?? "Unavailable"} / ${x.process?.processStartTime ? new Date(x.process.processStartTime).toLocaleString() : "Unavailable"}</dd><dt>User</dt><dd>${esc(x.user || "Unavailable")}</dd><dt>Attribution confidence</dt><dd>${esc(x.attributionConfidence)}</dd><dt>Hostname</dt><dd>${esc(x.hostname?.hostname || "Unavailable")}</dd><dt>Hostname source</dt><dd>${esc(x.hostname?.source || "No enrichment performed")}</dd></dl></article><article><h3>Normalized lifecycle</h3><dl><dt>Connection entity</dt><dd><code>${esc(x.connectionEntityId)}</code></dd><dt>Lifecycle completeness</dt><dd>${esc(x.lifecycleCompleteness)}</dd><dt>Result</dt><dd>${esc(x.result || "Unknown")}</dd><dt>Late / out of order</dt><dd>${x.late ? "Late" : "No"} / ${x.outOfOrder ? "Out of order" : "No"}</dd><dt>Quality flags</dt><dd>${esc((x.dataQualityFlags || []).join(", ") || "No flags")}</dd></dl></article></div><section><h2>Connection history</h2>${networkTable(h.items || [])}</section>`;
  } catch (e) {
    return state("Network event unavailable", e.message);
  }
}
async function exportNetwork() {
  const s = document.querySelector("#network-export-status");
  s.textContent = "Export pending…";
  try {
    const r = await fetch(
      `/api/v1/network-events:export?${new URLSearchParams(location.hash.split("?")[1] || "")}`,
      { headers: auth() },
    );
    if (!r.ok) throw Error(`status ${r.status}`);
    const u = URL.createObjectURL(await r.blob()),
      a = document.createElement("a");
    a.href = u;
    a.download = "network-telemetry.jsonl";
    a.click();
    URL.revokeObjectURL(u);
    s.textContent = "Export complete.";
  } catch (e) {
    s.textContent = `Export failed: ${e.message}`;
  }
}
async function networkPolicyList() {
  try {
    const items = (await api("/api/v1/network-telemetry/policies")).data || [],
      latest = [...new Map(items.map((x) => [x.name, x])).values()];
    return `<div class="toolbar"><p>Versioned collection policy. Packet and payload collection are never enabled.</p><a class="button" href="#/network-policies/new">Create policy</a></div>${latest.length ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Version</th><th>Collector</th><th>Protocols</th><th>Enabled</th><th>Exclusions</th></tr></thead><tbody>${latest.map((x) => `<tr><td><a href="#/network-policies/${x.id}">${esc(x.name)}</a></td><td>${x.version}</td><td>${esc(x.policy.collectorSource)}</td><td>${x.policy.tcpEnabled ? "TCP " : ""}${x.policy.udpEnabled ? "UDP" : ""}</td><td>${x.policy.enabled ? "On" : "Off"}</td><td>${(x.policy.exclusionRules || []).length}</td></tr>`).join("")}</tbody></table></div>` : state("No network policies", "The bounded safe default remains effective.")}`;
  } catch (e) {
    return state("Network policies unavailable", e.message);
  }
}
async function networkPolicyPage(id) {
  if (id === "new")
    return `<form id="network-policy-editor" class="admin-grid"><fieldset><legend>Network telemetry policy</legend><label>Name <input name="name" required maxlength="100"></label><label><input type="checkbox" name="enabled" checked> Collection enabled</label><label><input type="checkbox" name="tcpEnabled" checked> TCP</label><label><input type="checkbox" name="udpEnabled" checked> UDP</label><label><input type="checkbox" name="ipv4Enabled" checked> IPv4</label><label><input type="checkbox" name="ipv6Enabled" checked> IPv6</label><label><input type="checkbox" name="inboundEnabled" checked> Inbound evidence</label><label><input type="checkbox" name="listenerEnabled" checked> Listener evidence where supported</label><label>Included CIDRs, one per line <textarea name="includedCidrs"></textarea></label><label>Excluded CIDRs, one per line <textarea name="excludedCidrs"></textarea></label><label>Excluded ports/ranges, one per line <textarea name="excludedPorts"></textarea></label><label>Collector <select name="collectorSource"><option>auto</option><option>windows.etw-network</option><option>linux.falco-json</option></select></label><button>Validate and save</button><p id="network-policy-error" role="alert" tabindex="-1"></p></fieldset></form>`;
  try {
    const items = (await api("/api/v1/network-telemetry/policies")).data || [],
      x = items.find((v) => v.id === id);
    if (!x)
      return state(
        "Policy not found",
        "The policy is unavailable in this tenant.",
      );
    return `<a href="#/network-policies">← Network policies</a><div class="detail-head"><div><h2>${esc(x.name)}</h2><p><code>${esc(x.id)}</code></p></div><span class="badge">Version ${x.version}</span></div><div class="panels"><article><h3>Collection</h3><dl><dt>Collector</dt><dd>${esc(x.policy.collectorSource)}</dd><dt>Protocols</dt><dd>${x.policy.tcpEnabled ? "TCP " : ""}${x.policy.udpEnabled ? "UDP" : ""}</dd><dt>Address families</dt><dd>${x.policy.ipv4Enabled ? "IPv4 " : ""}${x.policy.ipv6Enabled ? "IPv6" : ""}</dd><dt>Queue bound</dt><dd>${x.policy.maximumQueueBytes} bytes</dd><dt>Batch bound</dt><dd>${x.policy.maximumBatchEvents} events</dd></dl></article><article><h3>Privacy boundary</h3><p>No packets, payloads, URLs, DNS domain, TLS, or HTTP content are collected.</p></article></div><section><h2>Exclusions</h2>${(x.policy.exclusionRules || []).length ? `<table><thead><tr><th>Category</th><th>Pattern</th><th>Enabled</th><th>Action</th></tr></thead><tbody>${x.policy.exclusionRules.map((r) => `<tr><td>${esc(r.category)}</td><td><code>${esc(r.pattern)}</code></td><td>${r.enabled ? "On" : "Off"}</td><td><button class="network-exclusion-delete" data-rule="${r.id}">Delete in new version</button></td></tr>`).join("")}</tbody></table>` : '<p class="muted">No exclusions.</p>'}<form id="network-exclusion-editor"><label>Category <select name="category"><option>cidr</option><option>address</option><option>port</option><option>protocol</option><option>process</option><option>user</option><option>direction</option></select></label><label>Pattern <input name="pattern" required maxlength="256"></label><label>Reason <input name="reason" required maxlength="200"></label><button>Add validated exclusion</button><p id="network-exclusion-error" role="alert"></p></form></section>`;
  } catch (e) {
    return state("Network policy unavailable", e.message);
  }
}
async function saveNetworkPolicy(e) {
  e.preventDefault();
  const f = new FormData(e.target),
    policy = {
      enabled: f.has("enabled"),
      tcpEnabled: f.has("tcpEnabled"),
      udpEnabled: f.has("udpEnabled"),
      ipv4Enabled: f.has("ipv4Enabled"),
      ipv6Enabled: f.has("ipv6Enabled"),
      inboundEnabled: f.has("inboundEnabled"),
      listenerEnabled: f.has("listenerEnabled"),
      includedCidrs: lines(f.get("includedCidrs")),
      excludedCidrs: lines(f.get("excludedCidrs")),
      excludedPorts: lines(f.get("excludedPorts")),
      collectorSource: f.get("collectorSource"),
    };
  try {
    const b = await api("/api/v1/network-telemetry/policies", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: f.get("name").trim(), policy }),
    });
    location.hash = `#/network-policies/${b.data.id}`;
  } catch (x) {
    const p = document.querySelector("#network-policy-error");
    p.textContent = x.message;
    p.focus();
  }
}
async function saveNetworkExclusion(e, id) {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    const b = await api(`/api/v1/network-telemetry/policies/${id}/exclusions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        category: f.get("category"),
        pattern: f.get("pattern").trim(),
        enabled: true,
        reason: f.get("reason").trim(),
      }),
    });
    location.hash = `#/network-policies/${b.data.id}`;
  } catch (x) {
    document.querySelector("#network-exclusion-error").textContent = x.message;
  }
}
async function deleteNetworkExclusion(id, rule) {
  const b = await api(
    `/api/v1/network-telemetry/policies/${id}/exclusions/${rule}`,
    { method: "DELETE" },
  );
  location.hash = `#/network-policies/${b.data.id}`;
}
async function hydrateNetworkHealth(endpoint) {
  try {
    const h = (
      await api(`/api/v1/endpoints/${endpoint.id}/network-telemetry-health`)
    ).data;
    const degraded =
        h.droppedEvents ||
        h.sourceLosses ||
        h.sequenceGaps ||
        h.attributionFailures ||
        h.lifecycleCorrelationFailures,
      status = !h.enabled
        ? "Disabled"
        : degraded
          ? "Degraded"
          : h.queueDepth
            ? "Recovering"
            : "Healthy";
    document
      .querySelector(".panels")
      ?.insertAdjacentHTML(
        "beforeend",
        `<article aria-labelledby="network-health-title"><div class="detail-head"><h3 id="network-health-title">Network telemetry health</h3><span class="badge">${status}</span></div><dl><dt>Collector</dt><dd>${esc(h.collectorSource)} ${esc(h.collectorVersion)}</dd><dt>Native provider</dt><dd>${esc(h.nativeProvider)}</dd><dt>TCP / UDP</dt><dd>${h.tcpEvents} / ${h.udpEvents}</dd><dt>IPv4 / IPv6</dt><dd>${h.ipv4Events} / ${h.ipv6Events}</dd><dt>Queue depth / age</dt><dd>${h.queueDepth} / ${h.oldestQueuedSeconds}s</dd><dt>Drops / source losses</dt><dd>${h.droppedEvents} / ${h.sourceLosses}</dd><dt>Attribution failures</dt><dd>${h.attributionFailures}</dd><dt>Lifecycle gaps</dt><dd>${h.lifecycleCorrelationFailures}</dd><dt>Policy / drift</dt><dd>${esc(h.policyVersion)} / ${h.drift ? "Yes" : "No"}</dd><dt>Known limitations</dt><dd>${esc((h.knownLimitations || []).join("; ") || "None reported")}</dd></dl><p><a href="#/network?endpointId=${endpoint.id}">Endpoint network timeline</a></p></article>`,
      );
  } catch {
    document
      .querySelector(".panels")
      ?.insertAdjacentHTML(
        "beforeend",
        '<article><h3>Network telemetry health</h3><p class="muted">No accepted network health report.</p></article>',
      );
  }
}
async function hydrateProcessNetwork(endpointId, entityId) {
  try {
    const b = await api(
      `/api/v1/endpoints/${endpointId}/processes/${entityId}/network`,
    );
    document
      .querySelector("#content")
      ?.insertAdjacentHTML(
        "beforeend",
        `<section><h2>Network activity</h2>${networkTable(b.data.items || [])}</section>`,
      );
  } catch (e) {
    document
      .querySelector("#content")
      ?.insertAdjacentHTML(
        "beforeend",
        `<section>${state("Network relationship unavailable", e.message)}</section>`,
      );
  }
}

function rememberAuthenticationDestination() {
  const destination = location.hash && location.hash !== "#/login" ? location.hash : "#/dashboard";
  sessionStorage.setItem("post_login_hash", destination);
}
function login(message = "Sign in to access the SOC workspace.") {
  return `<div class="auth-gate"><div class="auth-backdrop" aria-hidden="true"></div><section class="auth-dialog" role="dialog" aria-modal="true" aria-labelledby="login-title" aria-describedby="login-description"><div class="auth-brand"><span aria-hidden="true">OS</span><div><strong>Open Security</strong><small>SOC Operations</small></div></div><div class="auth-heading"><p class="eyebrow">SECURE WORKSPACE</p><h1 id="login-title">Sign in</h1><p id="login-description">${esc(message)}</p></div><form id="login"><label for="login-username">Username</label><input id="login-username" name="username" autocomplete="username" required autofocus><label for="login-password">Password</label><input id="login-password" name="password" type="password" autocomplete="current-password" required><button type="submit">Sign in</button><p id="login-error" role="alert" aria-live="assertive"></p></form><p class="auth-footnote">Your intended workspace will reopen after authentication.</p></section></div>`;
}
function renderAuthenticationGate(message) {
  activeReadController.abort();
  document.title = "Sign in · Open Security Platform";
  document.querySelector("#app").innerHTML = login(message);
  const form = document.querySelector("#login");
  form.onsubmit = authenticate;
  requestAnimationFrame(() => form.querySelector("input")?.focus());
}
async function authenticate(e) {
  e.preventDefault();
  const form = e.currentTarget;
  const submit = form.querySelector('button[type="submit"]');
  const error = form.querySelector("#login-error");
  submit.disabled = true;
  submit.textContent = "Signing in…";
  error.textContent = "";
  try {
    const r = await fetch("/api/v1/auth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(Object.fromEntries(new FormData(form))),
    });
    if (!r.ok) { error.textContent = "Username or password is incorrect."; return; }
    const b = await r.json();
    if (!tokenIsCurrent(b.access_token) || !tokenIsCurrent(b.refresh_token)) {
      error.textContent = "The server returned an invalid session. Please try again.";
      return;
    }
    sessionStorage.setItem("access_token", b.access_token);
    sessionStorage.setItem("refresh_token", b.refresh_token);
    sessionStorage.removeItem("platform_client_id");
    managedClients = [];
    const destination = sessionStorage.getItem("post_login_hash") || "#/dashboard";
    sessionStorage.removeItem("post_login_hash");
    if (location.hash === destination) await route();
    else location.hash = destination;
  } catch {
    error.textContent = "The gateway could not be reached. Check the platform connection and try again.";
  } finally {
    if (document.contains(submit)) { submit.disabled = false; submit.textContent = "Sign in"; }
  }
}
function moduleTable(items) {
  if (!items.length)
    return '<p class="muted">No module or image-load evidence matches this bounded query.</p>';
  return `<div class="table-wrap"><table><thead><tr><th>Observed</th><th>Event</th><th>Module</th><th>Mode</th><th>Process</th><th>Load base</th><th>Hash</th><th>Signer</th><th>Quality</th></tr></thead><tbody>${items.map((x) => `<tr><td><a href="#/modules/${x.eventId}">${new Date(x.observedAt).toLocaleString()}</a></td><td>${esc(x.kind)}</td><td title="${esc(x.originalPath)}"><code>${esc(x.normalizedPath)}</code></td><td>${esc(x.mode)}${x.driver ? " / driver" : ""}</td><td>${esc(x.process?.image || x.process?.processEntityId || "Unavailable")}</td><td><code>${x.actualLoadBase == null ? "Unavailable" : esc(x.actualLoadBase)}</code></td><td>${esc(x.hash?.state || "NotRequested")}</td><td>${esc(x.signer?.subject || x.signer?.signedState || "Unknown")}</td><td>${esc((x.dataQualityFlags || []).join(", ") || "No flags")}</td></tr>`).join("")}</tbody></table></div>`;
}
async function moduleSearch(drivers = false) {
  try {
    const q = new URLSearchParams(location.hash.split("?")[1] || "");
    const b = await api(
      `${drivers ? "/api/v1/drivers" : "/api/v1/module-events"}?${q}`,
    );
    return `<form id="module-search" class="toolbar"><label>Endpoint ID <input name="endpointId" value="${esc(q.get("endpointId") || "")}"></label><label>Path <input name="path" value="${esc(q.get("path") || "")}"></label><label>Basename <input name="basename" value="${esc(q.get("basename") || "")}"></label><label>Process <input name="process" value="${esc(q.get("process") || "")}"></label><label>SHA-256 <input name="sha256" minlength="64" maxlength="64" value="${esc(q.get("sha256") || "")}"></label><label>Signer <input name="signer" value="${esc(q.get("signer") || "")}"></label><label>Load address <input name="loadAddress" placeholder="0x7ff..." value="${esc(q.get("loadAddress") || "")}"></label><label>Image type <select name="imageType"><option value="">Any</option>${["dll", "executable", "driver", "shared-library", "image"].map((v) => `<option ${q.get("imageType") === v ? "selected" : ""}>${v}</option>`).join("")}</select></label><label>Mode <select name="mode"><option value="">Any</option><option>User</option><option>Kernel</option></select></label><label>Architecture <input name="architecture" value="${esc(q.get("architecture") || "")}"></label><label>User <input name="user" value="${esc(q.get("user") || "")}"></label><label>From <input type="datetime-local" name="from" value="${esc(q.get("from") || "")}"></label><label>To <input type="datetime-local" name="to" value="${esc(q.get("to") || "")}"></label><button>Search</button><button type="button" id="module-export">Export JSONL</button></form><p id="module-export-status" role="status" aria-live="polite"></p>${moduleTable(b.data.items || [])}`;
  } catch (e) {
    return state("Module search unavailable", e.message);
  }
}
async function moduleDetail(id) {
  try {
    const x = (await api(`/api/v1/module-events/${id}`)).data;
    return `<a href="#/modules">â† Back to module search</a><div class="detail-head"><div><h2>${esc(x.basename)}</h2><p class="muted">${esc(x.moduleEntityId)}</p></div><span class="badge">${esc(x.kind)}</span></div><div class="panels"><article><h3>Image identity</h3><dl><dt>Original path</dt><dd><code>${esc(x.originalPath)}</code></dd><dt>Normalized path</dt><dd><code>${esc(x.normalizedPath)}</code></dd><dt>Backing file</dt><dd><code>${esc(x.backingFileEntityId || "Unavailable")}</code></dd><dt>Native identity</dt><dd>${esc(x.nativeImageIdentity || "Unavailable")}</dd><dt>Image / mapping size</dt><dd>${x.imageSize ?? "Unavailable"} / ${x.mappingSize ?? "Unavailable"}</dd><dt>Load / preferred base</dt><dd>${x.actualLoadBase ?? "Unavailable"} / ${x.preferredImageBase ?? "Unavailable"}</dd></dl></article><article><h3>Enrichment</h3><dl><dt>Hash state</dt><dd>${esc(x.hash?.state)}</dd><dt>SHA-256</dt><dd><code>${esc(x.hash?.value || "Unavailable")}</code></dd><dt>Signed state</dt><dd>${esc(x.signer?.signedState)}</dd><dt>Verification</dt><dd>${esc(x.signer?.verificationStatus)}</dd><dt>Subject</dt><dd>${esc(x.signer?.subject || "Unavailable")}</dd><dt>Issuer</dt><dd>${esc(x.signer?.issuer || "Unavailable")}</dd></dl></article><article><h3>Provenance and relationship</h3><dl><dt>Collector</dt><dd>${esc(x.collectorSource)} ${esc(x.collectorVersion)}</dd><dt>Native provider/event</dt><dd>${esc(x.nativeProvider)} / ${esc(x.nativeEventId)}</dd><dt>Process</dt><dd>${esc(x.process?.image || x.process?.processEntityId || "Kernel / unavailable")}</dd><dt>User</dt><dd>${esc(x.user || "Unavailable")}</dd><dt>Confidence</dt><dd>${esc(x.sourceConfidence)}</dd><dt>Quality</dt><dd>${esc((x.dataQualityFlags || []).join(", ") || "No flags")}</dd></dl></article></div>`;
  } catch (e) {
    return state("Module evidence unavailable", e.message);
  }
}
async function exportModules() {
  const s = document.querySelector("#module-export-status");
  s.textContent = "Export pendingâ€¦";
  try {
    const r = await fetch(
      `/api/v1/module-events:export?${new URLSearchParams(location.hash.split("?")[1] || "")}`,
      { headers: auth() },
    );
    if (!r.ok) throw Error(`status ${r.status}`);
    const u = URL.createObjectURL(await r.blob()),
      a = document.createElement("a");
    a.href = u;
    a.download = "module-telemetry.jsonl";
    a.click();
    URL.revokeObjectURL(u);
    s.textContent = "Export complete.";
  } catch (e) {
    s.textContent = `Export failed: ${e.message}`;
  }
}
async function hydrateModuleHealth(endpoint) {
  try {
    const h = (
      await api(`/api/v1/endpoints/${endpoint.id}/module-telemetry-health`)
    ).data;
    const degraded =
      h.sourceDrops ||
      h.sequenceGaps ||
      h.queueDrops ||
      h.attributionFailures ||
      h.fileIdentityFailures;
    document
      .querySelector(".panels")
      ?.insertAdjacentHTML(
        "beforeend",
        `<article><div class="detail-head"><h3>Module telemetry health</h3><span class="badge">${!h.enabled ? "Disabled" : degraded ? "Degraded" : h.queueDepth ? "Recovering" : "Healthy"}</span></div><dl><dt>Collector</dt><dd>${esc(h.collectorSource)} ${esc(h.collectorVersion)}</dd><dt>Elevated</dt><dd>${h.elevated ? "Yes" : "No"}</dd><dt>User / driver loads</dt><dd>${h.userLoads} / ${h.driverLoads}</dd><dt>Hash completed / failed</dt><dd>${h.hashCompleted} / ${h.hashFailed}</dd><dt>Signer completed / failed</dt><dd>${h.signerCompleted} / ${h.signerFailed}</dd><dt>Queue depth / age</dt><dd>${h.queueDepth} / ${h.oldestQueuedSeconds}s</dd><dt>Source / sequence gaps</dt><dd>${h.sourceDrops} / ${h.sequenceGaps}</dd><dt>Known limitations</dt><dd>${esc((h.knownLimitations || []).join("; ") || "None reported")}</dd></dl><a href="#/modules?endpointId=${endpoint.id}">Endpoint module timeline</a></article>`,
      );
  } catch {
    document
      .querySelector(".panels")
      ?.insertAdjacentHTML(
        "beforeend",
        '<article><h3>Module telemetry health</h3><p class="muted">No accepted module health report.</p></article>',
      );
  }
}
async function hydrateProcessModules(endpointId, entityId) {
  try {
    const b = await api(
      `/api/v1/endpoints/${endpointId}/processes/${entityId}/modules`,
    );
    document
      .querySelector("#content")
      ?.insertAdjacentHTML(
        "beforeend",
        `<section><h2>Loaded modules</h2>${moduleTable(b.data.items || [])}</section>`,
      );
  } catch (e) {
    document
      .querySelector("#content")
      ?.insertAdjacentHTML(
        "beforeend",
        `<section>${state("Module relationship unavailable", e.message)}</section>`,
      );
  }
}
async function modulePolicyList() {
  try {
    const items = (await api("/api/v1/module-telemetry/policies")).data || [],
      latest = [...new Map(items.map((x) => [x.name, x])).values()];
    return `<div class="toolbar"><p>Immutable, bounded module collection policies.</p><a class="button" href="#/module-policies/new">Create policy</a></div>${latest.length ? `<table><thead><tr><th>Name</th><th>Version</th><th>Collector</th><th>Enabled</th><th>Hashing</th><th>Signer</th><th>Exclusions</th></tr></thead><tbody>${latest.map((x) => `<tr><td><a href="#/module-policies/${x.id}">${esc(x.name)}</a></td><td>${x.version}</td><td>${esc(x.policy.collectorSource)}</td><td>${x.policy.enabled ? "On" : "Off"}</td><td>${x.policy.hashing ? "On" : "Off"}</td><td>${x.policy.signerMetadata ? "On" : "Off"}</td><td>${(x.policy.exclusionRules || []).length}</td></tr>`).join("")}</tbody></table>` : state("No module policies", "The safe bounded default is effective.")}`;
  } catch (e) {
    return state("Module policies unavailable", e.message);
  }
}
async function modulePolicyPage(id) {
  if (id === "new")
    return `<form id="module-policy-editor" class="admin-grid"><fieldset><legend>Module telemetry policy</legend><label>Name <input name="name" required maxlength="100"></label><label><input type="checkbox" name="enabled" checked> Module telemetry enabled</label><label><input type="checkbox" name="userModeModules" checked> User-mode modules</label><label><input type="checkbox" name="executableImages" checked> Executable images</label><label><input type="checkbox" name="sharedLibraries" checked> Shared libraries</label><label><input type="checkbox" name="driverLoads" checked> Driver loads</label><label><input type="checkbox" name="unloadEvents"> Unloads where observable</label><label><input type="checkbox" name="hashing"> Bounded SHA-256 enrichment</label><label><input type="checkbox" name="signerMetadata"> Embedded signer metadata</label><label>Included paths, one per line <textarea name="includedPaths"></textarea></label><label>Excluded paths, one per line <textarea name="excludedPaths"></textarea></label><label>Collector <select name="collectorSource"><option>auto</option><option>windows.kernel-image-etw</option><option>linux.unsupported</option></select></label><button>Validate and save</button><p id="module-policy-error" role="alert" tabindex="-1"></p></fieldset></form>`;
  try {
    const x = (
      (await api("/api/v1/module-telemetry/policies")).data || []
    ).find((v) => v.id === id);
    if (!x)
      return state("Module policy not found", "Unavailable in this tenant.");
    const rules = x.policy.exclusionRules || [];
    return `<a href="#/module-policies">â† Module policies</a><h2>${esc(x.name)} <span class="badge">Version ${x.version}</span></h2><div class="panels"><article><h3>Collection and enrichment</h3><dl><dt>Collector</dt><dd>${esc(x.policy.collectorSource)}</dd><dt>User modules / drivers</dt><dd>${x.policy.userModeModules ? "On" : "Off"} / ${x.policy.driverLoads ? "On" : "Off"}</dd><dt>Hash / signer</dt><dd>${x.policy.hashing ? "On" : "Off"} / ${x.policy.signerMetadata ? "On" : "Off"}</dd><dt>Queue bound</dt><dd>${x.policy.maximumQueueBytes} bytes</dd></dl><form id="module-policy-assign"><label>Endpoint ID <input name="endpointId" required pattern="[0-9a-fA-F-]{36}"></label><button>Assign</button><p role="status" aria-live="polite"></p></form></article><article><h3>Audited exclusions</h3>${rules.length ? `<ul>${rules.map((r) => `<li>${esc(r.category)}: <code>${esc(r.pattern)}</code></li>`).join("")}</ul>` : '<p class="muted">No exclusions.</p>'}<form id="module-exclusion-editor"><label>Category <select name="category"><option>path</option><option>process</option><option>image-type</option></select></label><label>Pattern <input name="pattern" required></label><label>Reason <input name="reason" required></label><button>Add validated exclusion</button><p id="module-exclusion-error" role="alert"></p></form></article></div>`;
  } catch (e) {
    return state("Module policy unavailable", e.message);
  }
}
async function saveModulePolicy(e) {
  e.preventDefault();
  const f = new FormData(e.target),
    policy = {
      enabled: f.has("enabled"),
      userModeModules: f.has("userModeModules"),
      executableImages: f.has("executableImages"),
      sharedLibraries: f.has("sharedLibraries"),
      driverLoads: f.has("driverLoads"),
      unloadEvents: f.has("unloadEvents"),
      hashing: f.has("hashing"),
      signerMetadata: f.has("signerMetadata"),
      includedPaths: lines(f.get("includedPaths")),
      excludedPaths: lines(f.get("excludedPaths")),
      collectorSource: f.get("collectorSource"),
    };
  try {
    const b = await api("/api/v1/module-telemetry/policies", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: f.get("name").trim(), policy }),
    });
    location.hash = `#/module-policies/${b.data.id}`;
  } catch (x) {
    const p = document.querySelector("#module-policy-error");
    p.textContent = x.message;
    p.focus();
  }
}
async function assignModulePolicy(e, id) {
  e.preventDefault();
  const out = e.target.querySelector('[role="status"]');
  try {
    await api(`/api/v1/module-telemetry/policies/${id}:assign`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        endpointId: new FormData(e.target).get("endpointId"),
      }),
    });
    out.textContent = "Assignment accepted; agent acknowledgement pending.";
  } catch (x) {
    out.textContent = x.message;
  }
}
async function saveModuleExclusion(e, id) {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    const b = await api(`/api/v1/module-telemetry/policies/${id}/exclusions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        id: crypto.randomUUID(),
        category: f.get("category"),
        pattern: f.get("pattern").trim(),
        reason: f.get("reason").trim(),
        enabled: true,
      }),
    });
    location.hash = `#/module-policies/${b.data.id}`;
  } catch (x) {
    document.querySelector("#module-exclusion-error").textContent = x.message;
  }
}

function persistenceTable(items, kind) {
  if (!items.length)
    return `<p class="muted">No ${kind} evidence matches this bounded query.</p>`;
  return `<div class="table-wrap"><table><thead><tr><th>Observed</th><th>Event</th><th>Name</th><th>Path / binary</th><th>Account</th><th>Process relationship</th><th>Quality</th></tr></thead><tbody>${items
    .map((x) => {
      const o = x.service || x.scheduledTask,
        p = x.service?.process || x.scheduledTask?.process;
      return `<tr><td><a href="#/${kind}/${x.eventId}">${new Date(x.observedAt).toLocaleString()}</a></td><td>${esc(x.kind)}</td><td>${esc(o?.name || "Unknown")}</td><td><code>${esc(o?.binaryPath || o?.path || "Unavailable")}</code></td><td>${esc(o?.account || o?.principal || "Unknown")}</td><td>${esc(p?.processEntityId || p?.processId || "NOT OBSERVABLE BY SOURCE")}${p ? ` (${esc(p.attributionConfidence)})` : ""}</td><td>${esc(x.qualityState)}${x.dataQualityFlags?.length ? `: ${esc(x.dataQualityFlags.join(", "))}` : ""}</td></tr>`;
    })
    .join("")}</tbody></table></div>`;
}
async function persistenceSearch(kind) {
  try {
    const q = new URLSearchParams(location.hash.split("?")[1] || ""),
      path = kind === "services" ? "service-events" : "scheduled-task-events",
      b = await api(`/api/v1/${path}?${q}`);
    return `<form id="persistence-search" class="toolbar"><label>Name <input name="name" value="${esc(q.get("name") || "")}"></label><label>Path <input name="path" value="${esc(q.get("path") || "")}"></label><label>Account / principal <input name="account" value="${esc(q.get("account") || "")}"></label><label>State / result <input name="state" value="${esc(q.get("state") || "")}"></label><label>Process <input name="process" value="${esc(q.get("process") || "")}"></label><label>Quality <input name="quality" value="${esc(q.get("quality") || "")}"></label><button>Search</button><button type="button" id="persistence-export">Export JSONL</button></form><p id="persistence-export-status" role="status" aria-live="polite"></p>${persistenceTable(b.data.items || [], kind)}`;
  } catch (e) {
    return state(`${kind} search unavailable`, e.message);
  }
}
async function persistenceDetail(kind, id) {
  try {
    const path =
        kind === "services" ? "service-events" : "scheduled-task-events",
      x = (await api(`/api/v1/${path}/${id}`)).data,
      o = x.service || x.scheduledTask,
      h = (
        await api(
          `/api/v1/${kind}/${o.entityId}/history?endpointId=${x.endpointId}`,
        )
      ).data;
    return `<a href="#/${kind}">← Back to ${kind}</a><div class="detail-head"><div><h2>${esc(o.name)}</h2><p class="muted"><code>${esc(o.entityId)}</code></p></div><span class="badge">${esc(x.kind)}</span></div><div class="panels"><article><h3>Observed configuration</h3><dl><dt>Path / binary</dt><dd><code>${esc(o.binaryPath || o.path || "Unavailable")}</code></dd><dt>State</dt><dd>${esc(o.state ?? o.executionResult ?? "Unknown")}</dd><dt>Account / principal</dt><dd>${esc(o.account || o.principal || "Unknown")}</dd><dt>Type</dt><dd>${esc(o.serviceType || "Scheduled task")}</dd><dt>Enabled</dt><dd>${o.enabled == null ? "Unknown" : o.enabled ? "Yes" : "No"}</dd><dt>Arguments</dt><dd>${o.actions?.some((a) => a.redacted) ? "Redacted by policy" : "Unavailable or not collected"}</dd></dl></article><article><h3>Evidence-backed relationship</h3><dl><dt>Process entity</dt><dd><code>${esc(o.process?.processEntityId || "NOT OBSERVABLE BY SOURCE")}</code></dd><dt>PID</dt><dd>${o.process?.processId ?? "Unavailable"}</dd><dt>Attribution source</dt><dd>${esc(o.process?.attributionSource || "Unavailable")}</dd><dt>Confidence</dt><dd>${esc(o.process?.attributionConfidence || "Unknown")}</dd><dt>Mechanism</dt><dd>${esc(o.process?.correlationMechanism || "Unavailable")}</dd></dl></article><article><h3>Provenance and quality</h3><dl><dt>Provider</dt><dd>${esc(x.native.provider)}</dd><dt>Channel</dt><dd>${esc(x.native.channel)}</dd><dt>Event ID / record</dt><dd>${x.native.eventId} / ${x.native.recordId ?? "Unavailable"}</dd><dt>Native operation</dt><dd>${esc(x.native.nativeOperation)}</dd><dt>Evidence SHA-256</dt><dd><code>${esc(x.evidenceSha256)}</code></dd><dt>Quality</dt><dd>${esc(x.qualityState)} · ${esc((x.dataQualityFlags || []).join(", ") || "No flags")}</dd></dl></article></div><section><h2>Lifecycle and configuration history</h2>${persistenceTable(h.items || [], kind)}</section>${
      kind === "tasks"
        ? `<section><h2>Execution instances</h2>${persistenceTable(
            (h.items || []).filter((v) => /Execution/.test(v.kind)),
            kind,
          )}</section>`
        : ""
    }`;
  } catch (e) {
    return state(`${kind} detail unavailable`, e.message);
  }
}
async function exportPersistence(kind) {
  const out = document.querySelector("#persistence-export-status");
  out.textContent = "Export queued…";
  try {
    const query = Object.fromEntries(
      new URLSearchParams(location.hash.split("?")[1] || ""),
    );
    query.objectKind = kind === "services" ? "Service" : "ScheduledTask";
    const created = await api("/api/v1/persistence-exports", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ format: "jsonl", query, maximumRecords: 10000 }),
    });
    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 250));
      const job = (await api(`/api/v1/persistence-exports/${created.data.id}`))
        .data;
      if (job.state === "Completed") {
        const response = await fetch(
          `/api/v1/persistence-exports/${job.id}/content`,
          { headers: auth() },
        );
        if (!response.ok) throw Error(`status ${response.status}`);
        const url = URL.createObjectURL(await response.blob()),
          a = document.createElement("a");
        a.href = url;
        a.download = `${kind}-telemetry.jsonl`;
        a.click();
        URL.revokeObjectURL(url);
        out.textContent = "Export complete.";
        return;
      }
      if (job.state === "Failed") throw Error(job.errorCode || "export failed");
    }
    throw Error("export still pending");
  } catch (e) {
    out.textContent = `Export failed: ${e.message}`;
  }
}
function configurationTable(items) {
  if (!items.length)
    return '<p class="muted">No persistence configurations match this bounded query.</p>';
  return `<div class="table-wrap"><table><thead><tr><th>Observed</th><th>Category</th><th>Event</th><th>Name</th><th>Scope</th><th>Location</th><th>State</th><th>Raw evidence</th></tr></thead><tbody>${items
    .map((x) => {
      const c = x.configuration || {};
      return `<tr><td><a href="#/persistence-configurations/${x.eventId}">${new Date(x.observedAt).toLocaleString()}</a></td><td>${esc(c.category || "Unknown")} / ${esc(c.subtype || "Unknown")}</td><td>${esc(x.kind)}</td><td>${esc(c.name || "Unknown")}</td><td>${esc(c.scope || "Unknown")}</td><td><code>${esc(c.registryPath || c.filePath || c.namespaceOrLocation || "Unavailable")}</code></td><td>${esc(c.currentState || "Unknown")}</td><td>${(c.rawEvidenceEventIds || []).length}</td></tr>`;
    })
    .join("")}</tbody></table></div>`;
}
async function configurationSearch(wmiOnly = false) {
  try {
    const q = new URLSearchParams(location.hash.split("?")[1] || ""),
      request = new URLSearchParams(q);
    if (wmiOnly) request.delete("category");
    const response = await api(`/api/v1/persistence-configurations?${request}`),
      items = (response.data.items || []).filter(
        (x) => !wmiOnly || x.configuration?.category?.startsWith("wmi-"),
      );
    return `<p class="notice"><strong>Configuration evidence only.</strong> A configured action is not proof that it executed.</p><form id="configuration-search" class="toolbar"><label>Category <input name="category" value="${esc(q.get("category") || "")}" placeholder="autorun, com-registration, wmi-filter"></label><label>Subtype <input name="subtype" value="${esc(q.get("subtype") || "")}"></label><label>Name <input name="name" value="${esc(q.get("name") || "")}"></label><label>Path / location <input name="path" value="${esc(q.get("path") || "")}"></label><label>Scope <select name="scope"><option value="">Any</option>${["user", "machine"].map((v) => `<option ${q.get("scope") === v ? "selected" : ""}>${v}</option>`).join("")}</select></label><label>WMI namespace <input name="namespace" value="${esc(q.get("namespace") || "")}"></label><label>Endpoint ID <input name="endpointId" value="${esc(q.get("endpointId") || "")}"></label><button>Search</button><button type="button" id="configuration-export">Export JSONL</button></form><p id="configuration-export-status" role="status" aria-live="polite"></p>${configurationTable(items)}`;
  } catch (e) {
    return state("Persistence configurations unavailable", e.message);
  }
}
async function configurationDetail(id) {
  try {
    const x = (await api(`/api/v1/persistence-configurations/${id}`)).data,
      c = x.configuration,
      h = (
        await api(
          `/api/v1/persistence-configurations/${c.entityId}/history?endpointId=${x.endpointId}`,
        )
      ).data;
    return `<a href="#/persistence-configurations">← Back to configurations</a><p class="notice"><strong>Configured action — not execution.</strong> This record represents observed persistence configuration state.</p><div class="detail-head"><div><h2>${esc(c.name)}</h2><p class="muted"><code>${esc(c.entityId)}</code></p></div><span class="badge">${esc(c.currentState)}</span></div><div class="panels"><article><h3>Identity and configuration</h3><dl><dt>Category / subtype</dt><dd>${esc(c.category)} / ${esc(c.subtype)}</dd><dt>Native identity</dt><dd><code>${esc(c.nativeObjectIdentity)}</code></dd><dt>Namespace / location</dt><dd>${esc(c.namespaceOrLocation || "Unavailable")}</dd><dt>Registry path / view</dt><dd><code>${esc(c.registryPath || "Not applicable")}</code> / ${esc(c.registryView || "Not applicable")}</dd><dt>File path</dt><dd><code>${esc(c.filePath || "Not applicable")}</code></dd><dt>Scope / principal</dt><dd>${esc(c.scope || "Unknown")} / ${esc(c.principal || "Unknown")}</dd><dt>Generation</dt><dd>${c.generation}</dd></dl></article><article><h3>Configured behavior</h3><dl><dt>Action</dt><dd><code>${esc(c.actionPath || "Unavailable")}</code></dd><dt>Arguments</dt><dd>${c.redacted ? "Redacted by policy" : esc(c.arguments || "Not collected")}</dd><dt>Trigger</dt><dd>${esc(c.triggerMetadata || "Unavailable")}</dd><dt>Consumer</dt><dd>${esc(c.consumerMetadata || "Unavailable")}</dd><dt>Binding</dt><dd><code>${esc(c.bindingIdentity || "Not applicable")}</code></dd></dl></article><article><h3>Raw evidence relationship</h3><dl><dt>Registry entity</dt><dd><code>${esc(c.registryEntityId || "NOT OBSERVABLE BY SOURCE")}</code></dd><dt>File entity</dt><dd><code>${esc(c.fileEntityId || "NOT OBSERVABLE BY SOURCE")}</code></dd><dt>Raw event IDs</dt><dd>${(c.rawEvidenceEventIds || []).map((v) => `<code>${esc(v)}</code>`).join(" ") || "NOT OBSERVABLE BY SOURCE"}</dd><dt>Mapping rule / version</dt><dd>${esc(c.mappingRule)} / ${esc(c.mappingVersion)}</dd><dt>Confidence</dt><dd>${esc(c.relationshipConfidence)}${c.relationshipAmbiguous ? " (ambiguous)" : ""}</dd><dt>Quality</dt><dd>${esc(x.qualityState)} · ${esc((x.dataQualityFlags || []).join(", ") || "No flags")}</dd></dl></article></div><section><h2>Configuration history</h2>${configurationTable(h.items || [])}</section>`;
  } catch (e) {
    return state("Persistence configuration unavailable", e.message);
  }
}

async function hydratePersistenceResponse(kind, eventId) {
  const sourcePath = kind === "services" ? "service-events" : kind === "tasks" ? "scheduled-task-events" : "persistence-configurations";
  try {
    const observation = (await api(`/api/v1/${sourcePath}/${eventId}`)).data;
    const object = observation.service || observation.scheduledTask || observation.configuration;
    if (!object?.entityId) return;
    const [previewEnvelope, historyEnvelope] = await Promise.all([
      api(`/api/v1/endpoints/${observation.endpointId}/persistence/${object.entityId}/remediation-preview`),
      api(`/api/v1/endpoints/${observation.endpointId}/persistence-remediation-history`),
    ]);
    const preview = previewEnvelope.data;
    const actions = (historyEnvelope.data.items || []).filter((x) => x.sourceEntityId === object.entityId);
    const options = (preview.supportedActions || []).map((action) => `<option value="${esc(action)}">${esc(action)}</option>`).join("");
    document.querySelector("#content")?.insertAdjacentHTML("beforeend", `<section aria-labelledby="persistence-response-title"><div class="detail-head"><div><h2 id="persistence-response-title">Safe persistence remediation</h2><p>Every action is signed and bound to the endpoint installation, canonical native identity, lifecycle generation, expected state hash, and immutable evidence.</p></div><span class="badge">${preview.protected ? "Protected" : "Preview verified"}</span></div><div class="panels"><article><h3>Authoritative target</h3><dl><dt>Kind / category</dt><dd>${esc(preview.target.remediationKind)} / ${esc(preview.target.category)}</dd><dt>Canonical identity</dt><dd><code>${esc(preview.target.canonicalIdentity)}</code></dd><dt>Lifecycle generation</dt><dd>${preview.target.lifecycleGeneration}</dd><dt>Expected state hash</dt><dd><code>${esc(preview.target.expectedStateHash)}</code></dd><dt>Evidence references</dt><dd>${preview.target.evidenceReferences.length}</dd><dt>Dependencies</dt><dd>${preview.dependencies.length}</dd></dl></article><article><h3>Safety and reversibility</h3><dl><dt>Backup</dt><dd>${preview.backupSupported ? "Required before mutation" : "Unavailable"}</dd><dt>Restore</dt><dd>${preview.restoreSupported ? "Explicit verified restore supported" : "Unavailable"}</dd><dt>Protection</dt><dd>${esc(preview.protectionReason)}</dd><dt>Process relationships</dt><dd>${preview.processRelationshipCount}</dd></dl><p class="containment-warning"><strong>Warning:</strong> removal changes endpoint persistence state. Review the exact generation and dependency preview before approval.</p></article><article><h3>Analyst controls</h3>${options && !preview.protected ? '<button id="persistence-response-open">Open remediation dialog</button>' : '<p class="muted">No safe action is available for this object state.</p>'}<p id="persistence-response-status" role="status" aria-live="assertive" tabindex="-1"></p></article></div><dialog id="persistence-response-dialog" aria-labelledby="persistence-response-dialog-title"><form id="persistence-response-form"><h2 id="persistence-response-dialog-title">Confirm exact persistence remediation</h2><p><code>${esc(object.entityId)}</code></p><label>Action <select name="actionType">${options}</select></label><label>Required reason <textarea name="reason" required minlength="4" maxlength="1024"></textarea></label><p>The target fields are immutable. Destructive actions require separated approval of the exact parameter hash.</p><div class="danger"><button type="submit">Request signed action</button><button type="button" id="persistence-response-close">Cancel</button></div></form></dialog><h3>Immutable remediation history</h3>${actions.length ? `<ol class="timeline">${actions.map((action) => `<li><time>${new Date(action.requestedAt).toLocaleString()}</time> <a href="#/response-actions/${action.responseActionId}">${esc(action.actionType)}</a> — ${esc(action.state)} by ${esc(action.analystId)}</li>`).join("")}</ol>` : '<p class="muted">No remediation has been requested for this entity.</p>'}</section>`);
    const dialog = document.querySelector("#persistence-response-dialog");
    document.querySelector("#persistence-response-open")?.addEventListener("click", () => dialog.showModal());
    document.querySelector("#persistence-response-close")?.addEventListener("click", () => dialog.close());
    document.querySelector("#persistence-response-form")?.addEventListener("submit", async (event) => {
      event.preventDefault(); const status = document.querySelector("#persistence-response-status"); const values = Object.fromEntries(new FormData(event.currentTarget));
      try { const result = await api(`/api/v1/endpoints/${observation.endpointId}/persistence/${object.entityId}:remediate`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ actionType: values.actionType, reason: values.reason, ...responseSourceContext() }) }); dialog.close(); status.textContent = `Remediation action ${result.data.action.responseActionId} is ${result.data.action.state}.`; status.focus(); }
      catch (error) { status.textContent = `Remediation request failed: ${error.message}`; status.focus(); }
    });
  } catch (error) {
    document.querySelector("#content")?.insertAdjacentHTML("beforeend", `<section aria-labelledby="persistence-response-title"><h2 id="persistence-response-title">Safe persistence remediation</h2><p class="muted">No safe authoritative preview is available: ${esc(error.message)}</p></section>`);
  }
}

async function persistenceBackupList() {
  try {
    const items = (await api("/api/v1/persistence-remediation-backups")).data.items || [];
    return items.length ? `<div class="table-wrap"><table><caption>Encrypted endpoint-local persistence backups</caption><thead><tr><th>Created</th><th>Object</th><th>Endpoint</th><th>Generation</th><th>Integrity</th><th>State</th><th>Retention</th><th>Action</th></tr></thead><tbody>${items.map(({backup, action}) => `<tr><td>${new Date(backup.createdAt).toLocaleString()}</td><td>${esc(backup.target.remediationKind)}<br><code>${esc(backup.target.canonicalIdentity)}</code></td><td><code>${esc(backup.endpointId)}</code></td><td>${backup.target.lifecycleGeneration}</td><td>${esc(backup.integrityState)}</td><td>${esc(backup.state)}</td><td>${new Date(backup.retainUntil).toLocaleString()}</td><td><a href="#/persistence-backups/${backup.backupId}">Inspect / restore</a> · <a href="#/response-actions/${action.responseActionId}">Audit</a></td></tr>`).join("")}</tbody></table></div>` : state("No persistence backups", "No tenant-bound remediation backups are available.");
  } catch (error) { return state("Persistence backups unavailable", error.message); }
}

async function persistenceBackupDetail(id) {
  try {
    const {backup, action} = (await api(`/api/v1/persistence-remediation-backups/${id}`)).data;
    return `<a href="#/persistence-backups">← Persistence backups</a><div class="detail-head"><div><h2>${esc(backup.target.canonicalIdentity)}</h2><p><code>${esc(backup.backupId)}</code></p></div><span class="badge">${esc(backup.state)}</span></div><div class="panels"><article><h3>Exact backup identity</h3><dl><dt>Kind</dt><dd>${esc(backup.target.remediationKind)}</dd><dt>Entity</dt><dd><code>${esc(backup.target.persistenceEntityId)}</code></dd><dt>Generation</dt><dd>${backup.target.lifecycleGeneration}</dd><dt>Content SHA-256</dt><dd><code>${esc(backup.contentSha256)}</code></dd><dt>Encryption</dt><dd>${esc(backup.encryptionState)}</dd><dt>Integrity</dt><dd>${esc(backup.integrityState)}</dd></dl></article><article><h3>Lifecycle</h3><dl><dt>Created</dt><dd>${new Date(backup.createdAt).toLocaleString()}</dd><dt>Retain until</dt><dd>${new Date(backup.retainUntil).toLocaleString()}</dd><dt>Restore eligible</dt><dd>${backup.restoreEligible ? "Yes" : "No"}</dd><dt>Historical evidence</dt><dd>Preserved; restore creates a new audited action</dd></dl></article><article><h3>Explicit restore</h3>${backup.restoreEligible ? `<form id="persistence-backup-restore"><label>Required reason <textarea name="reason" required minlength="4" maxlength="1024"></textarea></label><button>Request verified restore</button></form>` : '<p class="muted">This backup is not restore eligible.</p>'}<p><a href="#/response-actions/${action.responseActionId}">Open original audit and evidence artifact</a></p><p id="persistence-backup-status" role="status" aria-live="assertive" tabindex="-1"></p></article></div>`;
  } catch (error) { return state("Persistence backup unavailable", error.message); }
}

async function restorePersistenceBackup(event, id) {
  event.preventDefault(); const out = document.querySelector("#persistence-backup-status");
  try { const values = Object.fromEntries(new FormData(event.currentTarget)); const result = await api(`/api/v1/persistence-remediation-backups/${id}:restore`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ reason: values.reason, ...responseSourceContext() }) }); out.textContent = `Restore action ${result.data.action.responseActionId} is ${result.data.action.state}.`; out.focus(); }
  catch (error) { out.textContent = `Restore request failed: ${error.message}`; out.focus(); }
}
async function exportConfigurations() {
  const out = document.querySelector("#configuration-export-status");
  out.textContent = "Export queued…";
  try {
    const query = Object.fromEntries(
      new URLSearchParams(location.hash.split("?")[1] || ""),
    );
    query.objectKind = "PersistenceConfiguration";
    const created = await api("/api/v1/persistence-exports", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ format: "jsonl", query, maximumRecords: 10000 }),
    });
    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 250));
      const job = (await api(`/api/v1/persistence-exports/${created.data.id}`))
        .data;
      if (job.state === "Completed") {
        const response = await fetch(
          `/api/v1/persistence-exports/${job.id}/content`,
          { headers: auth() },
        );
        if (!response.ok) throw Error(`status ${response.status}`);
        const url = URL.createObjectURL(await response.blob()),
          a = document.createElement("a");
        a.href = url;
        a.download = "persistence-configurations.jsonl";
        a.click();
        URL.revokeObjectURL(url);
        out.textContent = "Export complete.";
        return;
      }
      if (job.state === "Failed") throw Error(job.errorCode || "export failed");
    }
    throw Error("export still pending");
  } catch (e) {
    out.textContent = `Export failed: ${e.message}`;
  }
}
async function persistencePolicyList() {
  try {
    const items =
        (await api("/api/v1/persistence-telemetry/policies")).data || [],
      latest = [...new Map(items.map((x) => [x.name, x])).values()];
    return `<div class="toolbar"><p>Immutable metadata-first persistence collection policies.</p><a class="button" href="#/persistence-policies/new">Create policy</a></div>${latest.length ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Version</th><th>Services</th><th>Tasks</th><th>WMI</th><th>COM</th><th>Autorun/startup</th><th>Exclusions</th></tr></thead><tbody>${latest.map((x) => `<tr><td><a href="#/persistence-policies/${x.id}">${esc(x.name)}</a></td><td>${x.version}</td><td>${x.policy.servicesEnabled ? "On" : "Off"}</td><td>${x.policy.tasksEnabled ? "On" : "Off"}</td><td>${x.policy.wmiSubscriptionsEnabled !== false ? "On" : "Off"}</td><td>${x.policy.comRegistrationEnabled !== false ? "On" : "Off"}</td><td>${x.policy.autorunStartupEnabled !== false ? "On" : "Off"}</td><td>${(x.policy.exclusionRules || []).length}</td></tr>`).join("")}</tbody></table></div>` : state("No explicit policies", "Safe metadata-first defaults are active.")}`;
  } catch (e) {
    return state("Persistence policies unavailable", e.message);
  }
}
async function persistencePolicyPage(id) {
  if (id === "new")
    return `<form id="persistence-policy-editor" class="admin-grid"><fieldset><legend>Service and scheduled-task policy</legend><label>Name <input name="name" required maxlength="100"></label><label><input type="checkbox" name="servicesEnabled" checked> Service telemetry</label><label><input type="checkbox" name="tasksEnabled" checked> Scheduled-task telemetry</label><label><input type="checkbox" name="serviceProcessRelationships" checked> Service process relationships</label><label><input type="checkbox" name="taskProcessRelationships" checked> Task process relationships</label><label><input type="checkbox" name="actionMetadata" checked> Action metadata</label><label><input type="checkbox" name="triggerMetadata" checked> Trigger metadata</label><label><input type="checkbox" name="captureArguments"> Capture bounded arguments</label><label><input type="checkbox" name="captureTaskXml"> Process bounded task XML</label><label>Excluded service names, one per line <textarea name="excludedServiceNames"></textarea></label><label>Excluded task paths, one per line <textarea name="excludedTaskPaths"></textarea></label><button>Validate and save</button><p id="persistence-policy-error" role="alert" tabindex="-1"></p></fieldset></form>`;
  try {
    const x = (
      (await api("/api/v1/persistence-telemetry/policies")).data || []
    ).find((v) => v.id === id);
    if (!x)
      return state(
        "Policy unavailable",
        "This policy is not in the active tenant.",
      );
    return `<a href="#/persistence-policies">← Policies</a><h2>${esc(x.name)} <span class="badge">Version ${x.version}</span></h2><div class="panels"><article><h3>Collection</h3><dl><dt>Services</dt><dd>${x.policy.servicesEnabled ? "On" : "Off"}</dd><dt>Tasks</dt><dd>${x.policy.tasksEnabled ? "On" : "Off"}</dd><dt>Arguments</dt><dd>${x.policy.captureArguments ? "Bounded and redacted" : "Not collected"}</dd><dt>Task XML</dt><dd>${x.policy.captureTaskXml ? "Bounded parser enabled" : "Not collected"}</dd><dt>Queue bound</dt><dd>${x.policy.maximumQueueBytes} bytes</dd></dl><form id="persistence-policy-assign"><label>Endpoint ID <input name="endpointId" required pattern="[0-9a-fA-F-]{36}"></label><button>Assign</button><p role="status" aria-live="polite"></p></form></article><article><h3>Audited exclusions</h3>${(x.policy.exclusionRules || []).length ? `<ul>${x.policy.exclusionRules.map((r) => `<li>${esc(r.category)}: <code>${esc(r.pattern)}</code> — ${esc(r.reason)}</li>`).join("")}</ul>` : '<p class="muted">No exclusions.</p>'}<form id="persistence-exclusion-editor"><label>Category <select name="category"><option>service-name</option><option>service-type</option><option>service-executable</option><option>task-path</option><option>task-path-prefix</option><option>task-name</option><option>task-action</option><option>process</option><option>user</option></select></label><label>Pattern <input name="pattern" required maxlength="512"></label><label>Reason <input name="reason" required maxlength="256"></label><button>Add validated exclusion</button><p id="persistence-exclusion-error" role="alert"></p></form></article></div>`;
  } catch (e) {
    return state("Policy unavailable", e.message);
  }
}
async function savePersistencePolicy(e) {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    const result = await api("/api/v1/persistence-telemetry/policies", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: f.get("name"),
        policy: {
          servicesEnabled: f.has("servicesEnabled"),
          tasksEnabled: f.has("tasksEnabled"),
          wmiSubscriptionsEnabled: f.has("wmiSubscriptionsEnabled"),
          comRegistrationEnabled: f.has("comRegistrationEnabled"),
          autorunStartupEnabled: f.has("autorunStartupEnabled"),
          startupFolderEnabled: f.has("startupFolderEnabled"),
          ifeoMetadataEnabled: f.has("ifeoMetadataEnabled"),
          winlogonMetadataEnabled: f.has("winlogonMetadataEnabled"),
          appInitAppCertMetadataEnabled: f.has("appInitAppCertMetadataEnabled"),
          lsaPackageMetadataEnabled: f.has("lsaPackageMetadataEnabled"),
          serviceProcessRelationships: f.has("serviceProcessRelationships"),
          taskProcessRelationships: f.has("taskProcessRelationships"),
          actionMetadata: f.has("actionMetadata"),
          triggerMetadata: f.has("triggerMetadata"),
          captureArguments: f.has("captureArguments"),
          captureTaskXml: f.has("captureTaskXml"),
          excludedServiceNames: lines(f.get("excludedServiceNames")),
          excludedTaskPaths: lines(f.get("excludedTaskPaths")),
          includedPersistenceCategories: lines(
            f.get("includedPersistenceCategories"),
          ),
          excludedPersistenceCategories: lines(
            f.get("excludedPersistenceCategories"),
          ),
          includedPersistencePaths: lines(f.get("includedPersistencePaths")),
          excludedPersistencePaths: lines(f.get("excludedPersistencePaths")),
        },
      }),
    });
    location.hash = `#/persistence-policies/${result.data.id}`;
  } catch (error) {
    const out = document.querySelector("#persistence-policy-error");
    out.textContent = error.message;
    out.focus();
  }
}
async function assignPersistencePolicy(e, id) {
  e.preventDefault();
  const out = e.target.querySelector('[role="status"]');
  try {
    await api(`/api/v1/persistence-telemetry/policies/${id}:assign`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        endpointId: new FormData(e.target).get("endpointId"),
      }),
    });
    out.textContent = "Assignment accepted; agent acknowledgement pending.";
  } catch (error) {
    out.textContent = error.message;
  }
}
async function savePersistenceExclusion(e, id) {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    const result = await api(
      `/api/v1/persistence-telemetry/policies/${id}/exclusions`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: crypto.randomUUID(),
          category: f.get("category"),
          pattern: f.get("pattern"),
          reason: f.get("reason"),
          enabled: true,
        }),
      },
    );
    location.hash = `#/persistence-policies/${result.data.id}`;
  } catch (error) {
    document.querySelector("#persistence-exclusion-error").textContent =
      error.message;
  }
}
async function hydratePersistenceHealth(endpoint) {
  try {
    const h = (
        await api(
          `/api/v1/endpoints/${endpoint.id}/persistence-telemetry-health`,
        )
      ).data,
      degraded =
        h.sourceGaps ||
        h.sequenceGaps ||
        h.queueDrops ||
        h.normalizationFailures ||
        h.relationshipFailures;
    document
      .querySelector(".panels")
      ?.insertAdjacentHTML(
        "beforeend",
        `<article><div class="detail-head"><h3>Service/task telemetry health</h3><span class="badge">${!h.enabled ? "Disabled" : degraded ? "Degraded" : h.queueDepth ? "Recovering" : "Healthy"}</span></div><dl><dt>Service / task collectors</dt><dd>${esc(h.serviceCollectorState)} / ${esc(h.taskCollectorState)}</dd><dt>Source events</dt><dd>${h.sourceEvents}</dd><dt>Queue depth / age</dt><dd>${h.queueDepth} / ${h.oldestQueuedSeconds}s</dd><dt>Drops / exclusions</dt><dd>${h.queueDrops} / ${h.excludedEvents}</dd><dt>Source / sequence gaps</dt><dd>${h.sourceGaps} / ${h.sequenceGaps}</dd><dt>Relationship failures</dt><dd>${h.relationshipFailures}</dd><dt>Known limitations</dt><dd>${esc((h.knownLimitations || []).join("; ") || "None reported")}</dd></dl><a href="#/services?endpointId=${endpoint.id}">Services</a> · <a href="#/tasks?endpointId=${endpoint.id}">Scheduled tasks</a></article>`,
      );
  } catch {
    document
      .querySelector(".panels")
      ?.insertAdjacentHTML(
        "beforeend",
        '<article><h3>Service/task telemetry health</h3><p class="muted">No accepted health report.</p></article>',
      );
  }
}

async function persistencePolicyPageV9(id) {
  if (id !== "new") return persistencePolicyPage(id);
  return `<form id="persistence-policy-editor" class="admin-grid"><fieldset><legend>Persistence telemetry policy</legend><label>Name <input name="name" required maxlength="100"></label><label><input type="checkbox" name="servicesEnabled" checked> Service telemetry</label><label><input type="checkbox" name="tasksEnabled" checked> Scheduled-task telemetry</label><label><input type="checkbox" name="wmiSubscriptionsEnabled" checked> WMI subscription telemetry</label><label><input type="checkbox" name="comRegistrationEnabled" checked> COM and shell registration telemetry</label><label><input type="checkbox" name="autorunStartupEnabled" checked> Autorun/startup configuration telemetry</label><label><input type="checkbox" name="startupFolderEnabled" checked> Startup-folder telemetry</label><label><input type="checkbox" name="ifeoMetadataEnabled" checked> IFEO test-scope metadata</label><label><input type="checkbox" name="winlogonMetadataEnabled" checked> Winlogon metadata</label><label><input type="checkbox" name="appInitAppCertMetadataEnabled" checked> AppInit/AppCert metadata</label><label><input type="checkbox" name="lsaPackageMetadataEnabled" checked> LSA package metadata</label><label><input type="checkbox" name="serviceProcessRelationships" checked> Service process relationships</label><label><input type="checkbox" name="taskProcessRelationships" checked> Task process relationships</label><label><input type="checkbox" name="actionMetadata" checked> Bounded action metadata</label><label><input type="checkbox" name="triggerMetadata" checked> Bounded trigger metadata</label><label><input type="checkbox" name="captureArguments"> Capture bounded, redacted arguments</label><label><input type="checkbox" name="captureTaskXml"> Process bounded task XML</label><label>Included persistence categories, one per line <textarea name="includedPersistenceCategories"></textarea></label><label>Excluded persistence categories, one per line <textarea name="excludedPersistenceCategories"></textarea></label><label>Included persistence paths, one per line <textarea name="includedPersistencePaths"></textarea></label><label>Excluded persistence paths, one per line <textarea name="excludedPersistencePaths"></textarea></label><label>Excluded service names, one per line <textarea name="excludedServiceNames"></textarea></label><label>Excluded task paths, one per line <textarea name="excludedTaskPaths"></textarea></label><button>Validate and save</button><p id="persistence-policy-error" role="alert" tabindex="-1"></p></fieldset></form>`;
}
async function hydratePersistenceHealthV9(endpoint) {
  try {
    const h = (
        await api(
          `/api/v1/endpoints/${endpoint.id}/persistence-telemetry-health`,
        )
      ).data,
      degraded =
        h.sourceGaps ||
        h.sequenceGaps ||
        h.queueDrops ||
        h.normalizationFailures ||
        h.relationshipFailures ||
        h.orphanRelationships;
    document
      .querySelector(".panels")
      ?.insertAdjacentHTML(
        "beforeend",
        `<article><div class="detail-head"><h3>Persistence telemetry health</h3><span class="badge">${!h.enabled ? "Disabled" : degraded ? "Degraded" : h.queueDepth ? "Recovering" : "Healthy"}</span></div><dl><dt>Service / task / configuration collectors</dt><dd>${esc(h.serviceCollectorState)} / ${esc(h.taskCollectorState)} / ${esc(h.configurationCollectorState)}</dd><dt>WMI objects / bindings</dt><dd>${h.wmiObjects} / ${h.wmiBindings}</dd><dt>COM registrations</dt><dd>${h.comRegistrations}</dd><dt>Autorun / startup events</dt><dd>${h.autorunStartupEvents}</dd><dt>Raw registry / file inputs</dt><dd>${h.rawRegistryInputs} / ${h.rawFileInputs}</dd><dt>Orphan relationships</dt><dd>${h.orphanRelationships}</dd><dt>Queue depth / age</dt><dd>${h.queueDepth} / ${h.oldestQueuedSeconds}s</dd><dt>Drops / exclusions</dt><dd>${h.queueDrops} / ${h.excludedEvents}</dd><dt>Source / sequence gaps</dt><dd>${h.sourceGaps} / ${h.sequenceGaps}</dd><dt>Policy drift</dt><dd>${h.drift ? "Yes" : "No"}</dd><dt>Known limitations</dt><dd>${esc((h.knownLimitations || []).join("; ") || "None reported")}</dd></dl><a href="#/persistence-configurations?endpointId=${endpoint.id}">Configurations</a> · <a href="#/wmi-subscriptions?endpointId=${endpoint.id}">WMI subscriptions</a></article>`,
      );
  } catch {
    return hydratePersistenceHealth(endpoint);
  }
}

function identityTable(items) {
  if (!items.length)
    return '<p class="muted">No identity evidence matches this bounded query.</p>';
  return `<div class="table-wrap"><table><thead><tr><th>Observed</th><th>Native event</th><th>Account / SID</th><th>Logon / session</th><th>Token / integrity</th><th>Process relationship</th><th>Quality</th></tr></thead><tbody>${items.map((x) => `<tr><td><a href="#/identity/${x.eventId}">${new Date(x.observedAt).toLocaleString()}</a></td><td>${esc(x.kind)}<br><small>${esc(x.native?.provider)} / ${x.native?.eventId ?? "Unavailable"}</small></td><td>${esc(x.account?.canonicalName || x.account?.name || "Unknown")}<br><code>${esc(x.account?.sid || "Unknown")}</code></td><td>${esc(x.logon?.logonTypeLabel || "Unavailable")} (${x.logon?.nativeLogonType ?? "unknown"})<br>${esc(x.session?.state || x.logon?.result || "Unknown")}</td><td>${esc(x.token?.tokenType || "NOT OBSERVABLE BY SOURCE")} / ${esc(x.token?.integrityLevel || "Unknown")}${x.token?.elevated == null ? "" : x.token.elevated ? " / elevated" : " / not elevated"}</td><td><code>${esc(x.process?.processEntityId || "NOT OBSERVABLE BY SOURCE")}</code><br>${esc(x.process?.confidence || "")}</td><td>${esc(x.qualityState)}${x.logon?.incompleteLifecycle ? " · incomplete lifecycle" : ""}</td></tr>`).join("")}</tbody></table></div>`;
}
async function identitySearch() {
  try {
    const q = new URLSearchParams(location.hash.split("?")[1] || ""),
      b = await api(`/api/v1/identity-events?${q}`);
    return `<p class="notice"><strong>Investigation telemetry only.</strong> Native events and observed token state are distinguished; unknown values are not inferred.</p><form id="identity-search" class="toolbar"><label>Account <input name="account" value="${esc(q.get("account") || "")}"></label><label>SID <input name="sid" value="${esc(q.get("sid") || "")}"></label><label>Domain <input name="domain" value="${esc(q.get("domain") || "")}"></label><label>Logon type <input name="logonType" type="number" value="${esc(q.get("logonType") || "")}"></label><label>Result <input name="result" value="${esc(q.get("result") || "")}"></label><label>Source IP <input name="sourceIp" value="${esc(q.get("sourceIp") || "")}"></label><label>Session ID <input name="sessionId" type="number" value="${esc(q.get("sessionId") || "")}"></label><label>Integrity <input name="integrityLevel" value="${esc(q.get("integrityLevel") || "")}"></label><label>Privilege <input name="privilege" value="${esc(q.get("privilege") || "")}"></label><label>Process <input name="process" value="${esc(q.get("process") || "")}"></label><label>Endpoint <input name="endpointId" value="${esc(q.get("endpointId") || "")}"></label><button>Search</button><button type="button" id="identity-export">Export JSONL</button></form><p id="identity-export-status" role="status" aria-live="polite"></p>${identityTable(b.data.items || [])}`;
  } catch (e) {
    return state("Identity telemetry unavailable", e.message);
  }
}
async function identityDetail(id) {
  try {
    const x = (await api(`/api/v1/identity-events/${id}`)).data,
      entity =
        x.logon?.entityId ||
        x.session?.entityId ||
        x.token?.entityId ||
        x.process?.processEntityId,
      h = entity
        ? (
            await api(
              `/api/v1/identity-entities/${entity}/history?endpointId=${x.endpointId}`,
            )
          ).data
        : { items: [] };
    return `<a href="#/identity">← Identity search</a><div class="detail-head"><div><h2>${esc(x.account?.canonicalName || x.account?.name || "Unknown identity")}</h2><p class="muted"><code>${esc(x.account?.sid || "SID unavailable")}</code></p></div><span class="badge">${esc(x.kind)}</span></div><div class="panels"><article><h3>Native evidence</h3><dl><dt>Provider / channel</dt><dd>${esc(x.native.provider)} / ${esc(x.native.channel)}</dd><dt>Event ID / record</dt><dd>${x.native.eventId} / ${x.native.recordId ?? "Unavailable"}</dd><dt>Native operation / status</dt><dd>${esc(x.native.nativeOperation)} / ${esc(x.native.nativeStatus || "Unknown")}</dd><dt>Evidence SHA-256</dt><dd><code>${esc(x.evidenceSha256)}</code></dd><dt>Provenance</dt><dd>Native event</dd></dl></article><article><h3>Logon and session</h3><dl><dt>Logon ID</dt><dd>${esc(x.logon?.logonId || "Unknown")}</dd><dt>Native / normalized type</dt><dd>${x.logon?.nativeLogonType ?? "Unknown"} / ${esc(x.logon?.logonTypeLabel || "Unknown")}</dd><dt>Status / substatus</dt><dd>${esc(x.logon?.status || "Unknown")} / ${esc(x.logon?.subStatus || "Unknown")}</dd><dt>Source peer</dt><dd>${esc(x.logon?.sourceIp || "NOT OBSERVABLE BY SOURCE")}</dd><dt>Session / state</dt><dd>${x.session?.sessionId ?? "Unknown"} / ${esc(x.session?.state || "Unknown")}</dd><dt>Lifecycle</dt><dd>${x.logon?.incompleteLifecycle ? "Incomplete lifecycle" : "Complete or state-only"}</dd></dl></article><article><h3>Observed token state</h3><dl><dt>Provenance</dt><dd>${esc(x.token?.provenance || "Unavailable")}</dd><dt>Type / impersonation</dt><dd>${esc(x.token?.tokenType || "Unknown")} / ${esc(x.token?.impersonationLevel || "Not applicable")}</dd><dt>Elevation</dt><dd>${esc(x.token?.elevationType || "Unknown")} / ${x.token?.elevated == null ? "Unknown" : x.token.elevated ? "Elevated" : "Not elevated"}</dd><dt>Integrity</dt><dd>${esc(x.token?.integrityLevel || "Unknown")}</dd><dt>Restrictions / AppContainer</dt><dd>${x.token?.restricted ?? "Unknown"} / ${x.token?.appContainer ?? "Unknown"}</dd></dl></article><article><h3>Privilege and process context</h3><dl><dt>Privileges</dt><dd>${esc((x.privileges || []).map((p) => `${p.name}: ${p.state}`).join("; ") || "None observed")}</dd><dt>Groups</dt><dd>${esc((x.groups || []).map((g) => g.sid).join("; ") || "Not observed")}</dd><dt>Process entity</dt><dd><code>${esc(x.process?.processEntityId || "NOT OBSERVABLE BY SOURCE")}</code></dd><dt>PID reuse protection</dt><dd>${x.process?.pidReuseProtected ? "Yes" : "Unavailable"}</dd><dt>Relationship mechanism</dt><dd>${esc(x.process?.mechanism || "Unavailable")}</dd></dl></article></div><section><h2>Identity lifecycle history</h2>${identityTable(h.items || [])}</section>`;
  } catch (e) {
    return state("Identity evidence unavailable", e.message);
  }
}
async function exportIdentity() {
  const out = document.querySelector("#identity-export-status");
  out.textContent = "Export queued…";
  try {
    const query = Object.fromEntries(
      new URLSearchParams(location.hash.split("?")[1] || ""),
    );
    const created = await api("/api/v1/identity-exports", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ format: "jsonl", query, maximumRecords: 10000 }),
    });
    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 250));
      const job = (await api(`/api/v1/identity-exports/${created.data.id}`))
        .data;
      if (job.state === "Completed") {
        const response = await fetch(
          `/api/v1/identity-exports/${job.id}/content`,
          { headers: auth() },
        );
        if (!response.ok) throw Error(`status ${response.status}`);
        const url = URL.createObjectURL(await response.blob()),
          a = document.createElement("a");
        a.href = url;
        a.download = "identity-telemetry.jsonl";
        a.click();
        URL.revokeObjectURL(url);
        out.textContent = "Export complete.";
        return;
      }
      if (job.state === "Failed") throw Error(job.errorCode || "export failed");
    }
    throw Error("export still pending");
  } catch (e) {
    out.textContent = `Export failed: ${e.message}`;
  }
}
async function identityPolicyList() {
  try {
    const items = (await api("/api/v1/identity-telemetry/policies")).data || [];
    return `<div class="toolbar"><p>Immutable identity collection policies with audited, exact-match exclusions.</p><a class="button" href="#/identity-policies/new">Create policy</a></div>${items.length ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Version</th><th>Logons</th><th>Sessions</th><th>Token state</th><th>Exclusions</th></tr></thead><tbody>${items.map((x) => `<tr><td>${esc(x.name)}</td><td>${x.version}</td><td>${x.policy.successfulLogons && x.policy.failedLogons ? "On" : "Partial"}</td><td>${x.policy.sessionState ? "On" : "Off"}</td><td>${x.policy.tokenState ? "On" : "Off"}</td><td>${(x.policy.exclusionRules || []).length}</td></tr>`).join("")}</tbody></table></div>` : state("No explicit policies", "Safe defaults remain active, including SYSTEM and service identities.")}`;
  } catch (e) {
    return state("Identity policies unavailable", e.message);
  }
}
async function identityPolicyPage() {
  return `<form id="identity-policy-editor" class="admin-grid"><fieldset><legend>Identity telemetry policy</legend><label>Name <input name="name" required maxlength="100"></label><label><input type="checkbox" name="successfulLogons" checked> Successful logons</label><label><input type="checkbox" name="failedLogons" checked> Failed logons</label><label><input type="checkbox" name="logoffs" checked> Logoffs</label><label><input type="checkbox" name="sessionState" checked> Session and RDP state</label><label><input type="checkbox" name="specialPrivileges" checked> Special privilege assignments</label><label><input type="checkbox" name="groupContext" checked> Group context</label><label><input type="checkbox" name="tokenState" checked> Bounded observed token state</label><label><input type="checkbox" name="integrityElevation" checked> Integrity and elevation</label><label><input type="checkbox" name="processRelationships" checked> Evidence-backed process relationships</label><label>Excluded exact SIDs, one per line <textarea name="excludedSids"></textarea></label><label>Excluded exact accounts, one per line <textarea name="excludedAccounts"></textarea></label><label>Excluded privilege names, one per line <textarea name="excludedPrivileges"></textarea></label><button>Validate and save</button><p id="identity-policy-error" role="alert" tabindex="-1"></p></fieldset></form>`;
}
async function saveIdentityPolicy(e) {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    const policy = {
      successfulLogons: f.has("successfulLogons"),
      failedLogons: f.has("failedLogons"),
      logoffs: f.has("logoffs"),
      sessionState: f.has("sessionState"),
      rdpSessions: f.has("sessionState"),
      specialPrivileges: f.has("specialPrivileges"),
      groupContext: f.has("groupContext"),
      tokenState: f.has("tokenState"),
      integrityElevation: f.has("integrityElevation"),
      processRelationships: f.has("processRelationships"),
      excludedSids: lines(f.get("excludedSids")),
      excludedAccounts: lines(f.get("excludedAccounts")),
      excludedPrivileges: lines(f.get("excludedPrivileges")),
    };
    await api("/api/v1/identity-telemetry/policies", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: f.get("name"), policy }),
    });
    location.hash = "#/identity-policies";
  } catch (error) {
    const out = document.querySelector("#identity-policy-error");
    out.textContent = error.message;
    out.focus();
  }
}
async function hydrateIdentityHealth(endpoint) {
  try {
    const h = (
        await api(`/api/v1/endpoints/${endpoint.id}/identity-telemetry-health`)
      ).data,
      degraded =
        h.sourceGaps ||
        h.sequenceGaps ||
        h.queueDrops ||
        h.processRelationshipFailures;
    document
      .querySelector(".panels")
      ?.insertAdjacentHTML(
        "beforeend",
        `<article aria-labelledby="identity-health-title"><div class="detail-head"><h3 id="identity-health-title">Identity telemetry health</h3><span class="badge">${!h.enabled ? "Disabled" : degraded ? "Degraded" : h.queueDepth ? "Recovering" : "Healthy"}</span></div><dl><dt>Security / session / token collectors</dt><dd>${esc(h.securityCollectorState)} / ${esc(h.sessionCollectorState)} / ${esc(h.tokenCollectorState)}</dd><dt>Successful / failed / logoff</dt><dd>${h.successfulLogons} / ${h.failedLogons} / ${h.logoffs}</dd><dt>Session / RDP</dt><dd>${h.sessionEvents} / ${h.rdpEvents}</dd><dt>Token / privilege observations</dt><dd>${h.tokenObservations} / ${h.privilegeObservations}</dd><dt>Queue depth / age / drops</dt><dd>${h.queueDepth} / ${h.oldestQueuedSeconds}s / ${h.queueDrops}</dd><dt>Source / sequence gaps</dt><dd>${h.sourceGaps} / ${h.sequenceGaps}</dd><dt>Policy drift</dt><dd>${h.drift ? "Yes" : "No"}</dd><dt>Known limitations</dt><dd>${esc((h.knownLimitations || []).join("; ") || "None reported")}</dd></dl><a href="#/identity?endpointId=${endpoint.id}">Endpoint identity timeline</a></article>`,
      );
  } catch {
    document
      .querySelector(".panels")
      ?.insertAdjacentHTML(
        "beforeend",
        '<article><h3>Identity telemetry health</h3><p class="muted">No accepted identity health report.</p></article>',
      );
  }
}
async function hydrateProcessIdentity(endpoint, entity) {
  try {
    const b = (
      await api(`/api/v1/processes/${entity}/identity?endpointId=${endpoint}`)
    ).data;
    document
      .querySelector(".panels")
      ?.insertAdjacentHTML(
        "beforeend",
        `<article><h3>Identity and token context</h3>${identityTable(b.items || [])}</article>`,
      );
  } catch {}
}

function executionTable(items) {
  if (!items.length)
    return '<p class="muted">No supported low-level execution evidence matches this bounded query.</p>';
  return `<div class="table-wrap"><table><thead><tr><th>Observed</th><th>Native operation</th><th>Source</th><th>Target / thread</th><th>Access / memory</th><th>Quality</th></tr></thead><tbody>${items.map((x) => `<tr><td><a href="#/execution/${x.eventId}">${new Date(x.observedAt).toLocaleString()}</a></td><td>${esc(x.kind)}<br><small>${esc(x.native?.provider)} / ${esc(x.native?.nativeOperation)}</small></td><td>${esc(x.sourceProcess?.imagePath || "NOT OBSERVABLE BY SOURCE")}<br><code>${esc(x.sourceProcess?.processEntityId || "Unavailable")}</code></td><td>${esc(x.targetProcess?.imagePath || "Unavailable")}<br>${x.thread ? `TID ${x.thread.threadId} · ${x.thread.startAddress ?? "start unavailable"}` : "No thread evidence"}</td><td>${x.handle ? `${esc(x.handle.handleType)} 0x${Number(x.handle.desiredAccess).toString(16)} · ${esc((x.handle.desiredAccessFlags || []).join(", ") || "raw mask only")}` : x.memory ? `${x.memory.baseAddress} + ${x.memory.size} · ${esc((x.memory.protectionFlags || []).join("/"))}` : "NOT OBSERVABLE BY SOURCE"}</td><td>${esc(x.qualityState)}<br>${esc((x.dataQualityFlags || []).join(", ") || "No flags")}</td></tr>`).join("")}</tbody></table></div>`;
}
async function executionSearch() {
  try {
    const q = new URLSearchParams(location.hash.split("?")[1] || ""),
      b = await api(`/api/v1/execution-events?${q}`);
    return `<p class="notice"><strong>Investigation telemetry only.</strong> Requested access is not proof of an operation. No memory contents, injection labels, detections, or scoring are collected.</p><form id="execution-search" class="toolbar"><label>Source process <input name="sourceProcess" value="${esc(q.get("sourceProcess") || "")}"></label><label>Target process <input name="targetProcess" value="${esc(q.get("targetProcess") || "")}"></label><label>Source PID <input type="number" name="sourcePid" value="${esc(q.get("sourcePid") || "")}"></label><label>Target PID <input type="number" name="targetPid" value="${esc(q.get("targetPid") || "")}"></label><label>Operation <input name="operation" value="${esc(q.get("operation") || "")}"></label><label>Handle type <input name="handleType" value="${esc(q.get("handleType") || "")}"></label><label>Access flag <input name="accessFlag" value="${esc(q.get("accessFlag") || "")}"></label><label>Thread ID <input type="number" name="threadId" value="${esc(q.get("threadId") || "")}"></label><label>Section identity <input name="sectionIdentity" value="${esc(q.get("sectionIdentity") || "")}"></label><label>Endpoint <input name="endpointId" value="${esc(q.get("endpointId") || "")}"></label><button>Search</button><button type="button" id="execution-export">Export JSONL</button></form><p id="execution-export-status" role="status" aria-live="polite"></p>${executionTable(b.data.items || [])}`;
  } catch (e) {
    return state("Execution telemetry unavailable", e.message);
  }
}
async function executionDetail(id) {
  try {
    const x = (await api(`/api/v1/execution-events/${id}`)).data,
      entity =
        x.thread?.threadEntityId ||
        x.memory?.regionEntityId ||
        x.section?.sectionEntityId ||
        x.targetProcess?.processEntityId ||
        x.sourceProcess?.processEntityId,
      h = entity
        ? (
            await api(
              `/api/v1/execution-entities/${entity}/history?endpointId=${x.endpointId}`,
            )
          ).data
        : { items: [] };
    return `<a href="#/execution">← Execution search</a><p class="notice">Native evidence and normalized metadata only. No memory contents or maliciousness claim.</p><div class="detail-head"><div><h2>${esc(x.native.nativeOperation)}</h2><p class="muted"><code>${esc(x.eventId)}</code></p></div><span class="badge">${esc(x.kind)}</span></div><div class="panels"><article><h3>Native evidence</h3><dl><dt>Provider / channel</dt><dd>${esc(x.native.provider)} / ${esc(x.native.channel)}</dd><dt>Native identity</dt><dd><code>${esc(x.native.nativeEventIdentity)}</code></dd><dt>Status</dt><dd>${esc(x.native.nativeStatus || "Unknown")}</dd><dt>Evidence SHA-256</dt><dd><code>${esc(x.evidenceSha256)}</code></dd></dl></article><article><h3>Process relationship</h3><dl><dt>Source</dt><dd><code>${esc(x.sourceProcess?.processEntityId || "NOT OBSERVABLE BY SOURCE")}</code></dd><dt>Target</dt><dd><code>${esc(x.targetProcess?.processEntityId || "NOT OBSERVABLE BY SOURCE")}</code></dd><dt>PID reuse protection</dt><dd>${x.sourceProcess?.pidReuseProtected || x.targetProcess?.pidReuseProtected ? "Yes" : "Unavailable"}</dd><dt>Confidence</dt><dd>${esc((x.relationships || []).map((r) => `${r.relation}: ${r.confidence}`).join("; ") || "No relationship asserted")}</dd></dl></article><article><h3>Handle / thread</h3><dl><dt>Handle type</dt><dd>${esc(x.handle?.handleType || "Not applicable")}</dd><dt>Desired / granted mask</dt><dd>${x.handle ? `0x${Number(x.handle.desiredAccess).toString(16)} / ${x.handle.grantedAccess == null ? "NOT OBSERVABLE" : `0x${Number(x.handle.grantedAccess).toString(16)}`}` : "Not applicable"}</dd><dt>Operation confirmed</dt><dd>${x.handle?.operationConfirmed ? "Yes" : "No — request evidence only"}</dd><dt>Thread / start</dt><dd>${x.thread?.threadId ?? "Not applicable"} / ${x.thread?.startAddress ?? "Unavailable"}</dd><dt>Creator relationship</dt><dd>${x.thread?.crossProcess == null ? "NOT OBSERVABLE BY SOURCE" : x.thread.crossProcess ? "Cross-process" : "Same-process"}</dd></dl></article><article><h3>Memory / section</h3><dl><dt>Memory range</dt><dd>${x.memory ? `${x.memory.baseAddress} + ${x.memory.size}` : "NOT OBSERVABLE BY SOURCE"}</dd><dt>Protection</dt><dd>${esc((x.memory?.protectionFlags || []).join("/") || "NOT OBSERVABLE BY SOURCE")}</dd><dt>Section</dt><dd><code>${esc(x.section?.sectionEntityId || "NOT OBSERVABLE BY SOURCE")}</code></dd><dt>Quality</dt><dd>${esc(x.qualityState)} · ${esc((x.dataQualityFlags || []).join(", ") || "No flags")}</dd></dl></article></div><section><h2>Entity history</h2>${executionTable(h.items || [])}</section>`;
  } catch (e) {
    return state("Execution evidence unavailable", e.message);
  }
}
async function exportExecution() {
  const out = document.querySelector("#execution-export-status");
  out.textContent = "Export queued…";
  try {
    const query = Object.fromEntries(
      new URLSearchParams(location.hash.split("?")[1] || ""),
    );
    const created = await api("/api/v1/execution-exports", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ format: "jsonl", query, maximumRecords: 10000 }),
    });
    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 250));
      const job = (await api(`/api/v1/execution-exports/${created.data.id}`))
        .data;
      if (job.state === "Completed") {
        const response = await fetch(
          `/api/v1/execution-exports/${job.id}/content`,
          { headers: auth() },
        );
        if (!response.ok) throw Error(`status ${response.status}`);
        const url = URL.createObjectURL(await response.blob()),
          a = document.createElement("a");
        a.href = url;
        a.download = "execution-telemetry.jsonl";
        a.click();
        URL.revokeObjectURL(url);
        out.textContent = "Export complete.";
        return;
      }
      if (job.state === "Failed") throw Error(job.errorCode || "export failed");
    }
    throw Error("export still pending");
  } catch (e) {
    out.textContent = `Export failed: ${e.message}`;
  }
}
async function executionPolicyList() {
  try {
    const items =
      (await api("/api/v1/execution-telemetry/policies")).data || [];
    return `<div class="toolbar"><p>Versioned low-level execution collection policies. Memory collection defaults off when no trustworthy native source exists.</p><a class="button" href="#/execution-policies/new">Create policy</a></div>${items.length ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Version</th><th>Handles</th><th>Threads</th><th>Memory</th><th>Exclusions</th></tr></thead><tbody>${items.map((x) => `<tr><td>${esc(x.name)}</td><td>${x.version}</td><td>${x.policy.handleTelemetry ? "On" : "Off"}</td><td>${x.policy.threadCreation ? "On" : "Off"}</td><td>${x.policy.memoryAllocation ? "On" : "Source unavailable"}</td><td>${(x.policy.exclusionRules || []).length}</td></tr>`).join("")}</tbody></table></div>` : state("No explicit policies", "Safe rate-limited defaults are active.")}`;
  } catch (e) {
    return state("Execution policies unavailable", e.message);
  }
}
async function executionPolicyPage() {
  return `<form id="execution-policy-editor" class="admin-grid"><fieldset><legend>Low-level execution telemetry policy</legend><label>Name <input name="name" required maxlength="100"></label><label><input type="checkbox" name="handleTelemetry" checked> Handle request telemetry</label><label><input type="checkbox" name="processHandles" checked> Process handles</label><label><input type="checkbox" name="threadHandles" checked> Thread handles</label><label><input type="checkbox" name="threadCreation" checked> Thread creation</label><label><input type="checkbox" name="remoteThreadEvents" checked> Remote-thread evidence where source proves it</label><label><input type="checkbox" name="startAddressMetadata" checked> Native start-address metadata</label><label>Included source processes, one per line <textarea name="includedSourceProcesses"></textarea></label><label>Included target processes, one per line <textarea name="includedTargetProcesses"></textarea></label><label>Excluded source processes, one per line <textarea name="excludedSourceProcesses"></textarea></label><label>Excluded target processes, one per line <textarea name="excludedTargetProcesses"></textarea></label><label>Excluded operations, one per line <textarea name="excludedOperations"></textarea></label><button>Validate and save</button><p id="execution-policy-error" role="alert" tabindex="-1"></p></fieldset></form>`;
}
async function saveExecutionPolicy(e) {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    const policy = {
      handleTelemetry: f.has("handleTelemetry"),
      processHandles: f.has("processHandles"),
      threadHandles: f.has("threadHandles"),
      threadCreation: f.has("threadCreation"),
      remoteThreadEvents: f.has("remoteThreadEvents"),
      startAddressMetadata: f.has("startAddressMetadata"),
      includedSourceProcesses: lines(f.get("includedSourceProcesses")),
      includedTargetProcesses: lines(f.get("includedTargetProcesses")),
      excludedSourceProcesses: lines(f.get("excludedSourceProcesses")),
      excludedTargetProcesses: lines(f.get("excludedTargetProcesses")),
      excludedOperations: lines(f.get("excludedOperations")),
    };
    await api("/api/v1/execution-telemetry/policies", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: f.get("name"), policy }),
    });
    location.hash = "#/execution-policies";
  } catch (error) {
    const out = document.querySelector("#execution-policy-error");
    out.textContent = error.message;
    out.focus();
  }
}
async function hydrateExecutionHealth(endpoint) {
  try {
    const h = (
        await api(`/api/v1/endpoints/${endpoint.id}/execution-telemetry-health`)
      ).data,
      degraded =
        h.sourceDrops ||
        h.sequenceGaps ||
        h.queueDrops ||
        h.relationshipFailures;
    document
      .querySelector(".panels")
      ?.insertAdjacentHTML(
        "beforeend",
        `<article><div class="detail-head"><h3>Low-level execution health</h3><span class="badge">${!h.enabled ? "Disabled" : degraded ? "Degraded" : h.queueDepth ? "Recovering" : "Healthy"}</span></div><dl><dt>Handle / thread collectors</dt><dd>${esc(h.handleCollectorState)} / ${esc(h.threadCollectorState)}</dd><dt>Memory / section sources</dt><dd>${esc(h.memoryCollectorState)} / ${esc(h.sectionCollectorState)}</dd><dt>Handle / thread events</dt><dd>${h.processHandleEvents + h.threadHandleEvents} / ${h.threadCreations}</dd><dt>Queue depth / age / drops</dt><dd>${h.queueDepth} / ${h.oldestQueuedSeconds}s / ${h.queueDrops}</dd><dt>Source / sequence gaps</dt><dd>${h.sourceDrops} / ${h.sequenceGaps}</dd><dt>Known limitations</dt><dd>${esc((h.knownLimitations || []).join("; ") || "None reported")}</dd></dl><a href="#/execution?endpointId=${endpoint.id}">Endpoint execution timeline</a></article>`,
      );
  } catch {
    document
      .querySelector(".panels")
      ?.insertAdjacentHTML(
        "beforeend",
        '<article><h3>Low-level execution health</h3><p class="muted">No accepted execution health report.</p></article>',
      );
  }
}
async function hydrateProcessExecution(endpoint, entity) {
  try {
    const b = (
      await api(`/api/v1/processes/${entity}/execution?endpointId=${endpoint}`)
    ).data;
    document
      .querySelector(".panels")
      ?.insertAdjacentHTML(
        "beforeend",
        `<article><h3>Low-level execution evidence</h3>${executionTable(b.items || [])}</article>`,
      );
  } catch {}
}

function detectionStatus(x) {
  return x.status === "Active" && x.enabled
    ? "Production"
    : x.status === "Disabled"
      ? "Disabled"
      : x.status;
}
async function detectionList() {
  try {
    const items = (await api("/api/v1/detection-rules")).data || [];
    return `<div class="toolbar"><p>Versioned, declarative rules. Starter rules are controlled engine fixtures, not production detection content.</p><a class="button" href="#/detections/new">New bounded rule</a></div>${items.length ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Version</th><th>Domain</th><th>Type</th><th>Status</th><th>Severity</th><th>Validation</th></tr></thead><tbody>${items.map((x) => `<tr><td><a href="#/detections/${x.detectionId}">${esc(x.name)}</a></td><td>${x.detectionVersion}</td><td>${esc(x.domain)}</td><td>${esc(x.ruleType)}</td><td><span class="badge">${esc(detectionStatus(x))}</span></td><td>${x.severity}</td><td>${x.lastValidationPassed ? "Passed" : "Required"}</td></tr>`).join("")}</tbody></table></div>` : state("No detection rules", "Create a bounded draft and run its required fixtures before activation.")}`;
  } catch (e) {
    return state("Detection rules unavailable", e.message);
  }
}
async function detectionContent() {
  try {
    const [catalog, coverage, gaps] = await Promise.all([
      api("/api/v1/detection-content/catalog"),
      api("/api/v1/detection-content/coverage"),
      api("/api/v1/detection-content/gaps"),
    ]), q = new URLSearchParams(location.hash.split("?")[1] || ""),
      pack = q.get("pack") || "", domain = q.get("domain") || "", status = q.get("status") || "",
      minimum = Number(q.get("minimumSeverity") || 0), search = (q.get("search") || "").toLowerCase(),
      all = catalog.data || [], packs = [...new Set(all.map(x => x.pack))].sort(), domains = [...new Set(all.map(x => x.domain))].sort(),
      items = all.filter(x => (!pack || x.pack === pack) && (!domain || x.domain === domain) && (!status || x.status === status) && x.severity >= minimum && (!search || `${x.name} ${x.rationale} ${(x.mitreTechniques || []).join(" ")}`.toLowerCase().includes(search)));
    return `<section aria-labelledby="production-content-title"><div class="detail-head"><div><h2 id="production-content-title">Production detection content</h2><p>Source-supported, versioned Windows analytics. Activation requires schema validation, the complete fixture campaign, and bounded historical simulation.</p></div><span class="badge">${all.filter(x => x.enabled).length}/${all.length} active</span></div>
      <form id="detection-content-filter" class="toolbar" role="search"><label>Search <input name="search" value="${esc(q.get("search") || "")}" placeholder="name, rationale, ATT&CK"></label><label>Pack <select name="pack"><option value="">All</option>${packs.map(x=>`<option ${pack===x?"selected":""}>${esc(x)}</option>`).join("")}</select></label><label>Domain <select name="domain"><option value="">All</option>${domains.map(x=>`<option ${domain===x?"selected":""}>${esc(x)}</option>`).join("")}</select></label><label>Status <select name="status"><option value="">All</option>${["Active","Disabled","Draft","NotInstalled"].map(x=>`<option ${status===x?"selected":""}>${x}</option>`).join("")}</select></label><label>Minimum severity <input type="number" name="minimumSeverity" min="0" max="100" value="${minimum}"></label><button>Apply filters</button></form>
      <div class="table-wrap"><table><caption>${items.length} production detection rules matching current filters</caption><thead><tr><th>Rule</th><th>Pack / domain</th><th>ATT&amp;CK</th><th>Severity / confidence</th><th>State</th><th>Quality evidence</th></tr></thead><tbody>${items.map(x=>`<tr><td><a href="#/detections/${esc(x.detectionId)}">${esc(x.name)}</a><br><small>${esc(x.rationale)}</small></td><td>${esc(x.pack)}<br>${esc(x.domain)}</td><td>${esc((x.mitreTechniques||[]).join(", "))}</td><td>${x.severity} / ${x.confidence}</td><td><span class="badge">${esc(x.status)}</span><br>v${x.version}</td><td>${x.fixtureCount} fixtures<br>${x.validationPassed?"Validated":"Validation required"}</td></tr>`).join("")}</tbody></table></div></section>
      <section aria-labelledby="production-coverage-title"><h2 id="production-coverage-title">Evidence-based ATT&amp;CK coverage</h2><div class="table-wrap"><table><caption>Coverage requires active rules and fixture evidence; mappings alone do not count</caption><thead><tr><th>Tactic</th><th>Technique</th><th>Telemetry</th><th>Active rules</th><th>Fixtures</th><th>Support</th></tr></thead><tbody>${(coverage.data||[]).map(x=>`<tr><td>${esc(x.tactic)}</td><td>${esc(x.technique)}</td><td>${esc((x.telemetry||[]).join(", "))}</td><td>${x.activeRules}/${(x.rules||[]).length}</td><td>${x.fixtureEvidence}</td><td><span class="badge">${esc(x.support)}</span></td></tr>`).join("")}</tbody></table></div></section>
      <section aria-labelledby="coverage-gaps-title"><h2 id="coverage-gaps-title">Known coverage gaps</h2><div class="table-wrap"><table><caption>Unsupported and externally blocked qualification surfaces</caption><thead><tr><th>Area</th><th>Status</th><th>Reason</th></tr></thead><tbody>${(gaps.data||[]).map(x=>`<tr><td>${esc(x.area)}</td><td><span class="badge">${esc(x.status)}</span></td><td>${esc(x.reason)}</td></tr>`).join("")}</tbody></table></div></section>`;
  } catch (e) { return state("Production content unavailable", e.message); }
}
async function detectionDetail(id) {
  try {
    const [rule, history, tests] = await Promise.all([
        api(`/api/v1/detection-rules/${id}`),
        api(`/api/v1/detection-rules/${id}/versions`),
        api(`/api/v1/detection-rule-versions/${id}/1/tests`).catch(() => ({
          data: [],
        })),
      ]),
      x = rule.data;
    return `<a href="#/detections">← Detection rules</a><div class="detail-head"><div><h2>${esc(x.name)}</h2><p class="muted"><code>${esc(x.detectionId)}</code> · immutable version ${x.detectionVersion}</p></div><span class="badge">${esc(detectionStatus(x))}</span></div><div class="panels"><article><h3>Classification</h3><dl><dt>Severity / confidence</dt><dd>${x.severity} / ${x.confidence}</dd><dt>Domain / type</dt><dd>${esc(x.domain)} / ${esc(x.ruleType)}</dd><dt>MITRE</dt><dd>${esc((x.mitreTechniques || []).join(", ") || "Not assigned")}</dd><dt>Data sources</dt><dd>${esc((x.dataSources || []).join(", "))}</dd></dl></article><article><h3>Bounded execution</h3><dl><dt>Window / threshold</dt><dd>${x.windowSeconds}s / ${x.threshold}</dd><dt>Group by</dt><dd>${esc((x.groupBy || []).join(", ") || "Endpoint/entity default")}</dd><dt>Required fields</dt><dd>${esc((x.requiredFields || []).join(", ") || "None")}</dd><dt>Suppression</dt><dd>${esc(x.suppression?.scope)} / ${x.suppression?.durationMinutes || 0}m</dd></dl></article><article><h3>Evidence contract</h3><pre tabindex="0">${esc(JSON.stringify(x.condition, null, 2))}</pre></article></div><section><h2>Version history</h2><div class="table-wrap"><table><thead><tr><th>Version</th><th>Status</th><th>Validated</th><th>Activated</th></tr></thead><tbody>${history.data.map((v) => `<tr><td>${v.detectionVersion}</td><td>${esc(v.status)}</td><td>${v.lastValidationPassed ? "Passed" : "No"}</td><td>${v.activatedAt ? new Date(v.activatedAt).toLocaleString() : "Never"}</td></tr>`).join("")}</tbody></table></div></section><section><h2>Test results</h2><p>${tests.data.length ? esc(tests.data.map((t) => `${t.kind}: ${(t.item3?.passed ?? t.result?.passed) ? "PASS" : "FAIL"}`).join(" · ")) : "No fixture results recorded."}</p></section>`;
  } catch (e) {
    return state("Detection details unavailable", e.message);
  }
}
async function detectionEditor() {
  return `<form id="detection-editor" class="admin-grid"><fieldset><legend>Bounded declarative detection</legend><p class="notice">No SQL, JavaScript, C#, shell, unrestricted regex, or user code is accepted.</p><label>Name <input name="name" required maxlength="200"></label><label>Description <textarea name="description" required maxlength="4000"></textarea></label><label>Domain <select name="domain">${["Process", "File", "Registry", "Network", "Dns", "Module", "Persistence", "Identity", "Execution"].map((x) => `<option>${x}</option>`).join("")}</select></label><label>Rule type <select name="ruleType"><option>Event</option><option>Entity</option><option>Threshold</option></select></label><label>Severity (0–100) <input name="severity" type="number" min="0" max="100" value="50" required></label><label>Confidence (0–100) <input name="confidence" type="number" min="0" max="100" value="80" required></label><label>Window seconds (max 604800) <input name="window" type="number" min="0" max="604800" value="30" required></label><label>Threshold (max 100000) <input name="threshold" type="number" min="1" max="100000" value="1" required></label><label>Required fields, comma separated <input name="requiredFields" maxlength="500"></label><label>Group fields, comma separated <input name="groupBy" maxlength="200"></label><label>Condition tree JSON <textarea name="condition" required aria-describedby="dsl-help">{"logic":"Predicate","field":"path","operator":"ExactPath","value":"C:\\\\Sprint12Fixtures\\\\controlled.exe"}</textarea></label><small id="dsl-help">Maximum 8 levels and 64 nodes. Fields are allowlisted per domain.</small><button>Save draft</button><p id="detection-editor-error" role="alert" tabindex="-1"></p></fieldset></form>`;
}
async function saveDetection(e) {
  e.preventDefault();
  const f = new FormData(e.target),
    now = new Date().toISOString();
  try {
    const split = (n) =>
        String(f.get(n) || "")
          .split(",")
          .map((x) => x.trim())
          .filter(Boolean),
      body = {
        schemaVersion: "detection-rule.v1",
        detectionId: crypto.randomUUID(),
        detectionVersion: 1,
        tenantId: "00000000-0000-0000-0000-000000000000",
        name: f.get("name"),
        description: f.get("description"),
        status: "Draft",
        enabled: false,
        author: "ui",
        createdAt: now,
        updatedAt: now,
        severity: Number(f.get("severity")),
        confidence: Number(f.get("confidence")),
        category: "custom",
        tags: [],
        mitreTactics: [],
        mitreTechniques: [],
        dataSources: [f.get("domain")],
        ruleType: f.get("ruleType"),
        domain: f.get("domain"),
        prerequisites: [],
        requiredFields: split("requiredFields"),
        windowSeconds: Number(f.get("window")),
        groupBy: split("groupBy"),
        threshold: Number(f.get("threshold")),
        distinctCount: false,
        distinctField: null,
        condition: JSON.parse(f.get("condition")),
        evaluationMode: "Live",
        suppression: { scope: "detection+endpoint", durationMinutes: 0 },
        exclusionReferences: [],
      },
      created = await api("/api/v1/detection-rules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    location.hash = `#/detections/${created.data.detectionId}`;
  } catch (error) {
    const out = document.querySelector("#detection-editor-error");
    out.textContent = `Rule was not saved: ${error.message}`;
    out.focus();
  }
}
function findingTable(items) {
  if (!items.length)
    return '<p class="muted">No analyst-visible findings match this bounded query.</p>';
  return `<div class="table-wrap"><table><thead><tr><th>Created</th><th>Rule</th><th>Version</th><th>Severity</th><th>Mode</th><th>Evidence</th><th>State</th></tr></thead><tbody>${items.map((x) => `<tr><td><a href="#/findings/${x.findingId}">${new Date(x.createdAt).toLocaleString()}</a></td><td>${esc(x.ruleName)}</td><td>${x.detectionVersion}</td><td>${x.severity}</td><td>${esc(x.executionMode)}</td><td>${x.matchingEventIds.length}</td><td>${x.excluded ? "Excluded" : x.suppressed ? "Suppressed" : x.missingTelemetry.length ? "Missing telemetry" : "Production finding"}</td></tr>`).join("")}</tbody></table></div>`;
}
async function findingSearch() {
  try {
    const q = new URLSearchParams(location.hash.split("?")[1] || ""),
      b = await api(`/api/v1/findings?${q}`);
    return `<form id="finding-search" class="toolbar"><label>Detection ID <input name="detectionId" value="${esc(q.get("detectionId") || "")}"></label><label>Endpoint ID <input name="endpointId" value="${esc(q.get("endpointId") || "")}"></label><label>Minimum severity <input type="number" name="minimumSeverity" min="0" max="100" value="${esc(q.get("minimumSeverity") || "")}"></label><label>Mode <select name="mode"><option value="">Any</option>${["Live", "HistoricalReplay", "Simulation", "DryRun"].map((x) => `<option ${q.get("mode") === x ? "selected" : ""}>${x}</option>`).join("")}</select></label><button>Search</button></form>${findingTable(b.data.items || [])}`;
  } catch (e) {
    return state("Findings unavailable", e.message);
  }
}
async function findingDetail(id) {
  try {
    const [finding, evidence, conditions, rule] = await Promise.all([
        api(`/api/v1/findings/${id}`),
        api(`/api/v1/findings/${id}/evidence`),
        api(`/api/v1/findings/${id}/matched-conditions`),
        api(`/api/v1/findings/${id}/rule-version`),
      ]),
      x = finding.data;
    return `<a href="#/findings">← Findings</a><div class="detail-head"><div><h2>${esc(x.ruleName)}</h2><p class="muted"><code>${esc(x.findingId)}</code></p></div><span class="badge">${esc(x.executionMode)}</span></div><div class="panels"><article><h3>Exact rule</h3><dl><dt>Detection</dt><dd><a href="#/detections/${x.detectionId}">${esc(x.detectionId)}</a></dd><dt>Immutable version</dt><dd>${x.detectionVersion}</dd><dt>Engine</dt><dd>${esc(x.engineVersion)}</dd><dt>Severity / confidence</dt><dd>${x.severity} / ${x.confidence}</dd></dl></article><article><h3>Evidence</h3><dl><dt>Events</dt><dd>${x.eventCount}</dd><dt>References</dt><dd>${evidence.data.evidenceReferences.map((v) => `<code>${esc(v)}</code>`).join("<br>")}</dd><dt>Quality</dt><dd>${esc((x.telemetryQuality || []).join(", ") || "Complete")}</dd><dt>Missing telemetry</dt><dd>${esc((x.missingTelemetry || []).join(", ") || "None")}</dd></dl></article><article><h3>Suppression / exclusion</h3><dl><dt>Suppressed</dt><dd>${x.suppressed ? "Yes" : "No"}</dd><dt>Reason</dt><dd>${esc(x.suppressionReason || "Not applicable")}</dd><dt>Excluded</dt><dd>${x.excluded ? "Yes" : "No"}</dd></dl></article></div><section><h2>Why this matched</h2><div class="table-wrap"><table><thead><tr><th>Condition</th><th>Field</th><th>Actual</th><th>Expected</th><th>Result</th></tr></thead><tbody>${conditions.data.map((v) => `<tr><td>${esc(v.operator)}</td><td>${esc(v.field || v.path)}</td><td><code>${esc(v.actualValue)}</code></td><td><code>${esc(v.expectedValue)}</code></td><td>${v.matched ? "Matched" : "Not matched"}</td></tr>`).join("")}</tbody></table></div><details><summary>Rule version snapshot</summary><pre tabindex="0">${esc(JSON.stringify(rule.data, null, 2))}</pre></details></section>`;
  } catch (e) {
    return state("Finding details unavailable", e.message);
  }
}
async function replayPage() {
  const now = new Date(),
    before = new Date(now - 3600000);
  return `<form id="replay-form" class="admin-grid"><fieldset><legend>Bounded authoritative replay</legend><p>Simulation is the default. PostgreSQL authority is queried with a fixed immutable rule version.</p><label>Detection ID <input name="detectionId" required></label><label>Version <input type="number" name="version" min="1" value="1" required></label><label>From <input type="datetime-local" name="from" value="${before.toISOString().slice(0, 16)}" required></label><label>To <input type="datetime-local" name="to" value="${now.toISOString().slice(0, 16)}" required></label><button>Start simulation replay</button><p id="replay-status" role="status" aria-live="polite" tabindex="-1"></p></fieldset></form>`;
}
async function startReplay(e) {
  e.preventDefault();
  const f = new FormData(e.target),
    out = document.querySelector("#replay-status");
  try {
    out.textContent = "Replay running…";
    const b = await api("/api/v1/detection-replays", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        detectionId: f.get("detectionId"),
        version: Number(f.get("version")),
        from: new Date(f.get("from")).toISOString(),
        to: new Date(f.get("to")).toISOString(),
        productionFindings: false,
      }),
    });
    out.textContent = `Replay ${b.data.run.status}: ${b.data.run.eventsEvaluated}/${b.data.run.eventsTotal} events, ${b.data.run.findings} simulated findings.`;
    out.focus();
  } catch (error) {
    out.textContent = `Replay failed: ${error.message}`;
    out.focus();
  }
}
async function detectionHealth() {
  try {
    const h = (await api("/api/v1/detection-health")).data;
    return `<div class="panels"><article><h2>Evaluation</h2><dl><dt>Events evaluated</dt><dd>${h.eventsEvaluated}</dd><dt>Rules evaluated</dt><dd>${h.rulesEvaluated}</dd><dt>Matches</dt><dd>${h.matches}</dd><dt>Failures</dt><dd>${h.evaluationFailures}</dd><dt>Compile failures</dt><dd>${h.compileFailures}</dd></dl></article><article><h2>Finding outcomes</h2><dl><dt>Findings</dt><dd>${h.findings}</dd><dt>Suppressed</dt><dd>${h.suppressed}</dd><dt>Excluded</dt><dd>${h.excluded}</dd><dt>Missing fields</dt><dd>${h.missingFields}</dd><dt>Missing telemetry</dt><dd>${h.missingTelemetry}</dd></dl></article><article><h2>Replay and latency</h2><dl><dt>Replay queue</dt><dd>${h.replayQueueDepth}</dd><dt>Replay duration</dt><dd>${h.lastReplayDurationMilliseconds} ms</dd><dt>Evaluation latency</dt><dd>${h.lastEvaluationLatencyMilliseconds} ms</dd><dt>Projection latency</dt><dd>${h.lastProjectionLatencyMilliseconds} ms</dd><dt>Updated</dt><dd>${new Date(h.updatedAt).toLocaleString()}</dd></dl></article></div>`;
  } catch (e) {
    return state("Detection health unavailable", e.message);
  }
}

async function correlationRules(id) {
  try {
    if (id) {
      const [rb, hb, tb] = await Promise.all([
          api(`/api/v1/correlation-rules/${id}`),
          api(`/api/v1/correlation-rules/${id}/versions`),
          api(`/api/v1/correlation-rule-versions/${id}/1/tests`).catch(() => ({
            data: [],
          })),
        ]),
        x = rb.data;
      return `<a href="#/correlation-rules">Back to correlation rules</a><div class="detail-head"><div><h2>${esc(x.name)}</h2><p class="muted"><code>${esc(x.correlationRuleId)}</code> · immutable v${x.version}</p></div><span class="badge">${esc(x.status)}</span></div><div class="panels"><article><h3>Correlation contract</h3><dl><dt>Type</dt><dd>${esc(x.type)}</dd><dt>Window</dt><dd>${x.windowSeconds}s</dd><dt>Join keys</dt><dd>${esc((x.joinKeys || []).join(", "))}</dd><dt>Entity scope</dt><dd>${esc(x.entityScope)}</dd></dl></article><article><h3>Evidence and quality</h3><dl><dt>Telemetry</dt><dd>${esc((x.requiredTelemetry || []).join(", "))}</dd><dt>Known benign</dt><dd>${esc((x.quality?.knownBenignCases || []).join("; "))}</dd><dt>Tuning</dt><dd>${esc(x.quality?.tuningGuidance)}</dd><dt>Limitations</dt><dd>${esc((x.quality?.supportLimitations || []).join("; "))}</dd></dl></article><article><h3>MITRE</h3><dl><dt>Tactic</dt><dd>${esc(x.mitreTactic)}</dd><dt>Technique</dt><dd>${esc(x.mitreTechnique)}</dd><dt>Severity / confidence</dt><dd>${x.severity} / ${x.confidence}</dd></dl></article></div><section><h2>Ordered steps</h2><ol class="timeline">${(
        x.steps || []
      )
        .sort((a, b) => a.order - b.order)
        .map(
          (s) =>
            `<li><strong>${esc(s.id)}</strong> — ${esc(s.inputKind)} ${esc(s.domain || s.detectionId)}; minimum ${s.minimumCount}${s.distinct ? " distinct" : ""}</li>`,
        )
        .join(
          "",
        )}</ol></section><section><h2>Immutable history and tests</h2><p>${hb.data.map((v) => `v${v.version} ${esc(v.status)}`).join(" · ")}</p><p>${tb.data.map((t) => `${esc(t.kind)}: ${t.passed ? "PASS" : "FAIL"}`).join(" · ") || "No tests recorded"}</p></section>`;
    }
    const [rules, packs] = await Promise.all([
      api("/api/v1/correlation-rules"),
      api("/api/v1/correlation-packs"),
    ]);
    return `<p>Bounded, declarative, versioned stateful correlations. No user code is executed.</p><section><h2>Rule packs</h2><div class="table-wrap"><table><thead><tr><th>Pack</th><th>Version</th><th>Rules</th><th>Validation</th><th>State</th></tr></thead><tbody>${(packs.data || []).map((x) => `<tr><td>${esc(x.name)}</td><td>${x.version}</td><td>${x.ruleIds.length}</td><td>${x.validationPassed ? "PASS" : "Required"}</td><td>${x.enabled ? "Production" : "Disabled"}</td></tr>`).join("")}</tbody></table></div></section><section><h2>Correlation rules</h2><div class="table-wrap"><table><thead><tr><th>Name</th><th>Type</th><th>Window</th><th>MITRE</th><th>Severity</th><th>Status</th></tr></thead><tbody>${(rules.data || []).map((x) => `<tr><td><a href="#/correlation-rules/${x.correlationRuleId}">${esc(x.name)}</a></td><td>${esc(x.type)}</td><td>${x.windowSeconds}s</td><td>${esc(x.mitreTechnique)}</td><td>${x.severity}</td><td><span class="badge">${esc(x.status)}</span></td></tr>`).join("")}</tbody></table></div></section>`;
  } catch (e) {
    return state("Correlation rules unavailable", e.message);
  }
}
function correlatedFindingTable(items) {
  if (!items.length)
    return `<p class="muted">No correlated findings match this tenant-bound query.</p>`;
  return `<div class="table-wrap"><table><thead><tr><th>Completed</th><th>Rule</th><th>Severity</th><th>Confidence</th><th>Domains</th><th>Evidence</th><th>Quality</th></tr></thead><tbody>${items.map((x) => `<tr><td><a href="#/correlated-findings/${x.correlatedFindingId}">${new Date(x.createdAt).toLocaleString()}</a></td><td>${esc(x.ruleName)}</td><td>${x.severity}</td><td>${x.confidence}</td><td>${esc((x.sourceDomains || []).join(", "))}</td><td>${x.evidenceEventIds.length + x.childFindingIds.length}</td><td>${x.incompleteEvidence ? "Incomplete" : x.lateEvidence ? "Late" : "Complete"}</td></tr>`).join("")}</tbody></table></div>`;
}
async function correlatedFindings(id) {
  try {
    if (id) {
      const [fb, eb, tb, rb] = await Promise.all([
          api(`/api/v1/correlated-findings/${id}`),
          api(`/api/v1/correlated-findings/${id}/evidence`),
          api(`/api/v1/correlated-findings/${id}/timeline`),
          api(`/api/v1/correlated-findings/${id}/entity-relationships`),
        ]),
        x = fb.data;
      return `<a href="#/correlated-findings">Back to correlated findings</a><div class="detail-head"><div><h2>${esc(x.ruleName)}</h2><p><code>${esc(x.correlatedFindingId)}</code></p></div><span class="badge">${esc(x.completionState)}</span></div><div class="panels"><article><h3>Why this completed</h3><p>${esc(x.explanation)}</p><dl><dt>Rule / pack versions</dt><dd>${x.correlationRuleVersion} / ${x.packVersion}</dd><dt>Engine</dt><dd>${esc(x.engineVersion)}</dd><dt>Correlation key</dt><dd><code>${esc(x.correlationKey)}</code></dd></dl></article><article><h3>Evidence quality</h3><dl><dt>Events / child findings</dt><dd>${x.evidenceEventIds.length} / ${x.childFindingIds.length}</dd><dt>Missing telemetry</dt><dd>${esc((x.missingRequiredTelemetry || []).join(", ") || "None")}</dd><dt>Late / incomplete</dt><dd>${x.lateEvidence ? "Yes" : "No"} / ${x.incompleteEvidence ? "Yes" : "No"}</dd><dt>Maximum ingestion delay</dt><dd>${x.maximumIngestionDelayMilliseconds}ms</dd></dl></article><article><h3>Relationships</h3><p>${rb.data.map(esc).join(" · ") || "None"}</p><h3>Matched values</h3><p>${esc((eb.data.matchedValues || []).join(" · "))}</p></article></div><section><h2>Correlation timeline</h2><ol class="timeline">${tb.data.map((v) => `<li><strong>${esc(v.stepId)}</strong> ${new Date(v.eventTime).toLocaleString()} — ${esc(v.domain || "Detection finding")}<small>${esc(v.evidenceReference)}</small></li>`).join("")}</ol></section>`;
    }
    const q = new URLSearchParams(location.hash.split("?")[1] || ""),
      b = await api(`/api/v1/correlated-findings?${q}`);
    return `<form id="correlation-search" class="toolbar"><label>Rule ID <input name="ruleId" value="${esc(q.get("ruleId") || "")}"></label><label>Endpoint ID <input name="endpointId" value="${esc(q.get("endpointId") || "")}"></label><label>Minimum severity <input type="number" name="minimumSeverity" min="0" max="100" value="${esc(q.get("minimumSeverity") || "")}"></label><button>Search</button></form>${correlatedFindingTable(b.data.items || [])}`;
  } catch (e) {
    return state("Correlated findings unavailable", e.message);
  }
}
async function correlationReplay() {
  const now = new Date(),
    before = new Date(now - 3600000);
  return `<form id="correlation-replay-form" class="admin-grid"><fieldset><legend>Bounded correlation replay</legend><p>Replay defaults to simulation and never creates production findings.</p><label>Correlation rule ID <input name="correlationRuleId" required></label><label>Immutable version <input name="version" type="number" min="1" value="1" required></label><label>From <input type="datetime-local" name="from" value="${before.toISOString().slice(0, 16)}" required></label><label>To <input type="datetime-local" name="to" value="${now.toISOString().slice(0, 16)}" required></label><button>Start simulation replay</button><p id="correlation-replay-status" role="status" aria-live="polite" tabindex="-1"></p></fieldset></form>`;
}
async function startCorrelationReplay(e) {
  e.preventDefault();
  const f = new FormData(e.target),
    out = document.querySelector("#correlation-replay-status");
  try {
    const b = await api("/api/v1/correlation-replays", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          correlationRuleId: f.get("correlationRuleId"),
          version: Number(f.get("version")),
          from: new Date(f.get("from")).toISOString(),
          to: new Date(f.get("to")).toISOString(),
          productionFindings: false,
        }),
      }),
      r = b.data.run;
    out.textContent = `Replay ${r.status}: ${r.observationsEvaluated}/${r.observationsTotal} observations, ${r.findings} findings. Authoritative source: ${b.data.authoritativeSource ? "yes" : "controlled fixture"}.`;
  } catch (error) {
    out.textContent = `Replay failed: ${error.message}`;
  }
  out.focus();
}
async function correlationHealth() {
  try {
    const h = (await api("/api/v1/correlation-health")).data;
    return `<div class="panels"><article><h2>State</h2><dl><dt>Evaluated</dt><dd>${h.correlationsEvaluated}</dd><dt>Active state objects</dt><dd>${h.activeStateObjects}</dd><dt>Expired</dt><dd>${h.expiredStates}</dd><dt>Completed / incomplete</dt><dd>${h.completedCorrelations} / ${h.incompleteCorrelations}</dd></dl></article><article><h2>Quality</h2><dl><dt>Late events</dt><dd>${h.lateEvents}</dd><dt>Duplicates</dt><dd>${h.duplicateEvents}</dd><dt>Missing telemetry</dt><dd>${h.missingTelemetry}</dd><dt>Suppressed / excluded</dt><dd>${h.suppressed} / ${h.excluded}</dd></dl></article><article><h2>Performance</h2><dl><dt>State latency</dt><dd>${h.stateStoreLatencyMilliseconds}ms</dd><dt>Evaluation latency</dt><dd>${h.evaluationLatencyMilliseconds}ms</dd><dt>Replay latency</dt><dd>${h.replayLatencyMilliseconds}ms</dd><dt>Replay queue</dt><dd>${h.replayQueueDepth}</dd></dl></article></div>`;
  } catch (e) {
    return state("Correlation health unavailable", e.message);
  }
}
async function mitreCoverage() {
  try {
    const rows = (await api("/api/v1/mitre-coverage")).data || [];
    return `<p>Coverage is evidence-based: implementation, fixture tests, telemetry availability, and production activation are shown independently.</p><div class="table-wrap"><table><thead><tr><th>Tactic</th><th>Technique</th><th>Rules</th><th>Telemetry</th><th>Available</th><th>Tested</th><th>Production</th></tr></thead><tbody>${rows.map((x) => `<tr><td>${esc(x.tactic)}</td><td>${esc(x.technique)}</td><td>${esc(x.ruleNames.join(", "))}</td><td>${esc(x.requiredTelemetry.join(", "))}</td><td>${x.telemetryAvailable ? "PASS" : "BLOCKED"}</td><td>${x.detectionTested ? "PASS" : "FAIL"}</td><td>${x.productionActive ? "Active" : "Inactive"}</td></tr>`).join("")}</tbody></table></div>`;
  } catch (e) {
    return state("MITRE coverage unavailable", e.message);
  }
}

const investigationRoot = () =>
  new URLSearchParams(location.hash.split("?")[1] || "").get("root") || "";

async function recentProcessContexts(pageSize = 25) {
  const response = await api(`/api/v1/processes?pageSize=${pageSize}`);
  return response.data.items || [];
}

function processContextPicker(items, message = "Choose an observed process to build its lineage.", destination = "process-tree") {
  if (!items.length)
    return state(
      "No process telemetry available",
      "No evidence-backed process is available in the current 24-hour window.",
      '<a class="button" href="#/processes">Open process search</a>',
    );
  const action = destination === "entity-graph" ? "Open graph" : "View lineage";
  return `<section class="process-context-picker" aria-labelledby="process-context-title"><div class="detail-head"><div><span class="section-eyebrow">STARTING POINT</span><h2 id="process-context-title">Select a process</h2><p>${esc(message)}</p></div><a class="button" href="#/processes">Advanced process search</a></div><div class="table-wrap"><table><caption>Recently observed processes available for investigation</caption><thead><tr><th>Observed</th><th>Process</th><th>PID</th><th>Endpoint</th><th>Action</th></tr></thead><tbody>${items.map((item) => `<tr><td>${new Date(item.startTime).toLocaleString()}</td><td><strong>${esc(item.executableName || item.name || "Unknown process")}</strong><br><code>${esc(item.executablePath || item.path || "Path not collected")}</code></td><td>${item.processId ?? item.pid ?? "Unknown"}</td><td><code>${esc(item.endpointId)}</code></td><td><a class="button" href="#/${destination}?root=${encodeURIComponent(item.processEntityId)}&endpointId=${encodeURIComponent(item.endpointId)}">${action}</a></td></tr>`).join("")}</tbody></table></div></section>`;
}

async function resolveProcessContext(root, endpointId) {
  if (root && endpointId) return { root, endpointId, recent: null };
  const recent = await recentProcessContexts();
  const match = root
    ? recent.find((item) => item.processEntityId === root)
    : recent.find((item) => !endpointId || item.endpointId === endpointId);
  return {
    root: root || match?.processEntityId || "",
    endpointId: endpointId || match?.endpointId || "",
    recent,
  };
}
function responseSourceQuery(extra = {}) {
  const current = new URLSearchParams(location.hash.split("?")[1] || ""),
    query = new URLSearchParams(extra);
  for (const name of ["alertId", "incidentId"])
    if (current.get(name)) query.set(name, current.get(name));
  const value = query.toString();
  return value ? `?${value}` : "";
}
function responseSourceContext() {
  const query = new URLSearchParams(location.hash.split("?")[1] || "");
  return { sourceAlertId: query.get("alertId") || null, sourceIncidentId: query.get("incidentId") || null, sourceEntityId: query.get("entityId") || null };
}
function entityResponseLinks(entity) {
  if (!entity.endpointId) return "Not applicable";
  const links = [`<a href="#/forensic-collections/new${responseSourceQuery({ endpointId: entity.endpointId, entityId: entity.entityId })}">Collect bounded evidence</a>`];
  if (entity.type === "Process") links.unshift(`<a href="#/processes/${entity.endpointId}/${encodeURIComponent(entity.entityId)}${responseSourceQuery()}">Safe process response</a>`);
  return links.join("<br>");
}
function entityTable(items) {
  return items.length
    ? `<div class="table-wrap"><table><caption>Evidence-backed entities</caption><thead><tr><th>Observed</th><th>Type</th><th>Entity</th><th>Evidence</th><th>Quality</th><th>Response</th></tr></thead><tbody>${items.map((x) => `<tr><td>${new Date(x.firstObserved).toLocaleString()}</td><td><span class="badge">${esc(x.type)}</span></td><td><code>${esc(x.entityId)}</code><br>${esc(x.displayName)}</td><td>${(x.evidenceIds || []).length} exact IDs</td><td>${x.ambiguous ? "Ambiguous" : esc((x.dataQuality || []).join(", ") || "Complete")}</td><td>${entityResponseLinks(x)}</td></tr>`).join("")}</tbody></table></div>`
    : state(
        "No entities",
        "No evidence-backed entities matched the bounded traversal.",
      );
}
function relationshipTable(items) {
  return items.length
    ? `<div class="table-wrap"><table><caption>Relationship accessibility alternative</caption><thead><tr><th>Source</th><th>Relationship</th><th>Destination</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>${items.map((x) => `<tr><td><code>${esc(x.sourceEntityId)}</code></td><td>${esc(x.relationshipType)}${x.ambiguous ? " (ambiguous)" : ""}</td><td><code>${esc(x.destinationEntityId)}</code></td><td>${x.confidence}</td><td>${(x.sourceEvidenceIds || []).length}</td></tr>`).join("")}</tbody></table></div>`
    : state(
        "No relationships",
        "No relationship is shown without exact source evidence.",
      );
}
function entityGraphMarkup(nodes, edges, rootEntityId) {
  const bounded = (nodes || []).slice(0, 32),
    width = 1120,
    height = Math.max(480, Math.ceil(Math.max(1, bounded.length) / 8) * 180 + 120),
    positions = new Map();
  bounded.forEach((node, index) => {
    const columns = Math.min(8, Math.max(1, bounded.length)),
      row = Math.floor(index / columns),
      column = index % columns,
      rowCount = Math.min(columns, bounded.length - row * columns),
      spacing = width / (rowCount + 1);
    positions.set(node.entityId, { x: Math.round(spacing * (column + 1)), y: 95 + row * 180 });
  });
  const lines = (edges || []).filter((edge) => positions.has(edge.sourceEntityId) && positions.has(edge.destinationEntityId)).slice(0, 100).map((edge) => {
    const source = positions.get(edge.sourceEntityId), destination = positions.get(edge.destinationEntityId);
    return `<line x1="${source.x}" y1="${source.y}" x2="${destination.x}" y2="${destination.y}" class="${edge.ambiguous ? "ambiguous" : "observed"}"><title>${esc(edge.relationshipType)} · confidence ${edge.confidence}</title></line>`;
  }).join("");
  const cards = bounded.map((node) => {
    const position = positions.get(node.entityId), selected = node.entityId === rootEntityId;
    return `<button type="button" class="entity-map-node type-${statusClass(node.type)}${selected ? " selected" : ""}" data-entity-id="${esc(node.entityId)}" style="--node-x:${position.x}px;--node-y:${position.y}px"><span>${esc(node.type)}</span><strong>${esc(node.displayName)}</strong><small>${(node.evidenceIds || []).length} evidence · ${node.ambiguous ? "Ambiguous" : "Observed"}</small></button>`;
  }).join("");
  return `<div class="entity-map-shell"><div class="process-map-toolbar"><div class="action-strip"><button type="button" data-graph-action="zoom-out" aria-label="Zoom graph out">−</button><output data-graph-zoom>100%</output><button type="button" data-graph-action="zoom-in" aria-label="Zoom graph in">+</button><button type="button" data-graph-action="fit">Fit</button></div><div class="process-map-legend"><span><i class="legend-observed"></i>Evidence-backed</span><span><i class="legend-alerting"></i>Root</span><span><i class="legend-unresolved"></i>Ambiguous edge</span></div></div><div class="entity-map-canvas" tabindex="0" aria-label="Scrollable entity relationship map"><div class="entity-map-stage" style="width:${width}px;height:${height}px;--graph-zoom:1"><svg viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" aria-hidden="true">${lines}</svg>${cards}</div></div><p class="process-map-footnote">${bounded.length} of ${(nodes || []).length} node(s) and ${Math.min((edges || []).length, 100)} relationship(s) shown. The exact accessible tables follow.</p></div>`;
}
function installEntityMapControls() {
  document.querySelectorAll(".entity-map-shell").forEach((shell) => {
    const canvas = shell.querySelector(".entity-map-canvas"), stage = shell.querySelector(".entity-map-stage"), output = shell.querySelector("[data-graph-zoom]");
    if (!canvas || !stage || shell.dataset.controlsInstalled) return;
    shell.dataset.controlsInstalled = "true";
    let zoom = 1;
    const apply = () => { stage.style.setProperty("--graph-zoom", zoom); output.value = `${Math.round(zoom * 100)}%`; output.textContent = output.value; };
    shell.addEventListener("click", (event) => {
      const action = event.target.closest("[data-graph-action]")?.dataset.graphAction;
      if (action === "zoom-in") zoom = Math.min(1.5, zoom + .1);
      if (action === "zoom-out") zoom = Math.max(.55, zoom - .1);
      if (action === "fit") zoom = Math.max(.55, Math.min(1, canvas.clientWidth / 1120));
      if (action) apply();
      const node = event.target.closest(".entity-map-node");
      if (node) shell.querySelectorAll(".entity-map-node").forEach((item) => item.classList.toggle("focused", item === node));
    });
    apply();
  });
}
function processMapMarkup(processes, selectedEntityId, options = {}) {
  options.endpointId ||= new URLSearchParams(location.hash.split("?")[1] || "").get("endpointId") || "";
  const maximum = options.maximum || 80,
    source = (processes || []).slice(0, maximum),
    byId = new Map(source.map((process) => [process.entityId, process])),
    children = new Map(source.map((process) => [process.entityId, []]));
  for (const process of source) {
    const parent = process.properties?.parentProcessEntityId;
    if (parent && children.has(parent)) children.get(parent).push(process);
  }
  const roots = source.filter((process) => {
    const parent = process.properties?.parentProcessEntityId;
    return !parent || !byId.has(parent);
  }), rootIds = new Set(source.filter((process) => !process.properties?.unresolvedBoundary && (!process.properties?.parentProcessEntityId || byId.get(process.properties.parentProcessEntityId)?.properties?.unresolvedBoundary)).map((process) => process.entityId));
  const node = (process, ancestry = new Set()) => {
    if (ancestry.has(process.entityId)) return "";
    const next = new Set(ancestry).add(process.entityId),
      descendants = children.get(process.entityId) || [],
      properties = process.properties || {},
      selected = process.entityId === selectedEntityId,
      unresolved = !!properties.unresolvedBoundary,
      earliestObserved = rootIds.has(process.entityId) && !unresolved,
      command = properties.commandLine || (unresolved ? "Parent start event was not observed" : "Command line not collected by the source"),
      pid = properties.pid ?? properties.processId ?? "Not collected",
      user = properties.user || properties.userSid || "User not collected",
      integrity = properties.integrity || "Integrity not collected";
    return `<li role="treeitem" aria-selected="${selected}"${descendants.length ? ' aria-expanded="true"' : ""}><button type="button" class="process-map-node${selected ? " selected" : ""}${unresolved ? " unresolved" : ""}" data-process-entity="${esc(process.entityId)}" data-process-name="${esc(process.displayName || "Process image not collected")}" data-process-command="${esc(command)}" data-process-path="${esc(properties.path || "Not collected by the source")}" data-process-pid="${esc(pid)}" data-process-user="${esc(user)}" data-process-integrity="${esc(integrity)}" data-process-start="${esc(properties.startTime || process.firstObserved || "")}" data-process-exit="${esc(properties.exitTime || "")}" data-process-unresolved="${unresolved}" title="Inspect ${esc(process.displayName)}"><span class="process-node-top"><span class="process-node-kind">${selected ? "ALERTING PROCESS" : unresolved ? "SOURCE GAP" : earliestObserved ? "EARLIEST OBSERVED" : "PROCESS"}</span>${selected ? '<span class="process-node-risk">SELECTED</span>' : ""}</span><strong><span class="process-glyph" aria-hidden="true">${unresolved ? "?" : "P"}</span>${esc(process.displayName || "Process image not collected")}</strong><span class="process-command">${esc(command)}</span><span class="process-node-facts"><span>PID ${esc(pid)}</span><span>${esc(user)}</span><span>${esc(integrity)}</span><span>${unresolved ? "Non-actionable" : `${(process.evidenceIds || []).length} evidence`}</span></span></button>${descendants.length ? `<ul role="group">${descendants.map((child) => node(child, next)).join("")}</ul>` : ""}</li>`;
  };
  const rendered = roots.map((root) => node(root)).join(""),
    observedCount = source.filter((process) => !process.properties?.unresolvedBoundary).length,
    unresolvedCount = source.length - observedCount;
  return `<div class="process-map-shell" data-endpoint-id="${esc(options.endpointId || "")}"><div class="process-map-toolbar"><div class="action-strip"><button type="button" data-tree-action="zoom-out" aria-label="Zoom process tree out">−</button><output data-tree-zoom>100%</output><button type="button" data-tree-action="zoom-in" aria-label="Zoom process tree in">+</button><button type="button" data-tree-action="fit">Fit</button></div><div class="process-map-legend"><span><i class="legend-observed"></i>Observed</span><span><i class="legend-alerting"></i>Selected / alerting</span><span><i class="legend-unresolved"></i>Unresolved boundary</span></div></div><div class="process-map-canvas" tabindex="0" aria-label="Scrollable process node map"><ul class="soc-process-tree-map" role="tree">${rendered || '<li><div class="process-map-empty">No evidence-backed process node is available.</div></li>'}</ul></div><aside class="process-node-inspector" aria-live="polite"><span class="section-eyebrow">PROCESS INSPECTOR</span><p>Select a node to inspect its exact execution context without leaving the tree.</p></aside><p class="process-map-footnote">${observedCount} observed process node(s)${unresolvedCount ? ` and ${unresolvedCount} explicitly unresolved boundary` : ""} shown${(processes || []).length > source.length ? ` of ${(processes || []).length}; refine the root to inspect more` : ""}. Stable identities define observed connections; unresolved PID-only boundaries are dashed and non-actionable.</p></div>`;
}
function installProcessMapControls() {
  document.querySelectorAll(".process-map-shell").forEach((shell) => {
    const canvas = shell.querySelector(".process-map-canvas"),
      tree = shell.querySelector(".soc-process-tree-map"),
      output = shell.querySelector("[data-tree-zoom]");
    if (!canvas || !tree || shell.dataset.controlsInstalled) return;
    shell.dataset.controlsInstalled = "true";
    let zoom = 1;
    const drawConnectors = () => {
      tree.querySelector(".process-tree-connectors")?.remove();
      const treeRect = tree.getBoundingClientRect(),
        width = Math.max(tree.scrollWidth, Math.ceil(treeRect.width / zoom)),
        height = Math.max(tree.scrollHeight, Math.ceil(treeRect.height / zoom));
      if (!width || !height) return;
      const ns = "http://www.w3.org/2000/svg",
        svg = document.createElementNS(ns, "svg"),
        defs = document.createElementNS(ns, "defs"),
        marker = document.createElementNS(ns, "marker"),
        arrow = document.createElementNS(ns, "path");
      svg.classList.add("process-tree-connectors");
      svg.setAttribute("width", width);
      svg.setAttribute("height", height);
      svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
      svg.setAttribute("aria-hidden", "true");
      marker.setAttribute("id", `process-arrow-${crypto.randomUUID()}`);
      marker.setAttribute("viewBox", "0 0 8 8");
      marker.setAttribute("refX", "7");
      marker.setAttribute("refY", "4");
      marker.setAttribute("markerWidth", "7");
      marker.setAttribute("markerHeight", "7");
      marker.setAttribute("orient", "auto-start-reverse");
      arrow.setAttribute("d", "M 0 0 L 8 4 L 0 8 z");
      marker.append(arrow);
      defs.append(marker);
      svg.append(defs);
      const point = (element, side) => {
        const rect = element.getBoundingClientRect();
        return {
          x: (side === "right" ? rect.right - treeRect.left : rect.left - treeRect.left) / zoom,
          y: (rect.top + rect.height / 2 - treeRect.top) / zoom,
        };
      };
      tree.querySelectorAll("li").forEach((branch) => {
        const parent = branch.querySelector(":scope > .process-map-node"),
          group = branch.querySelector(":scope > ul");
        if (!parent || !group) return;
        [...group.children].forEach((childBranch) => {
          const child = childBranch.querySelector(":scope > .process-map-node");
          if (!child) return;
          const from = point(parent, "right"), to = point(child, "left"),
            middle = from.x + Math.max(22, (to.x - from.x) / 2),
            path = document.createElementNS(ns, "path");
          path.setAttribute("d", `M ${from.x} ${from.y} H ${middle} V ${to.y} H ${to.x}`);
          path.setAttribute("marker-end", `url(#${marker.id})`);
          svg.append(path);
        });
      });
      tree.prepend(svg);
    };
    const apply = () => {
      tree.style.setProperty("--tree-zoom", String(zoom));
      output.value = `${Math.round(zoom * 100)}%`;
      output.textContent = output.value;
      requestAnimationFrame(drawConnectors);
    };
    shell.addEventListener("click", (event) => {
      const action = event.target.closest("[data-tree-action]")?.dataset.treeAction;
      if (action === "zoom-in") zoom = Math.min(1.5, zoom + .1);
      if (action === "zoom-out") zoom = Math.max(.6, zoom - .1);
      if (action === "fit") zoom = Math.max(.6, Math.min(1, canvas.clientWidth / Math.max(tree.scrollWidth, 1)));
      if (action) apply();
      const selected = event.target.closest(".process-map-node");
      if (selected) {
        shell.querySelectorAll(".process-map-node").forEach((item) => item.classList.toggle("focused", item === selected));
        const d = selected.dataset,
          inspector = shell.querySelector(".process-node-inspector"),
          endpointId = shell.dataset.endpointId;
        if (inspector)
          inspector.innerHTML = `<div class="process-inspector-head"><div><span class="section-eyebrow">${d.processUnresolved === "true" ? "UNRESOLVED BOUNDARY" : "PROCESS INSPECTOR"}</span><h3>${esc(d.processName)}</h3></div>${endpointId && d.processUnresolved !== "true" ? `<a class="button" href="#/processes/${encodeURIComponent(endpointId)}/${encodeURIComponent(d.processEntity)}">Open process record</a>` : ""}</div><div class="node-detail-strip"><div><span>PID</span><strong>${esc(d.processPid)}</strong></div><div><span>User / integrity</span><strong>${esc(d.processUser)} · ${esc(d.processIntegrity)}</strong></div><div><span>Started / state</span><strong>${d.processStart ? esc(new Date(d.processStart).toLocaleString()) : "Not observed"} · ${d.processExit ? "Exited" : d.processUnresolved === "true" ? "Unresolved" : "Running at last observation"}</strong></div><div><span>Stable entity</span><code>${esc(d.processEntity)}</code></div></div><dl class="process-inspector-evidence"><dt>Executable</dt><dd><code>${esc(d.processPath)}</code></dd><dt>Command line</dt><dd><code>${esc(d.processCommand)}</code></dd></dl>`;
        selected.scrollIntoView({ block: "nearest", inline: "center" });
      }
    });
    apply();
    window.addEventListener("resize", () => requestAnimationFrame(drawConnectors), { passive: true });
  });
}
function normalizeNativeProcessTree(nativeTree, rootEntityId) {
  const processes = [], relationships = [];
  const visit = (branch, parent = null) => {
    const value = branch?.process || {}, entityId = value.processEntityId;
    if (!entityId) return;
    const pid = value.processId ?? value.pid,
      path = value.executablePath || value.path || value.executableMetadata?.path,
      pathName = path?.split(/[\\/]/).filter(Boolean).at(-1),
      displayName = value.executableName || value.name || value.executableMetadata?.fileName || pathName || `Process image not collected · PID ${pid ?? "not collected"}`;
    processes.push({ entityId, type: "Process", displayName, firstObserved: value.startTime || value.firstObservedAt, evidenceIds: [value.startEventId].filter(Boolean), ambiguous: !!branch.incompleteLineage, dataQuality: value.dataQualityFlags || [], properties: { parentProcessEntityId: parent, parentPid: value.parentProcessId ?? value.parentPid, pid, commandLine: value.commandLine, path, workingDirectory: value.workingDirectory, user: value.userName || value.userId || value.user, userId: value.userId, sessionId: value.sessionId, integrity: value.integrityLevel || value.integrity, elevated: value.elevated, architecture: value.architecture, collector: value.collectorType, collectorVersion: value.collectorVersion, startTime: value.startTime, exitTime: value.exitTime, firstObservedAt: value.firstObservedAt, lastUpdatedAt: value.lastUpdatedAt } });
    if (parent) relationships.push({ sourceEntityId: parent, destinationEntityId: entityId, relationshipType: "spawned", confidence: branch.incompleteLineage ? 50 : 100, ambiguous: !!branch.incompleteLineage, sourceEvidenceIds: [value.startEventId].filter(Boolean) });
    (branch.children || []).forEach((child) => visit(child, entityId));
  };
  visit(nativeTree);
  return { rootProcessEntityId: rootEntityId, processes, nodes: processes, relationships, edges: relationships, truncated: false, missingParents: processes.filter((process) => process.dataQuality?.includes("parent-not-observed")).map((process) => process.entityId), ambiguousRelationships: relationships.filter((relationship) => relationship.ambiguous).map((relationship) => `${relationship.sourceEntityId} -> ${relationship.destinationEntityId}`), depthReached: 6, elapsedMilliseconds: 0 };
}
function normalizeProcessLineage(lineage, endpointId) {
  const value = normalizeNativeProcessTree(lineage.tree, lineage.selectedProcessEntityId);
  value.earlierActivityUnavailable = !!lineage.ancestorBoundaryIncomplete;
  return value;
}

function mergeSelectedProcess(processes, selectedEntityId, process) {
  if (!process) return processes || [];
  return (processes || []).map((item) => {
    if (item.entityId !== selectedEntityId) return item;
    const path = process.executablePath || process.path || process.executableMetadata?.path,
      displayName = process.executableName || process.name || process.executableMetadata?.fileName || path?.split(/[\\/]/).filter(Boolean).at(-1) || item.displayName;
    return {
      ...item,
      displayName,
      evidenceIds: [...new Set([...(item.evidenceIds || []), process.startEventId].filter(Boolean))],
      dataQuality: process.dataQualityFlags || item.dataQuality || [],
      properties: {
        ...(item.properties || {}),
        pid: process.processId ?? process.pid ?? item.properties?.pid,
        parentPid: process.parentProcessId ?? process.parentPid ?? item.properties?.parentPid,
        parentProcessEntityId: process.parentProcessEntityId ?? item.properties?.parentProcessEntityId,
        commandLine: process.commandLine ?? item.properties?.commandLine,
        path: path ?? item.properties?.path,
        workingDirectory: process.workingDirectory ?? item.properties?.workingDirectory,
        user: process.userName || process.userId || process.user || item.properties?.user,
        userId: process.userId ?? item.properties?.userId,
        sessionId: process.sessionId ?? item.properties?.sessionId,
        integrity: process.integrityLevel || process.integrity || item.properties?.integrity,
        elevated: process.elevated ?? item.properties?.elevated,
        architecture: process.architecture ?? item.properties?.architecture,
        collector: process.collectorType ?? item.properties?.collector,
        collectorVersion: process.collectorVersion ?? item.properties?.collectorVersion,
        startTime: process.startTime ?? item.properties?.startTime,
        exitTime: process.exitTime ?? item.properties?.exitTime,
        firstObservedAt: process.firstObservedAt ?? item.properties?.firstObservedAt,
        lastUpdatedAt: process.lastUpdatedAt ?? item.properties?.lastUpdatedAt,
      },
    };
  });
}

function lineageNodeData(process, selectedEntityId, rootIds = new Set()) {
  const properties = process.properties || {},
    unresolved = !!properties.unresolvedBoundary,
    selected = process.entityId === selectedEntityId,
    root = rootIds.has(process.entityId),
    role = unresolved ? "Source gap" : selected ? "Alerting process" : root ? "Earliest observed" : "Observed process";
  return {
    entityId: process.entityId,
    name: process.displayName || `Process image not collected · PID ${properties.pid ?? "not collected"}`,
    role,
    selected,
    unresolved,
    pid: properties.pid ?? "Not collected",
    parentPid: properties.parentPid ?? "Not collected",
    command: properties.commandLine || (unresolved ? "Parent start event was not observed" : "Not collected by the source"),
    path: properties.path || "Not collected by the source",
    workingDirectory: properties.workingDirectory || "Not collected by the source",
    user: properties.user || "Not collected by the source",
    userId: properties.userId || "Not collected",
    sessionId: properties.sessionId || "Not collected",
    integrity: properties.integrity || "Not collected by the source",
    architecture: properties.architecture || "Not collected",
    elevated: properties.elevated === true ? "Yes" : properties.elevated === false ? "No" : "Not collected",
    collector: properties.collector ? `${properties.collector}${properties.collectorVersion ? ` · ${properties.collectorVersion}` : ""}` : "Not collected",
    started: properties.startTime || process.firstObserved || "",
    exited: properties.exitTime || "",
    evidenceCount: (process.evidenceIds || []).length,
    quality: (process.dataQuality || []).length ? process.dataQuality.join(", ") : unresolved ? "parent-start-not-observed" : "No quality flags",
  };
}

function lineageInspectorMarkup(data, endpointId) {
  const started = data.started ? new Date(data.started).toLocaleString() : "Not observed",
    stateLabel = data.unresolved ? "Unresolved source boundary" : data.exited ? `Exited ${new Date(data.exited).toLocaleString()}` : "No exit event observed";
  return `<div class="lineage-inspector-heading"><div><span class="section-eyebrow">${esc(data.role.toUpperCase())}</span><h3>${esc(data.name)}</h3></div><span class="badge ${data.selected ? "severity-high" : ""}">${data.unresolved ? "NON-ACTIONABLE" : data.selected ? "ALERT" : "OBSERVED"}</span></div><div class="lineage-inspector-summary"><div><span>PID</span><strong>${esc(data.pid)}</strong></div><div><span>Started</span><strong>${esc(started)}</strong></div><div><span>State</span><strong>${esc(stateLabel)}</strong></div><div><span>Evidence</span><strong>${data.evidenceCount} record${data.evidenceCount === 1 ? "" : "s"}</strong></div></div><section><h4>Execution</h4><dl><dt>Full command line</dt><dd><pre><code>${esc(data.command)}</code></pre></dd><dt>Executable</dt><dd><code>${esc(data.path)}</code></dd><dt>Working directory</dt><dd><code>${esc(data.workingDirectory)}</code></dd></dl></section><section><h4>Security context</h4><dl><dt>User</dt><dd>${esc(data.user)}</dd><dt>User identity</dt><dd><code>${esc(data.userId)}</code></dd><dt>Session</dt><dd>${esc(data.sessionId)}</dd><dt>Integrity / elevated</dt><dd>${esc(data.integrity)} · ${esc(data.elevated)}</dd><dt>Architecture</dt><dd>${esc(data.architecture)}</dd></dl></section><section><h4>Identity and source quality</h4><dl><dt>Stable process identity</dt><dd><code>${esc(data.entityId)}</code></dd><dt>Reported parent PID</dt><dd>${esc(data.parentPid)}</dd><dt>Collector</dt><dd>${esc(data.collector)}</dd><dt>Quality</dt><dd>${esc(data.quality)}</dd></dl></section>${endpointId && !data.unresolved ? `<a class="button" href="#/processes/${encodeURIComponent(endpointId)}/${encodeURIComponent(data.entityId)}">Open process record</a>` : '<p class="lineage-source-note">This boundary marks missing source telemetry. It is not a fabricated process and cannot be targeted for response.</p>'}`;
}

function lineageStudioMarkup(processes, selectedEntityId, endpointId, alert) {
  const source = (processes || []).slice(0, 160),
    byId = new Map(source.map((process) => [process.entityId, process])),
    children = new Map(source.map((process) => [process.entityId, []]));
  for (const process of source) {
    const parent = process.properties?.parentProcessEntityId;
    if (parent && children.has(parent)) children.get(parent).push(process);
  }
  const timeValue = (process) => Date.parse(process.properties?.startTime || process.firstObserved || "") || Number.MAX_SAFE_INTEGER;
  children.forEach((items) => items.sort((a, b) => timeValue(a) - timeValue(b)));
  const roots = source.filter((process) => !process.properties?.parentProcessEntityId || !byId.has(process.properties.parentProcessEntityId)).sort((a, b) => timeValue(a) - timeValue(b)),
    rootIds = new Set(source.filter((process) => !process.properties?.unresolvedBoundary && (!process.properties?.parentProcessEntityId || byId.get(process.properties.parentProcessEntityId)?.properties?.unresolvedBoundary)).map((process) => process.entityId)),
    positions = new Map();
  let row = 0, maximumDepth = 0;
  const place = (process, depth, ancestry = new Set()) => {
    if (ancestry.has(process.entityId)) return row++ * 172 + 64;
    maximumDepth = Math.max(maximumDepth, depth);
    const next = new Set(ancestry).add(process.entityId), descendants = children.get(process.entityId) || [];
    let y;
    if (!descendants.length) y = row++ * 172 + 64;
    else {
      const ys = descendants.map((child) => place(child, depth + 1, next));
      y = (ys[0] + ys.at(-1)) / 2;
    }
    positions.set(process.entityId, { x: depth * 316 + 54, y, depth });
    return y;
  };
  roots.forEach((root) => place(root, 0));
  const stageWidth = Math.max(920, (maximumDepth + 1) * 316 + 90), stageHeight = Math.max(620, row * 172 + 100),
    edges = source.flatMap((process) => {
      const parentId = process.properties?.parentProcessEntityId, from = positions.get(parentId), to = positions.get(process.entityId);
      if (!from || !to) return [];
      const x1 = from.x + 244, y1 = from.y + 58, x2 = to.x, y2 = to.y + 58, bend = Math.max(44, (x2 - x1) * .48);
      return [`<path class="${process.properties?.unresolvedBoundary ? "unresolved" : ""}" d="M ${x1} ${y1} C ${x1 + bend} ${y1}, ${x2 - bend} ${y2}, ${x2} ${y2}" />`];
    }).join(""),
    cards = source.map((process) => {
      const data = lineageNodeData(process, selectedEntityId, rootIds), point = positions.get(process.entityId);
      if (!point) return "";
      return `<button type="button" class="lineage-card${data.selected ? " selected" : ""}${data.unresolved ? " unresolved" : ""}" style="left:${point.x}px;top:${point.y}px;--lineage-depth:${point.depth}" data-lineage-node data-entity="${esc(data.entityId)}" data-name="${esc(data.name)}" data-role="${esc(data.role)}" data-selected="${data.selected}" data-unresolved="${data.unresolved}" data-pid="${esc(data.pid)}" data-parent-pid="${esc(data.parentPid)}" data-command="${esc(data.command)}" data-path="${esc(data.path)}" data-working-directory="${esc(data.workingDirectory)}" data-user="${esc(data.user)}" data-user-id="${esc(data.userId)}" data-session-id="${esc(data.sessionId)}" data-integrity="${esc(data.integrity)}" data-architecture="${esc(data.architecture)}" data-elevated="${esc(data.elevated)}" data-collector="${esc(data.collector)}" data-started="${esc(data.started)}" data-exited="${esc(data.exited)}" data-evidence-count="${data.evidenceCount}" data-quality="${esc(data.quality)}"><span class="lineage-card-role">${esc(data.role)}</span><strong><span aria-hidden="true">${data.unresolved ? "?" : "P"}</span>${esc(data.name)}</strong><code>${esc(data.command)}</code><span class="lineage-card-facts"><span>PID ${esc(data.pid)}</span><span>${esc(data.user)}</span></span><span class="lineage-card-time">${data.started ? esc(new Date(data.started).toLocaleTimeString()) : "Start not observed"}</span></button>`;
    }).join(""),
    selected = lineageNodeData(byId.get(selectedEntityId) || roots[0] || { entityId: selectedEntityId, properties: {} }, selectedEntityId, rootIds),
    observedRoots = source.filter((process) => rootIds.has(process.entityId)).sort((a, b) => timeValue(a) - timeValue(b)),
    unresolvedCount = source.filter((process) => process.properties?.unresolvedBoundary).length,
    descendantCount = source.filter((process) => {
      let current = process, seen = new Set();
      while (current?.properties?.parentProcessEntityId && !seen.has(current.entityId)) {
        seen.add(current.entityId);
        if (current.properties.parentProcessEntityId === selectedEntityId) return true;
        current = byId.get(current.properties.parentProcessEntityId);
      }
      return false;
    }).length;
  return `<div class="lineage-workspace"><header class="lineage-workspace-head"><div><a class="back-link" href="#/alerts/${encodeURIComponent(alert.alertId)}">← Back to alert</a><span class="section-eyebrow">ALERT PROCESS LINEAGE</span><h2>${esc(alert.title)}</h2><p>Follow the earliest observed process through the alerting execution and every loaded child. Missing source events remain explicit.</p></div><div class="lineage-workspace-actions"><button type="button" data-lineage-action="center">Center alert</button><button type="button" data-lineage-action="flat" aria-pressed="false">Flat view</button><button type="button" data-lineage-action="close">Close window</button></div></header><div class="lineage-overview"><div><span>Earliest observed</span><strong>${esc(observedRoots[0]?.displayName || "Not observed")}</strong></div><div><span>Alerting process</span><strong>${esc(selected.name)}</strong></div><div><span>Observed nodes</span><strong>${source.length - unresolvedCount}</strong></div><div><span>Children below alert</span><strong>${descendantCount}</strong></div><div><span>Source gaps</span><strong>${unresolvedCount}</strong></div><div><span>Loaded depth</span><strong>${maximumDepth}</strong></div></div><div class="lineage-studio"><section class="lineage-graph-panel" aria-label="Process lineage graph"><div class="lineage-graph-toolbar"><div><button type="button" data-lineage-action="zoom-out" aria-label="Zoom out">−</button><output data-lineage-zoom>100%</output><button type="button" data-lineage-action="zoom-in" aria-label="Zoom in">+</button><button type="button" data-lineage-action="fit">Fit</button></div><div class="process-map-legend"><span><i class="legend-observed"></i>Observed</span><span><i class="legend-alerting"></i>Alerting</span><span><i class="legend-unresolved"></i>Source gap</span></div></div><div class="lineage-viewport" tabindex="0"><div class="lineage-stage depth-view" style="width:${stageWidth}px;height:${stageHeight}px"><svg aria-hidden="true" width="${stageWidth}" height="${stageHeight}" viewBox="0 0 ${stageWidth} ${stageHeight}">${edges}</svg>${cards}</div></div></section><aside class="lineage-detail-panel" aria-live="polite">${lineageInspectorMarkup(selected, endpointId)}</aside></div><footer class="lineage-truth-note"><strong>Identity-safe lineage.</strong> Connections use stable process entities, not PID or filename alone. “Source gap” means the parent start event was not observed; it is never replaced with guessed data.</footer></div>`;
}

function installLineageStudioControls() {
  document.querySelectorAll(".lineage-workspace").forEach((workspace) => {
    if (workspace.dataset.controlsInstalled) return;
    workspace.dataset.controlsInstalled = "true";
    const viewport = workspace.querySelector(".lineage-viewport"), stage = workspace.querySelector(".lineage-stage"), output = workspace.querySelector("[data-lineage-zoom]"), inspector = workspace.querySelector(".lineage-detail-panel"), endpointId = inspector?.querySelector('a[href^="#/processes/"]')?.getAttribute("href").split("/")[2] || "";
    if (!viewport || !stage) return;
    let zoom = 1;
    const applyZoom = () => { stage.style.setProperty("--lineage-zoom", zoom); if (output) output.textContent = `${Math.round(zoom * 100)}%`; };
    const centerSelected = () => { const node = workspace.querySelector(".lineage-card.selected"); if (node) { viewport.scrollLeft = Math.max(0, node.offsetLeft * zoom - viewport.clientWidth / 2 + node.offsetWidth * zoom / 2); viewport.scrollTop = Math.max(0, node.offsetTop * zoom - viewport.clientHeight / 2 + node.offsetHeight * zoom / 2); } };
    workspace.addEventListener("click", (event) => {
      const action = event.target.closest("[data-lineage-action]")?.dataset.lineageAction;
      if (action === "zoom-in") zoom = Math.min(1.6, zoom + .1);
      if (action === "zoom-out") zoom = Math.max(.45, zoom - .1);
      if (action === "fit") zoom = Math.max(.45, Math.min(1, (viewport.clientWidth - 32) / stage.offsetWidth, (viewport.clientHeight - 32) / stage.offsetHeight));
      if (["zoom-in", "zoom-out", "fit"].includes(action)) { applyZoom(); if (action === "fit") { viewport.scrollLeft = 0; viewport.scrollTop = 0; } }
      if (action === "center") centerSelected();
      if (action === "flat") { const pressed = event.target.getAttribute("aria-pressed") === "true"; event.target.setAttribute("aria-pressed", String(!pressed)); event.target.textContent = pressed ? "Flat view" : "Depth view"; stage.classList.toggle("depth-view", pressed); }
      if (action === "close") window.close();
      const node = event.target.closest("[data-lineage-node]");
      if (node) {
        workspace.querySelectorAll("[data-lineage-node]").forEach((item) => item.classList.toggle("focused", item === node));
        const d = node.dataset;
        inspector.innerHTML = lineageInspectorMarkup({ entityId: d.entity, name: d.name, role: d.role, selected: d.selected === "true", unresolved: d.unresolved === "true", pid: d.pid, parentPid: d.parentPid, command: d.command, path: d.path, workingDirectory: d.workingDirectory, user: d.user, userId: d.userId, sessionId: d.sessionId, integrity: d.integrity, architecture: d.architecture, elevated: d.elevated, collector: d.collector, started: d.started, exited: d.exited, evidenceCount: Number(d.evidenceCount), quality: d.quality }, endpointId);
      }
    });
    applyZoom();
    requestAnimationFrame(centerSelected);
  });
}
async function investigationTree() {
  const requestedRoot = investigationRoot(), query = new URLSearchParams(location.hash.split("?")[1] || ""), requestedEndpointId = query.get("endpointId");
  try {
    const context = await resolveProcessContext(requestedRoot, requestedEndpointId),
      root = context.root,
      endpointId = context.endpointId;
    if (!root || !endpointId) return processContextPicker(context.recent || []);
    const lineage = (await api(`/api/v1/endpoints/${encodeURIComponent(endpointId)}/processes/${encodeURIComponent(root)}/lineage?ancestorDepth=12&descendantDepth=6`)).data,
      x = normalizeProcessLineage(lineage, endpointId);
    return `<form id="investigation-root" class="toolbar compact-query"><label>Process entity ID <input name="root" value="${esc(root)}" required maxlength="512"></label>${endpointId ? `<input type="hidden" name="endpointId" value="${esc(endpointId)}">` : ""}<button>Load tree</button></form><div class="truth-banner"><strong>Identity-safe lineage</strong><span>Stable process identities define every connection. PID and executable name alone never create lineage.</span></div><div class="detail-head"><div><h2>Process lineage</h2><p class="page-lead">Observed ancestor chain, selected process, and bounded descendants in one investigation map.</p></div><span class="badge">${lineage.ancestorBoundaryIncomplete ? "Earlier parent not observed" : "Observed boundary complete"}</span></div><div class="lineage-stats"><span><strong>${lineage.ancestorCount}</strong> ancestors</span><span><strong>1</strong> selected</span><span><strong>${lineage.descendantCount}</strong> descendants</span></div>${processMapMarkup(x.processes, x.rootProcessEntityId)}<details class="technical-details"><summary>Exact lineage and data-quality details</summary><section><h2>Accessible relationship table</h2>${relationshipTable(x.relationships)}</section><div class="panels"><article><h3>Missing parents</h3><p>${esc((x.missingParents || []).join(", ") || "None")}</p></article><article><h3>Ambiguous relationships</h3><p>${esc((x.ambiguousRelationships || []).join(", ") || "None")}</p></article></div></details>`;
  } catch (e) {
    try {
      const recent = await recentProcessContexts();
      return processContextPicker(recent, requestedRoot ? "That process is no longer available in the selected endpoint context. Choose a current evidence-backed process." : undefined);
    } catch {
      return state("Process tree unavailable", e.message);
    }
  }
}
async function entityGraph() {
  const requestedRoot = investigationRoot(), query = new URLSearchParams(location.hash.split("?")[1] || ""), requestedEndpointId = query.get("endpointId");
  try {
    const context = await resolveProcessContext(requestedRoot, requestedEndpointId),
      root = context.root,
      endpointId = context.endpointId;
    if (!root) return processContextPicker(context.recent || [], "Choose an observed process to explore its connected entities.", "entity-graph");
    const x = endpointId
      ? normalizeNativeProcessTree((await api(`/api/v1/endpoints/${encodeURIComponent(endpointId)}/processes/${encodeURIComponent(root)}/tree?depth=6`)).data, root)
      : (await api("/api/v1/entity-graph:query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          rootEntityId: root,
          maximumDepth: 3,
          maximumNodes: 200,
          maximumEdges: 400,
          maximumExpansionPerNode: 50,
          timeoutMilliseconds: 5000,
          pageSize: 200,
        }),
      })).data;
    return `<form id="investigation-root" class="toolbar compact-query"><label>Root entity ID <input name="root" value="${esc(root)}" required maxlength="512"></label>${endpointId ? `<input type="hidden" name="endpointId" value="${esc(endpointId)}">` : ""}<label>Depth <input name="depth" type="number" min="0" max="8" value="3"></label><button>Traverse graph</button></form><div class="truth-banner"><strong>Evidence-backed relationships</strong><span>Solid connections have exact source evidence. Ambiguous relationships remain visibly marked and are never silently promoted to facts.</span></div><div class="section-title-row"><div><span class="section-eyebrow">TOPOLOGY</span><h2>Entity relationship map</h2><p>${x.nodes.length} nodes · ${x.edges.length} edges · depth ${x.depthReached} · ${x.elapsedMilliseconds} ms</p></div><div class="action-strip"><a class="button" href="#/attack-stories?root=${encodeURIComponent(root)}">Open timeline</a><a class="button" href="#/threat-hunting?root=${encodeURIComponent(root)}">Hunt related activity</a></div></div><div class="toolbar graph-filters" aria-label="Graph filters"><label>Node type <select id="graph-node-filter"><option>All</option>${["Process", "File", "Registry", "Network", "Dns", "Module", "Persistence", "Identity", "Execution", "DetectionFinding", "CorrelatedFinding"].map((v) => `<option>${v}</option>`).join("")}</select></label><label>Edge type <select id="graph-edge-filter"><option>All</option>${[...new Set(x.edges.map((e) => e.relationshipType))].map((v) => `<option>${esc(v)}</option>`).join("")}</select></label></div>${entityGraphMarkup(x.nodes, x.edges, root)}<details class="technical-details"><summary>Accessible entity and relationship tables</summary>${entityTable(x.nodes)}<section><h2>Relationships</h2>${relationshipTable(x.edges)}</section></details>`;
  } catch (e) {
    if (!requestedRoot) {
      try {
        return processContextPicker(await recentProcessContexts(), "Choose an observed process to explore its connected entities.", "entity-graph");
      } catch {}
    }
    return state("Entity graph unavailable", e.message);
  }
}
async function attackStory() {
  const root = investigationRoot();
  try {
    const x = (
      await api(`/api/v1/attack-stories/${encodeURIComponent(root)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          rootEntityId: root,
          maximumDepth: 4,
          maximumNodes: 300,
          maximumEdges: 600,
          maximumExpansionPerNode: 50,
          timeoutMilliseconds: 5000,
          pageSize: 200,
        }),
      })
    ).data;
    return `<form id="investigation-root" class="toolbar"><label>Root entity ID <input name="root" value="${esc(root)}" required></label><button>Reconstruct story</button></form><p class="notice">This is a deterministic view over authoritative evidence, not a separate truth or AI narrative.</p><div class="detail-head"><div><h2>${esc(x.explanation)}</h2><p>${new Date(x.firstObserved).toLocaleString()} – ${new Date(x.lastObserved).toLocaleString()}</p></div><span class="badge">Confidence ${x.confidence}</span></div><div class="panels"><article><h3>Findings</h3><p>${x.detectionFindingIds.length} detection · ${x.correlatedFindingIds.length} correlated</p></article><article><h3>ATT&amp;CK</h3><p>${esc(x.mitreMappings.join(", ") || "No mapping")}</p></article><article><h3>Evidence quality</h3><p>Missing: ${esc(x.missingTelemetry.join(", ") || "none")}</p><p>Ambiguous: ${esc(x.ambiguities.join(", ") || "none")}</p><p>Source gaps: ${esc(x.sourceGaps.join(", ") || "none")}</p></article></div><section><h2>Ordered evidence timeline</h2><ol class="timeline">${x.timeline.map((t) => `<li><time>${new Date(t.at).toLocaleString()}</time> <strong>${esc(t.kind)}</strong> ${esc(t.description)}${t.ambiguous ? " · ambiguous" : ""}<br><small>${esc(t.evidenceReferences.join(", "))}</small></li>`).join("")}</ol></section><section><h2>Story entities</h2>${entityTable(x.entities)}</section><section><h2>Story relationships</h2>${relationshipTable(x.relationships)}</section>`;
  } catch (e) {
    return state("Attack story unavailable", e.message);
  }
}
function huntTemplate() {
  const tenant =
      sessionStorage.getItem("tenant_id") ||
      "00000000-0000-0000-0000-000000000000",
    now = new Date(),
    from = new Date(now - 86400000);
  return {
    schemaVersion: "threat-hunt.v1",
    huntId: "14141414-1414-1414-1414-141414140001",
    version: 1,
    tenantId: tenant,
    name: "Controlled multi-domain hunt",
    description: "Bounded evidence-backed entity hunt",
    entityTypes: [
      "Process",
      "File",
      "Registry",
      "Network",
      "Dns",
      "Module",
      "Persistence",
      "Identity",
      "Execution",
      "DetectionFinding",
      "CorrelatedFinding",
    ],
    from: from.toISOString(),
    to: now.toISOString(),
    where: {
      boolean: "And",
      predicate: {
        field: "processEntityId",
        operator: "Equal",
        values: ["sprint14-process-3"],
      },
      children: [],
    },
    maximumResults: 200,
    timeoutMilliseconds: 5000,
    maximumJoinDepth: 1,
    joinRelationships: [
      "modified",
      "connected-to",
      "queried",
      "loaded",
      "configured",
      "executed-as",
      "executed",
      "evidence-for",
    ],
    enabled: true,
    owner: "admin",
    sharedWith: [],
    createdAt: now.toISOString(),
  };
}
async function threatHunting() {
  const template = JSON.stringify(huntTemplate(), null, 2);
  return `<div class="truth-banner"><strong>Safe query boundary</strong><span>Hunts accept the bounded visual DSL only. SQL, scripts, regex, shell, and raw OpenSearch queries are unavailable.</span></div><form id="hunt-form" class="hunt-workbench"><section class="hunt-question" aria-labelledby="hunt-question-title"><span class="section-eyebrow">QUESTION</span><h2 id="hunt-question-title">What activity are you looking for?</h2><p class="page-lead">This controlled example searches process evidence by stable entity identity across the last 24 hours.</p><div class="hunt-plan"><div><span>Entity</span><strong>Process and related evidence</strong></div><div><span>Condition</span><strong>Process entity equals sprint14-process-3</strong></div><div><span>Time window</span><strong>Last 24 hours</strong></div><div><span>Limit</span><strong>200 results · depth 1</strong></div></div></section><details class="technical-details hunt-definition"><summary>Edit advanced bounded definition</summary><label>Bounded hunt DSL <textarea name="definition" rows="20" spellcheck="false">${esc(template)}</textarea></label></details><div class="hunt-actions"><button name="action" value="validate">Validate plan</button><button class="primary" name="action" value="execute">Run hunt</button><button name="action" value="save">Save hunt</button><p id="hunt-status" role="status" aria-live="polite" tabindex="-1"></p></div></form><section id="hunt-results" class="result-workspace" aria-live="polite"><div class="section-title-row"><div><span class="section-eyebrow">RESULTS</span><h2>Evidence timeline</h2></div></div><div class="empty-inline"><strong>No hunt has run yet</strong><p>Validate or run the bounded plan to inspect exact evidence and pivot to its process tree or entity graph.</p></div></section>`;
}
async function runHunt(e) {
  e.preventDefault();
  const out = document.querySelector("#hunt-status"),
    results = document.querySelector("#hunt-results");
  try {
    const hunt = JSON.parse(new FormData(e.target).get("definition")),
      action = e.submitter?.value || "validate",
      path =
        action === "validate"
          ? "/api/v1/threat-hunts:validate"
          : action === "save"
            ? "/api/v1/saved-hunts"
            : "/api/v1/threat-hunts:execute",
      body =
        action === "save"
          ? { hunt, newVersion: false }
          : action === "execute"
            ? { hunt }
            : hunt,
      b = await api(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    out.textContent =
      action === "validate"
        ? b.data.valid
          ? `Valid. Estimated cost ${b.data.estimatedCost}. ${b.data.plan.join("; ")}`
          : `Invalid: ${JSON.stringify(b.data.errors)}`
        : `${action} complete.`;
    if (action === "execute") {
      const rows = b.data.results || [];
      results.innerHTML = `<h2>Exact hunt results (${rows.length})</h2>${entityTable(rows.map((x) => ({ firstObserved: x.observedAt, type: x.entityType, entityId: x.entityId, displayName: x.displayName, evidenceIds: x.evidenceIds, dataQuality: [], ambiguous: false })))}<p>${rows.map((x) => `<a href="#/entity-graph?root=${encodeURIComponent(x.entityId)}">Graph ${esc(x.displayName)}</a>`).join(" · ")}</p>`;
      const table=results.querySelector("table");if(table){const header=document.createElement("th");header.textContent="Inspect";table.tHead.rows[0].append(header);const drawer=document.createElement("aside");drawer.className="detail-drawer hunt-result-drawer";drawer.hidden=true;drawer.setAttribute("aria-label","Hunt result context");drawer.innerHTML='<button type="button" aria-label="Close hunt result context">Close</button><div></div>';document.querySelector("#app").append(drawer);[...table.tBodies[0].rows].forEach((tr,index)=>{const cell=tr.insertCell(),button=document.createElement("button");button.type="button";button.textContent="Inspect context";button.onclick=()=>{const value=rows[index];drawer.querySelector("div").innerHTML=`<h2>${esc(value.displayName)}</h2><dl><dt>Type</dt><dd>${esc(value.entityType)}</dd><dt>Stable entity</dt><dd><code>${esc(value.entityId)}</code></dd><dt>Observed</dt><dd>${esc(value.observedAt)}</dd><dt>Evidence</dt><dd>${esc((value.evidenceIds||[]).join(", ")||"No reference")}</dd></dl><a href="#/entity-graph?root=${encodeURIComponent(value.entityId)}">Open full entity graph</a>`;drawer.hidden=false;drawer.querySelector("button").focus();};cell.append(button);});drawer.querySelector("button").onclick=()=>{drawer.hidden=true;table.querySelector("tbody button")?.focus();};}
    }
  } catch (error) {
    out.textContent = `Hunt failed: ${error.message}`;
  }
  out.focus();
}
async function savedHunts() {
  try {
    const items = (await api("/api/v1/saved-hunts")).data || [];
    return items.length
      ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Version</th><th>Owner</th><th>Shared</th><th>State</th><th>History</th></tr></thead><tbody>${items.map((x) => `<tr><td>${esc(x.name)}</td><td>${x.version}</td><td>${esc(x.owner)}</td><td>${esc(x.sharedWith.join(", ") || "Private")}</td><td>${x.enabled ? "Enabled" : "Disabled"}</td><td><button class="hunt-history" data-id="${x.huntId}">View history</button></td></tr>`).join("")}</tbody></table></div><p id="saved-hunt-status" role="status" tabindex="-1"></p>`
      : state(
          "No saved hunts",
          "Save a validated, tenant-scoped hunt from the hunting workspace.",
        );
  } catch (e) {
    return state("Saved hunts unavailable", e.message);
  }
}
async function investigationHealth() {
  try {
    const h = (await api("/api/v1/investigation-health")).data;
    return `<div class="panels"><article><h2>Queries</h2><dl><dt>Tree</dt><dd>${h.treeQueries}</dd><dt>Graph</dt><dd>${h.graphQueries}</dd><dt>Story</dt><dd>${h.storyQueries}</dd><dt>Hunt</dt><dd>${h.huntQueries}</dd></dl></article><article><h2>Traversal</h2><dl><dt>Nodes</dt><dd>${h.nodesTraversed}</dd><dt>Edges</dt><dd>${h.edgesTraversed}</dd><dt>Cancellations</dt><dd>${h.cancellations}</dd><dt>Cost rejections</dt><dd>${h.costRejections}</dd><dt>Timeouts</dt><dd>${h.timeouts}</dd></dl></article><article><h2>Latency and integrity</h2><dl><dt>Tree</dt><dd>${h.treeLatencyMilliseconds}ms</dd><dt>Graph</dt><dd>${h.graphLatencyMilliseconds}ms</dd><dt>Hunt</dt><dd>${h.huntLatencyMilliseconds}ms</dd><dt>Projection lag</dt><dd>${h.graphProjectionLagMilliseconds}ms</dd><dt>Relationship failures</dt><dd>${h.relationshipFailures}</dd></dl></article></div>`;
  } catch (e) {
    return state("Investigation health unavailable", e.message);
  }
}

const alertStatuses = [
    "New",
    "Acknowledged",
    "Investigating",
    "Escalated",
    "Resolved",
    "Closed",
  ],
  alertDispositions = [
    "None",
    "ConfirmedMalicious",
    "Suspicious",
    "Benign",
    "FalsePositive",
    "ExpectedActivity",
    "Duplicate",
    "Inconclusive",
  ],
  incidentStatuses = [
    "New",
    "Triage",
    "Investigating",
    "Contained",
    "Resolved",
    "Closed",
  ];
function optionList(values, current = "") {
  return values
    .map(
      (x) =>
        `<option value="${x}" ${x === current ? "selected" : ""}>${esc(x.replace(/([A-Z])/g, " $1").trim())}</option>`,
    )
    .join("");
}
function alertRows(items) {
  if (!items.length)
    return state(
      "No alerts",
      "No tenant-scoped alerts match the selected triage filters.",
    );
  return `<div class="table-wrap"><table class="alert-queue-table"><caption>Analyst triage queue</caption><colgroup><col class="alert-select-column"><col class="alert-updated-column"><col class="alert-name-column"><col class="alert-severity-column"><col class="alert-priority-column"><col class="alert-status-column"><col class="alert-assignee-column"><col class="alert-count-column"><col class="alert-count-column"></colgroup><thead><tr><th><span class="sr-only">Select</span></th><th>Updated</th><th>Alert</th><th>Severity</th><th>Priority</th><th>Status</th><th>Assignee</th><th>Evidence</th><th>Repeats</th></tr></thead><tbody>${items.map((x) => `<tr><td><input class="alert-select" type="checkbox" value="${x.alertId}" aria-label="Select ${esc(x.title)}"></td><td>${new Date(x.lastSeen).toLocaleString()}</td><td class="alert-name-cell"><a class="alert-name-link" data-queue-alert="${esc(x.alertId)}" href="#/alerts/${x.alertId}">${esc(x.title)}</a><small class="alert-row-id" title="${esc(x.alertId)}">${esc(x.alertId)}</small></td><td>${x.severity}</td><td>${x.priority}<br><small class="alert-priority-detail" title="${esc(x.priorityExplanation)}">${esc(x.priorityExplanation)}</small></td><td><span class="badge">${esc(x.currentStatus)}</span></td><td>${esc(x.assignee || x.team || "Unassigned")}</td><td>${x.evidence.rawEventIds.length + x.evidence.detectionFindingIds.length + x.evidence.correlatedFindingIds.length}</td><td>${x.repeatCount}</td></tr>`).join("")}</tbody></table></div>`;
}
function alertQueueNavigation(id) {
  let stored = null;
  try { stored = JSON.parse(sessionStorage.getItem(`soc.queue.${jwtContext().tenant}.${jwtContext().subject}`) || "null"); } catch { /* ignore invalid ephemeral context */ }
  const value = queueContext || stored, context = value?.ids?.includes(id) ? value : null;
  if (!context) return '<a href="#/alerts">Back to alert queue</a>';
  const index = context.ids.indexOf(id), previous = context.ids[index - 1], next = context.ids[index + 1];
  return `<nav class="queue-navigation" aria-label="Alert queue position"><a href="${esc(context.returnHash)}" data-restore-queue>Back to filtered queue</a><span>${index + 1} of ${context.ids.length} on this loaded page</span>${previous ? `<a href="#/alerts/${esc(previous)}">Previous alert</a>` : '<span>Start of page</span>'}${next ? `<a href="#/alerts/${esc(next)}">Next alert</a>` : '<span>End of page</span>'}</nav>`;
}
async function alertQueue() {
  try {
    const q = new URLSearchParams(location.hash.split("?")[1] || ""),
      [b, filters] = await Promise.all([
        api(`/api/v1/triage-queue?${q}`),
        api("/api/v1/triage-filters").catch(() => ({ data: [] })),
      ]);
    return `<form id="alert-filter" class="toolbar" aria-label="Alert queue filters"><label>Severity <input name="severity" type="number" min="0" max="100" value="${esc(q.get("severity") || "")}"></label><label>Priority <select name="priority"><option value="">Any</option>${[1, 2, 3, 4, 5].map((x) => `<option ${q.get("priority") === String(x) ? "selected" : ""}>${x}</option>`).join("")}</select></label><label>Status <select name="status"><option value="">Any</option>${optionList(alertStatuses, q.get("status"))}</select></label><label>Disposition <select name="disposition"><option value="">Any</option>${optionList(alertDispositions, q.get("disposition"))}</select></label><label>Assignee <input name="assignee" value="${esc(q.get("assignee") || "")}"></label><label>Team <input name="team" value="${esc(q.get("team") || "")}"></label><label>Endpoint <input name="endpointId" value="${esc(q.get("endpointId") || "")}"></label><label>User <input name="user" value="${esc(q.get("user") || "")}"></label><label>Rule <input name="ruleId" value="${esc(q.get("ruleId") || "")}"></label><label>ATT&amp;CK <input name="mitreTechnique" value="${esc(q.get("mitreTechnique") || "")}"></label><label>Evidence quality <input name="evidenceQuality" value="${esc(q.get("evidenceQuality") || "")}"></label><label>Sort <select name="sort">${["updated-desc", "updated-asc", "priority-desc", "age-desc"].map((x) => `<option ${q.get("sort") === x ? "selected" : ""}>${x}</option>`).join("")}</select></label><button>Apply filters</button></form><div class="toolbar"><button id="alert-bulk" type="button">Safe bulk action</button><a class="button" href="#/incidents">Incident queue</a><span>${b.data.total} matching alerts</span></div>${alertRows(b.data.items || [])}${b.data.nextCursor ? `<button id="alert-next" data-cursor="${esc(b.data.nextCursor)}">Next page</button>` : ""}<section><h2>Saved filters</h2><p>${(filters.data || []).map((x) => esc(x.name)).join(" · ") || "No saved filter"}</p><form id="save-alert-filter" class="toolbar"><label>Filter name <input name="name" required maxlength="120"></label><button>Save current filters</button></form></section><dialog id="bulk-dialog" aria-labelledby="bulk-title"><form method="dialog" id="bulk-form"><h2 id="bulk-title">Confirm bounded bulk action</h2><p id="bulk-count">No alerts selected.</p><label>Action <select name="action"><option value="acknowledge">Acknowledge</option><option value="assign">Assign</option></select></label><label>Assignee <input name="assignee" maxlength="200"></label><label>Team <input name="team" maxlength="200"></label><label>Reason <input name="reason" required maxlength="500" value="bounded analyst action"></label><button value="confirm">Apply</button><button value="cancel">Cancel</button><p id="bulk-error" role="alert" tabindex="-1"></p></form></dialog>`;
  } catch (e) {
    return state("Alert queue unavailable", e.message);
  }
}
function evidenceList(values) {
  return values?.length
    ? `<ul>${values.map((x) => `<li><code>${esc(x)}</code></li>`).join("")}</ul>`
    : '<p class="muted">None recorded.</p>';
}
async function alertDetailPage(id) {
  try {
    const [ab, tb, eb, pb] = await Promise.all([
        api(`/api/v1/alerts/${id}`),
        api(`/api/v1/alerts/${id}/timeline`),
        api(`/api/v1/alerts/${id}/evidence`),
        api(`/api/v1/alerts/${id}/pivots`),
      ]),
      x = ab.data,
      e = eb.data,
      p = pb.data;
    return `<a href="#/alerts">Back to alert queue</a><div class="detail-head"><div><h2>${esc(x.title)}</h2><p><code>${esc(x.alertId)}</code> · schema ${esc(x.schemaVersion)} · version ${x.version}</p></div><span class="badge">${esc(x.currentStatus)}</span></div><div class="panels"><article><h3>Classification</h3><dl><dt>Severity / priority / confidence</dt><dd>${x.severity} / ${x.priority} / ${x.confidence}</dd><dt>Disposition</dt><dd>${esc(x.disposition)}</dd><dt>Category</dt><dd>${esc(x.category)}</dd><dt>ATT&amp;CK</dt><dd>${esc(x.mitreTechniques.join(", ") || "None")}</dd><dt>Rule/version</dt><dd><code>${esc(x.ruleId)}</code> v${x.ruleVersion}</dd></dl></article><article><h3>Ownership and timing</h3><dl><dt>Assignee/team</dt><dd>${esc(x.assignee || "Unassigned")} / ${esc(x.team || "Unassigned")}</dd><dt>Age</dt><dd>${Math.round(x.ageSeconds)}s</dd><dt>Acknowledge</dt><dd>${x.timeToAcknowledgeSeconds ?? "Pending"}</dd><dt>Assign</dt><dd>${x.timeToAssignSeconds ?? "Pending"}</dd><dt>Investigation</dt><dd>${x.timeToInvestigationSeconds ?? "Pending"}</dd><dt>Close</dt><dd>${x.timeToCloseSeconds ?? "Pending"}</dd><dt>Reopens</dt><dd>${x.reopenCount}</dd></dl></article><article><h3>Finding provenance</h3><dl><dt>Type</dt><dd>${esc(x.alertType)}</dd><dt>Detection finding</dt><dd>${esc(x.sourceFindingId || "None")}</dd><dt>Correlated finding</dt><dd>${esc(x.sourceCorrelatedFindingId || "None")}</dd><dt>Repeat count</dt><dd>${x.repeatCount}</dd><dt>Evidence completeness</dt><dd>${e.missingEvidence.length ? `Missing: ${esc(e.missingEvidence.join(", "))}` : "Complete"}</dd></dl></article></div><section><h2>Investigation pivots</h2><p>${p.endpoint ? `<a href="#/endpoints/${p.endpoint.split("/").pop()}">Endpoint</a> · ` : ""}${p.processTree ? `<a href="#/process-tree?root=${encodeURIComponent(e.processEntities[0])}">Process tree</a> · <a href="#/entity-graph?root=${encodeURIComponent(e.processEntities[0])}">Entity graph</a> · <a href="#/attack-stories?root=${encodeURIComponent(e.processEntities[0])}">Attack story</a> · <a href="#/threat-hunting?root=${encodeURIComponent(e.processEntities[0])}">Threat hunt</a>` : "No process pivot"}</p><h3>Authoritative evidence references</h3>${evidenceList(e.evidenceReferences)}</section><section><h2>Analyst actions</h2><div class="panels"><form id="alert-assignment"><h3>Assignment</h3><label>Assignee <input name="assignee" value="${esc(x.assignee || "")}" maxlength="200"></label><label>Team <input name="team" value="${esc(x.team || "")}" maxlength="200"></label><label>Reason <input name="reason" required value="analyst assignment"></label><button>Assign</button></form><form id="alert-status"><h3>Status and disposition</h3><label>Status <select name="status">${optionList(alertStatuses, x.currentStatus)}</select></label><label>Disposition <select name="disposition">${optionList(alertDispositions, x.disposition)}</select></label><label>Reason <input name="reason" required value="evidence-based triage"></label><button>Apply transition</button></form><form id="alert-note"><h3>Immutable note</h3><label>Kind <select name="kind"><option>Comment</option><option>Investigation</option><option>Handoff</option><option>DispositionRationale</option></select></label><label>Plain-text note <textarea name="content" required maxlength="4096"></textarea></label><button>Add note</button></form></div><p id="alert-action-status" role="status" tabindex="-1"></p></section><section><h2>Comments</h2>${x.comments.length ? `<ol class="timeline">${x.comments.map((n) => `<li><strong>${esc(n.kind)}</strong> by ${esc(n.author)} at ${new Date(n.createdAt).toLocaleString()}<p>${esc(n.content)}</p></li>`).join("")}</ol>` : '<p class="muted">No notes.</p>'}</section><section><h2>Immutable audit history</h2><ol class="timeline">${tb.data.map((a) => `<li><time>${new Date(a.occurredAt).toLocaleString()}</time> <strong>${esc(a.action)}</strong> by ${esc(a.actor)}<p>${esc(a.reason)}</p></li>`).join("")}</ol></section>`;
  } catch (e) {
    return state("Alert details unavailable", e.message);
  }
}
async function alertLineageWindow(id) {
  try {
    const [alertResponse, evidenceResponse, pivotResponse] = await Promise.all([
        api(`/api/v1/alerts/${id}`),
        api(`/api/v1/alerts/${id}/evidence`),
        api(`/api/v1/alerts/${id}/pivots`),
      ]),
      alert = alertResponse.data,
      evidence = evidenceResponse.data,
      endpointId = pivotResponse.data.endpoint?.split("/").pop(),
      processEntityId = evidence.processEntities?.[0];
    if (!endpointId || !processEntityId)
      return state("Process lineage unavailable", "This alert has no evidence-backed endpoint and stable process identity. No lineage was inferred.", `<a class="button" href="#/alerts/${encodeURIComponent(id)}">Return to alert</a>`);
    const [process, lineage] = await Promise.all([
        api(`/api/v1/endpoints/${encodeURIComponent(endpointId)}/processes/${encodeURIComponent(processEntityId)}`).then((value) => value.data).catch(() => null),
        api(`/api/v1/endpoints/${encodeURIComponent(endpointId)}/processes/${encodeURIComponent(processEntityId)}/lineage?ancestorDepth=16&descendantDepth=8`).then((value) => normalizeProcessLineage(value.data, endpointId)),
      ]),
      processes = mergeSelectedProcess(lineage.processes, processEntityId, process);
    return lineageStudioMarkup(processes, processEntityId, endpointId, alert);
  } catch (error) {
    return state("Process lineage unavailable", error.message, `<a class="button" href="#/alerts/${encodeURIComponent(id)}">Return to alert</a>`);
  }
}
async function alertDetailPageV2(id) {
  try {
    const [ab, tb, eb, pb] = await Promise.all([
        api(`/api/v1/alerts/${id}`),
        api(`/api/v1/alerts/${id}/timeline`),
        api(`/api/v1/alerts/${id}/evidence`),
        api(`/api/v1/alerts/${id}/pivots`),
      ]),
      x = ab.data,
      evidence = eb.data,
      pivots = pb.data,
      endpointId = pivots.endpoint?.split("/").pop(),
      processEntityId = evidence.processEntities?.[0];
    let process = null,
      tree = null;
    if (endpointId && processEntityId) {
      [process, tree] = await Promise.all([
        api(`/api/v1/endpoints/${encodeURIComponent(endpointId)}/processes/${encodeURIComponent(processEntityId)}`).then((value) => value.data).catch(() => null),
        api(`/api/v1/endpoints/${encodeURIComponent(endpointId)}/processes/${encodeURIComponent(processEntityId)}/lineage?ancestorDepth=8&descendantDepth=4`).then((value) => normalizeProcessLineage(value.data, endpointId)).catch(() => null),
      ]);
    }
    const processName = process?.name || process?.executableName || x.category || "Observed activity",
      commandLine = process?.commandLine,
      processPath = process?.path || process?.executablePath,
      missing = evidence.missingEvidence || [],
      quality = missing.length ? `Partial · missing ${missing.join(", ")}` : "Complete",
      severityLabel = x.severity >= 90 ? "Critical" : x.severity >= 70 ? "High" : x.severity >= 40 ? "Medium" : "Low",
      processDetailLink = endpointId && processEntityId ? `#/processes/${endpointId}/${encodeURIComponent(processEntityId)}?alertId=${encodeURIComponent(id)}` : null,
      observed = process?.startTime || x.lastSeen || x.firstSeen,
      treeProcesses = tree?.processes?.length
        ? mergeSelectedProcess(tree.processes, processEntityId, process)
        : processEntityId
          ? [{ entityId: processEntityId, displayName: processName, firstObserved: process?.startTime || new Date().toISOString(), evidenceIds: evidence.rawEventIds || [], dataQuality: process?.dataQualityFlags || [], properties: { commandLine, pid: process?.pid ?? process?.processId, parentPid: process?.parentPid ?? process?.parentProcessId, parentProcessEntityId: process?.parentProcessEntityId, path: processPath, workingDirectory: process?.workingDirectory, user: process?.userName || process?.userId || process?.user, userId: process?.userId, sessionId: process?.sessionId, integrity: process?.integrityLevel || process?.integrity, elevated: process?.elevated, architecture: process?.architecture, collector: process?.collectorType, collectorVersion: process?.collectorVersion, startTime: process?.startTime, exitTime: process?.exitTime } }]
          : [];
    const processContextQuery = endpointId ? `&endpointId=${encodeURIComponent(endpointId)}` : "";
    return `<div class="alert-v2"><a class="back-link" href="#/alerts">← Return to analyst alert queue</a><header class="alert-hero"><div><div class="alert-signals">${statusBadge(severityLabel, "severity")}<span class="badge priority">P${x.priority}</span>${statusBadge(x.currentStatus)}<span class="confidence"><meter min="0" max="100" value="${x.confidence}">${x.confidence}%</meter>${x.confidence}% confidence</span></div><h2>${esc(x.title)}</h2><p class="identifier-line">${esc(x.alertId)} · ${esc(x.mitreTechniques.join(", ") || "No ATT&CK mapping")} · ${esc(x.category)}</p></div><div class="alert-primary-actions"><a class="button primary" href="#/dfir-workspace?alertId=${encodeURIComponent(id)}">Investigate</a><a class="button" href="#/response-actions/new?alertId=${encodeURIComponent(id)}">Response options</a></div></header><section class="why-fired" aria-labelledby="why-fired-title"><span class="section-eyebrow">DECISION SUMMARY</span><h3 id="why-fired-title">Why this alert fired</h3><p><strong>${esc(processName)}</strong> matched the detection “${esc(x.title)}”. ${commandLine ? "The exact observed command line is shown below." : "Command-line telemetry was not available for this evidence."}</p><div class="alert-fact-grid"><div><span>Endpoint</span><strong>${esc(endpointId || "Not linked")}</strong></div><div><span>Process</span><strong>${esc(processName)}${process?.pid || process?.processId ? ` · PID ${process.pid ?? process.processId}` : ""}</strong></div><div><span>Observed</span><strong>${observed ? new Date(observed).toLocaleString() : "Not reported"}</strong></div><div><span>Evidence quality</span><strong>${esc(quality)}</strong></div><div><span>Rule</span><strong>${esc(x.ruleId)} · v${x.ruleVersion}</strong></div><div><span>Disposition</span><strong>${esc(x.disposition)}</strong></div></div></section><section id="workspace-evidence" class="command-evidence" aria-labelledby="command-evidence-title"><div class="section-title-row"><div><span class="section-eyebrow">AUTHORITATIVE PROCESS EVIDENCE</span><h3 id="command-evidence-title">Command and execution context</h3></div>${processDetailLink ? `<a class="button" href="${processDetailLink}">Open process record</a>` : ""}</div><dl class="evidence-fields"><div><dt>Executable</dt><dd><code>${esc(processPath || "Not collected")}</code></dd></div><div class="wide"><dt>Full command line</dt><dd><pre class="command-line"><code>${esc(commandLine || "Not collected by the source")}</code></pre></dd></div><div><dt>Parent</dt><dd>${process?.parentPid ?? process?.parentProcessId ?? "Not collected"}${process?.parentProcessEntityId ? `<br><code>${esc(process.parentProcessEntityId)}</code>` : ""}</dd></div><div><dt>User / integrity</dt><dd>${esc(process?.userName || process?.user || "Not collected")} · ${esc(process?.integrityLevel || process?.integrity || "Not collected")}</dd></div><div><dt>Hash / signature</dt><dd>${esc(process?.executable?.sha256 || process?.executableMetadata?.sha256 || "Not collected")}<br>${esc(process?.executable?.signatureState || process?.executableMetadata?.signatureState || "Not checked")}</dd></div><div><dt>Collector</dt><dd>${esc(process?.collectorType || "See authoritative reference")}</dd></div></dl></section>${processEntityId ? `<section id="workspace-process" class="alert-process-section" aria-labelledby="alert-process-title"><div class="section-title-row"><div><span class="section-eyebrow">LINEAGE</span><h3 id="alert-process-title">Process tree</h3><p>Selected alerting process, its observed ancestry, and descendants.</p></div><a class="button" href="#/process-tree?root=${encodeURIComponent(processEntityId)}${processContextQuery}">Open full tree</a></div>${processMapMarkup(treeProcesses, processEntityId, { maximum: 60 })}</section>` : ""}<section id="workspace-entities" aria-labelledby="investigation-pivots-title"><div class="section-title-row"><div><span class="section-eyebrow">NEXT PIVOTS</span><h3 id="investigation-pivots-title">Continue investigation</h3></div></div><div class="pivot-grid">${endpointId ? `<a href="#/endpoints/${endpointId}"><strong>Endpoint</strong><span>Health, policy, and telemetry</span></a>` : ""}${processEntityId ? `<a href="#/entity-graph?root=${encodeURIComponent(processEntityId)}${processContextQuery}"><strong>Entity graph</strong><span>Connected evidence and relationships</span></a><a href="#/attack-stories?root=${encodeURIComponent(processEntityId)}"><strong>Attack story</strong><span>Chronological evidence narrative</span></a><a href="#/threat-hunting?root=${encodeURIComponent(processEntityId)}"><strong>Threat hunt</strong><span>Search related activity</span></a>` : '<p class="muted">No process-backed investigation pivot is available.</p>'}</div><details class="technical-details"><summary>Evidence provenance and identifiers</summary><dl class="technical-grid"><div><dt>Detection finding</dt><dd><code>${esc(x.sourceFindingId || "None")}</code></dd></div><div><dt>Correlated finding</dt><dd><code>${esc(x.sourceCorrelatedFindingId || "None")}</code></dd></div><div><dt>Repeat count</dt><dd>${x.repeatCount}</dd></div><div><dt>Alert schema</dt><dd>${esc(x.schemaVersion)} · version ${x.version}</dd></div></dl><h4>Authoritative references</h4>${evidenceList(evidence.evidenceReferences)}</details></section><section id="workspace-actions" aria-labelledby="alert-actions-title"><div class="section-title-row"><div><span class="section-eyebrow">TRIAGE</span><h3 id="alert-actions-title">Analyst actions</h3><p>Assignment, lifecycle changes, and notes remain immutable and audited.</p></div></div><div class="action-form-grid"><form id="alert-assignment"><h4>Ownership</h4><label>Assignee <input name="assignee" value="${esc(x.assignee || "")}" maxlength="200"></label><label>Team <input name="team" value="${esc(x.team || "")}" maxlength="200"></label><label>Reason <input name="reason" required value="analyst assignment"></label><button>Assign</button></form><form id="alert-status"><h4>Status and disposition</h4><label>Status <select name="status">${optionList(alertStatuses, x.currentStatus)}</select></label><label>Disposition <select name="disposition">${optionList(alertDispositions, x.disposition)}</select></label><label>Reason <input name="reason" required value="evidence-based triage"></label><button>Apply transition</button></form><form id="alert-note"><h4>Immutable note</h4><label>Kind <select name="kind"><option>Comment</option><option>Investigation</option><option>Handoff</option><option>DispositionRationale</option></select></label><label>Plain-text note <textarea name="content" required maxlength="4096"></textarea></label><button>Add note</button></form></div><p id="alert-action-status" role="status" tabindex="-1"></p></section><section id="workspace-audit" aria-labelledby="alert-history-title"><div class="section-title-row"><div><span class="section-eyebrow">RECORDED HISTORY</span><h3 id="alert-history-title">Timeline and audit</h3></div></div>${x.comments.length ? `<h4>Analyst notes</h4><ol class="timeline">${x.comments.map((note) => `<li><strong>${esc(note.kind)}</strong> by ${esc(note.author)} <time>${new Date(note.createdAt).toLocaleString()}</time><p>${esc(note.content)}</p></li>`).join("")}</ol>` : '<p class="muted">No analyst notes.</p>'}<details class="technical-details"><summary>Immutable audit history (${tb.data.length})</summary><ol class="timeline">${tb.data.map((item) => `<li><time>${new Date(item.occurredAt).toLocaleString()}</time> <strong>${esc(item.action)}</strong> by ${esc(item.actor)}<p>${esc(item.reason)}</p></li>`).join("")}</ol></details></section></div>`;
  } catch (error) {
    return state("Alert details unavailable", error.message);
  }
}
async function submitAlertAction(e, id, kind) {
  e.preventDefault();
  const f = new FormData(e.target),
    out = document.querySelector("#alert-action-status");
  try {
    if (kind === "assignment")
      await api(`/api/v1/alerts/${id}:assign`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          assignee: f.get("assignee") || null,
          team: f.get("team") || null,
          reason: f.get("reason"),
        }),
      });
    else if (kind === "note")
      await api(`/api/v1/alerts/${id}/comments`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          kind: f.get("kind"),
          content: f.get("content"),
        }),
      });
    else {
      await api(`/api/v1/alerts/${id}:status`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          status: f.get("status"),
          reason: f.get("reason"),
        }),
      });
      if (f.get("disposition") !== "None")
        await api(`/api/v1/alerts/${id}:disposition`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            disposition: f.get("disposition"),
            reason: f.get("reason"),
          }),
        });
    }
    out.textContent = "Action recorded in immutable audit history.";
    await route();
  } catch (error) {
    out.textContent = error.message;
    out.focus();
  }
}
function incidentRows(items) {
  return items.length
    ? `<div class="table-wrap"><table><caption>Incident queue</caption><thead><tr><th>Updated</th><th>Incident</th><th>Priority</th><th>Status</th><th>Owner</th><th>Alerts</th><th>Evidence</th></tr></thead><tbody>${items.map((x) => `<tr><td>${new Date(x.updatedAt).toLocaleString()}</td><td><a href="#/incidents/${x.incidentId}">${esc(x.title)}</a></td><td>${x.priority}</td><td>${esc(x.status)}</td><td>${esc(x.assignee || x.team || x.owner)}</td><td>${x.alertIds.length}</td><td>${x.evidenceReferences.length}</td></tr>`).join("")}</tbody></table></div>`
    : state(
        "No incidents",
        "Create an incident from selected strongly related alerts.",
      );
}
async function incidentQueue() {
  try {
    const q = new URLSearchParams(location.hash.split("?")[1] || ""),
      b = await api(`/api/v1/incidents?${q}`);
    return `<form id="incident-filter" class="toolbar"><label>Status <select name="status"><option value="">Any</option>${optionList(incidentStatuses, q.get("status"))}</select></label><label>Priority <select name="priority"><option value="">Any</option>${[1, 2, 3, 4, 5].map((x) => `<option>${x}</option>`).join("")}</select></label><label>Assignee <input name="assignee" value="${esc(q.get("assignee") || "")}"></label><label>Team <input name="team" value="${esc(q.get("team") || "")}"></label><button>Filter</button></form>${incidentRows(b.data.items || [])}<section><h2>Create incident from exact alerts</h2><form id="incident-create" class="admin-grid"><label>Title <input name="title" required maxlength="200"></label><label>Summary <textarea name="summary" required maxlength="4096"></textarea></label><label>Alert IDs, one per line <textarea name="alerts" required></textarea></label><label>Grouping reason <input name="reason" required value="manual selected alerts"></label><button>Create incident</button><p id="incident-create-status" role="alert" tabindex="-1"></p></form></section>`;
  } catch (e) {
    return state("Incident queue unavailable", e.message);
  }
}
async function incidentDetailPage(id) {
  try {
    const [ib, tb, pb] = await Promise.all([
        api(`/api/v1/incidents/${id}`),
        api(`/api/v1/incidents/${id}/timeline`),
        api(`/api/v1/incidents/${id}/pivots`),
      ]),
      x = ib.data,
      t = tb.data,
      p = pb.data;
    return `<a href="#/incidents">Back to incidents</a><div class="detail-head"><div><h2>${esc(x.title)}</h2><p><code>${esc(x.incidentId)}</code> · version ${x.version}</p></div><span class="badge">${esc(x.status)}</span></div><div class="panels"><article><h3>Summary</h3><p>${esc(x.summary)}</p><dl><dt>Severity / priority / confidence</dt><dd>${x.severity} / ${x.priority} / ${x.confidence}</dd><dt>Disposition</dt><dd>${esc(x.disposition)}</dd><dt>Grouping</dt><dd>${esc(x.groupingReason)}</dd></dl></article><article><h3>Entities</h3><dl><dt>Endpoints</dt><dd>${x.endpointIds.length}</dd><dt>Users</dt><dd>${esc(x.users.join(", ") || "None")}</dd><dt>Processes</dt><dd>${x.processEntities.length}</dd><dt>Files</dt><dd>${x.files.length}</dd><dt>Network/DNS</dt><dd>${x.networkDnsEntities.length}</dd></dl></article><article><h3>ATT&amp;CK and evidence</h3><p>${esc(x.mitreTechniques.join(", ") || "No mapping")}</p><p>${x.evidenceReferences.length} authoritative references · ${x.attackStoryIds.length} attack stories</p></article></div><section><h2>Alerts</h2><ul>${x.alertIds.map((a) => `<li><a href="#/alerts/${a}">${esc(a)}</a></li>`).join("")}</ul></section><section><h2>Investigation pivots</h2><p>${p.processTrees.map((_, i) => `<a href="#/process-tree?root=${encodeURIComponent(x.processEntities[i])}">Process tree ${i + 1}</a>`).join(" · ") || "No process tree"} · <a href="#/threat-hunting">Combined hunt starting points</a></p></section><section><h2>Incident actions</h2><div class="panels"><form id="incident-assignment"><h3>Assignment</h3><label>Assignee <input name="assignee" value="${esc(x.assignee || "")}"></label><label>Team <input name="team" value="${esc(x.team || "")}"></label><label>Reason <input name="reason" required value="incident assignment"></label><button>Assign</button></form><form id="incident-status"><h3>Status and disposition</h3><label>Status <select name="status">${optionList(incidentStatuses, x.status)}</select></label><label>Disposition <select name="disposition">${optionList(alertDispositions, x.disposition)}</select></label><label>Reason <input name="reason" required value="evidence-based incident triage"></label><button>Apply</button></form><form id="incident-note"><h3>Immutable note</h3><label>Kind <select name="kind"><option>Comment</option><option>Investigation</option><option>Handoff</option><option>DispositionRationale</option></select></label><label>Plain-text note <textarea name="content" required maxlength="4096"></textarea></label><button>Add note</button></form></div><p id="incident-action-status" role="status" tabindex="-1"></p></section><section><h2>Combined evidence timeline</h2><ol class="timeline">${t.alerts.flatMap((a) => a.auditHistory.map((v) => `<li><time>${new Date(v.occurredAt).toLocaleString()}</time> <a href="#/alerts/${a.alertId}">${esc(a.title)}</a>: ${esc(v.action)}</li>`)).join("")}</ol></section><section><h2>Incident audit trail</h2><ol class="timeline">${x.auditHistory.map((a) => `<li><time>${new Date(a.occurredAt).toLocaleString()}</time> <strong>${esc(a.action)}</strong> by ${esc(a.actor)}<p>${esc(a.reason)}</p></li>`).join("")}</ol></section>`;
  } catch (e) {
    return state("Incident details unavailable", e.message);
  }
}
async function submitIncidentAction(e, id, kind) {
  e.preventDefault();
  const f = new FormData(e.target),
    out = document.querySelector("#incident-action-status");
  try {
    if (kind === "assignment")
      await api(`/api/v1/incidents/${id}:assign`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          assignee: f.get("assignee") || null,
          team: f.get("team") || null,
          reason: f.get("reason"),
        }),
      });
    else if (kind === "note")
      await api(`/api/v1/incidents/${id}/comments`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          kind: f.get("kind"),
          content: f.get("content"),
        }),
      });
    else {
      await api(`/api/v1/incidents/${id}:status`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          status: f.get("status"),
          reason: f.get("reason"),
        }),
      });
      if (f.get("disposition") !== "None")
        await api(`/api/v1/incidents/${id}:disposition`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            disposition: f.get("disposition"),
            reason: f.get("reason"),
          }),
        });
    }
    out.textContent = "Incident action audited.";
    await route();
  } catch (error) {
    out.textContent = error.message;
    out.focus();
  }
}
function openAlertBulk() {
  const ids = [...document.querySelectorAll(".alert-select:checked")].map(
      (x) => x.value,
    ),
    dialog = document.querySelector("#bulk-dialog");
  document.querySelector("#bulk-count").textContent =
    `${ids.length} selected; maximum 100.`;
  dialog.dataset.ids = ids.join(",");
  dialog.showModal();
  dialog.querySelector("select").focus();
}
async function submitAlertBulk(e) {
  e.preventDefault();
  const dialog = document.querySelector("#bulk-dialog"),
    ids = (dialog.dataset.ids || "").split(",").filter(Boolean),
    f = new FormData(e.target),
    out = document.querySelector("#bulk-error");
  try {
    if (!ids.length || ids.length > 100) throw Error("Select 1-100 alerts.");
    const mutation =
      f.get("action") === "acknowledge"
        ? { status: "Acknowledged", reason: f.get("reason") }
        : {
            assignee: f.get("assignee") || null,
            team: f.get("team") || null,
            reason: f.get("reason"),
          };
    await api("/api/v1/alerts:bulk", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alertIds: ids, mutation }),
    });
    dialog.close();
    await route();
  } catch (error) {
    out.textContent = error.message;
    out.focus();
  }
}
async function saveAlertFilter(e) {
  e.preventDefault();
  const f = new FormData(e.target),
    q = new URLSearchParams(location.hash.split("?")[1] || ""),
    now = new Date().toISOString(),
    number = (n) => (q.get(n) ? Number(q.get(n)) : null);
  try {
    await api("/api/v1/triage-filters", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        filterId: "00000000-0000-0000-0000-000000000000",
        tenantId: "00000000-0000-0000-0000-000000000000",
        owner: "ui",
        name: f.get("name"),
        query: {
          severity: number("severity"),
          priority: number("priority"),
          status: q.get("status") || null,
          disposition: q.get("disposition") || null,
          assignee: q.get("assignee") || null,
          team: q.get("team") || null,
          endpointId: q.get("endpointId") || null,
          user: q.get("user") || null,
          ruleId: q.get("ruleId") || null,
          mitreTechnique: q.get("mitreTechnique") || null,
          evidenceQuality: q.get("evidenceQuality") || null,
          sort: q.get("sort") || "updated-desc",
          pageSize: 100,
        },
        version: 1,
        createdAt: now,
      }),
    });
    await route();
  } catch (error) {
    alert(error.message);
  }
}
async function createIncidentUi(e) {
  e.preventDefault();
  const f = new FormData(e.target),
    out = document.querySelector("#incident-create-status");
  try {
    const ids = String(f.get("alerts")).split(/\s+/).filter(Boolean),
      b = await api("/api/v1/incidents", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: f.get("title"),
          summary: f.get("summary"),
          alertIds: ids,
          groupingReason: f.get("reason"),
        }),
      });
    location.hash = `#/incidents/${b.data.incidentId}`;
  } catch (error) {
    out.textContent = error.message;
    out.focus();
  }
}
async function triageHealth() {
  try {
    const h = (await api("/api/v1/triage-health")).data;
    return `<div class="panels"><article><h2>Alerts</h2><dl><dt>Created</dt><dd>${h.alertsCreated}</dd><dt>Deduplicated</dt><dd>${h.alertsDeduplicated}</dd><dt>Closed</dt><dd>${h.alertsClosed}</dd><dt>Reopened</dt><dd>${h.alertsReopened}</dd></dl></article><article><h2>Incidents</h2><dl><dt>Created</dt><dd>${h.incidentsCreated}</dd><dt>Closed</dt><dd>${h.incidentsClosed}</dd><dt>Grouping executions/failures</dt><dd>${h.groupingExecutions}/${h.groupingFailures}</dd></dl></article><article><h2>Integrity and latency</h2><dl><dt>Assignment failures</dt><dd>${h.assignmentFailures}</dd><dt>Invalid transitions</dt><dd>${h.invalidStateTransitions}</dd><dt>Queue/API/export latency</dt><dd>${h.queueLatencyMilliseconds}/${h.apiLatencyMilliseconds}/${h.exportLatencyMilliseconds}ms</dd></dl><p>No user, alert or incident identifiers are metric labels.</p></article></div>`;
  } catch (e) {
    return state("Triage health unavailable", e.message);
  }
}

function responseActionTable(items) {
  if (!items.length)
    return '<p class="muted">No response actions match this view.</p>';
  return `<div class="table-wrap"><table><caption class="sr-only">Tenant response actions</caption><thead><tr><th>Requested</th><th>Action</th><th>Target</th><th>Requester</th><th>Approval</th><th>Status</th><th>Expires</th></tr></thead><tbody>${items.map((x) => `<tr><td><a href="#/response-actions/${x.responseActionId}">${new Date(x.requestedAt).toLocaleString()}</a></td><td>${esc(x.actionType)} v${x.actionVersion}</td><td><code>${esc(x.endpointId)}</code></td><td>${esc(x.analystId)}</td><td>${esc(x.approvalState)}</td><td><span class="badge ${esc(String(x.state).toLowerCase())}">${esc(x.state)}</span></td><td>${new Date(x.expiresAt).toLocaleString()}</td></tr>`).join("")}</tbody></table></div>`;
}

async function responseActionList() {
  try {
    const query = new URLSearchParams(location.hash.split("?")[1] || "");
    const suffix = query.toString() ? `?${query}` : "";
    const [actions, definitions] = await Promise.all([
      api(`/api/v1/response-actions${suffix}`),
      api("/api/v1/response-actions/definitions"),
    ]);
    const items = actions.data.items || [],
      active = items.filter(
        (x) =>
          ![
            "Succeeded",
            "Failed",
            "TimedOut",
            "Cancelled",
            "Expired",
            "Rejected",
          ].includes(x.state),
      ),
      completed = items.filter((x) => !active.includes(x));
    return `<div class="toolbar"><p>Signed, tenant-bound actions from the compiled safe allowlist.</p><a class="button" href="#/response-actions/new${query.get("endpointId") ? `?endpointId=${encodeURIComponent(query.get("endpointId"))}` : ""}">Request action</a></div><section><h2>Supported actions</h2><div class="endpoint-grid">${definitions.data.map((x) => `<article class="card"><h3>${esc(x.name)}</h3><p>${esc(x.description)}</p><small>${esc(x.actionType)} v${x.actionVersion} · ${esc(x.supportedPlatforms.join(", "))} · ${x.approvalRequired ? "Approval required" : "No approval"}</small></article>`).join("")}</div></section><section><h2>Active actions</h2>${responseActionTable(active)}</section><section><h2>Completed actions</h2>${responseActionTable(completed)}</section>`;
  } catch (e) {
    return state("Response actions unavailable", e.message);
  }
}

async function responseRequestPage() {
  try {
    const query = new URLSearchParams(location.hash.split("?")[1] || ""),
      endpointId = query.get("endpointId") || "";
    const [endpoints, definitions] = await Promise.all([
      api("/api/v1/endpoints?pageSize=100"),
      api("/api/v1/response-actions/definitions"),
    ]);
    const safeDefinitions = definitions.data.filter(
      (x) => !["endpoint.isolate", "endpoint.unisolate", "endpoint.isolation_status"].includes(x.actionType),
    );
    return `<a href="#/response-actions">← Response actions</a><form id="response-request" class="admin-grid"><fieldset><legend>Safe response request</legend><label>Exact endpoint <select name="endpointId" required><option value="">Select endpoint</option>${(endpoints.data.items || []).map((x) => `<option value="${x.id}" ${x.id === endpointId ? "selected" : ""}>${esc(x.hostname)} — ${esc(x.platform)} — ${esc(x.status)}</option>`).join("")}</select></label><label>Predefined action <select name="actionType" required>${safeDefinitions.map((x) => `<option value="${esc(x.actionType)}" data-version="${x.actionVersion}">${esc(x.name)} (${esc(x.actionType)})</option>`).join("")}</select></label><label>Timeout seconds <input name="timeoutSeconds" type="number" min="5" max="60" value="30" required></label><label>Expiry seconds <input name="expiresInSeconds" type="number" min="30" max="86400" value="900" required></label><label>Strict JSON parameters <textarea name="parameters" rows="8" required>{}</textarea></label><input name="sourceAlertId" type="hidden" value="${esc(query.get("alertId") || "")}"><input name="sourceIncidentId" type="hidden" value="${esc(query.get("incidentId") || "")}"><input name="sourceEntityId" type="hidden" value="${esc(query.get("entityId") || "")}"><p class="muted">Containment actions use the endpoint panel so management exceptions always come from trusted policy.</p><p id="response-request-status" role="alert" tabindex="-1"></p><button>Submit signed action request</button></fieldset></form>`;
  } catch (e) {
    return state("Response request unavailable", e.message);
  }
}

async function submitResponseRequest(event) {
  event.preventDefault();
  const form = event.currentTarget,
    status = document.querySelector("#response-request-status");
  try {
    const data = new FormData(form),
      parameters = JSON.parse(data.get("parameters"));
    const selected = form.elements.actionType.selectedOptions[0];
    const body = {
      endpointId: data.get("endpointId"),
      actionType: data.get("actionType"),
      actionVersion: Number(selected.dataset.version),
      parameters,
      timeoutSeconds: Number(data.get("timeoutSeconds")),
      expiresInSeconds: Number(data.get("expiresInSeconds")),
      sourceAlertId: data.get("sourceAlertId") || null,
      sourceIncidentId: data.get("sourceIncidentId") || null,
      sourceEntityId: data.get("sourceEntityId") || null,
    };
    const result = await api("/api/v1/response-actions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    location.hash = `#/response-actions/${result.data.responseActionId}`;
  } catch (e) {
    status.textContent = e.message;
    status.focus();
  }
}

function responseAudit(history) {
  return `<ol class="timeline">${history.map((x) => `<li><time>${new Date(x.occurredAt).toLocaleString()}</time> <strong>${esc(x.action)}</strong> by ${esc(x.actor)}<p>${esc(x.reason)} · parameter hash <code>${esc(x.parameterHash)}</code></p></li>`).join("")}</ol>`;
}

async function responseActionDetail(id) {
  try {
    const [action, history] = await Promise.all([
        api(`/api/v1/response-actions/${id}`),
        api(`/api/v1/response-actions/${id}/history`),
      ]),
      x = action.data,
      r = x.result;
    const pending = x.state === "PendingApproval",
      active = ![
        "Succeeded",
        "Failed",
        "TimedOut",
        "Cancelled",
        "Expired",
        "Rejected",
      ].includes(x.state);
    return `<a href="#/response-actions">← Response actions</a><div class="detail-head"><div><h2>${esc(x.actionType)} v${x.actionVersion}</h2><p><code>${esc(x.responseActionId)}</code></p></div><span class="badge ${esc(String(x.state).toLowerCase())}">${esc(x.state)}</span></div><div class="panels"><article><h3>Exact request</h3><dl><dt>Target endpoint</dt><dd><a href="#/endpoints/${x.endpointId}">${esc(x.endpointId)}</a></dd><dt>Agent installation</dt><dd><code>${esc(x.agentInstallationId)}</code></dd><dt>Requester</dt><dd>${esc(x.analystId)}</dd><dt>Requested</dt><dd>${new Date(x.requestedAt).toLocaleString()}</dd><dt>Expires</dt><dd>${new Date(x.expiresAt).toLocaleString()}</dd><dt>Parameter hash</dt><dd><code>${esc(x.parameterHash)}</code></dd><dt>Policy</dt><dd>${esc(x.policyVersion)}</dd></dl><h4>Parameters</h4><pre><code>${esc(JSON.stringify(x.parameters, null, 2))}</code></pre></article><article><h3>Approval</h3><dl><dt>State</dt><dd>${esc(x.approvalState)}</dd><dt>Approver</dt><dd>${esc(x.approverId || "Not approved")}</dd><dt>Reason</dt><dd>${esc(x.approvalReason || "None")}</dd><dt>Approved hash</dt><dd><code>${esc(x.approvedParameterHash || "None")}</code></dd></dl>${pending ? `<form id="response-approve"><label>Exact hash <input name="parameterHash" value="${esc(x.parameterHash)}" required></label><label>Approval reason <input name="reason" required maxlength="500"></label><button>Approve exact request</button></form><form id="response-reject"><label>Rejection reason <input name="reason" required maxlength="500"></label><button>Reject</button></form>` : ""}${active ? `<form id="response-cancel"><label>Cancellation reason <input name="reason" required maxlength="500"></label><button>Cancel action</button></form>` : ""}<p id="response-action-status" role="alert" tabindex="-1"></p></article></div><section><h2>Result details</h2>${r ? `<div class="panels"><article><dl><dt>State</dt><dd>${esc(r.state)}</dd><dt>Started/completed</dt><dd>${new Date(r.startedAt).toLocaleString()} / ${new Date(r.completedAt).toLocaleString()}</dd><dt>Records</dt><dd>${r.resultRecords}</dd><dt>Result hash</dt><dd><code>${esc(r.resultHash)}</code></dd><dt>stdout / stderr</dt><dd>${esc(r.stdoutState)} (${r.stdoutBytes}) / ${esc(r.stderrState)} (${r.stderrBytes})</dd><dt>Truncated</dt><dd>${r.truncated ? "Yes" : "No"}</dd><dt>Failure</dt><dd>${esc(r.failureCategory)} — ${esc(r.failureReason || "None")}</dd></dl><pre><code>${esc(JSON.stringify(r.structuredResult, null, 2))}</code></pre></article><article><h3>Artifacts</h3>${r.artifacts.length ? `<ul>${r.artifacts.map((a) => `<li><a href="/api/v1/response-actions/${id}/artifacts/${a.artifactId}/content">${esc(a.name)}</a> — ${a.size} bytes — <code>${esc(a.sha256)}</code></li>`).join("")}</ul>` : '<p class="muted">No artifacts.</p>'}</article></div>` : '<p class="muted">No endpoint result has been accepted.</p>'}</section><section><h2>Immutable audit timeline</h2>${responseAudit(history.data)}</section>`;
  } catch (e) {
    return state("Response action unavailable", e.message);
  }
}

async function responseDecision(event, id, operation) {
  event.preventDefault();
  const data = new FormData(event.currentTarget),
    status = document.querySelector("#response-action-status");
  try {
    const body = Object.fromEntries(data);
    await api(`/api/v1/response-actions/${id}:${operation}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    await route();
  } catch (e) {
    status.textContent = e.message;
    status.focus();
  }
}

async function responseHealthPage() {
  try {
    const x = (await api("/api/v1/response-health")).data;
    return `<div class="panels"><article><h2>Lifecycle totals</h2><dl>${["requested", "approvals", "rejections", "queued", "delivered", "acknowledged", "running", "succeeded", "failed", "timedOut", "expired", "cancelled"].map((k) => `<dt>${esc(k)}</dt><dd>${x[k]}</dd>`).join("")}</dl></article><article><h2>Safety and performance</h2><dl><dt>Replay rejections</dt><dd>${x.replayRejections}</dd><dt>Integrity failures</dt><dd>${x.integrityFailures}</dd><dt>Endpoint worker queue</dt><dd>${x.workerQueue}</dd><dt>Execution latency</dt><dd>${x.executionLatencyMilliseconds} ms</dd><dt>Upload latency</dt><dd>${x.resultUploadLatencyMilliseconds} ms</dd><dt>Updated</dt><dd>${new Date(x.updatedAt).toLocaleString()}</dd></dl></article></div>`;
  } catch (e) {
    return state("Response health unavailable", e.message);
  }
}

const liveTerminalText = (commands) =>
  commands
    .flatMap((c) => [
      `[${new Date(c.requestedAt).toLocaleString()}] ${c.commandType}> ${c.exactInput}`,
      ...(c.output || [])
        .sort((a, b) => a.sequence - b.sequence)
        .map((x) => `${x.stream}: ${x.text}`),
      `[${c.state}]${c.result?.exitCode == null ? "" : ` exit=${c.result.exitCode}`}`,
    ])
    .join("\n");
const endpointState = (value) => ({ 0: "Unknown", 1: "Pending", 2: "Online", 3: "Stale", 4: "Offline", 5: "Recovered", 6: "Disabled", 7: "Revoked" })[value] || String(value || "Unknown");
const endpointOnline = (value) => [2, 5, "Online", "Recovered"].includes(value);
const currentEndpoints = (items) => {
  const current = new Map();
  [...items].sort((a, b) => new Date(b.lastSeenAt || 0) - new Date(a.lastSeenAt || 0)).forEach((endpoint) => {
    if (!current.has(endpoint.deviceIdentity || endpoint.id)) current.set(endpoint.deviceIdentity || endpoint.id, endpoint);
  });
  return [...current.values()].sort((a, b) => Number(endpointOnline(b.status)) - Number(endpointOnline(a.status)) || new Date(b.lastSeenAt || 0) - new Date(a.lastSeenAt || 0) || a.hostname.localeCompare(b.hostname));
};
function liveTerminalHtml(commands, workingDirectory = "") {
  if (!commands.length) return '<div class="terminal-welcome">Remote terminal ready. Type a command below.</div>';
  return commands.map((command) => {
    const prompt = command.commandType === "PowerShell" ? "PS" : command.commandType === "Cmd" ? "C:\\>" : "OSP";
    const directory = command.workingDirectory || workingDirectory;
    const output = [...(command.output || [])].sort((a, b) => a.sequence - b.sequence).map((chunk) => `<span class="terminal-${esc(chunk.stream)}">${esc(chunk.text)}</span>`).join("");
    return `<div class="terminal-command"><div class="terminal-prompt"><span>${esc(prompt)}${prompt === "PS" ? ` ${directory}>` : ""}</span> ${esc(command.exactInput)}</div>${output ? `<pre>${output}</pre>` : `<div class="terminal-pending">${esc(command.state)}…</div>`}<div class="terminal-result ${statusClass(command.state)}">${esc(command.state)}${command.result?.exitCode == null ? "" : ` · exit ${command.result.exitCode}`}</div></div>`;
  }).join("");
}
function renderLiveTerminal(terminal, commands, workingDirectory = "", follow = false) {
  if (!terminal) return;
  const key = JSON.stringify((commands || []).map((command) => [command.commandId, command.state, command.output?.length || 0, command.result?.outputHash || ""]));
  if (!follow && terminal.dataset.renderKey === key) return;
  const previousTop = terminal.scrollTop,
    wasFollowing = terminal.scrollHeight - terminal.scrollTop - terminal.clientHeight <= 32;
  terminal.innerHTML = liveTerminalHtml(commands || [], workingDirectory);
  terminal.dataset.renderKey = key;
  terminal.scrollTop = follow || wasFollowing ? terminal.scrollHeight : previousTop;
}
function liveIsolationStatus(value, requestedState = "") {
  if (["IsolationPending", "Isolating"].includes(requestedState)) return { label: requestedState === "Isolating" ? "Isolating…" : "Isolation queued", className: "pending", description: "The isolation request is still being processed by the endpoint." };
  if (["UnisolationPending", "Unisolating"].includes(requestedState)) return { label: requestedState === "Unisolating" ? "Restoring…" : "Restore queued", className: "pending", description: "The network restoration request is still being processed by the endpoint." };
  if (value === "Isolated") return { label: "Isolated", className: "isolated", description: "Endpoint network isolation is active." };
  if (value === "NotIsolated" || value === "Not isolated") return { label: "Network open", className: "clear", description: "Endpoint network isolation is not active." };
  if (value === "Failed") return { label: "Isolation failed", className: "failed", description: "The most recent isolation attempt failed and its owned firewall controls were rolled back. The endpoint is not isolated." };
  if (value === "PartialIsolation") return { label: "Partial isolation", className: "failed", description: "Isolation is incomplete. Treat the endpoint as not safely isolated." };
  return { label: "State unavailable", className: "unknown", description: "The endpoint has not reported an authoritative isolation state yet." };
}
function renderLiveIsolationNotice(isolation) {
  let notice = document.querySelector("#live-isolation-notice");
  const failed = ["Failed", "PartialIsolation"].includes(isolation?.effectiveState) && !["IsolationPending", "Isolating", "UnisolationPending", "Unisolating"].includes(isolation?.requestedState);
  if (!failed) { notice?.remove(); return; }
  if (!notice) { notice = document.createElement("div"); notice.id = "live-isolation-notice"; document.querySelector(".live-console-grid")?.before(notice); }
  notice.className = "live-isolation-notice";
  notice.setAttribute("role", "alert");
  notice.innerHTML = `<div><strong>Endpoint is not isolated.</strong><span>${esc(isolation.failureReason || "The most recent isolation attempt failed and platform-owned firewall controls were rolled back.")}</span></div>${isolation.actionId ? `<a href="#/response-actions/${esc(isolation.actionId)}">View failed action</a>` : ""}`;
}
const liveBytes = (value) => value < 1024 ? `${value} B` : value < 1048576 ? `${(value / 1024).toFixed(1)} KB` : `${(value / 1048576).toFixed(1)} MB`;
function liveTransferPanelHtml(session) {
  const commands = session.commands || [], retrieved = commands.flatMap((command) => (command.result?.artifacts || []).map((artifact) => ({ command, artifact }))),
    collecting = commands.filter((command) => command.commandType === "BuiltIn" && /^get\s/i.test(command.normalizedInput || command.exactInput) && !(command.result?.artifacts || []).length),
    pushed = commands.filter((command) => command.commandType === "Upload");
  return `<div class="transfer-panel-head"><span class="section-eyebrow">Session files</span><h3>Transfers</h3><p>Files moving through this endpoint session.</p></div><form id="live-get-file" class="live-transfer-form"><label>Get from endpoint<input name="path" required maxlength="1024" autocomplete="off" spellcheck="false" placeholder="C:\\path\\artifact.zip"></label><button type="submit">Get file</button><p role="alert"></p></form><section><div class="transfer-section-title"><h4>Retrieved</h4><span>${retrieved.length}</span></div>${retrieved.length ? `<div class="transfer-list">${retrieved.map(({ command, artifact }) => `<article><div><strong>${esc(artifact.name)}</strong><small>${liveBytes(artifact.size)} · SHA-256 verified</small><code>${esc(artifact.sha256)}</code></div><button type="button" class="live-artifact" data-id="${artifact.artifactId}">Download</button></article>`).join("")}</div>` : '<p class="transfer-empty">No files retrieved yet.</p>'}${collecting.length ? `<div class="transfer-pending">${collecting.map((command) => `<p><strong>Collecting</strong> ${esc(command.exactInput.replace(/^get\s+/i, ""))}<span>${esc(command.state)}</span></p>`).join("")}</div>` : ""}</section><section><div class="transfer-section-title"><h4>Pushed</h4><span>${pushed.length}</span></div>${pushed.length ? `<div class="transfer-list">${pushed.map((command) => `<article><div><strong>${esc(command.exactInput.split(/[\\/]/).at(-1))}</strong><small>${esc(command.state)} · ${esc(command.exactInput)}</small><code>${esc(command.uploadSha256 || "Hash pending")}</code></div></article>`).join("")}</div>` : '<p class="transfer-empty">No files pushed in this session.</p>'}</section>`;
}
function installLiveConsoleLayout() {
  const shell = document.querySelector(".terminal-shell");
  if (!shell || shell.closest(".live-console-grid")) return;
  document.querySelector(".live-console-workspace > section .live-artifacts")?.closest("section")?.remove();
  const grid = document.createElement("div"), main = document.createElement("div"), aside = document.createElement("aside");
  grid.className = "live-console-grid"; main.className = "live-console-main"; aside.id = "live-transfer-panel"; aside.className = "live-transfer-panel"; aside.setAttribute("aria-label", "Live Response file transfers");
  const isolationState = document.querySelector("#live-isolation-state"), isolation = document.querySelector("#live-isolation"),
    consoleStatus = document.querySelector(".live-console-status"), endpointStatus = consoleStatus?.querySelector(".connection-state"),
    sessionState = document.querySelector("#live-session-state"), disconnect = document.querySelector("#live-disconnect");
  if (isolationState) {
    const value = isolationState.textContent.trim();
    const status = liveIsolationStatus(value);
    isolationState.textContent = status.label;
    isolationState.title = status.description;
    isolationState.setAttribute("aria-label", status.description);
    isolationState.className = `containment-state ${status.className}`;
  }
  if (isolation) {
    isolation.className = `containment-action ${isolation.dataset.operation === "unisolate" ? "restore" : "isolate"}`;
    isolation.title = isolation.dataset.operation === "unisolate" ? "Restore normal endpoint network access" : "Open the endpoint isolation confirmation";
    if (isolation.dataset.operation === "isolate" && !isolation.disabled) isolation.textContent = isolationState?.classList.contains("failed") ? "Retry isolation" : "Isolate";
  }
  if (consoleStatus) {
    const statusGroup = (label, className, nodes) => {
      const group = document.createElement("div"); group.className = `live-status-group ${className}`;
      const caption = document.createElement("span"); caption.className = "live-status-label"; caption.textContent = `${label}:`;
      group.append(caption, ...nodes.filter(Boolean)); return group;
    };
    consoleStatus.replaceChildren(
      statusGroup("Endpoint", "endpoint-status-group", [endpointStatus]),
      statusGroup("Network", "network-status-group", [isolationState, isolation]),
      statusGroup("Session", "session-status-group", [sessionState, disconnect]),
    );
  }
  shell.before(grid); main.append(shell); grid.append(main, aside);
  if (isolationState?.classList.contains("failed")) renderLiveIsolationNotice({ effectiveState: "Failed" });
}
function renderLiveTransferPanel(session) {
  const panel = document.querySelector("#live-transfer-panel"); if (!panel) return;
  const key = JSON.stringify((session.commands || []).map((command) => [command.commandId, command.state, command.result?.artifacts?.length || 0, command.result?.outputHash || ""]));
  if (panel.dataset.renderKey === key) return;
  panel.innerHTML = liveTransferPanelHtml(session); panel.dataset.renderKey = key;
  panel.querySelector("#live-get-file")?.addEventListener("submit", (event) => requestLiveFile(event, session.sessionId));
  panel.querySelectorAll(".live-artifact").forEach((button) => button.addEventListener("click", () => downloadLiveArtifact(button.dataset.id).catch((error) => notify(error.message, "error"))));
}
async function requestLiveFile(event, sessionId) {
  event.preventDefault(); const form = event.currentTarget, output = form.querySelector('[role="alert"]'), path = String(new FormData(form).get("path") || "").trim(), submit = form.querySelector("button");
  if (!path || /["\r\n\0]/.test(path)) { output.textContent = "Enter one exact path without quotes or line breaks."; return; }
  try {
    submit.disabled = true; output.textContent = "Collection queued…";
    await api(`/api/v1/live-response/sessions/${sessionId}/commands`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ commandType: "BuiltIn", input: `get "${path}"`, timeoutSeconds: 14400 }) });
    form.reset(); output.textContent = "Transfer started.";
    const session = (await api(`/api/v1/live-response/sessions/${sessionId}`)).data; renderLiveTerminal(document.querySelector("#live-terminal"), session.commands || [], session.workingDirectory, true); renderLiveTransferPanel(session);
  } catch (error) { output.textContent = error.message; } finally { submit.disabled = false; }
}
function liveSessionTable(items) {
  if (!items.length)
    return '<p class="muted">No Live Response sessions in this view.</p>';
  return `<div class="table-wrap"><table><caption class="sr-only">Tenant Live Response sessions</caption><thead><tr><th>Created</th><th>Endpoint</th><th>Requester</th><th>Capabilities</th><th>State</th><th>Last activity</th></tr></thead><tbody>${items.map((x) => `<tr><td><a href="#/live-response/${x.sessionId}">${new Date(x.createdAt).toLocaleString()}</a></td><td><a href="#/endpoints/${x.endpointId}"><code>${esc(x.endpointId)}</code></a></td><td>${esc(x.analystId)}</td><td>${esc(x.capabilities.join(", "))}</td><td><span class="badge ${esc(String(x.state).toLowerCase())}">${esc(x.state)}</span></td><td>${new Date(x.lastActivityAt).toLocaleString()}</td></tr>`).join("")}</tbody></table></div>`;
}
async function liveResponseList() {
  try {
    const [endpointResponse, sessionResponse] = await Promise.all([
      api("/api/v1/endpoints?pageSize=500"),
      api("/api/v1/live-response/sessions"),
    ]);
    const endpoints = currentEndpoints(endpointResponse.data.items || []).filter((endpoint) => endpoint.platform === "windows");
    const sessions = sessionResponse.data || [];
    const owned = new Map();
    sessions.filter((session) => ["Active", "Connecting", "Degraded"].includes(session.state) && session.analystId === jwtContext().subject).forEach((session) => { if (!owned.has(session.endpointId)) owned.set(session.endpointId, session); });
    const selectedClient = managedClients.find((client) => client.clientId === jwtContext().tenant);
    const clientList = managedClients.length ? managedClients : [{ clientId: jwtContext().tenant, name: "Current client", endpointCount: endpoints.length }];
    const endpointCard = (endpoint) => {
      const online = endpointOnline(endpoint.status), session = owned.get(endpoint.id), connection = endpointState(endpoint.status);
      return `<article class="live-endpoint ${online ? "online" : "offline"}"><button type="button" class="live-endpoint-open" data-endpoint="${esc(endpoint.id)}" ${session ? `data-session="${esc(session.sessionId)}"` : ""} ${online ? "" : "disabled"}><span class="endpoint-main"><strong>${esc(endpoint.hostname)}</strong><small>${esc(endpoint.osVersion || endpoint.platform)} · ${esc(endpoint.architecture || "Unknown architecture")}</small><code>${esc(endpoint.id)}</code></span><span class="endpoint-meta"><span class="connection-state ${online ? "online" : "offline"}"><i></i>${esc(connection)}</span><small>${online ? `Seen ${relativeTime(endpoint.lastSeenAt)}` : `Last seen ${relativeTime(endpoint.lastSeenAt)}`}</small><b>${session ? "Resume terminal" : online ? "Open terminal" : "Unavailable"}</b></span></button></article>`;
    };
    const onlineEndpoints = endpoints.filter((endpoint) => endpointOnline(endpoint.status));
    const offlineEndpoints = endpoints.filter((endpoint) => !endpointOnline(endpoint.status));
    const endpointDirectory = endpoints.length
      ? `<div class="live-directory-section"><div class="live-directory-heading"><h3>Available now</h3><span>${onlineEndpoints.length} online</span></div><div class="live-endpoints">${onlineEndpoints.length ? onlineEndpoints.map(endpointCard).join("") : '<p class="live-directory-empty">No endpoints are currently connected.</p>'}</div></div>${offlineEndpoints.length ? `<details class="live-offline-directory"><summary><span>Offline endpoints</span><small>${offlineEndpoints.length} unavailable · expand inventory</small></summary><div class="live-endpoints">${offlineEndpoints.map(endpointCard).join("")}</div></details>` : ""}`
      : state("No Windows endpoints", "This client has no enrolled Windows endpoints.");
    return `<div class="live-browser"><aside class="live-client-list" aria-label="Managed clients"><span class="section-eyebrow">Clients</span><h2>Organizations</h2>${clientList.map((client) => `<button type="button" class="live-client ${client.clientId === jwtContext().tenant ? "selected" : ""}" data-client="${esc(client.clientId)}"><span>${esc(client.name)}</span><small>${client.endpointCount}${client.hasMoreEndpoints ? "+" : ""} endpoints</small></button>`).join("")}</aside><section class="live-endpoint-list"><div class="section-title-row"><div><span class="section-eyebrow">Live Response</span><h2>${esc(selectedClient?.name || "Current client")}</h2><p>Select a connected endpoint to open its terminal.</p></div><a class="button compact" href="#/live-response-health">Service health</a></div>${endpointDirectory}<details class="technical-details"><summary>Previous Live Response sessions</summary>${liveSessionTable(sessions)}</details><p id="live-open-status" role="alert" tabindex="-1"></p></section></div>`;
  } catch (e) {
    return state("Live Response unavailable", e.message);
  }
}

async function openLiveEndpoint(event) {
  const button = event.currentTarget, existing = button.dataset.session, out = document.querySelector("#live-open-status");
  if (existing) { location.hash = `#/live-response/${existing}`; return; }
  button.disabled = true; button.querySelector("b").textContent = "Connecting…";
  try {
    const value = (await api("/api/v1/live-response/sessions", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ endpointId: button.dataset.endpoint, capabilities: ["builtin", "cmd", "powershell", "file-download"], idleTimeoutSeconds: 900, absoluteLifetimeSeconds: 3600, policyVersion: "live-response-policy.v1" }),
    })).data;
    location.hash = `#/live-response/${value.sessionId}`;
  } catch (error) { button.disabled = false; button.querySelector("b").textContent = "Open terminal"; out.textContent = error.message; out.focus(); }
}
async function liveResponseRequest() {
  try {
    const q = new URLSearchParams(location.hash.split("?")[1] || ""),
      endpointId = q.get("endpointId") || "",
      endpoints =
        (await api("/api/v1/endpoints?pageSize=100")).data.items || [];
    const currentByDevice = new Map();
    endpoints.sort((a, b) => new Date(b.lastSeenAt || 0) - new Date(a.lastSeenAt || 0)).forEach(x => { if (!currentByDevice.has(x.deviceIdentity)) currentByDevice.set(x.deviceIdentity, x); });
    endpoints.splice(0, endpoints.length, ...[...currentByDevice.values()].filter(x => x.platform === "windows" && [2, 5, "Online", "Recovered"].includes(x.status)));
    return `<a href="#/live-response">← Live Response</a><form id="live-session-request" class="admin-grid"><fieldset><legend>Authorize a bounded session</legend><label>Exact Windows endpoint <select name="endpointId" required><option value="">Select endpoint</option>${endpoints.map((x) => `<option value="${x.id}" ${x.id === endpointId ? "selected" : ""}>${esc(x.hostname)} — ${esc(x.platform)} — ${esc(x.status)}</option>`).join("")}</select></label><fieldset><legend>Capabilities</legend><label><input type="checkbox" name="capability" value="builtin" checked disabled> Safe built-ins (required)</label><label><input type="checkbox" name="capability" value="file-download"> File retrieval</label><label><input type="checkbox" name="capability" value="cmd"> Windows command shell</label><label><input type="checkbox" name="capability" value="powershell"> PowerShell</label></fieldset><div class="live-warning" role="note"><strong>Elevated capability warning.</strong> Cmd and PowerShell require separate approval and execute with the enrolled agent identity.</div><label>Idle timeout seconds <input type="number" name="idleTimeoutSeconds" min="60" max="3600" value="900" required></label><label>Absolute lifetime seconds <input type="number" name="absoluteLifetimeSeconds" min="300" max="14400" value="3600" required></label><input type="hidden" name="sourceAlertId" value="${esc(q.get("alertId") || "")}"><input type="hidden" name="sourceIncidentId" value="${esc(q.get("incidentId") || "")}"><input type="hidden" name="sourceEntityId" value="${esc(q.get("entityId") || "")}"><button>Request authorized session</button><p id="live-request-status" role="alert" tabindex="-1"></p></fieldset></form>`;
  } catch (e) {
    return state("Live Response request unavailable", e.message);
  }
}
async function submitLiveSession(event) {
  event.preventDefault();
  const f = new FormData(event.currentTarget),
    out = document.querySelector("#live-request-status");
  try {
    const capabilities = [
      "builtin",
      ...f.getAll("capability").filter((x) => x !== "builtin"),
    ];
    const body = {
      endpointId: f.get("endpointId"),
      capabilities,
      idleTimeoutSeconds: Number(f.get("idleTimeoutSeconds")),
      absoluteLifetimeSeconds: Number(f.get("absoluteLifetimeSeconds")),
      sourceAlertId: f.get("sourceAlertId") || null,
      sourceIncidentId: f.get("sourceIncidentId") || null,
      sourceEntityId: f.get("sourceEntityId") || null,
      policyVersion: "live-response-policy.v1",
    };
    const x = (
      await api("/api/v1/live-response/sessions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      })
    ).data;
    location.hash = `#/live-response/${x.sessionId}`;
  } catch (e) {
    out.textContent = e.message;
    out.focus();
  }
}
function liveTranscript(events) {
  return `<ol class="timeline">${events.map((x) => `<li><time>${new Date(x.occurredAt).toLocaleString()}</time> <strong>${esc(x.eventType)}</strong> by ${esc(x.actor)}<p>${esc(x.summary)}</p><small>integrity <code>${esc(x.integrityHash)}</code></small></li>`).join("")}</ol>`;
}
async function liveResponseDetailLegacy(id) {
  try {
    const x = (await api(`/api/v1/live-response/sessions/${id}`)).data,
      pending = x.state === "PendingApproval",
      active = x.state === "Active",
      terminal = liveTerminalText(x.commands || []);
    return `<a href="#/live-response">← Live Response</a><div class="detail-head"><div><h2>Session on ${esc(x.endpointId)}</h2><p><code>${esc(x.sessionId)}</code></p></div><span class="badge ${esc(String(x.state).toLowerCase())}">${esc(x.state)}</span></div><div class="panels"><article><h3>Authorization and binding</h3><dl><dt>Endpoint / agent</dt><dd>${esc(x.endpointId)} / ${esc(x.agentId)}</dd><dt>Installation</dt><dd><code>${esc(x.agentInstallationId)}</code></dd><dt>Requester</dt><dd>${esc(x.analystId)}</dd><dt>Approver</dt><dd>${esc(x.approverId || "Not required/pending")}</dd><dt>Capabilities</dt><dd>${esc(x.capabilities.join(", "))}</dd><dt>Capability hash</dt><dd><code>${esc(x.capabilityHash)}</code></dd><dt>Policy</dt><dd>${esc(x.policyVersion)}</dd><dt>Execution identity</dt><dd>${esc(x.executionIdentity || "Awaiting connection")} (${esc(x.integrityLevel || "unknown")})</dd><dt>Working directory</dt><dd><code>${esc(x.workingDirectory || "Awaiting connection")}</code></dd></dl>${pending ? `<form id="live-approve"><label>Exact capability hash <input name="capabilityHash" value="${esc(x.capabilityHash)}" required></label><label>Approval reason <input name="reason" required maxlength="500"></label><button>Approve exact capabilities</button></form><form id="live-reject"><label>Rejection reason <input name="reason" required maxlength="500"></label><button>Reject</button></form>` : ""}${active ? `<form id="live-close"><label>Closure reason <input name="reason" required maxlength="500"></label><button>Close session</button></form>` : ""}<p id="live-decision-status" role="alert" tabindex="-1"></p></article><article><h3>Safety bounds</h3><dl><dt>Idle expiry</dt><dd>${new Date(x.expiresAt).toLocaleString()}</dd><dt>Absolute expiry</dt><dd>${new Date(x.absoluteExpiresAt).toLocaleString()}</dd><dt>Commands</dt><dd>${x.commands.length}</dd><dt>Transcript hash</dt><dd><code>${esc(x.transcriptHash)}</code></dd></dl><button id="live-transcript-export">Export immutable transcript</button> <button id="live-refresh">Refresh</button><p id="live-export-status" role="status"></p></article></div>${active ? `<section><h2>Bounded terminal</h2><div class="live-warning"><strong>Remote execution.</strong> Cmd and PowerShell run exactly as entered using the shown agent identity. Review target and working directory before submission.</div><pre id="live-terminal" class="live-terminal" tabindex="0" aria-label="Live Response command transcript"></pre><form id="live-command"><label>Executor <select name="commandType"><option value="BuiltIn">Safe built-in</option>${x.capabilities.includes("cmd") ? '<option value="Cmd">Windows cmd.exe</option>' : ""}${x.capabilities.includes("powershell") ? '<option value="PowerShell">PowerShell</option>' : ""}</select></label><label>Exact command <textarea name="input" required maxlength="8192" placeholder="help"></textarea></label><label>Timeout seconds <input type="number" name="timeoutSeconds" min="1" max="300" value="30" required></label><button>Run exact command</button><p id="live-command-status" role="alert" tabindex="-1"></p></form></section>` : ""}<section><h2>Command history</h2>${(x.commands || []).length ? `<div class="table-wrap"><table><thead><tr><th>Command</th><th>Type</th><th>State</th><th>Result</th><th>Artifacts</th><th>Action</th></tr></thead><tbody>${x.commands.map((c) => `<tr><td><code>${esc(c.exactInput)}</code></td><td>${esc(c.commandType)}</td><td>${esc(c.state)}</td><td>${c.result ? `${c.result.exitCode ?? "—"}; ${c.result.stdoutBytes}/${c.result.stderrBytes} bytes${c.result.truncated ? "; truncated" : ""}` : "Pending"}</td><td>${(c.result?.artifacts || []).map((a) => `<a class="live-artifact" data-id="${a.artifactId}" href="#">${esc(a.name)}</a>`).join(", ") || "None"}</td><td>${["Queued", "Delivered", "Acknowledged", "Running", "CancelRequested"].includes(c.state) ? `<button class="live-cancel" data-command="${c.commandId}">Cancel</button>` : "—"}</td></tr>`).join("")}</tbody></table></div>` : '<p class="muted">No commands submitted.</p>'}</section><section><h2>Immutable transcript</h2>${liveTranscript(x.transcript || [])}</section><script type="application/json" id="live-terminal-data">${esc(JSON.stringify(terminal))}</script>`;
  } catch (e) {
    return state("Live Response session unavailable", e.message);
  }
}
function closeLivePresence(reason = "analyst left Live Response") {
  if (!livePresenceSessionId || livePresenceTerminal) return;
  const sessionId = livePresenceSessionId;
  livePresenceSessionId = null;
  clearInterval(livePresenceTimer); clearInterval(livePollTimer);
  livePresenceTimer = null; livePollTimer = null; livePresenceTerminal = true;
  fetch(`/api/v1/live-response/sessions/${sessionId}:close`, {
    method: "POST", headers: { ...auth(), "Content-Type": "application/json" },
    body: JSON.stringify({ reason }), keepalive: true,
  }).catch(() => {});
}
function stopLiveRuntime(close = false) {
  clearInterval(livePresenceTimer); clearInterval(livePollTimer);
  livePresenceTimer = null; livePollTimer = null;
  if (close) closeLivePresence();
  else livePresenceSessionId = null;
}
function startLiveRuntime(session) {
  if (!["Connecting", "Active", "Degraded"].includes(session.state)) { stopLiveRuntime(false); return; }
  stopLiveRuntime(false);
  livePresenceSessionId = session.sessionId; livePresenceTerminal = false;
  let pollCycle = 0;
  const presence = () => api(`/api/v1/live-response/sessions/${session.sessionId}:presence`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ clientInstanceId: liveClientInstanceId }),
  }).catch(() => {});
  presence(); livePresenceTimer = setInterval(presence, 20000);
  livePollTimer = setInterval(async () => {
    if (livePresenceSessionId !== session.sessionId) return;
    try {
      const current = (await api(`/api/v1/live-response/sessions/${session.sessionId}`)).data;
      if (current.state !== session.state && (session.state !== "Active" || current.state !== "Degraded")) { await route(); return; }
      renderLiveTerminal(document.querySelector("#live-terminal"), current.commands || [], current.workingDirectory);
      renderLiveTransferPanel(current);
      const status = document.querySelector("#live-session-state");
      if (status) { status.textContent = current.state; status.className = `badge ${statusClass(current.state)}`; }
      const cwd = document.querySelector("#live-current-directory"); if (cwd) cwd.textContent = current.workingDirectory || "Awaiting connection";
      if (++pollCycle % 3 === 0) {
        const isolation = (await api(`/api/v1/endpoints/${session.endpointId}/isolation`)).data,
          isolated = isolation.effectiveState === "Isolated",
          pending = ["IsolationPending", "Isolating", "UnisolationPending", "Unisolating"].includes(isolation.requestedState),
          badge = document.querySelector("#live-isolation-state"), button = document.querySelector("#live-isolation");
        if (badge) { const status = liveIsolationStatus(isolation.effectiveState, isolation.requestedState); badge.textContent = status.label; badge.title = isolation.failureReason || status.description; badge.setAttribute("aria-label", isolation.failureReason || status.description); badge.className = `containment-state ${status.className}`; }
        if (button) { button.dataset.operation = isolated ? "unisolate" : "isolate"; button.disabled = pending; button.textContent = pending ? "Please wait" : isolated ? "Restore network" : isolation.effectiveState === "Failed" ? "Retry isolation" : "Isolate"; button.title = isolated ? "Restore normal endpoint network access" : "Open the endpoint isolation confirmation"; button.className = `containment-action ${isolated ? "restore" : "isolate"}`; }
        renderLiveIsolationNotice(isolation);
      }
    } catch { /* presence lease safely closes a disconnected browser */ }
  }, 1500);
}
async function liveResponseDetail(id) {
  try {
    const session = (await api(`/api/v1/live-response/sessions/${id}`)).data;
    const [endpoint, isolation] = await Promise.all([
      api(`/api/v1/endpoints/${session.endpointId}`).then((value) => value.data).catch(() => ({ id: session.endpointId, hostname: session.endpointId, platform: session.platform, status: "Unknown" })),
      api(`/api/v1/endpoints/${session.endpointId}/isolation`).then((value) => value.data).catch(() => null),
    ]);
    const active = session.state === "Active", connecting = session.state === "Connecting", connectable = active || connecting || session.state === "Degraded", online = endpointOnline(endpoint.status);
    const prompt = session.capabilities.includes("powershell") ? "PowerShell" : session.capabilities.includes("cmd") ? "Cmd" : "BuiltIn";
    const artifacts = (session.commands || []).flatMap((command) => command.result?.artifacts || []);
    const isolationState = isolation?.effectiveState || "Unknown", isolationPending = isolation && ["IsolationPending", "Isolating", "UnisolationPending", "Unisolating"].includes(isolation.requestedState), isolated = isolationState === "Isolated";
    return `<div class="live-console-workspace"><div class="live-console-header"><div><a class="back-link" href="#/live-response">← End session and return to endpoints</a><span class="section-eyebrow">Remote terminal</span><h2>${esc(endpoint.hostname)}</h2><p>${esc(endpoint.osVersion || session.platform)} · ${esc(endpoint.architecture || "Unknown architecture")} · Agent ${esc(endpoint.agentVersion || session.endpointVersion)}</p></div><div class="live-console-status"><span class="connection-state ${online ? "online" : "offline"}"><i></i>${online ? "Online" : endpointState(endpoint.status)}</span><span id="live-isolation-state" class="badge ${isolated ? "status-critical" : "status-healthy"}">${isolated ? "Isolated" : isolationState === "NotIsolated" ? "Not isolated" : esc(isolationState)}</span>${isolation ? `<button type="button" id="live-isolation" class="${isolated ? "" : "danger"}" data-operation="${isolated ? "unisolate" : "isolate"}" ${isolationPending ? "disabled" : ""}>${isolationPending ? esc(isolation.requestedState) : isolated ? "Lift isolation" : "Isolate"}</button>` : ""}<span id="live-session-state" class="badge ${statusClass(session.state)}">${esc(session.state)}</span>${connectable ? '<button type="button" id="live-disconnect">End session</button>' : ""}</div></div><div class="live-facts"><div><span>Execution identity</span><strong>${esc(session.executionIdentity || "Connecting to agent…")}</strong></div><div><span>Working directory</span><code id="live-current-directory">${esc(session.workingDirectory || "Awaiting connection")}</code></div><div><span>Integrity</span><strong>${esc(session.integrityLevel || "Awaiting connection")}</strong></div><div><span>Endpoint ID</span><code>${esc(endpoint.id)}</code></div></div><section class="terminal-shell" aria-label="Remote endpoint terminal"><div class="terminal-titlebar"><strong>${esc(prompt)} · ${esc(endpoint.hostname)}</strong><span>${connectable ? "Session follows this page" : esc(session.state)}</span></div><div id="live-terminal" class="live-terminal-screen" role="log" aria-live="polite" tabindex="0">${liveTerminalHtml(session.commands || [], session.workingDirectory)}</div>${active ? `<form id="live-command" class="terminal-input"><label><span class="sr-only">Executor</span><select name="commandType" aria-label="Command shell">${session.capabilities.includes("powershell") ? '<option value="PowerShell">PS</option>' : ""}${session.capabilities.includes("cmd") ? '<option value="Cmd">CMD</option>' : ""}<option value="BuiltIn">OSP</option></select></label><label class="terminal-command-input"><span aria-hidden="true">›</span><textarea name="input" rows="1" required maxlength="8192" autocomplete="off" spellcheck="false" placeholder="Enter command"></textarea></label><button type="submit" class="terminal-send" aria-label="Execute command" title="Execute command (Enter)">↵</button><p id="live-command-status" role="alert" tabindex="-1"></p></form>` : `<div class="terminal-connecting">${connecting ? "Connecting securely to the endpoint…" : `Terminal unavailable: ${esc(session.state)}`}</div>`}</section><dialog id="live-isolation-dialog" class="live-isolation-dialog"><form id="live-isolation-form"><span class="section-eyebrow">Endpoint containment</span><h2>${isolated ? "Lift network isolation" : "Isolate endpoint"}</h2><p>${isolated ? "Restore normal network access while preserving the management channel and audit history." : "Block non-management network traffic while keeping this Live Response channel available."}</p><label>Reason <textarea name="reason" required maxlength="1024" placeholder="Incident or investigation reason"></textarea></label><div class="dialog-actions"><button type="button" id="live-isolation-cancel">Cancel</button><button type="submit" class="${isolated ? "primary" : "danger"}">${isolated ? "Lift isolation" : "Isolate endpoint"}</button></div><p id="live-isolation-result" role="alert"></p></form></dialog>${artifacts.length ? `<section><h3>Files retrieved in this session</h3><div class="live-artifacts">${artifacts.map((artifact) => `<button class="live-artifact" data-id="${artifact.artifactId}">${esc(artifact.name)}</button>`).join("")}</div></section>` : ""}<details class="technical-details"><summary>Session details and immutable audit</summary><div class="panels"><article><h3>Binding</h3><dl><dt>Session</dt><dd><code>${esc(session.sessionId)}</code></dd><dt>Endpoint / agent</dt><dd><code>${esc(session.endpointId)} / ${esc(session.agentId)}</code></dd><dt>Installation</dt><dd><code>${esc(session.agentInstallationId)}</code></dd><dt>Capabilities</dt><dd>${esc(session.capabilities.join(", "))}</dd></dl></article><article><h3>Audit</h3><dl><dt>Requester</dt><dd>${esc(session.analystId)}</dd><dt>Commands</dt><dd>${session.commands.length}</dd><dt>Transcript hash</dt><dd><code>${esc(session.transcriptHash)}</code></dd></dl><button id="live-transcript-export">Export transcript</button><p id="live-export-status" role="status"></p></article></div>${liveTranscript(session.transcript || [])}</details></div>`;
  } catch (error) { return state("Live Response session unavailable", error.message); }
}
async function liveDecision(event, id, operation) {
  event.preventDefault();
  const body = Object.fromEntries(new FormData(event.currentTarget)),
    out = document.querySelector("#live-decision-status");
  try {
    await api(`/api/v1/live-response/sessions/${id}:${operation}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    await route();
  } catch (e) {
    out.textContent = e.message;
    out.focus();
  }
}
async function submitLiveCommand(event, id) {
  event.preventDefault();
  const f = new FormData(event.currentTarget),
    out = document.querySelector("#live-command-status"),
    submit = event.currentTarget.querySelector('button[type="submit"]'),
    input = event.currentTarget.elements.input;
  try {
    const commandType = f.get("commandType");
    submit.disabled = true;
    await api(`/api/v1/live-response/sessions/${id}/commands`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        commandType,
        input: f.get("input"),
        timeoutSeconds: commandType === "BuiltIn" && /^get\s/i.test(String(f.get("input"))) ? 14400 : commandType === "BuiltIn" ? 120 : 300,
      }),
    });
    input.value = "";
    out.textContent = "";
    const session = (await api(`/api/v1/live-response/sessions/${id}`)).data,
      terminal = document.querySelector("#live-terminal");
    renderLiveTerminal(terminal, session.commands || [], session.workingDirectory, true);
    renderLiveTransferPanel(session);
    input.focus();
  } catch (e) {
    out.textContent = e.message;
    out.focus();
  } finally {
    submit.disabled = false;
  }
}
async function submitLiveIsolation(event, endpointId) {
  event.preventDefault();
  const form = event.currentTarget, operation = document.querySelector("#live-isolation")?.dataset.operation,
    output = document.querySelector("#live-isolation-result"), reason = new FormData(form).get("reason"),
    submit = form.querySelector('button[type="submit"]');
  if (!operation) return;
  try {
    submit.disabled = true; output.textContent = operation === "isolate" ? "Requesting endpoint isolation…" : "Requesting endpoint unisolation…";
    const result = (await api(`/api/v1/endpoints/${endpointId}:${operation}`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ endpointId, reason, expiresInSeconds: 900 }),
    })).data;
    const pending = result.state === "PendingApproval";
    output.innerHTML = pending ? `Request created and awaiting policy approval. <a href="#/response-actions/${esc(result.responseActionId)}">Open action</a>` : `Request accepted. <a href="#/response-actions/${esc(result.responseActionId || "")}">Track action</a>`;
    const button = document.querySelector("#live-isolation"); if (button) { button.disabled = true; button.textContent = pending ? "Approval pending" : "Applying…"; }
    setTimeout(() => document.querySelector("#live-isolation-dialog")?.close(), 1400);
  } catch (error) { output.textContent = error.message; submit.disabled = false; }
}
async function cancelLiveCommand(id, command) {
  const reason = window.prompt("Cancellation reason");
  if (!reason) return;
  await api(`/api/v1/live-response/sessions/${id}/commands/${command}:cancel`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reason }),
  });
  await route();
}
async function exportLiveTranscript(id) {
  const out = document.querySelector("#live-export-status");
  try {
    const x = (
      await api(`/api/v1/live-response/sessions/${id}/transcript:export`, {
        method: "POST",
      })
    ).data;
    out.textContent = `Exported ${x.records} records; SHA-256 ${x.sha256}.`;
  } catch (e) {
    out.textContent = e.message;
  }
}
async function downloadLiveArtifact(id) {
  const x = (
    await api(`/api/v1/live-response/artifacts/${id}:url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ expiresInSeconds: 120 }),
    })
  ).data;
  location.assign(x.url);
}
async function liveResponseHealthPage() {
  try {
    const x = (await api("/api/v1/live-response/health")).data;
    return `<div class="panels"><article><h2>Session lifecycle</h2><dl>${["sessionRequests", "activeSessions", "rejectedSessions", "expiredSessions", "sessionReconnects"].map((k) => `<dt>${esc(k)}</dt><dd>${x[k]}</dd>`).join("")}</dl></article><article><h2>Command safety and load</h2><dl>${["commandsRequested", "commandsSucceeded", "commandsFailed", "commandsTimedOut", "commandsCancelled", "outputLimitHits", "replayRejections", "commandQueueDepth"].map((k) => `<dt>${esc(k)}</dt><dd>${x[k]}</dd>`).join("")}<dt>Latency</dt><dd>${x.commandLatencyMilliseconds} ms</dd><dt>Updated</dt><dd>${new Date(x.updatedAt).toLocaleString()}</dd></dl></article></div>`;
  } catch (e) {
    return state("Live Response health unavailable", e.message);
  }
}

async function hydrateForensicCollectionContext(kind, id) {
  try {
    const record = (await api(kind === "incident" ? `/api/v1/incidents/${id}` : `/api/v1/alerts/${id}`)).data,
      endpoints = kind === "incident" ? record.endpointIds || [] : record.evidence?.endpointIds || [],
      entities = kind === "incident" ? record.processEntities || record.files || [] : record.evidence?.processEntities || record.evidence?.files || [],
      contextName = kind === "incident" ? "incidentId" : "alertId";
    document.querySelector("#content")?.insertAdjacentHTML("beforeend", `<section aria-labelledby="${kind}-forensic-collection-title"><h2 id="${kind}-forensic-collection-title">Remote forensic collection</h2>${endpoints.length ? `<p>${endpoints.map((endpoint) => `<a class="button" href="#/forensic-collections/new?endpointId=${encodeURIComponent(endpoint)}&${contextName}=${encodeURIComponent(id)}${entities[0] ? `&entityId=${encodeURIComponent(entities[0])}` : ""}">Preview bounded evidence scope</a>`).join(" ")}</p>` : '<p class="muted">No evidence-backed endpoint is linked to this record.</p>'}<p class="muted">Opening the wizard does not collect automatically. Exact scope review and policy approval remain required.</p></section>`);
  } catch (error) {
    document.querySelector("#content")?.insertAdjacentHTML("beforeend", `<section>${state("Forensic collection pivot unavailable", error.message)}</section>`);
  }
}

async function hydrateLiveResponseContext(kind, id) {
  try {
    const sessions = (await api("/api/v1/live-response/sessions")).data || [];
    const field = kind === "incident" ? "sourceIncidentId" : "sourceAlertId";
    const matches = sessions.filter(
      (session) =>
        String(session[field] || "").toLowerCase() === id.toLowerCase(),
    );
    document
      .querySelector("#content")
      ?.insertAdjacentHTML(
        "beforeend",
        `<section aria-labelledby="${kind}-live-history-title"><h2 id="${kind}-live-history-title">Live Response timeline</h2>${matches.length ? `<ol class="timeline">${matches.flatMap((session) => session.transcript.map((event) => `<li><time>${new Date(event.occurredAt).toLocaleString()}</time> <a href="#/live-response/${session.sessionId}">${esc(event.eventType)}</a> by ${esc(event.actor)}<p>${esc(event.summary)}</p></li>`)).join("")}</ol>` : '<p class="muted">No manually initiated Live Response session is linked to this record.</p>'}</section>`,
      );
  } catch (error) {
    document
      .querySelector("#content")
      ?.insertAdjacentHTML(
        "beforeend",
        `<section>${state("Live Response timeline unavailable", error.message)}</section>`,
      );
  }
}

async function hydrateProcessResponseContext(kind, id) {
  try {
    const page = (await api("/api/v1/response-actions?pageSize=200")).data,
      field = kind === "incident" ? "sourceIncidentId" : "sourceAlertId",
      actions = (page.items || []).filter(
        (action) =>
          action.actionType?.startsWith("process") &&
          String(action[field] || "").toLowerCase() === id.toLowerCase(),
      );
    document
      .querySelector("#content")
      ?.insertAdjacentHTML(
        "beforeend",
        `<section aria-labelledby="${kind}-process-response-history"><h2 id="${kind}-process-response-history">Process response timeline</h2>${actions.length ? `<ol class="timeline">${actions.flatMap((action) => action.auditHistory.map((event) => `<li><time>${new Date(event.occurredAt).toLocaleString()}</time> <a href="#/response-actions/${action.responseActionId}">${esc(action.actionType)}</a> — <strong>${esc(event.action)}</strong> by ${esc(event.actor)}<p>${esc(event.reason)}</p></li>`)).join("")}</ol>` : '<p class="muted">No structured process response has been requested from this context.</p>'}</section>`,
      );
  } catch (error) {
    document
      .querySelector("#content")
      ?.insertAdjacentHTML(
        "beforeend",
        `<p role="alert">Process response history unavailable: ${esc(error.message)}</p>`,
      );
  }
}

async function hydrateFileResponseContext(kind, id) {
  try {
    const record = (await api(kind === "incident" ? `/api/v1/incidents/${id}` : `/api/v1/alerts/${id}`)).data,
      endpoints = kind === "incident" ? record.endpointIds || [] : record.evidence?.endpointIds || [],
      files = (kind === "incident" ? record.files || [] : record.evidence?.files || []).filter((value) => /^[a-f0-9]{64}$/i.test(value)),
      page = (await api("/api/v1/response-actions?pageSize=200")).data,
      field = kind === "incident" ? "sourceIncidentId" : "sourceAlertId",
      actions = (page.items || []).filter((action) => action.actionType?.startsWith("file.") && String(action[field] || "").toLowerCase() === id.toLowerCase()),
      pivots = endpoints.length && files.length ? files.map((entity) => `<a class="button" href="#/files/${encodeURIComponent(endpoints[0])}/${encodeURIComponent(entity)}?${kind}Id=${encodeURIComponent(id)}">Review exact file response</a>`).join(" ") : '<span class="muted">No exact file entity is linked to this record.</span>';
    document.querySelector("#content")?.insertAdjacentHTML("beforeend", `<section aria-labelledby="${kind}-file-response-history"><h2 id="${kind}-file-response-history">File response</h2><p>${pivots}</p>${actions.length ? `<ol class="timeline">${actions.flatMap((action) => action.auditHistory.map((event) => `<li><time>${new Date(event.occurredAt).toLocaleString()}</time> <a href="#/response-actions/${action.responseActionId}">${esc(action.actionType)}</a> — <strong>${esc(event.action)}</strong> by ${esc(event.actor)}<p>${esc(event.reason)}</p></li>`)).join("")}</ol>` : '<p class="muted">No structured file response has been requested from this context.</p>'}</section>`);
  } catch (error) {
    document.querySelector("#content")?.insertAdjacentHTML("beforeend", `<p role="alert">File response history unavailable: ${esc(error.message)}</p>`);
  }
}

async function hydrateContainmentContext(kind, id) {
  try {
    const record = (
      await api(kind === "incident" ? `/api/v1/incidents/${id}` : `/api/v1/alerts/${id}`)
    ).data;
    const endpoints = kind === "incident" ? record.endpointIds || [] : [record.endpointId].filter(Boolean);
    document.querySelector("#content")?.insertAdjacentHTML(
      "beforeend",
      `<section aria-labelledby="${kind}-containment-title"><h2 id="${kind}-containment-title">Manual endpoint containment</h2>${endpoints.length ? `<p>${endpoints.map((endpoint) => `<a class="button" href="#/endpoints/${encodeURIComponent(endpoint)}?${kind}Id=${encodeURIComponent(id)}">Review and request isolation for ${esc(endpoint)}</a>`).join(" ")}</p>` : '<p class="muted">No evidence-backed endpoint is linked to this record.</p>'}<p class="muted">Opening this panel does not isolate automatically. The analyst must confirm, supply a reason, and satisfy policy approval.</p></section>`,
    );
  } catch (error) {
    document.querySelector("#content")?.insertAdjacentHTML(
      "beforeend",
      `<section>${state("Containment pivot unavailable", error.message)}</section>`,
    );
  }
}

async function dfirWorkspacePage(investigationId, evidenceId) {
  try {
    if (evidenceId) {
      const [artifact, custody] = await Promise.all([api(`/api/v1/forensics/evidence/${evidenceId}`), api(`/api/v1/investigations/${investigationId}/custody?evidenceId=${evidenceId}`)]), a = artifact.data;
      return `<a href="#/dfir-workspace/${investigationId}?view=evidence">← Evidence browser</a><div class="detail-head"><div><h2>${esc(a.evidenceType)}</h2><p><code>${esc(a.evidenceId)}</code></p></div><span class="badge">${esc(a.integrity)}</span></div><div class="panels"><article><h3>Authoritative source</h3><dl><dt>Endpoint / installation</dt><dd><code>${esc(a.endpointId)}</code><br><code>${esc(a.agentInstallationId)}</code></dd><dt>Collection</dt><dd><code>${esc(a.collectionId)}</code></dd><dt>Source</dt><dd>${esc(a.source)}</dd><dt>Requested path/object</dt><dd><code>${esc(a.requestedPath || "Structured source")}</code></dd><dt>Native identity</dt><dd><code>${esc(a.nativeIdentity || "Not applicable")}</code></dd><dt>Acquisition</dt><dd>${esc(a.acquisitionMechanism)} ${esc(a.acquisitionVersion)}</dd></dl></article><article><h3>Integrity and storage</h3><dl><dt>Size / transferred</dt><dd>${a.size.toLocaleString()} / ${a.bytesTransferred.toLocaleString()} bytes</dd><dt>Chunks</dt><dd>${a.chunks}</dd><dt>SHA-256</dt><dd><code>${esc(a.sha256)}</code></dd><dt>Transfer verified</dt><dd>${a.transferVerified}</dd><dt>Storage</dt><dd>Tenant object abstraction <code>${esc(a.objectId)}</code></dd><dt>State</dt><dd>${esc(a.state)}${a.failureCode ? ` — ${esc(a.failureCode)}: ${esc(a.failureDetail)}` : ""}</dd></dl><button class="evidence-verify" data-evidence="${a.evidenceId}">Reverify stored bytes</button> <button class="evidence-download" data-evidence="${a.evidenceId}">Download/resume</button><p id="evidence-action-status" role="status" aria-live="assertive" tabindex="-1"></p></article><article><h3>Parser and lineage</h3><dl><dt>Parser</dt><dd>${esc(a.parserId || "Not invoked")} ${esc(a.parserVersion || "")}</dd><dt>Parse/extraction</dt><dd>${esc(a.parseStatus)} / ${esc(a.extractionStatus)}</dd><dt>Derived from</dt><dd><code>${esc(a.derivedFromEvidenceId || "Original evidence")}</code></dd><dt>Source record</dt><dd>${esc(a.sourceRecordIdentity || "Not available")}</dd></dl><form id="evidence-parse"><label>Validated parser <select name="parserId"><option value="structured-json-summary">structured-json-summary</option></select></label><input type="hidden" name="parserVersion" value="1.0.0"><button>Parse into separate derived evidence</button></form></article></div><section><h2>Analyst metadata</h2><form id="evidence-tags"><label>Tags (comma separated) <input name="tags" value="${esc((a.tags || []).join(","))}" maxlength="500"></label><button>Save metadata tags</button></form><button class="evidence-bookmark" data-evidence="${a.evidenceId}">Bookmark for report</button><p>Tags and bookmarks never change source bytes.</p></section><section><h2>Technical chain of custody</h2><p>No legal-admissibility claim is made. Chronology is also available as the accessible table below.</p>${dfirCustodyTable(custody.data.events || [])}</section>`;
    }
    if (!investigationId) {
      const [investigations, health, profiles] = await Promise.all([api("/api/v1/investigations?limit=100"), api("/api/v1/forensics/workspace-health"), api("/api/v1/forensics/profiles")]);
      const h = health.data, items = investigations.data.items || [];
      return `<div class="toolbar"><p>Case-centric DFIR evidence remains immutable, tenant-bound, and traceable from acquisition through export.</p><a class="button" href="#/forensic-collections/new">Start bounded acquisition</a></div><section aria-labelledby="dfir-health"><h2 id="dfir-health">Workspace health</h2><div class="panels"><article><h3>Investigations</h3><p>${h.investigationsOpen} open</p></article><article><h3>Collections</h3><p>${h.collectionsRunning} running · ${h.collectionsPartial} partial · ${h.collectionsFailed} failed</p></article><article><h3>Evidence</h3><p>${h.artifactsAcquired} acquired · ${h.bytesAcquired.toLocaleString()} bytes · ${h.hashVerificationFailures} integrity failures</p></article><article><h3>Governance</h3><p>${h.heldEvidence} holds · ${h.exports} exports · object storage ${h.objectStorageHealthy ? "healthy" : "unavailable"}</p></article></div></section><section><h2>Create investigation</h2><form id="dfir-create" class="admin-grid"><label>Title <input name="title" required maxlength="200"></label><label>Description <textarea name="description" required maxlength="4000"></textarea></label><label>Priority <select name="priority"><option>Medium</option><option>High</option><option>Critical</option><option>Low</option></select></label><label>Owner <input name="owner" required maxlength="256" value="analyst"></label><label>Endpoint ID <input name="endpointId" pattern="[0-9a-fA-F-]{36}"></label><label>Tags <input name="tags" placeholder="NeedsReview,Malware"></label><button>Create investigation</button><p role="status" tabindex="-1"></p></form></section><section><h2>Investigations</h2>${items.length ? `<div class="table-wrap"><table><caption>Tenant forensic investigations</caption><thead><tr><th>Updated</th><th>Investigation</th><th>Status</th><th>Priority</th><th>Owner</th><th>Evidence / collections</th></tr></thead><tbody>${items.map(x => `<tr><td>${new Date(x.updatedAt).toLocaleString()}</td><td><a href="#/dfir-workspace/${x.investigationId}">${esc(x.title)}</a><br><code>${esc(x.investigationId)}</code></td><td>${esc(x.status)}</td><td>${esc(x.priority)}</td><td>${esc(x.owner)}</td><td>${x.evidenceIds.length} / ${x.collectionIds.length}</td></tr>`).join("")}</tbody></table></div>` : state("No DFIR investigations", "Create an investigation before linking evidence.")}</section><section><h2>Truthful collection-profile support</h2>${dfirProfileTable(profiles.data)}</section>`;
    }
    const hashParams = new URLSearchParams(location.hash.split("?")[1] || ""), view = hashParams.get("view") || "overview", evidenceParams = new URLSearchParams({ investigationId, limit: "500" });
    ["text", "evidenceType", "tag", "hash", "state", "parser"].forEach(name => { const value = hashParams.get(name); if (value) evidenceParams.set(name, value); });
    const [detail, collections, evidence, timeline, custody, notes, bookmarks, exports] = await Promise.all([api(`/api/v1/investigations/${investigationId}`), api(`/api/v1/investigations/${investigationId}/collections`), api(`/api/v1/forensics/evidence?${evidenceParams}`), api(`/api/v1/investigations/${investigationId}/timeline?limit=500`), api(`/api/v1/investigations/${investigationId}/custody`), api(`/api/v1/investigations/${investigationId}/notes`), api(`/api/v1/investigations/${investigationId}/bookmarks`), api(`/api/v1/investigations/${investigationId}/exports`)]), x = detail.data.x, artifacts = evidence.data.items || [];
    const tabs = [["overview","Overview"],["collections","Collections"],["evidence","Evidence"],["timeline","Timeline"],["entities","Entities"],["bookmarks","Bookmarks"],["notes","Notes"],["tools","Tools"],["readiness","Endpoint readiness"],["custody","Custody"],["exports","Exports"]];
    let body = "";
    if (view === "overview") body = `<div class="panels"><article><h3>Case</h3><dl><dt>Status</dt><dd>${esc(x.status)}</dd><dt>Priority</dt><dd>${esc(x.priority)}</dd><dt>Owner</dt><dd>${esc(x.owner)}</dd><dt>Endpoints</dt><dd>${x.endpointIds.map(esc).join("<br>") || "None"}</dd></dl></article><article><h3>Workflow</h3><p>${detail.data.activeCollections} active collection(s), ${detail.data.collectionFailures} failure/partial, ${detail.data.evidenceCount} evidence item(s), ${detail.data.bookmarks} bookmark(s).</p><a class="button" href="#/forensic-collections/new?endpointId=${encodeURIComponent(x.endpointIds[0] || "")}">Collect evidence</a></article><article><h3>Hold and AI</h3><form id="dfir-hold"><label>Hold reason <input name="reason" required maxlength="1024"></label><button>Apply evidence hold</button></form><button id="dfir-ai">Draft cited forensic summary</button><p id="dfir-status" role="status" tabindex="-1"></p></article></div><section><h2>Important evidence</h2>${dfirEvidenceTable(artifacts.filter(a => a.bookmarked || a.tags.includes("Suspicious")).slice(0, 10), investigationId)}</section>`;
    if (view === "collections") body = `<div class="toolbar"><a class="button" href="#/forensic-collections/new?endpointId=${encodeURIComponent(x.endpointIds[0] || "")}">New bounded collection</a></div><form id="dfir-import"><label>Completed collection ID <input name="collectionId" required pattern="[0-9a-fA-F-]{36}"></label><button>Import authoritative result</button><p role="status" tabindex="-1"></p></form>${dfirCollectionsTable(collections.data || [])}`;
    if (view === "evidence") body = `<form id="dfir-evidence-search" class="filters"><label>Search path/hash/source <input name="text" value="${esc(hashParams.get("text") || "")}"></label><label>Type <input name="evidenceType" value="${esc(hashParams.get("evidenceType") || "")}"></label><label>Tag <input name="tag" value="${esc(hashParams.get("tag") || "")}"></label><label>Exact SHA-256 <input name="hash" value="${esc(hashParams.get("hash") || "")}" pattern="[0-9a-fA-F]{64}"></label><button>Filter bounded evidence</button></form>${dfirEvidenceTable(artifacts, investigationId)}<form id="dfir-export"><fieldset><legend>Create evidence package</legend><p>Select evidence in the table. Unavailable or excluded items remain explicit in the manifest.</p><label>Reason <input name="reason" required maxlength="1024"></label><button>Create verified package</button></fieldset><p id="dfir-export-status" role="status" tabindex="-1"></p></form>`;
    if (view === "timeline") body = `<p>Every item identifies its authoritative source. Results are bounded to 500 in this view.</p>${dfirTimelineTable(timeline.data || [])}`;
    if (view === "entities") body = `<p><a class="button" href="#/entity-graph">Open evidence-backed entity graph</a> <a class="button" href="#/threat-hunting">Run authorized bounded cross-endpoint hunt</a></p><p>No unsupported relationship is synthesized by this workspace.</p>`;
    if (view === "bookmarks") body = dfirEvidenceTable(artifacts.filter(a => a.bookmarked), investigationId);
    if (view === "notes") body = `<form id="dfir-note"><label>Append-only investigation note <textarea name="body" required maxlength="8000"></textarea></label><button>Add note</button><p role="status" tabindex="-1"></p></form><ol class="timeline">${(notes.data || []).map(n => `<li><strong>v${n.version} ${esc(n.author)}</strong> <time>${new Date(n.createdAt).toLocaleString()}</time><p>${esc(n.body)}</p><small>${n.aiDraft ? "AI draft — analyst acceptance required" : "Analyst note"} · ${esc((n.evidenceCitations || []).join(", "))}</small></li>`).join("") || "<li>No notes.</li>"}</ol>`;
    if (view === "tools") { const library = (await api("/api/v1/forensics/tools/library")).data; body = `<p>${esc(library.boundary)}</p><div class="table-wrap"><table><caption>Approved acquisition-tool staging library</caption><thead><tr><th>Tool/version</th><th>Publisher/signature</th><th>Hash</th><th>Support</th><th>State/validation</th><th>Expiry/scan/use</th></tr></thead><tbody>${library.items.map(t => `<tr><td>${esc(t.name)} ${esc(t.version)}</td><td>${esc(t.publisher)}<br>${esc(t.signatureState)}</td><td><code>${esc(t.sha256)}</code></td><td>${esc((t.approvedAcquisitionTypes || []).join(", ") || "No execution type registered")}<br>${esc((t.supportedOs || []).join(", ") || "Not recorded")} / ${esc((t.supportedArchitecture || []).join(", ") || "Not recorded")}</td><td>${esc(t.stagedState)}<br>${esc(t.validationStatus)}</td><td>${esc(t.expiresAt || "No expiry recorded")}<br>${esc(t.securityScanState)}<br>${esc(t.lastUse || "Never/unknown")}</td></tr>`).join("") || '<tr><td colspan="6">No staged tools.</td></tr>'}</tbody></table></div><a class="button" href="#/forensic-tools">Manage staged packages</a>`; }
    if (view === "readiness") body = x.endpointIds.length ? `<div class="panels">${(await Promise.all(x.endpointIds.map(id => api(`/api/v1/endpoints/${id}/forensic-readiness`).catch(() => ({data:{endpointId:id,online:false,status:"Unavailable",forensicChannelAvailable:false}}))))).map(r => `<article><h3><code>${esc(r.data.endpointId)}</code></h3><dl><dt>Online</dt><dd>${r.data.online}</dd><dt>Status</dt><dd>${esc(r.data.status)}</dd><dt>Transfer</dt><dd>${r.data.transferReady ?? "Unknown"}</dd><dt>Tools</dt><dd>${r.data.approvedTools ?? 0} approved</dd><dt>Forensic channel</dt><dd>${r.data.forensicChannelAvailable ? "Available" : "Unavailable"}</dd><dt>Isolation</dt><dd>${esc(r.data.isolationState || "Unknown")}</dd><dt>Disk</dt><dd>${esc(r.data.diskAvailability || "Not reported")}</dd></dl></article>`).join("")}</div>` : state("No endpoint", "Relate an endpoint to show acquisition readiness.");
    if (view === "custody") body = `<p>Chronological custody timeline with an accessible table alternative.</p>${dfirCustodyTable(custody.data.events || [])}`;
    if (view === "exports") body = `<div class="table-wrap"><table><caption>Evidence packages</caption><thead><tr><th>Created</th><th>Package</th><th>Included / excluded / unavailable</th><th>Integrity</th><th>Download</th></tr></thead><tbody>${(exports.data || []).map(e => `<tr><td>${new Date(e.createdAt).toLocaleString()}</td><td><code>${esc(e.exportId)}</code></td><td>${e.included.length} / ${e.excluded.length} / ${e.unavailable.length}</td><td><code>${esc(e.packageSha256)}</code></td><td><a href="/api/v1/forensics/exports/${e.exportId}/manifest">Manifest</a> · <button class="dfir-export-download" data-export="${e.exportId}">Package</button></td></tr>`).join("") || '<tr><td colspan="5">No exports.</td></tr>'}</tbody></table></div>`;
    return `<a href="#/dfir-workspace">← Investigations</a><div class="detail-head"><div><h2>${esc(x.title)}</h2><p>${esc(x.description)}</p></div><span class="badge">${esc(x.status)}</span></div><nav aria-label="Investigation workspace sections"><ul class="subnav">${tabs.map(([id,label]) => `<li><a ${view===id?'aria-current="page"':''} href="#/dfir-workspace/${investigationId}?view=${id}">${label}</a></li>`).join("")}</ul></nav><section aria-live="polite">${body}</section>`;
  } catch (error) { return state("DFIR workspace unavailable", error.message); }
}
function dfirProfileTable(items) { return `<div class="table-wrap"><table><caption>Collection profile and evidence support</caption><thead><tr><th>Profile</th><th>Bounds</th><th>Evidence support</th><th>Approval</th></tr></thead><tbody>${items.map(p => `<tr><td><strong>${esc(p.name)}</strong><br>${esc(p.description)}<br><code>${esc(p.profileHash)}</code></td><td>${p.maximumItems} items<br>${p.maximumBytes.toLocaleString()} bytes<br>${p.maximumDurationSeconds}s</td><td><ul>${p.items.map(i => `<li><strong>${esc(i.evidenceType)}</strong>: ${esc(i.availability)}${i.requiredTool ? ` (${esc(i.requiredTool)})` : ""}${i.limitation ? ` — ${esc(i.limitation)}` : ""}</li>`).join("")}</ul></td><td>${p.approvalRequired ? "Required" : "Not required"}</td></tr>`).join("")}</tbody></table></div>`; }
function dfirCollectionsTable(items) { return `<div class="table-wrap"><table><caption>Collection progress and precise failures</caption><thead><tr><th>Requested</th><th>Endpoint/profile</th><th>State</th><th>Progress</th><th>Failure</th></tr></thead><tbody>${items.map(x => `<tr><td>${new Date(x.requestedAt).toLocaleString()}<br><code>${esc(x.collectionId)}</code></td><td><code>${esc(x.endpointId)}</code><br>${esc(x.profileId)} v${x.profileVersion}</td><td>${esc(x.state)}</td><td><progress max="${Math.max(1,x.requestedItems)}" value="${x.successfulItems+x.failedItems+x.unavailableItems}" aria-label="${esc(x.state)} collection progress"></progress><br>${x.successfulItems} successful · ${x.failedItems} failed · ${x.unavailableItems} unavailable<br>${x.bytesTransferred.toLocaleString()} / ${x.bytesAcquired.toLocaleString()} bytes · ${x.chunksVerified} chunks</td><td>${esc(x.failureCode || "None")} ${esc(x.failureDetail || "")}</td></tr>`).join("") || '<tr><td colspan="5">No linked collections.</td></tr>'}</tbody></table></div>`; }
function dfirEvidenceTable(items, investigation) { return `<div class="table-wrap"><table><caption>Immutable evidence browser</caption><thead><tr><th>Select</th><th>Acquired</th><th>Evidence/source</th><th>Endpoint</th><th>Integrity</th><th>Parser</th><th>Metadata</th></tr></thead><tbody>${items.map(a => `<tr><td><input form="dfir-export" class="dfir-export-item" type="checkbox" value="${a.evidenceId}" aria-label="Include ${esc(a.evidenceType)} ${a.evidenceId}"></td><td>${new Date(a.acquisitionCompletedAt).toLocaleString()}</td><td><a href="#/dfir-workspace/${investigation}/evidence/${a.evidenceId}">${esc(a.evidenceType)}</a><br><code>${esc(a.source)}</code>${a.failureCode ? `<br><strong>${esc(a.failureCode)}</strong>: ${esc(a.failureDetail)}` : ""}</td><td><code>${esc(a.endpointId)}</code></td><td>${esc(a.integrity)}<br><code>${esc(a.sha256)}</code></td><td>${esc(a.parserId || "Not parsed")}<br>${esc(a.parseStatus)}</td><td>${a.bookmarked ? "★ Bookmarked" : ""}<br>${esc((a.tags || []).join(", "))}</td></tr>`).join("") || '<tr><td colspan="7">No evidence matches this bounded view.</td></tr>'}</tbody></table></div>`; }
function dfirTimelineTable(items) { return `<div class="table-wrap"><table><caption>Source-attributed forensic timeline</caption><thead><tr><th>Time</th><th>Event</th><th>Endpoint/user</th><th>Confidence</th><th>Source</th></tr></thead><tbody>${items.map(x => `<tr><td>${new Date(x.occurredAt).toLocaleString()}</td><td>${esc(x.eventType)} — ${esc(x.summary)}</td><td><code>${esc(x.endpointId || "None")}</code><br>${esc(x.user || "Unknown")}</td><td>${esc(x.confidence)}</td><td>${esc(x.source)}<br><code>${esc(x.evidenceId || "No artifact")}</code></td></tr>`).join("") || '<tr><td colspan="5">No source-attributed timeline items.</td></tr>'}</tbody></table></div>`; }
function dfirCustodyTable(items) { return `<ol class="timeline" aria-label="Custody chronology">${items.map(x => `<li><time>${new Date(x.occurredAt).toLocaleString()}</time> <strong>${esc(x.operation)}</strong> by ${esc(x.actor)} — ${esc(x.result)}</li>`).join("")}</ol><div class="table-wrap"><table><caption>Technical chain of custody</caption><thead><tr><th>Time</th><th>Actor</th><th>Operation/result</th><th>Source → destination</th><th>Hash/detail</th></tr></thead><tbody>${items.map(x => `<tr><td>${new Date(x.occurredAt).toLocaleString()}</td><td>${esc(x.actor)}</td><td>${esc(x.operation)} / ${esc(x.result)}</td><td>${esc(x.source)} → ${esc(x.destination)}</td><td><code>${esc(x.sha256 || "Not applicable")}</code><br>${esc(x.detail)}</td></tr>`).join("") || '<tr><td colspan="5">No custody events.</td></tr>'}</tbody></table></div>`; }
async function dfirCreate(event){event.preventDefault();const f=Object.fromEntries(new FormData(event.currentTarget)),status=event.currentTarget.querySelector('[role="status"]');try{const body={title:f.title,description:f.description,priority:f.priority,owner:f.owner,endpointIds:f.endpointId?[f.endpointId]:[],incidentIds:[],alertIds:[],tags:(f.tags||"").split(",").map(x=>x.trim()).filter(Boolean)};const x=await api("/api/v1/investigations",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});location.hash=`#/dfir-workspace/${x.data.investigationId}`;}catch(e){status.textContent=e.message;status.focus();}}
async function dfirPost(path,body,statusId="dfir-status"){const status=document.querySelector(`#${statusId}`);try{await api(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});if(status){status.textContent="Operation recorded.";status.focus();}await route();}catch(e){if(status){status.textContent=e.message;status.focus();}else window.alert(e.message);}}
async function dfirDownload(path,name){const r=await fetch(path,{headers:auth()});if(!r.ok)throw Error(`Download failed with status ${r.status}.`);const url=URL.createObjectURL(await r.blob()),a=document.createElement("a");a.href=url;a.download=name;a.click();URL.revokeObjectURL(url);}
let pendingForensicRequest = null;

function forensicDefaultScope(profile, values) {
  const bounded = (requestId, artifactType, maximumItems = 1, maximumBytes = 524288) => ({ requestId, artifactType, maximumDepth: 0, maximumItems, maximumBytes, maximumRecords: 0, lookbackMinutes: 0, allowedExtensions: null, includeHidden: false, metadataOnly: false });
  if (profile === "quick-triage" || profile === "endpoint-investigation") return [
    bounded("system", "SystemInformation", 1, 262144), bounded("processes", "ProcessInventory", 32),
    bounded("users", "UserSessionInventory", 32, 262144), bounded("services", "ServiceInventory", 32),
    bounded("tasks", "ScheduledTaskInventory", 32), bounded("network", "NetworkState", 32),
    bounded("persistence", "PersistenceSnapshot", 32),
  ];
  if (profile === "windows-event-evidence") return [{ ...bounded("eventlog", "WindowsEventLog", 1, 4194304), source: values.source || "System", maximumRecords: 1000, lookbackMinutes: 60 }];
  if (profile === "registry-triage") return [{ ...bounded("registry", "Registry", 32, 1048576), source: values.source || "HKLM\\SOFTWARE", maximumDepth: 2, metadataOnly: true }];
  return [];
}

async function forensicRequestFromForm(form) {
  const values = Object.fromEntries(new FormData(form)), endpointId = values.endpointId, profileId = values.profileId;
  let requestedArtifacts = forensicDefaultScope(profileId, values);
  if (profileId === "file-evidence") {
    if (!values.fileEntityId) throw Error("An exact existing file entity is required; path-only collection is forbidden.");
    const file = (await api(`/api/v1/endpoints/${endpointId}/files/${encodeURIComponent(values.fileEntityId)}`)).data;
    requestedArtifacts = [{ requestId: "file", artifactType: "File", source: null, fileTarget: { fileEntityId: file.fileEntityId, nativeIdentity: file.nativeIdentity, canonicalPath: file.currentPath, expectedSize: file.metadata.size, expectedSha256: file.hash.sha256, observedAt: file.lastObserved }, maximumDepth: 0, maximumItems: 1, maximumBytes: Math.min(file.metadata.size, 8388608), maximumRecords: 0, lookbackMinutes: 0, allowedExtensions: null, includeHidden: false, metadataOnly: false }];
  }
  const context = responseSourceContext();
  return { endpointId, profileId, profileVersion: 1, requestedArtifacts, reason: values.reason, expiresInSeconds: 900, sourceAlertId: context.sourceAlertId, sourceIncidentId: context.sourceIncidentId, sourceEntityId: context.sourceEntityId, saveAsDraft: false, policyVersion: "forensic-collection-policy.v1" };
}

async function forensicWizard() {
  try {
    const [profiles, endpoints] = await Promise.all([api("/api/v1/forensic-collection-profiles"), api("/api/v1/endpoints?pageSize=100")]);
    const selected = new URLSearchParams(location.hash.split("?")[1] || "").get("endpointId") || "";
    return `<section aria-labelledby="forensic-wizard-title"><h2 id="forensic-wizard-title">Collection wizard</h2><p class="notice"><strong>Read-only acquisition.</strong> Review the exact immutable scope before requesting approval. Wildcards, volume roots, scripts, credential collection, and unrestricted recursion are prohibited.</p><form id="forensic-wizard"><label>Endpoint <select name="endpointId" required><option value="">Select endpoint</option>${(endpoints.data.items || []).map((x) => `<option value="${esc(x.id)}" ${x.id === selected ? "selected" : ""}>${esc(x.hostname || x.id)} · ${esc(x.status)}</option>`).join("")}</select></label><label>Collection profile <select name="profileId" required>${profiles.data.map((x) => `<option value="${esc(x.profileId)}">${esc(x.name)} · max ${x.maximumItems} items / ${Math.round(x.maximumBytes / 1048576)} MiB / ${x.maximumDurationSeconds}s${x.approvalRequired ? " · approval" : ""}</option>`).join("")}</select></label><label>Approved Event Log channel or Registry target <input name="source" maxlength="1024" placeholder="System or HKLM\\SOFTWARE\\ApprovedKey"></label><label>Exact file entity ID for File Evidence <input name="fileEntityId" pattern="[0-9a-fA-F]{64}" maxlength="64" placeholder="64-character authoritative entity ID"></label><label>Collection reason <textarea name="reason" required minlength="4" maxlength="1024"></textarea></label><button type="submit">Preview exact scope</button><p id="forensic-wizard-status" role="status" aria-live="assertive" tabindex="-1"></p></form><div id="forensic-scope-preview" tabindex="-1"></div></section>`;
  } catch (error) { return state("Collection wizard unavailable", error.message); }
}

async function previewForensic(event) {
  event.preventDefault(); const status = document.querySelector("#forensic-wizard-status"), output = document.querySelector("#forensic-scope-preview");
  try {
    pendingForensicRequest = await forensicRequestFromForm(event.currentTarget);
    const preview = (await api("/api/v1/forensic-collections:preview", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(pendingForensicRequest) })).data;
    output.innerHTML = `<section aria-labelledby="forensic-preview-title"><h2 id="forensic-preview-title">Exact scope preview</h2><div class="panels"><article><h3>Immutable profile</h3><dl><dt>Profile</dt><dd>${esc(preview.profile.name)} v${preview.profile.version}</dd><dt>Profile hash</dt><dd><code>${esc(preview.profile.profileHash)}</code></dd><dt>Request hash</dt><dd><code>${esc(preview.requestHash)}</code></dd><dt>Approval</dt><dd>${preview.approvalRequired ? "Separated approval required" : "Policy does not require approval"}</dd></dl></article><article><h3>Hard limits</h3><dl><dt>Items</dt><dd>${preview.maximumItems}</dd><dt>Bytes</dt><dd>${preview.maximumBytes}</dd><dt>Runtime</dt><dd>${preview.maximumRuntimeSeconds}s</dd></dl></article></div><h3>Requested artifacts</h3><ol>${preview.requestedArtifacts.map((x) => `<li><strong>${esc(x.artifactType)}</strong> — ${esc(x.source || x.fileTarget?.canonicalPath || "structured endpoint state")} · max ${x.maximumItems} item(s), ${x.maximumBytes} bytes</li>`).join("")}</ol>${preview.warnings.length ? `<div class="live-warning">${preview.warnings.map(esc).join(" ")}</div>` : ""}<button id="forensic-confirm">Request signed collection</button>`;
    document.querySelector("#forensic-confirm").addEventListener("click", createForensic); output.focus(); status.textContent = "Scope preview is ready for review.";
  } catch (error) { status.textContent = error.message; status.focus(); }
}

async function createForensic() {
  const status = document.querySelector("#forensic-wizard-status");
  try { const created = await api("/api/v1/forensic-collections", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(pendingForensicRequest) }); location.hash = `#/forensic-collections/${created.data.collectionId}`; }
  catch (error) { status.textContent = error.message; status.focus(); }
}

function forensicItems(items, collectionId) {
  if (!items?.length) return '<p class="muted">No evidence item has completed yet.</p>';
  return `<div class="table-wrap"><table><caption>Evidence items and explicit collection quality</caption><thead><tr><th>Artifact</th><th>Source</th><th>State</th><th>Race</th><th>Bytes</th><th>SHA-256</th><th>Action</th></tr></thead><tbody>${items.map((x) => `<tr><td>${esc(x.artifactType)}</td><td><code>${esc(x.sourceObject)}</code></td><td>${esc(x.state)}${x.truncated ? " · truncated" : ""}</td><td>${esc(x.raceState)}</td><td>${x.acquiredSize}</td><td><code>${esc(x.sha256 || "Not acquired")}</code></td><td>${x.artifactId ? `<button class="forensic-download" data-collection="${collectionId}" data-item="${x.evidenceItemId}">Download exact object</button>` : esc(x.failureReason || "—")}</td></tr>`).join("")}</tbody></table></div>`;
}

async function intelligencePage() {
  try {
    const requestedQuery = new URLSearchParams(location.hash.split("?")[1] || "").get("query") || "";
    const [sources, indicators, exclusions] = await Promise.all([api("/api/v1/intelligence/sources"), api(`/api/v1/intelligence/indicators?pageSize=100${requestedQuery ? `&query=${encodeURIComponent(requestedQuery)}` : ""}`), api("/api/v1/intelligence/exclusions")]);
    const sourceItems = sources.data || [], iocItems = indicators.data.items || [];
    return `<div class="toolbar"><p>Versioned, tenant-scoped intelligence with exact evidence matching. No IOC triggers automatic response.</p></div><div class="panels"><section aria-labelledby="intel-source-title"><h2 id="intel-source-title">Sources and feed status</h2>${sourceItems.length ? `<ul>${sourceItems.map((x) => `<li><strong>${esc(x.name)}</strong> · ${esc(x.type)} · reliability ${x.reliability}% · ${x.enabled ? "enabled" : "disabled"}${x.failureState ? ` · ${esc(x.failureState)}` : ""}</li>`).join("")}</ul>` : '<p class="muted">No intelligence sources.</p>'}<form id="intel-source"><h3>Add manual source</h3><label>Name <input name="name" required maxlength="200"></label><label>Reliability <input name="reliability" type="number" min="0" max="100" value="80"></label><label>Default confidence <input name="confidence" type="number" min="0" max="100" value="70"></label><button>Add source</button><p role="alert" tabindex="-1"></p></form></section><section aria-labelledby="intel-import-title"><h2 id="intel-import-title">Bounded import</h2><form id="intel-import"><label>Source <select name="sourceId" required>${sourceItems.map((x) => `<option value="${x.sourceId}">${esc(x.name)}</option>`).join("")}</select></label><label>Format <select name="format"><option value="csv">CSV</option><option value="json">JSON</option><option value="stix">STIX 2.x bounded subset</option></select></label><label>Import file (maximum 5 MiB / 10,000 records) <input name="file" type="file" required></label><button>Validate and import</button><p role="alert" tabindex="-1"></p></form></section></div><section aria-labelledby="ioc-list-title"><h2 id="ioc-list-title">Indicators</h2><form id="ioc-search" role="search"><label>Search normalized value or tag <input name="query"></label><button>Search</button></form>${iocItems.length ? `<div class="table-wrap"><table><caption>Versioned indicators</caption><thead><tr><th>Value</th><th>Type</th><th>Version</th><th>Confidence</th><th>Validity</th><th>Context</th></tr></thead><tbody>${iocItems.map((x) => `<tr><td><a href="#/intelligence/${x.indicatorId}?version=${x.version}"><code>${esc(x.canonicalValue)}</code></a></td><td>${esc(x.type)}</td><td>${x.version}</td><td>${x.confidence}%</td><td>${x.revoked ? "Revoked" : x.expired ? "Expired" : "Active"}</td><td>${esc([x.campaign, x.malwareFamily, ...(x.attackMappings || [])].filter(Boolean).join(", ") || "Source-provided context unavailable")}</td></tr>`).join("")}</tbody></table></div>` : state("No indicators", "Add a manual indicator or import a bounded source.")}</section><section aria-labelledby="intel-exclusion-title"><h2 id="intel-exclusion-title">Versioned exclusions</h2><p>${(exclusions.data || []).length} active or historical exclusion record(s). Matches are retained and explicitly marked, never silently deleted.</p></section>`;
  } catch (error) { return state("Threat intelligence unavailable", error.message); }
}
async function intelligenceDetail(id) {
  try { const q = new URLSearchParams(location.hash.split("?")[1] || ""), x = (await api(`/api/v1/intelligence/indicators/${id}${q.get("version") ? `?version=${encodeURIComponent(q.get("version"))}` : ""}`)).data, matches = (await api(`/api/v1/intelligence/matches?indicatorId=${id}&pageSize=100`)).data.items || []; return `<a href="#/intelligence">← Threat intelligence</a><div class="detail-head"><div><h2><code>${esc(x.canonicalValue)}</code></h2><p>${esc(x.type)} · immutable version ${x.version}</p></div><span class="badge">${x.revoked ? "Revoked" : x.expired ? "Expired" : "Active"}</span></div><div class="panels"><article><h3>Source and validity</h3><dl><dt>Source/version</dt><dd><code>${esc(x.sourceId)}</code> / ${esc(x.sourceVersion || "not supplied")}</dd><dt>Confidence/reliability</dt><dd>${x.confidence}% / ${x.reliability}%</dd><dt>Valid from/until</dt><dd>${new Date(x.validFrom).toLocaleString()} / ${x.validUntil ? new Date(x.validUntil).toLocaleString() : "No supplied expiry"}</dd><dt>TLP</dt><dd>${esc(x.tlp)}</dd><dt>Provenance</dt><dd>${esc(x.provenance)}</dd></dl></article><article><h3>Source-provided context</h3><dl><dt>Campaign</dt><dd>${esc(x.campaign || "Not provided")}</dd><dt>Malware family</dt><dd>${esc(x.malwareFamily || "Not provided")}</dd><dt>Threat actor</dt><dd>${esc(x.threatActor || "Not provided; no attribution inferred")}</dd><dt>ATT&CK</dt><dd>${esc((x.attackMappings || []).join(", ") || "Not provided")}</dd></dl></article></div><section><h2>Exact evidence matches</h2>${intelligenceMatchTable(matches)}</section>`; } catch (error) { return state("Indicator unavailable", error.message); }
}
function intelligenceMatchTable(items) { return items.length ? `<div class="table-wrap"><table><caption>Exact IOC match evidence</caption><thead><tr><th>Observed</th><th>Indicator version</th><th>Endpoint/process</th><th>Field/value</th><th>Evidence</th><th>Mode</th></tr></thead><tbody>${items.map((x) => `<tr><td>${new Date(x.firstSeen).toLocaleString()}</td><td>${x.indicatorVersion}</td><td><code>${esc(x.endpointId)}</code><br>${esc(x.processEntityId || "No process attribution")}</td><td>${esc(x.matchedField)}<br><code>${esc(x.matchedValue)}</code></td><td><code>${esc(x.evidenceReference)}</code></td><td>${esc(x.mode)}${x.excluded ? " · excluded" : ""}</td></tr>`).join("")}</tbody></table></div>` : '<p class="muted">No exact matches.</p>'; }
async function intelligenceMatches() { try { const values = (await api("/api/v1/intelligence/matches?pageSize=100")).data.items || []; return `<section aria-labelledby="ioc-match-title"><h2 id="ioc-match-title">IOC matches</h2><p>Every record binds an immutable indicator/source version to exact authoritative evidence.</p>${intelligenceMatchTable(values)}</section>`; } catch (error) { return state("IOC matches unavailable", error.message); } }
async function intelligenceHealth() { try { const x = (await api("/api/v1/intelligence/health")).data; return `<div class="panels"><article><h2>Indicators</h2><dl><dt>Sources</dt><dd>${x.sources}</dd><dt>Active / expired / revoked</dt><dd>${x.activeIndicators} / ${x.expiredIndicators} / ${x.revokedIndicators}</dd><dt>Invalid / duplicate</dt><dd>${x.invalidIndicators} / ${x.duplicateIndicators}</dd></dl></article><article><h2>Matching and imports</h2><dl><dt>Matches / excluded</dt><dd>${x.matches} / ${x.excludedMatches}</dd><dt>Imports / failures</dt><dd>${x.imports} / ${x.importFailures}</dd><dt>Backmatch jobs</dt><dd>${x.backmatchJobs}</dd><dt>Last match latency</dt><dd>${Math.round(x.lastMatchLatencyMilliseconds)} ms</dd></dl></article><article><h2>Safety</h2><p>Metric dimensions contain aggregate counts only; indicator values are not labels.</p></article></div>`; } catch (error) { return state("Intelligence health unavailable", error.message); } }
async function createIntelSource(event) { event.preventDefault(); const form = event.currentTarget, values = Object.fromEntries(new FormData(form)); try { await api("/api/v1/intelligence/sources", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ sourceId: "00000000-0000-0000-0000-000000000000", tenantId: "", name: values.name, type: "Manual", reliability: Number(values.reliability), defaultConfidence: Number(values.confidence), enabled: true, globalScope: false, lastSuccessfulSync: null, failureState: null, rateLimitPerMinute: 60, license: "manual tenant source", handling: "TLP:CLEAR", checkpoint: null, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), version: 1 }) }); await route(); } catch (error) { form.querySelector('[role="alert"]').textContent = error.message; form.querySelector('[role="alert"]').focus(); } }
async function importIntel(event) { event.preventDefault(); const form = event.currentTarget, data = new FormData(form), source = data.get("sourceId"); try { const response = await fetch(`/api/v1/intelligence/sources/${source}/imports`, { method: "POST", headers: auth(), body: data }); if (!response.ok) throw Error((await response.json()).detail || "Import rejected"); const result = (await response.json()).data; form.querySelector('[role="alert"]').textContent = `${result.imported} imported, ${result.duplicates} duplicates, ${result.rejected} rejected.`; form.querySelector('[role="alert"]').focus(); } catch (error) { form.querySelector('[role="alert"]').textContent = error.message; form.querySelector('[role="alert"]').focus(); } }

async function forensicList() {
  try { const values = (await api("/api/v1/forensic-collections")).data.items || []; return `<div class="toolbar"><p>Tenant-bound collection jobs. Evidence is immutable and retained independently of cancellation.</p><a class="button" href="#/forensic-collections/new">New collection</a></div>${values.length ? `<div class="table-wrap"><table><caption>Forensic collection history</caption><thead><tr><th>Requested</th><th>Endpoint</th><th>Profile</th><th>State</th><th>Approval</th><th>Retention</th></tr></thead><tbody>${values.map((x) => `<tr><td><a href="#/forensic-collections/${x.collectionId}">${new Date(x.requestedAt).toLocaleString()}</a></td><td><code>${esc(x.endpointId)}</code></td><td>${esc(x.profileId)} v${x.profileVersion}</td><td>${esc(x.state)}</td><td>${esc(x.approvalState)}</td><td>${esc(x.retentionState)}</td></tr>`).join("")}</tbody></table></div>` : state("No forensic collections", "No bounded collection has been requested.")}`; } catch (error) { return state("Collections unavailable", error.message); }
}

let currentForensicActionId = null;
async function forensicDetail(id) {
  try {
    const x = (await api(`/api/v1/forensic-collections/${id}`)).data, custody = await api(`/api/v1/forensic-collections/${id}/custody`), result = x.result; currentForensicActionId = x.actionId;
    const terminal = ["Succeeded", "Partial", "Failed", "Cancelled", "CancelledWithEvidence", "Expired"].includes(x.state), progress = result ? Math.min(100, Math.round(((result.collectedItems + result.failedItems + result.skippedItems) / Math.max(1, x.requestedArtifacts.length)) * 100)) : 0;
    return `<a href="#/forensic-collections">← Collection history</a><div class="detail-head"><div><h2>${esc(x.profileId)} v${x.profileVersion}</h2><p><code>${esc(x.collectionId)}</code></p></div><span class="badge">${esc(x.state)}</span></div><div class="panels"><article><h3>Immutable scope</h3><dl><dt>Endpoint / installation</dt><dd><code>${esc(x.endpointId)}</code><br><code>${esc(x.agentInstallationId)}</code></dd><dt>Analyst</dt><dd>${esc(x.analystId)}</dd><dt>Profile hash</dt><dd><code>${esc(x.profileHash)}</code></dd><dt>Parameter hash</dt><dd><code>${esc(x.parameterHash)}</code></dd><dt>Audit correlation</dt><dd><code>${esc(x.auditCorrelationId)}</code></dd></dl></article><article><h3>Progress and retention</h3><label for="collection-progress">Collection progress</label><progress id="collection-progress" max="100" value="${progress}" aria-valuetext="${progress} percent; ${esc(x.state)}">${progress}%</progress><p role="status" aria-live="polite">${esc(x.state)} · ${result?.collectedItems || 0} acquired · ${result?.failedItems || 0} failed · ${result?.skippedItems || 0} skipped</p><p>Retention: ${esc(x.retentionState)}</p>${result ? `<button id="forensic-manifest" data-collection="${id}">Download integrity manifest</button>` : ""}</article><article><h3>Approval and control</h3>${x.approvalState === "Pending" ? `<form id="forensic-approve"><label>Exact parameter hash <input name="parameterHash" value="${esc(x.parameterHash)}" required></label><label>Approval reason <input name="reason" required maxlength="500"></label><button>Approve exact scope</button></form>` : `<p>${esc(x.approvalState)}${x.approverId ? ` by ${esc(x.approverId)}` : ""}</p>`}${!terminal ? `<form id="forensic-cancel"><label>Cancellation reason <input name="reason" required maxlength="500"></label><button>Cancel future acquisition</button></form>` : ""}<button id="forensic-refresh">Refresh</button><p id="forensic-action-status" role="status" aria-live="assertive" tabindex="-1"></p></article></div><section><h2>Requested scope</h2><ol>${x.requestedArtifacts.map((a) => `<li>${esc(a.artifactType)} — <code>${esc(a.source || a.fileTarget?.canonicalPath || "structured endpoint state")}</code></li>`).join("")}</ol></section><section><h2>Evidence and failures</h2>${forensicItems(result?.items, id)}</section><section><h2>Auditable technical chain of custody</h2><p class="muted">This is technical audit history; no legal-admissibility claim is made.</p><ol class="timeline">${custody.data.events.map((e) => `<li><time>${new Date(e.occurredAt).toLocaleString()}</time> <strong>${esc(e.eventType)}</strong> by ${esc(e.actor)}<p>${esc(e.summary)} · <code>${esc(e.integrityHash)}</code></p></li>`).join("")}</ol></section>`;
  } catch (error) { return state("Collection unavailable", error.message); }
}

async function hydrateForensicTransfers() {
  if (!currentForensicActionId) return;
  try {
    const transfers = (await api(`/api/v1/artifact-transfers?ownerId=${encodeURIComponent(currentForensicActionId)}`)).data || [];
    if (!transfers.length) return;
    const section = document.createElement("section"); section.setAttribute("aria-labelledby", "forensic-transfer-title");
    section.innerHTML = `<h2 id="forensic-transfer-title">Large-artifact transfers</h2><div class="table-wrap"><table><caption>Resumable evidence transport progress</caption><thead><tr><th>Artifact</th><th>State</th><th>Progress</th><th>Bytes</th><th>Chunks</th></tr></thead><tbody>${transfers.map((x) => `<tr><td><code>${esc(x.artifactId)}</code></td><td>${esc(x.state)}</td><td><progress max="100" value="${x.progressPercent}" aria-label="Artifact transfer progress">${x.progressPercent}%</progress> ${x.progressPercent}%</td><td>${x.receivedBytes} / ${x.size}</td><td>${x.receivedChunks} / ${x.totalChunks}</td></tr>`).join("")}</tbody></table></div>`;
    document.querySelector("#content .panels")?.insertAdjacentElement("afterend", section);
  } catch { /* collection remains usable when transfer health is temporarily unavailable */ }
}

async function forensicDecision(event, id, operation) { event.preventDefault(); const status = document.querySelector("#forensic-action-status"); try { const body = Object.fromEntries(new FormData(event.currentTarget)); await api(`/api/v1/forensic-collections/${id}:${operation}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }); status.textContent = `${operation} recorded.`; status.focus(); await route(); } catch (error) { status.textContent = error.message; status.focus(); } }
async function downloadForensic(collection, item) { const response = await fetch(`/api/v1/forensic-collections/${collection}/items/${item}/content`, { headers: auth() }); if (!response.ok) throw Error(`Download failed with status ${response.status}.`); const url = URL.createObjectURL(await response.blob()), a = document.createElement("a"); a.href = url; a.download = `forensic-${item}.bin`; a.click(); URL.revokeObjectURL(url); }
async function downloadForensicManifest(collection) { const response = await fetch(`/api/v1/forensic-collections/${collection}/manifest`, { headers: auth() }); if (!response.ok) throw Error(`Manifest download failed with status ${response.status}.`); const url = URL.createObjectURL(await response.blob()), a = document.createElement("a"); a.href = url; a.download = `forensic-${collection}-manifest.json`; a.click(); URL.revokeObjectURL(url); }
async function forensicHealthPage() { try { const x = (await api("/api/v1/forensic-collection-health")).data; return `<div class="panels"><article><h2>Collection lifecycle</h2><dl><dt>Requests / running</dt><dd>${x.requests} / ${x.running}</dd><dt>Succeeded / partial / failed</dt><dd>${x.successful} / ${x.partial} / ${x.failed}</dd><dt>Cancelled / expired</dt><dd>${x.cancelled} / ${x.expired}</dd><dt>Average latency</dt><dd>${Math.round(x.collectionLatencyMilliseconds)} ms</dd></dl></article><article><h2>Evidence quality</h2><dl><dt>Items acquired</dt><dd>${x.itemsAcquired}</dd><dt>Unstable</dt><dd>${x.unstableItems}</dd><dt>Hash failures</dt><dd>${x.hashFailures}</dd><dt>Quota rejections</dt><dd>${x.quotaRejections}</dd><dt>Upload failures</dt><dd>${x.uploadFailures}</dd><dt>Bytes</dt><dd>${x.bytesCollected}</dd></dl></article><article><h2>Metric privacy</h2><p>${x.metricLabelsContainSensitiveDimensions ? "FAIL: sensitive dimensions present" : "PASS: no filename, hash, endpoint, or analyst labels"}</p></article></div>`; } catch (error) { return state("Collection health unavailable", error.message); } }

async function forensicToolsPage() {
  try {
    const tools = (await api("/api/v1/live-response/tool-packages")).data || [];
    return `<section aria-labelledby="tool-library-title"><h2 id="tool-library-title">Approved forensic tool library</h2><p class="notice">Packages are hash-pinned, staged without execution, and require a separately approved Live Response file-upload capability. Execution remains a distinct audited command.</p><form id="tool-package-upload"><label>Tool name <input name="name" required maxlength="128"></label><label>Version <input name="version" required maxlength="64"></label><label>Expected SHA-256 <input name="sha256" required pattern="[0-9a-fA-F]{64}" maxlength="64"></label><label>Expected Authenticode thumbprint <input name="signer" pattern="[0-9a-fA-F]{40,128}" maxlength="128"></label><label><input type="checkbox" name="allowUnsigned"> Explicitly approve unsigned package</label><label>Package <input type="file" name="package" accept=".exe,.dll,.ps1,.zip" required></label><button>Upload approved package</button><p id="tool-package-status" role="status" aria-live="assertive" tabindex="-1"></p></form></section><section><h2>Available packages</h2>${tools.length ? `<div class="table-wrap"><table><caption>Approved forensic tool packages</caption><thead><tr><th>Name</th><th>Version</th><th>File</th><th>Size</th><th>SHA-256</th><th>Signer policy</th><th>State</th></tr></thead><tbody>${tools.map((x) => `<tr><td>${esc(x.name)}</td><td>${esc(x.version)}</td><td>${esc(x.fileName)}</td><td>${x.size}</td><td><code>${esc(x.sha256)}</code></td><td>${esc(x.expectedSignerThumbprint || (x.allowUnsigned ? "Unsigned explicitly approved" : "Invalid policy"))}</td><td>${esc(x.state)}</td></tr>`).join("")}</tbody></table></div>` : state("No approved tools", "Upload a hash-pinned package when a native collector is insufficient.")}</section>`;
  } catch (error) { return state("Tool library unavailable", error.message); }
}

async function uploadForensicTool(event) {
  event.preventDefault(); const form = event.currentTarget, status = document.querySelector("#tool-package-status"), values = new FormData(form), file = values.get("package");
  try {
    const headers = { ...auth(), "Content-Type": "application/octet-stream", "X-Tool-Name": values.get("name"), "X-Tool-Version": values.get("version"), "X-Tool-FileName": file.name, "X-Tool-SHA256": values.get("sha256"), "X-Tool-Allow-Unsigned": values.get("allowUnsigned") ? "true" : "false" };
    if (values.get("signer")) headers["X-Tool-Signer"] = values.get("signer");
    const response = await fetch("/api/v1/live-response/tool-packages", { method: "POST", headers, body: file });
    if (!response.ok) throw Error((await response.json().catch(() => null))?.detail || `Upload failed with status ${response.status}.`);
    status.textContent = "Approved package stored. Use stage-tool <package-id> in an elevated Live Response session."; status.focus(); await route();
  } catch (error) { status.textContent = error.message; status.focus(); }
}

async function tunnelPage(id) {
  try {
    if (id) {
      const [finding, observations] = await Promise.all([api(`/api/v1/tunnels/findings/${id}`), api("/api/v1/tunnels/observations?pageSize=200")]), x = finding.data, source = (observations.data.items || []).find((o) => (x.observationIds || []).includes(o.observationId));
      let chain = null; if (source) chain = (await api(`/api/v1/tunnels/observations/${source.observationId}/chain?maximumDepth=4`)).data;
      return `<a href="#/tunnels">← Tunnel findings</a><div class="detail-head"><div><h2>${esc(x.ruleName)}</h2><p><code>${esc(x.findingId)}</code></p></div><span class="badge">${esc(x.confidence)} · ${x.score}</span></div><div class="panels"><article><h3>Classification</h3><dl><dt>Kind</dt><dd>${esc(x.kind)}</dd><dt>Rule</dt><dd><code>${esc(x.ruleId)}</code></dd><dt>Endpoint</dt><dd><code>${esc(x.endpointId)}</code></dd><dt>Process</dt><dd><code>${esc(x.processEntityId || "Unattributed")}</code></dd><dt>Excluded</dt><dd>${x.excluded ? "Yes" : "No"}</dd></dl></article><article><h3>Why this finding exists</h3><ul>${(x.reasons || []).map((v) => `<li>${esc(v)}</li>`).join("")}</ul><p>Missing telemetry: ${esc((x.missingTelemetry || []).join(", ") || "None")}</p></article><article><h3>Exact evidence</h3><ul>${(x.evidenceReferences || []).map((v) => `<li><code>${esc(v)}</code></li>`).join("")}</ul></article></div><section aria-labelledby="tunnel-chain-title"><h2 id="tunnel-chain-title">Bounded multi-tunnel chain</h2>${chain ? tunnelChainTable(chain) : '<p class="muted">Source observation unavailable.</p>'}</section>`;
    }
    const q = new URLSearchParams(location.hash.split("?")[1] || ""), suffix = q.toString() ? `&${q}` : "", [findings, exclusions] = await Promise.all([api(`/api/v1/tunnels/findings?pageSize=100${suffix}`), api("/api/v1/tunnels/exclusions")]), items = findings.data.items || [];
    return `<div class="toolbar"><p>Evidence-backed tunneling, proxy, nested-chain, and DNS covert-channel analytics. No packet payload inspection or automatic response.</p><a class="button" href="#/tunnel-rules">Review analytic rules</a></div><form id="tunnel-search" role="search"><div class="panels"><label>Endpoint ID <input name="endpointId" value="${esc(q.get("endpointId") || "")}"></label><label>Process entity <input name="processEntityId" value="${esc(q.get("processEntityId") || "")}"></label><label>Kind <select name="kind"><option value="">All</option>${["SshLocalForward","SshDynamicProxy","SshReverseForward","SocksProxy","HttpProxy","Vpn","DnsTunnel","NestedTunnel","Unknown"].map((v) => `<option ${q.get("kind") === v ? "selected" : ""}>${v}</option>`).join("")}</select></label><label>Minimum confidence <select name="minimumConfidence"><option value="">All</option><option>Low</option><option>Medium</option><option>High</option></select></label></div><button>Search</button></form>${items.length ? `<div class="table-wrap"><table><caption>Evidence-backed tunnel findings</caption><thead><tr><th>Last observed</th><th>Rule / kind</th><th>Confidence</th><th>Endpoint / process</th><th>Evidence</th><th>Disposition</th></tr></thead><tbody>${items.map((x) => `<tr><td><a href="#/tunnels/${x.findingId}">${new Date(x.lastObserved).toLocaleString()}</a></td><td>${esc(x.ruleName)}<br>${esc(x.kind)}</td><td>${esc(x.confidence)} (${x.score})</td><td><code>${esc(x.endpointId)}</code><br>${esc(x.processEntityId || "Unattributed")}</td><td>${x.evidenceIds.length} source event(s)</td><td>${x.excluded ? "Excluded" : "Active"}</td></tr>`).join("")}</tbody></table></div>` : state("No tunnel findings", "No evidence-backed finding matches this bounded query.")}<section><h2>Tenant exclusions</h2><p>${(exclusions.data || []).length} versioned exclusion record(s). Exclusions remain visible and measurable.</p><form id="tunnel-exclusion"><label>Name <input name="name" required maxlength="200"></label><label>Field <select name="field"><option>processEntityId</option><option>kind</option><option>remoteAddress</option><option>hostname</option></select></label><label>Exact value <input name="value" required maxlength="512"></label><label>Reason <input name="reason" required maxlength="1024"></label><button>Add 30-day exclusion</button><p role="alert" tabindex="-1"></p></form></section>`;
  } catch (error) { return state("Tunnel analytics unavailable", error.message); }
}
function tunnelChainTable(chain) { return `<p>Depth ${chain.depth} of 4${chain.truncated ? " · truncated" : ""}. Relationships are shown as a table for keyboard and screen-reader access.</p><div class="table-wrap"><table><caption>Evidence-backed tunnel chain</caption><thead><tr><th>From</th><th>Relationship</th><th>To</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>${(chain.relationships || []).map((x) => `<tr><td><code>${esc(x.sourceEntityId)}</code></td><td>${esc(x.type)}</td><td><code>${esc(x.destinationEntityId)}</code></td><td>${x.confidence}</td><td>${(x.evidenceReferences || []).map(esc).join("; ")}</td></tr>`).join("") || '<tr><td colspan="5">No additional source-backed hop was observable.</td></tr>'}</tbody></table></div>`; }
async function tunnelRulesPage() { try { const rules = (await api("/api/v1/tunnels/rules")).data; return `<p>Rules require observable metadata and exact source evidence. ICMP payload/covert-channel analytics are not claimed.</p><div class="table-wrap"><table><caption>Production tunnel analytic pack</caption><thead><tr><th>Rule</th><th>Kind</th><th>Threshold</th><th>Sources</th><th>Quality</th></tr></thead><tbody>${rules.map((x) => `<tr><td><strong>${esc(x.name)}</strong><br><code>${esc(x.ruleId)}</code><br>${esc(x.description)}</td><td>${esc(x.kind)}</td><td>${x.minimumScore}</td><td>${esc(x.requiredSources.join(", "))}</td><td>${esc(x.qualityNotes)}</td></tr>`).join("")}</tbody></table></div>`; } catch (error) { return state("Tunnel rules unavailable", error.message); } }
async function tunnelHealthPage() { try { const x=(await api("/api/v1/tunnels/health")).data; return `<div class="panels"><article><h2>Pipeline</h2><dl><dt>Observations / findings</dt><dd>${x.observations} / ${x.findings}</dd><dt>Excluded</dt><dd>${x.excluded}</dd><dt>Evaluation failures</dt><dd>${x.evaluationFailures}</dd></dl></article><article><h2>Safety</h2><dl><dt>Relationship rejects</dt><dd>${x.relationshipRejects}</dd><dt>Bounded-query rejects</dt><dd>${x.boundedQueryRejects}</dd><dt>Maximum chain depth</dt><dd>${x.maximumChainDepth}</dd><dt>ICMP visibility</dt><dd>${esc(x.icmpVisibility)}</dd></dl></article></div>`; } catch(error){return state("Tunnel health unavailable",error.message);} }
async function createTunnelExclusion(event){event.preventDefault();const form=event.currentTarget,values=Object.fromEntries(new FormData(form)),now=new Date();try{await api("/api/v1/tunnels/exclusions",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({exclusionId:crypto.randomUUID(),tenantId:"",version:1,name:values.name,field:values.field,value:values.value,startsAt:now.toISOString(),endsAt:new Date(now.getTime()+30*86400000).toISOString(),reason:values.reason,createdBy:"",createdAt:now.toISOString()})});await route();}catch(error){form.querySelector('[role="alert"]').textContent=error.message;form.querySelector('[role="alert"]').focus();}}

async function playbooksPage(id, version) {
  try {
    if (id) { const x=(await api(`/api/v1/playbooks/${id}/versions/${version || 1}`)).data; return `<a href="#/playbooks">← Playbooks</a><div class="detail-head"><div><h2>${esc(x.name)}</h2><p>${esc(x.description)}</p></div><span class="badge">${esc(x.state)} · v${x.version}</span></div><div class="panels"><article><h3>Immutable definition</h3><dl><dt>Version hash</dt><dd><code>${esc(x.versionHash)}</code></dd><dt>Risk</dt><dd>${esc(x.risk)}</dd><dt>Runtime / steps</dt><dd>${x.maximumRuntimeSeconds}s / ${x.steps.length}</dd><dt>Concurrency</dt><dd>${x.maximumConcurrency}</dd></dl></article><article><h3>Triggers</h3><ul>${x.triggers.map((t)=>`<li>${esc(t.type)}: ${esc(t.sourceTypes.join(", "))}</li>`).join("")}</ul></article></div><section><h2>Structured step graph</h2>${playbookStepTable(x.steps)}</section><section><h2>Version history</h2><p>This execution remains pinned to version ${x.version}. Edits create a new immutable version.</p></section>`; }
    const [books,actions]=await Promise.all([api("/api/v1/playbooks"),api("/api/v1/playbooks/actions")]), items=books.data||[], registry=actions.data||[];
    return `<div class="toolbar"><p>Deterministic orchestration over registered structured actions only. No shell, scripts, arbitrary HTTP, or Live Response text.</p><a class="button" href="#/playbook-approvals">Pending approvals</a></div><section aria-labelledby="playbook-editor-title"><h2 id="playbook-editor-title">Structured playbook editor</h2><form id="playbook-editor"><label>Name <input name="name" required maxlength="200"></label><label>Trigger <select name="trigger"><option>Manual</option><option>AlertCreated</option><option>IncidentCreated</option><option>DetectionFinding</option><option>CorrelatedFinding</option><option>IocMatch</option><option>TunnelFinding</option></select></label><label>Registered action <select name="action">${registry.map((x)=>`<option value="${esc(x.actionType)}" data-risk="${esc(x.risk)}">${esc(x.actionType)} — ${esc(x.risk)}</option>`).join("")}</select></label><p class="notice">The editor creates typed steps. High/Critical actions receive a required approval gate automatically.</p><button>Create draft</button><p role="status" aria-live="assertive" tabindex="-1"></p></form></section><section><h2>Playbook versions</h2>${items.length?`<div class="table-wrap"><table><caption>Tenant playbook versions</caption><thead><tr><th>Name</th><th>Version</th><th>State</th><th>Risk</th><th>Steps</th><th>Updated</th></tr></thead><tbody>${items.map((x)=>`<tr><td><a href="#/playbooks/${x.playbookId}/${x.version}">${esc(x.name)}</a></td><td>${x.version}</td><td>${esc(x.state)}</td><td>${esc(x.risk)}</td><td>${x.steps.length}</td><td>${new Date(x.updatedAt).toLocaleString()}</td></tr>`).join("")}</tbody></table></div>`:state("No playbooks","Create a structured draft or run the controlled starter-pack qualification.")}</section>`;
  } catch(error){return state("Playbooks unavailable",error.message);}
}
function playbookStepTable(steps){return `<div class="table-wrap"><table><caption>Accessible playbook graph alternative</caption><thead><tr><th>Step</th><th>Type</th><th>Dependencies</th><th>Action</th><th>Approval</th><th>Timeout</th></tr></thead><tbody>${steps.map((s)=>`<tr><td><code>${esc(s.stepId)}</code><br>${esc(s.name)}</td><td>${esc(s.type)}</td><td>${esc(s.dependencies.join(", ")||"Root")}</td><td>${esc(s.inputs.actionType||"Not applicable")}</td><td>${s.approval?.required?"Required":"Not required"}</td><td>${s.timeoutSeconds}s</td></tr>`).join("")}</tbody></table></div>`;}
async function createPlaybook(event){event.preventDefault();const form=event.currentTarget,status=form.querySelector('[role="status"]'),v=Object.fromEntries(new FormData(form)),risk=form.action.selectedOptions[0].dataset.risk,now=new Date().toISOString(),source=v.trigger==="Manual"?"manual":v.trigger.includes("Incident")?"incident":v.trigger.includes("Alert")?"alert":v.trigger==="IocMatch"?"ioc-match":v.trigger==="TunnelFinding"?"tunnel-finding":"finding",approval=["High","Critical"].includes(risk);try{await api("/api/v1/playbooks",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({schemaVersion:"playbook.v1",playbookId:crypto.randomUUID(),version:1,tenantId:"",name:v.name,description:"Structured analyst-authored playbook.",state:"Draft",author:"",createdAt:now,updatedAt:now,activatedAt:null,deactivatedAt:null,triggers:[{type:v.trigger,sourceTypes:[source],enabled:true}],supportedSourceTypes:[source],steps:[{stepId:"action",type:"StructuredResponse",name:v.action,dependencies:[],inputs:{actionType:v.action},timeoutSeconds:60,retry:{maximumAttempts:1,initialDelaySeconds:1,maximumDelaySeconds:30},approval:approval?{required:true,secondPerson:risk==="Critical",expiresInSeconds:900}:null,idempotencyPolicy:"exact-step-and-target.v1"}],inputSchema:{endpointId:"uuid",targetEntityId:"stable-identity"},requiredPermissions:["playbook:execute"],maximumRuntimeSeconds:900,maximumSteps:32,maximumBranching:4,maximumConcurrency:2,retryPolicy:{maximumAttempts:1,initialDelaySeconds:1,maximumDelaySeconds:30},approvalPolicy:{required:approval,secondPerson:risk==="Critical",expiresInSeconds:900},cancellationAllowed:true,simulationSupported:true,risk,versionHash:""})});status.textContent="Draft created.";status.focus();await route();}catch(error){status.textContent=error.message;status.focus();}}
async function playbookExecutionsPage(id){try{if(id){const x=(await api(`/api/v1/playbook-executions/${id}`)).data;return `<a href="#/playbook-executions">← Executions</a><div class="detail-head"><div><h2>Execution ${esc(x.executionId)}</h2><p>${esc(x.sourceType)}: <code>${esc(x.sourceObjectId)}</code></p></div><span class="badge">${esc(x.state)}</span></div><div class="panels"><article><h3>Binding</h3><dl><dt>Endpoint</dt><dd><code>${esc(x.endpointId)}</code></dd><dt>Target</dt><dd><code>${esc(x.targetEntityId||"None")}</code></dd><dt>Installation</dt><dd><code>${esc(x.expectedInstallationId||"Not pinned")}</code></dd><dt>Mode</dt><dd>${esc(x.mode)}</dd></dl></article><article><h3>Result</h3><p>${esc(x.result||"Running")}</p><p>Audit correlation: <code>${esc(x.auditCorrelation)}</code></p></article></div><section><h2>Execution timeline</h2><ol class="timeline">${x.steps.map((s)=>`<li><strong>${esc(s.stepId)}</strong> — ${esc(s.state)}${s.message?`: ${esc(s.message)}`:""}<br><small>${esc(s.evidenceReferences.join(", ")||"No response evidence yet")}</small></li>`).join("")}</ol></section>`;}const items=(await api("/api/v1/playbook-executions")).data||[];return items.length?`<div class="table-wrap"><table><caption>Playbook execution history</caption><thead><tr><th>Started</th><th>Source</th><th>Mode</th><th>Status</th><th>Steps</th></tr></thead><tbody>${items.map((x)=>`<tr><td><a href="#/playbook-executions/${x.executionId}">${new Date(x.startedAt).toLocaleString()}</a></td><td>${esc(x.sourceType)}: ${esc(x.sourceObjectId)}</td><td>${esc(x.mode)}</td><td>${esc(x.state)}</td><td>${x.steps.filter((s)=>["Succeeded","Simulated","Skipped"].includes(s.state)).length}/${x.steps.length}</td></tr>`).join("")}</tbody></table></div>`:state("No executions","No playbook has been initiated.");}catch(error){return state("Executions unavailable",error.message);}}
async function playbookApprovalsPage(){try{const items=(await api("/api/v1/playbook-approvals")).data||[];return items.length?`<div class="table-wrap"><table><caption>Exact bound playbook approvals</caption><thead><tr><th>Execution</th><th>Step/action</th><th>Target</th><th>Risk context</th><th>Decision</th></tr></thead><tbody>${items.map((x)=>{const s=x.steps.find((v)=>v.state==="WaitingForApproval");return `<tr><td><a href="#/playbook-executions/${x.executionId}">${esc(x.executionId)}</a></td><td>${esc(s?.stepId)}<br><code>${esc(s?.inputHash)}</code></td><td><code>${esc(x.targetEntityId||x.endpointId)}</code><br>${esc(x.expectedInstallationId||"Not pinned")}</td><td>Exact target and parameter hash; expires ${s?.approvalExpiresAt?new Date(s.approvalExpiresAt).toLocaleString():"Unknown"}</td><td><form class="playbook-approval" data-id="${x.executionId}" data-step="${esc(s?.stepId)}" data-hash="${esc(s?.inputHash)}"><label>Rationale <input name="reason" required maxlength="1024"></label><button name="decision" value="approve">Approve</button><button name="decision" value="deny">Deny</button><p role="status" tabindex="-1"></p></form></td></tr>`;}).join("")}</tbody></table></div>`:state("No pending approvals","Destructive playbook steps have not crossed their approval gates.");}catch(error){return state("Approvals unavailable",error.message);}}
async function decidePlaybookApproval(event){event.preventDefault();const form=event.currentTarget,status=form.querySelector('[role="status"]'),button=event.submitter,decision=button.value;try{await api(`/api/v1/playbook-executions/${form.dataset.id}:${decision}`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({stepId:form.dataset.step,inputHash:form.dataset.hash,reason:new FormData(form).get("reason")})});status.textContent=`${decision} recorded.`;status.focus();await route();}catch(error){status.textContent=error.message;status.focus();}}
async function playbookHealthPage(){try{const x=(await api("/api/v1/playbook-health")).data;return `<div class="panels"><article><h2>Definitions and queue</h2><dl><dt>Active playbooks</dt><dd>${x.activePlaybooks}</dd><dt>Triggered</dt><dd>${x.triggeredExecutions}</dd><dt>Running</dt><dd>${x.running}</dd><dt>Queue depth</dt><dd>${x.queueDepth}</dd><dt>Waiting approval</dt><dd>${x.waitingApprovals}</dd></dl></article><article><h2>Outcomes</h2><dl><dt>Succeeded / partial / failed</dt><dd>${x.succeeded} / ${x.partial} / ${x.failed}</dd><dt>Cancelled / timed out</dt><dd>${x.cancelled} / ${x.timedOut}</dd><dt>Safe automatic actions</dt><dd>${x.automaticSafeActions}</dd><dt>Approval-gated actions</dt><dd>${x.approvalGatedActions}</dd><dt>Rejected unsafe actions</dt><dd>${x.rejectedUnsafeActions}</dd></dl></article></div>`;}catch(error){return state("Playbook health unavailable",error.message);}}

async function selfProtectionPage() {
  if (!token()) return state("Authentication required", "Sign in to inspect tenant-scoped agent protection.", '<a class="button" href="#/login">Sign in</a>');
  try {
    const query = new URLSearchParams(location.hash.split("?")[1] || "");
    let endpointId = query.get("endpointId");
    if (!endpointId) {
      const endpoints = (await api("/api/v1/endpoints?pageSize=1")).data.items || [];
      endpointId = endpoints[0]?.id;
    }
    if (!endpointId) return state("No protected endpoint", "Enroll an endpoint before configuring self-protection.");
    const [status, resources, events, health] = await Promise.all([
      api(`/api/v1/endpoints/${endpointId}/self-protection`),
      api(`/api/v1/endpoints/${endpointId}/self-protection/resources`),
      api(`/api/v1/endpoints/${endpointId}/self-protection/tamper-events?limit=100`),
      api("/api/v1/self-protection/health"),
    ]);
    const x=status.data, inventory=resources.data, timeline=events.data || [], h=health.data;
    const observed = new Map((inventory.observed || []).map((v)=>[v.resourceId,v]));
    return `<div class="toolbar"><p>Evidence-backed agent self-protection. Administrative privilege boundaries are reported honestly; no kernel self-defense is claimed.</p><button id="protection-verify" data-endpoint="${esc(endpointId)}">Verify current report</button></div>
      <p id="protection-status" class="notice" role="status" aria-live="assertive" tabindex="-1">Overall protection state: <strong>${esc(x.state)}</strong>. Last verified ${new Date(x.verifiedAt).toLocaleString()}.</p>
      <div class="panels"><article><h2>Protection overview</h2><dl><dt>Endpoint</dt><dd><a href="#/endpoints/${esc(endpointId)}"><code>${esc(endpointId)}</code></a></dd><dt>Installation</dt><dd><code>${esc(x.installationId)}</code></dd><dt>Policy version</dt><dd>${x.policyVersion}</dd><dt>Drifted surfaces</dt><dd>${x.unresolvedDrift}</dd><dt>Maintenance mode</dt><dd>${x.maintenanceMode ? "Authorized and active" : "Inactive"}</dd><dt>Last repair</dt><dd>${esc(x.repair)}</dd></dl></article><article><h2>Tenant health</h2><dl><dt>Protected / degraded</dt><dd>${h.protectedEndpoints} / ${h.degradedEndpoints}</dd><dt>Tamper events</dt><dd>${h.tamperEvents}</dd><dt>Prevented / detected only</dt><dd>${h.preventedTamper} / ${h.detectedOnlyTamper}</dd><dt>Repairs succeeded / failed</dt><dd>${h.repairSucceeded} / ${h.repairFailed}</dd><dt>Maintenance sessions</dt><dd>${h.maintenanceSessions}</dd></dl></article></div>
      <section><h2>Protected resource inventory</h2><div class="table-wrap"><table><caption>Expected and observed self-protection surfaces</caption><thead><tr><th>Resource</th><th>Type</th><th>Expected</th><th>Observed</th><th>Integrity</th><th>Prevention</th><th>Repair</th><th>Evidence</th></tr></thead><tbody>${inventory.resources.map((r)=>{const o=observed.get(r.resourceId);return `<tr><td>${esc(r.resourceId)}<br><small>${esc(r.objectName)}</small></td><td>${esc(r.type)}</td><td>${esc(r.verificationMethod)}</td><td>${esc(o?.observedState || "Not yet observed")}</td><td>${esc(o?.state || "Unknown")}</td><td>${esc(o?.prevention || "NotObservable")}</td><td>${esc(o?.repair || "NotRequested")}${r.repairMethod ? `<br><button class="protection-repair" data-endpoint="${esc(endpointId)}" data-installation="${esc(x.installationId)}" data-resource="${esc(r.resourceId)}">Request ${esc(r.repairMethod)}</button>`:""}</td><td><code>${esc(o?.evidenceHash || "Unavailable")}</code></td></tr>`;}).join("")}</tbody></table></div></section>
      <div class="panels"><section aria-labelledby="maintenance-title"><h2 id="maintenance-title">Authorized maintenance</h2><p>Maintenance is separate from ordinary policy, exact-capability scoped, time bounded, signed, and requires a different approver.</p><form id="protection-maintenance" data-endpoint="${esc(endpointId)}" data-installation="${esc(x.installationId)}"><label>Reason <input name="reason" required maxlength="2048"></label><label>Capability <select name="capability"><option>upgrade</option><option>uninstall</option><option>repair</option><option>certificate-rotation</option><option>controlled-troubleshooting</option></select></label><label>Duration minutes <input name="minutes" type="number" min="1" max="60" value="15" required></label><button>Request maintenance</button><p role="alert" aria-live="assertive" tabindex="-1"></p></form></section>
      <section aria-labelledby="approval-title"><h2 id="approval-title">Maintenance approval</h2><form id="protection-approval"><label>Maintenance ID <input name="maintenanceId" required></label><label>Exact request hash <input name="requestHash" required maxlength="128"></label><label>Approval rationale <input name="reason" required maxlength="2048"></label><button>Approve exact authorization</button><p role="alert" aria-live="assertive" tabindex="-1"></p></form><p class="muted">The requester cannot approve their own request.</p></section></div>
      <section><h2>Tamper timeline and evidence</h2>${timeline.length?`<div class="table-wrap"><table><caption>Immutable self-protection audit evidence</caption><thead><tr><th>Occurred</th><th>Event</th><th>Resource</th><th>Expected / observed</th><th>Prevention</th><th>Repair</th><th>Evidence</th></tr></thead><tbody>${timeline.map((e)=>`<tr><td>${new Date(e.occurredAt).toLocaleString()}</td><td>${esc(e.eventType)}</td><td>${esc(e.resourceType)}<br>${esc(e.resourceId)}</td><td>${esc(e.expectedState)}<br>${esc(e.observedState)}</td><td>${esc(e.prevention)}</td><td>${esc(e.repair)}</td><td><code>${esc(e.evidenceHash)}</code><br>${esc((e.evidenceReferences || []).join(", "))}</td></tr>`).join("")}</tbody></table></div>`:state("No tamper events", "No evidence-backed tamper event has been reported for this endpoint.")}</section>`;
  } catch (error) { return state("Self-protection degraded or unavailable", error.message); }
}
async function requestProtectionMaintenance(event){event.preventDefault();const form=event.currentTarget,status=form.querySelector('[role="alert"]'),minutes=Number(new FormData(form).get("minutes")),now=new Date();try{const value=(await api("/api/v1/self-protection/maintenance",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({endpointId:form.dataset.endpoint,installationId:form.dataset.installation,reason:new FormData(form).get("reason"),capabilities:[new FormData(form).get("capability")],startsAt:now.toISOString(),expiresAt:new Date(now.getTime()+minutes*60000).toISOString()})})).data;status.textContent=`Requested ${value.maintenanceId}. Exact hash ${value.requestHash}. A different administrator must approve it.`;status.focus();}catch(error){status.textContent=error.message;status.focus();}}
async function approveProtectionMaintenance(event){event.preventDefault();const form=event.currentTarget,data=new FormData(form),status=form.querySelector('[role="alert"]');try{const value=(await api(`/api/v1/self-protection/maintenance/${encodeURIComponent(data.get("maintenanceId"))}:approve`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({requestHash:data.get("requestHash"),reason:data.get("reason")})})).data;status.textContent=`Approved until ${new Date(value.expiresAt).toLocaleString()}; signature ${value.signatureKeyId}.`;status.focus();}catch(error){status.textContent=error.message;status.focus();}}
async function requestProtectionRepair(button){const reason=window.prompt("Reason for this bounded repair request:");if(!reason)return;try{await api("/api/v1/self-protection/repairs",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({endpointId:button.dataset.endpoint,installationId:button.dataset.installation,resourceId:button.dataset.resource,reason})});window.alert("Repair request recorded. Completion requires fresh agent verification.");await route();}catch(error){window.alert(error.message);}}

async function fleetPage(endpointId) {
  if (endpointId) {
    try {
      const [endpoint, versions] = await Promise.all([
        api(`/api/v1/fleet/endpoints/${encodeURIComponent(endpointId)}`),
        api(`/api/v1/fleet/endpoints/${encodeURIComponent(endpointId)}/versions`),
      ]);
      const x = endpoint.data, history = versions.data || [];
      return `<nav aria-label="Fleet breadcrumb"><a href="#/fleet">Fleet</a> / Endpoint</nav>
        <section aria-labelledby="fleet-endpoint-title"><h2 id="fleet-endpoint-title">${esc(x.hostname)}</h2><div class="detail-grid"><p><strong>Endpoint identity</strong><br><code>${esc(x.endpointId)}</code></p><p><strong>Installation identity</strong><br><code>${esc(x.installationId)}</code></p><p><strong>Agent version</strong><br>${esc(x.agentVersion)}</p><p><strong>Assigned ring</strong><br>${esc(x.ringId)}</p><p><strong>Eligibility</strong><br>${esc(x.eligibility)}</p><p><strong>Health</strong><br>${esc(x.telemetryHealth)} / ${esc(x.responseHealth)} / ${esc(x.protectionState)}</p></div></section>
        <section aria-labelledby="update-history-title"><h2 id="update-history-title">Update history</h2>${history.length ? `<div class="table-wrap"><table><caption>Immutable endpoint update assignments and results</caption><thead><tr><th>Updated</th><th>Package</th><th>Ring</th><th>State</th><th>Failure</th></tr></thead><tbody>${history.map((v)=>`<tr><td>${new Date(v.updatedAt).toLocaleString()}</td><td><code>${esc(v.packageId)}</code></td><td>${esc(v.ringId)}</td><td><span class="badge">${esc(v.state)}</span></td><td>${esc(v.failureCode || "None")}</td></tr>`).join("")}</tbody></table></div>` : state("No update history", "This installation has no update assignments.")}</section>`;
    } catch (error) { return state("Endpoint unavailable", error.message); }
  }
  try {
    const [fleet, health] = await Promise.all([api("/api/v1/fleet/endpoints"), api("/api/v1/agent-update/health")]);
    const items=fleet.data.items || [], h=health.data;
    return `<section aria-labelledby="fleet-overview-title"><h2 id="fleet-overview-title">Fleet overview</h2><div class="stats"><div><strong>${items.length}</strong><span>Endpoints</span></div><div><strong>${items.filter(x=>x.onlineState==="Online").length}</strong><span>Online</span></div><div><strong>${items.filter(x=>x.onlineState!=="Online").length}</strong><span>Offline</span></div><div><strong>${h.eligible}</strong><span>Update eligible</span></div><div><strong>${h.failed}</strong><span>Failed updates</span></div><div><strong>${h.pausedRollouts}</strong><span>Paused rollouts</span></div></div></section>
      <section aria-labelledby="fleet-inventory-title"><h2 id="fleet-inventory-title">Endpoint inventory and agent versions</h2>${items.length ? `<div class="table-wrap"><table><caption>Tenant-scoped endpoints, installation identity, health, groups, tags, and update state</caption><thead><tr><th>Endpoint</th><th>Platform</th><th>Version</th><th>Online</th><th>Ring</th><th>Groups / tags</th><th>Eligibility</th><th>Health</th></tr></thead><tbody>${items.map(x=>`<tr><td><a href="#/fleet/${esc(x.endpointId)}">${esc(x.hostname)}</a><br><code>${esc(x.installationId)}</code></td><td>${esc(x.platform)} ${esc(x.architecture)}</td><td>${esc(x.agentVersion)}</td><td><span class="badge">${esc(x.onlineState)}</span></td><td>${esc(x.ringId)}</td><td>${esc([...(x.groupIds||[]),...(x.tags||[])].join(", ") || "None")}</td><td>${esc(x.eligibility)}</td><td>${esc(x.telemetryHealth)} / ${esc(x.protectionState)}</td></tr>`).join("")}</tbody></table></div>` : state("No fleet endpoints", "Enroll an endpoint before assigning groups, rings, or updates.")}</section>`;
  } catch(error){ return state("Fleet unavailable", error.message); }
}

async function resiliencePage() {
  try {
    const x = (await api("/api/v1/ha/status")).data;
    const now = Date.now();
    const activeWorkers = (x.workers || []).filter((w) => w.state === "Owned" && new Date(w.expiresAt).getTime() > now);
    const activeTransfers = (x.transfers || []).filter((t) => ["Receiving", "Verifying"].includes(t.state));
    const r = x.recovery || {};
    return `<section aria-labelledby="resilience-summary-title"><div class="detail-head"><div><h2 id="resilience-summary-title">Qualified resilience boundary</h2><p>${esc(x.tier)}. ${esc(x.qualified)} is qualified; multi-site operation is ${esc(x.multiSite)}.</p></div><span class="badge">${(x.instances || []).some((i) => i.live && i.ready) ? "Ready" : "Degraded"}</span></div><div class="stats"><div><strong>${(x.instances || []).filter((i) => i.live && i.ready).length}</strong><span>Ready instances</span></div><div><strong>${activeWorkers.length}</strong><span>Owned worker leases</span></div><div><strong>${activeTransfers.length}</strong><span>Active transfers</span></div><div><strong>${r.inventoriedObjects || 0}</strong><span>Inventoried objects</span></div><div><strong>${r.inventoryMismatches || 0}</strong><span>Object mismatches</span></div></div></section>
      <section aria-labelledby="instances-title"><h2 id="instances-title">Service instances</h2><div class="table-wrap"><table><caption>Heartbeat-backed service instance state</caption><thead><tr><th>Service</th><th>Instance</th><th>Region</th><th>Version</th><th>Live</th><th>Ready</th><th>Last heartbeat</th></tr></thead><tbody>${(x.instances || []).map((i) => `<tr><td>${esc(i.serviceName)}</td><td><code>${esc(i.instanceId)}</code></td><td>${esc(i.region)}</td><td>${esc(i.version)}</td><td>${i.live ? "Yes" : "No"}</td><td>${i.ready ? "Yes" : "No"}</td><td>${new Date(i.heartbeatAt).toLocaleString()}</td></tr>`).join("")}</tbody></table></div></section>
      <section aria-labelledby="leases-title"><h2 id="leases-title">Durable worker ownership</h2><div class="table-wrap"><table><caption>Fencing generation and lease expiry for singleton workers</caption><thead><tr><th>Worker</th><th>Owner</th><th>Generation</th><th>State</th><th>Expires</th></tr></thead><tbody>${(x.workers || []).map((w) => `<tr><td>${esc(w.jobType)}</td><td><code>${esc(w.workerId)}</code></td><td>${w.generation}</td><td>${esc(w.state)}</td><td>${new Date(w.expiresAt).toLocaleString()}</td></tr>`).join("")}</tbody></table></div></section>
      <section aria-labelledby="recovery-title"><h2 id="recovery-title">Backup, recovery, and object integrity</h2><div class="panels"><article><h3>Latest backup</h3><dl><dt>Status</dt><dd>${esc(r.backupState || "Not recorded")}</dd><dt>Completed</dt><dd>${r.backupCompletedAt ? new Date(r.backupCompletedAt).toLocaleString() : "Not available"}</dd><dt>Size</dt><dd>${r.backupSizeBytes == null ? "Not available" : `${r.backupSizeBytes} bytes`}</dd><dt>SHA-256</dt><dd><code>${esc(r.backupSha256 || "Not available")}</code></dd></dl></article><article><h3>Latest restore drill</h3><dl><dt>Status</dt><dd>${esc(r.drillState || "Not recorded")}</dd><dt>RTO</dt><dd>${r.rtoSeconds == null ? "Not available" : `${r.rtoSeconds} seconds`}</dd><dt>Tables / differences</dt><dd>${r.tableCount ?? "Not available"} / ${r.differenceCount ?? "Not available"}</dd><dt>Completed</dt><dd>${r.drillCompletedAt ? new Date(r.drillCompletedAt).toLocaleString() : "Not available"}</dd></dl></article><article><h3>Dependency behavior</h3><dl>${Object.entries(x.dependencies || {}).map(([name, behavior]) => `<dt>${esc(name)}</dt><dd>${esc(behavior)}</dd>`).join("")}</dl></article></div></section>
      <section aria-labelledby="transfer-title"><h2 id="transfer-title">Artifact transfer recovery</h2><div class="table-wrap"><table><caption>Authoritative resumable transfer cursors</caption><thead><tr><th>Transfer</th><th>State</th><th>Progress</th><th>Version</th><th>Updated</th></tr></thead><tbody>${(x.transfers || []).map((t) => `<tr><td><code>${esc(t.transferId)}</code></td><td>${esc(t.state)}</td><td>${t.receivedChunks}/${t.totalChunks} chunks</td><td>${t.version}</td><td>${new Date(t.updatedAt).toLocaleString()}</td></tr>`).join("")}</tbody></table></div></section>`;
  } catch (error) { return state("Resilience status unavailable", error.message); }
}

async function retentionPage() {
  try {
    const [policies, holds, runs, archives, cleanup] = await Promise.all([api("/api/v1/retention/policies"), api("/api/v1/retention/holds"), api("/api/v1/retention/runs"), api("/api/v1/retention/archives"), api("/api/v1/retention/cleanup")]);
    const latest = [...(policies.data || [])].filter((x, i, a) => a.findIndex((y) => y.category === x.category) === i);
    return `<section aria-labelledby="retention-title"><h2 id="retention-title">Versioned retention policies</h2><p class="notice"><strong>Preview is mandatory.</strong> Sprint 29 permits destructive execution only in the isolated qualification-fixture scope. Active incident, forensic, quarantine, legal, replay, export, and investigation references remain held.</p><form id="retention-policy-form" class="admin-grid"><fieldset><legend>Create bounded policy version</legend><label>Category <select name="category">${["raw-telemetry","search-projection","findings","correlated-findings","alerts-incidents","response-audit","live-response-transcripts","forensic-evidence","quarantine-artifacts","threat-intelligence","update-artifacts","audit-records","temporary-data"].map((x)=>`<option>${x}</option>`).join("")}</select></label><label>Authority days <input type="number" name="authorityDays" min="1" max="36500" value="30" required></label><label>Search projection days <input type="number" name="projectionDays" min="1" max="36500" value="14" required></label><label>Batch size <input type="number" name="batchSize" min="1" max="5000" value="500" required></label><label><input type="checkbox" name="archive" checked> Archive manifest before deletion</label><button type="submit">Create immutable version</button><p role="status" id="retention-policy-status" tabindex="-1"></p></fieldset></form><div class="table-wrap"><table><caption>Latest tenant retention policy per evidence class</caption><thead><tr><th>Category</th><th>Authority/search</th><th>Batch</th><th>Archive</th><th>Version/hash</th><th>Safe action</th></tr></thead><tbody>${latest.map((x)=>`<tr><td>${esc(x.category)}</td><td>${x.authorityDays}/${x.projectionDays} days</td><td>${x.batchSize}</td><td>${x.archiveBeforeDelete?"Required":"No"}</td><td>v${x.version}<code>${esc(x.policyHash)}</code></td><td><button class="retention-preview" data-policy="${x.policyId}">Preview qualification fixture</button></td></tr>`).join("")}</tbody></table></div><div id="retention-preview-result" tabindex="-1" aria-live="polite"></div></section>
      <section aria-labelledby="holds-title"><h2 id="holds-title">Held evidence</h2><div class="table-wrap"><table><caption>Active and historical retention holds</caption><thead><tr><th>Created</th><th>Type/category</th><th>Target</th><th>Reason</th><th>Status/expiry</th></tr></thead><tbody>${(holds.data||[]).map((x)=>`<tr><td>${new Date(x.createdAt).toLocaleString()}</td><td>${esc(x.holdType)} / ${esc(x.category)}</td><td><code>${esc(x.targetId||"Entire category")}</code></td><td>${esc(x.reason)}</td><td>${x.active?"Active":"Released"} / ${x.expiresAt?new Date(x.expiresAt).toLocaleString():"No automatic expiry"}</td></tr>`).join("")}</tbody></table></div></section>
      <section aria-labelledby="cleanup-title"><h2 id="cleanup-title">Cleanup and archive history</h2><div class="panels"><article><h3>Retention runs</h3><p>${(runs.data||[]).length} auditable runs; ${(runs.data||[]).reduce((n,x)=>n+x.deletedRows,0)} rows deleted; ${(runs.data||[]).reduce((n,x)=>n+x.heldRows,0)} held.</p></article><article><h3>Archives</h3><p>${(archives.data||[]).length} manifest-backed archives. Archive manifests record scope, range, schema, count and hash.</p></article><article><h3>Cleanup</h3><p>${(cleanup.data||[]).length} bounded cleanup records; ${(cleanup.data||[]).filter(x=>x.state==="Failed").length} failures.</p></article></div><div class="table-wrap"><table><caption>Bounded retention and cleanup execution history</caption><thead><tr><th>Time</th><th>State</th><th>Dry run</th><th>Deleted/archived/held</th><th>Actor</th><th>Detail</th></tr></thead><tbody>${(runs.data||[]).map((x)=>`<tr><td>${new Date(x.startedAt).toLocaleString()}</td><td>${esc(x.state)}</td><td>${x.dryRun?"Yes":"No"}</td><td>${x.deletedRows}/${x.archivedRows}/${x.heldRows}</td><td>${esc(x.actor)}</td><td>${esc(x.detail)}</td></tr>`).join("")}</tbody></table></div></section>`;
  } catch (error) { return state("Retention status unavailable", error.message); }
}

async function capacityPage() {
  try {
    const [storage, samples, quota] = await Promise.all([api("/api/v1/capacity/storage"), api("/api/v1/capacity/samples"), api("/api/v1/capacity/quota")]); const latest=(samples.data||[])[0];
    return `<section aria-labelledby="capacity-title"><div class="detail-head"><div><h2 id="capacity-title">Measured capacity context</h2><p>Every result distinguishes simulated endpoint identities from native running agents. Forecasts are estimates tied to the selected measured profile and are not physical endpoint-scale claims.</p></div><span class="badge">${latest?esc(latest.profile):"No measured profile"}</span></div>${latest?`<div class="stats"><div><strong>${Number(latest.eventsPerSecond).toFixed(2)}</strong><span>Measured events/sec</span></div><div><strong>${latest.simulatedEndpoints}</strong><span>Simulated identities</span></div><div><strong>${latest.nativeAgents}</strong><span>Native agents</span></div><div><strong>${latest.unexplainedLoss}</strong><span>Unexplained loss</span></div></div><div class="table-wrap"><table><caption>Latest measured latency, queue, and storage indicators</caption><thead><tr><th>Duration</th><th>Generated/accepted/rejected</th><th>PostgreSQL</th><th>OpenSearch</th><th>MinIO</th><th>NATS</th></tr></thead><tbody><tr><td>${latest.durationSeconds}s</td><td>${latest.generatedEvents}/${latest.acceptedEvents}/${latest.rejectedEvents}</td><td>${latest.postgreSqlBytes} bytes</td><td>${latest.openSearchBytes} bytes</td><td>${latest.minioBytes} bytes</td><td>${latest.natsBytes} bytes</td></tr></tbody></table></div>`:state("No capacity samples","Run a bounded, versioned Sprint 29 profile before using forecasts.")}</section>
      <section aria-labelledby="storage-title"><h2 id="storage-title">Tenant storage accounting</h2><div class="table-wrap"><table><caption>PostgreSQL authoritative bytes and record counts by domain</caption><thead><tr><th>Domain</th><th>Records</th><th>PostgreSQL bytes</th><th>Bytes/record</th></tr></thead><tbody>${(storage.data||[]).map((x)=>`<tr><td>${esc(x.domain)}</td><td>${x.records}</td><td>${x.postgreSqlBytes}</td><td>${x.records?Math.round(x.postgreSqlBytes/x.records):"Not applicable"}</td></tr>`).join("")}</tbody></table></div></section>
      <section aria-labelledby="quota-title"><h2 id="quota-title">Tenant fairness policy</h2><dl><dt>Ingest/search per minute</dt><dd>${quota.data.ingestPerMinute}/${quota.data.searchPerMinute}</dd><dt>Replay/export</dt><dd>${quota.data.replayPerMinute}/${quota.data.exportPerMinute}</dd><dt>Forensic/playbook/update</dt><dd>${quota.data.forensicPerMinute}/${quota.data.playbookPerMinute}/${quota.data.updatePerMinute}</dd><dt>Concurrent forensic/playbooks</dt><dd>${quota.data.maxConcurrentForensic}/${quota.data.maxConcurrentPlaybooks}</dd><dt>Policy version</dt><dd>${quota.data.version}<code>${esc(quota.data.policyHash)}</code></dd></dl></section>
      <section aria-labelledby="planner-title"><h2 id="planner-title">Measured-input capacity planner</h2><form id="capacity-planner" class="admin-grid"><fieldset><legend>Bounded estimate inputs</legend><label>Endpoint identities <input name="endpoints" type="number" min="1" max="10000000" value="100" required></label><label>Events per endpoint/day <input name="events" type="number" min="1" max="10000000" value="1000" required></label><label>Retention days <input name="days" type="number" min="1" max="3650" value="30" required></label><label>Measured PostgreSQL bytes/event <input name="pg" type="number" min="0.01" step="0.01" value="512" required></label><label>Measured OpenSearch bytes/event <input name="os" type="number" min="0" step="0.01" value="256" required></label><label>Forensic bytes/endpoint/day <input name="minio" type="number" min="0" value="1048576" required></label><label>Redundancy factor <input name="redundancy" type="number" min="1" max="10" step="0.1" value="1" required></label><label>Required margin percent <input name="margin" type="number" min="0" max="500" value="30" required></label><button type="submit">Calculate estimate</button></fieldset></form><div id="capacity-estimate" role="status" aria-live="polite" tabindex="-1"></div></section>`;
  } catch(error){return state("Capacity status unavailable",error.message);}
}

async function saveRetentionPolicy(event){event.preventDefault();const form=new FormData(event.currentTarget),status=document.querySelector("#retention-policy-status");try{await api("/api/v1/retention/policies",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({category:form.get("category"),authorityDays:Number(form.get("authorityDays")),projectionDays:Number(form.get("projectionDays")),batchSize:Number(form.get("batchSize")),archiveBeforeDelete:form.get("archive")==="on",enabled:true})});status.textContent="Immutable retention policy version created.";status.focus();await route();}catch(error){status.textContent=error.message;status.focus();}}
async function previewRetention(button){const target=document.querySelector("#retention-preview-result");try{const x=(await api("/api/v1/retention/previews",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({policyId:button.dataset.policy,scope:"qualification-fixture"})})).data;target.innerHTML=`<article><h3>Exact cleanup preview</h3><dl><dt>Eligible rows</dt><dd>${x.eligibleRows}</dd><dt>Estimated bytes</dt><dd>${x.estimatedBytes}</dd><dt>Held rows</dt><dd>${x.heldRows}</dd><dt>Cutoff</dt><dd>${new Date(x.cutoff).toLocaleString()}</dd><dt>Expires</dt><dd>${new Date(x.expiresAt).toLocaleString()}</dd><dt>Exact preview hash</dt><dd><code>${esc(x.previewHash)}</code></dd></dl><button class="retention-apply" data-preview="${x.previewId}" data-hash="${x.previewHash}">Apply bounded qualification-fixture cleanup</button><p class="notice">This cannot target production telemetry in Sprint 29.</p></article>`;target.focus();document.querySelector(".retention-apply")?.addEventListener("click",executeRetention);}catch(error){target.textContent=error.message;target.focus();}}
async function executeRetention(event){if(!window.confirm("Apply this exact preview only to the isolated qualification fixture?"))return;const target=document.querySelector("#retention-preview-result");try{const x=(await api("/api/v1/retention/runs",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({previewId:event.currentTarget.dataset.preview,previewHash:event.currentTarget.dataset.hash,dryRun:false})})).data;target.innerHTML=`<p role="status"><strong>${esc(x.state)}</strong>: ${x.deletedRows} deleted, ${x.archivedRows} archived, ${x.heldRows} held.</p>`;target.focus();}catch(error){target.textContent=error.message;target.focus();}}
async function calculateCapacity(event){event.preventDefault();const f=new FormData(event.currentTarget),target=document.querySelector("#capacity-estimate");try{const x=(await api("/api/v1/capacity/estimate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({endpointCount:Number(f.get("endpoints")),eventsPerEndpointDay:Number(f.get("events")),retentionDays:Number(f.get("days")),postgreSqlBytesPerEvent:Number(f.get("pg")),openSearchBytesPerEvent:Number(f.get("os")),forensicBytesPerEndpointDay:Number(f.get("minio")),redundancyFactor:Number(f.get("redundancy")),requiredMarginPercent:Number(f.get("margin"))})})).data;target.innerHTML=`<div class="table-wrap"><table><caption>Measured-input storage estimate with configured redundancy and margin</caption><thead><tr><th>Daily events</th><th>Daily ingest bytes</th><th>PostgreSQL</th><th>OpenSearch</th><th>MinIO</th><th>Total with margin</th></tr></thead><tbody><tr><td>${x.dailyEvents}</td><td>${x.dailyIngestBytes}</td><td>${x.postgreSqlBytes}</td><td>${x.openSearchBytes}</td><td>${x.minioBytes}</td><td>${x.totalWithMarginBytes}</td></tr></tbody></table></div><p>${esc(x.basis)}</p>`;target.focus();}catch(error){target.textContent=error.message;target.focus();}}

function aiClaim(claim, packageId) {
  const citations=(claim.citations||[]).map((id)=>`<button type="button" class="ai-citation" data-package="${esc(packageId)}" data-citation="${esc(id)}">[${esc(id)}]</button>`).join(" ");
  return `<li><div class="detail-head"><strong>${esc(claim.kind)}</strong><span class="badge">${esc(claim.confidence)}</span></div><p>${esc(claim.text)}</p><p>${citations||"No citation: explicitly unknown"}</p><small>${esc(claim.confidenceBasis)}</small></li>`;
}
async function aiInvestigationPage(conversationId) {
  try {
    const health=(await api("/api/v1/ai/health")).data;
    if (!conversationId) {
      const conversations=(await api("/api/v1/ai/conversations?limit=100")).data||[];
      return `<section aria-labelledby="ai-safety-title"><div class="detail-head"><div><h2 id="ai-safety-title">Evidence-grounded, advisory-only assistant</h2><p>Structured platform evidence is data, never an instruction. Every material claim requires a resolvable citation. The assistant cannot run commands, change detections, execute playbooks, or invoke response.</p></div><span class="badge">${esc(health.policy.dataMode)}</span></div><div class="panels"><article><h3>Provider boundary</h3><p>${esc(health.policy.providerId)} · policy v${health.policy.version}</p><p>${health.externalTransmissionDefault?"External transmission configured":"No external transmission by default"}</p></article><article><h3>Hard evidence bounds</h3><p>${health.policy.maximumEvidenceItems} items · ${health.policy.maximumEvidenceBytes} bytes · ${health.policy.maximumOutputCharacters} output characters</p></article><article><h3>Privacy</h3><p>Personal data redaction: ${health.policy.redactPersonalData?"on":"off"}<br>Secret redaction: ${health.policy.redactSecrets?"on":"off"}</p></article></div></section><section aria-labelledby="ai-new-title"><h2 id="ai-new-title">Start contextual investigation</h2><form id="ai-conversation-form" class="admin-grid"><fieldset><legend>Authoritative context</legend><label>Context type <select name="contextType">${["incident","alert","process","entity","detection","correlation","ioc","tunnel","forensic"].map((x)=>`<option>${x}</option>`).join("")}</select></label><label>Exact context identity <input name="contextId" required maxlength="512" autocomplete="off"></label><label>Conversation title <input name="title" required maxlength="200"></label><button type="submit">Create read-only investigation</button><p id="ai-action-status" role="status" aria-live="assertive" tabindex="-1"></p></fieldset></form></section><section aria-labelledby="ai-history-title"><h2 id="ai-history-title">Durable conversation history</h2>${conversations.length?`<div class="table-wrap"><table><caption>Tenant-scoped AI investigations</caption><thead><tr><th>Updated</th><th>Context</th><th>Title</th><th>Version</th></tr></thead><tbody>${conversations.map((x)=>`<tr><td>${new Date(x.updatedAt).toLocaleString()}</td><td>${esc(x.contextType)}<br><code>${esc(x.contextId)}</code></td><td><a href="#/ai-investigation/${esc(x.conversationId)}">${esc(x.title)}</a></td><td>${x.version}</td></tr>`).join("")}</tbody></table></div>`:state("No AI investigations","Create one from an exact authorized context.")}</section>`;
    }
    const result=(await api(`/api/v1/ai/conversations/${encodeURIComponent(conversationId)}`)).data,c=result.conversation,messages=result.messages||[];
    return `<a href="#/ai-investigation">← AI investigation history</a><section aria-labelledby="ai-conversation-title"><div class="detail-head"><div><h2 id="ai-conversation-title">${esc(c.title)}</h2><p>${esc(c.contextType)} · <code>${esc(c.contextId)}</code></p></div><span class="badge">Read only</span></div><ol class="timeline" aria-label="AI conversation">${messages.map((m)=>`<li><time>${new Date(m.createdAt).toLocaleString()}</time> <strong>${esc(m.role)}</strong>${m.role==="Assistant"&&m.claims?.length?`<ol>${m.claims.map((x)=>aiClaim(x,m.evidencePackageId)).join("")}</ol><button type="button" class="ai-note-draft" data-message="${esc(m.messageId)}">Draft analyst note</button>`:`<p>${esc(m.content)}</p>`}</li>`).join("")}</ol><form id="ai-analysis-form" class="admin-grid"><fieldset><legend>Ask about included authoritative evidence</legend><label for="ai-question">Question</label><textarea id="ai-question" name="question" required maxlength="4000" rows="5"></textarea><p class="muted">Evidence may be incomplete. Suggested pivots are advisory and never execute automatically.</p><button type="submit">Analyze bounded evidence</button><p id="ai-action-status" role="status" aria-live="assertive" tabindex="-1"></p></fieldset></form><section aria-labelledby="citation-detail-title"><h2 id="citation-detail-title">Resolved citation</h2><div id="ai-citation-detail" tabindex="-1" aria-live="polite">Select a citation to inspect its exact source and provenance.</div></section></section>`;
  } catch(error) { return state("AI investigation unavailable", error.message); }
}
async function createAiConversation(event){event.preventDefault();const f=new FormData(event.currentTarget),status=document.querySelector("#ai-action-status");try{const x=(await api("/api/v1/ai/conversations",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({contextType:f.get("contextType"),contextId:f.get("contextId"),title:f.get("title")})})).data;location.hash=`#/ai-investigation/${x.conversationId}`;}catch(error){status.textContent=error.message;status.focus();}}
async function analyzeAi(event,conversationId){event.preventDefault();const f=new FormData(event.currentTarget),status=document.querySelector("#ai-action-status");status.textContent="Building bounded evidence package and validating citations…";try{await api(`/api/v1/ai/conversations/${encodeURIComponent(conversationId)}/analyze`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({question:f.get("question"),clientRequestId:crypto.randomUUID()})});await route();}catch(error){status.textContent=error.message;status.focus();}}
async function resolveAiCitation(button){const target=document.querySelector("#ai-citation-detail");try{const x=(await api(`/api/v1/ai/evidence/${encodeURIComponent(button.dataset.package)}/citations/${encodeURIComponent(button.dataset.citation)}`)).data;target.innerHTML=`<dl><dt>Citation</dt><dd><strong>${esc(x.citationId)}</strong></dd><dt>Source</dt><dd>${esc(x.source)}</dd><dt>Observed</dt><dd>${new Date(x.observedAt).toLocaleString()}</dd><dt>Provenance</dt><dd>${esc(x.provenance)}</dd><dt>Exact source reference</dt><dd><code>${esc(x.sourceReference)}</code></dd><dt>Ambiguous</dt><dd>${x.ambiguous?"Yes":"No"}</dd><dt>Fields</dt><dd><pre>${esc(JSON.stringify(x.fields,null,2))}</pre></dd></dl>`;target.focus();}catch(error){target.textContent=error.message;target.focus();}}
async function draftAiNote(button,conversationId){const status=document.querySelector("#ai-action-status");try{const x=(await api(`/api/v1/ai/conversations/${encodeURIComponent(conversationId)}/note-drafts`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({assistantMessageId:button.dataset.message})})).data;status.textContent=`Draft ${x.draftId} created. It has not changed the alert or incident; explicit acceptance is required.`;const accept=document.createElement("button");accept.type="button";accept.textContent="Accept as immutable analyst note";accept.addEventListener("click",()=>acceptAiNote(x.draftId));status.after(accept);status.focus();}catch(error){status.textContent=error.message;status.focus();}}
async function acceptAiNote(draftId){const status=document.querySelector("#ai-action-status");try{const x=(await api(`/api/v1/ai/note-drafts/${encodeURIComponent(draftId)}/accept`,{method:"POST"})).data;status.textContent=`Accepted as immutable analyst note ${x.acceptedNoteId}.`;status.nextElementSibling?.remove();status.focus();}catch(error){status.textContent=error.message;status.focus();}}
function coverageLabel(x){return `<span class="badge">${esc(x)}</span>`;}
async function aiEngineeringPage(id){
  try{
    if(id){const x=(await api(`/api/v1/ai-engineering/drafts/${encodeURIComponent(id)}`)).data,r=x.detection||x.correlation;return `<a href="#/detection-engineering">← Detection engineering workspace</a><section aria-labelledby="ai-draft-title"><div class="detail-head"><div><h2 id="ai-draft-title">${esc(r?.name||"AI rule draft")}</h2><p><span class="badge">AI proposed</span> ${esc(x.kind)} · ${esc(x.providerId)} / ${esc(x.modelId)}</p></div>${coverageLabel(x.state)}</div><p>${esc(r?.description||"")}</p><dl><dt>Draft hash</dt><dd><code>${esc(x.draftHash)}</code></dd><dt>ATT&amp;CK</dt><dd>${esc((r?.mitreTechniques||[r?.mitreTechnique]).filter(Boolean).join(", "))}</dd><dt>Required telemetry</dt><dd>${esc(x.requiredTelemetry.join(", "))}</dd><dt>Known gaps</dt><dd>${esc(x.knownGaps.join(" "))}</dd></dl><h3>Deterministic review</h3><p>${esc(x.review.explanation)}</p><ul>${[...x.review.risks,...x.review.unsupportedFields,...x.review.unsafeIdentityAssumptions,...x.review.recommendations].map(v=>`<li>${esc(v)}</li>`).join("")}</ul><div class="table-wrap"><table><caption>Component quality scorecard; no opaque aggregate score</caption><tbody>${Object.entries(x.scorecard).filter(([,v])=>typeof v==="number").map(([k,v])=>`<tr><th>${esc(k)}</th><td>${v}</td></tr>`).join("")}</tbody></table></div><div class="table-wrap"><table><caption>AI-proposed canonical fixture matrix</caption><thead><tr><th>Case</th><th>Kind</th><th>Expected validity</th><th>Expected result</th></tr></thead><tbody>${x.fixtures.map(f=>`<tr><td>${esc(f.name)}</td><td>${esc(f.kind)}</td><td>${f.expectedValid?"Valid":"Rejected by schema"}</td><td>${esc(f.expectedOutcome)}</td></tr>`).join("")}</tbody></table></div>${x.state==="Validated"?`<div class="toolbar"><button type="button" class="ai-draft-save" data-id="${esc(x.draftId)}" data-hash="${esc(x.draftHash)}">Save as inactive repository draft</button><button type="button" class="ai-draft-reject" data-id="${esc(x.draftId)}" data-hash="${esc(x.draftHash)}">Reject proposal</button></div>`:""}<form id="ai-simulation-form" class="admin-grid" data-id="${esc(x.draftId)}" data-hash="${esc(x.draftHash)}"><fieldset><legend>Bounded historical simulation</legend><label>From <input name="from" type="datetime-local" required></label><label>To <input name="to" type="datetime-local" required></label><label>Maximum events <input name="maximum" type="number" min="1" max="10000" value="1000" required></label><button type="submit">Preview historical matches</button></fieldset></form><p id="ai-engineering-status" role="status" aria-live="assertive" tabindex="-1"></p><div id="ai-simulation-result" tabindex="-1"></div></section>`;}
    const [inventory,coverage,hunts,drafts]=await Promise.all([api("/api/v1/ai-engineering/inventory"),api("/api/v1/ai-engineering/coverage"),api("/api/v1/ai-engineering/hunts"),api("/api/v1/ai-engineering/drafts")]);return `<section aria-labelledby="ai-engineering-safety"><div class="detail-head"><div><h2 id="ai-engineering-safety">Bounded AI engineering workspace</h2><p>Natural language creates previews in existing DSLs. AI cannot execute raw SQL/search, activate rules, create exclusions, start response, or change production content.</p></div><span class="badge">Human approval required</span></div></section><section aria-labelledby="ai-hunt-builder"><h2 id="ai-hunt-builder">AI hunt builder</h2><form id="ai-hunt-form" class="admin-grid"><fieldset><legend>Natural-language intent</legend><label>Hunt intent <textarea name="prompt" maxlength="4000" required rows="3" placeholder="Find exact path 'C:\\Approved\\sample.exe'"></textarea></label><button type="submit">Create bounded preview</button></fieldset></form><div id="ai-hunt-preview" tabindex="-1"></div></section><section aria-labelledby="ai-rule-builder"><h2 id="ai-rule-builder">Detection draft builder</h2><form id="ai-detection-draft-form" class="admin-grid"><fieldset><legend>Existing detection DSL only</legend><label>Intent <input name="prompt" maxlength="4000" required></label><label>Domain <select name="domain">${["Process","File","Registry","Network","Dns","Module","Persistence","Identity","Execution"].map(v=>`<option>${v}</option>`).join("")}</select></label><label>Field <input name="field" value="path" maxlength="100" required></label><label>Operator <select name="operator">${["Equal","Contains","StartsWith","EndsWith","ExactPath","Exists"].map(v=>`<option>${v}</option>`).join("")}</select></label><label>Value <input name="value" maxlength="4096" required></label><label>ATT&amp;CK technique <input name="mitre" pattern="T[0-9]{4}(\\.[0-9]{3})?" value="T1059.001" required></label><button type="submit">Compile inactive AI draft</button></fieldset></form><form id="ai-correlation-draft-form" class="admin-grid"><fieldset><legend>Bounded correlation concept</legend><label>Intent <input name="prompt" maxlength="4000" required></label><label>Type <select name="type"><option>OrderedSequence</option><option>UnorderedSet</option><option>CrossDomain</option><option>ParentChild</option><option>NegativeSequence</option></select></label><label>First domain <select name="firstDomain"><option>Process</option><option>Persistence</option><option>Identity</option></select></label><label>Second domain <select name="secondDomain"><option>Network</option><option>Dns</option><option>File</option></select></label><label>Identity-safe join <select name="joinKey"><option>processEntityId</option><option>endpointId</option><option>entityId</option><option>user</option></select></label><label>ATT&amp;CK technique <input name="mitre" value="T1071.004" required></label><button type="submit">Compile inactive correlation draft</button></fieldset></form><p id="ai-engineering-status" role="status" aria-live="assertive" tabindex="-1"></p></section><section aria-labelledby="ai-drafts-title"><h2 id="ai-drafts-title">AI-proposed content</h2>${drafts.data.length?`<div class="table-wrap"><table><caption>Drafts remain inactive until explicit review</caption><thead><tr><th>Created</th><th>Kind</th><th>Rule</th><th>State</th><th>Provider</th></tr></thead><tbody>${drafts.data.map(x=>`<tr><td>${new Date(x.createdAt).toLocaleString()}</td><td>${esc(x.kind)}</td><td><a href="#/detection-engineering/${esc(x.draftId)}">${esc(x.detection?.name||x.correlation?.name)}</a></td><td>${coverageLabel(x.state)}</td><td>${esc(x.providerId)} / ${esc(x.modelId)}</td></tr>`).join("")}</tbody></table></div>`:state("No AI drafts","Create a bounded draft above.")}</section><section aria-labelledby="coverage-title"><h2 id="coverage-title">Evidence-based ATT&amp;CK coverage</h2><div class="table-wrap"><table><caption>Coverage uses telemetry, active validation and fixtures—not rule names</caption><thead><tr><th>Tactic</th><th>Technique</th><th>Support</th><th>Telemetry</th><th>Rules</th><th>Fixtures</th><th>Limitations</th></tr></thead><tbody>${coverage.data.map(x=>`<tr><td>${esc(x.tactic)}</td><td>${esc(x.technique)}${x.subTechnique?`.`+esc(x.subTechnique):""}</td><td>${coverageLabel(x.supportLevel)}</td><td>${esc(x.telemetrySources.join(", "))}</td><td>${x.ruleIds.length+x.correlationIds.length}</td><td>${x.evidenceFixtures.length}</td><td>${esc(x.knownLimitations.join(" ")||"None recorded")}</td></tr>`).join("")}</tbody></table></div></section><section aria-labelledby="inventory-title"><h2 id="inventory-title">Detection content inventory</h2><p>${inventory.data.detections.length} detection versions · ${inventory.data.correlations.length} correlation versions · ${hunts.data.length} AI hunt proposals.</p></section>`;
  }catch(error){return state("AI detection engineering unavailable",error.message);}
}
async function createAiHunt(event){event.preventDefault();const f=new FormData(event.currentTarget),status=document.querySelector("#ai-engineering-status"),preview=document.querySelector("#ai-hunt-preview");try{const x=(await api("/api/v1/ai-engineering/hunts",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({prompt:f.get("prompt"),evidenceCitations:[],evidencePackageHash:"analyst-unscoped"})})).data;preview.innerHTML=`<article><h3>Mandatory preview</h3><p><strong>${esc(x.normalizedIntent)}</strong> · estimated cost ${x.estimatedCost} · maximum ${x.hunt.maximumResults} results</p><ul>${x.explanation.map(v=>`<li>${esc(v)}</li>`).join("")}</ul><p><strong>May miss:</strong> ${esc(x.mayMiss.join(" "))}</p><button type="button" class="ai-hunt-execute" data-id="${esc(x.proposalId)}" data-hash="${esc(x.proposalHash)}">Execute reviewed bounded hunt</button></article>`;preview.focus();preview.querySelector("button").addEventListener("click",executeAiHunt);}catch(error){status.textContent=error.message;status.focus();}}
async function executeAiHunt(event){const b=event.currentTarget,status=document.querySelector("#ai-engineering-status");try{const x=(await api(`/api/v1/ai-engineering/hunts/${encodeURIComponent(b.dataset.id)}/execute`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({proposalHash:b.dataset.hash,reason:"Analyst reviewed bounded preview"})})).data;status.textContent=`Hunt executed after approval: ${x.run.returned} results, run ${x.run.runId}.`;status.focus();b.disabled=true;}catch(error){status.textContent=error.message;status.focus();}}
async function createAiRuleDraft(event,correlation=false){event.preventDefault();const f=new FormData(event.currentTarget),status=document.querySelector("#ai-engineering-status");try{const body=correlation?{prompt:f.get("prompt"),type:f.get("type"),firstDomain:f.get("firstDomain"),secondDomain:f.get("secondDomain"),joinKey:f.get("joinKey"),mitreTechnique:f.get("mitre")}:{prompt:f.get("prompt"),domain:f.get("domain"),field:f.get("field"),operator:f.get("operator"),value:f.get("value"),mitreTechnique:f.get("mitre")};const x=(await api(`/api/v1/ai-engineering/${correlation?"correlation":"detection"}-drafts`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})).data;location.hash=`#/detection-engineering/${x.draftId}`;}catch(error){status.textContent=error.message;status.focus();}}
async function decideAiDraft(button,decision){const status=document.querySelector("#ai-engineering-status");try{await api(`/api/v1/ai-engineering/drafts/${encodeURIComponent(button.dataset.id)}/${decision}`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({proposalHash:button.dataset.hash,reason:`Detection engineer explicitly ${decision==="save"?"accepted inactive draft":"rejected proposal"}`})});await route();}catch(error){status.textContent=error.message;status.focus();}}
async function simulateAiDraft(event){event.preventDefault();const form=event.currentTarget,f=new FormData(form),target=document.querySelector("#ai-simulation-result"),status=document.querySelector("#ai-engineering-status");try{const x=(await api(`/api/v1/ai-engineering/drafts/${encodeURIComponent(form.dataset.id)}/simulate`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({draftHash:form.dataset.hash,from:new Date(f.get("from")).toISOString(),to:new Date(f.get("to")).toISOString(),maximumEvents:Number(f.get("maximum"))})})).data;target.innerHTML=`<h3>Measured simulation</h3><p>${x.eventsScanned} events scanned; ${x.matches} matches across ${x.endpointCount} endpoints; ${x.runtimeMilliseconds} ms. No production findings or activation occurred.</p><button type="button" id="ai-tuning-request">Generate advisory tuning recommendation</button><div id="ai-tuning-result" tabindex="-1"></div>`;target.focus();document.querySelector("#ai-tuning-request").addEventListener("click",()=>tuneAiDraft(form,x));}catch(error){status.textContent=error.message;status.focus();}}
async function tuneAiDraft(form,simulation){const target=document.querySelector("#ai-tuning-result"),status=document.querySelector("#ai-engineering-status");try{const x=(await api(`/api/v1/ai-engineering/drafts/${encodeURIComponent(form.dataset.id)}/tuning`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({draftHash:form.dataset.hash,simulationId:simulation.simulationId})})).data;target.innerHTML=`<h3>${esc(x.label)} tuning</h3><p>${esc(x.why)}</p><p><strong>Expected impact:</strong> ${esc(x.expectedImpact)}</p><p><strong>Risks:</strong> ${esc(x.risks.join(" "))}</p><p>No mutation applied: ${x.mutationApplied?"No":"Yes"}.</p>`;target.focus();}catch(error){status.textContent=error.message;status.focus();}}
async function compareAiDraft(event){event.preventDefault();const form=event.currentTarget,f=new FormData(form),target=document.querySelector("#ai-comparison-result"),status=document.querySelector("#ai-engineering-status");try{const x=(await api(`/api/v1/ai-engineering/drafts/${encodeURIComponent(form.dataset.id)}/compare`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({draftHash:form.dataset.hash,currentRuleId:f.get("ruleId"),currentVersion:Number(f.get("version")),from:new Date(f.get("from")).toISOString(),to:new Date(f.get("to")).toISOString(),maximumEvents:Number(f.get("maximum"))})})).data;target.innerHTML=`<h3>Measured version comparison</h3><p>${x.newMatches} new, ${x.lostMatches} lost, ${x.unchangedMatches} unchanged; alert-volume delta ${x.alertVolumeDelta}; endpoint impact ${x.endpointImpact}; tenant impact ${x.tenantImpact}; severity impact ${x.severityImpact}.</p>`;target.focus();}catch(error){status.textContent=error.message;status.focus();}}
async function explainAiRule(button){const target=document.querySelector("#ai-rule-explanation"),status=document.querySelector("#ai-engineering-status");try{const x=(await api(`/api/v1/ai-engineering/detection-rules/${encodeURIComponent(button.dataset.id)}/explain?version=${encodeURIComponent(button.dataset.version)}`)).data;target.innerHTML=`<h3>AI explanation grounded in rule authority</h3><p>${esc(x.explanation.purpose)}</p><p><strong>Telemetry:</strong> ${esc(x.explanation.telemetryDependencies.join(", "))}</p><p><strong>Limitations:</strong> ${esc(x.explanation.limitations.join(" "))}</p><p><strong>Review:</strong> ${esc(x.review.explanation)}</p>`;target.focus();}catch(error){status.textContent=error.message;status.focus();}}
async function installAiComparison(id){const simulation=document.querySelector("#ai-simulation-form");if(!simulation)return;const draft=(await api(`/api/v1/ai-engineering/drafts/${encodeURIComponent(id)}`)).data;if(!draft.detection)return;const host=document.createElement("section");host.setAttribute("aria-labelledby","ai-comparison-title");host.innerHTML=`<h2 id="ai-comparison-title">Rule version comparison</h2><form id="ai-comparison-form" class="admin-grid" data-id="${esc(draft.draftId)}" data-hash="${esc(draft.draftHash)}"><fieldset><legend>Bounded current-versus-proposed simulation</legend><label>Current rule ID <input name="ruleId" required></label><label>Current version <input name="version" type="number" min="1" required></label><label>From <input name="from" type="datetime-local" required></label><label>To <input name="to" type="datetime-local" required></label><label>Maximum events <input name="maximum" type="number" min="1" max="10000" value="1000" required></label><button type="submit">Run bounded comparison</button></fieldset></form><div id="ai-comparison-result" tabindex="-1" aria-live="polite"></div>`;simulation.after(host);host.querySelector("form").addEventListener("submit",compareAiDraft);}
async function installAiInventory(){const heading=document.querySelector("#inventory-title");if(!heading)return;const inventory=(await api("/api/v1/ai-engineering/inventory")).data,host=document.createElement("div");host.className="table-wrap";host.innerHTML=`<table><caption>Tenant-scoped searchable rule inventory and AI explanations</caption><thead><tr><th>Rule</th><th>Version</th><th>Domain</th><th>State</th><th>Severity</th><th>Quality</th><th>Action</th></tr></thead><tbody>${inventory.detections.map(x=>`<tr><td>${esc(x.name)}</td><td>${x.detectionVersion}</td><td>${esc(x.domain)}</td><td>${esc(x.status)} / ${x.enabled?"Enabled":"Disabled"}</td><td>${x.severity}</td><td>${x.lastValidationPassed?"Validated":"Not validated"}</td><td><button type="button" class="ai-rule-explain" data-id="${esc(x.detectionId)}" data-version="${x.detectionVersion}">Explain with AI</button></td></tr>`).join("")}</tbody></table><div id="ai-rule-explanation" tabindex="-1" aria-live="polite"></div>`;heading.parentElement.append(host);host.querySelectorAll(".ai-rule-explain").forEach(button=>button.addEventListener("click",()=>explainAiRule(button)));}
async function updatePackagesPage(packageId) {
  try {
    const value=await api(packageId ? `/api/v1/agent-update/packages/${encodeURIComponent(packageId)}` : "/api/v1/agent-update/packages"), items=packageId?[value.data]:value.data;
    return `<section aria-labelledby="packages-title"><h2 id="packages-title">Signed agent update packages</h2><p>Only controlled-storage objects with an exact signed manifest, trusted chain, SHA-256, platform, architecture, expiry, and package identity can be assigned.</p>${items.length?`<div class="table-wrap"><table><caption>Registered immutable update and rollback packages</caption><thead><tr><th>Version</th><th>Package identity</th><th>Platform</th><th>Signer</th><th>SHA-256</th><th>Expiry</th><th>State</th><th>Release notes</th></tr></thead><tbody>${items.map(x=>`<tr><td>${esc(x.manifest.targetVersion)}</td><td><a href="#/agent-update-packages/${esc(x.manifest.packageId)}"><code>${esc(x.manifest.packageId)}</code></a><br>${esc(x.manifest.packageType)}</td><td>${esc(x.manifest.platform)} / ${esc(x.manifest.architecture)}</td><td><code>${esc(x.signingCertificateIdentity)}</code><br>${esc(x.signatureAlgorithm)}</td><td><code>${esc(x.manifest.packageSha256)}</code></td><td>${new Date(x.manifest.expiresAt).toLocaleString()}</td><td><span class="badge">${x.revoked?"Revoked":"Available"}</span></td><td>${esc(x.manifest.releaseNotes)}</td></tr>`).join("")}</tbody></table></div>`:state("No update packages", "Register a repository-built signed package in controlled storage.")}</section>`;
  } catch(error){return state("Packages unavailable",error.message);}
}
async function updateRolloutsPage(rolloutId) {
  try {
    if(rolloutId){const value=(await api(`/api/v1/agent-update/rollouts/${encodeURIComponent(rolloutId)}`)).data,x=value.rollout,a=value.assignments||[],done=x.succeeded+x.failed+x.rolledBack+x.skipped,pct=x.totalEndpoints?Math.round(done*100/x.totalEndpoints):0;return `<section aria-labelledby="rollout-title"><h2 id="rollout-title">Rollout ${esc(x.targetVersion)}</h2><p><strong>State:</strong> <span class="badge">${esc(x.state)}</span> · <strong>Current ring:</strong> ${esc(x.currentRing)}</p><label for="rollout-progress">Endpoint progress</label><progress id="rollout-progress" max="${x.totalEndpoints}" value="${done}" aria-valuetext="${pct}% complete">${pct}%</progress><p aria-live="polite">${done} of ${x.totalEndpoints}; ${x.succeeded} succeeded, ${x.failed} failed, ${x.rolledBack} rolled back, ${x.pending} pending.</p><div class="toolbar">${["start","pause","resume","cancel","advance"].map(t=>`<form class="rollout-transition" data-transition="${t}" data-rollout="${esc(x.rolloutId)}"><input type="hidden" name="reason" value="Administrator ${t} from rollout view"><button type="submit">${t[0].toUpperCase()+t.slice(1)}</button></form>`).join("")}</div><p id="rollout-action-status" role="status" aria-live="assertive" tabindex="-1"></p></section><section aria-labelledby="assignment-title"><h2 id="assignment-title">Endpoint assignments</h2><div class="table-wrap"><table><caption>Exact rollout counts and health-gated endpoint states</caption><thead><tr><th>Endpoint</th><th>Installation</th><th>Ring</th><th>State</th><th>Attempt</th><th>Failure</th></tr></thead><tbody>${a.map(v=>`<tr><td><a href="#/fleet/${esc(v.endpointId)}"><code>${esc(v.endpointId)}</code></a></td><td><code>${esc(v.installationId)}</code></td><td>${esc(v.ringId)}</td><td><span class="badge">${esc(v.state)}</span></td><td>${v.attempt}</td><td>${esc(v.failureCode||"None")}</td></tr>`).join("")}</tbody></table></div></section>`;}
    const items=(await api("/api/v1/agent-update/rollouts")).data;return `<section aria-labelledby="rollouts-title"><h2 id="rollouts-title">Staged agent rollouts</h2><p>Ring progression is explicit; unhealthy canaries pause before the next ring.</p>${items.length?`<div class="table-wrap"><table><caption>Tenant-scoped rollout progress</caption><thead><tr><th>Version</th><th>State</th><th>Ring</th><th>Total</th><th>Pending</th><th>Succeeded</th><th>Failed</th></tr></thead><tbody>${items.map(x=>`<tr><td><a href="#/update-rollouts/${esc(x.rolloutId)}">${esc(x.targetVersion)}</a></td><td><span class="badge">${esc(x.state)}</span></td><td>${esc(x.currentRing)}</td><td>${x.totalEndpoints}</td><td>${x.pending}</td><td>${x.succeeded}</td><td>${x.failed}</td></tr>`).join("")}</tbody></table></div>`:state("No rollouts", "Preview and create a bounded rollout after registering a signed package and versioned policy.")}</section>`;
  }catch(error){return state("Rollouts unavailable",error.message);}
}
async function updatePoliciesPage(){try{const health=(await api("/api/v1/agent-update/health")).data;return `<section aria-labelledby="update-policy-title"><h2 id="update-policy-title">Update policies and deployment rings</h2><p>Versioned policies bind target release, ordered rings, maintenance window, minimum health, disk, retry, bandwidth, cache, concurrency, offline, auto-pause, and rollback behavior. Unsafe global-now execution and arbitrary installer arguments are unavailable.</p><div class="stats"><div><strong>${health.pending}</strong><span>Pending</span></div><div><strong>${health.active}</strong><span>Active</span></div><div><strong>${health.verificationFailures}</strong><span>Verification failures</span></div><div><strong>${health.healthFailures}</strong><span>Health failures</span></div></div><p role="status">Policy and ring creation is restricted to platform administrators and every immutable version is audited.</p></section>`;}catch(error){return state("Update policy health unavailable",error.message);}}
async function rolloutTransition(event){event.preventDefault();const form=event.currentTarget,status=document.querySelector("#rollout-action-status");try{await api(`/api/v1/agent-update/rollouts/${encodeURIComponent(form.dataset.rollout)}:${form.dataset.transition}`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({reason:new FormData(form).get("reason")})});status.textContent=`Rollout ${form.dataset.transition} recorded.`;status.focus();await route();}catch(error){status.textContent=error.message;status.focus();}}

async function enterpriseAdministrationPage(){
  try{
    const auditQuery=location.hash.includes("?")?location.hash.split("?")[1]:"limit=100";
    const [health,principals,roles,permissions,configs,registry,credentials,audit,routes]=await Promise.all(["overview","principals","roles","permissions","configurations","configuration-registry","api-clients",`audit?${auditQuery}`,"permissions/routes"].map(x=>api(`/api/v1/admin/${x}`)));
    const h=health.data,p=principals.data||[],r=roles.data||[],c=configs.data||[],defs=registry.data||[],creds=credentials.data||[],events=audit.data||[],routeState=routes.data;
    const principalOptions=p.map(x=>`<option value="${esc(x.principalId)}">${esc(x.displayName)} — ${esc(x.type)}</option>`).join("");
    const roleOptions=r.filter(x=>x.active).map(x=>`<option value="${esc(x.roleId)}|${x.version}">${esc(x.name)} v${x.version}</option>`).join("");
    return `<section aria-labelledby="admin-overview-title"><div class="detail-head"><div><h2 id="admin-overview-title">Administrative health</h2><p>Tenant-scoped identities, exact permissions, immutable policy versions, credential lifecycle, and audit integrity.</p></div><span class="badge">${routeState.passed?"Permission campaign healthy":"Permission gap"}</span></div><div class="stats"><div><strong>${h.activeUsers}</strong><span>Active users</span></div><div><strong>${h.serviceAccounts+h.apiClients}</strong><span>Non-human identities</span></div><div><strong>${h.pendingApprovals}</strong><span>Pending approvals</span></div><div><strong>${h.driftedEndpoints}</strong><span>Drift indicators</span></div><div><strong>${h.expiringCredentials}</strong><span>Expiring credentials</span></div><div><strong>${h.auditEvents}</strong><span>Audit events</span></div></div></section>
    <section aria-labelledby="users-access-title"><h2 id="users-access-title">Users &amp; access</h2><form id="admin-principal-create" class="admin-grid"><fieldset><legend>Create bounded principal</legend><label>Type <select name="type"><option>HumanUser</option><option>ServiceAccount</option><option>ApiClient</option></select></label><label>Display name <input name="displayName" maxlength="160" required></label><label>Purpose <textarea name="purpose" maxlength="500" required></textarea></label><label>Expires <input name="expiresAt" type="datetime-local"></label><button type="submit">Create principal</button></fieldset></form><div class="table-wrap"><table><caption>Canonical principals and access state</caption><thead><tr><th>Principal</th><th>Type</th><th>Status</th><th>Purpose</th><th>Expiry / activity</th><th>Permissions</th></tr></thead><tbody>${p.map(x=>`<tr><td>${esc(x.displayName)}<br><code>${esc(x.principalId)}</code></td><td>${esc(x.type)}</td><td><span class="badge">${esc(x.status)}</span></td><td>${esc(x.purpose)}</td><td>${x.expiresAt?new Date(x.expiresAt).toLocaleString():"No principal expiry"}<br>${x.lastActivity?`Last used ${new Date(x.lastActivity).toLocaleString()}`:"Never used"}</td><td><button type="button" class="admin-effective" data-id="${esc(x.principalId)}">Explain access</button></td></tr>`).join("")}</tbody></table></div><div id="admin-effective-result" tabindex="-1" aria-live="polite"></div>
    <div class="panels"><article><h3>Assign exact role</h3><form id="admin-role-assign"><label>Principal <select name="principalId">${principalOptions}</select></label><label>Role version <select name="role">${roleOptions}</select></label><label>Ends <input name="expiresAt" type="datetime-local"></label><label><input name="temporary" type="checkbox"> Temporary elevation</label><label>Reason <textarea name="reason" required maxlength="500"></textarea></label><button type="submit">Assign role</button></form></article><article><h3>Create custom role</h3><form id="admin-role-create"><label>Name <input name="name" maxlength="120" required></label><label>Description <textarea name="description" maxlength="500"></textarea></label><label>Allowlisted permissions <select name="permissions" multiple size="8">${permissions.data.filter(x=>!x.internalOnly).map(x=>`<option>${esc(x.permission)}</option>`).join("")}</select></label><label>Reason <textarea name="reason" required></textarea></label><button type="submit">Create role</button></form></article></div><div class="table-wrap"><table><caption>Immutable built-in and custom role versions</caption><thead><tr><th>Role</th><th>Version</th><th>Kind</th><th>Permissions</th><th>Definition hash</th></tr></thead><tbody>${r.map(x=>`<tr><td>${esc(x.name)}</td><td>${x.version}</td><td>${x.builtIn?"Built-in":"Custom"}</td><td>${x.permissions.length}</td><td><code>${esc(x.definitionHash)}</code></td></tr>`).join("")}</tbody></table></div></section>
    <section aria-labelledby="configuration-title"><h2 id="configuration-title">Typed configuration and policy</h2><form id="admin-config-preview" class="admin-grid"><fieldset><legend>Preview tenant configuration</legend><label>Registered key <select name="key">${defs.map(x=>`<option value="${esc(x.key)}" data-type="${esc(x.valueType)}">${esc(x.key)} — ${esc(x.securityClassification)}</option>`).join("")}</select></label><label>New value <input name="value" required></label><label>Rollout percent <input name="rolloutPercent" type="number" min="1" max="100" value="10" required></label><label>Reason <textarea name="reason" required maxlength="500"></textarea></label><button type="submit">Preview impact</button></fieldset></form><div id="admin-config-result" tabindex="-1" aria-live="assertive"></div><div class="table-wrap"><table><caption>Immutable configuration versions and drift-aware rollout state</caption><thead><tr><th>Key</th><th>Version</th><th>Scope</th><th>State</th><th>Value</th><th>Approval</th><th>Diff</th></tr></thead><tbody>${c.map(x=>`<tr><td>${esc(x.key)}</td><td>${x.version}</td><td>${esc(x.scope)} ${esc(x.scopeId||"")}</td><td><span class="badge">${esc(x.state)}</span></td><td><code>${esc(JSON.stringify(x.value))}</code></td><td>${esc(x.approvedBy||"Not approved")}</td><td>${esc(x.diff)}</td></tr>`).join("")}</tbody></table></div></section>
    <section aria-labelledby="api-clients-title"><h2 id="api-clients-title">API clients and service credentials</h2><form id="admin-credential-create" class="admin-grid"><fieldset><legend>Create expiring credential</legend><label>Non-human principal <select name="principalId">${p.filter(x=>x.type==="ApiClient"||x.type==="ServiceAccount").map(x=>`<option value="${esc(x.principalId)}">${esc(x.displayName)}</option>`).join("")}</select></label><label>Name <input name="name" required maxlength="120"></label><label>Purpose <textarea name="purpose" required maxlength="500"></textarea></label><label>Expires <input name="expiresAt" type="datetime-local" required></label><button type="submit">Create credential</button></fieldset></form><div id="admin-secret" class="containment-warning" tabindex="-1" aria-live="assertive"></div><div class="table-wrap"><table><caption>Credential metadata; secrets are never retrievable</caption><thead><tr><th>Name</th><th>Prefix/version</th><th>Expires</th><th>Last used</th><th>State</th><th>Action</th></tr></thead><tbody>${creds.map(x=>`<tr><td>${esc(x.name)}<br>${esc(x.purpose)}</td><td><code>${esc(x.prefix)}</code> / ${x.version}</td><td>${new Date(x.expiresAt).toLocaleString()}</td><td>${x.lastUsedAt?new Date(x.lastUsedAt).toLocaleString():"Never"}</td><td>${x.revokedAt?"Revoked":"Active"}</td><td>${x.revokedAt?"—":`<button type="button" class="admin-credential-revoke" data-id="${esc(x.credentialId)}">Revoke</button>`}</td></tr>`).join("")}</tbody></table></div></section>
    <section aria-labelledby="admin-audit-title"><h2 id="admin-audit-title">Immutable administrative audit</h2><form id="admin-audit-search" class="toolbar"><label>Action <input name="action"></label><label>Principal <input name="principal"></label><button type="submit">Search</button><button type="button" id="admin-audit-export">Export last 24 hours</button></form><div class="table-wrap"><table><caption>Bounded tenant administrative history</caption><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Reason</th><th>Result</th></tr></thead><tbody>${events.map(x=>`<tr><td>${new Date(x.occurredAt).toLocaleString()}</td><td><code>${esc(x.actor)}</code></td><td>${esc(x.action)}</td><td>${esc(x.resourceType)} / <code>${esc(x.resourceId)}</code></td><td>${esc(x.reason)}</td><td>${esc(x.result)}</td></tr>`).join("")}</tbody></table></div><p><strong>Existing sensitive route campaign:</strong> ${routeState.routes.length} inventoried; ${routeState.sensitiveWithoutExplicitPermission} missing explicit mappings.</p></section><p id="admin-action-status" role="status" aria-live="assertive" tabindex="-1"></p>`;
  }catch(error){return state("Enterprise administration unavailable",error.message);}
}
const adminJson=(path,body,method="POST")=>api(path,{method,headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
async function adminSubmit(event,work){event.preventDefault();const status=document.querySelector("#admin-action-status");try{await work(new FormData(event.currentTarget));status.textContent="Administrative change recorded.";status.focus();await route();}catch(error){status.textContent=error.message;status.focus();}}
function installEnterpriseAdministration(){
  document.querySelector("#admin-principal-create")?.addEventListener("submit",e=>adminSubmit(e,f=>adminJson("/api/v1/admin/principals",{type:f.get("type"),displayName:f.get("displayName"),purpose:f.get("purpose"),expiresAt:f.get("expiresAt")?new Date(f.get("expiresAt")).toISOString():null})));
  document.querySelector("#admin-role-create")?.addEventListener("submit",e=>adminSubmit(e,f=>adminJson("/api/v1/admin/roles",{name:f.get("name"),description:f.get("description"),permissions:f.getAll("permissions"),reason:f.get("reason")})));
  document.querySelector("#admin-role-assign")?.addEventListener("submit",e=>adminSubmit(e,f=>{const [roleId,roleVersion]=f.get("role").split("|");return adminJson("/api/v1/admin/role-assignments",{principalId:f.get("principalId"),roleId,roleVersion:Number(roleVersion),startsAt:new Date().toISOString(),expiresAt:f.get("expiresAt")?new Date(f.get("expiresAt")).toISOString():null,temporaryElevation:f.get("temporary")==="on",scopeType:"tenant",scopeId:null,reason:f.get("reason")});}));
  document.querySelector("#admin-credential-create")?.addEventListener("submit",async e=>{e.preventDefault();const f=new FormData(e.currentTarget),target=document.querySelector("#admin-secret");try{const x=(await adminJson("/api/v1/admin/api-clients/credentials",{principalId:f.get("principalId"),name:f.get("name"),purpose:f.get("purpose"),expiresAt:new Date(f.get("expiresAt")).toISOString()})).data;target.textContent=`Copy this secret now; it will not be shown again: ${x.secret}`;target.focus();}catch(error){target.textContent=error.message;target.focus();}});
  document.querySelectorAll(".admin-credential-revoke").forEach(x=>x.addEventListener("click",()=>adminSubmit({preventDefault(){},currentTarget:null},()=>adminJson(`/api/v1/admin/api-clients/credentials/${x.dataset.id}:revoke`,{reason:"explicit administrator revocation"}))));
  document.querySelectorAll(".admin-effective").forEach(x=>x.addEventListener("click",async()=>{const target=document.querySelector("#admin-effective-result");try{const v=(await api(`/api/v1/admin/principals/${x.dataset.id}/effective-permissions`)).data;target.innerHTML=`<h3>Effective permission explanation</h3><p>${v.permissions.length} permissions; restrictions: ${esc(v.restrictions.join(", ")||"None")}</p><div class="table-wrap"><table><thead><tr><th>Permission</th><th>Source role</th><th>Scope</th><th>Expires</th></tr></thead><tbody>${v.permissions.map(p=>`<tr><td>${esc(p.permission)}</td><td>${esc(p.source)} v${p.roleVersion}</td><td>${esc(p.scopeType)} ${esc(p.scopeId||"")}</td><td>${p.expiresAt?new Date(p.expiresAt).toLocaleString():"No assignment expiry"}</td></tr>`).join("")}</tbody></table></div>`;target.focus();}catch(error){target.textContent=error.message;target.focus();}}));
  document.querySelector("#admin-config-preview")?.addEventListener("submit",async e=>{e.preventDefault();const f=new FormData(e.currentTarget),select=e.currentTarget.elements.key,type=select.selectedOptions[0].dataset.type,raw=f.get("value"),value=type==="integer"?Number(raw):type==="boolean"?raw.toLowerCase()==="true":raw,target=document.querySelector("#admin-config-result");try{const request={key:f.get("key"),scope:"Tenant",scopeId:null,value,reason:f.get("reason"),rolloutPercent:Number(f.get("rolloutPercent"))},preview=(await adminJson("/api/v1/admin/configurations:preview",request)).data;target.innerHTML=`<h3>Impact preview</h3><p>${preview.affectedEndpoints} endpoints; security impact ${esc(preview.securityImpact)}; approval ${preview.approvalRequired?"required":"not required"}; rollout ${preview.rolloutPercent}%.</p><button type="button" id="admin-config-confirm">Confirm immutable version</button>`;target.focus();target.querySelector("button").onclick=()=>adminSubmit({preventDefault(){},currentTarget:null},()=>adminJson("/api/v1/admin/configurations",{...request,confirmationHash:preview.confirmationHash}));}catch(error){target.textContent=error.message;target.focus();}});
  document.querySelector("#admin-audit-search")?.addEventListener("submit",e=>{e.preventDefault();const q=new URLSearchParams(new FormData(e.currentTarget));location.hash=`#/administration-governance?${q}`;});
  document.querySelector("#admin-audit-export")?.addEventListener("click",()=>adminSubmit({preventDefault(){},currentTarget:null},()=>adminJson("/api/v1/admin/audit-exports",{format:"jsonl",query:{from:new Date(Date.now()-86400000).toISOString(),to:new Date().toISOString(),limit:1000}})));
}

async function safeData(path, fallback) { try { return (await api(path)).data; } catch (error) { if (error.message === CANCELLED_NAVIGATION) throw error; return fallback; } }
async function socDashboardPage() {
  const [alerts, incidents, endpoints, responses, forensics, triage, ai] = await Promise.all([
    safeData("/api/v1/triage-queue?sort=priority-desc", { items: [], total: 0 }),
    safeData("/api/v1/incidents?sort=updated-desc", { items: [], total: 0 }),
    safeData("/api/v1/endpoints?pageSize=100", { items: [] }),
    safeData("/api/v1/response-actions", { items: [] }),
    safeData("/api/v1/forensics/workspace-health", null),
    safeData("/api/v1/triage-health", null),
    safeData("/api/v1/ai/health", null),
  ]);
  const alertItems = alerts.items || [], incidentItems = incidents.items || [], endpointItems = endpoints.items || [], responseItems = responses.items || [];
  const high = alertItems.filter(x => Number(x.severity) >= 70), attention = incidentItems.filter(x => !["Resolved", "Closed"].includes(x.status));
  const activeResponse = responseItems.filter(x => !["Succeeded", "Failed", "TimedOut", "Cancelled", "Expired", "Rejected"].includes(x.state));
  const riskyEndpoints = endpointItems.filter(x => ["Offline", "Stale", "Degraded", "Unknown"].includes(String(x.status)));
  return `<section aria-labelledby="soc-priority"><div class="detail-head"><div><h2 id="soc-priority">Analyst priorities</h2><p class="page-lead">Evidence-backed work requiring attention now. Counts reflect the current tenant and your server-authorized scope.</p></div><div class="action-strip"><a class="button primary" href="#/alerts?status=New">Open new alerts</a><a class="button" href="#/incidents">My incidents</a><a class="button" href="#/threat-hunting">New hunt</a></div></div><div class="panels"><article><span class="metric-label">Critical / high alerts</span><strong class="metric">${high.length}</strong><p>${alertItems.filter(x=>x.currentStatus==="New").length} new in this bounded page</p></article><article><span class="metric-label">Incidents needing attention</span><strong class="metric">${attention.length}</strong><p>${attention.filter(x=>!x.assignee).length} unassigned</p></article><article><span class="metric-label">Endpoint health warnings</span><strong class="metric">${riskyEndpoints.length}</strong><p>${endpointItems.length} endpoints visible</p></article><article><span class="metric-label">Active response / collections</span><strong class="metric">${activeResponse.length} / ${forensics?.collectionsRunning ?? "Unknown"}</strong><p>Approval and evidence operations remain separate</p></article></div></section><section class="work-queue" aria-labelledby="work-queue-title"><div><div class="detail-head"><h2 id="work-queue-title">Priority alert queue</h2><a href="#/alerts">View full queue</a></div>${alertRows(alertItems.slice(0, 12))}</div><aside class="card" aria-label="Operational awareness"><h2>Operational awareness</h2><div class="state-banner ${ai ? "" : "degraded"}"><div><strong>AI assistant</strong><p>${ai ? "Available under tenant provider policy." : "Availability not confirmed. Investigation remains fully usable without AI."}</p></div></div><dl><dt>Forensic object storage</dt><dd>${forensics ? statusBadge(forensics.objectStorageHealthy ? "Healthy" : "Degraded") : statusBadge("Unknown")}</dd><dt>Hash verification failures</dt><dd>${forensics?.hashVerificationFailures ?? "Unknown"}</dd><dt>Invalid triage transitions</dt><dd>${triage?.invalidStateTransitions ?? "Unknown"}</dd><dt>Active response approvals</dt><dd>${responseItems.filter(x=>x.state==="PendingApproval").length}</dd></dl><h3>Recent incidents</h3><ol class="timeline">${attention.slice(0,5).map(x=>`<li><a href="#/incidents/${x.incidentId}">${esc(x.title)}</a><br>${statusBadge(x.status)} ${relativeTime(x.updatedAt)}</li>`).join("") || "<li>No incidents require attention.</li>"}</ol></aside></section>`;
}
async function approvalCenterPage() {
  const [responses, playbooks, collections] = await Promise.all([
    safeData("/api/v1/response-actions", { items: [] }),
    safeData("/api/v1/playbook-approvals", []),
    safeData("/api/v1/forensic-collections", { items: [] }),
  ]);
  const responseItems=(responses.items||[]).filter(x=>/approval/i.test(String(x.state))),playbookItems=(playbooks||[]).filter(x=>x.steps?.some(s=>s.state==="WaitingForApproval")),collectionItems=(collections.items||collections||[]).filter(x=>x.approvalState==="Pending");
  const row=(kind,id,requester,target,risk,parameters,evidence,expiry,reason,href)=>`<tr><td>${esc(kind)}</td><td><a href="${esc(href)}"><code>${esc(id)}</code></a></td><td>${esc(requester||"Unknown")}</td><td><code>${esc(target||"Unknown")}</code></td><td>${statusBadge(risk||"Review required")}</td><td><code>${esc(JSON.stringify(parameters||{}).slice(0,500))}</code></td><td>${esc(evidence||"Inspect authoritative detail")}</td><td>${expiry?new Date(expiry).toLocaleString():"No expiry reported"}</td><td>${esc(reason||"No requester reason recorded")}</td></tr>`;
  const rows=[...responseItems.map(x=>row("Endpoint response",x.responseActionId,x.analystId,x.targetEntityId||x.endpointId,x.riskLevel,{action:x.actionType,hash:x.requestHash},x.sourceIncidentId||x.sourceAlertId,x.approvalExpiresAt,x.reason,`#/response-actions/${x.responseActionId}`)),...playbookItems.map(x=>{const s=x.steps.find(v=>v.state==="WaitingForApproval");return row("Playbook",x.executionId,x.requestedBy,x.targetEntityId||x.endpointId,s?.risk,{step:s?.stepId,inputHash:s?.inputHash},x.sourceIncidentId||x.sourceAlertId,s?.approvalExpiresAt,x.reason,`#/playbook-executions/${x.executionId}`)}),...collectionItems.map(x=>row("Forensic collection",x.collectionId,x.analystId,x.endpointId,x.riskLevel,{profile:x.profileId,parameterHash:x.parameterHash},x.sourceIncidentId,x.approvalExpiresAt,x.reason,`#/forensic-collections/${x.collectionId}`))];
  return `<section aria-labelledby="approval-title"><div class="detail-head"><div><h2 id="approval-title">Prioritized approval queue</h2><p class="page-lead">A bounded overview of existing response, playbook, and forensic approval gates. Decisions remain in each authoritative detail workflow.</p></div><span class="badge priority">${rows.length} pending</span></div>${rows.length?`<div class="table-wrap"><table><caption>Pending security-impacting approvals</caption><thead><tr><th>Type</th><th>Request</th><th>Requester</th><th>Exact target</th><th>Risk</th><th>Exact parameters</th><th>Evidence</th><th>Expiration</th><th>Reason</th></tr></thead><tbody>${rows.join("")}</tbody></table></div>`:state("No pending approvals","No response, playbook, or forensic request is currently waiting for approval.")}</section><section><h2>Other governed changes</h2><p>Maintenance, detection-content, policy, and update approvals remain in their versioned authoritative workspaces until a shared server-side approval contract exists. This overview does not synthesize or weaken those controls.</p><div class="quick-chips"><a href="#/self-protection">Maintenance</a><a href="#/detection-content">Detection changes</a><a href="#/administration-governance">Policy changes</a><a href="#/update-rollouts">Update rollouts</a></div></section>`;
}
async function unifiedSearchPage() {
  const query = new URLSearchParams(location.hash.split("?")[1] || ""), term = String(query.get("q") || "").trim();
  if (!term) return state("Search the tenant workspace", "Enter a hostname, process, hash, file, domain, IP, user, alert, incident, investigation, or IOC in the global search field.");
  if (term.length > 128 || /[\u0000-\u001f]/.test(term)) return state("Search rejected", "The bounded search term must be 1-128 visible characters.");
  const [endpoints, alerts, incidents, investigations, iocs] = await Promise.all([
    safeData("/api/v1/endpoints?pageSize=100", { items: [] }), safeData("/api/v1/triage-queue", { items: [] }), safeData("/api/v1/incidents", { items: [] }), safeData("/api/v1/investigations?limit=100", { items: [] }), safeData(`/api/v1/intelligence/indicators?query=${encodeURIComponent(term)}&limit=100`, { items: [] }),
  ]);
  const match = x => JSON.stringify(x).toLowerCase().includes(term.toLowerCase()), group = (title, items, href, label) => `<section><h2>${esc(title)} <span class="badge">${items.length}</span></h2>${items.length ? `<ul class="search-results">${items.slice(0,10).map(x=>`<li><a href="${href(x)}"><strong>${esc(label(x))}</strong><br><small>${esc(JSON.stringify(x).slice(0,220))}</small></a></li>`).join("")}</ul>` : `<p class="muted">No authorized ${esc(title.toLowerCase())} matched.</p>`}</section>`;
  const quick = /^[a-fA-F0-9]{64}$/.test(term) ? [["Search file hash", `#/files?sha256=${encodeURIComponent(term)}`], ["Search evidence hash", `#/dfir-workspace?view=evidence&hash=${encodeURIComponent(term)}`], ["Search IOC", `#/intelligence?query=${encodeURIComponent(term)}`]] : [["Search processes", `#/processes?name=${encodeURIComponent(term)}`], ["Search files", `#/files?path=${encodeURIComponent(term)}`], ["Search DNS", `#/dns?name=${encodeURIComponent(term)}`], ["Search network", `#/network?remoteAddress=${encodeURIComponent(term)}`], ["Search IOC", `#/intelligence?query=${encodeURIComponent(term)}`]];
  return `<div class="detail-head"><div><h2>Results for “${esc(term)}”</h2><p class="page-lead">Typed, bounded, tenant-scoped results. Search does not accept backend query syntax.</p></div></div><div class="quick-chips">${quick.map(([name,href])=>`<a class="button" href="${href}">${name}</a>`).join("")}</div>${group("Endpoints", (endpoints.items||[]).filter(match), x=>`#/endpoints/${x.id}`, x=>x.hostname||x.id)}${group("Alerts", (alerts.items||[]).filter(match), x=>`#/alerts/${x.alertId}`, x=>x.title)}${group("Incidents", (incidents.items||[]).filter(match), x=>`#/incidents/${x.incidentId}`, x=>x.title)}${group("Investigations", (investigations.items||[]).filter(match), x=>`#/dfir-workspace/${x.investigationId}`, x=>x.title)}${group("Indicators", (iocs.items||iocs||[]).filter(match), x=>`#/intelligence/${x.indicatorId}`, x=>x.value||x.canonicalValue||x.indicatorId)}`;
}
function commandItems() {
  const defaults = [["Open Alerts", "#/alerts"], ["Open Incidents", "#/incidents"], ["Open Investigations", "#/dfir-workspace"], ["Search endpoints", "#/endpoints"], ["New Hunt", "#/threat-hunting"], ["Response Center", "#/response-actions"], ["Approval queue", "#/approvals"], ["Live Response", "#/live-response"], ["Threat Intelligence", "#/intelligence"]];
  const context=jwtContext(),recentKey=`soc.recent-workspaces.${context.tenant}.${context.subject}`;let recent=[];try{recent=JSON.parse(localStorage.getItem(recentKey)||"[]").filter(x=>pages[x]).slice(0,5).map(x=>[`Recent: ${pages[x]}`,`#/${x}`]);}catch{localStorage.removeItem(recentKey);}
  return [...recent, ...defaults, ...boundedSavedViews().list().map(x=>[x.name, `#/${x.route}?${new URLSearchParams(x.filters)}`])];
}
function renderCommands(term = "") { const host = document.querySelector("#command-results"); if (!host) return; const values = commandItems().filter(([name])=>name.toLowerCase().includes(term.toLowerCase())).slice(0,20); host.innerHTML = values.map(([name,href],i)=>`<a href="${href}" tabindex="${i?"-1":"0"}">${esc(name)}<small>Navigate only; destructive actions require their normal workflow.</small></a>`).join("") || `<p class="muted">No command matched.</p>`; }
function installGlobalShell() {
  const palette = document.querySelector("#command-palette"), search = document.querySelector("#global-search"), commandInput = document.querySelector("#command-input");
  document.querySelector("#global-search-form")?.addEventListener("submit", e=>{ e.preventDefault(); const value=new FormData(e.currentTarget).get("q"); location.hash=`#/search?q=${encodeURIComponent(value)}`; });
  document.querySelector("#command-open")?.addEventListener("click", ()=>{ palette.showModal(); renderCommands(); commandInput.focus(); });
  commandInput?.addEventListener("input", ()=>renderCommands(commandInput.value));
  palette?.addEventListener("click", e=>{ if(e.target===palette) palette.close(); });
  document.querySelector("#density")?.addEventListener("click", ()=>{ const compact=document.body.dataset.density!=="compact"; document.body.dataset.density=compact?"compact":"comfortable"; localStorage.setItem("density", document.body.dataset.density); notify(`${compact?"Compact":"Comfortable"} table density enabled.`); });
  document.onkeydown = e=>{ if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==="k"){e.preventDefault();palette.showModal();renderCommands();commandInput.focus();} else if(e.key==="/"&&!/INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName)){e.preventDefault();search.focus();} else if(e.key==="Escape"&&palette.open)palette.close(); };
  document.querySelector("#activity-open")?.addEventListener("click", ()=>document.querySelector("#activity-drawer")?.toggleAttribute("hidden"));
  document.querySelector('#activity-drawer a[href="#/playbook-approvals"]')?.setAttribute("href", "#/approvals");
  document.querySelector("#content")?.addEventListener("submit", e=>{
    const form=e.target;
    if(!(form instanceof HTMLFormElement))return;
    if(form.dataset.submitting==="true"){e.preventDefault();notify("That request is already being submitted.");return;}
    form.dataset.submitting="true";
    const controls=[...form.querySelectorAll('button[type="submit"],button:not([type])')];
    controls.forEach(x=>x.disabled=true);
    setTimeout(()=>{form.dataset.submitting="false";controls.forEach(x=>x.disabled=false);},2000);
  },true);
  document.querySelector("#content")?.addEventListener("click", e=>{
    const link=e.target.closest('a[href^="#/"]'); if(!link)return;
    const destination=link.getAttribute("href"),source=location.hash||"#/dashboard";
    if(link.dataset.queueAlert){queueContext={returnHash:source,ids:[...document.querySelectorAll("[data-queue-alert]")].map(x=>x.dataset.queueAlert),scrollY,selected:link.dataset.queueAlert};sessionStorage.setItem(`soc.queue.${jwtContext().tenant}.${jwtContext().subject}`,JSON.stringify(queueContext));}
    if(destination!==source){navigationContext.push({hash:source,scrollY,title:document.querySelector("h1")?.textContent||"Previous workspace"});if(navigationContext.length>10)navigationContext.shift();}
    if(link.hasAttribute("data-restore-queue"))pendingScrollRestore=queueContext?.scrollY||0;
  });
}
function installAnalystKeyboard() {
  const rows=[...document.querySelectorAll("#content tbody tr")].filter(r=>r.querySelector("a[href]")); rows.forEach((r,i)=>{r.tabIndex=i? -1:0;r.dataset.href=r.querySelector("a[href]").getAttribute("href");});
  document.querySelector("#content")?.addEventListener("keydown", e=>{ const row=e.target.closest("tbody tr"); if(!row)return; const index=rows.indexOf(row); if(e.key==="j"||e.key==="ArrowDown"){e.preventDefault();rows[Math.min(rows.length-1,index+1)]?.focus();} if(e.key==="k"||e.key==="ArrowUp"){e.preventDefault();rows[Math.max(0,index-1)]?.focus();} if(e.key==="Enter"){e.preventDefault();location.hash=row.dataset.href;} });
}
function installTableSystem() {
  document.querySelectorAll("#content table").forEach(table=>{
    if(table.dataset.socTable)return; table.dataset.socTable="true"; table.setAttribute("aria-rowcount", String(table.tBodies[0]?.rows.length || 0));
    [...table.tHead?.rows[0]?.cells || []].forEach((header,index)=>{ if(!header.textContent.trim()||header.querySelector("input,button"))return; header.tabIndex=0; header.title="Sort this loaded page"; const sort=()=>{const body=table.tBodies[0],rows=[...body.rows],descending=header.getAttribute("aria-sort")!=="descending"; [...header.parentElement.cells].forEach(x=>x.removeAttribute("aria-sort")); header.setAttribute("aria-sort",descending?"descending":"ascending"); rows.sort((a,b)=>a.cells[index].innerText.localeCompare(b.cells[index].innerText,undefined,{numeric:true})*(descending?-1:1)).forEach(x=>body.append(x));}; header.addEventListener("click",sort);header.addEventListener("keydown",e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();sort();}}); });
  });
}
function installSavedViewControl(key) {
  if(!["alerts","incidents","threat-hunting","fleet"].includes(key)||document.querySelector("#soc-save-view"))return;
  const host=document.createElement("form"); host.id="soc-save-view"; host.className="toolbar"; host.innerHTML='<label>View name <input name="name" maxlength="80" required></label><button>Save safe view</button><span role="status"></span>'; document.querySelector("#content")?.prepend(host);
  host.addEventListener("submit",e=>{e.preventDefault();const name=new FormData(host).get("name"),filters=new URLSearchParams(location.hash.split("?")[1]||"");boundedSavedViews().save(name,key,filters);host.querySelector('[role="status"]').textContent="Saved for this signed-in analyst.";notify("Saved view added to Quick actions.");});
}
const workspaceGuidance = {
  dashboard: ["SOC overview", "Prioritized work and platform conditions that need attention now."],
  alerts: ["Alert triage", "Start with the reason, exact evidence, and affected entity. Technical provenance stays one step away."],
  incidents: ["Incident workspace", "Group related alerts into one evidence-backed investigation and chronological activity stream."],
  "dfir-workspace": ["Forensic investigations", "Browse collected evidence, timelines, notes, custody, and exports without losing case context."],
  "forensic-collections": ["Remote collections", "Review exact scope, limits, progress, integrity, and retention for endpoint evidence acquisition."],
  "forensic-tools": ["Forensic tools", "Manage approved, hash-pinned tools separately from execution and collection approval."],
  "threat-hunting": ["Threat hunting", "Build a bounded question, preview its scope, and inspect evidence-backed results."],
  "entity-graph": ["Entity graph", "Explore evidence-backed relationships while keeping ambiguity and source quality visible."],
  "attack-stories": ["Attack story", "Read authoritative activity in time order, then pivot into the evidence behind each step."],
  endpoints: ["Endpoint inventory", "Find an endpoint, understand its health, and pivot into telemetry or governed response."],
  "detection-content": ["Detection content", "Review coverage, validation state, telemetry dependencies, and production activation separately."],
  "detection-engineering": ["Detection engineering", "Draft, simulate, compare, and review content before any explicit activation."],
  "response-actions": ["Response center", "Inspect exact targets, approval state, execution progress, and verification without hiding risk."],
  approvals: ["Approval center", "Review security-impacting requests with exact targets, parameters, evidence, and expiry."],
  "live-response": ["Live Response", "Use bounded, audited endpoint sessions with explicit capabilities and visible transfer state."],
  intelligence: ["Threat intelligence", "Manage source provenance and inspect exact IOC matches without automatic response."],
  fleet: ["Fleet management", "Understand deployment health, version drift, and update readiness across endpoints."],
  resilience: ["Platform resilience", "See service health, recovery posture, backup integrity, and current operational risk."],
  "administration-governance": ["Administration", "Manage permissions, configuration, audit, and governed changes with clear blast radius."],
};
function enhanceInformationArchitecture(key, parts) {
  const content = document.querySelector("#content");
  if (!content) return;
  content.classList.add("soc-workspace", `workspace-${key}`);
  document.body.dataset.workspace = key;
  const guidance = workspaceGuidance[key];
  if (guidance && !(key === "alerts" && parts[1]) && !content.querySelector(".workspace-intro")) {
    const intro = document.createElement("div");
    intro.className = "workspace-intro";
    intro.innerHTML = `<div><span class="section-eyebrow">WORKSPACE</span><h2>${esc(guidance[0])}</h2><p>${esc(guidance[1])}</p></div>`;
    const freshness = content.querySelector(":scope > .freshness");
    (freshness || content.firstElementChild)?.insertAdjacentElement(freshness ? "afterend" : "beforebegin", intro);
  }
  content.querySelectorAll("form.toolbar").forEach((form) => {
    const labels = [...form.querySelectorAll(":scope > label")];
    if (labels.length < 6 || form.dataset.progressiveFilters) return;
    form.dataset.progressiveFilters = "true";
    form.classList.add("filter-workbench");
    const advanced = document.createElement("div"), toggle = document.createElement("button");
    advanced.className = "advanced-filter-fields";
    advanced.hidden = true;
    labels.slice(4).forEach((label) => advanced.append(label));
    toggle.type = "button";
    toggle.className = "filter-toggle";
    toggle.setAttribute("aria-expanded", "false");
    toggle.textContent = `More filters (${labels.length - 4})`;
    const action = form.querySelector(':scope > button:not([type="button"]),:scope > button[type="submit"]');
    form.insertBefore(toggle, action || null);
    form.insertBefore(advanced, action || null);
    const hasAdvancedValue = [...advanced.querySelectorAll("input,select")].some((control) => control.type === "checkbox" ? control.checked : control.value && control.value !== "Any");
    const setOpen = (open) => { advanced.hidden = !open; toggle.setAttribute("aria-expanded", String(open)); toggle.textContent = `${open ? "Fewer" : "More"} filters (${labels.length - 4})`; };
    toggle.addEventListener("click", () => setOpen(toggle.getAttribute("aria-expanded") !== "true"));
    setOpen(hasAdvancedValue);
  });
  content.querySelectorAll("table").forEach((table) => {
    if ((table.tHead?.rows[0]?.cells.length || 0) > 7) table.classList.add("wide-data-grid");
    const headers = [...table.tHead?.rows[0]?.cells || []].map((cell) => cell.textContent.trim().toLowerCase());
    headers.forEach((header, index) => {
      if (!/^(state|status|approval|retention|quality|validity)$/.test(header)) return;
      [...table.tBodies].flatMap((body) => [...body.rows]).forEach((row) => {
        const cell = row.cells[index], value = cell?.textContent.trim();
        if (cell && value && !cell.querySelector(".badge,a,button,input")) cell.innerHTML = statusBadge(value);
      });
    });
  });
  if (key === "alerts" && parts[1]) {
    const signatureTerm = [...content.querySelectorAll("dt")].find((term) => term.textContent.trim() === "Hash / signature"), signatureValue = signatureTerm?.nextElementSibling;
    if (signatureValue) {
      const values = signatureValue.innerText.split(/\r?\n/).map((value) => value.trim()).filter(Boolean), labels = ["Unknown", "Unsigned", "Valid", "Invalid", "Not checked", "Verification error"];
      if (values.length > 1 && /^\d+$/.test(values.at(-1))) signatureValue.innerHTML = `${esc(values.slice(0, -1).join(" "))}<br>${esc(labels[Number(values.at(-1))] || "Unknown")}`;
    }
  }
  installProcessMapControls();
  installEntityMapControls();
}
function enhanceCoreWorkspace(key, parts) {
  const content=document.querySelector("#content"); if(!content)return;
  const addTabs=(items)=>{ if(content.querySelector(".workspace-tabs"))return; const tabs=document.createElement("nav");tabs.className="workspace-tabs";tabs.setAttribute("aria-label","Workspace sections");tabs.innerHTML=items.map(([name,href])=>href.startsWith("@")?`<button type="button" data-section="${esc(href.slice(1))}">${esc(name)}</button>`:`<a href="${href}">${esc(name)}</a>`).join(""); const sections=[...content.querySelectorAll("section")];sections.forEach(section=>{const name=section.querySelector("h2,h3")?.textContent.toLowerCase()||"";for(const target of ["evidence","timeline","alerts","audit"]){if(name.includes(target)&&!content.querySelector(`#workspace-${target}`))section.id ||= `workspace-${target}`;}});tabs.addEventListener("click",e=>{const target=e.target.closest("[data-section]")?.dataset.section;if(!target)return;(target==="top"?content.querySelector(".detail-head,.alert-hero"):content.querySelector(`#workspace-${target}`))?.scrollIntoView({behavior:"smooth",block:"start"});}); const head=content.querySelector(".detail-head,.alert-hero");(head||content.firstElementChild)?.insertAdjacentElement(head?"afterend":"beforebegin",tabs);};
  if(key==="incidents"&&parts[1]){
    const activity=[...content.querySelectorAll("section ol.timeline li")].map(item=>({source:item.closest("section")?.querySelector("h2,h3")?.textContent.trim()||"Activity",node:item.cloneNode(true)}));
    if(activity.length){const unified=document.createElement("section");unified.id="workspace-timeline";const sources=[...new Set(activity.map(x=>x.source))];unified.innerHTML=`<h2>Unified incident activity</h2><p class="page-lead">Available canonical lifecycle, alert, response, collection, playbook, analyst, and audit activity remains linked to its source.</p><div class="toolbar"><label>Source <select id="incident-source"><option>All</option>${sources.map(x=>`<option>${esc(x)}</option>`).join("")}</select></label><label>Search loaded activity <input id="incident-timeline-search" maxlength="128"></label><button type="button" id="incident-timeline-clear">Clear</button><span role="status"></span></div><ol class="timeline"></ol>`;const list=unified.querySelector("ol");activity.forEach(x=>{x.node.dataset.source=x.source;x.node.insertAdjacentHTML("afterbegin",`<span class="badge">${esc(x.source)}</span> `);list.append(x.node);});const apply=()=>{const source=unified.querySelector("select").value,term=unified.querySelector("input").value.toLowerCase(),items=[...list.children];items.forEach(x=>x.hidden=(source!=="All"&&x.dataset.source!==source)||(term&&!x.textContent.toLowerCase().includes(term)));unified.querySelector('[role="status"]').textContent=`${items.filter(x=>!x.hidden).length} of ${items.length} activity items shown`;};unified.querySelector("select").addEventListener("change",apply);unified.querySelector("input").addEventListener("input",apply);unified.querySelector("button").addEventListener("click",()=>{unified.querySelector("select").value="All";unified.querySelector("input").value="";apply();});content.querySelector("section")?.insertAdjacentElement("beforebegin",unified);apply();}
  }
  if(key==="incidents"&&parts[1]&&content.querySelector("#workspace-timeline")){const timeline=content.querySelector("#workspace-timeline"),toolbar=timeline.querySelector(".toolbar"),windowLabel=document.createElement("label"),suspiciousLabel=document.createElement("label");windowLabel.innerHTML='Time window <select id="incident-time-window"><option value="0">All loaded activity</option><option value="1">Last hour</option><option value="24">Last 24 hours</option><option value="168">Last 7 days</option></select>';suspiciousLabel.innerHTML='<input id="incident-suspicious-only" type="checkbox"> Suspicious only';if(!timeline.querySelector('[data-suspicious="true"]')){suspiciousLabel.querySelector("input").disabled=true;suspiciousLabel.title="Not available: loaded activity has no authoritative suspicious classification.";}toolbar.append(windowLabel,suspiciousLabel);const refine=()=>{const hours=Number(windowLabel.querySelector("select").value),source=timeline.querySelector("#incident-source")?.value||"All",term=(timeline.querySelector("#incident-timeline-search")?.value||"").toLowerCase(),cutoff=hours?Date.now()-hours*3600000:0,items=[...timeline.querySelectorAll("ol.timeline > li")];items.forEach(item=>{const time=Date.parse(item.querySelector("time")?.dateTime||item.querySelector("time")?.textContent||""),sourceHidden=source!=="All"&&item.dataset.source!==source,termHidden=term&&!item.textContent.toLowerCase().includes(term),timeHidden=cutoff&&Number.isFinite(time)&&time<cutoff,suspiciousHidden=suspiciousLabel.querySelector("input").checked&&item.dataset.suspicious!=="true";item.hidden=sourceHidden||termHidden||timeHidden||suspiciousHidden;});toolbar.querySelector('[role="status"]').textContent=`${items.filter(x=>!x.hidden).length} of ${items.length} activity items shown`;};toolbar.querySelectorAll("select,input").forEach(x=>x.addEventListener(x.tagName==="INPUT"?"input":"change",refine));}
  if(key==="alerts"&&parts[1]&&!parts[2]) { const back=content.querySelector('a[href="#/alerts"]');if(back)back.outerHTML=alertQueueNavigation(parts[1]);addTabs([["Summary","@top"],["Evidence","@evidence"],["Process","@process"],["Entities","@entities"],["Triage","@actions"],["Response",`#/response-actions/new?alertId=${parts[1]}`],["AI",`#/ai-investigation?contextType=alert&contextId=${parts[1]}`],["Audit","@audit"]]); }
  if(key==="alerts"&&parts[1]&&!parts[2]) { const processLink=content.querySelector('a[href^="#/processes/"]'),treeLink=content.querySelector('a[href^="#/process-tree?root="]'),graphLink=content.querySelector('a[href^="#/entity-graph?root="]');if(treeLink){treeLink.setAttribute("href",`#/alerts/${encodeURIComponent(parts[1])}/lineage`);treeLink.setAttribute("target","_blank");treeLink.setAttribute("rel","noopener");treeLink.textContent="Open lineage window ↗";const section=treeLink.closest("section");const heading=section?.querySelector("h3");if(heading)heading.textContent="Process lineage";}if(processLink){const endpoint=processLink.getAttribute("href").split("/")[2];if(endpoint&&graphLink&&!graphLink.getAttribute("href").includes("endpointId="))graphLink.setAttribute("href",`${graphLink.getAttribute("href")}&endpointId=${encodeURIComponent(endpoint)}`);} }
  if(key==="alerts"&&parts[1]&&!parts[2]) { const lineageLink=content.querySelector(`a[href="#/alerts/${CSS.escape(parts[1])}/lineage"]`);lineageLink?.addEventListener("click",event=>{event.preventDefault();const href=lineageLink.getAttribute("href"),opened=window.open(href,`alert-lineage-${parts[1]}`,"popup,width=1600,height=980,resizable=yes,scrollbars=yes");if(!opened)window.open(href,"_blank","noopener");}); }
  if(key==="incidents"&&parts[1]) { addTabs([["Summary","@top"],["Timeline","@timeline"],["Alerts","@alerts"],["Attack story",`#/attack-stories?incidentId=${parts[1]}`],["Entities",`#/entity-graph?incidentId=${parts[1]}`],["Investigation",`#/dfir-workspace?incidentId=${parts[1]}`],["Response",`#/response-actions/new?incidentId=${parts[1]}`],["AI",`#/ai-investigation?contextType=incident&contextId=${parts[1]}`],["Audit","@audit"]]); const alerts=[...content.querySelectorAll('a[href^="#/alerts/"]')].slice(0,5);if(alerts.length){const summary=document.createElement("aside");summary.className="evidence-summary";summary.setAttribute("aria-label","Strongest available incident evidence");summary.innerHTML=`<strong>Strongest available evidence</strong><p>${alerts.length} directly linked alert source(s). Open a source to inspect canonical evidence and provenance.</p><div class="quick-chips">${alerts.map(x=>`<a href="${esc(x.getAttribute("href"))}">${esc(x.textContent)}</a>`).join("")}</div>`;content.querySelector(".detail-head")?.insertAdjacentElement("afterend",summary);} }
  if(key==="incidents"&&parts[1]) { const legacyTreeLinks=[...content.querySelectorAll('a[href^="#/process-tree?"]')];legacyTreeLinks.forEach(link=>link.remove());const pivotSection=[...content.querySelectorAll("section")].find(section=>section.querySelector("h2")?.textContent.trim()==="Investigation pivots");if(pivotSection){const paragraph=pivotSection.querySelector("p");if(paragraph)paragraph.insertAdjacentHTML("afterbegin",'<span class="muted">Open a linked alert for its process lineage.</span> · ');} }
  if(key==="endpoints"&&parts[1]) addTabs([["Overview",`#/endpoints/${parts[1]}`],["Processes",`#/processes?endpointId=${parts[1]}`],["Alerts",`#/alerts?endpointId=${parts[1]}`],["Network",`#/network?endpointId=${parts[1]}`],["Files",`#/files?endpointId=${parts[1]}`],["Persistence",`#/persistence-configurations?endpointId=${parts[1]}`],["Identity",`#/identity?endpointId=${parts[1]}`],["Response",`#/response-actions?endpointId=${parts[1]}`],["Forensics",`#/forensic-collections?endpointId=${parts[1]}`]]);
  if(key==="entity-graph") {
    content.querySelector('[role="img"]')?.classList.add("graph-viewport");
    const nodeFilter=content.querySelector("#graph-node-filter"),edgeFilter=content.querySelector("#graph-edge-filter"),tables=[...content.querySelectorAll("table")];
    nodeFilter?.addEventListener("change",()=>{[...tables[0]?.tBodies[0]?.rows||[]].forEach(row=>row.hidden=nodeFilter.value!=="All"&&row.cells[1]?.textContent.trim()!==nodeFilter.value);});
    edgeFilter?.addEventListener("change",()=>{[...tables[1]?.tBodies[0]?.rows||[]].forEach(row=>row.hidden=edgeFilter.value!=="All"&&!row.cells[1]?.textContent.includes(edgeFilter.value));});
    if(tables[0]){const drawer=document.createElement("aside");drawer.id="entity-detail-drawer";drawer.className="detail-drawer";drawer.hidden=true;drawer.setAttribute("aria-label","Entity details");drawer.innerHTML='<button type="button" aria-label="Close entity details">Close</button><div></div>';document.querySelector("#app").append(drawer);const header=document.createElement("th");header.textContent="Inspect";tables[0].tHead.rows[0].append(header);[...tables[0].tBodies[0].rows].forEach(row=>{const cell=row.insertCell(),button=document.createElement("button");button.type="button";button.textContent="Inspect";button.addEventListener("click",()=>{drawer.querySelector("div").innerHTML=`<h2>${esc(row.cells[2].textContent.trim())}</h2><dl><dt>Type</dt><dd>${esc(row.cells[1].textContent.trim())}</dd><dt>Observed</dt><dd>${esc(row.cells[0].textContent.trim())}</dd><dt>Evidence</dt><dd>${esc(row.cells[3].textContent.trim())}</dd><dt>Quality / ambiguity</dt><dd>${esc(row.cells[4].textContent.trim())}</dd></dl><h3>Available pivots and response state</h3>${row.cells[5].innerHTML}`;drawer.hidden=false;drawer.querySelector("button").focus();});cell.append(button);});drawer.querySelector("button").addEventListener("click",()=>{drawer.hidden=true;tables[0].querySelector("button")?.focus();});}
  }
  if(key==="response-actions"&&parts[1]) content.querySelectorAll("#response-approve,#response-reject,#response-cancel").forEach(x=>x.closest("article")?.classList.add("risk-context"));
  if(key==="live-response") content.querySelector(".live-terminal")?.setAttribute("aria-description","Explicit remote shell mode. Standard output and error retain their recorded stream identity.");
  if(["administration-governance","agent-update-packages","update-rollouts"].includes(key)){const banner=document.createElement("div");banner.className="state-banner degraded";banner.innerHTML="<strong>Security-impacting workspace.</strong><span>Changes remain server-authorized, versioned, and audited; approvals are not bypassed by this interface.</span>";content.prepend(banner);}
  if(["endpoints","response-actions","approvals","playbook-approvals","self-protection","agent-update-packages","update-rollouts","forensic-collections","dfir-workspace","live-response"].includes(key)){const stamp=document.createElement("div");stamp.className="freshness";stamp.setAttribute("role","status");stamp.innerHTML=`State refreshed <time datetime="${new Date().toISOString()}">${new Date().toLocaleTimeString()}</time>. <button type="button">Refresh current state</button>`;stamp.querySelector("button").addEventListener("click",()=>route());content.prepend(stamp);}
  const origin=navigationContext.at(-1);if(origin&&origin.hash!==location.hash&&parts[1]){const back=document.createElement("nav");back.className="queue-navigation context-return";back.setAttribute("aria-label","Investigation origin");back.innerHTML=`<button type="button">Return to ${esc(origin.title)}</button><span>Origin context and prior scroll position are retained in this browser session.</span>`;back.querySelector("button").onclick=()=>{navigationContext.pop();pendingScrollRestore=origin.scrollY;location.hash=origin.hash;};content.prepend(back);}
  content.querySelectorAll(".badge").forEach(x=>x.classList.add(statusClass(x.textContent)));
  content.querySelectorAll("table").forEach(table=>{const caption=table.caption?.textContent||"";if(caption.includes("Analyst triage queue")){[...table.tBodies[0]?.rows||[]].forEach(row=>{const score=Number(row.cells[3]?.textContent),label=score>=90?"Critical":score>=70?"High":score>=40?"Medium":"Low";if(row.cells[3])row.cells[3].innerHTML=`${statusBadge(label,"severity")} <small>${score}</small>`;if(row.cells[4]){const priority=row.cells[4].childNodes[0]?.textContent.trim(),explanation=row.cells[4].querySelector("small")?.textContent;row.cells[4].innerHTML=`<span class="badge priority">P${esc(priority)}</span>${explanation?`<br><small class="alert-priority-detail" title="${esc(explanation)}">${esc(explanation)}</small>`:""}`;}});}if(caption.includes("Incident queue")){[...table.tBodies[0]?.rows||[]].forEach(row=>{if(row.cells[2])row.cells[2].innerHTML=`<span class="badge priority">P${esc(row.cells[2].textContent.trim())}</span>`;});}});
  content.querySelectorAll('button').forEach(button=>{const label=button.textContent.toLowerCase();if(/terminate|delete|quarantine|isolate|revoke|rollback|reject/.test(label))button.classList.add("danger");});
  installTableSystem(); installSavedViewControl(key);
}

async function route() {
  const thisRoute = ++routeSequence;
  activeReadController.abort();
  activeReadController = new AbortController();
  endpointDetailContext = null;
  const parts = (location.hash.slice(2).split("?")[0] || "dashboard").split(
      "/",
    ),
    key = parts[0],
    title = pages[key] || pages.dashboard;
  if (key === "process-tree") {
    location.replace("#/alerts");
    return;
  }
  document.body.classList.toggle("lineage-window", key === "alerts" && parts[2] === "lineage");
  const hadSession = Boolean(token() || refreshToken());
  if (key === "login") {
    clearAuthentication();
    rememberAuthenticationDestination();
    renderAuthenticationGate("Sign in to access the SOC workspace.");
    return;
  }
  if (!await ensureAuthentication()) {
    rememberAuthenticationDestination();
    renderAuthenticationGate(hadSession ? "Your session expired. Sign in to continue where you left off." : "Sign in to access the SOC workspace.");
    return;
  }
  const nextLiveSession = key === "live-response" && parts[1] && parts[1] !== "new" ? parts[1] : null;
  if (livePresenceSessionId && livePresenceSessionId !== nextLiveSession) closeLivePresence();
  if (key === "alerts" && parts[1] && document.querySelector("[data-queue-alert]")) {
    queueContext = { returnHash: lastRenderedHash || "#/alerts", ids: [...document.querySelectorAll("[data-queue-alert]")].map(x => x.dataset.queueAlert), scrollY, selected: parts[1] };
    sessionStorage.setItem(`soc.queue.${jwtContext().tenant}.${jwtContext().subject}`, JSON.stringify(queueContext));
  }
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  const initial = loadingState(`Loading ${title}`);
  await loadManagedClients();
  const context = jwtContext(), family = pageFamilies.get(key) || "Workspace", crumb = `${family} / ${title}`;
  document.querySelector("#app").innerHTML = `<a class="skip" href="#content">Skip to content</a><div class="shell"><aside><div class="brand"><span>OS</span><div><b>Open Security</b><small>SOC Operations</small></div></div><nav aria-label="Primary">${navGroups.map(([group,items])=>`<div class="nav-group"><h2>${esc(group)}</h2>${items.map(([id,name])=>`<a href="#/${id}" class="${id===key?"active":""}" ${id===key?'aria-current="page"':""}>${esc(name)}</a>`).join("")}</div>`).join("")}</nav><footer><button id="density">Table density</button><button id="theme">${dark ? "Light" : "Dark"} mode</button><a href="#/login" id="signout">Sign out</a></footer></aside><main><header><button class="menu" aria-label="Toggle navigation">☰</button><div class="header-title"><div class="breadcrumbs">${esc(crumb)}</div><h1>${esc(title)}</h1></div><form id="global-search-form" class="global-search" role="search"><label class="sr-only" for="global-search">Search tenant workspace</label><input id="global-search" name="q" maxlength="128" autocomplete="off" placeholder="Search hostname, process, hash, domain, IP, user…  /" value="${key==="search"?esc(new URLSearchParams(location.hash.split("?")[1]||"").get("q")||""):""}"></form><div class="header-actions"><div class="header-control-group connection-context"><span class="header-group-label">Connection</span><span class="environment-status header-control-value">Connected</span></div><div class="header-control-group workspace-controls"><span class="header-group-label">Workspace</span><div class="header-control-row"><button id="activity-open" aria-controls="activity-drawer">Activity</button><button id="command-open" aria-keyshortcuts="Control+K">Quick actions <kbd>Ctrl K</kbd></button></div></div><div class="tenant-context header-control-group"><span class="header-group-label">Account</span><div class="account-control"><strong>${esc(context.subject)}</strong><span title="${esc(context.tenant)}">Tenant ${esc(context.tenant.slice(0,8))}</span></div></div></div></header><section id="content" tabindex="-1">${initial}</section></main></div><aside id="activity-drawer" class="detail-drawer" aria-label="Analyst activity" hidden><h2>Activity</h2><p class="state-banner">Operationally useful activity appears in its authoritative workspace.</p><ul><li><a href="#/playbook-approvals">Pending approvals</a></li><li><a href="#/response-actions">Response operations</a></li><li><a href="#/forensic-collections">Forensic collections</a></li><li><a href="#/update-rollouts">Update rollouts</a></li></ul></aside><dialog id="command-palette" class="command-palette" aria-labelledby="command-title"><form method="dialog"><h2 id="command-title">Quick navigation</h2><label class="sr-only" for="command-input">Filter commands</label><input id="command-input" maxlength="80" autocomplete="off" placeholder="Open alerts, new hunt…"><button value="close">Close</button></form><nav id="command-results" class="command-results" aria-label="Quick navigation results"></nav></dialog><div id="toast-region" class="toast-region" aria-live="polite"></div>`;
  if (managedClients.length) {
    const switcher = document.createElement("label");
    switcher.className = "client-switcher";
    switcher.innerHTML = `<span>Client</span><select id="platform-client" aria-label="Select managed client">${managedClients.map(x => `<option value="${esc(x.clientId)}" ${x.clientId === context.tenant ? "selected" : ""}>${esc(x.name)} · ${x.endpointCount}${x.hasMoreEndpoints ? "+" : ""} endpoint${x.endpointCount === 1 && !x.hasMoreEndpoints ? "" : "s"}</option>`).join("")}</select>`;
    document.querySelector(".tenant-context").before(switcher);
    document.querySelector(".tenant-context").innerHTML = `<span class="header-group-label">Account</span><div class="account-control"><strong>Super admin</strong><span title="${esc(context.subject)}">${esc(context.subject.slice(0, 8))}</span></div>`;
  }
  const environmentStatus = document.querySelector(".environment-status");
  environmentStatus.textContent = token() ? "Connected" : "Authentication required";
  environmentStatus.classList.add(token() ? "healthy" : "degraded");
  document.body.dataset.density = localStorage.getItem("density") || "comfortable";
  installGlobalShell();
  document.querySelector("#platform-client")?.addEventListener("change", (event) => {
    closeLivePresence("analyst switched client");
    sessionStorage.setItem("platform_client_id", event.currentTarget.value);
    queueContext = null;
    endpointDetailContext = null;
    route();
  });
  document.querySelector("#theme").onclick = () => {
    dark = !dark;
    localStorage.setItem("theme", dark ? "dark" : "light");
    route();
  };
  document.querySelector(".skip").onclick = (event) => {
    event.preventDefault();
    document.querySelector("#content").focus();
  };
  document.querySelector(".menu").onclick = () =>
    document.querySelector("aside").classList.toggle("open");
  document.querySelector("#signout").onclick = (event) => {
    event.preventDefault();
    closeLivePresence("analyst signed out");
    clearAuthentication();
    sessionStorage.setItem("post_login_hash", "#/dashboard");
    if (location.hash === "#/login") renderAuthenticationGate("You have signed out.");
    else location.hash = "#/login";
  };
  if (key === "dashboard") document.querySelector("#content").innerHTML = await socDashboardPage();
  if (key === "search") document.querySelector("#content").innerHTML = await unifiedSearchPage();
  if (key === "approvals") document.querySelector("#content").innerHTML = await approvalCenterPage();
  if (key === "endpoints") {
    document.querySelector("#content").innerHTML = parts[1]
      ? await endpointDetail(parts[1])
      : await endpointList();
    if (parts[1]) {
      const endpoint = endpointDetailContext?.id === parts[1]
        ? endpointDetailContext.endpoint
        : (await api(`/api/v1/endpoints/${parts[1]}`)).data;
      await hydrateFileHealth(endpoint);
      await hydrateRegistryHealth(endpoint);
      await hydrateNetworkHealth(endpoint);
      await hydrateDnsHealth(endpoint);
      await hydrateModuleHealth(endpoint);
      await hydratePersistenceHealthV9(endpoint);
      await hydrateIdentityHealth(endpoint);
      await hydrateExecutionHealth(endpoint);
      await hydrateIsolationPanel(endpoint);
      document
        .querySelector("#content")
        ?.insertAdjacentHTML(
          "beforeend",
          `<section aria-labelledby="endpoint-response-title"><h2 id="endpoint-response-title">Endpoint response</h2><p><a class="button" href="#/response-actions/new?endpointId=${endpoint.id}">Request safe action</a> <a href="#/response-actions?endpointId=${endpoint.id}">View action history</a></p></section>`,
        );
      document
        .querySelector("#content")
        ?.insertAdjacentHTML(
          "beforeend",
          `<section aria-labelledby="endpoint-live-title"><h2 id="endpoint-live-title">Secure Live Response</h2><p><a class="button" href="#/live-response/new?endpointId=${endpoint.id}">Open bounded session</a> <a href="#/live-response?endpointId=${endpoint.id}">View session history</a></p></section>`,
        );
      document.querySelector("#content")?.insertAdjacentHTML("beforeend", `<section aria-labelledby="endpoint-forensics-title"><h2 id="endpoint-forensics-title">Remote forensic collection</h2><p><a class="button" href="#/forensic-collections/new?endpointId=${endpoint.id}">Preview bounded collection</a> <a href="#/forensic-collections?endpointId=${endpoint.id}">Collection history</a></p></section>`);
    }
  }
  if (key === "processes") {
    document.querySelector("#content").innerHTML = parts[1]
      ? await processDetail(parts[1], parts[2])
      : await processSearch();
    document
      .querySelector("#process-search")
      ?.addEventListener("submit", (e) => {
        e.preventDefault();
        const q = new URLSearchParams(new FormData(e.target));
        [...q].forEach(([k, v]) => {
          if (!v) q.delete(k);
        });
        location.hash = `#/processes?${q}`;
      });
    document.querySelector("ul.tree")?.setAttribute("role", "tree");
    if (parts[1] && parts[2]) {
      const processDialog = document.querySelector("#process-response-dialog"),
        processOpener = document.querySelector("#process-response-open");
      processOpener?.addEventListener("click", () => processDialog.showModal());
      document.querySelector("#process-response-close")?.addEventListener("click", () => {
        processDialog.close();
        processOpener?.focus();
      });
      document.querySelector("#process-response-form")?.addEventListener("submit", (e) =>
        submitProcessResponse(e, parts[1], parts[2]),
      );
      await hydrateProcessRegistry(parts[1], parts[2]);
      await hydrateProcessNetwork(parts[1], parts[2]);
      await hydrateProcessDns(parts[1], parts[2]);
      await hydrateProcessModules(parts[1], parts[2]);
      await hydrateProcessIdentity(parts[1], parts[2]);
      await hydrateProcessExecution(parts[1], parts[2]);
      document
        .querySelector("#content")
        ?.insertAdjacentHTML(
          "beforeend",
          `<section aria-labelledby="process-live-title"><h2 id="process-live-title">Secure Live Response</h2><p><a class="button" href="#/live-response/new?endpointId=${encodeURIComponent(parts[1])}&entityId=${encodeURIComponent(parts[2])}">Open bounded session from this process</a></p></section>`,
        );
    }
  }
  if (key === "files") {
    document.querySelector("#content").innerHTML = parts[1]
      ? await fileDetail(parts[1], parts[2])
      : await fileSearch();
    document.querySelector("#file-search")?.addEventListener("submit", (e) => {
      e.preventDefault();
      const q = new URLSearchParams(new FormData(e.target));
      [...q].forEach(([k, v]) => {
        if (!v) q.delete(k);
      });
      location.hash = `#/files?${q}`;
    });
    document.querySelector("#file-next")?.addEventListener("click", (e) => {
      const q = new URLSearchParams(location.hash.split("?")[1] || "");
      q.set("cursor", e.currentTarget.dataset.cursor);
      location.hash = `#/files?${q}`;
    });
    document
      .querySelector("#file-export")
      ?.addEventListener("click", exportFiles);
    if (parts[1] && parts[2]) await hydrateFileResponse(parts[1], parts[2]);
  }
  if (key === "quarantines") {
    document.querySelector("#content").innerHTML = parts[1]
      ? await quarantineDetail(parts[1])
      : await quarantineList();
    document.querySelector("#quarantine-restore")?.addEventListener("submit", (event) => restoreQuarantine(event, parts[1]));
  }
  if (key === "persistence-backups") {
    document.querySelector("#content").innerHTML = parts[1]
      ? await persistenceBackupDetail(parts[1])
      : await persistenceBackupList();
    document.querySelector("#persistence-backup-restore")?.addEventListener("submit", (event) => restorePersistenceBackup(event, parts[1]));
  }
  if (key === "registry") {
    document.querySelector("#content").innerHTML = parts[1]
      ? await registryDetail(parts[1])
      : await registrySearch();
    document
      .querySelector("#registry-search")
      ?.addEventListener("submit", (e) => {
        e.preventDefault();
        const q = new URLSearchParams(new FormData(e.target));
        [...q].forEach(([k, v]) => {
          if (!v) q.delete(k);
        });
        location.hash = `#/registry?${q}`;
      });
    document.querySelector("#registry-next")?.addEventListener("click", (e) => {
      const q = new URLSearchParams(location.hash.split("?")[1] || "");
      q.set("cursor", e.currentTarget.dataset.cursor);
      location.hash = `#/registry?${q}`;
    });
    document
      .querySelector("#registry-export")
      ?.addEventListener("click", exportRegistry);
  }
  if (key === "registry-policies") {
    document.querySelector("#content").innerHTML = parts[1]
      ? await registryPolicyEditorPage(parts[1])
      : await registryPolicyList();
    document
      .querySelector("#registry-policy-editor")
      ?.addEventListener("submit", saveRegistryPolicyEditor);
    document
      .querySelector("#registry-exclusion-editor")
      ?.addEventListener("submit", (e) => saveRegistryExclusion(e, parts[1]));
    document
      .querySelector("#registry-policy-assign")
      ?.addEventListener("submit", (e) => assignRegistryPolicy(e, parts[1]));
    document
      .querySelectorAll(".registry-exclusion-delete")
      .forEach((x) =>
        x.addEventListener("click", () =>
          deleteRegistryExclusion(parts[1], x.dataset.rule),
        ),
      );
  }
  if (key === "network" || key === "network-listeners") {
    document.querySelector("#content").innerHTML =
      key === "network" && parts[1]
        ? await networkDetail(parts[1])
        : await networkSearch(key === "network-listeners");
    document
      .querySelector("#network-search")
      ?.addEventListener("submit", (e) => {
        e.preventDefault();
        const q = new URLSearchParams(new FormData(e.target));
        [...q].forEach(([k, v]) => {
          if (!v) q.delete(k);
        });
        location.hash = `#/${key}?${q}`;
      });
    document.querySelector("#network-next")?.addEventListener("click", (e) => {
      const q = new URLSearchParams(location.hash.split("?")[1] || "");
      q.set("cursor", e.currentTarget.dataset.cursor);
      location.hash = `#/${key}?${q}`;
    });
    document
      .querySelector("#network-export")
      ?.addEventListener("click", exportNetwork);
  }
  if (key === "network-policies") {
    document.querySelector("#content").innerHTML = parts[1]
      ? await networkPolicyPage(parts[1])
      : await networkPolicyList();
    document
      .querySelector("#network-policy-editor")
      ?.addEventListener("submit", saveNetworkPolicy);
    document
      .querySelector("#network-exclusion-editor")
      ?.addEventListener("submit", (e) => saveNetworkExclusion(e, parts[1]));
    document
      .querySelectorAll(".network-exclusion-delete")
      .forEach((x) =>
        x.addEventListener("click", () =>
          deleteNetworkExclusion(parts[1], x.dataset.rule),
        ),
      );
  }
  if (key === "dns") {
    document.querySelector("#content").innerHTML = parts[1]
      ? await dnsDetail(parts[1])
      : await dnsSearch();
    document.querySelector("#dns-search")?.addEventListener("submit", (e) => {
      e.preventDefault();
      const q = new URLSearchParams(new FormData(e.target));
      [...q].forEach(([k, v]) => {
        if (!v) q.delete(k);
      });
      location.hash = `#/dns?${q}`;
    });
    document.querySelector("#dns-export")?.addEventListener("click", exportDns);
  }
  if (key === "dns-policies") {
    document.querySelector("#content").innerHTML = parts[1]
      ? await dnsPolicyPage(parts[1])
      : await dnsPolicyList();
    document
      .querySelector("#dns-policy-editor")
      ?.addEventListener("submit", saveDnsPolicy);
    document
      .querySelector("#dns-exclusion-editor")
      ?.addEventListener("submit", (e) => saveDnsExclusion(e, parts[1]));
    document
      .querySelectorAll(".dns-exclusion-delete")
      .forEach((x) =>
        x.addEventListener("click", () =>
          deleteDnsExclusion(parts[1], x.dataset.rule),
        ),
      );
  }
  if (key === "modules" || key === "drivers") {
    document.querySelector("#content").innerHTML =
      key === "modules" && parts[1]
        ? await moduleDetail(parts[1])
        : await moduleSearch(key === "drivers");
    document
      .querySelector("#module-search")
      ?.addEventListener("submit", (e) => {
        e.preventDefault();
        const q = new URLSearchParams(new FormData(e.target));
        [...q].forEach(([k, v]) => {
          if (!v) q.delete(k);
        });
        location.hash = `#/${key}?${q}`;
      });
    document
      .querySelector("#module-export")
      ?.addEventListener("click", exportModules);
  }
  if (key === "module-policies") {
    document.querySelector("#content").innerHTML = parts[1]
      ? await modulePolicyPage(parts[1])
      : await modulePolicyList();
    document
      .querySelector("#module-policy-editor")
      ?.addEventListener("submit", saveModulePolicy);
    document
      .querySelector("#module-policy-assign")
      ?.addEventListener("submit", (e) => assignModulePolicy(e, parts[1]));
    document
      .querySelector("#module-exclusion-editor")
      ?.addEventListener("submit", (e) => saveModuleExclusion(e, parts[1]));
  }
  if (key === "services" || key === "tasks") {
    document.querySelector("#content").innerHTML = parts[1]
      ? await persistenceDetail(key, parts[1])
      : await persistenceSearch(key);
    document
      .querySelector("#persistence-search")
      ?.addEventListener("submit", (e) => {
        e.preventDefault();
        const q = new URLSearchParams(new FormData(e.target));
        [...q].forEach(([name, value]) => {
          if (!value) q.delete(name);
        });
        location.hash = `#/${key}?${q}`;
      });
    document
      .querySelector("#persistence-export")
      ?.addEventListener("click", () => exportPersistence(key));
    if (parts[1]) await hydratePersistenceResponse(key, parts[1]);
  }
  if (key === "persistence-configurations" || key === "wmi-subscriptions") {
    document.querySelector("#content").innerHTML =
      parts[1] && key === "persistence-configurations"
        ? await configurationDetail(parts[1])
        : await configurationSearch(key === "wmi-subscriptions");
    document
      .querySelector("#configuration-search")
      ?.addEventListener("submit", (e) => {
        e.preventDefault();
        const q = new URLSearchParams(new FormData(e.target));
        [...q].forEach(([name, value]) => {
          if (!value) q.delete(name);
        });
        location.hash = `#/${key}?${q}`;
      });
    document
      .querySelector("#configuration-export")
      ?.addEventListener("click", exportConfigurations);
    if (parts[1] && key === "persistence-configurations") await hydratePersistenceResponse(key, parts[1]);
  }
  if (key === "persistence-policies") {
    document.querySelector("#content").innerHTML = parts[1]
      ? await persistencePolicyPageV9(parts[1])
      : await persistencePolicyList();
    document
      .querySelector("#persistence-policy-editor")
      ?.addEventListener("submit", savePersistencePolicy);
    document
      .querySelector("#persistence-policy-assign")
      ?.addEventListener("submit", (e) => assignPersistencePolicy(e, parts[1]));
    document
      .querySelector("#persistence-exclusion-editor")
      ?.addEventListener("submit", (e) =>
        savePersistenceExclusion(e, parts[1]),
      );
  }
  if (key === "identity") {
    document.querySelector("#content").innerHTML = parts[1]
      ? await identityDetail(parts[1])
      : await identitySearch();
    document
      .querySelector("#identity-search")
      ?.addEventListener("submit", (e) => {
        e.preventDefault();
        const q = new URLSearchParams(new FormData(e.target));
        [...q].forEach(([name, value]) => {
          if (!value) q.delete(name);
        });
        location.hash = `#/identity?${q}`;
      });
    document
      .querySelector("#identity-export")
      ?.addEventListener("click", exportIdentity);
  }
  if (key === "identity-policies") {
    document.querySelector("#content").innerHTML =
      parts[1] === "new"
        ? await identityPolicyPage()
        : await identityPolicyList();
    document
      .querySelector("#identity-policy-editor")
      ?.addEventListener("submit", saveIdentityPolicy);
  }
  if (key === "execution") {
    document.querySelector("#content").innerHTML = parts[1]
      ? await executionDetail(parts[1])
      : await executionSearch();
    document
      .querySelector("#execution-search")
      ?.addEventListener("submit", (e) => {
        e.preventDefault();
        const q = new URLSearchParams(new FormData(e.target));
        [...q].forEach(([name, value]) => {
          if (!value) q.delete(name);
        });
        location.hash = `#/execution?${q}`;
      });
    document
      .querySelector("#execution-export")
      ?.addEventListener("click", exportExecution);
  }
  if (key === "execution-policies") {
    document.querySelector("#content").innerHTML =
      parts[1] === "new"
        ? await executionPolicyPage()
        : await executionPolicyList();
    document
      .querySelector("#execution-policy-editor")
      ?.addEventListener("submit", saveExecutionPolicy);
  }
  if (key === "detections") {
    document.querySelector("#content").innerHTML =
      parts[1] === "new"
        ? await detectionEditor()
        : parts[1]
          ? await detectionDetail(parts[1])
          : await detectionList();
    document
      .querySelector("#detection-editor")
      ?.addEventListener("submit", saveDetection);
  }
  if (key === "detection-content") {
    document.querySelector("#content").innerHTML = await detectionContent();
    document.querySelector("#detection-content-filter")?.addEventListener("submit", (e) => {
      e.preventDefault(); const q = new URLSearchParams(new FormData(e.target));
      [...q].forEach(([name, value]) => { if (!value || value === "0") q.delete(name); });
      location.hash = `#/detection-content?${q}`;
    });
  }
  if (key === "findings") {
    document.querySelector("#content").innerHTML = parts[1]
      ? await findingDetail(parts[1])
      : await findingSearch();
    document
      .querySelector("#finding-search")
      ?.addEventListener("submit", (e) => {
        e.preventDefault();
        const q = new URLSearchParams(new FormData(e.target));
        [...q].forEach(([name, value]) => {
          if (!value) q.delete(name);
        });
        location.hash = `#/findings?${q}`;
      });
  }
  if (key === "detection-replay") {
    document.querySelector("#content").innerHTML = await replayPage();
    document
      .querySelector("#replay-form")
      ?.addEventListener("submit", startReplay);
  }
  if (key === "detection-health")
    document.querySelector("#content").innerHTML = await detectionHealth();
  if (key === "correlation-rules")
    document.querySelector("#content").innerHTML = await correlationRules(
      parts[1],
    );
  if (key === "correlated-findings") {
    document.querySelector("#content").innerHTML = await correlatedFindings(
      parts[1],
    );
    document
      .querySelector("#correlation-search")
      ?.addEventListener("submit", (e) => {
        e.preventDefault();
        const q = new URLSearchParams(new FormData(e.target));
        [...q].forEach(([n, v]) => {
          if (!v) q.delete(n);
        });
        location.hash = `#/correlated-findings?${q}`;
      });
  }
  if (key === "correlation-replay") {
    document.querySelector("#content").innerHTML = await correlationReplay();
    document
      .querySelector("#correlation-replay-form")
      ?.addEventListener("submit", startCorrelationReplay);
  }
  if (key === "correlation-health")
    document.querySelector("#content").innerHTML = await correlationHealth();
  if (key === "mitre-coverage")
    document.querySelector("#content").innerHTML = await mitreCoverage();
  if (key === "entity-graph")
    document.querySelector("#content").innerHTML = await entityGraph();
  if (key === "attack-stories")
    document.querySelector("#content").innerHTML = await attackStory();
  if (key === "threat-hunting") {
    document.querySelector("#content").innerHTML = await threatHunting();
    document.querySelector("#hunt-form")?.addEventListener("submit", runHunt);
  }
  if (key === "saved-hunts")
    document.querySelector("#content").innerHTML = await savedHunts();
  if (key === "investigation-health")
    document.querySelector("#content").innerHTML = await investigationHealth();
  if (["entity-graph", "attack-stories"].includes(key))
    document
      .querySelector("#investigation-root")
      ?.addEventListener("submit", (e) => {
        e.preventDefault();
        const q = new URLSearchParams(new FormData(e.target));
        location.hash = `#/${key}?${q}`;
      });
  if (key === "alerts") {
    const lineageView = parts[1] && parts[2] === "lineage";
    document.querySelector("#content").innerHTML = lineageView
      ? await alertLineageWindow(parts[1])
      : parts[1] ? await alertDetailPageV2(parts[1])
      : await alertQueue();
    if (lineageView) installLineageStudioControls();
    if (!lineageView) {
    document.querySelector("#alert-filter")?.addEventListener("submit", (e) => {
      e.preventDefault();
      const q = new URLSearchParams(new FormData(e.target));
      [...q].forEach(([n, v]) => {
        if (!v) q.delete(n);
      });
      location.hash = `#/alerts?${q}`;
    });
    document.querySelector("#alert-next")?.addEventListener("click", (e) => {
      const q = new URLSearchParams(location.hash.split("?")[1] || "");
      q.set("cursor", e.currentTarget.dataset.cursor);
      location.hash = `#/alerts?${q}`;
    });
    document
      .querySelector("#alert-bulk")
      ?.addEventListener("click", openAlertBulk);
    document
      .querySelector("#bulk-form")
      ?.addEventListener("submit", submitAlertBulk);
    document
      .querySelector("#save-alert-filter")
      ?.addEventListener("submit", saveAlertFilter);
    document
      .querySelector("#alert-assignment")
      ?.addEventListener("submit", (e) =>
        submitAlertAction(e, parts[1], "assignment"),
      );
    document
      .querySelector("#alert-status")
      ?.addEventListener("submit", (e) =>
        submitAlertAction(e, parts[1], "status"),
      );
    document
      .querySelector("#alert-note")
      ?.addEventListener("submit", (e) =>
        submitAlertAction(e, parts[1], "note"),
      );
    if (parts[1]) {
      document.querySelector("#content")?.insertAdjacentHTML("beforeend", `<section aria-labelledby="alert-ai-title"><h2 id="alert-ai-title">Evidence-grounded AI investigation</h2><p><a class="button" href="#/ai-investigation?contextType=alert&contextId=${encodeURIComponent(parts[1])}">Start read-only analysis from this alert</a></p></section>`);
      const [evidence, pivots] = await Promise.all([
          api(`/api/v1/alerts/${parts[1]}/evidence`),
          api(`/api/v1/alerts/${parts[1]}/pivots`),
        ]),
        endpoint = pivots.data.endpoint?.split("/").pop(),
        entity = evidence.data.processEntities?.[0];
      document
        .querySelector("#content")
        ?.insertAdjacentHTML(
          "beforeend",
          `<section aria-labelledby="alert-response-title"><h2 id="alert-response-title">Endpoint response</h2><p><a class="button" href="#/response-actions/new?alertId=${parts[1]}">Request safe action from this alert</a>${endpoint && entity ? ` · <a class="button" href="#/processes/${endpoint}/${encodeURIComponent(entity)}?alertId=${parts[1]}">Open exact process response</a>` : ""}</p></section>`,
        );
    }
    if (parts[1])
      document
        .querySelector("#content")
        ?.insertAdjacentHTML(
          "beforeend",
          `<section aria-labelledby="alert-live-title"><h2 id="alert-live-title">Secure Live Response</h2><p><a class="button" href="#/live-response/new?alertId=${parts[1]}">Open bounded session from this alert</a></p></section>`,
        );
    if (parts[1]) {
      await hydrateLiveResponseContext("alert", parts[1]);
      await hydrateForensicCollectionContext("alert", parts[1]);
      await hydrateContainmentContext("alert", parts[1]);
      await hydrateProcessResponseContext("alert", parts[1]);
      await hydrateFileResponseContext("alert", parts[1]);
    }
    }
  }
  if (key === "incidents") {
    document.querySelector("#content").innerHTML = parts[1]
      ? await incidentDetailPage(parts[1])
      : await incidentQueue();
    document
      .querySelector("#incident-filter")
      ?.addEventListener("submit", (e) => {
        e.preventDefault();
        const q = new URLSearchParams(new FormData(e.target));
        [...q].forEach(([n, v]) => {
          if (!v) q.delete(n);
        });
        location.hash = `#/incidents?${q}`;
      });
    document
      .querySelector("#incident-create")
      ?.addEventListener("submit", createIncidentUi);
    document
      .querySelector("#incident-assignment")
      ?.addEventListener("submit", (e) =>
        submitIncidentAction(e, parts[1], "assignment"),
      );
    document
      .querySelector("#incident-status")
      ?.addEventListener("submit", (e) =>
        submitIncidentAction(e, parts[1], "status"),
      );
    document
      .querySelector("#incident-note")
      ?.addEventListener("submit", (e) =>
        submitIncidentAction(e, parts[1], "note"),
      );
    if (parts[1]) {
      document.querySelector("#content")?.insertAdjacentHTML("beforeend", `<section aria-labelledby="incident-ai-title"><h2 id="incident-ai-title">Evidence-grounded AI investigation</h2><p><a class="button" href="#/ai-investigation?contextType=incident&contextId=${encodeURIComponent(parts[1])}">Start read-only analysis from this incident</a></p></section>`);
      const incident = (await api(`/api/v1/incidents/${parts[1]}`)).data,
        endpoint = incident.endpointIds?.[0],
        entity = incident.processEntities?.[0];
      document
        .querySelector("#content")
        ?.insertAdjacentHTML(
          "beforeend",
          `<section aria-labelledby="incident-response-title"><h2 id="incident-response-title">Endpoint response</h2><p><a class="button" href="#/response-actions/new?incidentId=${parts[1]}">Request safe action from this incident</a>${endpoint && entity ? ` · <a class="button" href="#/processes/${endpoint}/${encodeURIComponent(entity)}?incidentId=${parts[1]}">Open exact process response</a>` : ""}</p></section>`,
        );
    }
    if (parts[1])
      document
        .querySelector("#content")
        ?.insertAdjacentHTML(
          "beforeend",
          `<section aria-labelledby="incident-live-title"><h2 id="incident-live-title">Secure Live Response</h2><p><a class="button" href="#/live-response/new?incidentId=${parts[1]}">Open bounded session from this incident</a></p></section>`,
        );
    if (parts[1]) {
      await hydrateLiveResponseContext("incident", parts[1]);
      await hydrateForensicCollectionContext("incident", parts[1]);
      await hydrateContainmentContext("incident", parts[1]);
      await hydrateProcessResponseContext("incident", parts[1]);
      await hydrateFileResponseContext("incident", parts[1]);
    }
  }
  if (key === "triage-health")
    document.querySelector("#content").innerHTML = await triageHealth();
  if (key === "response-actions") {
    document.querySelector("#content").innerHTML =
      parts[1] === "new"
        ? await responseRequestPage()
        : parts[1]
          ? await responseActionDetail(parts[1])
          : await responseActionList();
    document
      .querySelector("#response-request")
      ?.addEventListener("submit", submitResponseRequest);
    document
      .querySelector("#response-approve")
      ?.addEventListener("submit", (e) =>
        responseDecision(e, parts[1], "approve"),
      );
    document
      .querySelector("#response-reject")
      ?.addEventListener("submit", (e) =>
        responseDecision(e, parts[1], "reject"),
      );
    document
      .querySelector("#response-cancel")
      ?.addEventListener("submit", (e) =>
        responseDecision(e, parts[1], "cancel"),
      );
  }
  if (key === "response-health")
    document.querySelector("#content").innerHTML = await responseHealthPage();
  if (key === "dfir-workspace") {
    const evidenceId = parts[2] === "evidence" ? parts[3] : null;
    document.querySelector("#content").innerHTML = await dfirWorkspacePage(parts[1], evidenceId);
    if (evidenceId) {
      const holds = (await api(`/api/v1/investigations/${parts[1]}/holds`)).data.filter(x => String(x.targetId).toLowerCase() === evidenceId.toLowerCase());
      document.querySelector("#evidence-tags")?.closest("section")?.insertAdjacentHTML("beforeend", `<h3>Evidence retention hold</h3><p>${holds.length ? `${holds.length} hold(s) recorded; latest: ${esc(holds[0].reason)}` : "No evidence-specific hold."}</p>${holds.filter(x => x.active).map(x => `<p>Active since ${new Date(x.createdAt).toLocaleString()}${x.expiresAt ? ` · expires ${new Date(x.expiresAt).toLocaleString()}` : " · no automatic expiry"} <button class="evidence-hold-release" data-hold="${esc(x.holdId)}">Release hold</button></p>`).join("")}<form id="evidence-hold"><label>Hold reason <input name="reason" required maxlength="1024"></label><button>Apply evidence hold</button></form>`);
    }
    document.querySelector("#dfir-create")?.addEventListener("submit", dfirCreate);
    document.querySelector("#dfir-evidence-search")?.addEventListener("submit", event => { event.preventDefault(); const q = new URLSearchParams(new FormData(event.currentTarget)); [...q].forEach(([name,value]) => { if (!value) q.delete(name); }); q.set("view", "evidence"); location.hash = `#/dfir-workspace/${parts[1]}?${q}`; });
    document.querySelector("#dfir-import")?.addEventListener("submit", event => { event.preventDefault(); const collection = new FormData(event.currentTarget).get("collectionId"); dfirPost(`/api/v1/investigations/${parts[1]}/collections/${collection}:import`, {}); });
    document.querySelector("#dfir-hold")?.addEventListener("submit", event => { event.preventDefault(); dfirPost(`/api/v1/investigations/${parts[1]}:hold`, { reason: new FormData(event.currentTarget).get("reason") }); });
    document.querySelector("#dfir-ai")?.addEventListener("click", () => dfirPost(`/api/v1/investigations/${parts[1]}/ai-summary`, {}));
    document.querySelector("#dfir-note")?.addEventListener("submit", event => { event.preventDefault(); dfirPost(`/api/v1/investigations/${parts[1]}/notes`, { targetType: "investigation", targetId: parts[1], body: new FormData(event.currentTarget).get("body"), aiDraft: false, accepted: false, evidenceCitations: [] }); });
    document.querySelector("#dfir-export")?.addEventListener("submit", event => { event.preventDefault(); const evidenceIds = [...document.querySelectorAll(".dfir-export-item:checked")].map(x => x.value), reason = new FormData(event.currentTarget).get("reason"); dfirPost(`/api/v1/investigations/${parts[1]}/exports`, { evidenceIds, reason }, "dfir-export-status"); });
    document.querySelector("#evidence-tags")?.addEventListener("submit", event => { event.preventDefault(); const tags = String(new FormData(event.currentTarget).get("tags") || "").split(",").map(x => x.trim()).filter(Boolean); dfirPost(`/api/v1/investigations/${parts[1]}/evidence/${evidenceId}:tag`, { tags }, "evidence-action-status"); });
    document.querySelector("#evidence-parse")?.addEventListener("submit", event => { event.preventDefault(); dfirPost(`/api/v1/forensics/evidence/${evidenceId}:parse`, Object.fromEntries(new FormData(event.currentTarget)), "evidence-action-status"); });
    document.querySelector("#evidence-hold")?.addEventListener("submit", event => { event.preventDefault(); dfirPost(`/api/v1/investigations/${parts[1]}/evidence/${evidenceId}:hold`, { reason: new FormData(event.currentTarget).get("reason") }, "evidence-action-status"); });
    document.querySelectorAll(".evidence-hold-release").forEach(button => button.addEventListener("click", () => dfirPost(`/api/v1/investigations/${parts[1]}/holds/${button.dataset.hold}:release`, {}, "evidence-action-status")));
    document.querySelectorAll(".evidence-verify").forEach(button => button.addEventListener("click", () => dfirPost(`/api/v1/forensics/evidence/${button.dataset.evidence}:verify`, {}, "evidence-action-status")));
    document.querySelectorAll(".evidence-bookmark").forEach(button => button.addEventListener("click", () => dfirPost(`/api/v1/investigations/${parts[1]}/evidence/${button.dataset.evidence}:bookmark`, { purpose: "report" }, "evidence-action-status")));
    document.querySelectorAll(".evidence-download").forEach(button => button.addEventListener("click", () => dfirDownload(`/api/v1/forensics/evidence/${button.dataset.evidence}/download`, `evidence-${button.dataset.evidence}`).catch(error => window.alert(error.message))));
    document.querySelectorAll(".dfir-export-download").forEach(button => button.addEventListener("click", () => dfirDownload(`/api/v1/forensics/exports/${button.dataset.export}/download`, `evidence-package-${button.dataset.export}.zip`).catch(error => window.alert(error.message))));
    document.querySelectorAll('a[href*="/api/v1/forensics/exports/"][href$="/manifest"]').forEach(link => link.addEventListener("click", event => { event.preventDefault(); const id = link.href.split("/").at(-2); dfirDownload(`/api/v1/forensics/exports/${id}/manifest`, `evidence-package-${id}.manifest.json`).catch(error => window.alert(error.message)); }));
  }
  if (key === "forensic-collections") {
    document.querySelector("#content").innerHTML = parts[1] === "new" ? await forensicWizard() : parts[1] ? await forensicDetail(parts[1]) : await forensicList();
    if (parts[1] && parts[1] !== "new") await hydrateForensicTransfers();
    document.querySelector("#forensic-wizard")?.addEventListener("submit", previewForensic);
    document.querySelector("#forensic-approve")?.addEventListener("submit", (event) => forensicDecision(event, parts[1], "approve"));
    document.querySelector("#forensic-cancel")?.addEventListener("submit", (event) => forensicDecision(event, parts[1], "cancel"));
    document.querySelector("#forensic-refresh")?.addEventListener("click", route);
    document.querySelector("#forensic-manifest")?.addEventListener("click", (event) => downloadForensicManifest(event.currentTarget.dataset.collection).catch((error) => window.alert(error.message)));
    document.querySelectorAll(".forensic-download").forEach((button) => button.addEventListener("click", () => downloadForensic(button.dataset.collection, button.dataset.item).catch((error) => window.alert(error.message))));
  }
  if (key === "forensic-collection-health") document.querySelector("#content").innerHTML = await forensicHealthPage();
  if (key === "forensic-tools") {
    document.querySelector("#content").innerHTML = await forensicToolsPage();
    document.querySelector("#tool-package-upload")?.addEventListener("submit", uploadForensicTool);
  }
  if (key === "intelligence") {
    document.querySelector("#content").innerHTML = parts[1] ? await intelligenceDetail(parts[1]) : await intelligencePage();
    document.querySelector("#intel-source")?.addEventListener("submit", createIntelSource);
    document.querySelector("#intel-import")?.addEventListener("submit", importIntel);
    document.querySelector("#ioc-search")?.addEventListener("submit", (event) => { event.preventDefault(); const query = new FormData(event.currentTarget).get("query"); location.hash = `#/intelligence?query=${encodeURIComponent(query || "")}`; route(); });
  }
  if (key === "intelligence-matches") document.querySelector("#content").innerHTML = await intelligenceMatches();
  if (key === "intelligence-health") document.querySelector("#content").innerHTML = await intelligenceHealth();
  if (key === "tunnels") {
    document.querySelector("#content").innerHTML = await tunnelPage(parts[1]);
    document.querySelector("#tunnel-search")?.addEventListener("submit", (event) => { event.preventDefault(); const q=new URLSearchParams(new FormData(event.currentTarget)); [...q].forEach(([n,v])=>{if(!v)q.delete(n)}); location.hash=`#/tunnels?${q}`; });
    document.querySelector("#tunnel-exclusion")?.addEventListener("submit", createTunnelExclusion);
  }
  if (key === "tunnel-rules") document.querySelector("#content").innerHTML = await tunnelRulesPage();
  if (key === "tunnel-health") document.querySelector("#content").innerHTML = await tunnelHealthPage();
  if (key === "playbooks") {
    document.querySelector("#content").innerHTML = await playbooksPage(parts[1], parts[2]);
    document.querySelector("#playbook-editor")?.addEventListener("submit", createPlaybook);
  }
  if (key === "playbook-executions") document.querySelector("#content").innerHTML = await playbookExecutionsPage(parts[1]);
  if (key === "playbook-approvals") {
    document.querySelector("#content").innerHTML = await playbookApprovalsPage();
    document.querySelectorAll(".playbook-approval").forEach((form) => form.addEventListener("submit", decidePlaybookApproval));
  }
  if (key === "playbook-health") document.querySelector("#content").innerHTML = await playbookHealthPage();
  if (key === "self-protection") {
    document.querySelector("#content").innerHTML = await selfProtectionPage();
    document.querySelector("#protection-maintenance")?.addEventListener("submit", requestProtectionMaintenance);
    document.querySelector("#protection-approval")?.addEventListener("submit", approveProtectionMaintenance);
    document.querySelector("#protection-verify")?.addEventListener("click", async (event) => {
      const status=document.querySelector("#protection-status");
      try { const value=(await api(`/api/v1/endpoints/${event.currentTarget.dataset.endpoint}/self-protection:verify`,{method:"POST"})).data; status.textContent=`Verification request: ${value.result}. Stale: ${value.stale}.`; }
      catch(error){ status.textContent=error.message; }
      status.focus();
    });
    document.querySelectorAll(".protection-repair").forEach((button)=>button.addEventListener("click",()=>requestProtectionRepair(button)));
  }
  if (key === "fleet") document.querySelector("#content").innerHTML = await fleetPage(parts[1]);
  if (key === "resilience") document.querySelector("#content").innerHTML = await resiliencePage();
  if (key === "retention") {
    document.querySelector("#content").innerHTML = await retentionPage();
    document.querySelector("#retention-policy-form")?.addEventListener("submit", saveRetentionPolicy);
    document.querySelectorAll(".retention-preview").forEach((button)=>button.addEventListener("click",()=>previewRetention(button)));
  }
  if (key === "capacity") {
    document.querySelector("#content").innerHTML = await capacityPage();
    document.querySelector("#capacity-planner")?.addEventListener("submit", calculateCapacity);
  }
  if (key === "ai-investigation") {
    document.querySelector("#content").innerHTML = await aiInvestigationPage(parts[1]);
    if (!parts[1]) { const q=new URLSearchParams(location.hash.split("?")[1]||""),form=document.querySelector("#ai-conversation-form"); if(form){if(q.get("contextType"))form.elements.contextType.value=q.get("contextType");if(q.get("contextId"))form.elements.contextId.value=q.get("contextId");} }
    document.querySelector("#ai-conversation-form")?.addEventListener("submit", createAiConversation);
    document.querySelector("#ai-analysis-form")?.addEventListener("submit", (event)=>analyzeAi(event,parts[1]));
    document.querySelectorAll(".ai-citation").forEach((button)=>button.addEventListener("click",()=>resolveAiCitation(button)));
    document.querySelectorAll(".ai-note-draft").forEach((button)=>button.addEventListener("click",()=>draftAiNote(button,parts[1])));
  }
  if (key === "detection-engineering") {
    document.querySelector("#content").innerHTML = await aiEngineeringPage(parts[1]);
    document.querySelector("#ai-hunt-form")?.addEventListener("submit",createAiHunt);
    document.querySelector("#ai-detection-draft-form")?.addEventListener("submit",(event)=>createAiRuleDraft(event,false));
    document.querySelector("#ai-correlation-draft-form")?.addEventListener("submit",(event)=>createAiRuleDraft(event,true));
    document.querySelector(".ai-draft-save")?.addEventListener("click",(event)=>decideAiDraft(event.currentTarget,"save"));
    document.querySelector(".ai-draft-reject")?.addEventListener("click",(event)=>decideAiDraft(event.currentTarget,"reject"));
    document.querySelector("#ai-simulation-form")?.addEventListener("submit",simulateAiDraft);
    if(parts[1]) await installAiComparison(parts[1]); else await installAiInventory();
  }
  if (key === "agent-update-packages") document.querySelector("#content").innerHTML = await updatePackagesPage(parts[1]);
  if (key === "update-rollouts") {
    document.querySelector("#content").innerHTML = await updateRolloutsPage(parts[1]);
    document.querySelectorAll(".rollout-transition").forEach((form)=>form.addEventListener("submit",rolloutTransition));
  }
  if (key === "update-policies") document.querySelector("#content").innerHTML = await updatePoliciesPage();
  if (key === "live-response") {
    document.querySelector("#content").innerHTML =
      parts[1] === "new"
        ? await liveResponseRequest()
        : parts[1]
          ? await liveResponseDetail(parts[1])
          : await liveResponseList();
    if (parts[1] && parts[1] !== "new") installLiveConsoleLayout();
    document
      .querySelector("#live-session-request")
      ?.addEventListener("submit", submitLiveSession);
    document
      .querySelector("#live-approve")
      ?.addEventListener("submit", (e) => liveDecision(e, parts[1], "approve"));
    document
      .querySelector("#live-reject")
      ?.addEventListener("submit", (e) => liveDecision(e, parts[1], "reject"));
    document
      .querySelector("#live-close")
      ?.addEventListener("submit", (e) => liveDecision(e, parts[1], "close"));
    document
      .querySelector("#live-command")
      ?.addEventListener("submit", (e) => submitLiveCommand(e, parts[1]));
    document.querySelectorAll(".live-client").forEach((button) => button.addEventListener("click", () => {
      if (button.dataset.client === jwtContext().tenant) return;
      sessionStorage.setItem("platform_client_id", button.dataset.client); route();
    }));
    document.querySelectorAll(".live-endpoint-open").forEach((button) => button.addEventListener("click", openLiveEndpoint));
    document.querySelector("#live-disconnect")?.addEventListener("click", () => {
      closeLivePresence("analyst ended Live Response"); location.hash = "#/live-response";
    });
    const isolationDialog = document.querySelector("#live-isolation-dialog");
    document.querySelector("#live-isolation")?.addEventListener("click", (event) => {
      const lifting = event.currentTarget.dataset.operation === "unisolate";
      isolationDialog.querySelector("h2").textContent = lifting ? "Lift network isolation" : "Isolate endpoint";
      isolationDialog.querySelector("p").textContent = lifting ? "Restore normal network access while preserving the management channel and audit history." : "Block non-management network traffic while keeping this Live Response channel available.";
      const submit = isolationDialog.querySelector('button[type="submit"]'); submit.textContent = lifting ? "Lift isolation" : "Isolate endpoint"; submit.className = lifting ? "primary" : "danger";
      isolationDialog.showModal(); isolationDialog.querySelector("textarea").focus();
    });
    document.querySelector("#live-isolation-cancel")?.addEventListener("click", () => isolationDialog?.close());
    document.querySelector("#live-isolation-form")?.addEventListener("submit", (event) => submitLiveIsolation(event, document.querySelector("#live-isolation")?.closest(".live-console-workspace")?.querySelector(".live-facts > div:last-child code")?.textContent.trim() || ""));
    document.querySelector('#live-command textarea')?.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); event.currentTarget.form.requestSubmit(); }
    });
    document.querySelector("#live-refresh")?.addEventListener("click", route);
    document
      .querySelector("#live-transcript-export")
      ?.addEventListener("click", () => exportLiveTranscript(parts[1]));
    document
      .querySelectorAll(".live-cancel")
      .forEach((x) =>
        x.addEventListener("click", () =>
          cancelLiveCommand(parts[1], x.dataset.command),
        ),
      );
    document.querySelectorAll(".live-artifact").forEach((x) =>
      x.addEventListener("click", (e) => {
        e.preventDefault();
        downloadLiveArtifact(x.dataset.id).catch((error) =>
          window.alert(error.message),
        );
      }),
    );
    if (parts[1] && parts[1] !== "new") {
      try {
        const session = (
          await api(`/api/v1/live-response/sessions/${parts[1]}`)
        ).data;
        startLiveRuntime(session);
        renderLiveTerminal(document.querySelector("#live-terminal"), session.commands || [], session.workingDirectory, true);
        renderLiveTransferPanel(session);
        document.querySelector('#live-command textarea')?.focus();
      } catch {
        /* detail already presents the error */
      }
    }
  }
  if (key === "live-response-health")
    document.querySelector("#content").innerHTML =
      await liveResponseHealthPage();
  if (key === "file-policies") {
    document.querySelector("#content").innerHTML = !parts[1]
      ? await filePolicyList()
      : parts[1] === "new" || parts[2] === "edit"
        ? await filePolicyEditor(parts[1] === "new" ? null : parts[1])
        : await filePolicyDetail(parts[1]);
    document
      .querySelector("#add-file-exclusion")
      ?.addEventListener("click", () =>
        document
          .querySelector("#file-exclusion-rows")
          .insertAdjacentHTML("beforeend", fileExclusionRow()),
      );
    document
      .querySelector("#file-policy-editor")
      ?.addEventListener("submit", saveFilePolicy);
    document
      .querySelector("#file-policy-assign")
      ?.addEventListener("submit", (e) => assignFilePolicy(e, parts[1]));
    document
      .querySelectorAll(".file-rollback")
      .forEach((x) => x.addEventListener("click", () => openFileRollback(x)));
    document
      .querySelector("#file-rollback-confirm")
      ?.addEventListener("click", executeFileRollback);
    document
      .querySelector("#file-rollback-cancel")
      ?.addEventListener("click", () => {
        const d = document.querySelector("#file-rollback-dialog");
        d.close();
        d._trigger?.focus();
      });
  }
  enableTreeKeyboard();
  if (key === "administration-governance") {
    document.querySelector("#content").innerHTML = await enterpriseAdministrationPage();
    installEnterpriseAdministration();
  }
  if (key === "administration") {
    document.querySelector("#content").innerHTML = await administration();
    document
      .querySelector("#token-create")
      ?.addEventListener("submit", createToken);
  }
  if (key === "policies") {
    document.querySelector("#content").innerHTML = !parts[1]
      ? await policyList()
      : parts[1] === "new" || parts[2] === "edit"
        ? await policyEditor(parts[1] === "new" ? null : parts[1])
        : await policyDetail(parts[1]);
    document
      .querySelector("#policy-filter")
      ?.addEventListener("input", (e) =>
        document
          .querySelectorAll("#policy-table tbody tr")
          .forEach(
            (r) =>
              (r.hidden = !r.dataset.search.includes(
                e.target.value.toLowerCase(),
              )),
          ),
      );
    document
      .querySelector("#add-exclusion")
      ?.addEventListener("click", () =>
        document
          .querySelector("#exclusion-rows")
          .insertAdjacentHTML("beforeend", exclusionRow()),
      );
    document
      .querySelector("#policy-editor")
      ?.addEventListener("submit", savePolicy);
    document
      .querySelector("#policy-assign")
      ?.addEventListener("submit", (e) => assignPolicy(e, parts[1]));
    document
      .querySelector("#rollback-confirm")
      ?.addEventListener("click", executeRollback);
    document
      .querySelector("#rollback-cancel")
      ?.addEventListener("click", () =>
        document.querySelector("#rollback-dialog").close(),
      );
  }
  if (key === "operations") {
    document.querySelector("#content").innerHTML = operations();
    document
      .querySelector("#projection-rebuild")
      ?.addEventListener("click", rebuildProjection);
  }
  document
    .querySelector("#process-export")
    ?.addEventListener("click", exportProcesses);
  enhanceCoreWorkspace(key, parts);
  enhanceInformationArchitecture(key, parts);
  installAnalystKeyboard();
  if (thisRoute === routeSequence) {
    const context = jwtContext(), recentKey = `soc.recent-workspaces.${context.tenant}.${context.subject}`;
    let recent = [];
    try { recent = JSON.parse(localStorage.getItem(recentKey) || "[]"); } catch { /* replace invalid local preference below */ }
    recent = [key, ...recent.filter(x => x !== key && pages[x])].slice(0, 5);
    localStorage.setItem(recentKey, JSON.stringify(recent));
    if (pendingScrollRestore !== null) {
      const y = pendingScrollRestore; pendingScrollRestore = null;
      requestAnimationFrame(() => scrollTo({ top: y, behavior: "instant" }));
    }
    lastRenderedHash = location.hash || "#/dashboard";
  }
}
const runRoute = () => route().catch(error => {
  if (error?.message === CANCELLED_NAVIGATION || error?.message === AUTHENTICATION_REQUIRED || error?.name === "AbortError") return;
  const host = document.querySelector("#content");
  if (host) host.innerHTML = state("Workspace unavailable", error.message);
});
addEventListener("hashchange", runRoute);
addEventListener("pagehide", () => closeLivePresence("analyst left Live Response"));
Object.assign(window, {
  endpointAction,
  revokeToken,
  rollbackPolicy,
  enableTreeKeyboard,
});
runRoute();
