const state = {
  user: null,
  documents: [],
  events: [],
  filter: "all",
  search: "",
  activeDocument: null,
  csrf: "",
  auditIntegrity: { valid: true, events_checked: 0 },
};

const byId = (id) => document.getElementById(id);
const esc = (value = "") => String(value).replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[char]));

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (state.csrf && options.method && options.method !== "GET") headers.set("X-CSRF-Token", state.csrf);
  const response = await fetch(path, { credentials: "same-origin", ...options, headers });
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json") ? await response.json() : await response.text();
  if (!response.ok) {
    const detail = typeof payload === "object" && payload ? payload.detail : payload;
    throw new Error(detail || `Request failed (${response.status})`);
  }
  return payload;
}

async function refreshCsrf() {
  const result = await api("/api/csrf");
  state.csrf = result.csrf_token;
}

function toast(message, error = false) {
  const item = document.createElement("div");
  item.className = `toast${error ? " error" : ""}`;
  item.textContent = message;
  byId("toast-region").append(item);
  window.setTimeout(() => item.remove(), 3600);
}

function initials(name) {
  return name.split(/\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase();
}

function formatDate(value, includeTime = false) {
  if (!value) return "Never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  const options = includeTime
    ? { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }
    : { month: "short", day: "numeric" };
  return new Intl.DateTimeFormat(undefined, options).format(date);
}

function relativeDate(value) {
  if (!value) return "No requests";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return "Just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function bytesLabel(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function renderLogin() {
  byId("login-view").hidden = false;
  byId("app-shell").hidden = true;
}

function renderApp() {
  byId("login-view").hidden = true;
  byId("app-shell").hidden = false;
  byId("account-name").textContent = state.user.name;
  byId("account-role").textContent = state.user.role === "admin" ? "Administrator" : "Member";
  byId("account-avatar").textContent = initials(state.user.name);
  byId("topbar-date").textContent = new Intl.DateTimeFormat(undefined, { weekday: "short", month: "short", day: "numeric" }).format(new Date()).toUpperCase();
  document.querySelector('[data-view="activity"]').hidden = state.user.role !== "admin";
  byId("view-all-activity").hidden = state.user.role !== "admin";
  byId("audit-integrity-button").hidden = state.user.role !== "admin";
  const passwordDialog = byId("security-dialog");
  const forcedPasswordChange = state.user.must_change_password;
  passwordDialog.querySelectorAll(".close-dialog, #password-cancel").forEach((button) => {
    button.hidden = forcedPasswordChange;
  });
  if (forcedPasswordChange && !passwordDialog.open) passwordDialog.showModal();
  if (state.user.role !== "admin" && document.querySelector('[data-view="activity"]').classList.contains("is-active")) setView("documents");
}

function visibleDocuments() {
  return state.documents.filter((document) => {
    const matchesFilter = state.filter === "all"
      || (state.filter === "owned" && document.access === "owner")
      || (state.filter === "shared" && document.access === "shared");
    const needle = state.search.trim().toLowerCase();
    const matchesSearch = !needle || `${document.title} ${document.filename} ${document.owner_name}`.toLowerCase().includes(needle);
    return matchesFilter && matchesSearch;
  });
}

function renderDocuments() {
  const owned = state.documents.filter((document) => document.access === "owner");
  const shared = state.documents.filter((document) => document.access === "shared");
  const grants = owned.reduce((total, document) => total + (document.shared_count || 0), 0);
  const latestAccess = state.documents.map((document) => document.last_accessed).filter(Boolean).sort().at(-1);
  byId("metric-total").textContent = state.documents.length;
  byId("metric-shared").textContent = shared.length;
  byId("metric-grants").textContent = grants;
  byId("metric-last-access").textContent = relativeDate(latestAccess);
  byId("nav-document-count").textContent = state.documents.length;
  byId("count-all").textContent = state.documents.length;

  const docs = visibleDocuments();
  byId("document-list").innerHTML = docs.map((document) => {
    const extension = document.filename.split(".").pop().slice(0, 4).toUpperCase();
    const isOwner = document.access === "owner";
    const sharedCell = isOwner ? document.shared_count : "—";
    const accessBadge = `<span class="access-badge${isOwner ? "" : " shared"}">${isOwner ? "Owner" : "Shared"}</span>`;
    const controls = isOwner
      ? `<button class="icon-button" type="button" data-action="share" data-id="${esc(document.id)}" title="Manage access" aria-label="Manage access for ${esc(document.title)}">···</button>`
      : "";
    return `<article class="document-row">
      <div class="document-main"><span class="file-icon type-${esc(extension.toLowerCase())}">${esc(extension)}</span><div class="file-copy"><strong>${esc(document.title)}</strong><span>${esc(document.filename)} · ${bytesLabel(document.byte_size)} · ${isOwner ? "You" : `From ${esc(document.owner_name)}`}</span></div></div>
      ${accessBadge}<span class="shared-count">${sharedCell}</span><span class="last-request">${relativeDate(document.last_accessed)}</span>
      <div class="row-actions">${controls}<button class="icon-button download-button" type="button" data-action="download" data-id="${esc(document.id)}" title="Download document" aria-label="Download ${esc(document.title)}">↓</button></div>
    </article>`;
  }).join("");
  byId("empty-state").hidden = docs.length !== 0;
  byId("list-summary").textContent = `${docs.length} ${docs.length === 1 ? "document" : "documents"}`;
}

const actionCopy = {
  "auth.login": ["Signed in", "◉", ""],
  "auth.logout": ["Signed out", "↗", ""],
  "auth.login_failed": ["Sign-in failed", "!", "denied"],
  "document.uploaded": ["Document uploaded", "+", ""],
  "document.read": ["File requested", "↓", ""],
  "document.access_denied": ["Access denied", "!", "denied"],
  "document.shared": ["Access granted", "+", "share"],
  "document.share_revoked": ["Access revoked", "−", "revoke"],
};

function eventLabel(event) {
  return (actionCopy[event.action] || [event.action, "·", ""])[0];
}

function renderRecentActivity() {
  const events = state.events.slice(0, 5);
  byId("recent-activity").innerHTML = events.map((event) => {
    const [label, symbol, className] = actionCopy[event.action] || [event.action, "·", ""];
    return `<article class="activity-item"><span class="activity-mark ${className}">${symbol}</span><div class="activity-copy"><strong>${esc(label)}</strong><p>${esc(event.document_title || event.actor_email)}</p><time>${formatDate(event.occurred_at, true)}</time></div></article>`;
  }).join("") || `<div class="empty-state"><span>No recorded activity yet.</span></div>`;
}

function renderAudit() {
  const rows = state.events;
  byId("audit-list").innerHTML = rows.map((event) => {
    const isDenied = event.action.includes("denied") || event.action.includes("failed");
    const [, symbol] = actionCopy[event.action] || [event.action, "·"];
    return `<article class="audit-row"><span class="audit-action"><span class="audit-action-mark${isDenied ? " denied" : ""}">${symbol}</span>${esc(eventLabel(event))}</span><span class="audit-actor">${esc(event.actor_email)}</span><span>${esc(event.document_title || "—")}</span><time class="audit-time">${formatDate(event.occurred_at, true)}</time><code class="audit-hash" title="${esc(event.event_hash)}">${esc(event.event_hash.slice(0, 12))}…</code></article>`;
  }).join("") || `<div class="audit-empty">No events recorded yet.</div>`;
  byId("audit-event-total").textContent = `${state.auditIntegrity.events_checked} EVENTS`;
  const valid = state.auditIntegrity.valid;
  byId("audit-status").textContent = valid ? "Event chain verified" : "Integrity check failed";
  byId("audit-summary-detail").textContent = valid
    ? `All ${state.auditIntegrity.events_checked} events link to the previous event.`
    : "Event history does not match its recorded hashes.";
  byId("integrity-label").textContent = valid ? "Chain verified" : "Integrity check failed";
  byId("integrity-detail").textContent = `${state.auditIntegrity.events_checked} events checked`;
  byId("audit-integrity-button").classList.toggle("integrity-failed", !valid);
}

async function loadDashboard() {
  const [documentResult, auditResult] = await Promise.all([
    api("/api/documents"),
    api("/api/audit").catch((error) => {
      if (error.message.includes("Administrator")) return { events: [], integrity: null };
      throw error;
    }),
  ]);
  state.documents = documentResult.documents;
  state.events = auditResult.events;
  if (auditResult.integrity) state.auditIntegrity = auditResult.integrity;
  renderDocuments();
  renderRecentActivity();
  renderAudit();
}

byId("security-dialog").addEventListener("cancel", (event) => {
  if (state.user?.must_change_password) event.preventDefault();
});

function setView(view) {
  const showAudit = view === "activity" && state.user.role === "admin";
  byId("documents-view").hidden = showAudit;
  byId("activity-view").hidden = !showAudit;
  byId("breadcrumb-current").textContent = showAudit ? "Audit trail" : "Documents";
  document.querySelectorAll(".nav-item").forEach((button) => button.classList.toggle("is-active", button.dataset.view === (showAudit ? "activity" : "documents")));
}

async function refreshAudit() {
  const result = await api("/api/audit");
  state.events = result.events;
  state.auditIntegrity = result.integrity;
  renderRecentActivity();
  renderAudit();
}

async function openShares(documentId) {
  const document = state.documents.find((item) => item.id === documentId);
  if (!document) return;
  state.activeDocument = document;
  byId("share-title").textContent = document.title;
  byId("share-email").value = "";
  byId("share-expiry").value = "";
  await refreshShares();
  byId("share-dialog").showModal();
}

async function refreshShares() {
  const { shares } = await api(`/api/documents/${encodeURIComponent(state.activeDocument.id)}/shares`);
  byId("share-count").textContent = shares.filter((share) => !share.revoked_at).length;
  byId("share-list").innerHTML = shares.map((share) => {
    const active = !share.revoked_at && (!share.expires_at || new Date(share.expires_at) > new Date());
    const subline = share.revoked_at ? `Revoked ${formatDate(share.revoked_at)}`
      : share.expires_at ? `Expires ${formatDate(share.expires_at, true)}` : "No expiry";
    return `<div class="share-row"><span class="share-avatar">${initials(share.display_name)}</span><span class="share-person"><strong>${esc(share.display_name)}</strong><small>${esc(share.email)} · ${esc(subline)}</small></span>${active ? `<button class="share-revoke" type="button" data-action="revoke" data-share-id="${esc(share.id)}">Revoke</button>` : `<span class="share-revoked">${share.revoked_at ? "Revoked" : "Expired"}</span>`}</div>`;
  }).join("") || `<div class="no-shares">No one else has access to this document.</div>`;
}

async function downloadDocument(documentId) {
  const selectedDocument = state.documents.find((item) => item.id === documentId);
  const response = await fetch(`/api/documents/${encodeURIComponent(documentId)}/file`, { credentials: "same-origin" });
  if (!response.ok) {
    const result = await response.json().catch(() => ({}));
    throw new Error(result.detail || "Could not retrieve this document");
  }
  const blob = await response.blob();
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = selectedDocument?.filename || "document";
  link.click();
  URL.revokeObjectURL(link.href);
  toast("File request recorded in the audit trail.");
  await loadDashboard();
}

async function bootstrap() {
  await refreshCsrf();
  const config = await api("/api/config");
  byId("demo-access").hidden = !config.demo_mode;
  try {
    state.user = await api("/api/me");
    renderApp();
    if (!state.user.must_change_password) await loadDashboard();
  } catch (error) {
    if (error.message.includes("Failed to fetch")) throw error;
    renderLogin();
  }
}

byId("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  byId("login-error").textContent = "";
  const form = new FormData(event.currentTarget);
  try {
    state.user = await api("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: form.get("email"), password: form.get("password") }),
    });
    renderApp();
    if (!state.user.must_change_password) await loadDashboard();
  } catch (error) {
    byId("login-error").textContent = error.message;
  }
});

document.querySelectorAll("[data-demo]").forEach((button) => button.addEventListener("click", () => {
  const admin = button.dataset.demo === "admin";
  byId("login-email").value = admin ? "admin@trustvault.local" : "maya@northstar.example";
  byId("login-password").value = admin ? "VaultDemo!2026" : "Northstar!2026";
  byId("login-form").requestSubmit();
}));

byId("logout-button").addEventListener("click", async () => {
  try {
    await api("/api/logout", { method: "POST" });
    state.user = null;
    await refreshCsrf();
    renderLogin();
  } catch (error) { toast(error.message, true); }
});

byId("account-button").addEventListener("click", () => byId("security-dialog").showModal());
byId("password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const currentPassword = byId("current-password").value;
  const newPassword = byId("new-password").value;
  if (newPassword !== byId("confirm-password").value) {
    toast("The new passwords do not match.", true);
    return;
  }
  try {
    await api("/api/account/password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    });
    state.user.must_change_password = false;
    byId("security-dialog").close();
    event.currentTarget.reset();
    toast("Password updated. Other sessions were signed out.");
    await loadDashboard();
  } catch (error) { toast(error.message, true); }
});

document.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => setView(button.dataset.view)));
document.querySelectorAll("[data-filter]").forEach((button) => button.addEventListener("click", () => {
  state.filter = button.dataset.filter;
  document.querySelectorAll("[data-filter]").forEach((tab) => {
    const selected = tab === button;
    tab.classList.toggle("is-selected", selected);
    tab.setAttribute("aria-selected", String(selected));
  });
  renderDocuments();
}));
byId("search-input").addEventListener("input", (event) => { state.search = event.target.value; renderDocuments(); });
document.addEventListener("keydown", (event) => {
  if (event.key === "/" && !["INPUT", "TEXTAREA"].includes(document.activeElement.tagName)) {
    event.preventDefault();
    byId("search-input").focus();
  }
  if (event.key === "Escape") document.activeElement.blur();
});

byId("upload-open").addEventListener("click", () => byId("upload-dialog").showModal());
byId("upload-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    await api("/api/documents", { method: "POST", body: form });
    byId("upload-dialog").close();
    event.currentTarget.reset();
    toast("Document encrypted and uploaded.");
    await loadDashboard();
    await refreshAudit();
  } catch (error) { toast(error.message, true); }
});

byId("share-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const expiryValue = byId("share-expiry").value;
  const payload = { email: byId("share-email").value };
  if (expiryValue) payload.expires_at = new Date(expiryValue).toISOString();
  try {
    await api(`/api/documents/${encodeURIComponent(state.activeDocument.id)}/shares`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
    });
    toast("Direct access granted.");
    await refreshShares();
    await loadDashboard();
  } catch (error) { toast(error.message, true); }
});

for (const dialog of document.querySelectorAll("dialog")) {
  dialog.querySelectorAll(".close-dialog").forEach((button) => button.addEventListener("click", () => dialog.close()));
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog && !(dialog.id === "security-dialog" && state.user?.must_change_password)) {
      dialog.close();
    }
  });
}

document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-action]");
  if (!button) return;
  try {
    if (button.dataset.action === "download") await downloadDocument(button.dataset.id);
    if (button.dataset.action === "share") await openShares(button.dataset.id);
    if (button.dataset.action === "revoke") {
      await api(`/api/documents/${encodeURIComponent(state.activeDocument.id)}/shares/${encodeURIComponent(button.dataset.shareId)}`, { method: "DELETE" });
      toast("Access revoked. The next file request will be denied.");
      await refreshShares();
      await loadDashboard();
      await refreshAudit();
    }
  } catch (error) { toast(error.message, true); }
});

byId("view-all-activity").addEventListener("click", () => setView("activity"));
byId("audit-integrity-button").addEventListener("click", () => setView("activity"));
byId("verify-audit-button").addEventListener("click", async () => {
  try { await refreshAudit(); toast("Audit chain verified."); }
  catch (error) { toast(error.message, true); }
});

bootstrap().catch((error) => {
  console.error(error);
  renderLogin();
  byId("login-error").textContent = "Could not connect to TrustVault. Refresh the page and try again.";
});
