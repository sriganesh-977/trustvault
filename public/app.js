// TrustVault Frontend Application Client


let currentUser = null;
let currentToken = null;
let currentCsrfToken = null;

// Helpers: API fetch wrapper
async function api(path, options = {}) {
  const headers = options.headers || {};
  if (currentToken) {
    headers['Authorization'] = `Bearer ${currentToken}`;
  }
  if (currentCsrfToken && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(options.method?.toUpperCase())) {
    headers['X-CSRF-Token'] = currentCsrfToken;
  }
  headers['X-Requested-With'] = 'XMLHttpRequest';
  options.headers = headers;

  const res = await fetch(path, options);
  if (res.status === 401 && currentUser) {
    showToast('Session expired or unauthorized', 'error');
    logout();
    throw new Error('Unauthorized');
  }
  return res;
}

// Toast Notifications
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 250);
  }, 3500);
}

// Modal control
function openModal(id) {
  const m = document.getElementById(id);
  if (m) m.classList.remove('hidden');
}
function closeModal(id) {
  const m = document.getElementById(id);
  if (m) m.classList.add('hidden');
}

// Format bytes
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024, sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// Format date
function formatDate(d) {
  if (!d) return '-';
  try {
    const dt = new Date(d);
    return dt.toLocaleDateString() + ' ' + dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch {
    return d;
  }
}

// Quick Login (Demo Credentials)
function quickLogin(email, password) {
  document.getElementById('login-email').value = email;
  document.getElementById('login-password').value = password;
  document.getElementById('login-form').dispatchEvent(new Event('submit'));
}

// App Initialization
document.addEventListener('DOMContentLoaded', async () => {
  setupEventListeners();
  refreshIcons();
  try {
    const config = await fetch('/api/config').then((r) => r.json());
    const demoBox = document.querySelector('.demo-box');
    if (!config.demoAccounts) demoBox?.remove();
    else if (demoBox) demoBox.querySelector('.demo-title').textContent = 'Demo accounts · development only';
  } catch { document.querySelector('.demo-box')?.remove(); }
  const oauthStatus = new URLSearchParams(window.location.search).get('oauth');
  if (oauthStatus === 'success') showToast('Signed in successfully.', 'success');
  if (oauthStatus === 'not_configured') showToast('This sign-in provider is not configured yet.', 'error');
  if (oauthStatus === 'disabled') showToast('This account is disabled.', 'error');
  if (oauthStatus === 'failed') showToast('Social sign-in was not completed.', 'error');
  if (oauthStatus) window.history.replaceState({}, document.title, window.location.pathname);

  // Check both the bearer token and the secure OAuth session cookie.
  const savedToken = localStorage.getItem('tv_token');
  const savedCsrf = localStorage.getItem('tv_csrf');
  if (savedToken) {
    currentToken = savedToken;
    currentCsrfToken = savedCsrf;
  }
  if (!currentCsrfToken) {
    try {
      const csrfRes = await fetch('/api/auth/csrf');
      if (csrfRes.ok) currentCsrfToken = (await csrfRes.json()).csrfToken;
    } catch {}
  }
  try {
    const res = await api('/api/me');
    if (res.ok) {
      currentUser = await res.json();
      renderLoggedInView();
      return;
    }
  } catch {}
  if (savedToken) logout();
});

function refreshIcons() {
  if (window.lucide && typeof window.lucide.createIcons === 'function') window.lucide.createIcons();
}

function setupEventListeners() {
  // Tabs: Login vs Register
  document.getElementById('tab-login').addEventListener('click', () => {
    document.getElementById('tab-login').classList.add('active');
    document.getElementById('tab-register').classList.remove('active');
    document.getElementById('login-form').classList.remove('hidden');
    document.getElementById('register-form').classList.add('hidden');
    document.getElementById('auth-mode-title').textContent = 'Secure sign in';
    document.getElementById('auth-mode-copy').textContent = 'Use your TrustVault credentials to continue.';
  });

  document.getElementById('tab-register').addEventListener('click', () => {
    document.getElementById('tab-register').classList.add('active');
    document.getElementById('tab-login').classList.remove('active');
    document.getElementById('register-form').classList.remove('hidden');
    document.getElementById('login-form').classList.add('hidden');
    document.getElementById('auth-mode-title').textContent = 'Create your workspace account';
    document.getElementById('auth-mode-copy').textContent = 'Registration creates a viewer account until an administrator grants more access.';
  });

  // Login Submit
  document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || 'Login failed', 'error');
        return;
      }
      if (data.mfaRequired) {
        const code = window.prompt('Enter the 6-digit code from your authenticator app');
        if (!code) return showToast('Two-factor verification is required', 'warning');
        const verify = await fetch('/api/auth/mfa/verify', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ challenge: data.challenge, code })
        });
        const verified = await verify.json();
        if (!verify.ok) return showToast(verified.error || 'Verification failed', 'error');
        Object.assign(data, verified);
      }
      currentToken = data.token;
      currentCsrfToken = data.csrfToken;
      currentUser = data.user;
      localStorage.setItem('tv_token', currentToken);
      if (currentCsrfToken) localStorage.setItem('tv_csrf', currentCsrfToken);
      showToast(`Welcome back, ${currentUser.name}!`, 'success');
      renderLoggedInView();
    } catch (err) {
      showToast('Network error during login', 'error');
    }
  });

  // Start the provider authorization flow. The server validates state and
  // creates the normal TrustVault session after the provider callback.
  document.querySelectorAll('.social-login-btn').forEach((button) => {
    button.addEventListener('click', () => {
      const provider = button.dataset.provider;
      window.location.assign(`/api/auth/oauth/${provider}`);
    });
  });

  // Register Submit
  document.getElementById('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = document.getElementById('reg-name').value;
    const email = document.getElementById('reg-email').value;
    const password = document.getElementById('reg-password').value;
    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password })
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || 'Registration failed', 'error');
        return;
      }
      showToast('Registration successful! Please sign in.', 'success');
      document.getElementById('tab-login').click();
      document.getElementById('login-email').value = email;
      document.getElementById('login-password').value = '';
    } catch (err) {
      showToast('Registration failed', 'error');
    }
  });

  // Logout
  document.getElementById('btn-logout').addEventListener('click', logout);

  // Dashboard Main Tabs (Documents vs Admin)
  document.getElementById('tab-documents').addEventListener('click', () => {
    document.getElementById('tab-documents').classList.add('active');
    document.getElementById('tab-admin').classList.remove('active');
    document.getElementById('view-documents').classList.remove('hidden');
    document.getElementById('view-admin').classList.add('hidden');
    loadDocuments();
  });

  document.getElementById('tab-admin').addEventListener('click', () => {
    document.getElementById('tab-admin').classList.add('active');
    document.getElementById('tab-documents').classList.remove('active');
    document.getElementById('view-admin').classList.remove('hidden');
    document.getElementById('view-documents').classList.add('hidden');
    loadAdminDashboard();
  });

  document.getElementById('tab-dashboard').addEventListener('click', () => {
    document.getElementById('tab-documents').click();
  });
  document.getElementById('nav-security').addEventListener('click', () => {
    document.getElementById('security-card')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
  document.getElementById('nav-audit').addEventListener('click', () => {
    if (currentUser?.role !== 'admin') return showToast('Audit access is limited to administrators', 'error');
    document.getElementById('tab-admin').click();
    document.getElementById('subtab-audit').click();
  });
  document.getElementById('nav-users').addEventListener('click', () => {
    if (currentUser?.role !== 'admin') return showToast('User management is limited to administrators', 'error');
    document.getElementById('tab-admin').click();
    document.getElementById('subtab-users').click();
  });

  // Admin Subtabs
  ['audit', 'users', 'docmeta'].forEach(tab => {
    document.getElementById(`subtab-${tab}`).addEventListener('click', () => {
      ['audit', 'users', 'docmeta'].forEach(t => {
        document.getElementById(`subtab-${t}`).classList.toggle('active', t === tab);
        document.getElementById(`admin-pane-${t}`).classList.toggle('hidden', t !== tab);
      });
      if (tab === 'audit') loadAuditLogs();
      if (tab === 'users') loadUsers();
      if (tab === 'docmeta') loadDocMeta();
    });
  });

  // Search filters
  document.getElementById('btn-search').addEventListener('click', loadDocuments);
  document.getElementById('btn-reset-search').addEventListener('click', () => {
    document.getElementById('search-q').value = '';
    document.getElementById('search-category').value = '';
    document.getElementById('search-owner').value = '';
    loadDocuments();
  });
  document.getElementById('document-sort').addEventListener('change', () => { window.documentPage = 1; loadDocuments(); });

  // Upload Form
  document.getElementById('upload-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fileInput = document.getElementById('upload-file');
    if (!fileInput.files.length) return showToast('Please select a file', 'warning');

    const file = fileInput.files[0];
    const allowed = ['pdf', 'png', 'jpg', 'jpeg', 'docx', 'xlsx', 'txt'];
    const ext = file.name.split('.').pop().toLowerCase();
    if (!allowed.includes(ext)) {
      return showToast(`Extension .${ext} not allowed. Supported: ${allowed.join(', ')}`, 'error');
    }

    const formData = new FormData();
    formData.append('file', file);
    const name = document.getElementById('upload-name').value;
    const category = document.getElementById('upload-category').value;
    const grantEmail = document.getElementById('upload-grant-email').value.trim();
    const grantLevel = document.getElementById('upload-grant-level').value;
    if (name) formData.append('name', name);
    if (category) formData.append('category', category);
    if (grantEmail) {
      formData.append('grant_email', grantEmail);
      formData.append('grant_level', grantLevel);
    }

    try {
      const res = await api('/api/documents', {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      if (!res.ok) return showToast(data.error || 'Upload failed', 'error');
      showToast(grantEmail ? `Document uploaded and shared with ${grantEmail}.` : `Document "${data.name}" uploaded successfully!`, 'success');
      document.getElementById('upload-form').reset();
      loadDocuments();
    } catch (err) {
      showToast('Error uploading document', 'error');
    }
  });

  // Edit Doc Modal Form
  document.getElementById('edit-doc-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = document.getElementById('edit-doc-id').value;
    const name = document.getElementById('edit-doc-name').value;
    const category = document.getElementById('edit-doc-category').value;
    try {
      const res = await api(`/api/documents/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, category })
      });
      const data = await res.json();
      if (!res.ok) return showToast(data.error || 'Update failed', 'error');
      showToast('Document updated successfully', 'success');
      closeModal('modal-edit');
      loadDocuments();
    } catch {
      showToast('Update failed', 'error');
    }
  });

  // Replace Content Form
  document.getElementById('replace-content-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = document.getElementById('replace-doc-id').value;
    const fileInput = document.getElementById('replace-file');
    if (!fileInput.files.length) return showToast('Please select a file', 'warning');

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    try {
      const res = await api(`/api/documents/${id}/content`, {
        method: 'PUT',
        body: formData
      });
      const data = await res.json();
      if (!res.ok) return showToast(data.error || 'Replacement failed', 'error');
      showToast(`New version uploaded! Current SHA-256 updated.`, 'success');
      closeModal('modal-replace');
      loadDocuments();
    } catch {
      showToast('Failed to replace content', 'error');
    }
  });

  // Grant Form
  document.getElementById('grant-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const docId = document.getElementById('grant-form').dataset.docId;
    const email = document.getElementById('grant-email').value;
    const level = document.getElementById('grant-level').value;

    try {
      const res = await api(`/api/documents/${docId}/grants`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, level })
      });
      const data = await res.json();
      if (!res.ok) return showToast(data.error || 'Grant failed', 'error');
      showToast(`Granted ${level} access to ${email}`, 'success');
      document.getElementById('grant-email').value = '';
      loadGrants(docId);
    } catch {
      showToast('Grant request failed', 'error');
    }
  });

  // Admin Chain Verification Buttons
  document.getElementById('btn-verify-chain').addEventListener('click', checkChainIntegrity);
  document.getElementById('btn-anchor-chain').addEventListener('click', createExternalAnchor);
  document.getElementById('btn-refresh-audit').addEventListener('click', loadAuditLogs);
  document.getElementById('audit-filter-action').addEventListener('change', loadAuditLogs);
  document.getElementById('audit-filter-outcome').addEventListener('change', loadAuditLogs);
  document.getElementById('btn-mfa-setup').addEventListener('click', async () => {
    const res = await api('/api/auth/mfa/setup', { method: 'POST' });
    const data = await res.json();
    if (!res.ok) return showToast(data.error || 'Could not start MFA setup', 'error');
    const secret = document.getElementById('mfa-secret');
    secret.textContent = `Secret: ${data.secret} (add it to your authenticator app)`;
    secret.classList.remove('hidden');
    showToast('MFA secret created. Verify a code to enable it.', 'info');
  });
  document.getElementById('btn-mfa-enable').addEventListener('click', async () => {
    const code = document.getElementById('mfa-code').value.trim();
    const res = await api('/api/auth/mfa/enable', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code }) });
    const data = await res.json();
    if (!res.ok) return showToast(data.error || 'Could not enable MFA', 'error');
    document.getElementById('mfa-status').textContent = 'MFA enabled';
    document.getElementById('mfa-status').className = 'badge badge-success';
    showToast('Multi-factor authentication enabled.', 'success');
  });
}

function logout() {
  if (currentToken) {
    api('/api/auth/logout', { method: 'POST' }).catch(() => {});
  }
  currentUser = null;
  currentToken = null;
  currentCsrfToken = null;
  localStorage.removeItem('tv_token');
  localStorage.removeItem('tv_csrf');
  document.getElementById('auth-section').classList.remove('hidden');
  document.getElementById('dashboard-section').classList.add('hidden');
  document.getElementById('nav-user-panel').classList.add('hidden');
  showToast('Signed out', 'info');
}

function renderLoggedInView() {
  document.getElementById('auth-section').classList.add('hidden');
  document.getElementById('dashboard-section').classList.remove('hidden');
  document.getElementById('nav-user-panel').classList.remove('hidden');
  // Security is an account concern, not an admin-only concern.
  const securityCard = document.getElementById('security-card');
  if (securityCard && securityCard.parentElement !== document.getElementById('dashboard-section')) {
    document.getElementById('dashboard-section').prepend(securityCard);
  }

  // Header user badge
  document.getElementById('user-email').textContent = currentUser.email;
  const badge = document.getElementById('user-badge');
  badge.textContent = currentUser.role;
  badge.className = `badge badge-${currentUser.role}`;

  // Role permissions
  const isOwner = currentUser.role === 'owner';
  const isAdmin = currentUser.role === 'admin';

  document.getElementById('upload-panel').classList.toggle('hidden', !isOwner);
  document.getElementById('tab-admin').classList.toggle('hidden', !isAdmin);
  document.getElementById('nav-audit').classList.toggle('hidden', !isAdmin);
  document.getElementById('nav-users').classList.toggle('hidden', !isAdmin);

  document.getElementById('tab-documents').click();
  refreshIcons();
}

// ---------- Document Management
async function loadDocuments() {
  const tbody = document.getElementById('documents-tbody');
  tbody.innerHTML = '<tr class="skeleton-row"><td colspan="7"><span class="loading-skeleton"></span><span class="loading-skeleton short"></span><span class="loading-skeleton"></span></td></tr>';

  const q = document.getElementById('search-q').value;
  const category = document.getElementById('search-category').value;
  const owner = document.getElementById('search-owner').value;

  const params = new URLSearchParams();
  if (q) params.set('q', q);
  if (category) params.set('category', category);
  if (owner) params.set('owner', owner);
  const [sort, direction] = document.getElementById('document-sort').value.split(':');
  params.set('sort', sort);
  params.set('direction', direction);
  params.set('page', String(window.documentPage || 1));
  params.set('pageSize', '20');

  try {
    const res = await api(`/api/documents?${params.toString()}`);
    if (!res.ok) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center text-danger">Failed to load documents</td></tr>';
      return;
    }
    const docs = await res.json();
    const total = Number(res.headers.get('X-Total-Count') || docs.length);
    document.getElementById('doc-count-badge').textContent = `${total} document${total === 1 ? '' : 's'}`;

    if (!docs.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No documents found matching your criteria.</td></tr>';
      return;
    }

    const page = Number(window.documentPage || 1);
    const pageSize = 20;
    const pages = Math.max(1, Math.ceil(total / pageSize));
    document.getElementById('document-pagination').innerHTML = `
      <button class="btn btn-sm btn-outline" ${page <= 1 ? 'disabled' : ''} data-page="${page - 1}">Previous</button>
      <span>Page ${page} of ${pages}</span>
      <button class="btn btn-sm btn-outline" ${page >= pages ? 'disabled' : ''} data-page="${page + 1}">Next</button>`;
    document.querySelectorAll('#document-pagination [data-page]').forEach((button) => button.addEventListener('click', () => {
      window.documentPage = Number(button.dataset.page);
      loadDocuments();
    }));

    tbody.innerHTML = docs.map(d => {
      const isOwner = d.my_level === 'owner';
      const canEdit = d.my_level === 'owner' || d.my_level === 'edit';
      const canRead = true; // All returned documents have at least read level
      const permissionLabel = isOwner ? 'Owner · View / Download / Edit / Share' : d.my_level === 'edit' ? 'Editor · View / Download / Edit' : 'Viewer · View / Download';

      return `
        <tr>
          <td><strong>📄 ${escapeHtml(d.name)}</strong></td>
          <td><span class="badge badge-secondary">${escapeHtml(d.category)}</span></td>
          <td>${formatBytes(d.size)}</td>
          <td>${escapeHtml(d.owner || 'You')}</td>
          <td><span class="badge badge-${d.my_level}" title="${permissionLabel}">${permissionLabel}</span></td>
          <td>${formatDate(d.updated_at)}</td>
          <td>
            <div class="action-group">
              <button class="btn btn-sm btn-primary" onclick="downloadDoc('${d.id}', '${escapeAttr(d.name)}')">📥 Download</button>
              <button class="btn btn-sm btn-secondary" onclick="openVersionsModal('${d.id}', '${escapeAttr(d.name)}')">🕒 Versions</button>
              ${canEdit ? `<button class="btn btn-sm btn-secondary" onclick="openEditModal('${d.id}', '${escapeAttr(d.name)}', '${escapeAttr(d.category)}')">✏️ Edit</button>` : ''}
              ${canEdit ? `<button class="btn btn-sm btn-warning" onclick="openReplaceModal('${d.id}', '${escapeAttr(d.name)}')">🔄 Replace</button>` : ''}
              ${isOwner ? `<button class="btn btn-sm btn-outline" onclick="openGrantsModal('${d.id}', '${escapeAttr(d.name)}')">👥 Grants</button>` : ''}
              ${isOwner ? `<button class="btn btn-sm btn-danger" onclick="deleteDoc('${d.id}', '${escapeAttr(d.name)}')">🗑️</button>` : ''}
            </div>
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="7" class="text-center text-danger">Error fetching documents</td></tr>';
  }
}

// Download Document
async function downloadDoc(id, filename) {
  try {
    const res = await api(`/api/documents/${id}/download`);
    if (!res.ok) return showToast('Download refused or not authorized', 'error');
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
    showToast(`Downloaded ${filename}`, 'success');
  } catch {
    showToast('Failed to download document', 'error');
  }
}

// Delete Document
async function deleteDoc(id, name) {
  if (!confirm(`Are you sure you want to permanently delete "${name}"? This removes all versions and grants.`)) return;
  try {
    const res = await api(`/api/documents/${id}`, { method: 'DELETE' });
    if (!res.ok) return showToast('Failed to delete document', 'error');
    showToast('Document deleted', 'success');
    loadDocuments();
  } catch {
    showToast('Delete request error', 'error');
  }
}

// Edit Modal
function openEditModal(id, name, category) {
  document.getElementById('edit-doc-id').value = id;
  document.getElementById('edit-doc-name').value = name;
  document.getElementById('edit-doc-category').value = category;
  openModal('modal-edit');
}

// Replace Content Modal
function openReplaceModal(id, name) {
  document.getElementById('replace-doc-id').value = id;
  document.getElementById('replace-doc-name').textContent = name;
  document.getElementById('replace-file').value = '';
  openModal('modal-replace');
}

// Grants Modal
async function openGrantsModal(docId, docName) {
  document.getElementById('grants-doc-name').textContent = docName;
  document.getElementById('grant-form').dataset.docId = docId;
  openModal('modal-grants');
  loadGrants(docId);
}

async function loadGrants(docId) {
  const tbody = document.getElementById('grants-tbody');
  tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">Loading grants...</td></tr>';
  try {
    const res = await api(`/api/documents/${docId}/grants`);
    if (!res.ok) {
      tbody.innerHTML = '<tr><td colspan="4" class="text-center text-danger">Could not load grants</td></tr>';
      return;
    }
    const grants = await res.json();
    if (!grants.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No active grants. Only you can reach this document.</td></tr>';
      return;
    }
    tbody.innerHTML = grants.map(g => `
      <tr>
        <td><strong>${escapeHtml(g.email)}</strong> (${escapeHtml(g.name)})</td>
        <td><span class="badge badge-${g.level}">${g.level}</span></td>
        <td>${formatDate(g.created_at)}</td>
        <td>
          <button class="btn btn-sm btn-danger" onclick="revokeGrant('${docId}', ${g.user_id}, '${escapeAttr(g.email)}')">Revoke</button>
        </td>
      </tr>
    `).join('');
  } catch {
    tbody.innerHTML = '<tr><td colspan="4" class="text-center text-danger">Error loading grants</td></tr>';
  }
}

async function revokeGrant(docId, userId, email) {
  if (!confirm(`Revoke document access from ${email}? Immediate revocation.`)) return;
  try {
    const res = await api(`/api/documents/${docId}/grants/${userId}`, { method: 'DELETE' });
    if (!res.ok) return showToast('Revocation failed', 'error');
    showToast(`Access revoked for ${email}`, 'success');
    loadGrants(docId);
  } catch {
    showToast('Error revoking grant', 'error');
  }
}

// Versions Modal
async function openVersionsModal(docId, docName) {
  document.getElementById('versions-doc-name').textContent = docName;
  openModal('modal-versions');
  const tbody = document.getElementById('versions-tbody');
  tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">Loading versions...</td></tr>';

  try {
    const res = await api(`/api/documents/${docId}/versions`);
    if (!res.ok) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-center text-danger">Failed to load version history</td></tr>';
      return;
    }
    const versions = await res.json();
    tbody.innerHTML = versions.map((v, idx) => `
      <tr>
        <td><span class="badge badge-primary">v${v.version_number}</span> ${idx === 0 ? '<em>(Current)</em>' : ''}</td>
        <td>${formatDate(v.created_at)}</td>
        <td>${escapeHtml(v.created_by)}</td>
        <td>${formatBytes(v.size)}</td>
        <td><code>${v.sha256.slice(0, 12)}...</code></td>
        <td>
          <div class="action-group">
            <button class="btn btn-sm btn-primary" onclick="downloadVersion('${docId}', ${v.version_number}, '${escapeAttr(docName)}')">📥 Download</button>
            ${idx > 0 && currentUser.role !== 'viewer' ? `<button class="btn btn-sm btn-warning" onclick="rollbackVersion('${docId}', ${v.version_number})">⏪ Rollback</button>` : ''}
          </div>
        </td>
      </tr>
    `).join('');
  } catch {
    tbody.innerHTML = '<tr><td colspan="6" class="text-center text-danger">Error loading versions</td></tr>';
  }
}

async function downloadVersion(docId, version, filename) {
  try {
    const res = await api(`/api/documents/${docId}/versions/${version}/download`);
    if (!res.ok) return showToast('Failed to download version', 'error');
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `v${version}_${filename}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
    showToast(`Downloaded version ${version}`, 'success');
  } catch {
    showToast('Download version error', 'error');
  }
}

async function rollbackVersion(docId, version) {
  if (!confirm(`Restore document to version ${version}? This will create a new current version from historical content.`)) return;
  try {
    const res = await api(`/api/documents/${docId}/rollback/${version}`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) return showToast(data.error || 'Rollback failed', 'error');
    showToast(`Successfully rolled back! Active version is now v${data.version}`, 'success');
    closeModal('modal-versions');
    loadDocuments();
  } catch {
    showToast('Rollback error', 'error');
  }
}

// ---------- Admin Dashboard
async function loadAdminDashboard() {
  checkChainIntegrity();
  checkAnchorStatus();
  loadAlerts();
  loadAuditLogs();
}

async function checkChainIntegrity() {
  const ind = document.getElementById('chain-indicator');
  const txt = document.getElementById('chain-status-text');
  const entries = document.getElementById('chain-entries');
  const head = document.getElementById('chain-head');

  ind.className = 'dot dot-unknown';
  txt.textContent = 'Verifying cryptographic chain...';

  try {
    const res = await api('/api/admin/audit/verify');
    const data = await res.json();
    if (data.ok) {
      ind.className = 'dot dot-valid';
      txt.textContent = 'Chain Intact (Append-Only Validated)';
      entries.textContent = data.entries;
      head.textContent = data.head;
      showToast('Audit log verification: Chain is fully valid', 'success');
    } else {
      ind.className = 'dot dot-invalid';
      txt.textContent = `TAMPER DETECTED at sequence #${data.brokenAt}`;
      entries.textContent = data.entries;
      head.textContent = 'BROKEN';
      showToast(`Warning: Audit chain integrity violation detected at seq #${data.brokenAt}!`, 'error');
    }
  } catch {
    ind.className = 'dot dot-invalid';
    txt.textContent = 'Verification error';
  }
}

async function checkAnchorStatus() {
  const box = document.getElementById('anchor-status-box');
  box.textContent = 'Checking external anchor...';
  try {
    const res = await api('/api/admin/audit/anchor');
    const data = await res.json();
    if (!data.anchored) {
      box.innerHTML = '⚓ External Anchor: <em>None established yet</em>';
    } else if (data.ok) {
      box.innerHTML = `⚓ External Anchor: <strong>MATCHED</strong> (Seq #${data.anchor.seq}, ${formatDate(data.anchor.anchored_at)})`;
    } else {
      box.innerHTML = `⚠️ External Anchor: <strong style="color:var(--danger)">MISMATCH (${data.reason})</strong>`;
    }
  } catch {
    box.textContent = 'Could not check anchor status';
  }
}

async function createExternalAnchor() {
  try {
    const res = await api('/api/admin/audit/anchor', { method: 'POST' });
    const data = await res.json();
    if (res.ok) {
      showToast(`External anchor established at seq #${data.seq}!`, 'success');
      checkAnchorStatus();
    } else {
      showToast(data.error || 'Failed to establish anchor', 'error');
    }
  } catch {
    showToast('Anchor request failed', 'error');
  }
}

async function loadAlerts() {
  try {
    const res = await api('/api/admin/alerts');
    if (!res.ok) return;
    const data = await res.json();
    const denials = data.repeated_denials.reduce((sum, r) => sum + r.denials, 0);
    const logins = data.failed_logins.reduce((sum, r) => sum + r.failures, 0);
    document.getElementById('alert-denials').textContent = denials;
    document.getElementById('alert-logins').textContent = logins;
    document.getElementById('alert-perms').textContent = data.permission_changes;
  } catch {}
}

async function loadAuditLogs() {
  const tbody = document.getElementById('audit-tbody');
  tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">Loading audit log entries...</td></tr>';

  const action = document.getElementById('audit-filter-action').value;
  const outcome = document.getElementById('audit-filter-outcome').value;
  const params = new URLSearchParams();
  if (action) params.set('action', action);
  if (outcome) params.set('outcome', outcome);
  params.set('limit', '50');

  try {
    const res = await api(`/api/admin/audit?${params.toString()}`);
    if (!res.ok) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center text-danger">Failed to load audit entries</td></tr>';
      return;
    }
    const rows = await res.json();
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No audit records found</td></tr>';
      return;
    }

    tbody.innerHTML = rows.map(r => `
      <tr>
        <td><strong>#${r.seq}</strong></td>
        <td>${formatDate(r.ts)}</td>
        <td>${escapeHtml(r.actor_email || 'anonymous')}</td>
        <td><code>${escapeHtml(r.action)}</code></td>
        <td><span class="badge badge-${r.outcome === 'allowed' ? 'success' : r.outcome === 'denied' ? 'danger' : 'secondary'}">${r.outcome}</span></td>
        <td><small>${escapeHtml(r.ip || '-')}</small></td>
        <td><small><code>${escapeHtml(JSON.stringify(r.detail))}</code></small></td>
        <td><code>${r.hash.slice(0, 10)}...</code></td>
      </tr>
    `).join('');
  } catch {
    tbody.innerHTML = '<tr><td colspan="8" class="text-center text-danger">Error loading audit logs</td></tr>';
  }
}

async function loadUsers() {
  const tbody = document.getElementById('users-tbody');
  tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">Loading user accounts...</td></tr>';

  try {
    const res = await api('/api/admin/users');
    if (!res.ok) return;
    const users = await res.json();

    tbody.innerHTML = users.map(u => `
      <tr>
        <td>#${u.id}</td>
        <td><strong>${escapeHtml(u.name)}</strong></td>
        <td>${escapeHtml(u.email)}</td>
        <td>
          <select class="filter-select-sm" onchange="updateUserRole(${u.id}, this.value)" ${u.id === currentUser.id ? 'disabled' : ''}>
            <option value="viewer" ${u.role === 'viewer' ? 'selected' : ''}>viewer</option>
            <option value="owner" ${u.role === 'owner' ? 'selected' : ''}>owner</option>
            <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>admin</option>
          </select>
        </td>
        <td>
          <span class="badge badge-${u.active ? 'success' : 'danger'}">${u.active ? 'Active' : 'Disabled'}</span>
        </td>
        <td>${formatDate(u.created_at)}</td>
        <td>
          ${u.id !== currentUser.id ? `
            <button class="btn btn-sm ${u.active ? 'btn-danger' : 'btn-success'}" onclick="toggleUserActive(${u.id}, ${!u.active}, '${escapeAttr(u.email)}')">
              ${u.active ? 'Disable' : 'Activate'}
            </button>
          ` : '<em>(You)</em>'}
        </td>
      </tr>
    `).join('');
  } catch {
    tbody.innerHTML = '<tr><td colspan="7" class="text-center text-danger">Error loading users</td></tr>';
  }
}

async function updateUserRole(userId, newRole) {
  try {
    const res = await api(`/api/admin/users/${userId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: newRole })
    });
    if (!res.ok) return showToast('Failed to update role', 'error');
    showToast(`Role updated to ${newRole}`, 'success');
    loadUsers();
  } catch {
    showToast('Role update failed', 'error');
  }
}

async function toggleUserActive(userId, active, email) {
  const action = active ? 'activate' : 'disable';
  if (!confirm(`Are you sure you want to ${action} ${email}? Disabling immediately kills active sessions.`)) return;
  try {
    const res = await api(`/api/admin/users/${userId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ active })
    });
    if (!res.ok) return showToast('Failed to update user status', 'error');
    showToast(`User ${email} ${action}d!`, 'success');
    loadUsers();
  } catch {
    showToast('Failed to update user status', 'error');
  }
}

async function loadDocMeta() {
  const tbody = document.getElementById('docmeta-tbody');
  tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">Loading vault document catalog...</td></tr>';
  try {
    const res = await api('/api/admin/documents');
    if (!res.ok) return;
    const docs = await res.json();
    if (!docs.length) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No documents in vault catalog</td></tr>';
      return;
    }
    tbody.innerHTML = docs.map(d => `
      <tr>
        <td><code>${d.id.slice(0, 8)}...</code></td>
        <td><strong>${escapeHtml(d.name)}</strong></td>
        <td><span class="badge badge-secondary">${escapeHtml(d.category)}</span></td>
        <td>${formatBytes(d.size)}</td>
        <td>${escapeHtml(d.owner)}</td>
        <td><span class="badge badge-info">${d.grants} user(s)</span></td>
        <td>${formatDate(d.created_at)}</td>
        <td>${d.deleted_at ? `<span class="badge badge-danger">Deleted</span>` : '<span class="badge badge-success">Active</span>'}</td>
      </tr>
    `).join('');
  } catch {
    tbody.innerHTML = '<tr><td colspan="8" class="text-center text-danger">Error loading document catalog</td></tr>';
  }
}

// Helpers
function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function escapeAttr(str) {
  if (!str) return '';
  return String(str).replace(/'/g, "\\'").replace(/"/g, '&quot;');
}
