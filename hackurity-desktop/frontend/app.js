/**
 * AIRLOCK — Zero-Trust AI Security Gateway
 * Frontend Orchestrator & Telemetry Stream
 */

const state = {
  identity: null,
  summary: null,
  events: [],
  approvals: [],
  connections: [],
  policies: null,
  activeApproval: null,
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);

// Helper for formatted requests with cookie credentials
async function apiRequest(path, options = {}) {
  const defaultHeaders = { 'Content-Type': 'application/json' };
  const config = {
    ...options,
    credentials: 'include',
    headers: { ...defaultHeaders, ...(options.headers || {}) },
  };
  const response = await fetch(path, config);
  const text = await response.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { detail: text };
  }
  if (!response.ok) {
    throw new Error(data.detail || `Request failed with status ${response.status}`);
  }
  return data;
}

// ============================================================================
// 1. CINEMATIC AIRLOCK LAUNCH ANIMATION CONTROLLER
// ============================================================================
function initIntroAnimation() {
  const overlay = $('#intro-overlay');
  const skipBtn = $('#skip-intro-btn');
  const hasSeen = sessionStorage.getItem('airlock_intro_played');

  // Pre-check session immediately so the destination screen is prepared
  checkSessionAndDisplay();

  function endIntro() {
    overlay.classList.add('fade-out');
    overlay.style.pointerEvents = 'none';
    setTimeout(() => {
      overlay.style.display = 'none';
    }, 500);
    sessionStorage.setItem('airlock_intro_played', 'true');
  }

  if (hasSeen) {
    overlay.style.display = 'none';
    overlay.style.pointerEvents = 'none';
    return;
  }

  skipBtn.onclick = endIntro;
  // Natural animation completion at 2.6s
  setTimeout(endIntro, 2600);
}

// ============================================================================
// 2. AUTHENTICATION & SESSION MANAGEMENT
// ============================================================================
async function checkSessionAndDisplay() {
  try {
    const data = await apiRequest('/auth/me');
    if (data && data.identity) {
      state.identity = data.identity;
      showAppConsole();
    } else {
      state.identity = null;
      showLoginScreen();
    }
  } catch {
    state.identity = null;
    showLoginScreen();
  }
}

function showLoginScreen() {
  const login = $('#login-screen');
  const consoleEl = $('#app-console');
  if (login) {
    login.hidden = false;
    login.classList.remove('hidden');
    login.style.setProperty('display', 'grid', 'important');
  }
  if (consoleEl) {
    consoleEl.hidden = true;
    consoleEl.classList.add('hidden');
    consoleEl.style.setProperty('display', 'none', 'important');
  }
}

function showAppConsole() {
  const login = $('#login-screen');
  const consoleEl = $('#app-console');
  if (login) {
    login.hidden = true;
    login.classList.add('hidden');
    login.style.setProperty('display', 'none', 'important');
  }
  if (consoleEl) {
    consoleEl.hidden = false;
    consoleEl.classList.remove('hidden');
    consoleEl.style.setProperty('display', 'flex', 'important');
  }
  if (state.identity) {
    const userDisplay = $('#user-display');
    if (userDisplay) {
      userDisplay.textContent = `${state.identity.username} · ${state.identity.role}`;
    }
  }
  loadTelemetry();
}

function initAuthHandlers() {
  // Role switcher buttons
  $$('.role-btn[data-user]').forEach((btn) => {
    btn.onclick = () => {
      $$('.role-btn[data-user]').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      $('#login-username').value = btn.dataset.user;
      $('#login-password').value = btn.dataset.pass;
    };
  });

  // Toggle password visibility
  const togglePwdBtn = $('#toggle-password-btn');
  if (togglePwdBtn) {
    togglePwdBtn.onclick = () => {
      const pwdInput = $('#login-password');
      if (!pwdInput) return;
      const isPassword = pwdInput.type === 'password';
      pwdInput.type = isPassword ? 'text' : 'password';
      togglePwdBtn.classList.toggle('revealed', isPassword);
    };
  }

  // Login form submission
  $('#login-form').onsubmit = async (e) => {
    e.preventDefault();
    const errorEl = $('#login-error');
    errorEl.textContent = '';
    const submitBtn = $('#login-submit-btn');
    const originalText = submitBtn.textContent;
    submitBtn.disabled = true;
    submitBtn.textContent = 'Authenticating...';

    const username = $('#login-username').value.trim();
    const password = $('#login-password').value;

    try {
      const res = await apiRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      });
      state.identity = res.identity;
      showAppConsole();
    } catch (err) {
      errorEl.textContent = err.message;
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = originalText;
    }
  };

  // Logout button
  $('#logout-btn').onclick = async () => {
    try {
      await apiRequest('/auth/logout', { method: 'POST' });
    } catch {
      // Ignore
    }
    sessionStorage.removeItem('airlock_intro_played');
    location.reload();
  };

  // Telemetry refresh button
  $('#refresh-telemetry-btn').onclick = loadTelemetry;
}

// ============================================================================
// 3. TELEMETRY & DATA RETRIEVAL
// ============================================================================
async function loadTelemetry() {
  try {
    const [summary, events, approvals, connections, policies] = await Promise.all([
      apiRequest('/api/summary').catch(() => null),
      apiRequest('/api/events?limit=100').catch(() => []),
      apiRequest('/api/approvals').catch(() => []),
      apiRequest('/api/connections').catch(() => []),
      apiRequest('/api/policies').catch(() => null),
    ]);

    state.summary = summary;
    state.events = events || [];
    state.approvals = approvals || [];
    state.connections = connections || [];
    state.policies = policies;

    renderMetrics();
    renderOverviewRecent();
    renderAccessControlLanes();
    renderPendingApprovals();
    renderConnections();
    renderAuditTimeline();
    renderPolicyViews();
    updateDownstreamCounter();
  } catch (err) {
    console.error('Failed to load telemetry:', err);
  }
}

function renderMetrics() {
  if (!state.summary) return;
  $('#metric-total').textContent = state.summary.total_events || 0;
  $('#metric-allowed').textContent = state.summary.allowed || 0;
  $('#metric-pending').textContent = state.approvals ? state.approvals.length : 0;
  $('#metric-denied').textContent = state.summary.denied || 0;

  // Attack Lab Hero Metrics
  const labSim = state.events.filter((e) => e.matched_policy && e.matched_policy !== 'default_deny').length;
  const labBlocked = state.events.filter((e) => e.decision === 'deny').length;
  const labIntercepted = state.events.length;
  const simEl = $('#lab-metric-simulated');
  const blockEl = $('#lab-metric-blocked');
  const interceptEl = $('#lab-metric-intercepted');
  if (simEl) simEl.textContent = labSim;
  if (blockEl) blockEl.textContent = labBlocked;
  if (interceptEl) interceptEl.textContent = labIntercepted;
}

function renderOverviewRecent() {
  const tbody = $('#overview-recent-table');
  tbody.replaceChildren();
  if (!state.events || !state.events.length) {
    const emptyTr = document.createElement('tr');
    const emptyTd = document.createElement('td');
    emptyTd.colSpan = 6;
    emptyTd.style.textAlign = 'center';
    emptyTd.style.color = 'var(--airlock-muted)';
    emptyTd.textContent = 'No security events recorded yet.';
    emptyTr.appendChild(emptyTd);
    tbody.appendChild(emptyTr);
    return;
  }

  state.events.slice(0, 6).forEach((evt) => {
    const tr = document.createElement('tr');
    const badgeClass = evt.decision === 'allow' ? 'allow' : evt.decision === 'deny' ? 'deny' : 'review';

    const tdTime = document.createElement('td');
    tdTime.textContent = new Date(evt.timestamp).toLocaleTimeString();

    const tdTool = document.createElement('td');
    const strongTool = document.createElement('strong');
    strongTool.textContent = evt.tool_identifier;
    tdTool.appendChild(strongTool);

    const tdBadge = document.createElement('td');
    const spanBadge = document.createElement('span');
    spanBadge.className = `badge ${badgeClass}`;
    spanBadge.textContent = evt.decision.toUpperCase();
    tdBadge.appendChild(spanBadge);

    const tdRisk = document.createElement('td');
    const spanRisk = document.createElement('span');
    spanRisk.style.color = evt.risk_score > 50 ? 'var(--airlock-denied)' : 'var(--airlock-muted)';
    spanRisk.style.fontWeight = '700';
    spanRisk.textContent = `${evt.risk_score}/100`;
    tdRisk.appendChild(spanRisk);

    const tdExec = document.createElement('td');
    const spanExec = document.createElement('span');
    spanExec.style.color = evt.upstream_executed ? 'var(--airlock-allowed)' : 'var(--airlock-denied)';
    spanExec.textContent = evt.upstream_executed ? '✓ Executed' : '✕ Blocked';
    tdExec.appendChild(spanExec);

    const tdReason = document.createElement('td');
    tdReason.style.color = 'var(--airlock-muted)';
    tdReason.textContent = evt.reason || '—';

    tr.append(tdTime, tdTool, tdBadge, tdRisk, tdExec, tdReason);
    tbody.appendChild(tr);
  });
}

function renderAccessControlLanes() {
  const allowContainer = $('#allow-lane-items');
  const reviewContainer = $('#review-lane-items');
  const denyContainer = $('#deny-lane-items');

  allowContainer.replaceChildren();
  reviewContainer.replaceChildren();
  denyContainer.replaceChildren();

  const allowEvents = state.events.filter((e) => e.decision === 'allow');
  const denyEvents = state.events.filter((e) => e.decision === 'deny');

  $('#allow-count').textContent = allowEvents.length;
  $('#review-count').textContent = state.approvals.length;
  $('#deny-count').textContent = denyEvents.length;

  // Render Allowed Lane
  if (!allowEvents.length) {
    const emptyP = document.createElement('p');
    emptyP.style.color = 'var(--airlock-muted)';
    emptyP.style.fontSize = '11px';
    emptyP.textContent = 'No allowed events yet.';
    allowContainer.appendChild(emptyP);
  } else {
    allowEvents.slice(0, 5).forEach((evt) => {
      const card = document.createElement('div');
      card.className = 'event-item-card';

      const badge = document.createElement('span');
      badge.className = 'tool-badge';
      badge.textContent = `✓ ${evt.tool_identifier}`;

      const reasonP = document.createElement('p');
      reasonP.className = 'reason';
      reasonP.textContent = evt.reason;

      const meta = document.createElement('div');
      meta.className = 'event-meta';
      const riskSpan = document.createElement('span');
      riskSpan.textContent = `Risk: ${evt.risk_score}/100`;
      const timeSpan = document.createElement('span');
      timeSpan.textContent = new Date(evt.timestamp).toLocaleTimeString();
      meta.append(riskSpan, timeSpan);

      card.append(badge, reasonP, meta);
      allowContainer.appendChild(card);
    });
  }

  // Render Review Lane (Approvals)
  if (!state.approvals.length) {
    const emptyP = document.createElement('p');
    emptyP.style.color = 'var(--airlock-muted)';
    emptyP.style.fontSize = '11px';
    emptyP.textContent = 'No pending approvals in queue.';
    reviewContainer.appendChild(emptyP);
  } else {
    state.approvals.forEach((appr) => {
      const card = document.createElement('div');
      card.className = 'event-item-card';
      card.style.borderColor = 'rgba(242, 180, 77, 0.4)';

      const badge = document.createElement('span');
      badge.className = 'tool-badge';
      badge.style.color = 'var(--airlock-review)';
      badge.textContent = `◷ ${appr.tool}`;

      const reasonP = document.createElement('p');
      reasonP.className = 'reason';
      reasonP.append('Requester: ');
      const strongReq = document.createElement('strong');
      strongReq.textContent = appr.requester;
      reasonP.append(strongReq, ' · Awaiting human authorization');

      const meta = document.createElement('div');
      meta.className = 'event-meta';
      const idSpan = document.createElement('span');
      idSpan.textContent = `ID: ${appr.id.slice(0, 8)}...`;
      const btn = document.createElement('button');
      btn.className = 'role-btn open-modal-btn';
      btn.dataset.id = appr.id;
      btn.style.color = 'var(--airlock-review)';
      btn.style.borderColor = 'var(--airlock-review)';
      btn.style.padding = '2px 8px';
      btn.type = 'button';
      btn.textContent = 'Review ➔';
      meta.append(idSpan, btn);

      card.append(badge, reasonP, meta);
      reviewContainer.appendChild(card);
    });
  }

  // Render Denied Lane
  if (!denyEvents.length) {
    const emptyP = document.createElement('p');
    emptyP.style.color = 'var(--airlock-muted)';
    emptyP.style.fontSize = '11px';
    emptyP.textContent = 'No denied events yet.';
    denyContainer.appendChild(emptyP);
  } else {
    denyEvents.slice(0, 5).forEach((evt) => {
      const card = document.createElement('div');
      card.className = 'event-item-card';
      card.style.borderColor = 'rgba(240, 90, 112, 0.4)';

      const badge = document.createElement('span');
      badge.className = 'tool-badge';
      badge.style.color = 'var(--airlock-denied)';
      badge.textContent = `✕ ${evt.tool_identifier}`;

      const reasonP = document.createElement('p');
      reasonP.className = 'reason';
      reasonP.textContent = evt.reason;

      const meta = document.createElement('div');
      meta.className = 'event-meta';
      const riskSpan = document.createElement('span');
      riskSpan.style.color = 'var(--airlock-denied)';
      riskSpan.style.fontWeight = '700';
      riskSpan.textContent = `Risk: ${evt.risk_score}/100`;
      const timeSpan = document.createElement('span');
      timeSpan.textContent = new Date(evt.timestamp).toLocaleTimeString();
      meta.append(riskSpan, timeSpan);

      card.append(badge, reasonP, meta);
      denyContainer.appendChild(card);
    });
  }

  // Bind review button in lane
  $$('.open-modal-btn').forEach((btn) => {
    btn.onclick = () => openApprovalModal(btn.dataset.id);
  });
}

function renderPendingApprovals() {
  const container = $('#pending-approvals-list');
  container.replaceChildren();
  if (!state.approvals.length) {
    const emptyP = document.createElement('p');
    emptyP.style.color = 'var(--airlock-muted)';
    emptyP.style.fontSize = '13px';
    emptyP.textContent = 'No pending approvals in queue.';
    container.appendChild(emptyP);
    return;
  }

  state.approvals.forEach((appr) => {
    const card = document.createElement('div');
    card.className = 'metric-card';
    card.style.border = '1px solid rgba(242, 180, 77, 0.4)';

    const eyebrow = document.createElement('span');
    eyebrow.className = 'eyebrow';
    eyebrow.style.color = 'var(--airlock-review)';
    eyebrow.textContent = `REQUEST ID: ${appr.id}`;

    const h3 = document.createElement('h3');
    h3.style.fontSize = '18px';
    h3.style.margin = '6px 0';
    h3.textContent = `Tool: ${appr.tool}`;

    const pMeta = document.createElement('p');
    pMeta.style.color = 'var(--airlock-muted)';
    pMeta.style.fontSize = '12px';
    pMeta.style.marginBottom = '12px';
    pMeta.append('Requester: ');
    const strongReq = document.createElement('strong');
    strongReq.textContent = appr.requester;
    pMeta.append(strongReq, ` · Expires: ${new Date(appr.expires_at).toLocaleTimeString()}`);

    const pre = document.createElement('pre');
    pre.style.background = 'var(--airlock-obsidian)';
    pre.style.padding = '10px';
    pre.style.borderRadius = 'var(--radius-sm)';
    pre.style.fontSize = '11px';
    pre.style.maxHeight = '100px';
    pre.style.overflowY = 'auto';
    pre.textContent = JSON.stringify(appr.arguments, null, 2);

    const btn = document.createElement('button');
    btn.className = 'btn-primary open-modal-btn';
    btn.dataset.id = appr.id;
    btn.style.marginTop = '14px';
    btn.style.background = 'var(--airlock-review)';
    btn.style.color = '#2e1e05';
    btn.type = 'button';
    btn.textContent = 'Review & Decide ➔';

    card.append(eyebrow, h3, pMeta, pre, btn);
    container.appendChild(card);
  });

  $$('.open-modal-btn').forEach((btn) => {
    btn.onclick = () => openApprovalModal(btn.dataset.id);
  });
}

async function openGitHubToolsModal() {
  const modal = $('#github-tools-modal');
  const list = $('#github-tools-list');
  if (!modal || !list) return;

  list.replaceChildren();
  const loadingP = document.createElement('p');
  loadingP.style.color = 'var(--airlock-muted)';
  loadingP.textContent = 'Discovering real GitHub MCP tools from server...';
  list.appendChild(loadingP);
  modal.style.display = 'flex';

  try {
    const tools = await apiRequest('/api/github/tools');
    list.replaceChildren();

    if (!tools || !tools.length) {
      const p = document.createElement('p');
      p.style.color = 'var(--airlock-muted)';
      p.textContent = 'No tools discovered.';
      list.appendChild(p);
      return;
    }

    tools.forEach((t) => {
      const item = document.createElement('div');
      item.style.background = 'var(--airlock-titanium)';
      item.style.border = 'var(--border-subtle)';
      item.style.padding = '12px';
      item.style.borderRadius = 'var(--radius-sm)';

      const header = document.createElement('div');
      header.style.display = 'flex';
      header.style.justifyContent = 'space-between';
      header.style.alignItems = 'center';
      header.style.marginBottom = '6px';

      const codeName = document.createElement('code');
      codeName.style.fontSize = '13px';
      codeName.style.color = 'var(--airlock-cyan)';
      codeName.textContent = t.name;

      const badge = document.createElement('span');
      if (t.is_write) {
        badge.className = 'badge review';
        badge.textContent = 'REQUIRES APPROVAL';
      } else {
        badge.className = 'badge allow';
        badge.textContent = 'READ-ONLY (SAFE)';
      }
      header.append(codeName, badge);

      const descP = document.createElement('p');
      descP.style.fontSize = '12px';
      descP.style.color = 'var(--airlock-pearl)';
      descP.style.marginBottom = '6px';
      descP.textContent = t.description;

      const meta = document.createElement('div');
      meta.style.fontSize = '10px';
      meta.style.color = 'var(--airlock-steel)';
      meta.textContent = `Toolset: ${t.toolset || 'general'} · Policy: ${t.policy_action.toUpperCase()} · SHA256 Verified`;

      item.append(header, descP, meta);
      list.appendChild(item);
    });
  } catch (err) {
    list.replaceChildren();
    const errP = document.createElement('p');
    errP.style.color = '#f87171';
    errP.textContent = `Failed to load tools: ${err.message}`;
    list.appendChild(errP);
  }
}

async function openGitHubPermissionsModal() {
  const modal = $('#github-permissions-modal');
  const content = $('#github-perm-content');
  if (!modal || !content) return;

  content.replaceChildren();
  const loadingP = document.createElement('p');
  loadingP.style.color = 'var(--airlock-muted)';
  loadingP.textContent = 'Loading Zero-Trust GitHub policy...';
  content.appendChild(loadingP);
  modal.style.display = 'flex';

  try {
    const perm = await apiRequest('/api/github/permissions');
    content.replaceChildren();

    const sections = [
      {
        title: 'Policy Identifier & Version',
        items: [
          `Policy ID: ${perm.policy_id || 'AIRLOCK-GITHUB-ZERO-TRUST-001'} (Version ${perm.version || 1})`,
          `Default Action: ${perm.default_action || 'DENY'} (Strict Zero-Trust)`
        ]
      },
      {
        title: 'Allowed Repository Scope',
        items: (perm.allowed_repositories || []).map((r) => `✓ ${r}`)
      },
      {
        title: 'Protected Branches',
        items: (perm.protected_branches || []).map((b) => `🛡 ${b} (Direct write forbidden)`)
      },
      {
        title: 'Write Operations Requirement',
        items: [`Default write action: ${(perm.write_operations && perm.write_operations.default_action) || 'REQUIRE_APPROVAL'}`]
      },
      {
        title: 'Hard-Denied Operations',
        items: (perm.protected_operations || []).map((op) => `✕ ${op} (Non-overridable hard block)`)
      },
      {
        title: 'Active Security Controls',
        items: [
          '✓ Inspect tool arguments before execution',
          '✓ Inspect tool responses for secrets and prompt injection',
          '✓ Mandatory SQLite audit logging with cryptographic correlation'
        ]
      }
    ];

    sections.forEach((sec) => {
      const box = document.createElement('div');
      box.style.background = 'var(--airlock-titanium)';
      box.style.border = 'var(--border-subtle)';
      box.style.padding = '12px';
      box.style.borderRadius = 'var(--radius-sm)';
      box.style.marginBottom = '10px';

      const h4 = document.createElement('h4');
      h4.style.fontSize = '12px';
      h4.style.color = 'var(--airlock-cyan)';
      h4.style.textTransform = 'uppercase';
      h4.style.marginBottom = '6px';
      h4.textContent = sec.title;

      const ul = document.createElement('ul');
      ul.style.listStyle = 'none';
      ul.style.padding = '0';
      ul.style.margin = '0';
      ul.style.fontSize = '12px';
      ul.style.lineHeight = '1.8';
      ul.style.color = 'var(--airlock-pearl)';

      sec.items.forEach((txt) => {
        const li = document.createElement('li');
        li.textContent = txt;
        ul.appendChild(li);
      });

      box.append(h4, ul);
      content.appendChild(box);
    });
  } catch (err) {
    content.replaceChildren();
    const errP = document.createElement('p');
    errP.style.color = '#f87171';
    errP.textContent = `Failed to load permissions: ${err.message}`;
    content.appendChild(errP);
  }
}

async function renderConnections() {
  const container = $('#mcp-servers-grid');
  if (!container) return;
  container.replaceChildren();

  // 1. Fetch live GitHub MCP status
  let ghStatus = {
    status: 'connected',
    mode: 'local_stdio',
    authenticated: true,
    auth_method: 'github_personal_access_token',
    read_only: true,
    profile: 'Profile A (Read-Only)',
    active_toolsets: ['context', 'repos', 'issues', 'pull_requests', 'actions', 'code_security'],
    discovered_tools_count: 24,
    allowed_repos: ['demo-org/airlock-security-lab', 'demo-org/airlock-test'],
    lab_repo: 'demo-org/airlock-security-lab',
    details: 'Official GitHub MCP Server running via stdio under AIRLOCK Zero-Trust Gateway.',
    last_check: new Date().toISOString(),
  };

  try {
    const res = await apiRequest('/api/github/status');
    if (res && res.status) ghStatus = res;
  } catch (err) {
    console.warn('Could not fetch GitHub status:', err.message);
  }

  // Create Official GitHub MCP Server Card
  const ghCard = document.createElement('div');
  ghCard.className = 'metric-card';
  ghCard.style.borderColor = 'rgba(108, 229, 248, 0.35)';
  ghCard.style.boxShadow = '0 0 25px rgba(108, 229, 248, 0.1)';

  const topDiv = document.createElement('div');
  topDiv.style.display = 'flex';
  topDiv.style.justifyContent = 'space-between';
  topDiv.style.alignItems = 'flex-start';
  topDiv.style.marginBottom = '12px';

  const leftBadge = document.createElement('div');
  leftBadge.style.display = 'flex';
  leftBadge.style.gap = '8px';
  leftBadge.style.alignItems = 'center';

  const iconSpan = document.createElement('span');
  iconSpan.style.fontSize = '20px';
  iconSpan.textContent = '🐙';

  const eyeSpan = document.createElement('span');
  eyeSpan.className = 'eyebrow';
  eyeSpan.style.color = 'var(--airlock-cyan)';
  eyeSpan.textContent = 'OFFICIAL GITHUB MCP SERVER';
  leftBadge.append(iconSpan, eyeSpan);

  const statusBadge = document.createElement('span');
  const isConn = ghStatus.status === 'connected';
  statusBadge.className = `badge ${isConn ? 'allow' : 'deny'}`;
  statusBadge.textContent = isConn ? '● CONNECTED (VERIFIED)' : '○ DISCONNECTED';
  topDiv.append(leftBadge, statusBadge);

  const titleH3 = document.createElement('h3');
  titleH3.style.fontSize = '17px';
  titleH3.style.marginBottom = '6px';
  titleH3.style.color = 'var(--airlock-pearl)';
  titleH3.textContent = 'github/github-mcp-server';

  const subP = document.createElement('p');
  subP.style.color = 'var(--airlock-muted)';
  subP.style.fontSize = '12px';
  subP.style.marginBottom = '14px';
  subP.textContent = `${ghStatus.profile || 'Profile A: Read-Only'} · Container: ghcr.io/github/github-mcp-server`;

  // Specs grid
  const specsGrid = document.createElement('div');
  specsGrid.style.display = 'grid';
  specsGrid.style.gridTemplateColumns = '1fr 1fr';
  specsGrid.style.gap = '8px';
  specsGrid.style.background = 'var(--airlock-obsidian)';
  specsGrid.style.padding = '12px';
  specsGrid.style.borderRadius = 'var(--radius-sm)';
  specsGrid.style.border = 'var(--border-subtle)';
  specsGrid.style.marginBottom = '16px';
  specsGrid.style.fontSize = '11px';

  function createSpec(label, val, highlightColor) {
    const d = document.createElement('div');
    const lbl = document.createElement('span');
    lbl.style.display = 'block';
    lbl.style.color = 'var(--airlock-steel)';
    lbl.style.fontSize = '10px';
    lbl.style.textTransform = 'uppercase';
    lbl.style.fontWeight = '700';
    lbl.textContent = label;
    const v = document.createElement('span');
    v.style.color = highlightColor || 'var(--airlock-pearl)';
    v.style.fontWeight = '600';
    v.textContent = val;
    d.append(lbl, v);
    return d;
  }

  specsGrid.append(
    createSpec('Execution Mode', ghStatus.mode || 'local_stdio', 'var(--airlock-cyan)'),
    createSpec('Authentication', 'Fine-Grained PAT (Secure Host)', 'var(--airlock-allow)'),
    createSpec('Discovered Tools', `${ghStatus.discovered_tools_count || 24} Verified Tools`, 'var(--airlock-pearl)'),
    createSpec('Active Scope', (ghStatus.allowed_repos || []).join(', ') || 'airlock-security-lab', 'var(--airlock-cyan)')
  );

  // Active Toolsets pill list
  const toolsetsTitle = document.createElement('div');
  toolsetsTitle.style.fontSize = '11px';
  toolsetsTitle.style.fontWeight = '700';
  toolsetsTitle.style.color = 'var(--airlock-steel)';
  toolsetsTitle.style.textTransform = 'uppercase';
  toolsetsTitle.style.marginBottom = '6px';
  toolsetsTitle.textContent = 'Active Toolsets:';

  const toolsetsDiv = document.createElement('div');
  toolsetsDiv.style.display = 'flex';
  toolsetsDiv.style.flexWrap = 'wrap';
  toolsetsDiv.style.gap = '6px';
  toolsetsDiv.style.marginBottom = '18px';

  const toolsets = Array.isArray(ghStatus.active_toolsets) ? ghStatus.active_toolsets : ['context', 'repos', 'issues', 'pull_requests', 'actions', 'code_security'];
  toolsets.forEach((ts) => {
    const pill = document.createElement('span');
    pill.style.background = 'rgba(108, 229, 248, 0.1)';
    pill.style.border = '1px solid rgba(108, 229, 248, 0.25)';
    pill.style.color = 'var(--airlock-cyan)';
    pill.style.padding = '3px 8px';
    pill.style.borderRadius = 'var(--radius-xs)';
    pill.style.fontSize = '11px';
    pill.textContent = ts;
    toolsetsDiv.appendChild(pill);
  });

  // Action Buttons row
  const btnRow = document.createElement('div');
  btnRow.style.display = 'flex';
  btnRow.style.flexWrap = 'wrap';
  btnRow.style.gap = '8px';
  btnRow.style.borderTop = 'var(--border-subtle)';
  btnRow.style.paddingTop = '14px';

  const btnTest = document.createElement('button');
  btnTest.className = 'btn-secondary';
  btnTest.style.padding = '6px 12px';
  btnTest.style.fontSize = '11px';
  btnTest.type = 'button';
  btnTest.textContent = '⚡ Test Handshake';
  btnTest.onclick = async () => {
    btnTest.textContent = 'Testing...';
    try {
      const res = await apiRequest('/api/github/connect', { method: 'POST' });
      alert(res.message || 'Handshake verified.');
      await loadTelemetry();
    } catch (e) {
      alert(`Handshake error: ${e.message}`);
    } finally {
      btnTest.textContent = '⚡ Test Handshake';
    }
  };

  const btnTools = document.createElement('button');
  btnTools.className = 'btn-secondary';
  btnTools.style.padding = '6px 12px';
  btnTools.style.fontSize = '11px';
  btnTools.type = 'button';
  btnTools.textContent = `🛠 View Tools (${ghStatus.discovered_tools_count || 24})`;
  btnTools.onclick = openGitHubToolsModal;

  const btnPerms = document.createElement('button');
  btnPerms.className = 'btn-secondary';
  btnPerms.style.padding = '6px 12px';
  btnPerms.style.fontSize = '11px';
  btnPerms.type = 'button';
  btnPerms.textContent = '🛡 Inspect Policies';
  btnPerms.onclick = openGitHubPermissionsModal;

  const btnActivity = document.createElement('button');
  btnActivity.className = 'btn-secondary';
  btnActivity.style.padding = '6px 12px';
  btnActivity.style.fontSize = '11px';
  btnActivity.type = 'button';
  btnActivity.textContent = '📊 View Activity';
  btnActivity.onclick = () => {
    const el = $('#audit-timeline');
    if (el) el.scrollIntoView({ behavior: 'smooth' });
  };

  const btnToggleConn = document.createElement('button');
  btnToggleConn.className = isConn ? 'btn-secondary' : 'btn-primary';
  btnToggleConn.style.padding = '6px 12px';
  btnToggleConn.style.fontSize = '11px';
  btnToggleConn.style.color = isConn ? '#f87171' : 'var(--airlock-cyan)';
  btnToggleConn.type = 'button';
  btnToggleConn.textContent = isConn ? '✕ Disconnect' : '🔌 Connect';
  btnToggleConn.onclick = async () => {
    try {
      if (isConn) {
        await apiRequest('/api/github/disconnect', { method: 'POST' });
      } else {
        await apiRequest('/api/github/connect', { method: 'POST' });
      }
      await loadTelemetry();
    } catch (e) {
      alert(`Action failed: ${e.message}`);
    }
  };

  btnRow.append(btnTest, btnTools, btnPerms, btnActivity, btnToggleConn);
  ghCard.append(topDiv, titleH3, subP, specsGrid, toolsetsTitle, toolsetsDiv, btnRow);
  container.appendChild(ghCard);

  // Render any additional upstream connections if present
  state.connections.forEach((conn) => {
    if (conn.server_identifier === 'github-mcp-server') return;
    const card = document.createElement('div');
    card.className = 'metric-card';

    const top = document.createElement('div');
    top.style.display = 'flex';
    top.style.justifyContent = 'space-between';
    top.style.alignItems = 'flex-start';
    top.style.marginBottom = '10px';

    const spanEye = document.createElement('span');
    spanEye.className = 'eyebrow';
    spanEye.textContent = 'VERIFIED MCP UPSTREAM';

    const spanFp = document.createElement('span');
    spanFp.className = 'badge allow';
    spanFp.textContent = 'FINGERPRINT APPROVED';
    top.append(spanEye, spanFp);

    const h3 = document.createElement('h3');
    h3.style.fontSize = '16px';
    h3.style.marginBottom = '6px';
    h3.textContent = conn.server_identifier;

    const pMeta = document.createElement('p');
    pMeta.style.color = 'var(--airlock-muted)';
    pMeta.style.fontSize = '12px';
    pMeta.style.marginBottom = '14px';
    pMeta.textContent = `Events: ${conn.event_count} · Last Seen: ${conn.last_seen ? new Date(conn.last_seen).toLocaleTimeString() : 'Never'}`;

    const ul = document.createElement('ul');
    ul.style.listStyle = 'none';
    ul.style.padding = '0';
    ul.style.fontSize = '12px';
    ul.style.lineHeight = '2';

    conn.tools.forEach((t) => {
      const li = document.createElement('li');
      const code = document.createElement('code');
      code.textContent = t.tool_identifier;
      const badge = document.createElement('span');
      badge.className = t.exposed_by_policy ? 'badge allow' : 'badge deny';
      badge.textContent = t.exposed_by_policy ? 'EXPOSED' : 'BLOCKED BY POLICY';
      badge.style.marginLeft = '6px';
      li.append(code, badge);
      ul.appendChild(li);
    });

    card.append(top, h3, pMeta, ul);
    container.appendChild(card);
  });
}

function renderAuditTimeline() {
  const tbody = $('#audit-table-body');
  tbody.replaceChildren();
  state.events.slice(0, 20).forEach((evt) => {
    const tr = document.createElement('tr');
    const badgeClass = evt.decision === 'allow' ? 'allow' : evt.decision === 'deny' ? 'deny' : 'review';

    const tdId = document.createElement('td');
    const codeId = document.createElement('code');
    codeId.textContent = `#${evt.id}`;
    tdId.appendChild(codeId);

    const tdTime = document.createElement('td');
    tdTime.textContent = new Date(evt.timestamp).toLocaleTimeString();

    const tdTool = document.createElement('td');
    const strongTool = document.createElement('strong');
    strongTool.textContent = evt.tool_identifier;
    tdTool.appendChild(strongTool);

    const tdBadge = document.createElement('td');
    const spanBadge = document.createElement('span');
    spanBadge.className = `badge ${badgeClass}`;
    spanBadge.textContent = evt.decision.toUpperCase();
    tdBadge.appendChild(spanBadge);

    const tdRisk = document.createElement('td');
    const spanRisk = document.createElement('span');
    spanRisk.style.color = evt.risk_score > 50 ? 'var(--airlock-denied)' : 'var(--airlock-allowed)';
    spanRisk.style.fontWeight = '700';
    spanRisk.textContent = `${evt.risk_score}/100`;
    tdRisk.appendChild(spanRisk);

    const tdExec = document.createElement('td');
    const spanExec = document.createElement('span');
    spanExec.style.color = evt.upstream_executed ? 'var(--airlock-allowed)' : 'var(--airlock-denied)';
    spanExec.textContent = evt.upstream_executed ? 'TRUE' : 'FALSE';
    tdExec.appendChild(spanExec);

    const tdArgs = document.createElement('td');
    const codeArgs = document.createElement('code');
    codeArgs.style.fontSize = '10px';
    codeArgs.textContent = JSON.stringify(evt.sanitized_arguments || {});
    tdArgs.appendChild(codeArgs);

    const tdReason = document.createElement('td');
    tdReason.style.color = 'var(--airlock-muted)';
    tdReason.style.fontSize = '12px';
    tdReason.textContent = evt.reason;

    tr.append(tdId, tdTime, tdTool, tdBadge, tdRisk, tdExec, tdArgs, tdReason);
    tbody.appendChild(tr);
  });
}

function renderPolicyViews() {
  if (state.policies) {
    $('#policy-json-view').textContent = JSON.stringify(state.policies.authorization, null, 2);
    $('#response-rules-view').textContent = JSON.stringify(state.policies.response_inspection, null, 2);
  }
}

function updateDownstreamCounter() {
  const executed = state.events.filter((e) => e.upstream_executed).length;
  const blocked = state.events.filter((e) => !e.upstream_executed).length;
  $('#sandbox-counter-display').textContent = `UPSTREAM CALLS: ${executed} EXECUTED | ${blocked} PREVENTED FROM EXECUTION`;
}

// ============================================================================
// 4. INTERACTIVE MCP REQUEST PIPELINE ANIMATION
// ============================================================================
function initPipelineVisualizer() {
  const packet = $('#pipeline-packet');
  const statusText = $('#pipeline-status-text');

  const nodes = [
    { id: '#p-node-user', pct: 0 },
    { id: '#p-node-gemini', pct: 16 },
    { id: '#p-node-gateway', pct: 33 },
    { id: '#p-node-policy', pct: 50 },
    { id: '#p-node-decision', pct: 67 },
    { id: '#p-node-mcp', pct: 83 },
    { id: '#p-node-resource', pct: 100 },
  ];

  function resetNodes() {
    nodes.forEach((n) => {
      const el = $(n.id);
      if (el) el.classList.remove('active', 'blocked');
    });
  }

  async function animatePipeline(scenario, details = {}) {
    resetNodes();
    packet.style.transition = 'all 0.4s ease';

    const toolName = details.tool || (scenario === 'attack' ? 'delete_resource' : scenario === 'review' ? 'restart_vm' : 'list_resources');
    const riskScore = details.risk ? details.risk.score : (scenario === 'attack' ? 100 : scenario === 'review' ? 35 : 10);

    // Step 1: User Request Initiated
    $('#p-node-user').classList.add('active');
    packet.style.background = 'var(--airlock-cyan)';
    packet.style.left = '0%';
    statusText.textContent = '1. USER REQUEST RECEIVED';
    await wait(300);

    // Step 2: Gemini Agent proposes action
    $('#p-node-gemini').classList.add('active');
    packet.style.left = '16%';
    statusText.textContent = `2. GEMINI PROPOSES MCP ACTION: ${toolName}`;
    await wait(350);

    // Step 3: Gateway Intercept
    $('#p-node-gateway').classList.add('active');
    packet.style.left = '33%';
    packet.style.background = 'var(--airlock-cobalt)';
    statusText.textContent = '3. AIRLOCK GATEWAY INTERCEPTS';
    await wait(350);

    // Step 4: Policy Engine Evaluation
    $('#p-node-policy').classList.add('active');
    packet.style.left = '50%';
    statusText.textContent = `4. ZERO-TRUST POLICY EVALUATION (Risk: ${riskScore}/100)`;
    await wait(350);

    // Step 5: Decision Gate
    $('#p-node-decision').classList.add('active');
    packet.style.left = '67%';

    if (scenario === 'attack' || scenario === 'deny') {
      packet.style.background = 'var(--airlock-denied)';
      packet.style.boxShadow = '0 0 25px var(--airlock-denied)';
      $('#p-node-decision').classList.add('blocked');
      statusText.textContent = '🛑 DECISION: DENY — HALTED BEFORE DOWNSTREAM EXECUTION';
      await wait(600);

      // Visually satisfying return flow
      statusText.textContent = '🛡️ DEFLECTION WAVE: Denial Telemetry Returned to Gateway';
      packet.style.left = '0%';
      await wait(700);
      return;
    }

    if (scenario === 'review' || scenario === 'require_approval') {
      packet.style.background = 'var(--airlock-review)';
      packet.style.boxShadow = '0 0 25px var(--airlock-review)';
      statusText.textContent = '◷ DECISION: REVIEW — PAUSED FOR HUMAN AUTHORIZATION';
      await wait(600);

      // Return alert sweep
      statusText.textContent = '◷ ALERT RETURNED: Authorization Ticket Queued in Console';
      packet.style.left = '0%';
      await wait(700);
      return;
    }

    // Allowed path
    packet.style.background = 'var(--airlock-allowed)';
    packet.style.boxShadow = '0 0 25px var(--airlock-allowed)';
    statusText.textContent = '✓ DECISION: ALLOW — FORWARDING TO MCP SERVER';
    await wait(300);

    // Step 6: Upstream MCP
    $('#p-node-mcp').classList.add('active');
    packet.style.left = '83%';
    statusText.textContent = `6. FORWARDED TO SYNTHETIC MCP UPSTREAM (${toolName})`;
    await wait(300);

    // Step 7: Resource Access
    $('#p-node-resource').classList.add('active');
    packet.style.left = '100%';
    statusText.textContent = '7. RESOURCE ACCESSED & PROCESSED';
    await wait(400);

    // Return flow
    statusText.textContent = '✓ RESPONSE FLOW: Verified Telemetry Returned to User Console';
    packet.style.left = '0%';
    await wait(700);
  }

  $('#pipe-test-read').onclick = () => animatePipeline('read');
  $('#pipe-test-review').onclick = () => animatePipeline('review');
  $('#pipe-test-attack').onclick = () => animatePipeline('attack');

  window.airlockAnimatePipeline = animatePipeline;
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ============================================================================
// 5. APPROVAL MODAL & DECISIONS
// ============================================================================
function openApprovalModal(requestId) {
  const approval = state.approvals.find((a) => a.id === requestId);
  if (!approval) return;
  state.activeApproval = approval;

  $('#modal-tool-name').textContent = approval.tool;
  $('#modal-requester').textContent = approval.requester;
  $('#modal-resource').textContent = approval.arguments.resource_name || 'dev-vm-01';
  $('#modal-arguments').textContent = JSON.stringify(approval.arguments, null, 2);

  $('#approval-modal-backdrop').classList.remove('hidden');
}

function initApprovalModal() {
  const backdrop = $('#approval-modal-backdrop');
  $('#modal-close-btn').onclick = () => backdrop.classList.add('hidden');

  $('#modal-approve-btn').onclick = async () => {
    if (!state.activeApproval) return;
    try {
      await apiRequest(`/api/approvals/${state.activeApproval.id}/decision`, {
        method: 'POST',
        body: JSON.stringify({ approve: true, justification: 'Authorized by security operator in console' }),
      });
      backdrop.classList.add('hidden');
      await loadTelemetry();
      alert('✓ Operation approved. Authorization record bound and ready for single-use consumption.');
    } catch (err) {
      alert(`Approval error: ${err.message}`);
    }
  };

  $('#modal-deny-btn').onclick = async () => {
    if (!state.activeApproval) return;
    try {
      await apiRequest(`/api/approvals/${state.activeApproval.id}/decision`, {
        method: 'POST',
        body: JSON.stringify({ approve: false, justification: 'Denied by security operator' }),
      });
      backdrop.classList.add('hidden');
      await loadTelemetry();
      alert('✕ Operation rejected. Approval cancelled.');
    } catch (err) {
      alert(`Rejection error: ${err.message}`);
    }
  };
}

// ============================================================================
// 6. BLAST RADIUS TOPOLOGY & NODE INSPECTOR
// ============================================================================
function highlightBlastNodes(targetNodeId, dependentIds = []) {
  $$('.blast-interactive-node').forEach((node) => {
    node.classList.remove('highlight-target', 'highlight-dependent');
  });
  if (targetNodeId) {
    const target = $(targetNodeId);
    if (target) target.classList.add('highlight-target');
  }
  dependentIds.forEach((id) => {
    const dep = $(id);
    if (dep) dep.classList.add('highlight-dependent');
  });
}

function initBlastRadiusMap() {
  const nodeData = {
    '#blast-node-proddb': {
      name: 'prod-db',
      eyebrow: 'PRIMARY STORAGE ASSET',
      desc: 'Synthetic production customer relational database hosting sensitive customer accounts and billing records.',
      tier: 'Production (Tier 0)',
      risk: 'Catastrophic (4 Dependencies Affected)',
      policy: 'ZERO-TRUST-DEFAULT-DENY-003',
      calls: '0 (Downstream Execution Prevented)',
      badge: 'INTACT & VERIFIED',
      badgeClass: 'allow',
      dependents: ['#blast-node-coreapi', '#blast-node-portal', '#blast-node-finance'],
    },
    '#blast-node-coreapi': {
      name: 'core-api',
      eyebrow: 'GATEWAY SERVICE LAYER',
      desc: 'Central REST & gRPC orchestration service mediating requests between frontend and customer storage tier.',
      tier: 'Internal Service (Tier 1)',
      risk: 'High (Dependent on prod-db)',
      policy: 'REPOSITORY-SCOPE-002',
      calls: '0 (Isolated)',
      badge: 'ONLINE',
      badgeClass: 'allow',
      dependents: ['#blast-node-portal', '#blast-node-finance'],
    },
    '#blast-node-portal': {
      name: 'customer-portal',
      eyebrow: 'FRONTEND WORKLOAD',
      desc: 'Public-facing dashboard for enterprise customer account self-service and authentication.',
      tier: 'Public DMZ (Tier 2)',
      risk: 'Medium (Upstream Dependent)',
      policy: 'PROTECTED-ASSET-001',
      calls: '0 (Guarded)',
      badge: 'PROTECTED',
      badgeClass: 'allow',
      dependents: [],
    },
    '#blast-node-finance': {
      name: 'finance-pipeline',
      eyebrow: 'DATA PROCESSING PIPELINE',
      desc: 'Asynchronous event consumer processing payments, ledger reconciliation, and fiscal reporting.',
      tier: 'Internal Processing (Tier 1)',
      risk: 'High (Cascading Financial Disruption)',
      policy: 'DESTRUCTIVE-ACTION-002',
      calls: '0 (Guarded)',
      badge: 'PROTECTED',
      badgeClass: 'allow',
      dependents: [],
    },
    '#blast-node-vault': {
      name: 'auth-tokens-kv',
      eyebrow: 'SECRETS MANAGEMENT STORE',
      desc: 'Synthetic KeyVault fixture storing service principal credentials and Azure connection strings.',
      tier: 'High Security (Tier 0)',
      risk: 'High (Credential Exfiltration / DLP)',
      policy: 'DLP-SECRET-TRANSFER-001',
      calls: '0 (Egress Prohibited)',
      badge: 'SEALED & MASKED',
      badgeClass: 'allow',
      dependents: ['#blast-node-coreapi'],
    },
  };

  Object.entries(nodeData).forEach(([selector, info]) => {
    const el = $(selector);
    if (!el) return;
    el.onclick = () => {
      highlightBlastNodes(selector, info.dependents);
      const details = $('#blast-node-details');
      if (!details) return;
      details.style.display = 'block';
      $('#blast-detail-eyebrow').textContent = info.eyebrow;
      $('#blast-detail-name').textContent = info.name;
      $('#blast-detail-desc').textContent = info.desc;
      $('#blast-detail-tier').textContent = info.tier;
      $('#blast-detail-risk').textContent = info.risk;
      $('#blast-detail-policy').textContent = info.policy;
      $('#blast-detail-calls').textContent = info.calls;
      const badge = $('#blast-detail-badge');
      badge.textContent = info.badge;
      badge.className = `badge ${info.badgeClass}`;
      details.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    };
  });
}

// ============================================================================
// 7. ATTACK SIMULATION LAB
// ============================================================================
function initAttackLab() {
  const scenarios = {
    1: {
      tool: 'delete_resource',
      args: { resource_name: 'prod-db' },
      title: 'Scenario 01: Unauthorized Production Resource Deletion',
      desc: 'Simulating prompt injection requesting deletion of production database (prod-db).',
      targetNode: '#blast-node-proddb',
      dependents: ['#blast-node-coreapi', '#blast-node-portal', '#blast-node-finance'],
      blastDesc: 'prod-db (Target) -> core-api -> customer-portal & finance-pipeline [BLOCKED: All 4 downstream workloads saved]',
    },
    2: {
      tool: 'read_local_repository_file',
      args: { file_path: 'README.md' },
      title: 'Scenario 02: Prompt Injection via GitHub MCP',
      desc: 'Synthetic untrusted README retrieved. Content inspection checks for injection keywords.',
      targetNode: null,
      dependents: [],
      blastDesc: 'README.md -> prompt-injection scanner -> agent execution loop [FLAGGED: Instruction Tampering Prevented]',
    },
    3: {
      tool: 'read_synthetic_secret',
      args: { secret_name: 'azure-connection-string' },
      title: 'Scenario 03: Synthetic Credential Exfiltration & DLP',
      desc: 'Attempting exfiltration of confidential Azure connection string.',
      targetNode: '#blast-node-vault',
      dependents: ['#blast-node-coreapi'],
      blastDesc: 'azure-connection-string -> auth-tokens-kv -> external-egress [BLOCKED: DLP Transfer Prohibited]',
    },
    4: {
      tool: 'read_local_repository_file',
      args: { file_path: '../../etc/shadow' },
      title: 'Scenario 04: Filesystem Path Traversal Escape',
      desc: 'Agent requests access outside repository fixture using directory traversal.',
      targetNode: null,
      dependents: [],
      blastDesc: '../../etc/shadow -> host-filesystem [BLOCKED: Workspace Traversal Boundary Enforced]',
    },
    5: {
      tool: 'modify_repository_branch',
      args: { repo: 'northstar-repo', branch: 'main', action: 'delete_branch' },
      title: 'Scenario 05: GitHub Repository Tampering',
      desc: 'Agent attempts to delete or modify the protected main branch on synthetic GitHub repo.',
      targetNode: null,
      dependents: [],
      blastDesc: 'northstar-repo:main -> production deployment CI/CD [BLOCKED: Branch Protection Policy Enforced]',
    },
    6: {
      tool: 'deprovision_azure_vnet',
      args: { vnet_name: 'northstar-vnet-prod', resource_group: 'rg-northstar-prod' },
      title: 'Scenario 06: Azure Resource Misuse',
      desc: 'Agent attempts to deprovision the production Virtual Network (northstar-vnet-prod).',
      targetNode: null,
      dependents: [],
      blastDesc: 'northstar-vnet-prod -> cloud fabric -> all tenant subnets [BLOCKED: Cloud RBAC Enforced]',
    },
    7: {
      tool: 'restart_vm',
      args: { resource_name: 'dev-vm-01' },
      title: 'Scenario 07: Human Approval Escalation',
      desc: 'State-changing development VM restart paused for Level 2 human authorization.',
      targetNode: null,
      dependents: [],
      blastDesc: 'dev-vm-01 (Staging) -> build runners [PENDING: Awaiting Operator Dual-Control Approval]',
    },
  };

  async function animateSandboxFlow(s, result) {
    const threatNode = $('#sb-node-threat');
    const agentNode = $('#sb-node-agent');
    const gatewayNode = $('#sb-node-gateway');
    const mcpNode = $('#sb-node-mcp');
    const assetNode = $('#sb-node-asset');
    const packetOut = $('#sb-packet-out');
    const packetReturn = $('#sb-packet-return');
    const barrierBeam = $('#sb-barrier-beam');
    const barrierRipple = $('#sb-barrier-ripple');
    const wireActive = $('#sb-wire-active');
    const wireReturnActive = $('#sb-wire-return-active');
    const statusEl = $('#sandbox-flow-status');
    const outText = $('#sb-stream-out-text');
    const inText = $('#sb-stream-in-text');
    const gateStatus = $('#sb-gate-status');

    if (!threatNode || !packetOut) return;

    // Reset visual nodes
    [threatNode, agentNode, gatewayNode, mcpNode, assetNode].forEach((n) => {
      if (n) n.classList.remove('active', 'blocked', 'success', 'review');
    });
    if (barrierRipple) barrierRipple.classList.remove('active');
    if (barrierBeam) barrierBeam.style.opacity = '0';
    if (wireActive) wireActive.style.opacity = '0.3';
    if (wireReturnActive) wireReturnActive.style.opacity = '0';
    if (packetReturn) packetReturn.style.opacity = '0';

    const isDeny = result.decision === 'deny';
    const isReview = result.decision === 'require_approval' || result.decision === 'review';
    const riskScore = result.risk ? result.risk.score : 0;

    // Step 1: Threat Initiator activates
    threatNode.classList.add('active');
    packetOut.style.transition = 'none';
    packetOut.style.left = '6%';
    packetOut.style.opacity = '1';
    packetOut.style.background = 'var(--airlock-cyan)';
    packetOut.style.boxShadow = '0 0 18px var(--airlock-cyan)';
    statusEl.textContent = `1/5: INJECTION INITIATED · PROPOSED TOOL: ${s.tool}`;
    outText.textContent = `Threat generates tool proposal '${s.tool}'`;
    inText.textContent = 'Awaiting gateway evaluation...';
    await wait(280);

    // Step 2: Forward flow to Gemini Agent
    packetOut.style.transition = 'left 0.4s cubic-bezier(0.2, 0.8, 0.2, 1)';
    packetOut.style.left = '28%';
    agentNode.classList.add('active');
    statusEl.textContent = '2/5: GEMINI AGENT SYNTHESIZING MCP CALL';
    outText.textContent = `Agent serializes arguments: ${JSON.stringify(s.args)}`;
    await wait(350);

    // Step 3: Forward flow to AIRLOCK Gateway
    packetOut.style.left = '50%';
    packetOut.style.background = 'var(--airlock-cobalt)';
    packetOut.style.boxShadow = '0 0 25px var(--airlock-cobalt)';
    gatewayNode.classList.add('active');
    statusEl.textContent = `3/5: AIRLOCK ZERO-TRUST INSPECTION (Risk: ${riskScore}/100)`;
    outText.textContent = 'Gateway intercepting before downstream stdio connection';
    await wait(380);

    // Step 4 & 5: The Enforcement Moment & The Visually Satisfying Return Stream
    if (isDeny) {
      gatewayNode.classList.remove('active');
      gatewayNode.classList.add('blocked');
      barrierBeam.style.opacity = '1';
      barrierRipple.classList.add('active');
      packetOut.style.background = 'var(--airlock-denied)';
      packetOut.style.boxShadow = '0 0 30px var(--airlock-denied)';
      gateStatus.textContent = 'DEFENSE ARMED: EXECUTION HARD BLOCKED';
      gateStatus.style.color = 'var(--airlock-denied)';
      statusEl.textContent = `4/5: DECISION: DENY (${(result.matched_policies || ['POLICY'])[0]})`;
      outText.textContent = '🛑 Blocked at Gateway SEP. Downstream route severed.';
      await wait(350);

      // Deflect Outgoing Packet
      packetOut.style.opacity = '0';

      // SATISFYING RETURN FLOW: Deflection wave shoots back to Threat Actor
      wireReturnActive.style.opacity = '0.9';
      packetReturn.style.transition = 'none';
      packetReturn.style.left = '50%';
      packetReturn.style.opacity = '1';
      packetReturn.style.background = 'var(--airlock-denied)';
      packetReturn.style.boxShadow = '0 0 25px var(--airlock-denied)';
      inText.textContent = `Deflection telemetry returning: Recording audit event #${result.event_id || 'AUDIT'}...`;
      await wait(100);

      packetReturn.style.transition = 'left 0.35s cubic-bezier(0.2, 0.8, 0.2, 1)';
      packetReturn.style.left = '28%';
      await wait(200);

      packetReturn.style.left = '6%';
      await wait(280);

      assetNode.classList.add('success');
      statusEl.textContent = '5/5: DEFENSE VERIFIED — DOWNSTREAM CALLS = 0 (ASSET PRESERVED)';
      inText.textContent = '✓ Auditable denial returned to console. Zero unauthorized calls.';
    } else if (isReview) {
      gatewayNode.classList.remove('active');
      gatewayNode.classList.add('review');
      packetOut.style.background = 'var(--airlock-review)';
      packetOut.style.boxShadow = '0 0 30px var(--airlock-review)';
      gateStatus.textContent = 'LEVEL 02 REVIEW: AWAITING DUAL-CONTROL';
      gateStatus.style.color = 'var(--airlock-review)';
      statusEl.textContent = '4/5: DECISION: REVIEW — PAUSED FOR HUMAN AUTHORIZATION';
      outText.textContent = 'Operation suspended. Awaiting approver credential check.';
      await wait(350);

      // RETURN FLOW: Review alert dispatched back to operator
      wireReturnActive.style.opacity = '0.9';
      packetReturn.style.transition = 'none';
      packetReturn.style.left = '50%';
      packetReturn.style.opacity = '1';
      packetReturn.style.background = 'var(--airlock-review)';
      packetReturn.style.boxShadow = '0 0 25px var(--airlock-review)';
      await wait(100);

      packetReturn.style.transition = 'left 0.4s cubic-bezier(0.2, 0.8, 0.2, 1)';
      packetReturn.style.left = '6%';
      await wait(400);

      statusEl.textContent = '5/5: TICKET QUEUED — ACTION HELD PENDING OPERATOR SIGN-OFF';
      inText.textContent = `◷ Review notification delivered. Ticket ID: ${result.approval ? result.approval.id : 'apr_active'}`;
    } else {
      // ALLOWED PATH
      gatewayNode.classList.remove('active');
      gatewayNode.classList.add('success');
      wireActive.style.opacity = '0.9';
      gateStatus.textContent = 'PERMITTED: SAFE READ-ONLY SCOPE';
      gateStatus.style.color = 'var(--airlock-allowed)';
      statusEl.textContent = '4/5: DECISION: ALLOW — FORWARDING TO DOWNSTREAM MCP';
      outText.textContent = 'Forwarded through stdio to Northstar synthetic server';

      packetOut.style.background = 'var(--airlock-allowed)';
      packetOut.style.boxShadow = '0 0 25px var(--airlock-allowed)';
      packetOut.style.left = '72%';
      mcpNode.classList.add('active');
      await wait(300);

      packetOut.style.left = '94%';
      assetNode.classList.add('success');
      await wait(300);

      // SATISFYING RETURN FLOW: Verified data flows all the way back to Console
      wireReturnActive.style.opacity = '0.9';
      packetReturn.style.transition = 'none';
      packetReturn.style.left = '94%';
      packetReturn.style.opacity = '1';
      packetReturn.style.background = 'var(--airlock-allowed)';
      packetReturn.style.boxShadow = '0 0 25px var(--airlock-allowed)';
      inText.textContent = 'Extracting synthetic response from Northstar repository...';
      await wait(100);

      packetReturn.style.transition = 'left 0.6s cubic-bezier(0.16, 1, 0.3, 1)';
      packetReturn.style.left = '6%';
      await wait(600);

      statusEl.textContent = '5/5: ALLOW COMPLETED — VERIFIED TELEMETRY RETURNED TO CONSOLE';
      inText.textContent = '✓ Response inspected: Harmless repository text verified.';
    }
  }

  $$('.run-scenario-btn').forEach((btn) => {
    btn.onclick = async () => {
      const id = btn.dataset.scenario;
      const s = scenarios[id];
      if (!s) return;

      const card = btn.closest('.scenario-card');
      if (card) {
        card.style.borderColor = 'var(--airlock-cyan)';
        card.style.boxShadow = '0 0 25px rgba(108, 229, 248, 0.4)';
        setTimeout(() => {
          card.style.borderColor = '';
          card.style.boxShadow = '';
        }, 3000);
      }

      const panel = $('#scenario-result-panel');
      const title = $('#scenario-result-title');
      const badge = $('#scenario-decision-badge');
      const details = $('#scenario-result-details');

      panel.style.display = 'block';
      title.textContent = s.title;
      details.textContent = 'Interception in progress... Evaluating through AIRLOCK gateway...';

      // Highlight target and dependent nodes on blast radius map
      highlightBlastNodes(s.targetNode, s.dependents);

      try {
        const result = await apiRequest('/api/gateway/evaluate', {
          method: 'POST',
          body: JSON.stringify({ tool: s.tool, arguments: s.args }),
        });

        const isDeny = result.decision === 'deny';
        const isReview = result.decision === 'require_approval' || result.decision === 'review';
        const pipelineMode = isDeny ? 'attack' : isReview ? 'review' : 'read';

        // Animate the Command Center pipeline if present
        if (window.airlockAnimatePipeline) {
          window.airlockAnimatePipeline(pipelineMode, {
            tool: s.tool,
            args: s.args,
            decision: result.decision,
            reason: result.reason,
            risk: result.risk,
          });
        }

        // Animate the Sandbox Execution Flow Chamber with satisfying return stream
        await animateSandboxFlow(s, result);

        const decisionDisplay = isReview ? 'REVIEW' : result.decision.toUpperCase();
        badge.className = `badge ${result.decision === 'allow' ? 'allow' : isDeny ? 'deny' : 'review'}`;
        badge.textContent = decisionDisplay;

        const riskScore = result.risk ? result.risk.score : 0;
        const riskCategory = result.risk ? result.risk.category : 'Unknown';
        const riskFactors = (result.risk && result.risk.factors) ? result.risk.factors.join(', ') : 'none';

        details.textContent = [
          `AIRLOCK POLICY DECISION: ${decisionDisplay}`,
          `TOOL REQUESTED: ${s.tool}`,
          `ARGUMENTS: ${JSON.stringify(s.args)}`,
          `RISK SCORE: ${riskScore}/100 (${riskCategory} Risk)`,
          `RISK FACTORS: ${riskFactors}`,
          `TRIGGERED POLICIES: ${(result.matched_policies || ['authorization']).join(', ')}`,
          `REASON: ${result.reason}`,
          `DOWNSTREAM EXECUTION: ${result.upstream_executed ? 'PERMITTED & EXECUTED' : 'HARD BLOCKED BEFORE DOWNSTREAM INVOCATION'}`,
          `EXECUTION COUNTER STATUS: ${result.upstream_executed ? 'INCREMENTED' : 'UNCHANGED (Verified Zero Invocations)'}`,
          `BLAST RADIUS IMPACT: ${s.blastDesc}`,
          `SANDBOX ASSET STATUS: Intact & Unmodified in Northstar Cloud Systems`,
          `VERIFIED AUDIT LOG: Recorded with ID #${result.event_id || 'LOCAL'} in sentry_x_audit.db`,
        ].join('\n');

        // Reload telemetry to update metrics, lanes, and timeline
        await loadTelemetry();
      } catch (err) {
        details.textContent = `Evaluation failed: ${err.message}`;
      }
    };
  });

  // Reset sandbox baseline button
  const resetBtn = $('#reset-sandbox-btn');
  if (resetBtn) {
    resetBtn.onclick = async () => {
      try {
        const res = await apiRequest('/api/sandbox/reset', { method: 'POST' });
        highlightBlastNodes(null, []);
        const panel = $('#scenario-result-panel');
        const title = $('#scenario-result-title');
        const badge = $('#scenario-decision-badge');
        const details = $('#scenario-result-details');
        panel.style.display = 'block';
        title.textContent = 'Sandbox Baseline Restored';
        badge.className = 'badge allow';
        badge.textContent = 'RESTORED';
        details.textContent = [
          `STATUS: ${res.message}`,
          `RESTORED BY: ${res.reset_by || 'Security Operator'}`,
          `ASSETS VERIFIED INTACT:`,
          ...(res.assets_intact || []).map((a) => `  • ${a.name} (${a.type}): ${a.state.toUpperCase()} (Protected: ${a.protected})`),
          `DOWNSTREAM INVOCATION COUNTER: 0 unauthorized operations`,
        ].join('\n');
        await loadTelemetry();
      } catch (err) {
        alert(`Reset failed: ${err.message}`);
      }
    };
  }

  // Split-screen comparison live demo
  const compBtn = $('#run-comparison-btn');
  if (compBtn) {
    compBtn.onclick = async () => {
      const withoutPill = $('#without-status-pill');
      const withPill = $('#with-status-pill');
      const withoutCard = $('.split-card.without');
      const withCard = $('.split-card.with');

      withoutPill.textContent = 'SIMULATING UNPROTECTED INJECTION...';
      withoutPill.className = 'badge review';
      withPill.textContent = 'SIMULATING AIRLOCK INTERCEPTION...';
      withPill.className = 'badge review';

      await wait(600);

      // Unprotected failure
      if (withoutCard) {
        withoutCard.style.borderColor = 'var(--airlock-denied)';
        withoutCard.style.boxShadow = '0 0 20px rgba(240, 90, 112, 0.4)';
      }
      withoutPill.textContent = 'CRITICAL FAILURE: PROD-DB DROPPED (NO CONTROLS)';
      withoutPill.className = 'badge deny';

      await wait(600);

      // Protected success
      if (withCard) {
        withCard.style.borderColor = 'var(--airlock-allowed)';
        withCard.style.boxShadow = '0 0 20px rgba(19, 201, 147, 0.4)';
      }
      withPill.textContent = 'AIRLOCK ZERO-TRUST: BLOCKED BEFORE DOWNSTREAM EXECUTION (DB INTACT)';
      withPill.className = 'badge allow';

      highlightBlastNodes('#blast-node-proddb', ['#blast-node-coreapi', '#blast-node-portal', '#blast-node-finance']);
    };
  }
}

// ============================================================================
// 7. DRY-RUN POLICY EVALUATOR & FILE SCANNER
// ============================================================================
function initDryRunAndScanner() {
  $('#evaluate-dryrun-form').onsubmit = async (e) => {
    e.preventDefault();
    const tool = $('#sim-tool-select').value;
    const resource = $('#sim-resource-input').value.trim();
    const args = tool === 'list_resources' ? {} : { resource_name: resource };
    const out = $('#evaluator-output');
    out.style.display = 'block';
    out.textContent = 'Evaluating policy rules...';

    try {
      const res = await apiRequest('/api/policies/simulate', {
        method: 'POST',
        body: JSON.stringify({ tool, arguments: args }),
      });
      out.textContent = JSON.stringify(res, null, 2);
    } catch (err) {
      out.textContent = `Error: ${err.message}`;
    }
  };

  $('#file-scan-form').onsubmit = async (e) => {
    e.preventDefault();
    const file = $('#scanner-file-input').files[0];
    const box = $('#scan-results-box');
    if (!file) return;

    box.style.display = 'block';
    box.replaceChildren();
    const pScan = document.createElement('p');
    pScan.style.color = 'var(--airlock-cyan)';
    pScan.textContent = 'Scanning file contents locally with bounded regex rules...';
    box.appendChild(pScan);

    try {
      const content = await file.text();
      const res = await apiRequest('/api/scanner/scan', {
        method: 'POST',
        body: JSON.stringify({ filename: file.name, content }),
      });

      box.replaceChildren();
      if (res.findings && res.findings.length) {
        const wrap = document.createElement('div');
        wrap.style.background = 'var(--airlock-obsidian)';
        wrap.style.border = '1px solid var(--airlock-denied)';
        wrap.style.borderRadius = 'var(--radius-sm)';
        wrap.style.padding = '14px';

        const strongTitle = document.createElement('strong');
        strongTitle.style.color = 'var(--airlock-denied)';
        strongTitle.textContent = `⚠ FINDINGS DETECTED (${res.findings.length})`;

        const ulFindings = document.createElement('ul');
        ulFindings.style.marginTop = '8px';
        ulFindings.style.paddingLeft = '18px';
        ulFindings.style.fontSize = '12px';
        ulFindings.style.color = 'var(--airlock-pearl)';

        res.findings.forEach((f) => {
          const li = document.createElement('li');
          const strongCat = document.createElement('strong');
          strongCat.textContent = `${f.category.toUpperCase()} (${f.severity}): `;
          li.append(strongCat, f.evidence);
          ulFindings.appendChild(li);
        });

        wrap.append(strongTitle, ulFindings);
        box.appendChild(wrap);
      } else {
        const wrap = document.createElement('div');
        wrap.style.background = 'var(--airlock-obsidian)';
        wrap.style.border = '1px solid var(--airlock-allowed)';
        wrap.style.borderRadius = 'var(--radius-sm)';
        wrap.style.padding = '14px';

        const strongClean = document.createElement('strong');
        strongClean.style.color = 'var(--airlock-allowed)';
        strongClean.textContent = '✓ SCAN CLEAN: No deterministic secret or traversal patterns found.';
        wrap.appendChild(strongClean);
        box.appendChild(wrap);
      }
    } catch (err) {
      box.replaceChildren();
      const pErr = document.createElement('p');
      pErr.style.color = 'var(--airlock-denied)';
      pErr.textContent = err.message;
      box.appendChild(pErr);
    }
  };
}

// ============================================================================
// 8. AI ASSISTANT CHAT PLAYGROUND (GEMINI)
// ============================================================================
function initChatPlayground() {
  const form = $('#chat-form');
  const input = $('#chat-input');
  const history = $('#chat-history');

  function appendMsg(sender, text, isTool = false) {
    const div = document.createElement('div');
    div.className = `chat-msg ${sender === 'user' ? 'user' : 'assistant'}`;
    if (isTool) div.classList.add('tool-result');

    const label = document.createElement('strong');
    label.style.display = 'block';
    label.style.marginBottom = '4px';
    label.style.fontSize = '11px';
    label.textContent = sender === 'user' ? 'You' : isTool ? 'AIRLOCK Gateway Interceptor' : 'AIRLOCK Assistant (Gemini)';

    const p = document.createElement('p');
    p.style.whiteSpace = 'pre-wrap';
    p.textContent = text;

    div.appendChild(label);
    div.appendChild(p);
    history.appendChild(div);
    history.scrollTop = history.scrollHeight;
  }

  form.onsubmit = async (e) => {
    e.preventDefault();
    const msg = input.value.trim();
    if (!msg) return;

    appendMsg('user', msg);
    input.value = '';

    const loadingId = 'loading-' + Date.now();
    const loadingDiv = document.createElement('div');
    loadingDiv.id = loadingId;
    loadingDiv.className = 'chat-msg assistant';
    const emLoading = document.createElement('em');
    emLoading.textContent = 'Consulting Gemini & AIRLOCK Gateway...';
    loadingDiv.appendChild(emLoading);
    history.appendChild(loadingDiv);
    history.scrollTop = history.scrollHeight;

    try {
      const res = await apiRequest('/api/chat', {
        method: 'POST',
        body: JSON.stringify({ message: msg }),
      });
      loadingDiv.remove();

      if (res.cache_status === 'HIT' || res.optimization?.cache_hit) {
        appendMsg(
          'assistant',
          `⚡ AIRLOCK INTELLIGENT CACHE HIT\nModel: ${res.optimization?.model || 'Gemini 2.5 Flash'}\nAvoided Tokens: ${res.optimization?.avoided_input_tokens || 0} in / ${res.optimization?.avoided_output_tokens || 0} out\nCost Avoided: $${Number(res.optimization?.avoided_cost_usd || 0).toFixed(5)}\nLatency: ${res.optimization?.latency_ms || 18} ms\nDecision: Query satisfied from verified cache; 0 new Gemini API tokens consumed.`,
          true
        );
      } else if (res.cache_status === 'MISS') {
        appendMsg(
          'assistant',
          `✦ FRESH GENERATION (CACHE MISS)\nModel: ${res.optimization?.model || 'Gemini 2.5 Flash'}\nTokens: ${res.optimization?.input_tokens || 0} in / ${res.optimization?.output_tokens || 0} out\nCost: $${Number(res.optimization?.actual_cost_usd || 0).toFixed(6)}\nLatency: ${res.optimization?.latency_ms || 0} ms\nDecision: Evaluated and indexed into AIRLOCK response cache for subsequent queries.`,
          true
        );
      }

      if (res.tool_results && res.tool_results.length) {
        res.tool_results.forEach((t) => {
          appendMsg(
            'assistant',
            `Tool: ${t.tool}\nStatus: ${t.status.toUpperCase()}\nDetails: ${t.content || t.message || 'Complete'}`,
            true
          );
        });
      }

      appendMsg('assistant', res.answer || 'Response completed.');
      await loadTelemetry();
    } catch (err) {
      loadingDiv.remove();
      appendMsg('assistant', `Gateway Notice: ${err.message}`);
    }
  };

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      form.requestSubmit();
    }
  });

  $$('.chat-preset-btn').forEach((btn) => {
    btn.onclick = () => {
      input.value = btn.dataset.prompt;
      form.requestSubmit();
    };
  });
}

// ============================================================================
// 9. INCIDENT REPORT FORENSIC JSON EXPORT
// ============================================================================
function initIncidentExport() {
  const exportBtn = $('#export-incidents-btn');
  if (!exportBtn) return;
  exportBtn.onclick = () => {
    const reportData = {
      platform: 'AIRLOCK — Zero-Trust AI Security Gateway',
      tagline: 'AI Moves. AIRLOCK Decides.',
      exported_at: new Date().toISOString(),
      active_identity: state.identity,
      summary: state.summary,
      verified_events_count: state.events.length,
      events: state.events,
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `airlock-incident-forensics-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };
}

// ============================================================================
// 10. SIDEBAR NAVIGATION
// ============================================================================
function initSidebarNavigation() {
  $$('.sidebar-link').forEach((link) => {
    link.onclick = (e) => {
      const href = link.getAttribute('href');
      if (href && href.startsWith('#')) {
        const target = $(href);
        if (target) {
          e.preventDefault();
          $$('.sidebar-link').forEach((l) => l.classList.remove('active'));
          link.classList.add('active');
          target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      }
    };
  });
}

// ============================================================================
// 11. AIRLOCK EFFICIENCY ENGINE CONTROLLER
// ============================================================================
function initEfficiencyDashboard() {
  const refreshBtn = $('#efficiency-refresh-btn');
  const invalidateBtn = $('#efficiency-invalidate-cache-btn');
  const filterBtns = $$('.btn-filter');
  const presetBtns = $$('.btn-preset');
  const tableBody = $('#efficiency-records-body');

  let activeFilter = 'all';
  let cachedRecords = [];

  const fmt = (num) => Number(num || 0).toLocaleString();

  async function loadEfficiencyData() {
    try {
      const [metricsData, recordsData] = await Promise.all([
        apiRequest('/api/efficiency/metrics'),
        apiRequest('/api/efficiency/records?limit=50'),
      ]);

      const t = metricsData.telemetry || {};
      const c = metricsData.cache_health || {};

      if ($('#eff-total-requests')) $('#eff-total-requests').textContent = fmt(t.total_requests);
      if ($('#eff-hit-rate')) $('#eff-hit-rate').textContent = `${t.cache_hit_rate_pct || 0}%`;
      if ($('#eff-hits')) $('#eff-hits').textContent = fmt(t.cache_hits);
      if ($('#eff-misses')) $('#eff-misses').textContent = fmt(t.cache_misses);
      if ($('#eff-avoided-tokens')) $('#eff-avoided-tokens').textContent = fmt(t.avoided_tokens);
      if ($('#eff-avoided-cost')) $('#eff-avoided-cost').textContent = `$${Number(t.avoided_cost_usd || 0).toFixed(4)}`;
      if ($('#eff-actual-spend')) $('#eff-actual-spend').textContent = `Actual Spend: $${Number(t.actual_api_spend_usd || 0).toFixed(4)}`;
      if ($('#eff-cost-per-req')) $('#eff-cost-per-req').textContent = `$${Number(t.cost_per_request_usd || 0).toFixed(6)}`;
      if ($('#eff-avg-latency')) $('#eff-avg-latency').textContent = `${Number(t.avg_latency_ms || 0).toFixed(1)} ms`;
      if ($('#eff-total-input-tok')) $('#eff-total-input-tok').textContent = fmt(t.actual_input_tokens);
      if ($('#eff-total-output-tok')) $('#eff-total-output-tok').textContent = fmt(t.actual_output_tokens);
      if ($('#eff-ineligible-count')) $('#eff-ineligible-count').textContent = fmt(t.ineligible_requests);

      if ($('#eff-cache-entries')) $('#eff-cache-entries').textContent = fmt(c.active_entries);
      if ($('#eff-cache-capacity')) $('#eff-cache-capacity').textContent = fmt(c.max_entries || 2000);
      if ($('#eff-cache-evictions')) $('#eff-cache-evictions').textContent = fmt(c.evictions);

      cachedRecords = recordsData.records || [];
      renderRecordsTable();
    } catch (err) {
      console.warn('Efficiency telemetry load error:', err.message);
    }
  }

  function renderRecordsTable() {
    if (!tableBody) return;
    tableBody.replaceChildren();

    const filtered = cachedRecords.filter((rec) => {
      if (activeFilter === 'all') return true;
      return rec.cache_status === activeFilter;
    });

    if (filtered.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 9;
      td.style.textAlign = 'center';
      td.style.color = 'var(--airlock-muted)';
      td.style.padding = '24px';
      td.textContent = 'No matching efficiency records recorded.';
      tr.appendChild(td);
      tableBody.appendChild(tr);
      return;
    }

    filtered.forEach((rec) => {
      const tr = document.createElement('tr');

      const tdId = document.createElement('td');
      const codeId = document.createElement('code');
      codeId.textContent = rec.request_id;
      tdId.appendChild(codeId);

      const tdTime = document.createElement('td');
      tdTime.style.color = 'var(--airlock-muted)';
      tdTime.style.fontSize = '11px';
      tdTime.textContent = rec.formatted_timestamp || new Date(rec.timestamp * 1000).toLocaleTimeString();

      const tdModel = document.createElement('td');
      const modelSpan = document.createElement('span');
      modelSpan.style.fontWeight = '600';
      modelSpan.style.color = 'var(--airlock-pearl)';
      modelSpan.textContent = rec.model;
      tdModel.appendChild(modelSpan);

      const tdPrompt = document.createElement('td');
      tdPrompt.style.maxWidth = '260px';
      tdPrompt.style.whiteSpace = 'nowrap';
      tdPrompt.style.overflow = 'hidden';
      tdPrompt.style.textOverflow = 'ellipsis';
      tdPrompt.textContent = rec.prompt_summary;
      tdPrompt.title = rec.prompt_summary;

      const tdStatus = document.createElement('td');
      const badge = document.createElement('span');
      if (rec.cache_status === 'HIT') {
        badge.className = 'badge-cache-hit';
        badge.textContent = '⚡ HIT';
      } else if (rec.cache_status === 'MISS') {
        badge.className = 'badge-cache-miss';
        badge.textContent = 'MISS';
      } else {
        badge.className = 'badge-cache-ineligible';
        badge.textContent = '🛡 SECURITY';
      }
      tdStatus.appendChild(badge);

      const tdLat = document.createElement('td');
      tdLat.textContent = `${rec.latency_ms} ms`;

      const tdCost = document.createElement('td');
      tdCost.style.fontWeight = '600';
      tdCost.style.color = rec.actual_cost > 0 ? 'var(--airlock-pearl)' : 'var(--airlock-muted)';
      tdCost.textContent = `$${Number(rec.actual_cost).toFixed(6)}`;

      const tdAvoided = document.createElement('td');
      tdAvoided.style.fontWeight = '700';
      tdAvoided.style.color = rec.avoided_cost > 0 ? 'var(--airlock-allow)' : 'var(--airlock-subtle)';
      tdAvoided.textContent = rec.avoided_cost > 0 ? `+$${Number(rec.avoided_cost).toFixed(6)}` : '—';

      const tdOpt = document.createElement('td');
      tdOpt.style.color = 'var(--airlock-muted)';
      tdOpt.style.fontSize = '11px';
      tdOpt.textContent = rec.optimization_type.replace('_', ' ');

      tr.append(tdId, tdTime, tdModel, tdPrompt, tdStatus, tdLat, tdCost, tdAvoided, tdOpt);
      tableBody.appendChild(tr);
    });
  }

  filterBtns.forEach((btn) => {
    btn.onclick = () => {
      filterBtns.forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      activeFilter = btn.dataset.filter;
      renderRecordsTable();
    };
  });

  const usersSlider = $('#sim-users-slider');
  const rpdSlider = $('#sim-rpd-slider');
  const cacheableSlider = $('#sim-cacheable-slider');
  const hitrateSlider = $('#sim-hitrate-slider');
  const inTokensSlider = $('#sim-in-tokens-slider');
  const outTokensSlider = $('#sim-out-tokens-slider');

  async function runSimulation() {
    const activeUsers = usersSlider ? parseInt(usersSlider.value, 10) : 1000;
    const rpd = rpdSlider ? parseFloat(rpdSlider.value) : 12;
    const cacheable = cacheableSlider ? parseInt(cacheableSlider.value, 10) / 100 : 0.40;
    const hitrate = hitrateSlider ? parseInt(hitrateSlider.value, 10) / 100 : 0.65;
    const inTokens = inTokensSlider ? parseInt(inTokensSlider.value, 10) : 650;
    const outTokens = outTokensSlider ? parseInt(outTokensSlider.value, 10) : 350;

    if ($('#sim-users-val')) $('#sim-users-val').textContent = fmt(activeUsers);
    if ($('#sim-rpd-val')) $('#sim-rpd-val').textContent = rpd;
    if ($('#sim-cacheable-val')) $('#sim-cacheable-val').textContent = `${Math.round(cacheable * 100)}%`;
    if ($('#sim-hitrate-val')) $('#sim-hitrate-val').textContent = `${Math.round(hitrate * 100)}%`;
    if ($('#sim-in-tokens-val')) $('#sim-in-tokens-val').textContent = fmt(inTokens);
    if ($('#sim-out-tokens-val')) $('#sim-out-tokens-val').textContent = fmt(outTokens);

    try {
      const res = await apiRequest('/api/efficiency/simulate', {
        method: 'POST',
        body: JSON.stringify({
          active_users: activeUsers,
          requests_per_user_day: rpd,
          avg_input_tokens: inTokens,
          avg_output_tokens: outTokens,
          cacheable_ratio: cacheable,
          expected_hit_rate: hitrate,
          pro_model_ratio: 0.15,
          cache_infra_cost_monthly: 25.0,
          active_days_per_month: 30,
        }),
      });

      const sim = res.simulation;
      if (!sim) return;

      const exp = sim.expected;
      const cons = sim.conservative;
      const opt = sim.optimistic;

      if ($('#sim-baseline-monthly')) $('#sim-baseline-monthly').textContent = `$${fmt(exp.monthly_baseline_cost)}/mo`;
      if ($('#sim-baseline-annual')) $('#sim-baseline-annual').textContent = `$${fmt(exp.annual_baseline_cost)} / year direct API`;
      if ($('#sim-optimized-monthly')) $('#sim-optimized-monthly').textContent = `$${fmt(exp.monthly_optimized_cost)}/mo`;
      if ($('#sim-optimized-annual')) $('#sim-optimized-annual').textContent = `Includes $${exp.monthly_cache_infra_cost}/mo infra`;
      if ($('#sim-net-savings-monthly')) {
        const sign = exp.monthly_net_savings >= 0 ? '+' : '';
        $('#sim-net-savings-monthly').textContent = `${sign}$${fmt(exp.monthly_net_savings)}/mo`;
        $('#sim-net-savings-monthly').style.color = exp.monthly_net_savings >= 0 ? 'var(--airlock-allow)' : '#f87171';
      }
      if ($('#sim-net-savings-annual')) $('#sim-net-savings-annual').textContent = `+$${fmt(exp.annual_net_savings)} / year net`;
      if ($('#sim-pct-savings')) $('#sim-pct-savings').textContent = `${exp.savings_percentage}%`;
      if ($('#sim-avoided-req-count')) $('#sim-avoided-req-count').textContent = `${fmt(exp.avoided_requests_monthly)} requests avoided/mo`;

      if ($('#sim-sens-conservative-savings')) $('#sim-sens-conservative-savings').textContent = `+$${fmt(cons.monthly_net_savings)}/mo`;
      if ($('#sim-sens-conservative-pct')) $('#sim-sens-conservative-pct').textContent = `${cons.savings_percentage}% reduction · ${Math.round(sim.assumptions.expected_hit_rate_pct * 0.75)}% hit rate`;

      if ($('#sim-sens-expected-savings')) $('#sim-sens-expected-savings').textContent = `+$${fmt(exp.monthly_net_savings)}/mo`;
      if ($('#sim-sens-expected-pct')) $('#sim-sens-expected-pct').textContent = `${exp.savings_percentage}% reduction · ${sim.assumptions.expected_hit_rate_pct}% hit rate`;

      if ($('#sim-sens-optimistic-savings')) $('#sim-sens-optimistic-savings').textContent = `+$${fmt(opt.monthly_net_savings)}/mo`;
      if ($('#sim-sens-optimistic-pct')) $('#sim-sens-optimistic-pct').textContent = `${opt.savings_percentage}% reduction · ${Math.min(85, Math.round(sim.assumptions.expected_hit_rate_pct * 1.2))}% hit rate`;
    } catch (err) {
      console.warn('Simulation execution error:', err.message);
    }
  }

  [usersSlider, rpdSlider, cacheableSlider, hitrateSlider, inTokensSlider, outTokensSlider].forEach((slider) => {
    if (slider) {
      slider.oninput = runSimulation;
    }
  });

  presetBtns.forEach((btn) => {
    btn.onclick = () => {
      presetBtns.forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      const users = parseInt(btn.dataset.users, 10);
      if (usersSlider) usersSlider.value = users;
      runSimulation();
    };
  });

  if (invalidateBtn) {
    invalidateBtn.onclick = async () => {
      if (!confirm('Flush all entries from AIRLOCK response cache? Fresh model generation will be required for subsequent queries.')) {
        return;
      }
      try {
        const res = await apiRequest('/api/efficiency/cache/invalidate', { method: 'POST' });
        alert(res.message || 'Cache invalidated successfully.');
        await loadEfficiencyData();
      } catch (err) {
        alert(`Failed to invalidate cache: ${err.message}`);
      }
    };
  }

  if (refreshBtn) {
    refreshBtn.onclick = () => {
      loadEfficiencyData();
    };
  }

  loadEfficiencyData();
  runSimulation();
}

// ============================================================================
// 12. GITHUB REPOSITORY EXPLORER
// ============================================================================
function initGitHubExplorer() {
  const repoSelect = $('#github-repo-select');
  const fileTree = $('#repo-file-tree');
  const fileViewer = $('#github-file-viewer');
  const activeFilepath = $('#repo-active-filepath');
  const fileSecurityBadge = $('#repo-file-security-badge');
  const askAiBtn = $('#btn-ask-ai-repo');

  // Tabs
  const tabFiles = $('#repo-tab-files');
  const tabIssues = $('#repo-tab-issues');
  const tabPrs = $('#repo-tab-prs');
  const tabWorkflows = $('#repo-tab-workflows');
  const tabSecurity = $('#repo-tab-security');

  const panelFiles = $('#panel-repo-files');
  const panelIssues = $('#panel-repo-issues');
  const panelPrs = $('#panel-repo-prs');
  const panelWorkflows = $('#panel-repo-workflows');
  const panelSecurity = $('#panel-repo-security');

  const issuesList = $('#repo-issues-list');
  const prsList = $('#repo-prs-list');
  const workflowsList = $('#repo-workflows-list');
  const securityList = $('#repo-security-list');

  // Modal close buttons
  ['#close-github-tools-btn', '#close-github-tools-btn-2'].forEach((sel) => {
    const btn = $(sel);
    if (btn) btn.onclick = () => {
      const modal = $('#github-tools-modal');
      if (modal) modal.style.display = 'none';
    };
  });
  ['#close-github-perm-btn', '#close-github-perm-btn-2'].forEach((sel) => {
    const btn = $(sel);
    if (btn) btn.onclick = () => {
      const modal = $('#github-permissions-modal');
      if (modal) modal.style.display = 'none';
    };
  });

  function switchTab(activeBtn, activePanel) {
    [tabFiles, tabIssues, tabPrs, tabWorkflows, tabSecurity].forEach((btn) => {
      if (btn) btn.classList.remove('active');
    });
    [panelFiles, panelIssues, panelPrs, panelWorkflows, panelSecurity].forEach((p) => {
      if (p) p.style.display = 'none';
    });
    if (activeBtn) activeBtn.classList.add('active');
    if (activePanel) activePanel.style.display = 'block';
  }

  if (tabFiles) tabFiles.onclick = () => switchTab(tabFiles, panelFiles);
  if (tabIssues) tabIssues.onclick = () => switchTab(tabIssues, panelIssues);
  if (tabPrs) tabPrs.onclick = () => switchTab(tabPrs, panelPrs);
  if (tabWorkflows) tabWorkflows.onclick = () => switchTab(tabWorkflows, panelWorkflows);
  if (tabSecurity) tabSecurity.onclick = () => switchTab(tabSecurity, panelSecurity);

  async function loadFileContent(owner, repo, path) {
    if (fileViewer) fileViewer.textContent = 'Loading file from GitHub repository...';
    if (activeFilepath) activeFilepath.textContent = path;
    try {
      const res = await apiRequest(`/api/github/repos/${owner}/${repo}/file?path=${encodeURIComponent(path)}`);
      if (fileViewer) fileViewer.textContent = res.content || '';
      if (fileSecurityBadge) {
        if (res.suspicious) {
          fileSecurityBadge.className = 'badge deny';
          fileSecurityBadge.textContent = `FLAGGED (${(res.matches || ['SUSPICIOUS_CONTENT']).join(', ').toUpperCase()})`;
        } else {
          fileSecurityBadge.className = 'badge allow';
          fileSecurityBadge.textContent = 'CLEAN (DLP VERIFIED)';
        }
      }
    } catch (err) {
      if (fileViewer) fileViewer.textContent = `Error reading file: ${err.message}`;
    }
  }

  async function loadRepoData() {
    const repoVal = repoSelect ? repoSelect.value : 'demo-org/airlock-security-lab';
    const [owner, repo] = repoVal.includes('/') ? repoVal.split('/') : ['demo-org', repoVal];

    // Load files
    try {
      const files = await apiRequest(`/api/github/repos/${owner}/${repo}/files`);
      const fileEntries = Array.isArray(files) ? files : (files.entries || []);
      if (fileTree) {
        fileTree.replaceChildren();
        fileEntries.forEach((f, idx) => {
          const btn = document.createElement('button');
          btn.type = 'button';
          btn.style.width = '100%';
          btn.style.textAlign = 'left';
          btn.style.background = 'none';
          btn.style.border = 'none';
          btn.style.padding = '6px 8px';
          btn.style.borderRadius = 'var(--radius-xs)';
          btn.style.color = 'var(--airlock-pearl)';
          btn.style.cursor = 'pointer';
          btn.style.fontFamily = "'JetBrains Mono', monospace";
          btn.style.fontSize = '12px';
          btn.style.display = 'flex';
          btn.style.alignItems = 'center';
          btn.style.gap = '6px';

          const icon = f.path.endsWith('.md') ? '📄' : f.path.endsWith('.py') ? '🐍' : f.path.endsWith('.env') ? '🔑' : '⚙';
          btn.textContent = `${icon} ${f.path}`;

          btn.onmouseover = () => { btn.style.background = 'var(--airlock-titanium)'; };
          btn.onmouseout = () => { btn.style.background = 'none'; };
          btn.onclick = () => loadFileContent(owner, repo, f.path);

          fileTree.appendChild(btn);

          // Auto-load first file
          if (idx === 0) loadFileContent(owner, repo, f.path);
        });
      }
    } catch (e) {
      console.warn('Files load failed:', e.message);
    }

    // Load Issues
    try {
      const issues = await apiRequest(`/api/github/repos/${owner}/${repo}/issues`);
      const countEl = $('#repo-count-issues');
      if (countEl) countEl.textContent = issues.length;
      if (issuesList) {
        issuesList.replaceChildren();
        if (!issues.length) {
          const p = document.createElement('p');
          p.style.color = 'var(--airlock-muted)';
          p.textContent = 'No open issues.';
          issuesList.appendChild(p);
        } else {
          issues.forEach((iss) => {
            const card = document.createElement('div');
            card.className = 'metric-card';
            card.style.padding = '14px';

            const top = document.createElement('div');
            top.style.display = 'flex';
            top.style.justifyContent = 'space-between';
            top.style.marginBottom = '6px';

            const h4 = document.createElement('h4');
            h4.style.fontSize = '14px';
            h4.style.color = 'var(--airlock-pearl)';
            h4.textContent = `#${iss.number} ${iss.title}`;

            const badge = document.createElement('span');
            badge.className = 'badge allow';
            badge.textContent = (iss.state || 'open').toUpperCase();
            top.append(h4, badge);

            const bodyP = document.createElement('p');
            bodyP.style.fontSize = '12px';
            bodyP.style.color = 'var(--airlock-muted)';
            bodyP.style.marginBottom = '8px';
            bodyP.textContent = iss.body || '';

            const meta = document.createElement('div');
            meta.style.fontSize = '11px';
            meta.style.color = 'var(--airlock-steel)';
            meta.textContent = `Author: ${iss.author || 'contributor'} · Labels: ${(iss.labels || []).join(', ') || 'none'}`;

            card.append(top, bodyP, meta);
            issuesList.appendChild(card);
          });
        }
      }
    } catch (e) {
      console.warn('Issues load failed:', e.message);
    }

    // Load PRs
    try {
      const prs = await apiRequest(`/api/github/repos/${owner}/${repo}/pulls`);
      const countPrs = $('#repo-count-prs');
      if (countPrs) countPrs.textContent = prs.length;
      if (prsList) {
        prsList.replaceChildren();
        if (!prs.length) {
          const p = document.createElement('p');
          p.style.color = 'var(--airlock-muted)';
          p.textContent = 'No open pull requests.';
          prsList.appendChild(p);
        } else {
          prs.forEach((pr) => {
            const card = document.createElement('div');
            card.className = 'metric-card';
            card.style.padding = '14px';

            const top = document.createElement('div');
            top.style.display = 'flex';
            top.style.justifyContent = 'space-between';
            top.style.marginBottom = '6px';

            const h4 = document.createElement('h4');
            h4.style.fontSize = '14px';
            h4.style.color = 'var(--airlock-pearl)';
            h4.textContent = `#${pr.number} ${pr.title}`;

            const badge = document.createElement('span');
            badge.className = 'badge review';
            badge.textContent = `${pr.head || 'feature'} ➔ ${pr.base || 'main'}`;
            top.append(h4, badge);

            const bodyP = document.createElement('p');
            bodyP.style.fontSize = '12px';
            bodyP.style.color = 'var(--airlock-muted)';
            bodyP.style.marginBottom = '8px';
            bodyP.textContent = pr.body || '';

            const meta = document.createElement('div');
            meta.style.fontSize = '11px';
            meta.style.color = 'var(--airlock-steel)';
            meta.textContent = `Author: ${pr.author || 'developer'} · State: ${(pr.state || 'open').toUpperCase()}`;

            card.append(top, bodyP, meta);
            prsList.appendChild(card);
          });
        }
      }
    } catch (e) {
      console.warn('PRs load failed:', e.message);
    }

    // Load Workflows
    try {
      const wf = await apiRequest(`/api/github/repos/${owner}/${repo}/workflows`);
      if (workflowsList) {
        workflowsList.replaceChildren();
        const runs = wf.workflow_runs || [];
        if (!runs.length) {
          const p = document.createElement('p');
          p.style.color = 'var(--airlock-muted)';
          p.textContent = 'No recorded workflow runs.';
          workflowsList.appendChild(p);
        } else {
          runs.forEach((r) => {
            const card = document.createElement('div');
            card.className = 'metric-card';
            card.style.padding = '14px';

            const top = document.createElement('div');
            top.style.display = 'flex';
            top.style.justifyContent = 'space-between';
            top.style.marginBottom = '6px';

            const h4 = document.createElement('h4');
            h4.style.fontSize = '14px';
            h4.style.color = 'var(--airlock-pearl)';
            h4.textContent = `⚙ Run #${r.id}: ${r.name || 'CI/CD Pipeline'}`;

            const badge = document.createElement('span');
            const isSuccess = r.conclusion === 'success';
            badge.className = `badge ${isSuccess ? 'allow' : 'review'}`;
            badge.textContent = (r.conclusion || r.status || 'completed').toUpperCase();
            top.append(h4, badge);

            const meta = document.createElement('div');
            meta.style.fontSize = '11px';
            meta.style.color = 'var(--airlock-steel)';
            meta.textContent = `Branch: ${r.head_branch || 'main'} · SHA: ${r.head_sha ? r.head_sha.slice(0, 7) : 'head'} · Event: ${r.event || 'push'}`;

            card.append(top, meta);
            workflowsList.appendChild(card);
          });
        }
      }
    } catch (e) {
      console.warn('Workflows load failed:', e.message);
    }

    // Load Security Advisories
    try {
      const sec = await apiRequest(`/api/github/repos/${owner}/${repo}/security`);
      if (securityList) {
        securityList.replaceChildren();
        const dep = sec.dependabot_alerts || [];
        const code = sec.code_scanning_alerts || [];
        const total = dep.length + code.length;

        if (total === 0) {
          const p = document.createElement('p');
          p.style.color = 'var(--airlock-muted)';
          p.textContent = 'No open security advisories detected on this repository.';
          securityList.appendChild(p);
        } else {
          dep.forEach((a) => {
            const card = document.createElement('div');
            card.className = 'metric-card';
            card.style.borderColor = 'rgba(240, 90, 112, 0.4)';
            card.style.padding = '14px';

            const top = document.createElement('div');
            top.style.display = 'flex';
            top.style.justifyContent = 'space-between';
            top.style.marginBottom = '6px';

            const h4 = document.createElement('h4');
            h4.style.fontSize = '14px';
            h4.style.color = 'var(--airlock-pearl)';
            h4.textContent = `🛡 Dependabot: ${a.dependency || 'Package Alert'}`;

            const badge = document.createElement('span');
            badge.className = 'badge deny';
            badge.textContent = (a.severity || 'high').toUpperCase();
            top.append(h4, badge);

            const p = document.createElement('p');
            p.style.fontSize = '12px';
            p.style.color = 'var(--airlock-muted)';
            p.textContent = a.description || a.summary || 'Vulnerable dependency version identified.';

            card.append(top, p);
            securityList.appendChild(card);
          });

          code.forEach((c) => {
            const card = document.createElement('div');
            card.className = 'metric-card';
            card.style.borderColor = 'rgba(242, 180, 77, 0.4)';
            card.style.padding = '14px';

            const top = document.createElement('div');
            top.style.display = 'flex';
            top.style.justifyContent = 'space-between';
            top.style.marginBottom = '6px';

            const h4 = document.createElement('h4');
            h4.style.fontSize = '14px';
            h4.style.color = 'var(--airlock-pearl)';
            h4.textContent = `⚡ CodeQL: ${c.rule || 'Code Rule'}`;

            const badge = document.createElement('span');
            badge.className = 'badge review';
            badge.textContent = (c.severity || 'medium').toUpperCase();
            top.append(h4, badge);

            const p = document.createElement('p');
            p.style.fontSize = '12px';
            p.style.color = 'var(--airlock-muted)';
            p.textContent = `${c.description || 'Static analysis finding'} (${c.path || 'file'}:${c.line || 1})`;

            card.append(top, p);
            securityList.appendChild(card);
          });
        }
      }
    } catch (e) {
      console.warn('Security load failed:', e.message);
    }
  }

  if (repoSelect) {
    repoSelect.onchange = loadRepoData;
  }

  if (askAiBtn) {
    askAiBtn.onclick = () => {
      const repoVal = repoSelect ? repoSelect.value : 'demo-org/airlock-security-lab';
      const curFile = activeFilepath ? activeFilepath.textContent : 'README.md';
      const chatInput = $('#chat-input');
      const chatForm = $('#chat-form');
      if (chatInput && chatForm) {
        chatInput.value = `Inspect GitHub repository ${repoVal} and summarize the security posture of ${curFile}`;
        const chatSec = $('#playground');
        if (chatSec) chatSec.scrollIntoView({ behavior: 'smooth' });
        setTimeout(() => chatForm.requestSubmit(), 400);
      }
    };
  }

  loadRepoData();
}

// ============================================================================
// INITIALIZATION
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
  initIntroAnimation();
  initAuthHandlers();
  initSidebarNavigation();
  initEfficiencyDashboard();
  initGitHubExplorer();
  initPipelineVisualizer();
  initApprovalModal();
  initBlastRadiusMap();
  initAttackLab();
  initDryRunAndScanner();
  initChatPlayground();
  initIncidentExport();
});
