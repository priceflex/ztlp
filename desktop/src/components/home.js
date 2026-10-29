// ── Home — single-page readiness checklist (Task C3) ──────────────────
//
// Replaces the old hero-ring/Connect-button UI with the same 3-row
// checklist shape as the macOS app's HomeView: Service / Identity /
// Network ready, each with at most one action button, driven by
// `computeReadiness()` (home-readiness.js) polling `setup_status` /
// `get_identity` (Tauri `invoke`).
//
// There is no manual "Connect" step in the steady-state flow — ZTLP
// connects on demand once enrolled. A button only appears on a row that
// `computeReadiness` marks `needsAction`.
//
// Service-state signal: unlike macOS (which queries SMAppService
// directly for notRegistered/requiresApproval/running/notFound), this
// Windows/Linux build has no dedicated "is the service installed"
// query yet — the only signal available from `setup_status` is
// `daemon_running` (the control socket answered). We map that directly:
// reachable -> 'running', unreachable -> 'not_installed'. This is an
// honest simplification, not a full port of the macOS state machine;
// revisit if/when a real service-install-state IPC command exists.

const HomeComponent = (() => {
  const container = document.getElementById('page-home');
  let currentReadiness = null;
  let currentZone = '';

  function render() {
    container.innerHTML = `
      <div class="home">
        <div class="home-header">
          <img class="home-logo" src="assets/ztlp-logo.png" alt="ZTLP">
          <div class="home-titles">
            <div class="status-label" id="home-status-label">Set up ZTLP</div>
            <div class="status-sublabel" id="home-status-sublabel"></div>
          </div>
        </div>

        <div class="readiness-list" id="home-readiness-rows"></div>
        <div class="readiness-guidance" id="home-guidance"></div>

        <details class="log-details">
          <summary>Live activity</summary>
          <div class="log" id="home-log"></div>
        </details>
      </div>
    `;

    LiveLog.render();
  }

  // PR #112 review fix: row details can carry daemon/config-supplied text
  // (the zone name, failure reasons). Escape everything interpolated into
  // innerHTML — Setup/Settings already do; Home did not.
  function escapeHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function rowBadge(state) {
    switch (state.kind) {
      case 'ready': return { cls: 'ready', symbol: '✓' };
      case 'needsAction': return { cls: 'needs-action', symbol: '' };
      case 'failed': return { cls: 'failed', symbol: '✕' };
      default: return { cls: 'waiting', symbol: '' }; // 'waiting' (CSS spinner)
    }
  }

  function actionLabel(action) {
    switch (action) {
      case 'installService': return 'Install Service';
      case 'openLoginItems': return 'Open Settings';
      case 'enroll': return 'Enroll';
      case 'trustHTTPS': return 'Trust HTTPS';
      default: return 'Fix';
    }
  }

  function renderRows(readiness) {
    const rowsEl = document.getElementById('home-readiness-rows');
    const guidanceEl = document.getElementById('home-guidance');
    if (!rowsEl) return; // not rendered yet

    rowsEl.innerHTML = readiness.rows
      .map((row, i) => {
        const badge = rowBadge(row.state);
        const btn = row.state.kind === 'needsAction'
          ? `<button class="btn btn-sm readiness-action" data-row="${i}" data-action="${escapeHtml(row.state.action)}">${escapeHtml(actionLabel(row.state.action))}</button>`
          : '';
        return `
          <div class="readiness-row state-${badge.cls}" id="home.row.${escapeHtml(row.title.toLowerCase().replace(/\s+/g, '-'))}">
            <span class="readiness-badge ${badge.cls}">${badge.symbol}</span>
            <div class="readiness-text">
              <div class="readiness-title"><span class="readiness-num">${i + 1}.</span> ${escapeHtml(row.title)}</div>
              <div class="readiness-detail">${escapeHtml(row.state.detail)}</div>
            </div>
            ${btn}
          </div>
        `;
      })
      .join('');

    guidanceEl.textContent = readiness.guidance(currentZone);

    rowsEl.querySelectorAll('.readiness-action').forEach((btn) => {
      btn.addEventListener('click', () => onRowAction(btn.dataset.action));
    });

    const label = document.getElementById('home-status-label');
    const sublabel = document.getElementById('home-status-sublabel');
    if (label) label.textContent = readiness.allReady ? 'Ready' : 'Set up ZTLP';
    if (sublabel) {
      sublabel.textContent = readiness.allReady
        ? currentZone || ''
        : '';
      sublabel.style.display = sublabel.textContent ? '' : 'none';
    }
  }

  async function onRowAction(action) {
    try {
      if (action === 'installService') {
        LiveLog.setup('Installing background service (one-time permission prompt)…');
        await invoke('setup_install_service');
        LiveLog.success('Service install requested.');
        // The elevated `ztlp agent install` runs detached (UAC) and returns
        // immediately; it registers AND starts the service. Poll until the
        // control socket answers so the checklist advances by itself.
        LiveLog.setup('Waiting for the service to start…');
        for (let i = 0; i < 30; i++) {
          await new Promise((r) => setTimeout(r, 1000));
          await load();
          if (currentReadiness && currentReadiness.service &&
              currentReadiness.service.state.kind === 'ready') {
            LiveLog.success('Service is running.');
            return;
          }
        }
        LiveLog.log('warn', 'Service has not started yet — check Windows Services (ZtlpAgent).');
      } else if (action === 'trustHTTPS') {
        LiveLog.setup('Installing CA into system trust (one-time permission prompt)…');
        await invoke('setup_install_ca');
        LiveLog.success('CA trust install requested.');
      } else if (action === 'enroll') {
        // Enrollment needs a token from the user — hand off to Setup, the
        // page that already owns the paste-token flow (Task C4).
        document.querySelector('.nav-item[data-page="setup"]').click();
        return;
      } else if (action === 'openLoginItems') {
        LiveLog.log('warn', 'Open System Settings > Login Items and approve ZTLP.');
        return;
      }
    } catch (e) {
      LiveLog.fail(`${action} failed: ${e}`);
    }
    await load();
  }

  // ── Windows per-user agent: four end-to-end checks ──────────────────
  // Agent / Identity / DNS / HTTPS, computed in Rust (peruser.rs
  // `health_report`). The only buttons: Enroll (identity) and Fix (DNS or
  // HTTPS red -> one UAC prompt that re-runs the installer's machine setup).
  function isPerUser() {
    return !!(window.ZTLP_ENV && window.ZTLP_ENV.per_user_agent);
  }

  const lastRowState = {};
  let healthInFlight = false;
  let lastHealthAt = 0;
  let repairing = false;

  function healthBadge(state) {
    switch (state) {
      case 'ready': return { cls: 'ready', symbol: '✓' };
      case 'action': return { cls: 'needs-action', symbol: '' };
      case 'failed': return { cls: 'failed', symbol: '✕' };
      default: return { cls: 'waiting', symbol: '' };
    }
  }

  function renderHealth(report) {
    const rowsEl = document.getElementById('home-readiness-rows');
    const guidanceEl = document.getElementById('home-guidance');
    if (!rowsEl) return;
    rowsEl.innerHTML = report.rows
      .map((row, i) => {
        const badge = healthBadge(row.state);
        const label = row.action === 'enroll' ? 'Enroll' : 'Fix';
        const btn = row.action && (row.state === 'action' || row.state === 'failed')
          ? `<button class="btn btn-sm readiness-action" data-action="${escapeHtml(row.action)}"${repairing && row.action === 'repair' ? ' disabled' : ''}>${escapeHtml(repairing && row.action === 'repair' ? 'Fixing…' : label)}</button>`
          : '';
        return `
          <div class="readiness-row state-${badge.cls}" id="home.row.${escapeHtml(row.key)}">
            <span class="readiness-badge ${badge.cls}">${badge.symbol}</span>
            <div class="readiness-text">
              <div class="readiness-title"><span class="readiness-num">${i + 1}.</span> ${escapeHtml(row.title)}</div>
              <div class="readiness-detail">${escapeHtml(row.detail)}</div>
            </div>
            ${btn}
          </div>
        `;
      })
      .join('');
    rowsEl.querySelectorAll('.readiness-action').forEach((b) => {
      b.addEventListener('click', () => onHealthAction(b.dataset.action));
    });

    // Log each row's transitions once (not every poll).
    report.rows.forEach((row) => {
      const key = `${row.state}|${row.detail}`;
      if (lastRowState[row.key] !== key) {
        if (lastRowState[row.key] !== undefined || row.state !== 'waiting') {
          if (row.state === 'ready') LiveLog.success(`${row.title}: ${row.detail}`);
          else if (row.state === 'failed') LiveLog.fail(`${row.title}: ${row.detail}`);
          else LiveLog.log('info', `${row.title}: ${row.detail}`);
        }
        lastRowState[row.key] = key;
      }
    });

    if (guidanceEl) {
      guidanceEl.textContent = report.all_ready
        ? 'Everything works. Open any https://<service>.<zone>.ztlp address in your browser.'
        : report.rows.some((r) => r.action === 'repair')
          ? 'Click Fix to repair DNS / certificates (Windows asks for an administrator once).'
          : report.rows.some((r) => r.action === 'enroll')
            ? 'Enroll this device with the link from your administrator.'
            : '';
    }
    currentZone = report.zone || currentZone;
    const label = document.getElementById('home-status-label');
    const sublabel = document.getElementById('home-status-sublabel');
    if (label) label.textContent = report.all_ready ? 'Ready' : (report.in_use_by_other ? 'In use by another user' : 'Setting up');
    if (sublabel) {
      sublabel.textContent = report.all_ready ? (report.zone || '') : '';
      sublabel.style.display = sublabel.textContent ? '' : 'none';
    }
  }

  async function loadHealth(force) {
    const now = Date.now();
    if (healthInFlight || (!force && now - lastHealthAt < 4000)) return;
    healthInFlight = true;
    try {
      const report = await invoke('health_report');
      lastHealthAt = Date.now();
      currentReadiness = report;
      renderHealth(report);
    } catch (e) {
      LiveLog.fail(`Health check failed: ${e}`);
    } finally {
      healthInFlight = false;
    }
  }

  async function onHealthAction(action) {
    if (action === 'enroll') {
      document.querySelector('.nav-item[data-page="setup"]').click();
      return;
    }
    if (action === 'repair' && !repairing) {
      repairing = true;
      try {
        LiveLog.setup('Repairing DNS and certificates (Windows will ask for an administrator)…');
        await invoke('repair_machine');
        // The elevated machine setup runs detached; re-check until green.
        for (let i = 0; i < 45; i++) {
          await new Promise((r) => setTimeout(r, 2000));
          await loadHealth(true);
          const r = currentReadiness;
          if (r && r.rows && !r.rows.some((x) => x.action === 'repair')) {
            LiveLog.success('Repair done.');
            break;
          }
        }
      } catch (e) {
        LiveLog.fail(`Repair failed: ${e}`);
      } finally {
        repairing = false;
        await loadHealth(true);
      }
    }
  }

  async function load() {
    if (isPerUser()) {
      await loadHealth(false);
      return;
    }
    try {
      const [status, identity] = await Promise.all([
        invoke('setup_status'),
        invoke('get_identity').catch(() => null),
      ]);
      applyStatus(status, identity);
    } catch (e) {
      applyStatus({ daemon_running: false, daemon_error: `setup_status invoke failed: ${e}` }, null);
    }
  }

  // Recompute + repaint readiness from a fresh `setup_status` snapshot.
  // `identity` is optional — when omitted we keep the current zone label.
  let lastDaemonError = null;
  function applyStatus(status, identity) {
    const s = status || { daemon_running: false };
    // Surface WHY the service looks down (deduped) instead of silently
    // showing "Not installed".
    const err = s.daemon_running ? null : (s.daemon_error || null);
    if (err && err !== lastDaemonError && typeof LiveLog !== 'undefined' && LiveLog.fail) {
      LiveLog.fail(`Service check: ${err}`);
    }
    lastDaemonError = err;
    currentZone = s.zone || (identity && identity.zone_name) || currentZone;

    const serviceState = s.daemon_running ? 'running' : 'not_installed';
    const daemon = s.daemon_running
      ? {
          identityEnrolled: !!s.identity_enrolled,
          zone: currentZone,
          caInitialized: !!s.ca_initialized,
          caInstalled: !!s.ca_installed_system_trust,
          dnsConfigured: !!s.dns_configured,
        }
      : null;

    currentReadiness = HomeReadiness.computeReadiness({
      serviceState,
      daemonReachable: !!s.daemon_running,
      daemon,
    });
    renderRows(currentReadiness);
    return currentReadiness;
  }

  // Kept for app.js/pollState compatibility: it calls `HomeComponent.update(status)`
  // with a `ConnectionStatus` shape (get_status), not `SetupStatusUi`. Home no
  // longer derives its rows from that shape, so `update` now just triggers a
  // fresh readiness pull instead of trying to map connection state to rows.
  function update(_connectionStatus) {
    load();
  }

  return { render, load, update, applyStatus, escapeHtml };
})();
