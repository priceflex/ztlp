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
        <div class="home-hero">
          <img class="home-logo" src="assets/ztlp-logo.png" alt="ZTLP">
          <div class="status-label" id="home-status-label">Ready</div>
          <div class="status-sublabel" id="home-status-sublabel"></div>
        </div>

        <div class="card readiness-card">
          <div id="home-readiness-rows"></div>
          <div class="readiness-guidance" id="home-guidance"></div>
        </div>

        <div class="card log-card">
          <div class="card-title">Live activity</div>
          <div class="log" id="home-log"></div>
        </div>
      </div>
    `;

    LiveLog.render();
  }

  function rowBadge(state) {
    switch (state.kind) {
      case 'ready': return { cls: 'ready', symbol: '✓' };
      case 'needsAction': return { cls: 'needs-action', symbol: '!' };
      case 'failed': return { cls: 'failed', symbol: '✗' };
      default: return { cls: 'waiting', symbol: '…' }; // 'waiting'
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
          ? `<button class="btn btn-sm readiness-action" data-row="${i}" data-action="${row.state.action}">${actionLabel(row.state.action)}</button>`
          : '';
        return `
          <div class="readiness-row" id="home.row.${row.title.toLowerCase().replace(/\s+/g, '-')}">
            <span class="readiness-badge ${badge.cls}">${badge.symbol}</span>
            <span class="readiness-title">${row.title}</span>
            <span class="readiness-detail">${row.state.detail}</span>
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
    if (label) label.textContent = readiness.allReady ? 'Ready' : 'Setting up…';
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

  async function load() {
    try {
      const [status, identity] = await Promise.all([
        invoke('setup_status'),
        invoke('get_identity').catch(() => null),
      ]);
      applyStatus(status, identity);
    } catch (e) {
      applyStatus({ daemon_running: false }, null);
    }
  }

  // Recompute + repaint readiness from a fresh `setup_status` snapshot.
  // `identity` is optional — when omitted we keep the current zone label.
  function applyStatus(status, identity) {
    const s = status || { daemon_running: false };
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

  return { render, load, update, applyStatus };
})();
