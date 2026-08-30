// ── ZTLP Desktop — Main App Controller ───────────────────────────────
//
// Three pages (Home / Setup / Settings). Responsibilities:
//   • page navigation
//   • poll connection state and drive the status ring + the live log
//   • auto-connect on launch (honor the `auto_connect` config, default ON —
//     the app is not a VPN, it just stays ready)
//
// Uses the Tauri IPC bridge (`window.__TAURI__.core.invoke`).

const { invoke } = window.__TAURI__.core;

// ── Navigation ──────────────────────────────────────────────────────────
const navItems = document.querySelectorAll('.nav-item');
const pages = document.querySelectorAll('.page');

function navigateTo(pageName) {
  navItems.forEach((item) => item.classList.toggle('active', item.dataset.page === pageName));
  pages.forEach((page) => page.classList.toggle('active', page.id === `page-${pageName}`));
}

navItems.forEach((item) => item.addEventListener('click', () => navigateTo(item.dataset.page)));

// ── Utilities ───────────────────────────────────────────────────────────
async function copyToClipboard(text, btnEl) {
  try {
    await navigator.clipboard.writeText(text);
    if (btnEl) {
      btnEl.classList.add('copied');
      btnEl.textContent = '✓';
      setTimeout(() => { btnEl.classList.remove('copied'); btnEl.textContent = '📋'; }, 1500);
    }
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  }
}
window.copyToClipboard = copyToClipboard; // exposed for the settings copy button

// ── Polling ─────────────────────────────────────────────────────────────
// Adaptive: 2s when the agent is reachable, back off to 10s after repeated
// failures so a dead socket doesn't jank the UI.
let pollTimer = null;
let consecutiveFailures = 0;
const POLL_FAST_MS = 2000;
const POLL_SLOW_MS = 10000;
const FAILURE_THRESHOLD = 3;

async function pollState() {
  try {
    const status = await invoke('get_status');
    HomeComponent.update(status);
    LiveLog.stateChange(status);
    // When secured, also reflect the live background service-attach state so
    // the log shows what the device is actually attached to via its identity.
    // Best-effort: a momentary `tunnels` IPC miss must never break the
    // status poll.
    if (status.state === 'connected' || status.state === 'reconnecting') {
      invoke('get_attached')
        .then((attached) => LiveLog.serviceAttach(attached))
        .catch(() => {});
    }
    if (consecutiveFailures >= FAILURE_THRESHOLD) restartPolling(POLL_FAST_MS);
    consecutiveFailures = 0;
  } catch (e) {
    consecutiveFailures += 1;
    if (consecutiveFailures === FAILURE_THRESHOLD) {
      restartPolling(POLL_SLOW_MS);
      // Log once that the agent went quiet (LiveLog dedups by state).
      LiveLog.stateChange({ state: 'error', error: 'agent not reachable' });
    }
  }
}

function restartPolling(intervalMs) {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(pollState, intervalMs);
}

function startPolling() {
  if (!pollTimer) pollTimer = setInterval(pollState, POLL_FAST_MS);
}

function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

// ── Auto-connect on launch ──────────────────────────────────────────────
// "It's not a VPN — stay ready." So on launch we connect if the device is
// enrolled and auto_connect is enabled (default true). We never nag the user;
// if it's not enrolled we just log a hint pointing at Setup.
async function maybeAutoConnect() {
  // Refresh Home's view of the (possibly new) status so the ring/label repaint
  // after any state change. Safe to call repeatedly.
  const refresh = async () => {
    try {
      const s = await invoke('get_status');
      HomeComponent.update(s);
      LiveLog.stateChange(s);
    } catch { /* agent down; poller will surface it */ }
  };
  try {
    const cfg = await invoke('get_config');
    const identity = await invoke('get_identity');
    const enrolled = !!(identity && identity.enrolled);
    const want = cfg ? !!cfg.auto_connect : true; // default ON

    if (enrolled && want) {
      const relay = (cfg && cfg.relay_address) || 'relay.ztlp.net:4433';
      LiveLog.setup('Auto-connect: connecting and staying ready…');
      await invoke('connect', { relay, zone: (identity && identity.zone_name) || 'default' });
      await refresh(); // repaint Home + log the transition

      // Zero-click provisioning: once the agent is up, finish whatever the
      // one-time environment setup still needs (CA chain, CA trust, DNS
      // routing) automatically so a plain browser visit to a zone hostname
      // "just works" with no return trip to Setup. Each step is a no-op if
      // already done. CA-trust/DNS installs pop a native OS elevation
      // prompt (UAC/pkexec) — that's an OS security boundary the user must
      // confirm once, not an in-app button.
      await SetupComponent.autoProvision();
    } else if (!enrolled) {
      LiveLog.log('warn', 'This device is not enrolled yet — open Setup to enroll it.');
    }
    // (enrolled, want=false → intentionally stay disconnected; nothing to do.)
  } catch (e) {
    console.error('Auto-connect error:', e);
  }
}

// ── Init ────────────────────────────────────────────────────────────────
async function init() {
  // Expose the components on the global object. This is harmless in the browser
  // (classic <script> scope already makes them visible to each other) and it
  // makes the app testable/inspectable from outside — the headless UI harness
  // and any future debug tooling can drive them via window.HomeComponent, etc.
  window.HomeComponent = HomeComponent;
  window.SetupComponent = SetupComponent;
  window.SettingsComponent = SettingsComponent;
  window.LiveLog = LiveLog;

  // Render the (now three) components.
  HomeComponent.render();
  SetupComponent.render();
  SettingsComponent.render();

  // Load initial data. Setup + Settings load their own daemon/identity state;
  // Home loads connection status.
  await Promise.all([
    HomeComponent.load(),
    SetupComponent.load(),
    SettingsComponent.load(),
  ]);

  // Establish the live log's baseline from the true current state, so the very
  // first transition is reported accurately (a fresh log has no prior state,
  // and Home's initial load doesn't feed the log).
  try {
    LiveLog.stateChange(await invoke('get_status'));
  } catch {
    LiveLog.stateChange({ state: 'disconnected' });
  }

  // Auto-connect first, THEN start the steady-state poller. (Connect is a one-
  // shot; polling handles everything after. Doing it in this order avoids a
  // redundant double-connect at launch.)
  await maybeAutoConnect();
  startPolling();
}

// Boot
init().catch(console.error);
