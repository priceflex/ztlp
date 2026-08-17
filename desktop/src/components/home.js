// ── Home — the entire point of the app, in one screen ─────────────────
//
// Per the goal, Home is nearly empty:
//   • the ZTLP logo (big)
//   • a status ring + label
//   • ONE big Connect button (uses the existing connection manager)
//   • a live activity log showing what's actually happening
//
// Removed from the old Home: relay address, connection-detail table, and the
// whole traffic panel. This is not a user-facing VPN — the app just stays
// ready to accept connections.

const HomeComponent = (() => {
  const container = document.getElementById('page-home');
  let currentStatus = null;

  function render() {
    container.innerHTML = `
      <div class="home">
        <div class="home-hero">
          <img class="home-logo" src="assets/ztlp-logo.png" alt="ZTLP">
          <div class="status-ring" id="home-status-ring">
            <div class="status-dot"></div>
          </div>
          <div class="status-label" id="home-status-label">Ready</div>
          <div class="status-sublabel" id="home-status-sublabel">ZTLP is standing by — connect when you're ready.</div>
          <button class="btn btn-primary btn-connect" id="home-toggle-btn">
            Connect
          </button>
        </div>

        <div class="card log-card">
          <div class="card-title">Live activity</div>
          <div class="log" id="home-log"></div>
        </div>
      </div>
    `;

    LiveLog.render();

    // Bind the single Connect button. We use addEventListener (NOT an inline
    // onclick attribute) — inline handlers are unreliable in the WebView2
    // Runtime this app targets (see the note in enrollment.js's header).
    const btn = document.getElementById('home-toggle-btn');
    if (btn) btn.addEventListener('click', toggle);
  }

  async function load() {
    try {
      const status = await invoke('get_status');
      update(status);
      LiveLog.stateChange(status);
    } catch (e) {
      renderErrorState(e);
    }
  }

  function update(status) {
    currentStatus = status;

    const ring = document.getElementById('home-status-ring');
    const label = document.getElementById('home-status-label');
    const sublabel = document.getElementById('home-status-sublabel');
    const btn = document.getElementById('home-toggle-btn');
    if (!ring) return; // not rendered yet

    // Reset ring state classes, then apply the one for the current state.
    ring.className = 'status-ring';

    const stateMap = {
      disconnected:   { label: 'Ready',         sub: 'ZTLP is standing by — connect when you\u2019re ready.', btn: 'Connect',     cls: 'btn btn-primary btn-connect', ring: '',            disabled: false },
      connecting:     { label: 'Connecting…',   sub: 'Handshaking over the tunnel.',                         btn: 'Connecting…', cls: 'btn btn-secondary',           ring: 'connecting',  disabled: true  },
      connected:      { label: 'Connected',     sub: 'Secured and ready to accept connections.',             btn: 'Disconnect',  cls: 'btn btn-danger',              ring: 'connected',   disabled: false },
      reconnecting:   { label: 'Reconnecting…', sub: 'Restoring the connection.',                            btn: 'Disconnect',  cls: 'btn btn-danger',              ring: 'reconnecting',disabled: true  },
      disconnecting:  { label: 'Disconnecting…',sub: 'Tearing down.',                                         btn: 'Disconnect',  cls: 'btn btn-secondary',           ring: 'disconnecting',disabled: true },
      failed:         { label: 'Connection failed', sub: status.error || 'See the log for details.',         btn: 'Retry',       cls: 'btn btn-primary',           ring: 'error',       disabled: false },
      error:          { label: 'Error',         sub: status.error || 'System error.',                        btn: 'Retry',       cls: 'btn btn-primary',           ring: 'error',       disabled: false },
    };

    const s = stateMap[status.state] || stateMap.disconnected;
    if (s.ring) ring.classList.add(s.ring);
    label.textContent = s.label;
    sublabel.textContent = s.sub;
    btn.textContent = s.btn;
    btn.className = s.cls;
    btn.disabled = s.disabled;
  }

  function renderErrorState(err) {
    const ring = document.getElementById('home-status-ring');
    const label = document.getElementById('home-status-label');
    const sublabel = document.getElementById('home-status-sublabel');
    const btn = document.getElementById('home-toggle-btn');
    if (!ring) return;

    const errStr = err && err.toString ? err.toString() : String(err);
    const isAgentDown = /Failed to connect to daemon|connection refused|ConnectionRefused/i.test(errStr);

    ring.className = 'status-ring error';
    if (isAgentDown) {
      label.textContent = 'Agent not running';
      sublabel.textContent = 'Start the ZTLP agent (ztlp-node service) to connect.';
      LiveLog.fail('Agent not reachable — is the ztlp-node service running?');
    } else {
      label.textContent = 'Error';
      sublabel.textContent = errStr;
      LiveLog.fail(errStr);
    }
    btn.textContent = 'Retry';
    btn.className = 'btn btn-primary btn-connect';
    btn.disabled = false;
  }

  async function toggle() {
    try {
      const st = currentStatus ? currentStatus.state : 'disconnected';
      if (st === 'connected') {
        LiveLog.setup('Disconnect requested.');
        LiveLog.markConnected();
        await invoke('disconnect');
        LiveLog.markDisconnected();
        await invoke('get_status').then(update).catch(() => {});
        LiveLog.stateChange(await safeStatus());
      } else {
        LiveLog.setup('Connect requested.');
        const config = await invoke('get_config');
        // Relay is handled by the name server + tunnel — never surfaced to the
        // user. Read it from config silently, fall back to the default.
        const relay = config.relay_address || 'relay.ztlp.net:4433';
        await invoke('connect', { relay, zone: 'default' });
        LiveLog.stateChange(await safeStatus());
      }
    } catch (e) {
      console.error('Toggle error:', e);
      renderErrorState(e);
    }
  }

  async function safeStatus() {
    try {
      const status = await invoke('get_status');
      update(status);
      return status;
    } catch {
      return null;
    }
  }

  return { render, load, update, toggle };
})();
