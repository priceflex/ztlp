// ── Home — the entire point of the app, in one screen ─────────────────
//
// Per the goal, Home is nearly empty:
//   • the ZTLP logo (big)
//   • a status ring + label ("Active" once connected, no button needed)
//   • the enrolled identity, once known
//   • a live activity log showing what's actually happening
//
// The app auto-connects on launch (see app.js's maybeAutoConnect) once
// enrolled — there is no manual "Connect" step in the steady-state flow.
// A button only appears when the user needs to take an action: retrying
// after an error, or manually disconnecting.

const HomeComponent = (() => {
  const container = document.getElementById('page-home');
  let currentStatus = null;
  let currentIdentity = null;

  function render() {
    container.innerHTML = `
      <div class="home">
        <div class="home-hero">
          <img class="home-logo" src="assets/ztlp-logo.png" alt="ZTLP">
          <div class="status-ring" id="home-status-ring">
            <div class="status-dot"></div>
          </div>
          <div class="status-label" id="home-status-label">Ready</div>
          <div class="status-sublabel" id="home-status-sublabel">ZTLP is standing by — connecting automatically.</div>
          <div class="identity-line" id="home-identity-line" style="display:none;"></div>
          <button class="btn btn-primary btn-connect" id="home-toggle-btn" style="display:none;">
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

    // Bind the button (hidden by default — only shown for retry/disconnect,
    // see update()). We use addEventListener (NOT an inline onclick
    // attribute) — inline handlers are unreliable in the WebView2 Runtime
    // this app targets (see the note in enrollment.js's header).
    const btn = document.getElementById('home-toggle-btn');
    if (btn) btn.addEventListener('click', toggle);
  }

  async function load() {
    try {
      const [status, identity] = await Promise.all([
        invoke('get_status'),
        invoke('get_identity').catch(() => null),
      ]);
      currentIdentity = identity;
      update(status);
      LiveLog.stateChange(status);
    } catch (e) {
      renderErrorState(e);
    }
  }

  function identityLabel() {
    if (!currentIdentity || !currentIdentity.enrolled) return '';
    const zone = currentIdentity.zone_name || '';
    const nodeId = currentIdentity.node_id || '';
    const short = nodeId ? `${nodeId.slice(0, 12)}…` : '';
    return zone ? `${zone}${short ? ` · ${short}` : ''}` : short;
  }

  function update(status) {
    currentStatus = status;

    const ring = document.getElementById('home-status-ring');
    const label = document.getElementById('home-status-label');
    const sublabel = document.getElementById('home-status-sublabel');
    const btn = document.getElementById('home-toggle-btn');
    const identityLine = document.getElementById('home-identity-line');
    if (!ring) return; // not rendered yet

    // Reset ring state classes, then apply the one for the current state.
    ring.className = 'status-ring';

    // "Active" (not "Connected") — this isn't a VPN the user toggles; once
    // enrolled it just quietly stays attached, and the button is hidden in
    // that state. The button only resurfaces for manual disconnect/retry.
    const stateMap = {
      disconnected:   { label: 'Ready',          sub: 'ZTLP is standing by — connecting automatically.',       showBtn: false, btn: 'Connect',     cls: 'btn btn-primary btn-connect', ring: '',             disabled: false },
      connecting:     { label: 'Connecting…',    sub: 'Handshaking over the tunnel.',                          showBtn: false, btn: 'Connecting…', cls: 'btn btn-secondary',           ring: 'connecting',   disabled: true  },
      connected:      { label: 'Active',         sub: '',                                                      showBtn: true,  btn: 'Disconnect',  cls: 'btn btn-tertiary',             ring: 'connected',    disabled: false },
      reconnecting:   { label: 'Reconnecting…',  sub: 'Restoring the connection.',                             showBtn: false, btn: 'Disconnect',  cls: 'btn btn-danger',              ring: 'reconnecting', disabled: true  },
      disconnecting:  { label: 'Disconnecting…', sub: 'Tearing down.',                                          showBtn: false, btn: 'Disconnect',  cls: 'btn btn-secondary',           ring: 'disconnecting',disabled: true },
      failed:         { label: 'Connection failed', sub: status.error || 'See the log for details.',           showBtn: true,  btn: 'Retry',       cls: 'btn btn-primary',             ring: 'error',        disabled: false },
      error:          { label: 'Error',          sub: status.error || 'System error.',                         showBtn: true,  btn: 'Retry',       cls: 'btn btn-primary',             ring: 'error',        disabled: false },
    };

    const s = stateMap[status.state] || stateMap.disconnected;
    if (s.ring) ring.classList.add(s.ring);
    label.textContent = s.label;
    sublabel.textContent = s.sub;
    sublabel.style.display = s.sub ? '' : 'none';
    btn.textContent = s.btn;
    btn.className = s.cls;
    btn.disabled = s.disabled;
    btn.style.display = s.showBtn ? '' : 'none';

    // Identity readout — only shown once Active, so the home screen reads
    // "Active" + who/where you're attached as, per the intended UX.
    const idText = identityLabel();
    if (identityLine) {
      if (status.state === 'connected' && idText) {
        identityLine.textContent = idText;
        identityLine.style.display = '';
      } else {
        identityLine.style.display = 'none';
      }
    }
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
      sublabel.textContent = 'Starting the ZTLP agent automatically…';
      LiveLog.fail('Agent not reachable yet — starting it automatically.');
    } else {
      label.textContent = 'Error';
      sublabel.textContent = errStr;
      LiveLog.fail(errStr);
    }
    sublabel.style.display = '';
    btn.textContent = 'Retry';
    btn.className = 'btn btn-primary btn-connect';
    btn.disabled = false;
    btn.style.display = '';
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
