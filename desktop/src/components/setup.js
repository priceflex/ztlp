// ── Setup Wizard Component (D6) ─────────────────────────────────────────
//
// Walks a non-technical user through the post-enrollment one-time setup:
//   ① Identity      — enrolled?
//   ② CA Chain      — `~/.ztlp/ca/` has a real X.509 root + intermediate?
//   ③ CA Installed  — root cert is in the OS trust store?
//   ④ DNS Routes    — NRPT (Windows) / resolver rules (mac/linux) for the zone?
//   ⑤ Browser Test  — fetch https://<hostname>/ and check the chain validates?
//
// Each step is one button on the page. The buttons enable/disable based on
// the latest `setup_status` snapshot we got from the daemon. After every
// click we re-fetch status and re-render so the green check appears as
// soon as the work is done.

const SetupComponent = (() => {
  const container = document.getElementById('page-setup');
  let lastStatus = null;
  let busyStep = null; // step id currently executing, used to show spinners

  function render() {
    container.innerHTML = `
      <h2 class="page-title">Setup Wizard</h2>
      <p style="color: var(--text-secondary); margin-bottom: 16px; font-size: 13px;">
        Run these one-time steps to enable secure browsing inside your zone.
        Each step is safe to re-run — they're all idempotent.
      </p>

      <div class="card" id="setup-status-card">
        <div class="card-title">Status</div>
        <div id="setup-status-body">
          <p style="color: var(--text-secondary);">Loading…</p>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Step 1 — Identity</div>
        <p style="color: var(--text-secondary); font-size: 13px;">
          You must enroll this device with a ztlp:// token before you can run
          the rest of setup. <a href="#" onclick="navigateTo('enrollment'); return false;">Go to Enrollment</a>.
        </p>
        <div id="step-identity-state" class="setup-step-state"></div>
      </div>

      <div class="card">
        <div class="card-title">Step 2 — Certificate Authority</div>
        <p style="color: var(--text-secondary); font-size: 13px;">
          Generates a per-device CA chain (root + intermediate) used to issue
          trusted certificates for services in your zone. Stored in
          <code>~/.ztlp/ca/</code>.
        </p>
        <button class="btn btn-primary" id="btn-ca-init"
                onclick="SetupComponent.runCaInit()">
          🔐 Generate CA Chain
        </button>
        <div id="step-ca-init-state" class="setup-step-state"></div>
      </div>

      <div class="card">
        <div class="card-title">Step 3 — Install CA in System Trust</div>
        <p style="color: var(--text-secondary); font-size: 13px;">
          Installs the root CA so all programs (including your browser) trust
          ZTLP service certificates. <strong>You will see a Windows
          administrator prompt</strong> — that's expected.
        </p>
        <button class="btn btn-primary" id="btn-install-ca"
                onclick="SetupComponent.installCa()">
          🛡️ Install CA (admin required)
        </button>
        <div id="step-install-ca-state" class="setup-step-state"></div>
      </div>

      <div class="card">
        <div class="card-title">Step 4 — DNS Routing</div>
        <p style="color: var(--text-secondary); font-size: 13px;">
          Routes traffic for your zone (<code id="setup-zone-display">…</code>)
          to the local ZTLP agent. On Windows this uses NRPT;
          <strong>you'll see another administrator prompt</strong>.
        </p>
        <button class="btn btn-primary" id="btn-install-dns"
                onclick="SetupComponent.installDns()">
          🌐 Configure DNS (admin required)
        </button>
        <div id="step-install-dns-state" class="setup-step-state"></div>
      </div>

      <div class="card">
        <div class="card-title">Step 5 — Browser Smoke Test</div>
        <p style="color: var(--text-secondary); font-size: 13px;">
          Verifies the entire stack end-to-end: type a hostname in your zone
          and we'll fetch it over HTTPS using the CA you installed. A
          <strong>2xx response</strong> means everything works — your
          browser will show a green lock on the same URL.
        </p>
        <div class="form-group" style="display: flex; gap: 8px;">
          <input type="text" id="setup-test-hostname" class="form-input"
                 placeholder="e.g. vault.trs.ztlp"
                 spellcheck="false" autocomplete="off"
                 style="flex: 1;">
          <button class="btn btn-primary" id="btn-test-browse"
                  onclick="SetupComponent.testBrowse()">
            🚀 Test
          </button>
        </div>
        <div id="step-test-browse-state" class="setup-step-state"></div>
      </div>
    `;
  }

  function stateLine(ok, text) {
    if (ok === true) return `<span class="setup-ok">✓ ${escapeHtml(text)}</span>`;
    if (ok === false) return `<span class="setup-err">✗ ${escapeHtml(text)}</span>`;
    return `<span class="setup-pending">… ${escapeHtml(text)}</span>`;
  }

  function escapeHtml(s) {
    return String(s).replace(/[<>&"']/g, c => ({
      '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;',
    })[c]);
  }

  function setStepMessage(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
  }

  async function load() {
    try {
      lastStatus = await invoke('setup_status');
    } catch (e) {
      lastStatus = { daemon_running: false };
    }
    repaint();
  }

  function repaint() {
    const s = lastStatus || {};
    const body = document.getElementById('setup-status-body');
    if (!body) return;

    if (!s.daemon_running) {
      body.innerHTML = `
        <p class="setup-err">✗ ZTLP agent is not running.</p>
        <p style="color: var(--text-secondary); font-size: 13px;">
          Start the agent from the system tray (right-click the ZTLP icon →
          Connect), then click <strong>Refresh</strong>.
        </p>
        <button class="btn btn-secondary" onclick="SetupComponent.load()">🔄 Refresh</button>
      `;
      setControls(false);
      return;
    }

    const zone = s.zone || '(none)';
    body.innerHTML = `
      <p>Agent: ✓ running. Zone: <code>${escapeHtml(zone)}</code></p>
      <ul style="margin-top: 8px; padding-left: 20px;">
        <li>${stateLine(s.identity_enrolled, s.identity_enrolled ? 'Identity enrolled' : 'Identity not enrolled')}</li>
        <li>${stateLine(s.ca_initialized, s.ca_initialized ? 'CA chain generated' : 'CA chain missing')}</li>
        <li>${stateLine(s.ca_installed_system_trust, s.ca_installed_system_trust ? 'CA installed in system trust' : 'CA not installed in system trust')}</li>
        <li>${stateLine(s.dns_configured, s.dns_configured ? 'DNS routes configured' : 'DNS routes missing')}</li>
      </ul>
      <button class="btn btn-secondary" style="margin-top: 8px;" onclick="SetupComponent.load()">🔄 Refresh</button>
    `;

    const zoneDisp = document.getElementById('setup-zone-display');
    if (zoneDisp) zoneDisp.textContent = zone;

    setStepMessage('step-identity-state',
      s.identity_enrolled
        ? stateLine(true, `enrolled to ${zone}`)
        : stateLine(false, 'not enrolled — visit the Enrollment page first'));

    setStepMessage('step-ca-init-state',
      s.ca_initialized
        ? stateLine(true, 'CA chain present')
        : stateLine(null, 'click the button to generate'));

    setStepMessage('step-install-ca-state',
      s.ca_installed_system_trust
        ? stateLine(true, 'CA installed in trust store')
        : stateLine(null, 'click the button to install (requires admin)'));

    setStepMessage('step-install-dns-state',
      s.dns_configured
        ? stateLine(true, 'DNS routes active')
        : stateLine(null, 'click the button to configure (requires admin)'));

    setStepMessage('step-test-browse-state', '');

    setControls(true, s);
  }

  function setControls(daemonUp, s) {
    const map = {
      'btn-ca-init': daemonUp && (s ? s.identity_enrolled : false),
      'btn-install-ca': daemonUp && (s ? s.ca_initialized : false),
      'btn-install-dns': daemonUp && (s ? s.ca_initialized : false),
      'btn-test-browse': daemonUp,
    };
    for (const [id, enabled] of Object.entries(map)) {
      const el = document.getElementById(id);
      if (el) el.disabled = !enabled || (busyStep !== null);
    }
  }

  async function runCaInit() {
    if (!lastStatus || !lastStatus.zone) {
      setStepMessage('step-ca-init-state', stateLine(false, 'enroll a zone first'));
      return;
    }
    busyStep = 'ca-init';
    setStepMessage('step-ca-init-state', stateLine(null, 'generating...'));
    setControls(true, lastStatus);
    try {
      const out = await invoke('setup_run_ca_init', { zone: lastStatus.zone });
      setStepMessage('step-ca-init-state', stateLine(true, 'CA chain generated'));
      console.log('[setup] ca-init output:', out);
    } catch (e) {
      setStepMessage('step-ca-init-state', stateLine(false, String(e)));
    } finally {
      busyStep = null;
      await load();
    }
  }

  async function installCa() {
    busyStep = 'install-ca';
    setStepMessage('step-install-ca-state', stateLine(null, 'waiting for UAC prompt — please confirm...'));
    setControls(true, lastStatus);
    try {
      const out = await invoke('setup_install_ca');
      setStepMessage('step-install-ca-state', stateLine(null, 'elevation dispatched — verifying...'));
      console.log('[setup] install-ca output:', out);
      // The UAC'd process runs detached; poll status a few times.
      for (let i = 0; i < 6; i++) {
        await new Promise(r => setTimeout(r, 1500));
        await load();
        if (lastStatus && lastStatus.ca_installed_system_trust) break;
      }
    } catch (e) {
      setStepMessage('step-install-ca-state', stateLine(false, String(e)));
    } finally {
      busyStep = null;
      await load();
    }
  }

  async function installDns() {
    if (!lastStatus || !lastStatus.zone) {
      setStepMessage('step-install-dns-state', stateLine(false, 'enroll a zone first'));
      return;
    }
    busyStep = 'install-dns';
    setStepMessage('step-install-dns-state', stateLine(null, 'waiting for UAC prompt — please confirm...'));
    setControls(true, lastStatus);
    try {
      const out = await invoke('setup_install_dns', { zone: lastStatus.zone });
      setStepMessage('step-install-dns-state', stateLine(null, 'elevation dispatched — verifying...'));
      console.log('[setup] install-dns output:', out);
      for (let i = 0; i < 6; i++) {
        await new Promise(r => setTimeout(r, 1500));
        await load();
        if (lastStatus && lastStatus.dns_configured) break;
      }
    } catch (e) {
      setStepMessage('step-install-dns-state', stateLine(false, String(e)));
    } finally {
      busyStep = null;
      await load();
    }
  }

  async function testBrowse() {
    const input = document.getElementById('setup-test-hostname');
    const hostname = input ? input.value.trim() : '';
    if (!hostname) {
      setStepMessage('step-test-browse-state', stateLine(false, 'enter a hostname first (e.g. vault.trs.ztlp)'));
      return;
    }
    busyStep = 'test';
    setStepMessage('step-test-browse-state', stateLine(null, `fetching https://${hostname}/ ...`));
    setControls(true, lastStatus);
    try {
      const out = await invoke('setup_test_browse', { hostname });
      // out is "HTTP 200 from https://..."
      const m = /HTTP (\d+)/.exec(out);
      const code = m ? parseInt(m[1], 10) : 0;
      const ok = code >= 200 && code < 400;
      setStepMessage('step-test-browse-state',
        ok ? stateLine(true, `${out} — your browser will show a green lock!`)
           : stateLine(false, out));
    } catch (e) {
      setStepMessage('step-test-browse-state', stateLine(false, String(e)));
    } finally {
      busyStep = null;
      setControls(true, lastStatus);
    }
  }

  return { render, load, runCaInit, installCa, installDns, testBrowse };
})();
