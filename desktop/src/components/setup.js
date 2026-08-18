// ── Setup — first-time environment initialization + enrollment ───────
//
// Per the goal, Setup is where BOTH of these live:
//   1. Enrollment — paste the `ztlp://enroll/...` string. It surfaces
//      prominently when the device is NOT yet enrolled, and hides (shows a
//      green "enrolled" state) once it is.
//   2. One-time environment init — CA chain, CA install into system trust,
//      DNS routing. These need admin (ports / trust store / DNS), so they
//      trigger the OS elevation prompt (UAC on Windows, pkexec/sudo on
//      macOS/Linux). The backend already implements the per-platform
//      elevation — the UI just reports it.
//   3. A final browser smoke test to confirm the green lock.
//
// All meaningful actions are mirrored into the global LiveLog so Home's
// feed always reflects what's happening, even when the user is on Setup.
//
// NOTE: interactive elements are bound with addEventListener (NOT inline
// onclick/oninput attributes) — inline handlers do not reliably fire in the
// WebView2 Runtime this app targets. See the header in the old enrollment.js.

const SetupComponent = (() => {
  const container = document.getElementById('page-setup');
  let lastStatus = null;
  let busy = false;

  function render() {
    container.innerHTML = `
      <h2 class="page-title">Setup</h2>
      <p class="page-sub">
        Enroll this device, then run the one-time environment setup. Each step is
        safe to re-run. Steps that need admin rights will ask for permission.
      </p>

      <div class="card" id="setup-status-card">
        <div class="card-title">Status</div>
        <div id="setup-status-body">
          <p class="setup-pending">Loading…</p>
        </div>
      </div>

      <!-- 1 — Enrollment (the "setup string") -->
      <div class="card">
        <div class="card-title">1 · Enroll this device</div>
        <div id="enroll-panel">
          <p class="setup-pending">Checking enrollment status…</p>
        </div>
      </div>

      <!-- 2 — CA chain (no admin) -->
      <div class="card">
        <div class="card-title">2 · Certificate Authority chain</div>
        <p class="setup-help">
          Generates this device's CA chain (root + intermediate) used to issue
          trusted certificates for services in your zone. Stored in
          <code>~/.ztlp/ca/</code>. No admin needed.
        </p>
        <button class="btn btn-primary" id="btn-ca-init">🔐 Generate CA chain</button>
        <div class="setup-step-state" id="step-ca-init-state"></div>
      </div>

      <!-- 3 — Install CA (admin) -->
      <div class="card">
        <div class="card-title">3 · Install CA in system trust</div>
        <p class="setup-help">
          Installs the root CA so browsers and other programs trust ZTLP service
          certificates. <strong>Requires admin</strong> — you'll see an OS
          permission prompt.
        </p>
        <button class="btn btn-primary" id="btn-install-ca">🛡️ Install CA (admin required)</button>
        <div class="setup-step-state" id="step-install-ca-state"></div>
      </div>

      <!-- 4 — DNS routing (admin) -->
      <div class="card">
        <div class="card-title">4 · DNS routing for your zone</div>
        <p class="setup-help">
          Routes traffic for <code id="setup-zone-display">…</code> to the local
          ZTLP agent. <strong>Requires admin.</strong>
        </p>
        <button class="btn btn-primary" id="btn-install-dns">🌐 Configure DNS (admin required)</button>
        <div class="setup-step-state" id="step-install-dns-state"></div>
      </div>

      <!-- 5 — Browser smoke test -->
      <div class="card">
        <div class="card-title">5 · Browser smoke test</div>
        <p class="setup-help">
          Verifies the whole stack end-to-end. Type a hostname in your zone and we
          fetch it over HTTPS with your installed CA. A 2xx means your browser will
          show a green lock on the same URL.
        </p>
        <div class="form-row">
          <input type="text" id="setup-test-hostname" class="form-input"
                 placeholder="e.g. vault.trs.ztlp" spellcheck="false" autocomplete="off">
          <button class="btn btn-primary" id="btn-test-browse">🚀 Test</button>
        </div>
        <div class="setup-step-state" id="step-test-browse-state"></div>
      </div>
    `;

    bindHandlers();
  }

  function bindHandlers() {
    wire('btn-ca-init', runCaInit);
    wire('btn-install-ca', installCa);
    wire('btn-install-dns', installDns);
    wire('btn-test-browse', testBrowse);
  }

  function wire(id, fn) {
    const el = document.getElementById(id);
    if (el) el.addEventListener('click', fn);
  }

  // ── enrollment panel ────────────────────────────────────────────────
  // Rendered separately so it can flip between "not enrolled" (show the paste
  // form) and "enrolled" (show a green done state) based on live status.
  function renderEnrollPanel(s) {
    const panel = document.getElementById('enroll-panel');
    if (!panel) return;

    if (s && s.daemon_running && s.identity_enrolled) {
      const zone = s.zone || '(unknown zone)';
      panel.innerHTML = `
        <div class="setup-done">
          <span class="setup-ok">✓ Enrolled</span>
          <span class="setup-zone">Zone: <code>${escapeHtml(zone)}</code></span>
          <button class="btn btn-secondary btn-sm" id="enroll-change-btn">Change enrollment</button>
        </div>
      `;
      const change = document.getElementById('enroll-change-btn');
      if (change) change.addEventListener('click', () => renderEnrollForm(panel));
      return;
    }

    renderEnrollForm(panel);
  }

  function renderEnrollForm(panel) {
    panel.innerHTML = `
      <p class="setup-help">
        Paste the <code>ztlp://enroll/…</code> string from your administrator to
        join a zone. This sets your relay and zone automatically.
      </p>
      <div class="form-group">
        <label class="form-label" for="enroll-uri">Enrollment string</label>
        <div class="enrollment-input-row">
          <input type="text" id="enroll-uri" class="form-input"
                 placeholder="ztlp://enroll/zone-name/token…"
                 spellcheck="false" autocomplete="off">
          <button class="btn btn-secondary btn-sm" id="enroll-paste-btn">📋 Paste</button>
        </div>
        <div class="form-hint">Get this string from your zone admin or the ZTLP gateway dashboard.</div>
      </div>
      <label class="form-label attestation-label">
        <input type="checkbox" id="enroll-attestation">
        <span>I attest I am the only user of this device.</span>
      </label>
      <button class="btn btn-primary" id="enroll-btn" disabled>🔑 Enroll</button>
      <div class="enrollment-status" id="enroll-status"></div>
    `;

    const uri = document.getElementById('enroll-uri');
    const att = document.getElementById('enroll-attestation');
    const paste = document.getElementById('enroll-paste-btn');
    const enrollBtn = document.getElementById('enroll-btn');

    if (uri) uri.addEventListener('input', updateEnrollBtn);
    if (att) att.addEventListener('change', updateEnrollBtn);
    if (paste) paste.addEventListener('click', pasteUri);
    if (enrollBtn) enrollBtn.addEventListener('click', enroll);
    updateEnrollBtn();
  }

  function updateEnrollBtn() {
    const att = document.getElementById('enroll-attestation');
    const uri = document.getElementById('enroll-uri');
    const btn = document.getElementById('enroll-btn');
    if (!btn) return;
    const hasUri = !!(uri && uri.value && uri.value.trim());
    btn.disabled = !(att && att.checked && hasUri);
  }

  async function pasteUri() {
    const uri = document.getElementById('enroll-uri');
    if (!uri) return;
    try {
      const text = await navigator.clipboard.readText();
      uri.value = (text || '').trim();
      uri.dispatchEvent(new Event('input', { bubbles: true }));
      updateEnrollBtn();
    } catch (e) {
      console.warn('clipboard readText failed:', e);
      setEnrollStatus('error', 'Clipboard access denied. Paste manually with Ctrl+V.');
      uri.focus();
    }
  }

  function setEnrollStatus(type, message) {
    const el = document.getElementById('enroll-status');
    if (!el) return;
    el.className = `enrollment-status ${type}`;
    el.textContent = message;
  }

  async function enroll() {
    const uri = document.getElementById('enroll-uri');
    const btn = document.getElementById('enroll-btn');
    const tokenUri = uri ? uri.value.trim() : '';

    if (!tokenUri) { setEnrollStatus('error', 'Please enter an enrollment string.'); return; }
    if (!tokenUri.startsWith('ztlp://enroll/')) {
      setEnrollStatus('error', 'Invalid string — it must start with ztlp://enroll/');
      LiveLog.fail('Enrollment string rejected (must start with ztlp://enroll/).');
      return;
    }

    btn.disabled = true;
    btn.textContent = 'Enrolling…';
    LiveLog.setup(`Enrolling device with zone "${tokenUri.split('/')[3] || '…'}".`);

    try {
      const result = await invoke('enroll', { tokenUri });
      if (result.success) {
        // Record the attestation audit trail (non-fatal if it fails).
        try {
          await invoke('record_attestation', { text: 'I attest I am the only user of this device.' });
        } catch (e) { console.warn('attestation record failed (non-fatal):', e); }
        setEnrollStatus('success',
          `✓ ${result.message}${result.zone_name ? ` — Zone: ${result.zone_name}` : ''}`);
        LiveLog.success(`Enrolled — ${result.zone_name || 'zone'} (relay + zone configured).`);
        // Now the rest of setup becomes actionable.
        await load();
      } else {
        setEnrollStatus('error', result.message || 'Enrollment failed.');
        LiveLog.fail(`Enrollment failed: ${result.message || 'unknown error'}`);
      }
    } catch (e) {
      setEnrollStatus('error', `Error: ${e}`);
      LiveLog.fail(`Enrollment error: ${e}`);
    } finally {
      btn.textContent = '🔑 Enroll';
      updateEnrollBtn();
    }
  }

  // ── status + repaint ────────────────────────────────────────────────
  function stateLine(ok, text) {
    if (ok === true) return `<span class="setup-ok">✓ ${escapeHtml(text)}</span>`;
    if (ok === false) return `<span class="setup-err">✗ ${escapeHtml(text)}</span>`;
    return `<span class="setup-pending">… ${escapeHtml(text)}</span>`;
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
    renderEnrollPanel(s);

    const body = document.getElementById('setup-status-body');
    if (!body) return;

    if (!s.daemon_running) {
      body.innerHTML = `
        <p class="setup-err">✗ ZTLP agent is not running.</p>
        <p class="setup-help">
          Start the agent (ztlp-node service), then click Refresh. Enrollment and
          the CA/DNS steps need the agent.
        </p>
        <button class="btn btn-secondary" id="setup-refresh">🔄 Refresh</button>
      `;
      const rf = document.getElementById('setup-refresh');
      if (rf) rf.addEventListener('click', load);
      setControls(false);
      return;
    }

    const zone = s.zone || '(none)';
    body.innerHTML = `
      <p>Agent: <span class="setup-ok">✓ running</span> · Zone: <code>${escapeHtml(zone)}</code></p>
      <ul class="setup-checklist">
        <li>${stateLine(s.identity_enrolled, s.identity_enrolled ? 'Identity enrolled' : 'Identity not enrolled')}</li>
        <li>${stateLine(s.ca_initialized, s.ca_initialized ? 'CA chain generated' : 'CA chain missing')}</li>
        <li>${stateLine(s.ca_installed_system_trust, s.ca_installed_system_trust ? 'CA installed in system trust' : 'CA not installed in system trust')}</li>
        <li>${stateLine(s.dns_configured, s.dns_configured ? 'DNS routes configured' : 'DNS routes missing')}</li>
      </ul>
      <button class="btn btn-secondary" id="setup-refresh">🔄 Refresh</button>
    `;
    const rf = document.getElementById('setup-refresh');
    if (rf) rf.addEventListener('click', load);

    const zoneDisp = document.getElementById('setup-zone-display');
    if (zoneDisp) zoneDisp.textContent = zone;

    setStepMessage('step-ca-init-state',
      s.ca_initialized ? stateLine(true, 'CA chain present') : stateLine(null, 'click to generate'));
    setStepMessage('step-install-ca-state',
      s.ca_installed_system_trust
        ? stateLine(true, 'CA installed in trust store')
        : stateLine(null, 'click to install (admin required)'));
    setStepMessage('step-install-dns-state',
      s.dns_configured
        ? stateLine(true, 'DNS routes active')
        : stateLine(null, 'click to configure (admin required)'));
    setStepMessage('step-test-browse-state', '');

    setControls(true, s);
  }

  function setControls(daemonUp, s) {
    const map = {
      'btn-ca-init': daemonUp && !!(s && s.identity_enrolled),
      'btn-install-ca': daemonUp && !!(s && s.ca_initialized),
      'btn-install-dns': daemonUp && !!(s && s.ca_initialized),
      'btn-test-browse': !!daemonUp,
    };
    for (const [id, enabled] of Object.entries(map)) {
      const el = document.getElementById(id);
      if (el) el.disabled = !enabled || busy;
    }
  }

  // ── the four init operations ────────────────────────────────────────
  async function runCaInit() {
    if (!lastStatus || !lastStatus.zone) {
      setStepMessage('step-ca-init-state', stateLine(false, 'enroll a zone first'));
      LiveLog.fail('CA init: enroll a zone first.');
      return;
    }
    busy = true;
    setStepMessage('step-ca-init-state', stateLine(null, 'generating…'));
    setControls(true, lastStatus);
    LiveLog.setup(`Generating CA chain for zone "${lastStatus.zone}".`);
    try {
      const out = await invoke('setup_run_ca_init', { zone: lastStatus.zone });
      setStepMessage('step-ca-init-state', stateLine(true, 'CA chain generated'));
      LiveLog.success('CA chain generated.');
      console.log('[setup] ca-init output:', out);
    } catch (e) {
      setStepMessage('step-ca-init-state', stateLine(false, String(e)));
      LiveLog.fail(`CA init failed: ${e}`);
    } finally {
      busy = false;
      await load();
    }
  }

  async function installCa() {
    busy = true;
    setStepMessage('step-install-ca-state', stateLine(null, 'waiting for admin prompt — please confirm…'));
    setControls(true, lastStatus);
    LiveLog.setup('Installing CA into system trust (admin prompt will appear).');
    try {
      const out = await invoke('setup_install_ca');
      setStepMessage('step-install-ca-state', stateLine(null, 'elevation dispatched — verifying…'));
      console.log('[setup] install-ca output:', out);
      // Elevated process runs detached — poll a few times for the flag to flip.
      for (let i = 0; i < 6; i++) {
        await new Promise(r => setTimeout(r, 1500));
        await load();
        if (lastStatus && lastStatus.ca_installed_system_trust) {
          LiveLog.success('CA installed into system trust.');
          break;
        }
      }
    } catch (e) {
      setStepMessage('step-install-ca-state', stateLine(false, String(e)));
      LiveLog.fail(`CA install failed: ${e}`);
    } finally {
      busy = false;
      await load();
    }
  }

  async function installDns() {
    if (!lastStatus || !lastStatus.zone) {
      setStepMessage('step-install-dns-state', stateLine(false, 'enroll a zone first'));
      LiveLog.fail('DNS setup: enroll a zone first.');
      return;
    }
    busy = true;
    setStepMessage('step-install-dns-state', stateLine(null, 'waiting for admin prompt — please confirm…'));
    setControls(true, lastStatus);
    LiveLog.setup(`Configuring DNS routing for zone "${lastStatus.zone}" (admin prompt will appear).`);
    try {
      const out = await invoke('setup_install_dns', { zone: lastStatus.zone });
      setStepMessage('step-install-dns-state', stateLine(null, 'elevation dispatched — verifying…'));
      console.log('[setup] install-dns output:', out);
      for (let i = 0; i < 6; i++) {
        await new Promise(r => setTimeout(r, 1500));
        await load();
        if (lastStatus && lastStatus.dns_configured) {
          LiveLog.success(`DNS routing active for ${lastStatus.zone}.`);
          break;
        }
      }
    } catch (e) {
      setStepMessage('step-install-dns-state', stateLine(false, String(e)));
      LiveLog.fail(`DNS setup failed: ${e}`);
    } finally {
      busy = false;
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
    busy = true;
    setStepMessage('step-test-browse-state', stateLine(null, `fetching https://${hostname}/ …`));
    setControls(true, lastStatus);
    LiveLog.setup(`Browser smoke test: fetching https://${hostname}/`);
    try {
      const out = await invoke('setup_test_browse', { hostname });
      const m = /HTTP (\d+)/.exec(out);
      const code = m ? parseInt(m[1], 10) : 0;
      const ok = code >= 200 && code < 400;
      setStepMessage('step-test-browse-state',
        ok ? stateLine(true, `${out} — your browser will show a green lock!`)
           : stateLine(false, out));
      if (ok) LiveLog.success(`Green lock confirmed: ${out}`);
      else LiveLog.fail(`Smoke test returned ${out}`);
    } catch (e) {
      setStepMessage('step-test-browse-state', stateLine(false, String(e)));
      LiveLog.fail(`Smoke test failed: ${e}`);
    } finally {
      busy = false;
      setControls(true, lastStatus);
    }
  }

  function escapeHtml(s) {
    return String(s).replace(/[<>&"']/g, c => ({
      '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;',
    })[c]);
  }

  return { render, load };
})();
