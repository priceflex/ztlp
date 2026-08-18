// ── Settings — behavior + identity/zone info ──────────────────────────
//
// Per the goal, Settings keeps just the essentials:
//   • Auto-connect toggle (default ON — the app "stays ready")
//   • Zone + identity info (what used to be the standalone Identity page)
//
// Removed: the relay address field, STUN, tunnel address, DNS servers, and
// the MTU slider. Relay/DNS are handled through the name server + tunnel and
// are not user-facing. If power users ever need the tunnel knobs again, they
// can reappear here behind an "Advanced" section without disturbing the
// simple default.

const SettingsComponent = (() => {
  const container = document.getElementById('page-settings');
  let config = null;
  let identity = null;

  function render() {
    container.innerHTML = `
      <h2 class="page-title">Settings</h2>

      <div class="card">
        <div class="card-title">Behavior</div>
        <div class="toggle-row">
          <div>
            <div class="toggle-label">Auto-connect</div>
            <div class="toggle-desc">
              Connect automatically and stay ready for connections. ZTLP is not a
              VPN you flip on and off — it just keeps a secured channel ready.
            </div>
          </div>
          <label class="toggle">
            <input type="checkbox" id="settings-autoconnect">
            <span class="toggle-slider"></span>
          </label>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Identity &amp; zone</div>
        <div id="settings-identity-body">
          <p class="setup-pending">Loading…</p>
        </div>
      </div>

      <div style="display:flex; gap:8px; margin-top:4px;">
        <button id="settings-save-btn" class="btn btn-primary">💾 Save settings</button>
        <button id="settings-reload-btn" class="btn btn-secondary">↩ Reload</button>
      </div>

      <div class="enrollment-status" id="settings-status"></div>
    `;

    const save = document.getElementById('settings-save-btn');
    const reload = document.getElementById('settings-reload-btn');
    if (save) save.addEventListener('click', save);
    if (reload) reload.addEventListener('click', load);
  }

  async function load() {
    // Config is optional (settings may not exist yet); identity is optional too.
    try {
      config = await invoke('get_config');
      const ac = document.getElementById('settings-autoconnect');
      if (ac) ac.checked = !!config.auto_connect;
    } catch (e) {
      console.error('Settings load (config) error:', e);
    }
    try {
      identity = await invoke('get_identity');
    } catch (e) {
      identity = null;
    }
    renderIdentity();
  }

  function renderIdentity() {
    const body = document.getElementById('settings-identity-body');
    if (!body) return;

    if (!identity || !identity.node_id) {
      body.innerHTML = `
        <p class="setup-err">✗ No identity found.</p>
        <p class="setup-help">Run Setup to enroll this device, then it will appear here.</p>
      `;
      return;
    }

    const zone = identity.zone_name || 'not enrolled';
    body.innerHTML = `
      <div class="info-row">
        <span class="info-label">Zone</span>
        <span class="info-value">${escapeHtml(zone)}</span>
      </div>
      <div class="info-row">
        <span class="info-label">Enrollment</span>
        <span class="info-value">
          ${identity.enrolled
            ? '<span class="badge badge-green">✓ Enrolled</span>'
            : '<span class="badge badge-red">Not enrolled</span>'}
        </span>
      </div>
      <div class="info-row">
        <span class="info-label">Node ID</span>
        <span class="info-value">
          <span title="${escapeAttr(identity.node_id)}">${escapeHtml(truncateMiddle(identity.node_id, 10, 6))}</span>
          <button class="copy-btn" id="copy-nodeid">📋</button>
        </span>
      </div>
      <div class="info-row">
        <span class="info-label">Key provider</span>
        <span class="info-value">${escapeHtml(identity.provider_type || 'software')}</span>
      </div>
    `;
    const copyBtn = document.getElementById('copy-nodeid');
    if (copyBtn) copyBtn.addEventListener('click', () => copyToClipboard(identity.node_id, copyBtn));
  }

  async function save() {
    const ac = document.getElementById('settings-autoconnect');
    try {
      const newConfig = {
        ...config,
        auto_connect: !!(ac && ac.checked),
      };
      await invoke('save_config', { config: newConfig });
      config = newConfig;
      const on = newConfig.auto_connect;
      LiveLog.setup(`Auto-connect ${on ? 'enabled' : 'disabled'}.`);
      showStatus('success', `✓ Auto-connect ${on ? 'on' : 'off'}.`);
      // Honor the new setting immediately.
      if (on) {
        try { await invoke('connect', { relay: config.relay_address || 'relay.ztlp.net:4433', zone: 'default' }); }
        catch (e) { LiveLog.fail(`Auto-connect attempt: ${e}`); }
      } else {
        try { await invoke('disconnect'); } catch (e) { /* already down */ }
      }
    } catch (e) {
      showStatus('error', `Error saving settings: ${e}`);
    }
  }

  function showStatus(type, message) {
    const el = document.getElementById('settings-status');
    if (!el) return;
    el.className = `enrollment-status ${type}`;
    el.textContent = message;
    setTimeout(() => {
      if (el.textContent === message) { el.className = 'enrollment-status'; el.textContent = ''; }
    }, 3000);
  }

  function truncateMiddle(str, prefix, suffix) {
    if (!str || str.length <= prefix + suffix + 3) return str || '';
    return str.slice(0, prefix) + '…' + str.slice(-suffix);
  }

  function escapeHtml(s) {
    return String(s).replace(/[<>&"']/g, c => ({
      '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;',
    })[c]);
  }

  function escapeAttr(s) {
    return String(s).replace(/'/g, "\\'").replace(/"/g, '&quot;');
  }

  return { render, load };
})();
