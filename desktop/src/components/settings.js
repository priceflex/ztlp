// ── Settings Component — Configuration ──────────────────────────────

const SettingsComponent = (() => {
  const container = document.getElementById('page-settings');
  let config = null;

  function render() {
    container.innerHTML = `
      <h2 class="page-title">Settings</h2>

      <div class="card">
        <div class="card-title">Network</div>

        <div class="form-group">
          <label class="form-label" for="settings-relay">Relay Address</label>
          <input type="text" id="settings-relay" class="form-input"
                 placeholder="relay.ztlp.net:4433" spellcheck="false">
          <div class="form-hint">The ZTLP relay server to connect through.</div>
        </div>

        <div class="form-group">
          <label class="form-label" for="settings-stun">STUN Server</label>
          <input type="text" id="settings-stun" class="form-input"
                 placeholder="stun.l.google.com:19302" spellcheck="false">
          <div class="form-hint">STUN server used for NAT traversal.</div>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Tunnel</div>

        <div class="form-group">
          <label class="form-label" for="settings-tunnel-addr">Tunnel Address</label>
          <input type="text" id="settings-tunnel-addr" class="form-input"
                 placeholder="10.0.0.2" spellcheck="false">
          <div class="form-hint">Local TUN interface address.</div>
        </div>

        <div class="form-group">
          <label class="form-label" for="settings-dns">DNS Servers</label>
          <input type="text" id="settings-dns" class="form-input"
                 placeholder="1.1.1.1, 8.8.8.8" spellcheck="false">
          <div class="form-hint">Comma-separated DNS servers used while tunnel is active.</div>
        </div>

        <div class="form-group">
          <label class="form-label">MTU</label>
          <div class="range-row">
            <input type="range" id="settings-mtu" min="1200" max="1500" step="10" value="1400">
            <span class="range-value" id="settings-mtu-value">1400</span>
          </div>
          <div class="form-hint">Maximum Transmission Unit for the tunnel interface.</div>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Behavior</div>

        <div class="toggle-row">
          <div>
            <div class="toggle-label">Auto-connect</div>
            <div class="toggle-desc">Automatically connect when the app launches</div>
          </div>
          <label class="toggle">
            <input type="checkbox" id="settings-autoconnect">
            <span class="toggle-slider"></span>
          </label>
        </div>
      </div>

      <div style="display: flex; gap: 8px; margin-top: 8px;">
        <button class="btn btn-primary" onclick="SettingsComponent.save()">
          💾 Save Settings
        </button>
        <button class="btn btn-secondary" onclick="SettingsComponent.load()">
          ↩ Reset
        </button>
      </div>

      <div class="enrollment-status" id="settings-status" style="margin-top: 12px;"></div>
    `;

    // MTU slider live update
    const mtuSlider = document.getElementById('settings-mtu');
    const mtuValue = document.getElementById('settings-mtu-value');
    if (mtuSlider && mtuValue) {
      mtuSlider.addEventListener('input', () => {
        mtuValue.textContent = mtuSlider.value;
      });
    }
  }

  async function load() {
    try {
      config = await invoke('get_config');
      populateForm(config);
    } catch (e) {
      console.error('Settings load error:', e);
    }
  }

  function populateForm(c) {
    const el = (id) => document.getElementById(id);

    if (el('settings-relay')) el('settings-relay').value = c.relay_address || '';
    if (el('settings-stun')) el('settings-stun').value = c.stun_server || '';
    if (el('settings-tunnel-addr')) el('settings-tunnel-addr').value = c.tunnel_address || '';
    if (el('settings-dns')) el('settings-dns').value = (c.dns_servers || []).join(', ');
    if (el('settings-mtu')) {
      el('settings-mtu').value = c.mtu || 1400;
      if (el('settings-mtu-value')) el('settings-mtu-value').textContent = c.mtu || 1400;
    }
    if (el('settings-autoconnect')) el('settings-autoconnect').checked = !!c.auto_connect;
  }

  async function save() {
    const el = (id) => document.getElementById(id);

    const dnsStr = (el('settings-dns')?.value || '').trim();
    const dnsServers = dnsStr ? dnsStr.split(',').map(s => s.trim()).filter(Boolean) : [];

    const newConfig = {
      relay_address: el('settings-relay')?.value.trim() || '',
      stun_server: el('settings-stun')?.value.trim() || 'stun.l.google.com:19302',
      tunnel_address: el('settings-tunnel-addr')?.value.trim() || '10.0.0.2',
      dns_servers: dnsServers,
      mtu: parseInt(el('settings-mtu')?.value || '1400', 10),
      auto_connect: el('settings-autoconnect')?.checked || false,
    };

    try {
      await invoke('save_config', { config: newConfig });
      config = newConfig;
      showStatus('success', '✓ Settings saved.');
    } catch (e) {
      showStatus('error', `Error saving settings: ${e}`);
    }
  }

  function showStatus(type, message) {
    const el = document.getElementById('settings-status');
    if (!el) return;
    el.className = `enrollment-status ${type}`;
    el.textContent = message;
    // Auto-clear after 3s
    setTimeout(() => {
      if (el.textContent === message) {
        el.className = 'enrollment-status';
        el.textContent = '';
      }
    }, 3000);
  }

  return { render, load, save };
})();
