// ── Home Component — Connection status + toggle ─────────────────────

const HomeComponent = (() => {
  const container = document.getElementById('page-home');
  let currentStatus = null;

  function render() {
    container.innerHTML = `
      <h2 class="page-title">Connection</h2>
      <div class="card">
        <div class="status-hero">
          <div class="status-ring" id="home-status-ring">
            <div class="status-dot"></div>
          </div>
          <div class="status-label" id="home-status-label">Disconnected</div>
          <div class="status-sublabel" id="home-status-sublabel">Not connected to any relay</div>
          <button class="btn btn-primary" id="home-toggle-btn" onclick="HomeComponent.toggle()">
            Connect
          </button>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Connection Details</div>
        <div class="info-row">
          <span class="info-label">Relay</span>
          <span class="info-value" id="home-relay">—</span>
        </div>
        <div class="info-row">
          <span class="info-label">Zone</span>
          <span class="info-value" id="home-zone">—</span>
        </div>
        <div class="info-row">
          <span class="info-label">Duration</span>
          <span class="info-value" id="home-duration">--:--:--</span>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Traffic</div>
        <div class="stats-grid">
          <div class="stat-item">
            <div class="stat-value" id="home-bytes-up">0 B</div>
            <div class="stat-label">↑ Sent</div>
          </div>
          <div class="stat-item">
            <div class="stat-value" id="home-bytes-down">0 B</div>
            <div class="stat-label">↓ Received</div>
          </div>
          <div class="stat-item">
            <div class="stat-value" id="home-pkts-up">0</div>
            <div class="stat-label">Packets Sent</div>
          </div>
          <div class="stat-item">
            <div class="stat-value" id="home-pkts-down">0</div>
            <div class="stat-label">Packets Received</div>
          </div>
        </div>
      </div>
    `;
  }

  async function load() {
    try {
      const [status, traffic] = await Promise.all([
        invoke('get_status'),
        invoke('get_traffic_stats'),
      ]);
      update(status, traffic);
    } catch (e) {
      console.error('Home load error:', e);
    }
  }

  function update(status, traffic) {
    currentStatus = status;

    const ring = document.getElementById('home-status-ring');
    const label = document.getElementById('home-status-label');
    const sublabel = document.getElementById('home-status-sublabel');
    const btn = document.getElementById('home-toggle-btn');
    const relay = document.getElementById('home-relay');
    const zone = document.getElementById('home-zone');
    const duration = document.getElementById('home-duration');

    if (!ring) return; // Page not rendered yet

    // Reset ring classes
    ring.className = 'status-ring';

    const stateMap = {
      disconnected: { label: 'Disconnected', sub: 'Not connected to any relay', btnText: 'Connect', btnClass: 'btn btn-primary', ring: '' },
      connecting: { label: 'Connecting…', sub: `Reaching ${status.relay || '…'}`, btnText: 'Connecting…', btnClass: 'btn btn-secondary', ring: 'connecting' },
      connected: { label: 'Connected', sub: `Secured via ${status.relay}`, btnText: 'Disconnect', btnClass: 'btn btn-danger', ring: 'connected' },
      reconnecting: { label: 'Reconnecting…', sub: 'Attempting to restore connection', btnText: 'Disconnect', btnClass: 'btn btn-danger', ring: 'reconnecting' },
      disconnecting: { label: 'Disconnecting…', sub: 'Tearing down tunnel', btnText: 'Disconnecting…', btnClass: 'btn btn-secondary', ring: 'disconnecting' },
    };

    const s = stateMap[status.state] || stateMap.disconnected;
    if (s.ring) ring.classList.add(s.ring);
    label.textContent = s.label;
    sublabel.textContent = s.sub;
    btn.textContent = s.btnText;
    btn.className = s.btnClass;
    btn.disabled = status.state === 'connecting' || status.state === 'disconnecting';

    relay.textContent = status.relay || '—';
    zone.textContent = status.zone || '—';

    // Duration
    if (status.connected_since && status.state === 'connected') {
      const elapsed = Math.floor(Date.now() / 1000) - status.connected_since;
      duration.textContent = formatDuration(elapsed);
    } else {
      duration.textContent = '--:--:--';
    }

    // Traffic
    if (traffic) {
      document.getElementById('home-bytes-up').textContent = formatBytes(traffic.bytes_sent);
      document.getElementById('home-bytes-down').textContent = formatBytes(traffic.bytes_received);
      document.getElementById('home-pkts-up').textContent = traffic.packets_sent.toLocaleString();
      document.getElementById('home-pkts-down').textContent = traffic.packets_received.toLocaleString();
    }
  }

  async function toggle() {
    try {
      if (currentStatus && currentStatus.state === 'connected') {
        await invoke('disconnect');
      } else {
        // Get relay from config
        const config = await invoke('get_config');
        const relay = config.relay_address || 'relay.ztlp.net:4433';
        await invoke('connect', { relay, zone: 'default' });
      }
      // Immediately poll to update UI
      await pollState();
    } catch (e) {
      console.error('Toggle error:', e);
    }
  }

  return { render, load, update, toggle };
})();
