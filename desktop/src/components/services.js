// ── Services Component — Service discovery browser ──────────────────

const ServicesComponent = (() => {
  const container = document.getElementById('page-services');

  function render() {
    container.innerHTML = `
      <h2 class="page-title">Services</h2>
      <div class="card">
        <div class="card-title">Discovered Services</div>
        <div id="services-table-wrap"></div>
      </div>
    `;
  }

  async function load() {
    try {
      const services = await invoke('get_services');
      renderTable(services);
    } catch (e) {
      console.error('Services load error:', e);
      renderEmpty();
    }
  }

  function renderTable(services) {
    const wrap = document.getElementById('services-table-wrap');
    if (!wrap) return;

    if (!services || services.length === 0) {
      renderEmpty();
      return;
    }

    wrap.innerHTML = `
      <table class="data-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Endpoint</th>
            <th>Status</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          ${services.map(svc => `
            <tr>
              <td>
                <strong>${escapeHtml(svc.name)}</strong>
                ${svc.description ? `<br><span style="color: var(--text-muted); font-size: 11px;">${escapeHtml(svc.description)}</span>` : ''}
              </td>
              <td><span class="badge badge-blue">${escapeHtml(svc.protocol_type)}</span></td>
              <td class="info-value">${escapeHtml(svc.hostname)}:${svc.port}</td>
              <td>
                ${svc.is_reachable
                  ? '<span class="badge badge-green">● Reachable</span>'
                  : '<span class="badge badge-red">● Unreachable</span>'
                }
              </td>
              <td>
                <button class="copy-btn" onclick="copyToClipboard('${escapeHtml(svc.hostname)}:${svc.port}', this)" title="Copy endpoint">📋</button>
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  }

  function renderEmpty() {
    const wrap = document.getElementById('services-table-wrap');
    if (!wrap) return;
    wrap.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">🔌</div>
        <p>No services discovered yet.</p>
        <p style="margin-top: 4px;">Connect to a relay to discover zone services.</p>
      </div>
    `;
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  return { render, load };
})();
