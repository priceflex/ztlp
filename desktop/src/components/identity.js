// ── Identity Component — Node ID, keys, enrollment status ───────────

const IdentityComponent = (() => {
  const container = document.getElementById('page-identity');
  let expanded = {};

  function render() {
    container.innerHTML = `
      <h2 class="page-title">Identity</h2>
      <div id="identity-content">
        <div class="empty-state">
          <div class="empty-icon">🪪</div>
          <p>Loading identity…</p>
        </div>
      </div>
    `;
  }

  async function load() {
    try {
      const identity = await invoke('get_identity');
      renderIdentity(identity);
    } catch (e) {
      console.error('Identity load error:', e);
      renderNoIdentity();
    }
  }

  function renderIdentity(identity) {
    const content = document.getElementById('identity-content');
    if (!content) return;

    if (!identity) {
      renderNoIdentity();
      return;
    }

    const shortNodeId = truncateMiddle(identity.node_id, 8, 4);
    const shortPubKey = truncateMiddle(identity.public_key, 8, 4);

    content.innerHTML = `
      <div class="card">
        <div class="card-title">Node Identity</div>
        <div class="info-row">
          <span class="info-label">Node ID</span>
          <span class="info-value">
            <span id="identity-node-id" title="${escapeAttr(identity.node_id)}">${escapeHtml(shortNodeId)}</span>
            <button class="copy-btn" onclick="copyToClipboard('${escapeAttr(identity.node_id)}', this)" title="Copy Node ID">📋</button>
          </span>
        </div>
        <div class="info-row">
          <span class="info-label">Public Key</span>
          <span class="info-value">
            <span id="identity-pubkey" style="cursor: pointer;" onclick="IdentityComponent.toggleExpand('pubkey', '${escapeAttr(identity.public_key)}')" title="Click to expand">
              ${escapeHtml(shortPubKey)}
            </span>
            <button class="copy-btn" onclick="copyToClipboard('${escapeAttr(identity.public_key)}', this)" title="Copy Public Key">📋</button>
          </span>
        </div>
        <div class="info-row">
          <span class="info-label">Zone</span>
          <span class="info-value">${identity.zone_name ? escapeHtml(identity.zone_name) : '<span style="color: var(--text-muted)">Not enrolled</span>'}</span>
        </div>
        <div class="info-row">
          <span class="info-label">Enrollment</span>
          <span class="info-value">
            ${identity.enrolled
              ? '<span class="badge badge-green">✓ Enrolled</span>'
              : '<span class="badge badge-red">Not Enrolled</span>'
            }
          </span>
        </div>
        <div class="info-row">
          <span class="info-label">Key Provider</span>
          <span class="info-value">${escapeHtml(identity.provider_type)}</span>
        </div>
      </div>
    `;
  }

  function renderNoIdentity() {
    const content = document.getElementById('identity-content');
    if (!content) return;
    content.innerHTML = `
      <div class="card">
        <div class="empty-state">
          <div class="empty-icon">🪪</div>
          <p>No identity found.</p>
          <p style="margin-top: 4px;">Generate or import an identity to get started.</p>
        </div>
      </div>
    `;
  }

  function toggleExpand(field, fullValue) {
    const el = document.getElementById(`identity-${field}`);
    if (!el) return;
    expanded[field] = !expanded[field];
    if (expanded[field]) {
      el.textContent = fullValue;
      el.style.wordBreak = 'break-all';
      el.style.fontSize = '11px';
    } else {
      el.textContent = truncateMiddle(fullValue, 8, 4);
      el.style.wordBreak = '';
      el.style.fontSize = '';
    }
  }

  function truncateMiddle(str, prefixLen, suffixLen) {
    if (!str || str.length <= prefixLen + suffixLen + 3) return str || '';
    return str.slice(0, prefixLen) + '…' + str.slice(-suffixLen);
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function escapeAttr(str) {
    return str.replace(/'/g, "\\'").replace(/"/g, '&quot;');
  }

  return { render, load, toggleExpand };
})();
