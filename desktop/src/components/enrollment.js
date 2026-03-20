// ── Enrollment Component — Token paste enrollment ───────────────────

const EnrollmentComponent = (() => {
  const container = document.getElementById('page-enrollment');

  function render() {
    container.innerHTML = `
      <h2 class="page-title">Enrollment</h2>
      <div class="card">
        <div class="card-title">Enroll This Device</div>
        <p style="color: var(--text-secondary); margin-bottom: 16px; font-size: 13px;">
          Paste a <code>ztlp://enroll/...</code> URI from your administrator to join a zone.
          This will configure your relay and zone settings automatically.
        </p>

        <div class="form-group">
          <label class="form-label" for="enroll-uri">Enrollment URI</label>
          <div class="enrollment-input-row">
            <input
              type="text"
              id="enroll-uri"
              class="form-input"
              placeholder="ztlp://enroll/zone-name/token..."
              spellcheck="false"
              autocomplete="off"
            >
            <button class="btn btn-secondary btn-sm" onclick="EnrollmentComponent.paste()" title="Paste from clipboard">
              📋 Paste
            </button>
          </div>
          <div class="form-hint">Get this URI from your zone administrator or the ZTLP gateway dashboard.</div>
        </div>

        <button class="btn btn-primary" id="enroll-btn" onclick="EnrollmentComponent.enroll()">
          🔑 Enroll
        </button>

        <div class="enrollment-status" id="enroll-status"></div>
      </div>

      <div class="card">
        <div class="card-title">What Happens During Enrollment?</div>
        <div style="color: var(--text-secondary); font-size: 13px; line-height: 1.6;">
          <p><strong>1.</strong> Your device identity is registered with the zone's gateway.</p>
          <p><strong>2.</strong> Relay and zone configuration is downloaded automatically.</p>
          <p><strong>3.</strong> A Noise_XX handshake establishes mutual trust.</p>
          <p><strong>4.</strong> Your device can now discover and connect to zone services.</p>
        </div>
      </div>
    `;
  }

  async function paste() {
    try {
      const text = await navigator.clipboard.readText();
      const input = document.getElementById('enroll-uri');
      if (input) input.value = text;
    } catch {
      // Clipboard permission denied
      showStatus('error', 'Clipboard access denied. Please paste manually.');
    }
  }

  async function enroll() {
    const input = document.getElementById('enroll-uri');
    const btn = document.getElementById('enroll-btn');
    const uri = input ? input.value.trim() : '';

    if (!uri) {
      showStatus('error', 'Please enter an enrollment URI.');
      return;
    }

    if (!uri.startsWith('ztlp://enroll/')) {
      showStatus('error', 'Invalid URI — must start with ztlp://enroll/');
      return;
    }

    btn.disabled = true;
    btn.textContent = 'Enrolling…';

    try {
      const result = await invoke('enroll', { tokenUri: uri });
      if (result.success) {
        showStatus('success',
          `✓ ${result.message}` +
          (result.zone_name ? ` — Zone: ${result.zone_name}` : '') +
          (result.relay_address ? ` — Relay: ${result.relay_address}` : '')
        );
        // Refresh identity view
        if (typeof IdentityComponent !== 'undefined') {
          IdentityComponent.load();
        }
      } else {
        showStatus('error', result.message || 'Enrollment failed.');
      }
    } catch (e) {
      showStatus('error', `Error: ${e}`);
    } finally {
      btn.disabled = false;
      btn.textContent = '🔑 Enroll';
    }
  }

  function showStatus(type, message) {
    const el = document.getElementById('enroll-status');
    if (!el) return;
    el.className = `enrollment-status ${type}`;
    el.textContent = message;
  }

  return { render, paste, enroll };
})();
