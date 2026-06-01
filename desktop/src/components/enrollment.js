// ── Enrollment Component — Token paste enrollment ───────────────────

// DIAGNOSTIC BUILD (PR #89, June 2026):
// Steve reported the Enroll button stayed disabled even with URI + attestation
// satisfied. AHK-driven repro on the Windows bench confirmed the bug is NOT in
// paste() (the previously-suspected programmatic-value-set issue) — typing the
// URI directly into the field + ticking the checkbox also leaves Enroll faded.
// This build instruments updateButtonState() so we can see what's happening
// without DevTools (writes to an on-page #enroll-debug strip + localStorage).
const ENROLL_BUILD_TAG = 'ENROLL-BUILD-3-DIAGNOSTIC';
console.log(ENROLL_BUILD_TAG);

// Visible debug surface — appended to the enrollment page so screenshots
// capture the gate's state without needing DevTools.
function _enrollDebug(msg) {
  try {
    const ts = new Date().toISOString().split('T')[1].replace('Z', '');
    const line = `${ts} ${msg}`;
    console.log('[enroll-debug]', line);
    // Persist last 20 lines in localStorage so we survive page reloads
    const prev = JSON.parse(localStorage.getItem('enroll_debug') || '[]');
    prev.push(line);
    while (prev.length > 20) prev.shift();
    localStorage.setItem('enroll_debug', JSON.stringify(prev));
    // Render to on-page strip if present
    const strip = document.getElementById('enroll-debug');
    if (strip) {
      strip.textContent = prev.slice(-6).join('\n');
    }
  } catch (e) {
    console.error('[enroll-debug] write failed', e);
  }
}

const EnrollmentComponent = (() => {
  const container = document.getElementById('page-enrollment');
  _enrollDebug(`component init tag=${ENROLL_BUILD_TAG} container=${!!container}`);

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
              oninput="EnrollmentComponent.updateButtonState()"
            >
            <button class="btn btn-secondary btn-sm" onclick="EnrollmentComponent.paste()" title="Paste from clipboard">
              📋 Paste
            </button>
          </div>
          <div class="form-hint">Get this URI from your zone administrator or the ZTLP gateway dashboard.</div>
        </div>

        <!-- D3.T4: Single-user attestation. Verbatim text per the plan; do
             not edit without revisiting the desktop-windows plan. The
             checkbox MUST be checked to enable the Enroll button. -->
        <div class="form-group" style="margin-top: 12px;">
          <label class="form-label" style="display: flex; align-items: flex-start; gap: 8px; cursor: pointer;">
            <input
              type="checkbox"
              id="enroll-attestation"
              style="margin-top: 3px; flex-shrink: 0;"
              onchange="EnrollmentComponent.updateButtonState()"
            >
            <span style="font-size: 13px; line-height: 1.4;">
              I attest I am the only user of this device.
            </span>
          </label>
        </div>

        <button class="btn btn-primary" id="enroll-btn" onclick="EnrollmentComponent.enroll()" disabled>
          🔑 Enroll
        </button>

        <div class="enrollment-status" id="enroll-status"></div>

        <!-- DIAGNOSTIC strip (PR #89): renders the gate's last-seen state so
             screenshots tell us what fired. Remove before merge to main. -->
        <pre id="enroll-debug" style="margin-top:12px; padding:8px; background:#f5f5f5; border:1px solid #ddd; font-size:11px; white-space:pre-wrap; color:#333; max-height:120px; overflow-y:auto;">build: ${ENROLL_BUILD_TAG} (waiting for first event)</pre>
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

    // DIAGNOSTIC: also wire listeners programmatically. If the inline
    // oninput/onchange attributes aren't firing (CSP, scope, whatever),
    // these addEventListener calls will. _enrollDebug() will tell us
    // which path actually invoked the gate.
    const uriInput = document.getElementById('enroll-uri');
    const checkbox = document.getElementById('enroll-attestation');
    const pasteBtn = container.querySelector('button.btn-secondary');
    if (uriInput) {
      uriInput.addEventListener('input', () => {
        _enrollDebug('addEventListener input fired');
        updateButtonState();
      });
    }
    if (checkbox) {
      checkbox.addEventListener('change', () => {
        _enrollDebug('addEventListener change fired');
        updateButtonState();
      });
    }
    if (pasteBtn) {
      pasteBtn.addEventListener('click', () => {
        _enrollDebug('addEventListener paste-click fired');
      });
    }
    _enrollDebug(`render done uri=${!!uriInput} cb=${!!checkbox} paste=${!!pasteBtn}`);
  }

  async function paste() {
    _enrollDebug('paste() entered');
    try {
      const text = await navigator.clipboard.readText();
      _enrollDebug(`paste() readText OK len=${text.length}`);
      const input = document.getElementById('enroll-uri');
      if (input) {
        input.value = text.trim();
        // Programmatic .value = ... does NOT fire 'input' / oninput, so the
        // gating button stays disabled until the user clicks into the field.
        // Re-run the gate directly (and dispatch an input event for any
        // future listeners that might attach to this field).
        input.dispatchEvent(new Event('input', { bubbles: true }));
        updateButtonState();
        _enrollDebug(`paste() input value set len=${input.value.length}`);
      } else {
        _enrollDebug('paste() input element NOT FOUND');
      }
    } catch (e) {
      _enrollDebug(`paste() readText THREW: ${e && e.message ? e.message : String(e)}`);
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
        // D3.T4: Record the attestation audit trail. The verbatim text is
        // captured server-side along with timestamp + resolved SID/UID.
        // Failure here is non-fatal — enrollment already succeeded; we
        // surface a warning so operators can manually re-record later.
        try {
          await invoke('record_attestation', {
            text: 'I attest I am the only user of this device.',
          });
        } catch (attestErr) {
          console.warn('attestation record failed (non-fatal):', attestErr);
        }
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
      // Re-evaluate gating: enroll button stays disabled until attestation
      // is re-confirmed for the next attempt.
      updateButtonState();
    }
  }

  // D3.T4: Enroll button is disabled until the single-user attestation
  // checkbox is checked AND a token URI is present. Idempotent — safe to
  // call any number of times.
  function updateButtonState() {
    const checkbox = document.getElementById('enroll-attestation');
    const input = document.getElementById('enroll-uri');
    const btn = document.getElementById('enroll-btn');
    if (!checkbox || !btn) {
      _enrollDebug(`gate ABORT checkbox=${!!checkbox} btn=${!!btn} input=${!!input}`);
      return;
    }
    const rawValue = input ? input.value : '(no input element)';
    const hasUri = input && input.value && input.value.trim().length > 0;
    const checked = checkbox.checked;
    const shouldDisable = !(checked && hasUri);
    btn.disabled = shouldDisable;
    _enrollDebug(`gate checked=${checked} hasUri=${hasUri} rawLen=${rawValue.length} disabled=${btn.disabled}`);
  }

  function showStatus(type, message) {
    const el = document.getElementById('enroll-status');
    if (!el) return;
    el.className = `enrollment-status ${type}`;
    el.textContent = message;
  }

  return { render, paste, enroll, updateButtonState };
})();
