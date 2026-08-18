// ── Live Activity Log ─────────────────────────────────────────────────
//
// A single, global, scrolling activity feed. It is the primary "what is
// actually happening" surface — it replaces the removed Services/traffic
// panels. Every meaningful event is appended here in real time:
//
//   • app lifecycle     (launch, auto-connect decision)
//   • connection state  (disconnected → connecting → connected → …)
//   • setup operations  (enrollment, CA init, CA install, DNS, browser test)
//   • errors
//
// The log is intentionally backend-agnostic: it does NOT talk to the daemon
// itself. Callers push events in via `LiveLog.log(...)` / `LiveLog.stateChange`.
//
// NOTE ON "live" (honest seam): the desktop's daemon IPC (127.100.255.1:4433)
// is request/response today — there is no push/event-stream command. The
// connection state the app tracks is also only ever set to connected/disconnected
// by the app's own connect/disconnect, not streamed from the daemon. So the
// feed is synthesized from (a) connection-state transitions observed by the
// poller and (b) explicit setup-operation events. When the daemon exposes an
// event stream (or a `logs`/`events` control command), swap `poll` to consume
// it and the same feed will render real daemon events with no UI change.

const LiveLog = (() => {
  let el = null;            // the <div class="log"> (created in render)
  const MAX_LINES = 400;    // hard cap so the DOM can't grow unbounded
  let lastState = null;     // last connection state we logged, to detect transitions
  let booted = false;

  // Render the (empty) log panel once. Called by Home on mount. Safe to call
  // again if the element is missing.
  function render(targetId = 'home-log') {
    el = document.getElementById(targetId);
    if (!el) return;
    if (!booted) {
      booted = true;
      log('info', 'ZTLP desktop ready. Staying ready to connect.');
    }
  }

  function now() {
    const d = new Date();
    const p = (n) => String(n).padStart(2, '0');
    return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }

  // Append one line. `level` ∈ {info, ok, warn, error, sys}.
  function log(level, message) {
    if (!el) return;
    const line = document.createElement('div');
    line.className = `log-line log-${level}`;
    const ts = document.createElement('span');
    ts.className = 'log-ts';
    ts.textContent = now();
    const msg = document.createElement('span');
    msg.className = 'log-msg';
    msg.textContent = message;
    line.appendChild(ts);
    line.appendChild(msg);
    el.appendChild(line);

    // Trim old lines beyond the cap.
    while (el.childNodes.length > MAX_LINES) {
      el.removeChild(el.firstChild);
    }
    // Always scroll to the newest line.
    el.scrollTop = el.scrollHeight;
  }

  // Emit a transition line only when the connection state actually changed.
  // `state` is the raw ConnectionStatus object from get_status().
  function stateChange(status) {
    if (!status) return;
    const s = status.state;
    if (s === lastState) return; // no change → no noise
    const prev = lastState;
    lastState = s;

    switch (s) {
      case 'connected':
        log('ok', `Connected — ${status.zone || 'zone'} secured and ready.`);
        break;
      case 'connecting':
        log('info', 'Connecting… (handshaking over the tunnel).');
        break;
      case 'reconnecting':
        log('warn', 'Connection dropped — reconnecting.');
        break;
      case 'disconnecting':
        log('info', 'Disconnecting…');
        break;
      case 'disconnected':
        if (prev && prev !== 'disconnected') {
          log('info', 'Disconnected.');
        }
        break;
      case 'failed':
      case 'error':
        log('error', `Connection ${s}: ${status.error || 'unknown error'}.`);
        break;
      default:
        if (prev !== undefined) log('info', `State: ${s}`);
    }
  }

  // Convenience wrappers used by setup/setup-wizard operations.
  function setup(label) { log('info', label); }
  function success(label) { log('ok', `✓ ${label}`); }
  function fail(label) { log('error', `✗ ${label}`); }

  // Background service attach, reflected from the daemon's live tunnel/forward
  // list (get_attached). This is the "attaches to zone services using the
  // device identity" signal — shown so the user sees what's actually attached,
  // not a static assumption. Deduped so we only log on a real change, not on
  // every poll. `status` is { reachable, active, endpoints }.
  let lastAttachActive = null;
  function serviceAttach(status) {
    if (!status) return;
    if (!status.reachable) {
      if (lastAttachActive !== null) {
        lastAttachActive = null;
        log('warn', 'Service attach: agent not reachable.');
      }
      return;
    }
    if (status.active === lastAttachActive) return; // no change → no noise
    lastAttachActive = status.active;
    if (status.active > 0) {
      const shown = (status.endpoints || []).slice(0, 3).join(', ');
      const more = status.active > 3 ? `, +${status.active - 3} more` : '';
      log('ok', `Attached to ${status.active} zone service${status.active === 1 ? '' : 's'} via identity: ${shown}${more}.`);
    } else {
      log('info', 'Staying ready — no active service attachments yet.');
    }
  }

  function clear() {
    if (el) el.innerHTML = '';
    lastState = null;
  }

  function markConnected() { lastState = 'connected'; }
  function markDisconnected() { lastState = 'disconnected'; }

  return { render, log, stateChange, setup, success, fail, serviceAttach, clear, markConnected, markDisconnected };
})();
