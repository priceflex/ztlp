// home-readiness.js — pure state-derivation module (Task C2).
//
// 1:1 port of macOS's `HomeReadiness.compute` (ZTLP/ViewModels/TunnelViewModel.swift).
// Pure so it can be verified without a live daemon or Tauri runtime — see
// scripts/test_home_readiness.js for the ported XCTest suite.
//
// Inputs:
//   serviceState: 'running' | 'requires_approval' | 'not_installed'
//                 | 'not_found' | 'failed:<msg>'
//   daemonReachable: bool — whether the control socket answered.
//   daemon: {
//     identityEnrolled, zone,
//     caInitialized, caInstalled, dnsConfigured,
//   } | null

function computeReadiness({ serviceState, daemonReachable, daemon }) {
  // Row 1 — Service (service install/registration + daemon answering).
  const service = (() => {
    if (serviceState === 'running') {
      return {
        title: 'Service',
        state: daemonReachable
          ? { kind: 'ready', detail: 'Running' }
          : { kind: 'waiting', detail: 'Starting…' },
      };
    }
    if (serviceState === 'requires_approval') {
      return {
        title: 'Service',
        state: { kind: 'needsAction', detail: 'Needs your approval in System Settings', action: 'openLoginItems' },
      };
    }
    if (serviceState === 'not_installed') {
      return {
        title: 'Service',
        state: { kind: 'needsAction', detail: 'Not installed', action: 'installService' },
      };
    }
    if (serviceState === 'not_found') {
      return {
        title: 'Service',
        state: { kind: 'failed', detail: 'Service missing from this app bundle — reinstall ZTLP' },
      };
    }
    if (typeof serviceState === 'string' && serviceState.startsWith('failed:')) {
      return {
        title: 'Service',
        state: { kind: 'failed', detail: serviceState.slice('failed:'.length) },
      };
    }
    // Unknown state — treat like not_installed rather than throwing, so a
    // future serviceState value degrades safely instead of crashing Home.
    return {
      title: 'Service',
      state: { kind: 'needsAction', detail: 'Not installed', action: 'installService' },
    };
  })();

  // Row 2 — Identity (the root daemon's enrollment; that is what DNS/TLS use).
  const identity = (() => {
    if (service.state.kind !== 'ready') {
      return { title: 'Identity', state: { kind: 'waiting', detail: 'Waiting for service' } };
    }
    if (daemon && daemon.identityEnrolled) {
      const zone = daemon.zone || '';
      return {
        title: 'Identity',
        state: { kind: 'ready', detail: zone ? `Enrolled in ${zone}` : 'Enrolled' },
      };
    }
    return { title: 'Identity', state: { kind: 'needsAction', detail: 'Not enrolled', action: 'enroll' } };
  })();

  // Row 3 — Network ready (HTTPS trusted + DNS routed, from the daemon).
  const network = (() => {
    if (identity.state.kind !== 'ready') {
      return {
        title: 'Network ready',
        state: { kind: 'waiting', detail: service.state.kind === 'ready' ? 'Waiting for enrollment' : 'Waiting for service' },
      };
    }
    if (daemon) {
      if (daemon.caInstalled && daemon.dnsConfigured) {
        return { title: 'Network ready', state: { kind: 'ready', detail: 'HTTPS trusted · DNS routed' } };
      }
      if (daemon.caInitialized && !daemon.caInstalled) {
        // The daemon made the CA; only the human trust step remains.
        const detail = daemon.dnsConfigured
          ? 'HTTPS not trusted yet'
          : 'HTTPS not trusted yet · DNS routing pending';
        return { title: 'Network ready', state: { kind: 'needsAction', detail, action: 'trustHTTPS' } };
      }
      const missing = [];
      if (!daemon.caInitialized) missing.push('HTTPS certificate');
      if (!daemon.dnsConfigured) missing.push('DNS routing');
      return { title: 'Network ready', state: { kind: 'waiting', detail: `Setting up ${missing.join(' and ')}…` } };
    }
    return { title: 'Network ready', state: { kind: 'waiting', detail: 'Waiting for service' } };
  })();

  const rows = [service, identity, network];
  const allReady = rows.every((r) => r.state.kind === 'ready');

  function guidance(zone) {
    if (allReady) {
      const z = zone || '<zone>';
      return `Open any https://<name>.${z} site in your browser. ZTLP connects on demand — there is nothing to switch on.`;
    }
    if (service.state.kind !== 'ready') return 'Step 1: install the ZTLP background service.';
    if (identity.state.kind !== 'ready') return 'Step 2: enroll this device with the enrollment link from your administrator.';
    if (network.state.kind === 'needsAction' && network.state.action === 'trustHTTPS') {
      return "Step 3: press Trust HTTPS once so your browser trusts this device's ZTLP certificates for every .ztlp site. No password needed.";
    }
    return 'Almost there — the service is finishing HTTPS and DNS setup.';
  }

  return { service, identity, network, rows, allReady, guidance };
}

// Dual-environment export: Node (CommonJS, used by the test harness) has no
// `window`; the Tauri webview (plain <script src>, no bundler) has no
// CommonJS `module` global. Referencing either identifier when it doesn't
// exist throws a ReferenceError that aborts the whole script — so each
// branch must be guarded, not just the window one (a bug that shipped here
// once already: an unconditional `module.exports = ...` at top level threw
// in the webview and left `window.HomeReadiness` never assigned).
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { computeReadiness };
}
if (typeof window !== 'undefined') {
  window.HomeReadiness = { computeReadiness };
}
