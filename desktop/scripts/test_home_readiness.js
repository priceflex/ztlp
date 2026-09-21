// Port of macOS ZTLPTests.swift's HomeReadiness test suite (Task C2).
// Run with: node desktop/scripts/test_home_readiness.js
//
// Each test name mirrors the Swift original 1:1 (renamed "Mac" -> nothing
// OS-specific, since this module is shared across Windows/Linux/macOS-Tauri).

const assert = require('assert');
const { computeReadiness } = require('../src/components/home-readiness.js');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ok - ${name}`);
  } catch (e) {
    failed++;
    console.log(`  FAIL - ${name}`);
    console.log(`    ${e.message}`);
  }
}

// Mirror of the Swift `snap()` test helper.
function snap({ enrolled, ca, dns, zone = 'defcon.ztlp', caInit = null }) {
  return {
    identityEnrolled: enrolled,
    caInstalled: ca,
    // Default: CA is initialized whenever it is installed (legacy tests).
    caInitialized: caInit === null ? ca : caInit,
    caRootPemPath: '/Library/Application Support/ZTLP/.ztlp/ca/root.pem',
    dnsConfigured: dns,
    zone,
  };
}

test('freshInstallServiceNotInstalledGatesEverything', () => {
  const r = computeReadiness({ serviceState: 'not_installed', daemonReachable: false, daemon: null });
  assert.deepStrictEqual(r.service.state, { kind: 'needsAction', detail: 'Not installed', action: 'installService' });
  assert.deepStrictEqual(r.identity.state, { kind: 'waiting', detail: 'Waiting for service' });
  assert.deepStrictEqual(r.network.state, { kind: 'waiting', detail: 'Waiting for service' });
  assert.strictEqual(r.allReady, false);
  assert.ok(r.guidance('').startsWith('Step 1'));
});

test('requiresApprovalOffersLoginItems', () => {
  const r = computeReadiness({ serviceState: 'requires_approval', daemonReachable: false, daemon: null });
  assert.deepStrictEqual(r.service.state, { kind: 'needsAction', detail: 'Needs your approval in System Settings', action: 'openLoginItems' });
  assert.deepStrictEqual(r.identity.state, { kind: 'waiting', detail: 'Waiting for service' });
});

test('registeredButNotAnsweringIsWaitingNotEnroll', () => {
  // B4 user-facing half: the daemon is registered but has not answered
  // yet -> Identity must NOT offer Enroll (that was the old timeout path).
  const r = computeReadiness({ serviceState: 'running', daemonReachable: false, daemon: null });
  assert.deepStrictEqual(r.service.state, { kind: 'waiting', detail: 'Starting…' });
  assert.deepStrictEqual(r.identity.state, { kind: 'waiting', detail: 'Waiting for service' });
  assert.strictEqual(r.allReady, false);
});

test('standbyDaemonOffersEnroll', () => {
  const r = computeReadiness({
    serviceState: 'running', daemonReachable: true,
    daemon: snap({ enrolled: false, ca: false, dns: false, zone: '' }),
  });
  assert.deepStrictEqual(r.service.state, { kind: 'ready', detail: 'Running' });
  assert.deepStrictEqual(r.identity.state, { kind: 'needsAction', detail: 'Not enrolled', action: 'enroll' });
  assert.deepStrictEqual(r.network.state, { kind: 'waiting', detail: 'Waiting for enrollment' });
  assert.ok(r.guidance('').startsWith('Step 2'));
});

test('enrolledButTlsPendingIsWaiting', () => {
  const r = computeReadiness({
    serviceState: 'running', daemonReachable: true,
    daemon: snap({ enrolled: true, ca: false, dns: true }),
  });
  assert.deepStrictEqual(r.identity.state, { kind: 'ready', detail: 'Enrolled in defcon.ztlp' });
  assert.deepStrictEqual(r.network.state, { kind: 'waiting', detail: 'Setting up HTTPS certificate…' });
  assert.strictEqual(r.allReady, false);
  assert.ok(r.guidance('defcon.ztlp').startsWith('Almost there'));
});

// Option B (2026-09-20): the daemon makes the CA; the GUI does the ONE
// human trust step with the standard admin prompt.
test('caMadeButUntrustedOffersTrustHTTPS', () => {
  const r = computeReadiness({
    serviceState: 'running', daemonReachable: true,
    daemon: snap({ enrolled: true, ca: false, dns: true, caInit: true }),
  });
  assert.deepStrictEqual(r.network.state, { kind: 'needsAction', detail: 'HTTPS not trusted yet', action: 'trustHTTPS' });
  assert.ok(r.guidance('defcon.ztlp').startsWith('Step 3'), r.guidance('defcon.ztlp'));
  assert.strictEqual(r.allReady, false);
});

test('trustStepNotOfferedBeforeEnrollment', () => {
  // Never ask for a password before there is anything to trust for.
  const r = computeReadiness({
    serviceState: 'running', daemonReachable: true,
    daemon: snap({ enrolled: false, ca: false, dns: false, zone: '', caInit: true }),
  });
  assert.deepStrictEqual(r.identity.state, { kind: 'needsAction', detail: 'Not enrolled', action: 'enroll' });
  assert.deepStrictEqual(r.network.state, { kind: 'waiting', detail: 'Waiting for enrollment' });
});

test('allGreenGuidanceHasNoConnectVerb', () => {
  const r = computeReadiness({
    serviceState: 'running', daemonReachable: true,
    daemon: snap({ enrolled: true, ca: true, dns: true }),
  });
  assert.strictEqual(r.allReady, true);
  assert.deepStrictEqual(r.network.state, { kind: 'ready', detail: 'HTTPS trusted · DNS routed' });
  const g = r.guidance('defcon.ztlp');
  assert.ok(g.includes('https://<name>.defcon.ztlp'), g);
  assert.ok(g.includes('on demand'), g);
  // Steven: "There is no connection required until the user goes to a
  // website" — the UI must never ask the user to press Connect.
  assert.ok(!g.toLowerCase().includes('press connect'), g);
});

test('serviceFailedIsRed', () => {
  const r = computeReadiness({ serviceState: 'failed:boom', daemonReachable: false, daemon: null });
  assert.deepStrictEqual(r.service.state, { kind: 'failed', detail: 'boom' });
  const r2 = computeReadiness({ serviceState: 'not_found', daemonReachable: false, daemon: null });
  assert.strictEqual(r2.service.state.kind, 'failed');
  assert.ok(r2.service.state.detail.includes('reinstall'), r2.service.state.detail);
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
