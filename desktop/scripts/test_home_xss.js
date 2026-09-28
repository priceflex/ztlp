// PR #112 review regression: a daemon/config-supplied zone must never be
// interpreted as markup on the Home readiness screen.
// Run with: node desktop/scripts/test_home_xss.js   (needs `npm i jsdom@24`)
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const src = path.join(__dirname, '..', 'src', 'components');
const dom = new JSDOM('<!doctype html><div id="page-home"></div>', { runScripts: 'outside-only' });
const w = dom.window;
w.LiveLog = { render() {}, fail() {} };
w.eval(fs.readFileSync(path.join(src, 'home-readiness.js'), 'utf8'));
w.eval(fs.readFileSync(path.join(src, 'home.js'), 'utf8') + '\nwindow.HomeComponent = HomeComponent;');

const evil = '<img src=x onerror="window.__pwned=1">evil.ztlp';
w.HomeComponent.render();
w.HomeComponent.applyStatus({
  daemon_running: true,
  identity_enrolled: true,
  ca_initialized: true,
  ca_installed_system_trust: false,
  dns_configured: true,
  zone: evil,
});

const rows = w.document.getElementById('home-readiness-rows');
assert.strictEqual(rows.querySelectorAll('img').length, 0, 'zone markup must not create elements');
assert.ok(rows.textContent.includes(evil), 'zone must render as literal text');
assert.strictEqual(w.__pwned, undefined);
assert.strictEqual(w.HomeComponent.escapeHtml('<a href="x">&\''), '&lt;a href=&quot;x&quot;&gt;&amp;&#39;');
console.log('ok - home readiness escapes daemon-supplied zone');
