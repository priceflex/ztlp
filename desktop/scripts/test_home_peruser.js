// Windows per-user agent Home: four rows from `health_report`, only
// Enroll / Fix buttons, agent-supplied text never interpreted as markup.
// Run with: node desktop/scripts/test_home_peruser.js   (needs `npm i jsdom@24`)
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const src = path.join(__dirname, '..', 'src', 'components');
const dom = new JSDOM('<!doctype html><div id="page-home"></div><button class="nav-item" data-page="setup"></button>', {
  runScripts: 'outside-only',
});
const w = dom.window;
const logged = [];
w.LiveLog = {
  render() {},
  fail(m) { logged.push(['fail', m]); },
  success(m) { logged.push(['ok', m]); },
  log(l, m) { logged.push([l, m]); },
  setup(m) { logged.push(['setup', m]); },
};
w.ZTLP_ENV = { per_user_agent: true };
const evil = '<img src=x onerror="window.__pwned=1">';
const report = {
  per_user: true,
  all_ready: false,
  enrolled: true,
  zone: 'trs.ztlp',
  frozen: false,
  in_use_by_other: false,
  rows: [
    { key: 'agent', title: 'Agent', state: 'ready', detail: 'Running (v0.37.0)' },
    { key: 'identity', title: 'Identity', state: 'ready', detail: 'pc.trs.ztlp' },
    { key: 'dns', title: 'DNS', state: 'failed', detail: `no answer ${evil}`, action: 'repair' },
    { key: 'https', title: 'HTTPS', state: 'waiting', detail: 'Waiting for DNS' },
  ],
};
let invoked = [];
w.__TAURI__ = { core: { invoke: async (cmd) => { invoked.push(cmd); return report; } } };
w.eval('const { invoke } = window.__TAURI__.core;\n'
  + fs.readFileSync(path.join(src, 'home-readiness.js'), 'utf8') + '\n'
  + fs.readFileSync(path.join(src, 'home.js'), 'utf8') + '\nwindow.HomeComponent = HomeComponent;');

(async () => {
  w.HomeComponent.render();
  await w.HomeComponent.load();
  const rows = w.document.getElementById('home-readiness-rows');
  const ids = [...rows.querySelectorAll('.readiness-row')].map((r) => r.id);
  assert.deepStrictEqual(ids, ['home.row.agent', 'home.row.identity', 'home.row.dns', 'home.row.https']);
  assert.deepStrictEqual(invoked, ['health_report'], 'per-user Home must not call setup_status');
  const buttons = [...rows.querySelectorAll('button')];
  assert.strictEqual(buttons.length, 1, 'only the red DNS row gets a button');
  assert.strictEqual(buttons[0].textContent, 'Fix');
  assert.strictEqual(buttons[0].dataset.action, 'repair');
  assert.strictEqual(rows.querySelectorAll('img').length, 0, 'detail markup must not create elements');
  assert.ok(rows.textContent.includes(evil));
  assert.strictEqual(w.__pwned, undefined);
  assert.ok(!rows.textContent.toLowerCase().includes('service'), 'no service wording on Windows');
  assert.ok(logged.some(([l, m]) => l === 'fail' && m.startsWith('DNS:')), 'red row is logged');
  console.log('ok - per-user Home renders four checks, Fix only on red rows, escapes details');
})().catch((e) => { console.error(e); process.exit(1); });
