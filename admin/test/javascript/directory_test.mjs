// Slice 2b — pure-function unit tests for app/assets/javascripts/directory.js.
// Plain node:test + a ~30-line fake document (no jsdom, per §2.3 contract).
// Run via: node --test test/javascript/   (node v22 auto-discovers *_test.mjs)
//
// The module exposes its pure functions on window.ZtlpDirectory so they can be
// imported here without a browser. Anything that needs a real network / DOM is
// NOT exercised — only the pure helpers get unit-tested.

import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const jsPath = join(here, '../../app/assets/javascripts/directory.js')
const src = readFileSync(jsPath, 'utf8')

// ---------------------------------------------------------------------------
// Fake document / localStorage — just enough for directory.js to load and to
// exercise its pure helpers. We never attach real DOM events; we only need the
// module to evaluate its top-level IIFE and expose window.ZtlpDirectory.
// ---------------------------------------------------------------------------
function makeLocalStorage() {
  const store = new Map()
  return {
    getItem: k => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => { store.set(k, String(v)) },
    removeItem: k => { store.delete(k) },
    clear: () => { store.clear() },
  }
}

function makeDocument() {
  const elements = {}
  const byId = (id) => elements[id] || null
  const document = {
    querySelector: (sel) => {
      // Support only the two selectors directory.js uses: '[data-act=...]'
      // returns the same fake element for every such selector (we don't
      // attach events in this unit test — we only need the module to load).
      if (sel && sel.startsWith('[data-act=')) {
        return {
          addEventListener() {},
          classList: { toggle() {}, add() {}, remove() {}, contains: () => false },
        }
      }
      return null
    },
    querySelectorAll: () => [],
    getElementById: byId,
    createElement: (tag) => ({
      tagName: String(tag).toUpperCase(),
      style: {},
      classList: { toggle() {}, add() {}, remove() {}, contains: () => false },
      appendChild() {},
      setAttribute() {},
      textContent: '',
      role: '',
    }),
  }
  return document
}

function loadModule() {
  // Reset globals so each test gets a fresh module state.
  globalThis.window = { ZtlpDirectory: undefined }
  globalThis.document = makeDocument()
  globalThis.localStorage = makeLocalStorage()
  globalThis.fetch = () => { throw new Error('fetch should not be called in pure-helper tests') }
  // NOTE: Node 22 already defines a getter-only globalThis.navigator, so we
  // do NOT override it here. The copy() pure helper guards for the clipboard
  // presence on its own and returns the text on unsupported environments.
  // Eval the module in this context (it is a classic IIFE, no import/export).
  // eslint-disable-next-line no-new-func
  const fn = new Function(`${src}\n;return globalThis.window.ZtlpDirectory;`)
  return fn()
}

const Z = loadModule()

// ---------------------------------------------------------------------------
// Sanity: the module exposes the contract.
// ---------------------------------------------------------------------------
test('window.ZtlpDirectory is an object', () => {
  assert.ok(Z, 'window.ZtlpDirectory should be defined')
  assert.equal(typeof Z, 'object')
})

// ---------------------------------------------------------------------------
// theme
// ---------------------------------------------------------------------------
test('nextTheme: light -> dark', () => {
  assert.equal(Z.nextTheme('light'), 'dark')
})
test('nextTheme: dark -> light', () => {
  assert.equal(Z.nextTheme('dark'), 'light')
})
test('nextTheme: unrecognized -> light (anything that is not "light" toggles to light)', () => {
  // The contract: the app default is "dark"; if the current theme is
  // "light", the next is "dark". If the current theme is anything else
  // (unrecognized, empty, nil), the next is "light" (toggle to the
  // non-current value, which defaults to "light").
  assert.equal(Z.nextTheme('bogus'), 'light')
  assert.equal(Z.nextTheme(''), 'light')
  assert.equal(Z.nextTheme(undefined), 'light')
})

// ---------------------------------------------------------------------------
// search (query string, pure — no fetch)
// ---------------------------------------------------------------------------
test('searchUrl: empty q returns null', () => {
  assert.equal(Z.searchUrl(''), null)
  assert.equal(Z.searchUrl('   '), null)
  assert.equal(Z.searchUrl(null), null)
})
test('searchUrl: builds /search.json?q=... with encoded q', () => {
  assert.equal(Z.searchUrl('a b'), '/search.json?q=a%20b')
  assert.equal(Z.searchUrl('<script>'), '/search.json?q=%3Cscript%3E')
  // NOTE: encodeURIComponent does NOT encode the apostrophe (it is in the
  // unreserved set). Pin the honest output, not an over-specified one.
  assert.equal(Z.searchUrl("o'brien"), "/search.json?q=o'brien")
  // But the double-quote IS encoded (it is not unreserved).
  assert.equal(Z.searchUrl('a"b'), '/search.json?q=a%22b')
})

test('rankSearch: exact name match scores 3 (case-insensitive)', () => {
  const rows = [{ type: 'user', id: 1, name: 'steve', sub: 'steve.users.trs.ztlp', url: '/users/1' }]
  const out = Z.rankSearch(rows, 'steve')
  assert.equal(out.length, 1)
  assert.equal(out[0].score, 3)
  // Also case-insensitive:
  const out2 = Z.rankSearch(rows, 'STEVE')
  assert.equal(out2[0].score, 3)
})
test('rankSearch: matches on sub (ns name) score 1', () => {
  const rows = [{ type: 'user', id: 1, name: 'Steve', sub: 'steve.users.trs.ztlp', url: '/users/1' }]
  const out = Z.rankSearch(rows, 'trs.ztlp')
  assert.equal(out.length, 1)
  assert.equal(out[0].score, 1)
})
test('rankSearch: non-matching row is dropped', () => {
  const rows = [{ type: 'user', id: 1, name: 'alice', sub: 'alice.users.trs.ztlp', url: '/users/1' }]
  assert.deepEqual(Z.rankSearch(rows, 'zulu'), [])
})
test('rankSearch: maxResults caps output', () => {
  const rows = [1, 2, 3, 4, 5].map(i => ({ type: 'user', id: i, name: `user${i}`, sub: '', url: '' }))
  const out = Z.rankSearch(rows, 'user', { maxResults: 3 })
  assert.equal(out.length, 3)
})
test('rankSearch: higher score sorts first', () => {
  // Scoring (from the impl): name exact = 3, name prefix = 2,
  // name substring (non-prefix) / sub substring = 1.
  const rows = [
    { type: 'user', id: 1, name: 'zzz', sub: 'match.sub', url: '' },      // sub substring -> 1
    { type: 'user', id: 2, name: 'match', sub: '', url: '' },             // name exact -> 3
    { type: 'user', id: 3, name: 'matching', sub: '', url: '' },          // name prefix -> 2
  ]
  const out = Z.rankSearch(rows, 'match')
  // Expected: 2 (exact, 3) > 3 (prefix, 2) > 1 (sub, 1).
  assert.deepEqual(out.map(r => r.id), [2, 3, 1])
  assert.deepEqual(out.map(r => r.score), [3, 2, 1])
})

// Search results are built with createElement + textContent (§2.3: no innerHTML
// with server data), and only same-origin paths become links.
function fakeEl(tag) {
  return {
    tagName: tag.toUpperCase(), attrs: {}, children: [], textContent: '',
    setAttribute(k, v) { this.attrs[k] = String(v) },
    appendChild(c) { this.children.push(c); return c },
    replaceChildren(...c) { this.children = c },
  }
}
const fakeDoc = { createElement: fakeEl }

test('safeUrl: only same-origin absolute paths pass', () => {
  assert.equal(Z.safeUrl('/users/1'), '/users/1')
  assert.equal(Z.safeUrl('javascript:alert(1)'), null)
  assert.equal(Z.safeUrl('JaVaScRiPt:alert(1)'), null)
  assert.equal(Z.safeUrl('//evil.example/x'), null)
  assert.equal(Z.safeUrl('/\\evil.example'), null)
  assert.equal(Z.safeUrl('https://evil.example/'), null)
  assert.equal(Z.safeUrl(''), null)
  assert.equal(Z.safeUrl(undefined), null)
})
test('renderSearchResults: names are text, never markup', () => {
  const box = fakeEl('div')
  Z.renderSearchResults(fakeDoc, box, [
    { type: 'user', id: 1, name: '<img src=x onerror=alert(1)>', sub: 'a&b', url: '/users/1' },
  ])
  assert.equal(box.children.length, 1)
  const a = box.children[0]
  assert.equal(a.tagName, 'A')
  assert.equal(a.attrs.role, 'option')
  assert.equal(a.attrs.href, '/users/1')
  assert.equal(a.attrs['data-url'], '/users/1')
  assert.deepEqual(a.children.map(c => c.textContent), ['user', '<img src=x onerror=alert(1)>', 'a&b'])
})
test('renderSearchResults: rows with an unsafe url are dropped', () => {
  const box = fakeEl('div')
  Z.renderSearchResults(fakeDoc, box, [
    { type: 'user', id: 1, name: 'bad', sub: '', url: 'javascript:alert(1)' },
    { type: 'user', id: 2, name: 'ok', sub: '', url: '/users/2' },
  ])
  assert.equal(box.children.length, 1)
  assert.equal(box.children[0].attrs.href, '/users/2')
})
test('renderSearchResults: empty list renders an honest "no matches" line', () => {
  const box = fakeEl('div')
  Z.renderSearchResults(fakeDoc, box, [])
  assert.equal(box.children.length, 1)
  assert.equal(box.children[0].textContent, 'no matches')
})

// ---------------------------------------------------------------------------
// copy (pure: returns the value it would have written)
// ---------------------------------------------------------------------------
test('copy: returns the copied text', async () => {
  assert.equal(await Z.copy('hello'), 'hello')
})
test('copy: falls back to navigator.clipboard when text is empty', async () => {
  // copy() should never throw on empty/nil — it returns "" and no toast.
  assert.equal(await Z.copy(''), '')
})

// ---------------------------------------------------------------------------
// confirm (pure predicate helper — the click handler reads this before submit)
// ---------------------------------------------------------------------------
test('shouldConfirm: returns true for non-empty text', () => {
  assert.equal(Z.shouldConfirm('Are you sure?'), true)
})
test('shouldConfirm: returns false for empty/nil text', () => {
  assert.equal(Z.shouldConfirm(''), false)
  assert.equal(Z.shouldConfirm(null), false)
  assert.equal(Z.shouldConfirm(undefined), false)
})
