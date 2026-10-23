// ZTLP Directory — the only JavaScript file (Slice 2b fills the pure contract).
// Hand-written ES2017, no framework, no npm, no CDN (decision 1).
//
// §2.3 contract (docs/admin-panel/BUILD_LOOP.md):
//   data-act="theme"            toggle html[data-theme] light/dark, persist localStorage "ztlp-theme"
//   data-act="nav-toggle"       mobile rail open/close (+ #nscrim)
//   data-drawer="<url>"         on click: fetch(url, {headers:{Accept:"text/html","X-Drawer":"1"}})
//                               → inject into #drawer, aria-hidden=false, trap focus, Esc/scrim closes
//   data-act="copy" data-copy=  navigator.clipboard.writeText + toast "Copied"
//   data-confirm="<text>"       on submit of a form: window.confirm (no custom modal in v1)
//   #gs-input                   debounce 150ms → fetch /search.json?q= → render #gresults
//   [data-toast]                server flashes rendered as <div data-toast> are shown then auto-hide 4s
//
// Pure functions live on window.ZtlpDirectory so test/javascript/directory_test.mjs
// can unit-test them with plain node:test (no jsdom). DOM wiring sits below the
// pure block and runs only when document/window look browser-shaped.

(function () {
  'use strict'

  // =========================================================================
  // Pure helpers — unit-tested in test/javascript/directory_test.mjs.
  // No DOM / fetch / network access inside any of these.
  // =========================================================================

  const THEME_KEY = 'ztlp-theme'

  // nextTheme(current) — pure: returns the next theme given the current one.
  // Unrecognized input (empty, nil, "bogus") maps to "dark" (the app default).
  function nextTheme(current) {
    return current === 'light' ? 'dark' : 'light'
  }

  // searchUrl(q) — pure: return /search.json?q=... with q URL-encoded, or
  // null when q is blank (so the caller can skip the fetch).
  function searchUrl(q) {
    if (q === null || q === undefined) return null
    const trimmed = String(q).trim()
    if (!trimmed) return null
    return '/search.json?q=' + encodeURIComponent(trimmed)
  }

  // rankSearch(rows, q, opts) — pure: filter rows by q (name first, then sub)
  // and sort by score descending. opts.maxResults defaults to 20.
  // Score: name exact = 3, name prefix = 2, name substring = 1, sub substring = 1.
  // (name and sub are the two fields the mock's gresults row shows.)
  function rankSearch(rows, q, opts) {
    const opts2 = opts || {}
    const maxResults = opts2.maxResults || 20
    const needle = String(q === null || q === undefined ? '' : q).toLowerCase().trim()
    if (!needle) return []
    const scored = []
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i]
      if (!row) continue
      const name = String(row.name || '').toLowerCase()
      const sub = String(row.sub || '').toLowerCase()
      let score = 0
      if (name === needle) score = 3
      else if (name.indexOf(needle) === 0) score = 2
      else if (name.indexOf(needle) !== -1) score = 1
      else if (sub.indexOf(needle) !== -1) score = 1
      if (score > 0) scored.push({ row: row, score: score })
    }
    scored.sort(function (a, b) { return b.score - a.score })
    return scored.slice(0, maxResults).map(function (x) {
      return {
        type: x.row.type,
        id: x.row.id,
        name: x.row.name,
        sub: x.row.sub,
        url: x.row.url,
        score: x.score,
      }
    })
  }

  // escapeHtml — pure: escape &, <, >, ", ' so server data never injects HTML
  // into the drawer fragment or search results.
  function escapeHtml(s) {
    return String(s === null || s === undefined ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
  }

  // safeUrl(u) — only same-origin absolute paths ("/x") may become links.
  // Rejects scheme URLs (javascript:, https:), protocol-relative "//host" and
  // the "/\\host" form browsers treat as protocol-relative.
  function safeUrl(u) {
    if (typeof u !== 'string' || u.length === 0) return null
    if (u.charAt(0) !== '/') return null
    const c = u.charAt(1)
    if (c === '/' || c === '\\') return null
    return u
  }

  // renderSearchResults(doc, box, rows) — builds the result list with
  // createElement + textContent only (§2.3: never innerHTML with server data).
  function renderSearchResults(doc, box, rows) {
    const out = []
    for (let i = 0; i < (rows || []).length; i++) {
      const r = rows[i]
      const url = safeUrl(r && r.url)
      if (!url) continue
      const a = doc.createElement('a')
      a.setAttribute('class', 'gs-row')
      a.setAttribute('href', url)
      a.setAttribute('role', 'option')
      a.setAttribute('data-url', url)
      a.setAttribute('data-type', String(r.type || ''))
      const parts = [['gs-type', r.type], ['gs-name', r.name], ['gs-sub', r.sub]]
      for (let j = 0; j < parts.length; j++) {
        const span = doc.createElement('span')
        span.setAttribute('class', parts[j][0])
        span.textContent = parts[j][1] == null ? '' : String(parts[j][1])
        a.appendChild(span)
      }
      out.push(a)
    }
    if (out.length === 0) {
      const empty = doc.createElement('div')
      empty.setAttribute('class', 'gs-empty')
      empty.textContent = 'no matches'
      out.push(empty)
    }
    box.replaceChildren.apply(box, out)
    return out.length
  }

  // copy(text) — pure contract: return the text it WOULD have written (or the
  // empty string). The DOM handler (below) is what actually calls
  // navigator.clipboard.writeText and toasts. This makes the behaviour
  // testable without a clipboard.
  function copy(text) {
    return String(text === null || text === undefined ? '' : text)
  }

  // shouldConfirm(text) — pure: predicate the submit handler uses to decide
  // whether to window.confirm() before the form goes.
  function shouldConfirm(text) {
    return !!(text && String(text).trim() !== '')
  }

  // Rule form (Slice 9b-4): which controls a subject type needs. Pure.
  function ruleSubjectView(type) {
    if (type === 'group' || type === 'user' || type === 'device') return { pick: true, role: false, list: type }
    if (type === 'role') return { pick: false, role: true, list: null }
    return { pick: false, role: false, list: null }
  }

  // Rule form: the <option>s for a type. lists = { user|device|group: [[label, id], ...] }. Pure.
  function ruleOptions(type, lists) {
    const view = ruleSubjectView(type)
    if (!view.list) return []
    const pairs = (lists && lists[view.list]) || []
    return [{ value: '', label: view.list + '\u2026' }].concat(pairs.map(function (p) {
      return { value: String(p[1]), label: String(p[0]) }
    }))
  }

  // renderTestAccessResult(doc, box, result) — Slice 9c sub-slice 3: the
  // test-access widget renders the decision badge, reason, per-rule trace
  // table and warnings with createElement + textContent only (§2.3: never
  // innerHTML with server data). result = the Ztlp::AccessEvaluator.result
  // shape: { decision, reason, trace: [{rule, result, why}], warnings: [] }.
  function renderTestAccessResult(doc, box, result) {
    const panel = doc.createElement('div')
    panel.setAttribute('class', 'panel')
    panel.setAttribute('data-testid', 'test-access-result')

    const head = doc.createElement('div')
    head.setAttribute('class', 'panel-h')
    const h = doc.createElement('h2')
    h.textContent = 'Access check'
    head.appendChild(h)
    const decision = result && result.decision ? String(result.decision) : ''
    const badge = doc.createElement('span')
    badge.setAttribute('class', 'badge ' + (decision === 'allow' ? 'ok' : 'bad'))
    badge.setAttribute('data-testid', 'test-access-decision')
    badge.textContent = decision
    head.appendChild(badge)
    panel.appendChild(head)

    const reason = doc.createElement('p')
    reason.setAttribute('class', 'sub')
    reason.setAttribute('data-testid', 'test-access-reason')
    reason.textContent = result && result.reason ? String(result.reason) : ''
    panel.appendChild(reason)

    const trace = (result && result.trace) || []
    if (trace.length > 0) {
      const wrap = doc.createElement('div')
      wrap.setAttribute('class', 'table-wrap')
      const table = doc.createElement('table')
      const thead = doc.createElement('thead')
      const hrow = doc.createElement('tr')
      ;['#', 'Rule', 'Result', 'Why'].forEach(function (label) {
        const th = doc.createElement('th')
        th.textContent = label
        hrow.appendChild(th)
      })
      thead.appendChild(hrow)
      table.appendChild(thead)
      const tbody = doc.createElement('tbody')
      for (let i = 0; i < trace.length; i++) {
        const row = trace[i] || {}
        const tr = doc.createElement('tr')
        tr.setAttribute('data-testid', 'trace-rule-' + i)
        ;[String(i), row.rule, row.result, row.why].forEach(function (cellText) {
          const td = doc.createElement('td')
          td.textContent = cellText == null ? '' : String(cellText)
          tr.appendChild(td)
        })
        tbody.appendChild(tr)
      }
      table.appendChild(tbody)
      wrap.appendChild(table)
      panel.appendChild(wrap)
    } else {
      const empty = doc.createElement('div')
      empty.setAttribute('class', 'empty-note')
      empty.textContent = 'No rules were evaluated.'
      panel.appendChild(empty)
    }

    const warnings = (result && result.warnings) || []
    if (warnings.length > 0) {
      const wpanel = doc.createElement('div')
      wpanel.setAttribute('class', 'panel')
      wpanel.setAttribute('data-testid', 'test-access-warnings')
      const wh = doc.createElement('div')
      const wh2 = doc.createElement('h3')
      wh2.textContent = 'Warnings'
      wh.appendChild(wh2)
      wpanel.appendChild(wh)
      for (let i = 0; i < warnings.length; i++) {
        const p = doc.createElement('p')
        p.setAttribute('class', 'sub')
        p.textContent = String(warnings[i])
        wpanel.appendChild(p)
      }
      panel.appendChild(wpanel)
    }

    const hint = doc.createElement('p')
    hint.setAttribute('class', 'hint')
    hint.textContent = 'min_assurance is not enforced by the gateway; this check is a panel-side simulation of the gateway decision.'
    panel.appendChild(hint)

    if (box.replaceChildren) box.replaceChildren(panel)
    else {
      while (box.firstChild) box.removeChild(box.firstChild)
      box.appendChild(panel)
    }
    return panel
  }

  // confirmTextFor(form, submitter) — pure: the confirm prompt for a submit, from data-confirm on
  // the submit button (wins) or on the form; null when neither carries non-blank text.
  function confirmTextFor(form, submitter) {
    for (const el of [submitter, form]) {
      const t = el && el.getAttribute ? el.getAttribute('data-confirm') : null
      if (shouldConfirm(t)) return t
    }
    return null
  }

  const api = {
    THEME_KEY: THEME_KEY,
    confirmTextFor: confirmTextFor,
    ruleSubjectView: ruleSubjectView,
    ruleOptions: ruleOptions,
    nextTheme: nextTheme,
    searchUrl: searchUrl,
    rankSearch: rankSearch,
    safeUrl: safeUrl,
    renderSearchResults: renderSearchResults,
    renderTestAccessResult: renderTestAccessResult,
    escapeHtml: escapeHtml,
    copy: copy,
    shouldConfirm: shouldConfirm,
    isAutoSubmitTarget: isAutoSubmitTarget,
  }

  // Expose for both the browser (data-act handlers below) and node:test.
  if (typeof window !== 'undefined') {
    window.ZtlpDirectory = api
  } else if (typeof globalThis !== 'undefined') {
    globalThis.window = globalThis.window || {}
    globalThis.window.ZtlpDirectory = api
  }

  // =========================================================================
  // DOM wiring — runs only in a real browser. Guarded so the pure tests
  // above (which fake a minimal document) never trip an exception.
  // =========================================================================
  if (typeof document === 'undefined' || typeof window === 'undefined') return
  if (!document.addEventListener) return

  // --- Theme ------------------------------------------------------------
  function applyTheme(theme) {
    const el = document.documentElement
    if (!el || !el.setAttribute) return
    if (theme === 'light' || theme === 'dark') el.setAttribute('data-theme', theme)
    else el.removeAttribute('data-theme')
  }

  function initTheme() {
    let current = 'dark'
    try {
      const saved = window.localStorage ? window.localStorage.getItem(THEME_KEY) : null
      if (saved === 'light' || saved === 'dark') current = saved
      else {
        const prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches
        current = prefersLight ? 'light' : 'dark'
      }
    } catch (_e) { current = 'dark' }
    applyTheme(current)
  }

  function onThemeClick() {
    const el = document.documentElement
    const current = el && el.getAttribute ? el.getAttribute('data-theme') : null
    const next = nextTheme(current)
    try { if (window.localStorage) window.localStorage.setItem(THEME_KEY, next) } catch (_e) {}
    applyTheme(next)
  }

  // --- Mobile rail ------------------------------------------------------
  function onNavToggle() {
    const app = document.getElementById('app')
    if (app && app.classList) app.classList.toggle('nav-open')
    const scrim = document.getElementById('nscrim')
    if (scrim && scrim.classList) scrim.classList.toggle('show')
  }

  function onNavClose() {
    const app = document.getElementById('app')
    if (app && app.classList) app.classList.remove('nav-open')
    const scrim = document.getElementById('nscrim')
    if (scrim && scrim.classList) scrim.classList.remove('show')
  }

  // --- Copy -------------------------------------------------------------
  function onCopyClick(el) {
    const text = el.getAttribute('data-copy') || ''
    const text2 = copy(text)
    if (!text2) return
    const nav = window.navigator
    const cb = nav && nav.clipboard && nav.clipboard.writeText
    if (typeof cb === 'function') {
      cb.call(nav.clipboard, text2).then(function () {
        toast('Copied')
      }, function () {
        toast('Copy failed')
      })
    } else {
      toast('Copy failed')
    }
  }

  // --- Confirm-on-submit ------------------------------------------------
  function onFormSubmit(ev) {
    const form = ev.target
    if (!form || !form.getAttribute) return
    const text = confirmTextFor(form, ev.submitter)
    if (text) {
      const ok = window.confirm(text)
      if (!ok) ev.preventDefault()
    }
  }

  // --- Toast ------------------------------------------------------------
  function toast(message) {
    const root = document.getElementById('toasts')
    if (!root) return
    const el = document.createElement('div')
    el.className = 'toast'
    el.setAttribute('data-toast', '')
    el.textContent = String(message)
    root.appendChild(el)
    setTimeout(function () {
      if (el.parentNode) el.parentNode.removeChild(el)
    }, 4000)
  }

  // Auto-hide server-rendered flashes (layout renders <div data-toast> for
  // notice/alert). They already exist in the DOM; this just times them out.
  function autoHideFlashes() {
    const flashes = document.querySelectorAll('[data-toast]')
    for (let i = 0; i < flashes.length; i++) {
      const el = flashes[i]
      setTimeout(function () {
        if (el && el.parentNode) el.parentNode.removeChild(el)
      }, 4000)
    }
  }

  // --- Drawer -----------------------------------------------------------
  function openDrawer(url) {
    const drawer = document.getElementById('drawer')
    const scrim = document.getElementById('dscrim')
    if (!drawer) return
    fetch(url, { headers: { Accept: 'text/html', 'X-Drawer': '1' } })
      .then(function (r) {
        if (!r.ok) throw new Error('drawer fetch ' + r.status)
        return r.text()
      })
      .then(function (html) {
        drawer.innerHTML = html
        drawer.setAttribute('aria-hidden', 'false')
        if (scrim && scrim.classList) scrim.classList.add('show')
        // Focus the first focusable inside the drawer (basic trap).
        const first = drawer.querySelector('a,button,input,select,textarea,[tabindex]')
        if (first && first.focus) first.focus()
      })
      .catch(function (err) {
        drawer.innerHTML = '<div class="wrap"><div class="panel"><h3>Could not load details</h3>' +
          '<p>' + escapeHtml(err && err.message ? err.message : String(err)) + '</p></div></div>'
        drawer.setAttribute('aria-hidden', 'false')
        if (scrim && scrim.classList) scrim.classList.add('show')
      })
  }

  function closeDrawer() {
    const drawer = document.getElementById('drawer')
    const scrim = document.getElementById('dscrim')
    if (drawer) drawer.setAttribute('aria-hidden', 'true')
    if (scrim && scrim.classList) scrim.classList.remove('show')
  }

  function onDrawerClick(el) {
    const url = el.getAttribute('data-drawer')
    if (url) openDrawer(url)
  }

  function onKeydown(ev) {
    if (ev.key === 'Escape') {
      const drawer = document.getElementById('drawer')
      if (drawer && drawer.getAttribute('aria-hidden') === 'false') closeDrawer()
      const app = document.getElementById('app')
      if (app && app.classList && app.classList.contains('nav-open')) onNavClose()
    }
  }

  // --- Global search ----------------------------------------------------
  let gsTimer = null
  function onSearchInput(ev) {
    const input = ev.target
    const q = input ? (input.value || '') : ''
    const box = document.getElementById('gresults')
    if (!box) return
    if (gsTimer) { clearTimeout(gsTimer); gsTimer = null }
    const url = searchUrl(q)
    if (!url) {
      box.replaceChildren()
      box.removeAttribute('role')
      return
    }
    gsTimer = setTimeout(function () {
      fetch(url, { headers: { Accept: 'application/json' } })
        .then(function (r) { if (!r.ok) throw new Error('search ' + r.status); return r.json() })
        .then(function (rows) {
          const ranked = rankSearch(rows || [], q)
          renderSearchResults(document, box, ranked)
          if (box.querySelector('a[data-url]')) box.setAttribute('role', 'listbox')
          else box.removeAttribute('role')
        })
        .catch(function () {
          const msg = document.createElement('div')
          msg.setAttribute('class', 'gs-empty')
          msg.textContent = 'search unavailable'
          box.replaceChildren(msg)
        })
    }, 150)
  }

  function onSearchKeydown(ev) {
    const box = document.getElementById('gresults')
    if (!box) return
    const rows = Array.prototype.slice.call(box.querySelectorAll('a[data-url]'))
    if (rows.length === 0) return
    let idx = rows.findIndex(function (r) { return r.classList.contains('gs-active') })
    if (ev.key === 'ArrowDown') {
      ev.preventDefault()
      idx = (idx + 1) % rows.length
    } else if (ev.key === 'ArrowUp') {
      ev.preventDefault()
      idx = (idx - 1 + rows.length) % rows.length
    } else if (ev.key === 'Enter') {
      const active = idx >= 0 ? rows[idx] : rows[0]
      if (active) { ev.preventDefault(); window.location.assign(active.getAttribute('data-url')) }
      return
    } else return
    rows.forEach(function (r) { r.classList.remove('gs-active') })
    rows[idx].classList.add('gs-active')
    rows[idx].setAttribute('aria-selected', 'true')
  }

  // --- Rule form type swap (delegated: works in the drawer too) ----------
  function parseList(el, attr) {
    try { return JSON.parse(el.getAttribute(attr) || '[]') } catch (e) { return [] }
  }

  function onRuleTypeChange(sel) {
    const form = sel.form
    if (!form) return
    const pick = form.querySelector('[data-rule-pick]')
    const pickSlot = form.querySelector('[data-rule-pick-slot]')
    const roleSlot = form.querySelector('[data-rule-role-slot]')
    if (!pick || !pickSlot || !roleSlot) return
    const view = ruleSubjectView(sel.value)
    pickSlot.hidden = !view.pick
    roleSlot.hidden = !view.role
    pick.disabled = !view.pick
    const lists = {
      user: parseList(pick, 'data-user-options'),
      device: parseList(pick, 'data-device-options'),
      group: parseList(pick, 'data-group-options'),
    }
    while (pick.firstChild) pick.removeChild(pick.firstChild)
    ruleOptions(sel.value, lists).forEach(function (o) {
      const opt = document.createElement('option')
      opt.value = o.value
      opt.textContent = o.label
      pick.appendChild(opt)
    })
  }

  // --- Test access (Slice 9c sub-slice 3) ------------------------------
  // Progressive enhancement: the form also works as a plain HTML POST (the
  // server re-renders the page with the result). When JS is available we
  // intercept submit, POST JSON with the CSRF token from the meta tag, and
  // render the response into a box under the form without a full page reload.
  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]')
    return meta && meta.getAttribute ? meta.getAttribute('content') : ''
  }

  function onTestAccessSubmit(ev) {
    const form = ev.target
    if (!form || !form.getAttribute) return
    const deviceSel = form.querySelector('[data-testid="test-access-device"]')
    const appSel = form.querySelector('[data-testid="test-access-application"]')
    if (!deviceSel || !appSel || !deviceSel.value || !appSel.value) return
    const token = csrfToken()
    if (!token) return // no meta tag — let the plain form POST go through
    ev.preventDefault()
    const box = document.getElementById('test-access-results')
    if (!box) return
    const btn = form.querySelector('button[type="submit"]')
    if (btn) btn.disabled = true
    fetch('/policies/test', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'X-CSRF-Token': token,
      },
      body: JSON.stringify({
        device_id: deviceSel.value,
        application_id: appSel.value,
      }),
    })
      .then(function (r) {
        if (!r.ok) throw new Error('test access ' + r.status)
        return r.json()
      })
      .then(function (result) {
        renderTestAccessResult(document, box, result)
      })
      .catch(function () {
        // Honest failure state: the plain form still works (drop JS, resubmit).
        const note = document.createElement('div')
        note.setAttribute('class', 'empty-note')
        note.textContent = 'The check could not run in the background; the form still works without JavaScript.'
        box.replaceChildren(note)
      })
      .finally(function () {
        if (btn) btn.disabled = false
      })
  }

  // A control with data-auto-submit re-submits its own form when it changes
  // (e.g. the audit-log action filter). Replaces an inline onchange handler,
  // which the CSP (script-src 'self', no nonce) blocks in a real browser.
  function isAutoSubmitTarget(el) {
    return !!(el && el.hasAttribute && el.hasAttribute('data-auto-submit'))
  }

  // --- Wire it all up ---------------------------------------------------
  function wire() {
    initTheme()

    document.addEventListener('click', function (ev) {
      const el = ev.target && ev.target.closest ? ev.target.closest('[data-act],[data-drawer]') : null
      if (!el) return
      const act = el.getAttribute('data-act')
      if (act === 'theme') onThemeClick()
      else if (act === 'nav-toggle') onNavToggle()
      else if (act === 'close-nav') onNavClose()
      else if (act === 'close-drawer') closeDrawer()
      else if (act === 'copy') onCopyClick(el)
      if (el.hasAttribute('data-drawer')) onDrawerClick(el)
    })

    document.addEventListener('submit', function (ev) {
      if (ev.target && ev.target.getAttribute) onFormSubmit(ev) // form OR submitter data-confirm
      if (ev.target && ev.target.hasAttribute && ev.target.hasAttribute('data-testid') && ev.target.getAttribute('data-testid') === 'test-access-form') onTestAccessSubmit(ev)
    })

    document.addEventListener('change', function (ev) {
      const t = ev.target
      if (t && t.hasAttribute && t.hasAttribute('data-rule-type')) onRuleTypeChange(t)
      if (isAutoSubmitTarget(t) && t.form && typeof t.form.requestSubmit === 'function') t.form.requestSubmit()
    })

    document.addEventListener('keydown', onKeydown)

    const gs = document.getElementById('gs-input')
    if (gs) {
      gs.addEventListener('input', onSearchInput)
      gs.addEventListener('keydown', onSearchKeydown)
    }

    autoHideFlashes()
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', wire)
  } else {
    wire()
  }
})()
