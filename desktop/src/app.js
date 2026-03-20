// ── ZTLP Desktop — Main App Controller ───────────────────────────────
//
// Manages page navigation, state polling, and coordinates all component
// modules. Uses the Tauri IPC bridge (`window.__TAURI__.core.invoke`).

const { invoke } = window.__TAURI__.core;

// ── Navigation ──────────────────────────────────────────────────────────

const navItems = document.querySelectorAll('.nav-item');
const pages = document.querySelectorAll('.page');

function navigateTo(pageName) {
  navItems.forEach(item => {
    item.classList.toggle('active', item.dataset.page === pageName);
  });
  pages.forEach(page => {
    page.classList.toggle('active', page.id === `page-${pageName}`);
  });
}

navItems.forEach(item => {
  item.addEventListener('click', () => navigateTo(item.dataset.page));
});

// ── Utility: copy to clipboard ──────────────────────────────────────────

async function copyToClipboard(text, btnEl) {
  try {
    await navigator.clipboard.writeText(text);
    if (btnEl) {
      btnEl.classList.add('copied');
      btnEl.textContent = '✓';
      setTimeout(() => {
        btnEl.classList.remove('copied');
        btnEl.textContent = '📋';
      }, 1500);
    }
  } catch {
    // Fallback
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  }
}

// ── Utility: format bytes ───────────────────────────────────────────────

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
}

// ── Utility: format duration ────────────────────────────────────────────

function formatDuration(seconds) {
  if (!seconds || seconds < 0) return '--:--:--';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  return [h, m, s].map(v => String(v).padStart(2, '0')).join(':');
}

// ── State polling ───────────────────────────────────────────────────────

let pollTimer = null;

async function pollState() {
  try {
    const [status, traffic] = await Promise.all([
      invoke('get_status'),
      invoke('get_traffic_stats'),
    ]);
    HomeComponent.update(status, traffic);
  } catch (e) {
    console.error('Poll error:', e);
  }
}

function startPolling() {
  if (pollTimer) return;
  pollTimer = setInterval(pollState, 2000);
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

// ── Init ────────────────────────────────────────────────────────────────

async function init() {
  // Render all components
  HomeComponent.render();
  ServicesComponent.render();
  IdentityComponent.render();
  EnrollmentComponent.render();
  SettingsComponent.render();

  // Load initial data
  await Promise.all([
    HomeComponent.load(),
    ServicesComponent.load(),
    IdentityComponent.load(),
    SettingsComponent.load(),
  ]);

  // Start polling connection status
  startPolling();
}

// Boot
init().catch(console.error);
