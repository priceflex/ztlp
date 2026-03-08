// ── MOBILE MENU ─────────────────────────────────────────
const menuToggle = document.getElementById('menuToggle');
const topbarNav  = document.querySelector('.topbar-nav');

menuToggle?.addEventListener('click', () => {
  topbarNav.classList.toggle('open');
});

// Close nav when a link is clicked on mobile
topbarNav?.querySelectorAll('a').forEach(link => {
  link.addEventListener('click', () => topbarNav.classList.remove('open'));
});

// ── ACTIVE TOC HIGHLIGHT ─────────────────────────────────
const tocLinks = document.querySelectorAll('.toc-link');
const sections = document.querySelectorAll('.spec-section[id]');

const tocObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      tocLinks.forEach(l => l.classList.remove('active'));
      const active = document.querySelector(`.toc-link[href="#${entry.target.id}"]`);
      active?.classList.add('active');
    }
  });
}, {
  root: null,
  rootMargin: '-80px 0px -60% 0px',
  threshold: 0
});

sections.forEach(s => tocObserver.observe(s));
