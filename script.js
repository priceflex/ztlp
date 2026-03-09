// Copyright 2026 Steven Price / ZTLP.org
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
