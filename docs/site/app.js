/* Coraza docs · interactivity */
(function () {
  'use strict';

  // ---------------- THEME ----------------
  const body = document.body;
  const mql = window.matchMedia('(prefers-color-scheme: dark)');

  function applyTheme(theme) {
    body.setAttribute('data-theme', theme);
    localStorage.setItem('coraza-theme', theme);
  }
  const savedTheme = localStorage.getItem('coraza-theme') || TWEAK_DEFAULTS.theme || 'auto';
  applyTheme(savedTheme);

  document.getElementById('themeToggle').addEventListener('click', () => {
    const cur = body.getAttribute('data-theme');
    const next = cur === 'dark' ? 'light' : cur === 'light' ? 'auto' : 'dark';
    applyTheme(next);
    syncSegmented('theme', next);
  });

  // ---------------- DENSITY / FONT / ACCENT ----------------
  function applyDensity(v) { body.setAttribute('data-density', v); localStorage.setItem('coraza-density', v); }
  function applyFont(v) { body.setAttribute('data-font', v); localStorage.setItem('coraza-font', v); }
  function applyAccent(hex) {
    // convert hex -> hue; keep the palette coherent by mapping to accent-h
    const hue = hexToHue(hex);
    document.documentElement.style.setProperty('--accent-h', String(hue));
    localStorage.setItem('coraza-accent', hex);
  }
  applyDensity(localStorage.getItem('coraza-density') || TWEAK_DEFAULTS.density || 'comfy');
  applyFont(localStorage.getItem('coraza-font') || TWEAK_DEFAULTS.font || 'sans');
  applyAccent(localStorage.getItem('coraza-accent') || TWEAK_DEFAULTS.accent || '#14b8a6');

  function hexToHue(hex) {
    const h = hex.replace('#', '');
    const r = parseInt(h.substring(0, 2), 16) / 255;
    const g = parseInt(h.substring(2, 4), 16) / 255;
    const b = parseInt(h.substring(4, 6), 16) / 255;
    const max = Math.max(r, g, b), min = Math.min(r, g, b);
    let hue = 0;
    if (max === min) hue = 0;
    else if (max === r) hue = 60 * (((g - b) / (max - min)) % 6);
    else if (max === g) hue = 60 * ((b - r) / (max - min) + 2);
    else hue = 60 * ((r - g) / (max - min) + 4);
    if (hue < 0) hue += 360;
    return Math.round(hue);
  }

  // ---------------- CODE COPY BUTTONS ----------------
  document.querySelectorAll('pre.code').forEach((pre) => {
    const wrap = document.createElement('div');
    wrap.className = 'code-wrap';
    pre.parentNode.insertBefore(wrap, pre);
    wrap.appendChild(pre);

    const btn = document.createElement('button');
    btn.className = 'copy-btn';
    btn.type = 'button';
    btn.textContent = 'copy';
    btn.addEventListener('click', async () => {
      const txt = pre.innerText;
      try {
        await navigator.clipboard.writeText(txt);
        btn.textContent = 'copied';
        btn.classList.add('is-copied');
        setTimeout(() => { btn.textContent = 'copy'; btn.classList.remove('is-copied'); }, 1400);
      } catch {
        btn.textContent = 'error';
      }
    });
    wrap.appendChild(btn);
  });

  // ---------------- TABS (synced by group) ----------------
  const tabGroups = {};
  document.querySelectorAll('.tabs').forEach((tabsEl) => {
    const group = tabsEl.dataset.tabgroup;
    if (!tabGroups[group]) tabGroups[group] = [];
    tabGroups[group].push(tabsEl);

    tabsEl.querySelectorAll('.tab').forEach((tab) => {
      tab.addEventListener('click', () => {
        const val = tab.dataset.tab;
        selectTab(group, val);
        localStorage.setItem('coraza-tab-' + group, val);
      });
    });
  });

  function selectTab(group, val) {
    (tabGroups[group] || []).forEach((tabsEl) => {
      let found = false;
      tabsEl.querySelectorAll('.tab').forEach((t) => {
        const on = t.dataset.tab === val;
        if (on) found = true;
        t.setAttribute('aria-selected', on ? 'true' : 'false');
      });
      if (!found) return; // this tabs block doesn't have this framework — leave it alone
      tabsEl.querySelectorAll('.tab-panel').forEach((p) => {
        p.hidden = p.dataset.tab !== val;
      });
    });
  }
  // restore framework tab
  const savedFramework = localStorage.getItem('coraza-tab-framework');
  if (savedFramework) selectTab('framework', savedFramework);

  // ---------------- BUILD RIGHT TOC (removed — no right panel) ----------------
  const tocNav = null;
  const sections = [];
  document.querySelectorAll('.main section[id]').forEach((sec) => {
    const h2 = sec.querySelector(':scope > .h2, :scope > .api-head > .h2, :scope > .adapter-head > .h2, :scope > .hero .h1');
    if (!h2) return;
    sections.push({ id: sec.id, title: cleanText(h2), sub: true });

    sec.querySelectorAll(':scope > .api-item[id] > .api-item-head .h3').forEach((h3) => {
      const item = h3.closest('.api-item');
      if (!item || !item.id) return;
      sections.push({ id: item.id, title: cleanText(h3), nested: true });
    });
  });
  if (sections[0] && sections[0].id === 'overview') sections[0].title = 'Overview';

  function cleanText(el) {
    return el.textContent.replace(/\s+/g, ' ').trim();
  }

  // ---------------- SCROLL SPY ----------------
  const sideLinks = document.querySelectorAll('.side-link[href^="#"]');
  const tocLinks = document.querySelectorAll('.toc-link');

  const watched = new Set();
  sections.forEach((s) => watched.add(s.id));
  // also include section ids referenced from sidebar that might not be in toc
  sideLinks.forEach((l) => {
    const id = l.getAttribute('href').slice(1);
    if (id) watched.add(id);
  });

  const io = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      const id = e.target.id;
      if (!id) return;
      if (e.isIntersecting) {
        activeId = id;
        updateActive();
      }
    });
  }, { rootMargin: '-80px 0px -70% 0px', threshold: 0 });

  watched.forEach((id) => {
    const el = document.getElementById(id);
    if (el) io.observe(el);
  });

  let activeId = null;
  function updateActive() {
    sideLinks.forEach((l) => {
      const id = l.getAttribute('href').slice(1);
      l.classList.toggle('is-active', id === activeId);
    });
    tocLinks.forEach((l) => {
      l.classList.toggle('is-active', l.dataset.target === activeId);
    });
  }

  // ---------------- CMD+K ----------------
  const cmdk = document.getElementById('cmdk');
  const cmdkInput = document.getElementById('cmdkInput');
  const cmdkResults = document.getElementById('cmdkResults');
  const searchTrigger = document.getElementById('searchTrigger');

  // Build index from sidebar + sections
  const index = [];
  document.querySelectorAll('.side-link[href^="#"]').forEach((l) => {
    index.push({
      title: l.textContent.trim(),
      id: l.getAttribute('href').slice(1),
      kind: l.classList.contains('side-sub') ? 'method' : 'section',
    });
  });
  document.querySelectorAll('.api-item[id]').forEach((item) => {
    const h3 = item.querySelector('.api-item-head .h3');
    if (!h3) return;
    index.push({ title: cleanText(h3), id: item.id, kind: 'api' });
  });
  document.querySelectorAll('.preset code').forEach((c) => {
    index.push({ title: c.textContent.trim(), id: 'api-coreruleset', kind: 'preset' });
  });

  // dedupe by title+id
  const seen = new Set();
  const searchIndex = index.filter((i) => {
    const k = i.id + '|' + i.title;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  function openCmdk() {
    cmdk.hidden = false;
    requestAnimationFrame(() => { cmdkInput.focus(); cmdkInput.select(); });
    renderResults('');
  }
  function closeCmdk() { cmdk.hidden = true; cmdkInput.value = ''; }

  searchTrigger.addEventListener('click', openCmdk);
  cmdk.querySelector('[data-close]').addEventListener('click', closeCmdk);

  let activeResultIdx = 0;
  function renderResults(q) {
    q = q.trim().toLowerCase();
    const filtered = q
      ? searchIndex.filter((i) => i.title.toLowerCase().includes(q))
      : searchIndex.slice(0, 14);

    if (filtered.length === 0) {
      cmdkResults.innerHTML = '<div class="cmdk-empty">No results for <code>' + escapeHtml(q) + '</code></div>';
      return;
    }

    // group
    const groups = {};
    filtered.forEach((i) => { (groups[i.kind] = groups[i.kind] || []).push(i); });
    const order = ['section', 'api', 'method', 'preset'];
    const labels = { section: 'Sections', api: 'API', method: 'Methods', preset: 'Presets' };

    let html = '';
    let idx = 0;
    order.forEach((k) => {
      if (!groups[k]) return;
      html += '<div class="cmdk-group-label">' + labels[k] + '</div>';
      groups[k].forEach((item) => {
        html += '<div class="cmdk-item' + (idx === activeResultIdx ? ' is-active' : '') +
          '" data-id="' + item.id + '" data-idx="' + idx + '">' +
          '<span class="cmdk-item-title">' + highlight(item.title, q) + '</span>' +
          '<span class="cmdk-item-kind">' + item.kind + '</span></div>';
        idx++;
      });
    });
    cmdkResults.innerHTML = html;

    cmdkResults.querySelectorAll('.cmdk-item').forEach((el) => {
      el.addEventListener('click', () => {
        go(el.dataset.id);
      });
      el.addEventListener('mousemove', () => {
        const i = parseInt(el.dataset.idx, 10);
        if (i !== activeResultIdx) {
          activeResultIdx = i;
          cmdkResults.querySelectorAll('.cmdk-item').forEach((x) => x.classList.remove('is-active'));
          el.classList.add('is-active');
        }
      });
    });
  }

  function go(id) {
    closeCmdk();
    const el = document.getElementById(id);
    if (el) {
      history.replaceState(null, '', '#' + id);
      window.scrollTo({ top: el.getBoundingClientRect().top + window.scrollY - 68, behavior: 'smooth' });
    }
  }

  function highlight(text, q) {
    if (!q) return escapeHtml(text);
    const i = text.toLowerCase().indexOf(q);
    if (i === -1) return escapeHtml(text);
    return escapeHtml(text.slice(0, i)) +
      '<mark>' + escapeHtml(text.slice(i, i + q.length)) + '</mark>' +
      escapeHtml(text.slice(i + q.length));
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  }

  cmdkInput.addEventListener('input', (e) => {
    activeResultIdx = 0;
    renderResults(e.target.value);
  });

  cmdkInput.addEventListener('keydown', (e) => {
    const items = cmdkResults.querySelectorAll('.cmdk-item');
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      activeResultIdx = Math.min(items.length - 1, activeResultIdx + 1);
      syncActive(items);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      activeResultIdx = Math.max(0, activeResultIdx - 1);
      syncActive(items);
    } else if (e.key === 'Enter') {
      const el = items[activeResultIdx];
      if (el) go(el.dataset.id);
    } else if (e.key === 'Escape') {
      closeCmdk();
    }
  });

  function syncActive(items) {
    items.forEach((el, i) => el.classList.toggle('is-active', i === activeResultIdx));
    const el = items[activeResultIdx];
    if (el) el.scrollIntoViewIfNeeded ? el.scrollIntoViewIfNeeded() : el.scrollIntoView({ block: 'nearest' });
  }

  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      cmdk.hidden ? openCmdk() : closeCmdk();
    }
    if ((e.metaKey || e.ctrlKey) && e.key === '.') {
      e.preventDefault();
      document.getElementById('themeToggle').click();
    }
    if (e.key === 'Escape' && !cmdk.hidden) closeCmdk();
    if (e.key === '/' && document.activeElement === document.body) {
      e.preventDefault();
      openCmdk();
    }
  });

  // ---------------- TWEAKS ----------------
  const tweaksPanel = document.getElementById('tweaksPanel');
  const ACCENTS = [
    { name: 'teal',   hex: '#14b8a6' },
    { name: 'blue',   hex: '#3b82f6' },
    { name: 'violet', hex: '#8b5cf6' },
    { name: 'amber',  hex: '#f59e0b' },
    { name: 'rose',   hex: '#f43f5e' },
    { name: 'green',  hex: '#10b981' },
  ];
  const swatches = document.getElementById('swatches');
  ACCENTS.forEach((a) => {
    const b = document.createElement('button');
    b.className = 'swatch';
    b.style.background = a.hex;
    b.dataset.hex = a.hex;
    b.title = a.name;
    if ((localStorage.getItem('coraza-accent') || TWEAK_DEFAULTS.accent) === a.hex) b.classList.add('is-on');
    b.addEventListener('click', () => {
      applyAccent(a.hex);
      swatches.querySelectorAll('.swatch').forEach((s) => s.classList.remove('is-on'));
      b.classList.add('is-on');
      postEdit({ accent: a.hex });
    });
    swatches.appendChild(b);
  });

  document.querySelectorAll('.segmented').forEach((seg) => {
    const key = seg.dataset.seg;
    seg.querySelectorAll('button').forEach((btn) => {
      btn.addEventListener('click', () => {
        const v = btn.dataset.val;
        seg.querySelectorAll('button').forEach((x) => x.classList.remove('is-on'));
        btn.classList.add('is-on');
        if (key === 'theme') applyTheme(v);
        else if (key === 'density') applyDensity(v);
        else if (key === 'font') applyFont(v);
        const edits = {};
        edits[key] = v;
        postEdit(edits);
      });
    });
  });

  syncSegmented('theme', body.getAttribute('data-theme'));
  syncSegmented('density', body.getAttribute('data-density'));
  syncSegmented('font', body.getAttribute('data-font'));

  function syncSegmented(key, val) {
    const seg = document.querySelector('.segmented[data-seg="' + key + '"]');
    if (!seg) return;
    seg.querySelectorAll('button').forEach((b) => b.classList.toggle('is-on', b.dataset.val === val));
  }

  document.getElementById('tweaksClose').addEventListener('click', () => {
    tweaksPanel.hidden = true;
  });

  // Edit-mode protocol
  window.addEventListener('message', (e) => {
    const d = e.data;
    if (!d || typeof d !== 'object') return;
    if (d.type === '__activate_edit_mode') tweaksPanel.hidden = false;
    if (d.type === '__deactivate_edit_mode') tweaksPanel.hidden = true;
  });
  function postEdit(edits) {
    try { window.parent.postMessage({ type: '__edit_mode_set_keys', edits }, '*'); } catch {}
  }
  try { window.parent.postMessage({ type: '__edit_mode_available' }, '*'); } catch {}
  // ---------------- INSTALLER (framework only; all pm commands rendered) ----------------
  const installer = document.getElementById('installer');
  if (installer) {
    const pkgMap = {
      express: '@coraza/express',
      fastify: '@coraza/fastify',
      next: '@coraza/next',
      nestjs: '@coraza/nestjs',
    };
    const state = { fw: localStorage.getItem('coraza-inst-fw') || 'express' };
    const copyBtn = document.getElementById('installerCopyBtn');

    function renderInstaller() {
      const pkg = pkgMap[state.fw] || pkgMap.express;
      installer.querySelectorAll('[data-installer-pkg]').forEach((el) => {
        el.textContent = pkg;
      });
      installer.querySelectorAll('.fw-card').forEach((b) => {
        b.classList.toggle('is-on', b.dataset.val === state.fw);
        b.setAttribute('aria-selected', b.dataset.val === state.fw ? 'true' : 'false');
      });
    }

    installer.querySelectorAll('.fw-card').forEach((b) => {
      b.addEventListener('click', () => {
        state.fw = b.dataset.val;
        localStorage.setItem('coraza-inst-fw', state.fw);
        renderInstaller();
        // Keep the quickstart code block in sync with the framework the
        // user picked in the installer.
        selectTab('framework', state.fw);
        localStorage.setItem('coraza-tab-framework', state.fw);
      });
    });

    if (copyBtn) {
      copyBtn.addEventListener('click', async () => {
        const text = installer.querySelector('#installerMulti')?.innerText ?? '';
        try {
          await navigator.clipboard.writeText(text);
          copyBtn.classList.add('is-copied');
          const span = copyBtn.querySelector('span');
          if (span) span.textContent = 'copied';
          setTimeout(() => {
            copyBtn.classList.remove('is-copied');
            if (span) span.textContent = 'copy';
          }, 1400);
        } catch {}
      });
    }

    renderInstaller();
  }

})();
