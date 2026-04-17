/**
 * Red Team Academy — main.js
 * Notes persistence, code block copy buttons, and table of contents.
 */

/* ─────────────────────────────────────────────────────
   NOTES — localStorage persistence
   ───────────────────────────────────────────────────── */

function initNotes(pageKey) {
  var textarea = document.getElementById('notes-textarea');
  var savedIndicator = document.getElementById('notes-saved');
  if (!textarea) return;

  var saveTimer = null;
  var storageKey = 'rta-notes-' + pageKey;

  var saved = localStorage.getItem(storageKey);
  if (saved) textarea.value = saved;

  textarea.addEventListener('input', function() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(function() {
      localStorage.setItem(storageKey, textarea.value);
      if (savedIndicator) {
        savedIndicator.classList.add('visible');
        setTimeout(function() { savedIndicator.classList.remove('visible'); }, 1500);
      }
    }, 800);
  });
}

/* ─────────────────────────────────────────────────────
   CODE BLOCKS — terminal header + copy button
   ───────────────────────────────────────────────────── */

function initCodeBlocks() {
  var panels = document.querySelectorAll('.content-panel');
  if (!panels.length) return;

  panels.forEach(function(panel) {
    panel.querySelectorAll('pre').forEach(function(pre) {
      var code = pre.querySelector('code');
      if (!code) return;

      // Wrap in .code-block
      var wrapper = document.createElement('div');
      wrapper.className = 'code-block';
      pre.parentNode.insertBefore(wrapper, pre);
      wrapper.appendChild(pre);

      // Build header
      var header = document.createElement('div');
      header.className = 'code-block-header';

      // Fake traffic-light dots
      var dots = document.createElement('div');
      dots.className = 'code-block-dots';
      for (var i = 0; i < 3; i++) {
        var dot = document.createElement('span');
        dot.className = 'code-block-dot';
        dots.appendChild(dot);
      }
      header.appendChild(dots);

      // Label
      var label = document.createElement('span');
      label.className = 'code-block-label';
      var langMatch = (code.className || '').match(/\blanguage-(\S+)/);
      label.textContent = langMatch ? langMatch[1] : 'shell';
      header.appendChild(label);

      // Copy button
      var btn = document.createElement('button');
      btn.className = 'copy-btn';
      btn.setAttribute('aria-label', 'Copy code to clipboard');
      btn.textContent = 'copy';

      btn.addEventListener('click', function() {
        var text = (code.innerText || code.textContent || '').trimEnd();

        function onCopied() {
          btn.textContent = 'copied!';
          btn.classList.add('copied');
          setTimeout(function() {
            btn.textContent = 'copy';
            btn.classList.remove('copied');
          }, 2000);
        }

        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(onCopied).catch(function() {
            fallbackCopy(text, onCopied);
          });
        } else {
          fallbackCopy(text, onCopied);
        }
      });

      header.appendChild(btn);
      wrapper.insertBefore(header, pre);
    });
  });
}

function fallbackCopy(text, callback) {
  try {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;top:-9999px;left:-9999px;opacity:0;';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    if (callback) callback();
  } catch (e) { /* silent fail */ }
}

/* ─────────────────────────────────────────────────────
   TABLE OF CONTENTS — injected for pages with 4+ sections
   ───────────────────────────────────────────────────── */

function initTableOfContents() {
  var contentPanel = document.querySelector('.content-panel');
  if (!contentPanel) return;

  var headings = contentPanel.querySelectorAll('h2');
  // Only build TOC if there are enough meaningful sections
  var sections = [];
  headings.forEach(function(h) {
    var text = (h.textContent || '').trim();
    if (text && text !== 'Resources') {
      sections.push(h);
    }
  });

  if (sections.length < 4) return;

  // Assign IDs to headings that lack them
  sections.forEach(function(h, i) {
    if (!h.id) {
      h.id = 'sec-' + h.textContent.toLowerCase()
        .replace(/[^a-z0-9\s]/g, '')
        .trim()
        .replace(/\s+/g, '-')
        .substring(0, 40) + '-' + i;
    }
  });

  // Build TOC element
  var toc = document.createElement('div');
  toc.className = 'toc-panel';

  var tocTitle = document.createElement('div');
  tocTitle.className = 'toc-title';
  tocTitle.textContent = '// sections';
  toc.appendChild(tocTitle);

  var tocList = document.createElement('ol');
  tocList.className = 'toc-list';
  sections.forEach(function(h) {
    var li = document.createElement('li');
    var a = document.createElement('a');
    a.href = '#' + h.id;
    a.textContent = h.textContent;
    li.appendChild(a);
    tocList.appendChild(li);
  });
  toc.appendChild(tocList);

  // Insert after .page-meta if present, otherwise prepend
  var pageMeta = contentPanel.querySelector('.page-meta');
  if (pageMeta && pageMeta.nextSibling) {
    contentPanel.insertBefore(toc, pageMeta.nextSibling);
  } else if (pageMeta) {
    pageMeta.parentNode.appendChild(toc);
  } else {
    contentPanel.insertBefore(toc, contentPanel.firstChild);
  }
}

/* ─────────────────────────────────────────────────────
   INIT — run after DOM is ready
   ───────────────────────────────────────────────────── */

document.addEventListener('DOMContentLoaded', function() {
  initCodeBlocks();
  initTableOfContents();
  initHeadingTools();
  initSearch();
});

/* ─────────────────────────────────────────────────────
   HEADING TOOLS — permalinks + copy section
   ───────────────────────────────────────────────────── */

function initHeadingTools() {
  var contentPanel = document.querySelector('.content-panel');
  if (!contentPanel) return;

  var headings = contentPanel.querySelectorAll('h2, h3');
  if (!headings.length) return;

  headings.forEach(function(h, idx) {
    var text = (h.textContent || '').trim();
    if (!text) return;

    // Ensure stable-ish id
    if (!h.id) {
      h.id = 'sec-' + text.toLowerCase()
        .replace(/[^a-z0-9\s]/g, '')
        .trim()
        .replace(/\s+/g, '-')
        .substring(0, 50) + '-' + idx;
    }

    // Avoid double-wrapping if rerun
    if (h.querySelector('.heading-row')) return;

    var row = document.createElement('span');
    row.className = 'heading-row';

    var title = document.createElement('span');
    title.className = 'heading-text';
    title.textContent = text;

    // Clear existing nodes and rebuild
    while (h.firstChild) h.removeChild(h.firstChild);

    var tools = document.createElement('span');
    tools.className = 'heading-tools';

    var linkBtn = document.createElement('button');
    linkBtn.className = 'heading-btn';
    linkBtn.type = 'button';
    linkBtn.textContent = 'link';
    linkBtn.setAttribute('aria-label', 'Copy section link');

    linkBtn.addEventListener('click', function(e) {
      e.preventDefault();
      e.stopPropagation();
      var url = window.location.origin + window.location.pathname + '#' + h.id;
      copyText(url, linkBtn);
    });

    var secBtn = document.createElement('button');
    secBtn.className = 'heading-btn';
    secBtn.type = 'button';
    secBtn.textContent = 'copy';
    secBtn.setAttribute('aria-label', 'Copy section content');

    secBtn.addEventListener('click', function(e) {
      e.preventDefault();
      e.stopPropagation();
      var sectionText = extractSectionText(h);
      if (sectionText) copyText(sectionText, secBtn);
    });

    tools.appendChild(linkBtn);
    tools.appendChild(secBtn);

    row.appendChild(title);
    row.appendChild(tools);
    h.appendChild(row);
  });
}

function extractSectionText(headingEl) {
  if (!headingEl || !headingEl.parentNode) return '';

  var tag = (headingEl.tagName || '').toLowerCase();
  var stopTag = tag;

  var parts = [];
  var headingTextEl = headingEl.querySelector('.heading-text');
  var headingTitle = headingTextEl
    ? (headingTextEl.textContent || '').trim()
    : (headingEl.textContent || '').replace(/\s+/g, ' ').trim();
  parts.push(headingTitle);

  var n = headingEl.nextElementSibling;
  while (n) {
    var t = (n.tagName || '').toLowerCase();
    if (t === stopTag) break;
    if (stopTag === 'h2' && t === 'h2') break;
    if (stopTag === 'h3' && (t === 'h2' || t === 'h3')) break;

    // Prefer code blocks verbatim
    if (t === 'pre') {
      var code = n.querySelector('code');
      var codeText = (code ? (code.innerText || code.textContent) : (n.innerText || n.textContent)) || '';
      parts.push(codeText.trimEnd());
    } else {
      var txt = (n.innerText || n.textContent || '').trim();
      if (txt) parts.push(txt);
    }
    n = n.nextElementSibling;
  }

  return parts.join('\n\n').trim();
}

function copyText(text, btnEl) {
  if (!text) return;

  function onCopied() {
    if (!btnEl) return;
    btnEl.classList.add('copied');
    var old = btnEl.textContent;
    btnEl.textContent = 'copied!';
    setTimeout(function() {
      btnEl.textContent = old;
      btnEl.classList.remove('copied');
    }, 1200);
  }

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(onCopied).catch(function() {
      fallbackCopy(text, onCopied);
    });
  } else {
    fallbackCopy(text, onCopied);
  }
}

/* ─────────────────────────────────────────────────────
   SEARCH — client-side index + Ctrl+K shortcut
   ───────────────────────────────────────────────────── */

function initSearch() {
  // Global shortcut
  document.addEventListener('keydown', function(e) {
    // Ctrl+K / Cmd+K
    if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
      e.preventDefault();
      if (window.location.pathname.replace(/\/$/, '') !== '/search') {
        window.location.href = '/search/';
        return;
      }
      var input = document.getElementById('search-input');
      if (input) input.focus();
    }
  });

  // Only render search UI on /search/
  var input = document.getElementById('search-input');
  var resultsEl = document.getElementById('search-results');
  var metaEl = document.getElementById('search-meta');
  var modulesEl = document.getElementById('filter-modules');
  var tagsEl = document.getElementById('filter-tags');
  if (!input || !resultsEl) return;

  var index = [];
  var loaded = false;
  var activeModule = '';
  var activeTags = [];

  function setMeta(msg) {
    if (metaEl) metaEl.textContent = msg;
  }

  function normalize(s) {
    return (s || '')
      .toString()
      .toLowerCase()
      .replace(/\s+/g, ' ')
      .trim();
  }

  function renderEmpty() {
    resultsEl.innerHTML = '';
    setMeta('type to search…');
  }

  function uniqueSorted(arr) {
    var m = {};
    (arr || []).forEach(function(x) {
      var k = (x || '').toString().trim();
      if (!k) return;
      m[k] = true;
    });
    return Object.keys(m).sort(function(a, b) { return a.localeCompare(b); });
  }

  function renderChips() {
    if (!modulesEl && !tagsEl) return;

    var mods = uniqueSorted(index.map(function(p) { return p.module || ''; }).filter(Boolean));
    var tags = uniqueSorted([].concat.apply([], index.map(function(p) { return Array.isArray(p.tags) ? p.tags : []; })));

    function chip(label, isActive, onClick) {
      return (
        '<button type="button" class="chip' + (isActive ? ' active' : '') + '" data-val="' + escapeAttr(label) + '">' +
          escapeHtml(label) +
        '</button>'
      );
    }

    if (modulesEl) {
      var htmlM = chip('all', !activeModule, null) + mods.map(function(m) {
        return chip(m, activeModule === m, null);
      }).join('');
      modulesEl.innerHTML = htmlM;
      modulesEl.querySelectorAll('button.chip').forEach(function(b) {
        b.addEventListener('click', function() {
          var v = b.getAttribute('data-val') || '';
          activeModule = (v === 'all') ? '' : v;
          renderChips();
          runSearch();
        });
      });
    }

    if (tagsEl) {
      // keep tags reasonably small in UI
      var top = tags.slice(0, 60);
      tagsEl.innerHTML = top.map(function(t) {
        var on = activeTags.indexOf(t) >= 0;
        return chip(t, on, null);
      }).join('');
      tagsEl.querySelectorAll('button.chip').forEach(function(b) {
        b.addEventListener('click', function() {
          var v = b.getAttribute('data-val') || '';
          if (!v) return;
          var i = activeTags.indexOf(v);
          if (i >= 0) activeTags.splice(i, 1);
          else activeTags.push(v);
          renderChips();
          runSearch();
        });
      });
    }
  }

  function renderResults(q, items) {
    if (!q) {
      renderEmpty();
      return;
    }

    if (!items.length) {
      resultsEl.innerHTML =
        '<div class="search-empty">no matches</div>';
      setMeta('0 results');
      return;
    }

    setMeta(items.length + (items.length === 1 ? ' result' : ' results'));

    var html = items.map(function(p) {
      var tags = Array.isArray(p.tags) ? p.tags : [];
      var tagHtml = tags.slice(0, 6).map(function(t) {
        return '<span class="tag">' + escapeHtml(t) + '</span>';
      }).join('');

      var module = p.module ? '<span class="search-module">' + escapeHtml(p.module) + '</span>' : '';

      return (
        '<a class="search-hit" href="' + escapeAttr(p.url) + '">' +
          '<div class="search-hit-title">' + escapeHtml(p.title || p.url) + '</div>' +
          '<div class="search-hit-meta">' + module + tagHtml + '</div>' +
        '</a>'
      );
    }).join('');

    resultsEl.innerHTML = html;
  }

  function escapeHtml(str) {
    return (str || '').toString()
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function escapeAttr(str) {
    return escapeHtml(str).replace(/"/g, '&quot;');
  }

  function scorePage(q, p) {
    var title = normalize(p.title);
    var module = normalize(p.module);
    var tags = Array.isArray(p.tags) ? normalize(p.tags.join(' ')) : '';
    var body = normalize(p.content);

    var s = 0;
    if (title === q) s += 100;
    if (title.indexOf(q) === 0) s += 60;
    if (title.indexOf(q) >= 0) s += 40;
    if (tags.indexOf(q) >= 0) s += 25;
    if (module.indexOf(q) >= 0) s += 15;
    if (body.indexOf(q) >= 0) s += 10;
    return s;
  }

  function runSearch() {
    var q = normalize(input.value);
    if (!loaded) {
      setMeta('loading index…');
      return;
    }

    if (!q || q.length < 2) {
      renderEmpty();
      return;
    }

    var scoped = index.filter(function(p) {
      if (activeModule && p.module !== activeModule) return false;
      if (activeTags.length) {
        var pt = Array.isArray(p.tags) ? p.tags : [];
        for (var i = 0; i < activeTags.length; i++) {
          if (pt.indexOf(activeTags[i]) < 0) return false;
        }
      }
      return true;
    });

    var scored = scoped
      .map(function(p) { return { p: p, s: scorePage(q, p) }; })
      .filter(function(x) { return x.s > 0; })
      .sort(function(a, b) { return b.s - a.s; })
      .slice(0, 60)
      .map(function(x) { return x.p; });

    renderResults(q, scored);
  }

  // Load index
  fetch('/search.json', { cache: 'no-store' })
    .then(function(r) {
      if (!r.ok) throw new Error('network');
      return r.json();
    })
    .then(function(data) {
      index = Array.isArray(data) ? data : [];
      loaded = true;
      setMeta(index.length + ' pages indexed');
      renderChips();
      input.focus();
      renderEmpty();
    })
    .catch(function(err) {
      loaded = true;
      setMeta(err && err.message === 'network' ? 'search index unavailable' : 'search index could not be parsed');
    });

  input.addEventListener('input', function() {
    runSearch();
  });
}

/* ─────────────────────────────────────────────────────
   STALENESS WARNING — amber banner when content > 12 months old
   ───────────────────────────────────────────────────── */

function initStalenessWarning() {
  var panel = document.querySelector('.content-panel');
  if (!panel) return;

  var updated = (panel.getAttribute('data-updated') || '').trim();
  if (!updated) return;

  var updatedDate = new Date(updated);
  if (isNaN(updatedDate.getTime())) return;

  var monthsAgo = (Date.now() - updatedDate.getTime()) / (1000 * 60 * 60 * 24 * 30);
  if (monthsAgo < 12) return;

  var banner = document.createElement('div');
  banner.className = 'stale-warning';
  banner.innerHTML =
    '<span class="stale-icon">⚠</span>' +
    '<span>Last verified <strong>' + updated + '</strong> — offensive techniques evolve quickly. Verify tool syntax and CVE status before use in engagements.</span>' +
    '<button class="stale-dismiss" aria-label="Dismiss">×</button>';

  banner.querySelector('.stale-dismiss').addEventListener('click', function() {
    banner.remove();
  });

  var meta = panel.querySelector('.page-meta');
  if (meta && meta.parentNode) {
    meta.parentNode.insertBefore(banner, meta.nextSibling);
  } else {
    panel.insertBefore(banner, panel.firstChild);
  }
}

/* ─────────────────────────────────────────────────────
   NOTES I/O — export all notes as markdown, import from file
   ───────────────────────────────────────────────────── */

function initNotesIO() {
  var exportBtn  = document.getElementById('notes-export-btn');
  var importInput = document.getElementById('notes-import-input');
  if (!exportBtn && !importInput) return;

  if (exportBtn) {
    exportBtn.addEventListener('click', function() {
      var lines = [];
      var keys = [];

      for (var i = 0; i < localStorage.length; i++) {
        var k = localStorage.key(i);
        if (k && k.indexOf('rta-notes-') === 0) keys.push(k);
      }

      keys.sort();

      keys.forEach(function(k) {
        var content = (localStorage.getItem(k) || '').trim();
        if (!content) return;
        var slug = k.replace('rta-notes-', '');
        lines.push('# ' + slug + '\n\n' + content + '\n');
      });

      if (!lines.length) {
        alert('No notes to export.');
        return;
      }

      var blob = new Blob([lines.join('\n---\n\n')], { type: 'text/markdown' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'rta-notes-' + new Date().toISOString().slice(0, 10) + '.md';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });
  }

  if (importInput) {
    importInput.addEventListener('change', function() {
      var file = importInput.files && importInput.files[0];
      if (!file) return;

      var reader = new FileReader();
      reader.onload = function(e) {
        var text = (e.target.result || '');
        var sections = text.split(/\n---\n\n/);
        var count = 0;

        sections.forEach(function(section) {
          var match = section.match(/^# ([^\n]+)\n\n([\s\S]*)/);
          if (!match) return;
          var slug = match[1].trim();
          var content = match[2].trim();
          if (!slug || !content) return;
          localStorage.setItem('rta-notes-' + slug, content);
          count++;
        });

        if (count > 0) {
          alert('Imported ' + count + ' note page' + (count !== 1 ? 's' : '') + '. Reload the page to see this page\'s notes.');
        } else {
          alert('No valid notes found in the file.');
        }
        importInput.value = '';
      };
      reader.readAsText(file);
    });
  }
}
