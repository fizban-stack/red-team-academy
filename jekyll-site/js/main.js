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
      label.textContent = 'shell';
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
});
