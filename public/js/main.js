/**
 * Red Team Academy — main.js
 * Server-side notes persistence via /api/notes/:pageKey (PUT/GET).
 * Falls back to localStorage if the API is unreachable.
 */

async function initNotes(pageKey) {
  const textarea = document.getElementById('notes-textarea');
  const savedIndicator = document.getElementById('notes-saved');
  if (!textarea) return;

  let saveTimer = null;

  // ── Load notes from server ────────────────────────────────────────
  try {
    const res = await fetch('/api/notes/' + pageKey);
    if (res.ok) {
      const text = await res.text();
      textarea.value = text;
    } else {
      // Server reachable but API not available (e.g. 404) — fall back to localStorage
      const local = localStorage.getItem('rta-notes-' + pageKey);
      if (local) textarea.value = local;
    }
  } catch {
    // Network error — fall back to localStorage
    const local = localStorage.getItem('rta-notes-' + pageKey);
    if (local) textarea.value = local;
  }

  // ── Save notes on input (debounced 800ms) ─────────────────────────
  textarea.addEventListener('input', () => {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => saveNotes(pageKey, textarea.value, savedIndicator), 800);
  });
}

async function saveNotes(pageKey, content, indicator) {
  let saved = false;

  try {
    const res = await fetch('/api/notes/' + pageKey, {
      method: 'PUT',
      headers: { 'Content-Type': 'text/plain' },
      body: content,
    });
    saved = res.ok;
  } catch {
    // Server unreachable — fall back to localStorage
  }

  if (!saved) {
    localStorage.setItem('rta-notes-' + pageKey, content);
  }

  if (indicator) {
    indicator.classList.add('visible');
    setTimeout(() => indicator.classList.remove('visible'), 1500);
  }
}
