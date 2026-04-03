/**
 * Red Team Academy — main.js
 * Notes persistence via localStorage.
 */

function initNotes(pageKey) {
  var textarea = document.getElementById('notes-textarea');
  var savedIndicator = document.getElementById('notes-saved');
  if (!textarea) return;

  var saveTimer = null;
  var storageKey = 'rta-notes-' + pageKey;

  // Load notes from localStorage
  var saved = localStorage.getItem(storageKey);
  if (saved) textarea.value = saved;

  // Save on input (debounced 800ms)
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
