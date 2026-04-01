import db from './db';

const KEY_RE = /^[a-z0-9_-]{1,128}$/;

export function isValidKey(key: string): boolean {
  return KEY_RE.test(key);
}

const stmtGet = db.prepare<[string], { content: string }>(
  'SELECT content FROM notes WHERE page_key = ?'
);
const stmtSave = db.prepare<[string, string]>(
  'INSERT INTO notes (page_key, content, updated_at) VALUES (?, ?, unixepoch()) ON CONFLICT(page_key) DO UPDATE SET content = excluded.content, updated_at = unixepoch()'
);
const stmtDelete = db.prepare<[string]>(
  'DELETE FROM notes WHERE page_key = ?'
);

export function getNote(pageKey: string): string {
  const row = stmtGet.get(pageKey);
  return row?.content ?? '';
}

export function saveNote(pageKey: string, content: string): void {
  stmtSave.run(pageKey, content);
}

export function deleteNote(pageKey: string): void {
  stmtDelete.run(pageKey);
}
