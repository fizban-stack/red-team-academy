import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

const dataDir = join(process.cwd(), 'data');
mkdirSync(dataDir, { recursive: true });

const db = new Database(join(dataDir, 'notes.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS notes (
    page_key   TEXT PRIMARY KEY,
    content    TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
  )
`);

export default db;
