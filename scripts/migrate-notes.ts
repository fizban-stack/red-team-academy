/**
 * Migrate notes from old flat .txt files → SQLite.
 * Usage: npx tsx scripts/migrate-notes.ts --source ../website/data/notes
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join, basename } from 'node:path';
import { saveNote, isValidKey } from '../src/lib/notes';

const args = process.argv.slice(2);
const srcIdx = args.indexOf('--source');
if (srcIdx === -1 || !args[srcIdx + 1]) {
  console.error('Usage: npx tsx scripts/migrate-notes.ts --source <path-to-notes-dir>');
  process.exit(1);
}

const sourceDir = args[srcIdx + 1];
let migrated = 0;
let skipped = 0;

const files = readdirSync(sourceDir).filter(f => f.endsWith('.txt'));
for (const file of files) {
  const pageKey = basename(file, '.txt');
  if (!isValidKey(pageKey)) {
    console.warn(`Skipping invalid key: ${pageKey}`);
    skipped++;
    continue;
  }
  const content = readFileSync(join(sourceDir, file), 'utf8');
  saveNote(pageKey, content);
  console.log(`Migrated: ${pageKey}`);
  migrated++;
}

console.log(`\nDone. Migrated: ${migrated}, Skipped: ${skipped}`);
