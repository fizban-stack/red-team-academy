# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Running the Site

```bash
npm run dev      # dev server on port 8080 (http://localhost:8080)
npm run build    # production build → dist/
npm run start    # serve production build (node dist/server/entry.mjs)
```

## Architecture

**Astro hybrid SSR** — pages are statically rendered, API routes are server-rendered.
Adapter: `@astrojs/node` (standalone mode). Notes stored in SQLite via `better-sqlite3`.

### Directory Structure

```
src/
  layouts/
    Base.astro          # navbar + sidebar + footer (server-rendered, active-page aware)
    TrainingPage.astro  # extends Base: adds notes panel + content slot
  pages/
    index.astro         # homepage with module grid
    about.astro
    <module>/           # one directory per module, one .astro file per lesson
    api/notes/
      [pageKey].ts      # GET / PUT / DELETE — reads/writes SQLite
  lib/
    db.ts               # better-sqlite3 singleton, creates data/notes.db on first run
    notes.ts            # getNote / saveNote / deleteNote with prepared statements
public/
  css/styles.css        # terminal/hacker theme — edit here for global style changes
  js/main.js            # client-side notes: fetch /api/notes/:key, debounced save
  images/<module>/      # SVG diagrams, referenced as /images/<module>/file.svg
data/
  notes.db              # SQLite database (gitignored, auto-created on first run)
scripts/
  migrate-notes.ts      # one-time: import old .txt notes → SQLite
```

### Page Key Convention

Each training page calls `initNotes(pageKey)` where `pageKey` matches `/^[a-z0-9_-]{1,128}$/`.
Convention: `module-topic` (e.g., `ad-acl-abuse`, `recon-active`).

### Active Page Highlighting

`Base.astro` uses `Astro.url.pathname` at render time — no client-side JS needed.
`isActive('/fundamentals/methodology')` returns true when the path matches exactly.

## Adding a New Page

1. Create `src/pages/<module>/<page-name>.astro`:
   ```astro
   ---
   import TrainingPage from '../../layouts/TrainingPage.astro';
   ---
   <TrainingPage
     title="Page Title — Red Team Academy"
     module="Module Name"
     tags={['tag1', 'tag2']}
     pageKey="module-page-slug"
   >
     <h1>Page Title</h1>
     <!-- content here -->
   </TrainingPage>
   ```
2. Add the SVG diagram to `public/images/<module>/` and reference it as `/images/<module>/file.svg`
3. Add the nav link in `src/layouts/Base.astro` (the `<details>` block for the module)
4. Add a card to `src/pages/index.astro` if it's a new module

## Migrating Notes from Old Site

If migrating from the previous Express flat-file site:
```bash
npx tsx scripts/migrate-notes.ts --source ../website/data/notes
```

## Notes API

| Method | Path | Behaviour |
|--------|------|-----------|
| GET | `/api/notes/:pageKey` | Returns note text (empty string if none) |
| PUT | `/api/notes/:pageKey` | Saves body as note content, returns 204 |
| DELETE | `/api/notes/:pageKey` | Deletes note, returns 204 |

Page key validation: `/^[a-z0-9_-]{1,128}$/` — same as previous site.
