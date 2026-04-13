---
layout: training-page
title: "Authoring Guide & QA Checklist — Red Team Academy"
module: "Fundamentals"
tags:
  - authoring
  - qa
  - style-guide
page_key: "fundamentals-authoring-guide"
render_with_liquid: false
updated: "2026-04-13"
---

# Authoring Guide & QA Checklist

This page is the *internal* checklist for keeping the playbook consistent and ops-friendly.

## Recommended Page Skeleton

- **Overview** — what the technique is and when to use it.
- **Prereqs / Assumptions** — access level, OS, required ports/tools, constraints.
- **Workflow** — operator sequence, step-by-step.
- **Commands** — copy-ready blocks; prefer minimal placeholders.
- **Detection / Telemetry** — what blue teams will see (logs/events/process/network).
- **OpSec Notes** — what to avoid, common footguns, noise sources.
- **Resources** — sources and references.

## Front Matter Checklist

Ensure every training page includes:

```yaml
layout: training-page
title: "Topic — Red Team Academy"
module: "Exact Module Name"
tags:
  - kebab-case
page_key: "module-topic"
render_with_liquid: false
updated: "YYYY-MM-DD"   # optional but recommended
```

## Content Rules (Practical)

- Use **Markdown** for content pages (`.md`) or HTML (`.html`) — both are supported.
- Code blocks should be Markdown fenced code blocks; Jekyll renders them as `<pre><code>…</code></pre>` which the site enhances with copy buttons.
- Avoid inline styles and per-page scripts.
- Keep placeholders consistent: `<TARGET>`, `<USER>`, `<PASS>`, `<DOMAIN>`, `<LHOST>`, `<RHOST>`.
- Prefer **curation** over dumping massive lists: highlight the best 10–30 operator payloads and point to a canonical source for the full library.

## Ops-Friendliness Checklist

- Add **clear section headings** (so TOC + permalinks are useful).
- Ensure commands are **runnable** and reflect real tool flags.
- Add at least one **“quick triage”** block for common scenarios.
- If the technique is noisy, call it out explicitly in **Detection/OpSec**.
- Include **evidence capture** hints (what outputs/screenshots to save for reporting).

## QA Pass (Before You Commit)

```text
1) Sidebar link exists (nav.yml)
2) Page renders with training-page layout
3) page_key is unique across the site
4) Tags are relevant + kebab-case
5) Resources section exists and includes source URLs
6) Copy buttons work on all code blocks (no weird formatting)
7) Headings are meaningful (permabuttons generate clean anchors)
```

## Resources

- Jekyll docs — `jekyllrb.com/docs/`
