---
layout: training-page
title: "Ops Cheatsheets — Red Team Academy"
module: "Ops Cheatsheets"
tags:
  - cheatsheet
  - ops
  - overview
page_key: "cheatsheets-overview"
render_with_liquid: false
updated: "2026-04-13"
---

# Ops Cheatsheets

One-screen references for live operations: copy-ready commands, triage order, and evidence habits. Use **Search** (`Ctrl+K`) or the sidebar to jump. Toggle **[notes]** in the navbar to hide the notes panel when you only need the playbook.

## What’s in this module

| Page | Use when |
|------|----------|
| [Quick payloads](/cheatsheets/quick-payloads/) | You need a fast probe, one-liner, or canonical string — SSRF, web, shells, AD stubs. |
| [AD triage](/cheatsheets/ad-triage/) | You have domain context and need a repeatable Windows/AD enumeration order. |
| [Web triage](/cheatsheets/web-triage/) | You are mapping an app and prioritizing test classes under time pressure. |
| [Pivoting patterns](/cheatsheets/pivoting-patterns/) | You need SSH, SOCKS, or Chisel-style tunnels without re-reading full lessons. |
| [Exfil & evidence](/cheatsheets/exfil-evidence/) | You need scope-safe handling of data movement and report-ready artifacts. |

## How to use safely

- Replace placeholders (`<TARGET>`, `<LHOST>`, etc.) before running anything.
- Stay inside **authorized scope**; these pages are for **training and authorized assessments** only.
- Prefer your engagement’s **evidence standard** (screenshots, command logs, hashes) over ad-hoc copies.

## Resources

- [Authoring guide](/fundamentals/authoring-guide/) — how pages in this site are structured
- MITRE ATT&CK — `https://attack.mitre.org/`
