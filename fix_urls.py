#!/usr/bin/env python3
"""Convert bare backtick-wrapped URLs in RTA Jekyll site to markdown hyperlinks.

Rules:
- Pattern 1: `- \`URL\` — Description` → `- [Description](URL)` (reference lists)
- Pattern 2: any remaining `URL` in prose → `[URL](URL)` (if URL is real/external)
- Skip: URLs inside ``` code blocks, localhost, IPs, fictional/placeholder domains
"""
import re
import os
from urllib.parse import urlparse

SITE_DIR = os.path.expanduser('~/code-server/red-team-academy/jekyll-site')

# Check hostname only (prevent matching "attacker" in a blog post URL path)
SKIP_HOSTNAME_PATTERNS = re.compile(
    r'localhost|127\.0\.0\.1|0\.0\.0\.0'
    r'|attacker|victim|medtech\.local|example\.com'
    r'|\.corp\.|^target\.com$|globalbank|jobs-techrecruit'
    r'|phish\.|front-domain|attacker-c2',
    re.IGNORECASE
)

# Check full URL (placeholders, IPs, capital-letter sentinels)
SKIP_URL_PATTERNS = re.compile(
    r'<|>|TARGET|HARVESTED|stage2'
    r'|//\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'  # IP in URL
)


def should_skip(url: str) -> bool:
    if SKIP_URL_PATTERNS.search(url):
        return True
    try:
        host = urlparse(url).hostname or ''
    except Exception:
        host = ''
    return bool(SKIP_HOSTNAME_PATTERNS.search(host))


# Reference list: - `URL` — Description
REF_LIST_RE = re.compile(r'^((?:\s*[-*]\s+)?)\`(https?://[^`]+)\`\s+—\s+(.+)$')

# Any remaining backtick-wrapped URL (not already a markdown link)
# No lookarounds needed: [text](URL) never has backticks around the URL
INLINE_URL_RE = re.compile(r'\`(https?://[^`]+)\`')


def convert_line(line: str) -> str:
    # Pattern 1: reference list entry
    m = REF_LIST_RE.match(line)
    if m:
        prefix, url, desc = m.group(1), m.group(2), m.group(3)
        if not should_skip(url):
            return f'{prefix}[{desc}]({url})'

    # Pattern 2: any remaining inline backtick URL
    def replace_inline(m):
        url = m.group(1)
        if should_skip(url):
            return m.group(0)
        return f'[{url}]({url})'

    return INLINE_URL_RE.sub(replace_inline, line)


def process_file(filepath: str) -> tuple[int, int]:
    """Returns (lines_changed, total_urls_converted)."""
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    in_code_block = False
    new_lines = []
    changed = 0

    for line in lines:
        stripped = line.rstrip('\n')

        # Track fenced code blocks (``` or ~~~)
        if re.match(r'^\s*(`{3,}|~{3,})', stripped):
            in_code_block = not in_code_block
            new_lines.append(line)
            continue

        if in_code_block:
            new_lines.append(line)
            continue

        converted = convert_line(stripped)
        if converted != stripped:
            changed += 1
        new_lines.append(converted + '\n' if line.endswith('\n') else converted)

    if changed:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)

    return changed


def main():
    total_files = 0
    total_lines = 0

    for root, dirs, files in os.walk(SITE_DIR):
        # Skip hidden dirs and _site build output
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != '_site']
        for fname in sorted(files):
            if not fname.endswith(('.md', '.html')):
                continue
            fpath = os.path.join(root, fname)
            changed = process_file(fpath)
            if changed:
                total_files += 1
                total_lines += changed
                rel = os.path.relpath(fpath, SITE_DIR)
                print(f'  {rel}: {changed} line(s) converted')

    print(f'\nDone: {total_lines} lines converted across {total_files} files.')


if __name__ == '__main__':
    main()
