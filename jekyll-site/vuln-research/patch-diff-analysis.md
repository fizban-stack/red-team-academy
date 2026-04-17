---
layout: training-page
title: "Patch Diff Analysis & CVE Research — Red Team Academy"
module: "Vulnerability Research"
tags:
  - patch-diff
  - bindiff
  - cve-research
  - 1-day-exploit
  - patch-tuesday
  - vulnerability-analysis
  - exploit-timeline
page_key: "vuln-research-patch-diff-analysis"
render_with_liquid: false
---

# Patch Diff Analysis & CVE Research

When a vendor releases a security patch, the diff between the patched and unpatched binary is a map to the vulnerability. A skilled researcher can work backward from the patch to discover the exact bug, build a PoC, and develop an exploit — often before most deployments are updated. This page covers the complete patch diffing workflow across Windows, Linux, and open-source targets, plus the broader CVE research ecosystem.

---

## Why Patch Diffs

Patch diffing is the most efficient path to known vulnerabilities when:

1. **1-day exploitation**: you know a CVE exists but the full details aren't published yet
2. **Variant analysis**: find related bugs in code that was partially patched
3. **Root cause understanding**: understand exactly what the vulnerability was
4. **Exploit development**: the patch shows you precisely what was wrong — the exploit uses the unpatched version

The 1-day window (between patch release and widespread deployment) is routinely used by sophisticated threat actors. Understanding patch diffing is essential for defenders (to prioritize patches) and red teams (to validate patch compliance).

---

## Tools

| Tool | Type | Best For |
|------|------|---------|
| BinDiff (Zynamics/Google) | Binary diff | Windows DLL/EXE patch comparison |
| Diaphora | Binary diff (IDA) | Alternative to BinDiff, open source |
| git diff | Source diff | Linux kernel, open source projects |
| diffoscope | Package diff | Comparing OS packages (RPM, DEB) |
| BinExport | IDA/Ghidra export | Bridge to BinDiff |
| patchdiff2 | IDA plugin | Older, still functional |
| bindifflib | Python library | Automating diff analysis |

---

## Microsoft Patch Tuesday Workflow

Microsoft releases security patches on the second Tuesday of each month. This creates a predictable 1-day analysis opportunity.

### Step 1: Download Patched and Unpatched DLLs

```powershell
# Get the specific file version before patching
# Source: previous Windows update package (CAB/MSU file)

# Download the patch MSU
# From: https://catalog.update.microsoft.com/
# Search for KB number (e.g., KB5034441)

# Extract MSU
expand.exe KB5034441.msu -F:* C:\extracted\

# Inside will be a CAB file containing patched DLLs
expand.exe Windows10.0-KB5034441-x64.cab -F:* C:\patched_dlls\

# Find the DLL of interest (from MSRC advisory)
# e.g., CVE says "Windows CLFS Driver" → clfs.sys
# Note the file version of patched vs. unpatched system
```

```bash
# Get unpatched version from older Windows installation / VM snapshot
# Or from MSDN subscriber downloads

# For research VMs: restore snapshot to pre-patch state
virsh snapshot-revert win10-vm pre-kb5034441

# Copy out the DLL
cp /mnt/vm_share/Windows/System32/clfs.sys ./clfs_unpatched.sys
```

### Step 2: BinDiff Comparison

```
1. Open both DLLs in IDA Pro (separate sessions)
2. Run auto-analysis in both
3. Export BinExport from each:
   Edit → Plugins → BinExport → Export to BinExport2
4. Open BinDiff Differ:
   File → Diff Databases → select both .BinExport files
5. Review primary/secondary function matches
```

### Step 3: Analyzing the Diff

```
BinDiff result categories:
├── Matched functions (similar in both versions)
│   ├── Similarity 1.00: identical — not the fix
│   ├── Similarity 0.80-0.99: minor change — INVESTIGATE
│   └── Similarity < 0.80: major change — HIGH PRIORITY
├── Added functions (new in patched)
│   └── Often: input validation functions, sanitizers
└── Removed functions (only in unpatched)
    └── Rarely removed outright — more often rewritten
```

**Reading the diff for a bounds check fix:**

```c
// UNPATCHED (decompiled):
int process_data(char *buf, int user_len) {
    char local_buf[256];
    memcpy(local_buf, buf, user_len);  // No bounds check!
    return parse(local_buf);
}

// PATCHED (decompiled):
int process_data(char *buf, int user_len) {
    char local_buf[256];
    if (user_len > 256) return ERROR_INVALID_PARAM;  // Added check
    memcpy(local_buf, buf, user_len);
    return parse(local_buf);
}

// Conclusion: user_len > 256 bypasses the check → stack overflow
// PoC: send user_len = 257 with controlled data
```

### Step 4: Diaphora (Open Source Alternative)

```python
# Diaphora — open source IDA plugin for binary diffing
# https://github.com/joxeankoret/diaphora

# Install: copy diaphora.py to IDA plugins directory
# Use: File → Script File → diaphora.py → export both DBs → diff

# Diaphora advantage: open source, can script the diffing
import diaphora
d = diaphora.CBinDiff()
d.db_name = "target_unpatched.sqlite"
d.export()  # Export from IDA

# Compare two exported databases
d2 = diaphora.CBinDiff()
d2.db_name = "target_patched.sqlite"
d2.diff("target_unpatched.sqlite")
# Results contain similarity scores and changed basic blocks
```

---

## Linux Kernel Patches

Linux kernel vulnerabilities are disclosed via git commits with security-relevant commit messages.

### Finding Security Patches

```bash
# Search kernel git log for security fixes
git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
cd linux

# Find commits mentioning "CVE"
git log --oneline --grep="CVE-" --since="2024-01-01" | head -50

# Find commits related to specific subsystem
git log --oneline --grep="buffer overflow" -- drivers/net/ | head -20

# Follow a CVE to its fix
# Example: CVE-2024-26581 — nftables out-of-bounds write
git log --all --grep="CVE-2024-26581"
git show <commit_hash>
```

### Reading a Kernel Patch

```diff
# Example: kernel buffer overflow fix
# git show a3b7c19f2e4d

commit a3b7c19f2e4d7e8f9a0b1c2d3e4f5a6b7c8d9e0
Author: Kernel Developer <dev@kernel.org>
Date:   Mon Jan 15 09:23:11 2024 +0000

    net: fix buffer overflow in packet_recvmsg()

    When user specifies a length larger than the packet size,
    the copy operation can overflow the destination buffer.

    CVE-2024-XXXXX

diff --git a/net/packet/af_packet.c b/net/packet/af_packet.c
index a1b2c3d..d4e5f6g 100644
--- a/net/packet/af_packet.c
+++ b/net/packet/af_packet.c
@@ -3520,6 +3520,9 @@ static int packet_recvmsg(struct socket *sock,
        
        copied = skb->len;
        if (copied > len) {
+               /* Clamp to user-requested length */
+               err = -EMSGSIZE;
+               goto out_free;
                copied = len;
        }
```

**Analysis:**
- Before: `copied = len` even when `len > skb->len` — but wait, it's the other way: `copied = skb->len` → then copying `copied` bytes. The patch adds a check before the copy.
- This reveals: sending a crafted packet where the length prefix exceeds actual data → OOB read

### Kernel Module Analysis

```bash
# Extract and analyze kernel modules from target system
# .ko files are ELF shared objects
file vuln_module.ko  # ELF 64-bit LSB relocatable

# Disassemble with objdump
objdump -d vuln_module.ko | grep -A 20 "proc_write"

# Load into Ghidra with IOCTL analysis
# Look for copy_from_user / copy_to_user with unchecked sizes
```

---

## Chrome/Firefox Security Patches

Browser security patches are disclosed with varying detail:

### Chromium Vulnerability Workflow

```
1. CVSS score assigned → minimal info until patch ships
2. Bug filed as chromium.googlesource.com issue (restricted)
3. Patch lands in Chromium repository (public)
4. Chrome Beta released with fix
5. Chrome Stable released (typically 4-6 weeks after Beta)
6. Bug report made public (typically 90 days after fix, or when major version ships)
```

```bash
# Find Chrome security patches
# Search Chromium source for "Security:" or CVE references
git clone https://chromium.googlesource.com/chromium/src
git log --oneline --grep="Security:" -- v8/ | head -20

# Find specific CVE patch
git log --all --grep="CVE-2024-" -- third_party/blink/ | head -10

# Diff the V8 change
git show <commit> -- v8/src/compiler/
```

### Mozilla Firefox

```bash
# Mozilla uses Bugzilla with security bugs initially restricted
# View landed patches via mercurial:
hg clone https://hg.mozilla.org/mozilla-central/
hg log -r "keyword('CVE-2024')" --template "{rev}:{node|short} {desc|firstline}\n"
```

---

## CVE Advisory Interpretation

### CVSS Vector Analysis

CVSS (Common Vulnerability Scoring System) v3.1 vector encodes:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

AV: Attack Vector
  N=Network, A=Adjacent, L=Local, P=Physical

AC: Attack Complexity  
  L=Low, H=High

PR: Privileges Required
  N=None, L=Low, H=High

UI: User Interaction
  N=None, R=Required

S: Scope
  U=Unchanged, C=Changed

C/I/A: Confidentiality/Integrity/Availability Impact
  N=None, L=Low, H=High
```

**Translating CVSS to exploitation:**
```
AV:N + AC:L + PR:N + UI:N = unauthenticated network attack, low complexity
→ Highest priority for exploitation research

AV:L + PR:H = requires local access and admin privileges
→ Lower priority (post-exploitation use only)

S:C (Scope Changed) = vulnerability in one component affects another
→ Common in hypervisor escapes (VM → host), container breakouts, browser renderer → OS

C:H/I:H/A:H = full triad impact
→ Likely full system compromise possible
```

### Affected Versions

```bash
# Parse affected versions from NVD API
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-12345" | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
cve = data['vulnerabilities'][0]['cve']
print('Description:', cve['descriptions'][0]['value'])
print('\nAffected configurations:')
for config in cve.get('configurations', []):
    for node in config.get('nodes', []):
        for cpe in node.get('cpeMatch', []):
            if cpe['vulnerable']:
                print(f\"  {cpe['criteria']} version {cpe.get('versionStartIncluding','?')} to {cpe.get('versionEndExcluding','?')}\")"
```

---

## 1-Day Exploitation Timeline

The exploitation window after patch release:

```
Day 0:   Patch released (Patch Tuesday, security advisory)
         → Researchers begin diffing
Day 1-3: Binary diff complete, bug class identified
         → PoC development begins
Day 3-7: PoC crash achieved, root cause confirmed
Day 7-14: Primitive development (arbitrary read/write)
Day 14-30: Reliable exploit development
Day 30+:  Weaponized, integrated into offensive frameworks

Fastest documented 1-days: 24-72 hours for simple bugs
Average: 7-21 days for memory corruption
Longest: months for complex interaction-required chains
```

### Tracking Patch Adoption

```bash
# Shodan: find unpatched systems (example: Exchange Server)
shodan search "X-OWA-Version: 15.1" --fields ip_str,port,org

# Censys: find systems with specific version strings
python3 - << 'EOF'
import requests
r = requests.get(
    "https://search.censys.io/api/v2/hosts/search",
    params={"q": "services.banner: 'Server: Microsoft-IIS/10.0'"},
    auth=("api_id", "api_secret")
)
data = r.json()
print(f"Unpatched IIS 10.0 hosts: {data['result']['total']}")
EOF
```

---

## Public Vulnerability Databases

### NVD (National Vulnerability Database)

```bash
# NVD API v2
# Search by keyword
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=heap+overflow&resultsPerPage=10" | \
  python3 -m json.tool

# Search by CWE
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-120&pubStartDate=2024-01-01T00:00:00.000&resultsPerPage=20"

# Recent critical CVEs
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=CRITICAL&pubStartDate=2024-01-01T00:00:00.000&resultsPerPage=5"
```

### ExploitDB

```bash
# Search ExploitDB locally (Kali)
searchsploit apache 2.4
searchsploit --cve 2024-12345

# Update database
searchsploit -u

# Copy exploit to working directory
searchsploit -m exploits/linux/remote/12345.py

# Online search
curl "https://www.exploit-db.com/search?cve=2024-12345" -o results.html
```

### Following Disclosure: Project Zero 90-Day Policy

Project Zero's disclosure policy:
- Bug reported to vendor in private
- 90-day clock starts on report date
- If unpatched at day 90 → public disclosure
- If patch is in beta or release: additional 14-day grace period
- "Policy Compliant Bypass": technical bypass of the fix → new 90 days

```bash
# Monitor Project Zero bug tracker
# https://bugs.chromium.org/p/project-zero/issues/list
# Filter: Type=Bug, Status=Fixed, restrict_view=SecurityTeam

# RSS feed for new PZ disclosures
curl -s "https://bugs.chromium.org/p/project-zero/issues/list?q=type%3Dbug&can=1" \
  | grep -oP 'b/\d+' | head -10 | while read id; do
    echo "Bug $id: https://bugs.chromium.org/p/project-zero/issues/detail?id=${id#b/}"
done
```

### ZDI (Zero Day Initiative)

ZDI operates the largest vendor-neutral bug bounty program, purchasing vulnerabilities and coordinating disclosure:

```
ZDI Process:
1. Researcher submits (private): ZDI evaluates
2. ZDI purchases: researcher paid immediately
3. ZDI reports to vendor: disclosure coordinated
4. Vendor patches: typically 120 days
5. ZDI publishes advisory: ZDI-YY-NNNN format

ZDI advisories include: CVSS score, affected version, bug class
(often limited PoC details until later)
```

```bash
# Parse ZDI advisories via RSS
curl -s "https://www.zerodayinitiative.com/rss/published" | \
  python3 -c "
import sys
from xml.etree import ElementTree as ET
tree = ET.parse(sys.stdin)
for item in tree.findall('.//item'):
    title = item.find('title').text
    link = item.find('link').text
    print(f'{title}')
    print(f'  {link}\n')"
```

---

## Variant Analysis

After finding a CVE, search for unfixed related bugs:

```bash
# If CVE-2024-XXXXX is a heap overflow in function X,
# search for similar patterns in related functions

# Find all functions that use the same pattern
rg "memcpy\([^,]+,\s*[^,]+,\s*user_" --type c -l

# CodeQL variant analysis
codeql query run variant_of_cve.ql --database target-db

# In Ghidra: script to find similar basic block patterns
# Write Python script that finds functions with similar instruction sequences
```

### Patch Bypass Discovery

Some patches fix only one path to the bug, leaving others open:

```
Original bug: malloc(user_len) where user_len unchecked
Patch: add if (user_len > MAX) return ERROR

Bypass analysis:
- Is MAX correctly calculated? Off-by-one?
- Are there other callers of the vulnerable function that bypass the check?
- Can user_len be manipulated to be negative (wraps to large positive)?
- Is the check done before or after any arithmetic on user_len?
```
