---
layout: training-page
title: "The C2 Matrix — Framework Comparison — Red Team Academy"
module: "C2 Frameworks"
tags:
  - c2-matrix
  - comparison
  - c2-selection
  - frameworks
page_key: "c2-matrix"
render_with_liquid: false
---

# The C2 Matrix — Choosing a C2 for an Engagement

The **C2 Matrix** (maintained at `thec2matrix.com` by Jorge Orchilles and SANS) is the most complete public comparison of red-team C2 frameworks. It's a Google Sheet catalog graded against ~30 dimensions — use it when you need to pick a C2 that matches engagement constraints, when you're building a new C2 and want to see which features are table-stakes, or when you're writing a client deliverable that justifies your tool choice.

The companion site **howto.thec2matrix.com** hosts install/config walkthroughs for the cataloged frameworks plus the **Slingshot C2 Matrix Edition** — a pre-built Ubuntu VM with ~20 C2s installed side-by-side for comparison in a lab.

## Evaluation Dimensions

The Matrix scores each framework across roughly these axes. Use this list as your own selection checklist.

| Category | What to ask |
|----------|-------------|
| **API** | REST? Programmatic scriptable control? Python / Go bindings? |
| **Agents** | Which languages/runtimes (C, C#, Python, Go, Rust, PowerShell)? Architectures (x86/x64/ARM)? |
| **Channels** | HTTP/S, DNS, SMB named pipes, mail, cloud services? Custom/external listeners? |
| **Staging** | Stageless vs. staged? Reflective? BOF/OBJ loader? |
| **Evasion** | AMSI/ETW patching built in? Sleep obfuscation (Ekko/FOLIAGE)? Indirect syscalls? |
| **Malleability** | Malleable profile support? Proxy / CDN fronting? |
| **OPSEC** | Peer-to-peer agent modes (SMB)? Traffic fingerprint? Default JA3/JARM? |
| **Execution** | Execute-assembly, BOF, reflective DLL, PowerShell, Python, shellcode? |
| **Lateral Movement** | Built-in WMI / PsExec / DCOM / SCM / SSH modules? |
| **Pivoting** | Built-in SOCKS / port-forward / reverse-port-fwd? |
| **Logging** | What's captured server-side for attribution? Exportable for reports? |
| **Key Exchange** | TLS pinned? Mutual-auth? Post-quantum? |
| **Development Activity** | Last commit, release cadence, bus factor |
| **Documentation** | Wiki? Tutorials? Community size? |
| **Cost / License** | Free, open-source, paid, licensed-per-seat? |
| **Price** | Actual $ if commercial |
| **Kill Switch** | Built-in burn signal / self-destruct? |

## Top Frameworks Cataloged

The Matrix tracks 40+ C2s; the ones you'll actually encounter on engagements cluster into:

**Commercial / flagship**
- Cobalt Strike (Fortra)
- Brute Ratel C4 (Dark Vortex)
- Outflank OST
- Nighthawk (MDSec)

**Open-source full-featured**
- Havoc Framework
- Mythic
- Sliver (BishopFox)
- Empire (BC-SECURITY)
- Merlin
- Covenant

**Open-source specialized**
- PoshC2 (PoshC2)
- Silent Trinity (byt3bl33d3r)
- Pupy (n1nj4sec)
- Prism (Unit 8200 / academic)
- Caldera + Sandcat (MITRE)
- Metasploit / Meterpreter (Rapid7)
- Evil-WinRM (adjunct, not a C2)

## Using the Matrix for C2 Selection

For any engagement, run through this short script:

1. **Filter by constraint**
   - Target environment Windows-only? Drop frameworks without first-class Windows agents
   - OSX/iOS in scope? Only Mythic, Metasploit, and a handful of others have real coverage
   - Highly monitored EDR? Need Ekko/FOLIAGE sleep obfuscation + indirect syscalls out of the box
   - Air-gapped or highly egress-restricted? Need SMB P2P, DNS, or alternate channels
2. **Filter by capability**
   - Must execute BOFs? Cobalt Strike, Havoc, Mythic (via Apollo), Sliver (via extension)
   - Must support DNS covert channel? Cobalt Strike, Mythic, PoshC2
   - Multi-operator? Every modern commercial + Havoc + Mythic + Sliver
3. **Filter by budget**
   - Commercial frameworks cost $3k–$10k+/year per seat
   - Open-source has no license cost but has a support cost (you fix bugs)
4. **Filter by attribution concern**
   - Some DFIR vendors block on JA3/JARM of well-known OSS C2s by default
   - Malleable profiles and custom builds matter more for OSS than commercial

## Slingshot C2 Matrix Edition

A pre-built Ubuntu VM image with ~20 C2s and supporting tools installed side-by-side. Use it when:

- Learning — stand up a lab and beacon between frameworks on the same host
- Cross-framework redirection — Empire → foreign listener → Cobalt Strike (verify handoff works)
- Comparing traffic fingerprints in Wireshark without installing ten frameworks
- Team training — single VM per attendee instead of ten

Download: `c2matrix.com/slingshot-c2-matrix-edition/`

## Resources

- C2 Matrix site — `thec2matrix.com`
- C2 Matrix How-To — `howto.thec2matrix.com`
- Google Sheet (golden source) — linked from thec2matrix.com
- Slingshot C2 Matrix Edition — `c2matrix.com/slingshot-c2-matrix-edition/`
- Jorge Orchilles (maintainer) blog posts on new C2s
- See also: `c2-frameworks/cobalt-strike.md`, `sliver.md`, `havoc.md`, `mythic.md`, `empire.md`, `brute-ratel.md`, `c2-opsec.md`
