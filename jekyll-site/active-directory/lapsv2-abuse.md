---
layout: training-page
title: "Windows LAPS (v2) Abuse — Red Team Academy"
module: "Active Directory"
tags:
  - laps
  - windows-laps
  - lapsv2
  - local-admin
  - credential-access
  - entra
  - encrypted-passwords
page_key: "ad-lapsv2-abuse"
render_with_liquid: false
---

# Windows LAPS (v2) Abuse

Windows LAPS (sometimes called LAPS v2) is Microsoft's 2023 rewrite of the Local Administrator Password Solution. It replaced the venerable Legacy LAPS (Microsoft LAPS, the 2015-era MSI) with a built-in Windows component that supports both Active Directory and Microsoft Entra ID as password storage backends, adds password encryption, and ships with Windows 10/11 and Windows Server 2019+ out of the box. The change matters operationally — the attack surface against LAPS-protected environments shifted with the v2 design, and operators trained on Legacy LAPS need to recalibrate.

This page covers Windows LAPS architecture, the AD-backed and Entra-backed deployment modes, the encryption model, what attackers can and cannot do under each configuration, and the defender controls that determine whether the deployment actually delivers its promised hardening.

## Why LAPS Matters

LAPS solves a recurring AD-security problem: the local administrator password on every Windows endpoint, historically identical across the fleet because IT ops set one image and deployed it everywhere. A single compromised endpoint with that shared local admin yields lateral movement to every endpoint in the fleet — the classic Pass-the-Hash playbook.

LAPS rotates the local admin password per endpoint, stores it in a directory (AD or Entra), and authorizes specific identities to read it. The "shared local admin = lateral movement" problem goes away. In its place, the attack surface becomes "who can read the LAPS password" — which is what the operator now hunts.

## Legacy LAPS (Microsoft LAPS, 2015-2023)

Briefly, for comparison:

- Installed via MSI
- Stored password in cleartext in the `ms-Mcs-AdmPwd` AD attribute
- Read access controlled by ACL on that attribute
- No encryption at rest in AD (cleartext attribute, protected only by ACL)
- Read by anyone with `ReadProperty` on `ms-Mcs-AdmPwd` for the target computer object

Attacker path against Legacy LAPS: enumerate which identities have ReadProperty on the AD attribute, compromise one of those identities, query the attribute. Standard tools: `Get-LAPSPasswords` (PowerView), `LAPSToolkit`, `PingCastle`, `BloodHound` (which surfaces the readable-attribute relationship).

## Windows LAPS (v2, 2023+)

Architecturally:

- Built into Windows (no MSI needed) — enabled via group policy or Intune policy
- Storage: AD or Microsoft Entra ID (the Entra mode is the major addition)
- AD-stored password uses **AD-side attribute** `ms-LAPS-Password` (plaintext-equivalent under attribute ACL) OR `ms-LAPS-EncryptedPassword` (encrypted with a DPAPI-NG key)
- Entra-stored password is encrypted in Entra
- Password rotation policy configurable
- Password history retained on AD-backed mode (configurable)

### AD-Backed Mode — Encryption

In AD-backed mode, three storage forms exist:

| Attribute | Form | Notes |
|---|---|---|
| `ms-LAPS-Password` | Plaintext (within ACL) | Default if encryption not configured |
| `ms-LAPS-EncryptedPassword` | DPAPI-NG encrypted | Encryption-enabled mode |
| `ms-LAPS-EncryptedPasswordHistory` | DPAPI-NG encrypted history | If history configured |

The "DPAPI-NG encrypted" mode is the v2 improvement. The encryption key is a domain-controller-protected key that an authorized identity can decrypt. Without authorization, the encrypted blob is opaque.

### Entra-Backed Mode

The password lives in Entra (formerly Azure AD). The retrieval API is `Microsoft Graph` — specifically the `deviceLocalCredentials` resource. Retrieval requires:

- The device must be Entra-joined or Entra hybrid-joined
- The caller must have `DeviceLocalCredential.Read.All` Graph permission (granted via Intune Service Administrator role or via a custom role)
- The caller's tenant context must match the device's tenant

The encryption-at-rest in Entra is Microsoft-managed. From the operator's perspective, Entra-backed LAPS shifts the attack surface from "AD ACL on attribute" to "Entra role with Graph permission."

## Attack Paths

### AD-Backed Plaintext Mode

If LAPS is configured but encryption is not enabled, the attack is essentially identical to Legacy LAPS:

```
# PowerView equivalent for the v2 attribute name
Get-DomainComputer -Properties dnshostname,ms-LAPS-Password | Where-Object {$_.'ms-LAPS-Password' -ne $null}

# Or direct LDAP query as authorized identity
Get-ADComputer -Filter * -Properties ms-LAPS-Password | Where-Object {$_.'ms-LAPS-Password' -ne $null}

# BloodHound: visualize who has ReadProperty on ms-LAPS-Password
# Bloodhound CE collects this; the relevant edge is ReadLAPSPassword
```

Operator workflow: BloodHound → find identities with ReadLAPSPassword → compromise one → query → local admin on the target endpoint.

### AD-Backed Encrypted Mode

Reading `ms-LAPS-EncryptedPassword` yields a DPAPI-NG blob. The blob can be decrypted only by an identity authorized for the encryption key. The authorized identities are configured via group policy.

The attack now has two prerequisites:
1. ReadProperty on the encrypted attribute (the same ACL check as before)
2. Decryption-authorization on the DPAPI-NG key

Standard tooling needs updating for the v2 encrypted-mode. Public research from Andy Robbins and others has documented the encrypted-mode attack path; tools to decrypt the v2-encrypted blob have appeared since 2023. Specific tooling:

- **`LAPSv2 PowerShell module`** — Microsoft's official module for managing v2; can also read passwords with appropriate identity.
- **`Get-LAPSADPassword`** (built-in PowerShell cmdlet) — reads and decrypts under the calling identity.
- Public attacker tooling under various names tracks the format.

The encrypted-mode raises the bar but does not eliminate the attack — it concentrates it on the authorized-decryption-identity tier.

### Entra-Backed Mode

For Entra-backed LAPS, the attack moves to Entra:

```
# Graph API call to retrieve a device local credential
GET https://graph.microsoft.com/v1.0/directory/deviceLocalCredentials/{deviceId}

# Requires DeviceLocalCredential.Read.All scope on the calling token
```

Operator workflow: compromise an Entra identity with `DeviceLocalCredential.Read.All` scope (Intune Service Administrator, custom roles that include this scope) → Graph API call → local admin password returned.

This is materially easier than AD-backed encrypted mode because the Entra Graph permission is more discoverable and the attack relies on Entra-side privilege rather than DPAPI-NG-key authorization. From the operator's perspective, Entra-backed LAPS is easier to attack post-Entra-admin-compromise.

## Tooling

| Tool | Use |
|---|---|
| **BloodHound CE** | Visualizes LAPS read paths, including v2 attribute |
| **ROADtools** | Entra-side enumeration, including Graph permissions on LAPS endpoints |
| **AADInternals** | Entra abuse including LAPS retrieval |
| **GraphRunner** | Graph API enumeration |
| **Native PowerShell `Get-LAPSADPassword`** | Standard cmdlet for AD-backed retrieval |
| **`Get-MgDeviceLocalCredential` (Graph PowerShell)** | Entra-backed retrieval |
| **PingCastle** | AD posture audit including LAPS coverage |

The detection-evading aspect of LAPS read operations is moderate — they generate LDAP queries (AD-backed) or Graph API calls (Entra-backed) that the SOC can monitor. Loud if monitored, invisible if not.

## Defender Controls

For each deployment mode:

### AD-Backed Encrypted Mode (Strongest AD-side)

- Enable `Authentication` setting in LAPS GPO with encryption-enabled
- Restrict the LAPS-key-authorized identity set to a tier-0 group
- Audit `ms-LAPS-EncryptedPassword` read events
- Monitor for `Get-LAPSADPassword` cmdlet executions outside known admin sources
- Periodic audit of LAPS history retention

### Entra-Backed Mode

- Minimize identities with `DeviceLocalCredential.Read.All` scope
- Conditional Access requiring managed device + FIDO2 for Intune admin role
- Audit log streaming for Graph LAPS-read events
- Detection rule on `deviceLocalCredentials` Graph API calls
- Privileged Access Management (PIM) for Intune Service Administrator

### Universal Controls

- Don't grant LAPS-read scope to broad groups
- Audit LAPS-read identities quarterly
- Detect LAPS-read events that don't match the on-call admin schedule
- Monitor BloodHound-collection events (the standard pre-LAPS-read enumeration)

## Engagement Considerations

For scoped AD engagements:

- LAPS-read is a high-fidelity attacker action — exploitation generally indicates the engagement reached a privileged-identity tier
- Recovery should be straightforward (the password rotation will replace the read value)
- Documentation of which identities had LAPS-read scope is consistently a high-value engagement finding

## Cross-References

- `/active-directory/azure-ad` — Entra surface relevant for Entra-backed LAPS
- `/active-directory/bloodhound` — the enumeration tool for AD-backed LAPS read paths
- `/active-directory/dcsync` — broader DA-tier credential-access context
- `/post-exploitation/intune-attacks` — Intune-admin compromise as Entra-backed LAPS path
- `/reporting/engagement-scoping-deep-dive` — engagement scoping for AD actions

## Resources

- Microsoft Learn — Windows LAPS overview and admin guide
- SpecterOps — Andy Robbins blog on LAPS v2 attack paths
- TrustedSec — multiple LAPS v2 research posts
- PingCastle documentation on LAPS audit
- BloodHound Community Edition release notes covering LAPS v2 edges
- ROADtools and AADInternals documentation on Entra-side LAPS
- Microsoft documentation on the `deviceLocalCredentials` Graph API
