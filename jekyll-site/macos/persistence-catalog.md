---
layout: training-page
title: "macOS Persistence Catalog — Red Team Academy"
module: "macOS"
tags:
  - macos
  - persistence
  - launchd
  - launchagent
  - launchdaemon
  - login-items
  - cron
page_key: "macos-persistence-catalog"
render_with_liquid: false
---

# macOS Persistence Catalog

macOS has roughly fifteen distinct persistence vectors at any given OS version, and the list shifts with each macOS release as Apple deprecates older mechanisms and adds new restrictions. This page is the working catalog — what each vector is, how it looks on disk, what defender telemetry it produces, and the relative noise level. The catalog is for understanding the mechanism so operators can predict which vectors are still viable on a given target and so defenders know what to instrument.

Each section pairs the technique with what the Endpoint Security framework or Unified Log will surface — which is what every Mac EDR (Jamf Protect, CrowdStrike Falcon for Mac, SentinelOne, BlockBlock, Objective-See suite) sees.

## The Big Three — launchd

launchd is the system supervisor. It loads plist files on a schedule and runs the binaries they describe. Three location classes:

| Location | Context | Persistence reach |
|---|---|---|
| `~/Library/LaunchAgents/` | User session | Per-user, runs at user login |
| `/Library/LaunchAgents/` | User session, system-wide | Every user that logs in |
| `/Library/LaunchDaemons/` | Root context, system-wide | Always running |
| `/System/Library/LaunchAgents/` | SIP-protected | Generally not writable |
| `/System/Library/LaunchDaemons/` | SIP-protected | Generally not writable |

The plist is a small XML or binary plist with keys including `Label`, `ProgramArguments`, `RunAtLoad`, `KeepAlive`, `StartInterval`, `StartCalendarInterval`. Sample:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.legitlooking</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/Shared/.runtime/helper</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

Loading the plist:

```
launchctl load ~/Library/LaunchAgents/com.example.legitlooking.plist
launchctl list | grep example
launchctl unload ~/Library/LaunchAgents/com.example.legitlooking.plist
```

**Defender telemetry**: `ES_EVENT_TYPE_NOTIFY_CREATE` and `ES_EVENT_TYPE_NOTIFY_WRITE` on the plist file, plus Unified Log entries from `com.apple.xpc.launchd` on load. KnockKnock (Objective-See) and equivalent EDR tools enumerate all LaunchAgents/LaunchDaemons in known locations on demand. **Noise level: high.** Every Mac EDR catches this.

## Login Items (Modern, macOS 13+)

Starting in macOS 13 Ventura, Apple introduced a new Background Items framework. Apps register their persistent components via `SMAppService` (replacement for older `SMLoginItemSetEnabled`). The user sees a system notification when a new background item is added, and can review them in System Settings → General → Login Items.

```
# View registered background items (per user)
defaults read /var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v9.btm 2>/dev/null
# (or via the dedicated frameworks API)

# View login items the legacy way
osascript -e 'tell application "System Events" to get the name of every login item'
```

**Defender telemetry**: Background Task Management framework events. The user-visible notification is the strongest signal — defenders cannot mute the OS-level notification, which means this technique is noisy by design on modern macOS.

## Login Items (Legacy)

Before macOS 13, login items were managed via the deprecated `SMLoginItemSetEnabled` API and the underlying `~/Library/Application Support/com.apple.backgroundtaskmanagement/` directory. The legacy path is still functional on older systems and frequently used by older malware.

**Noise level: moderate to high on macOS 13+, moderate on older.**

## Cron and atd

The traditional Unix cron is supported but heavily defanged:

```
# Per-user crontab
crontab -e
crontab -l

# System crontab
sudo nano /etc/crontab

# Periodic scripts (run daily/weekly/monthly)
ls /etc/periodic/daily/
ls /etc/periodic/weekly/
ls /etc/periodic/monthly/
```

cron requires **Full Disk Access** to read its database on modern macOS, which is itself a TCC-gated permission. This makes cron persistence loud — adding a cron job triggers a TCC dialog on most modern Mac configurations.

**Noise level: very high on modern macOS due to TCC dialog.**

## Login Hooks (Deprecated)

```
# Legacy login hook (deprecated since 10.7 but still functional on older systems)
sudo defaults write com.apple.loginwindow LoginHook /path/to/script
```

Functional on old systems; defenders look for the specific defaults key.

**Noise level: high — well-known IOC pattern.**

## Configuration Profiles (PPPCs and General)

Configuration profiles can grant TCC entitlements, modify settings, and install certificates. A locally-installed profile (not pushed via MDM) requires admin password and produces a System Settings notification.

```
# View installed profiles
profiles list
profiles show -type configuration
```

A maliciously-pushed PPPC via compromised MDM grants TCC entitlements silently. **Noise level**: very high for local install (user sees prompt); silent if pushed via MDM admin compromise.

## Kernel Extensions (Deprecated)

KEXTs require Apple signing and explicit user/MDM approval on modern macOS. On Apple Silicon Full Security, KEXTs cannot load. **Noise level: extreme** — KEXT loading is heavily logged and user-visible. Effectively extinct for operational use.

## System Extensions and Endpoint Security

The modern replacement for KEXTs. `/Library/SystemExtensions/` houses installed system extensions, including Network Extensions, Endpoint Security extensions, and DriverKit extensions. Installation requires user approval through System Settings → Privacy & Security.

**Noise level: very high** — surfaces in MDM inventory, EDR enumeration, and System Settings UI.

## Dock and Finder Plist Hijacks

```
# Modify Dock items
defaults write com.apple.dock persistent-apps -array-add ...

# Modify Finder sidebar
defaults write com.apple.finder ...
```

Persistence-by-visibility — relies on the user clicking a Dock item or Finder shortcut. Limited operational value alone.

## App Bundle Modification

Modifying a frequently-launched `.app` bundle's `Info.plist` or `MacOS/<executable>` to chain through attacker code. Modern macOS hardened-runtime apps will fail codesigning checks if modified. Affects ad-hoc-signed apps more than identified-developer apps.

**Noise level: moderate** — codesign mismatch is visible if defender checks.

## Shell Configuration Files

```
~/.zshrc       # zsh interactive
~/.zprofile    # zsh login
~/.zshenv      # zsh on every invocation (most useful for persistence)
~/.bashrc / ~/.bash_profile      # bash (default shell pre-Catalina)
/etc/zshenv    # system-wide zsh
```

Execute every time the user opens Terminal. Limited reach (only triggers when user uses shell), but easy to plant. **Noise level: low** unless defender specifically monitors these files.

## SSH Configuration

```
# Add SSH key persistence
echo "ssh-rsa AAAAB3...attacker-key" >> ~/.ssh/authorized_keys

# ProxyCommand abuse in SSH config
~/.ssh/config:
    Host innocent
        HostName real.target
        ProxyCommand /path/to/attacker-binary
```

Requires Remote Login enabled (a System Settings toggle, defender-visible). SSH key on `~/.ssh/authorized_keys` is straightforward but requires the user/operator to come back via SSH.

**Noise level: low for the file write; high for enabling Remote Login if not already on.**

## Re-Open Apps After Reboot

```
~/Library/Saved Application State/<bundle>.savedState/
```

Apps that the user had open at shutdown get reopened. Modifying these can chain attacker code into a re-opened app. Limited utility.

## Periodic / Software Update Hooks

Files in `/etc/periodic/` run on schedule. Software Update hooks run on update install. Both produce TCC dialogs on modern macOS for the persistence mechanism.

## TCC.db Modification (Persistence by Permission)

Modifying user TCC.db to grant attacker process broad permissions — covered at length in `/macos/tcc-bypass`. This is "persistence by capability inheritance" rather than "persistence by run-on-boot." Often paired with a launchd persistence above.

## Defender Detection Signal Summary

| Vector | ES Event | Unified Log | EDR catch rate |
|---|---|---|---|
| LaunchAgent / LaunchDaemon | NOTIFY_CREATE on plist | xpc.launchd subsystem | ~99% |
| SMAppService / Background Items | BackgroundTaskMgmt events | systemmanager subsystem | High; user-notification too |
| Legacy SMLoginItem | BackgroundTaskMgmt events | systemmanager | Moderate |
| Cron | TCC dialog before install | tcc subsystem | High due to TCC |
| Login Hooks | defaults command | defaults subsystem | High — known IOC |
| Configuration Profiles | profile install event | mdmclient | High; user sees install |
| Kernel Extensions | KEXT load event | kxlserver | Extreme |
| System Extensions | extension install event | sysextd | Extreme |
| Dock plist hijack | NOTIFY_WRITE on com.apple.dock | dock subsystem | Low — often missed |
| App bundle modification | codesign failure | codesign subsystem | Moderate |
| Shell rc files | NOTIFY_WRITE on user files | varies | Low unless monitored |
| SSH authorized_keys | NOTIFY_WRITE | ssh subsystem | Moderate |
| TCC.db write | NOTIFY_TCC_MODIFY | tcc subsystem | High on EDR-equipped hosts |

## Apple Silicon and Boot-Time Considerations

- Recovery mode access requires physical or remote-recovery-OS — not reachable via SSH on a running system
- 1TR mode (One True RecoveryOS) is Apple Silicon-specific
- The boot volume is cryptographically sealed; persistence must land outside the system volume
- Reduced Security vs Full Security policy affects what kexts/system extensions are loadable

## Cross-References

- `/macos/tcc-bypass` — TCC.db modifications and inheritance
- `/macos/sip-bypass` — what SIP protects and where persistence is forced to live
- `/macos/gatekeeper-xprotect` — first-launch evaluation that interacts with new persistence
- `/macos/mdm-jamf-kandji-abuse` — MDM as a persistence-distribution channel
- `/post-exploitation/macos-red-team` — operator post-ex broader content

## Resources

- Apple's official launchd documentation
- Patrick Wardle / Objective-See — long-running coverage of Mac persistence
- *The Art of Mac Malware* (Wardle) — persistence chapter
- Csaba Fitzl — persistence-vector research blog
- Apple's Endpoint Security framework documentation
- Jaron Bradley, *OS X Incident Response*
- Objective-See's annual Mac Malware Report — persistence statistics
- BlackHat / Defcon Mac talks on persistence (multiple years)
