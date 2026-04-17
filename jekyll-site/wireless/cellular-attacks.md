---
layout: training-page
title: "Cellular & GSM Security — Red Team Academy"
module: "Wireless"
tags: [cellular, gsm, imsi-catcher, stingray, ss7, sms-intercept, 4g, 5g, sdr]
page_key: "wireless-cellular-attacks"
render_with_liquid: false
updated: "2026-04-17"
---

# Cellular & GSM Security

## Overview

Cellular network security has improved significantly from GSM (2G) through 4G LTE and into 5G NR — but older standards remain in use globally, legacy protocol weaknesses persist in deployed infrastructure, and SS7 (the backbone signaling protocol of the public telephone network) retains decades-old vulnerabilities that affect modern SIM cards. This page covers the security architecture of each generation, known attack techniques, and their practical applicability in red team contexts.

**Critical legal notice**: IMSI catcher operation, active cellular interception, and SS7 exploitation without authorization is illegal in virtually all jurisdictions worldwide. These are serious federal offenses in the US (18 U.S.C. § 2511 — ECPA, FCC regulations) and equivalent laws elsewhere. SS7 access requires being a licensed telecommunications carrier or exploiting a compromised carrier. This content is for defensive understanding and authorized research in isolated lab environments only.

## Cellular Security Architecture by Generation

```
# GSM (2G) — Fundamental security flaws:
#
# Authentication: One-way only — phone authenticates to network (A3 algorithm)
#                 Network does NOT authenticate to phone
#                 A fake base station (IMSI catcher) can impersonate any tower
#
# Encryption: A5/1 (stream cipher, 64-bit effective key — crackable with rainbow tables)
#             A5/2 (deliberately weakened for export — trivially broken)
#             A5/0 (no encryption — transmitted in plaintext)
#             Encryption on air interface only — decrypted at base station
#
# Identifiers: IMSI (International Mobile Subscriber Identity) sent in cleartext
#              on first registration and when network requests it
#
# Known attacks: A5/1 rainbow table attack, IMSI catchers, null encryption downgrade

# UMTS / 3G — Improved but incomplete:
# Mutual authentication: both phone and network authenticate
# AKA protocol (Authentication and Key Agreement)
# But: still susceptible to IMSI catchers that downgrade to 2G
# And: integrity protection was optional (not always enforced)

# LTE / 4G — Significantly stronger:
# Mandatory mutual authentication via EPS-AKA
# IPsec-based NAS layer protection
# IMSI sent encrypted in most cases (GUTI replaces IMSI in most messages)
# Integrity protection mandatory for NAS and RRC
# But: IMSI still exposed in initial attachment request
#      No protection against SS7 attacks (operates at different layer)
#      Some implementation vulnerabilities (RACH timing attacks, RRC replay)

# 5G NR — State of the art:
# SUCI (Subscription Concealment Identifier) — IMSI always encrypted
#   ECIES-based encryption using home network's public key
# Mutual authentication mandatory
# Improved key derivation (128/256-bit)
# Better forward secrecy (key separation)
# Still vulnerable: downgrade attacks in NSA mode (5G NR + 4G LTE core)
#                  SS7 attacks (backhaul still often uses SS7)
#                  Implementation vulnerabilities in specific vendors
```

## IMSI Catchers (Stingray)

IMSI catchers are devices that impersonate legitimate cellular base stations. Phones in the area connect to the fake tower, allowing the operator to collect IMSI numbers, track device locations, and in GSM, intercept calls and SMS. Understanding IMSI catchers is essential for red teams assessing physical surveillance risks.

```
# How IMSI catchers work:

# Step 1: Beacon as strongest base station
# IMSI catcher transmits on target carrier frequency with high TX power
# Nearby phones see it as the strongest signal → attempt registration

# Step 2: Force IMSI disclosure (GSM)
# Network sends Identity Request message → phone sends its IMSI in plaintext
# IMSI = unique 15-digit number tied to SIM card / subscriber identity

# Step 3: Force downgrade (4G/5G targets)
# LTE-capable IMSI catchers deny LTE service → phone falls back to GSM
# On GSM: standard IMSI collection applies
# Modern (5G) IMSI catchers can operate at LTE level — collect GUTI then request IMSI

# Hardware for research (lab/authorized use only):
# BladeRF 2.0 micro + OpenBTS + YateBTS — software-defined LTE/GSM base station
# LimeSDR + srsRAN (formerly srsLTE) — open-source LTE stack
# USRP B210 + OpenBTS — classic research platform
# Commercial IMSI catchers (Harris StingRay, Boeing DRT): law enforcement only

# --- Detection of IMSI catchers ---
# SnoopSnitch (Android — requires root): detects suspicious base station changes
# AIMSICD (Android IMSI Catcher Detector): monitors for weak ciphering, ID requests
# Watch for: sudden 2G downgrade in area with strong 4G coverage
#            Unusual "No Service" followed by reconnection
#            Battery drain spike (constant re-registration)
```

## GSM Passive Monitoring

GSM downlink traffic is broadcast over the air. With appropriate hardware and software, A5/1-encrypted GSM traffic can be captured and cracked using pre-computed rainbow tables (Kraken attack). Unencrypted channels (BCCH, paging) are always readable without any cryptanalysis.

```
# gr-gsm — GSM capture and decoding with RTL-SDR:
# https://github.com/ptrkrysik/gr-gsm

sudo apt install gr-gsm

# Identify GSM towers:
grgsm_scanner -b GSM900 -s 2000000 -v
# Output: ARFCN, frequency, MCC, MNC, cell ID, signal strength

# Capture BCCH (Broadcast Control Channel — always unencrypted):
grgsm_livemon -f 945.2M  # Replace with local BCCH frequency from scanner
# Outputs decoded system information frames to stdout

# Capture downlink traffic on specific ARFCN:
rtl_sdr -f 945200000 -s 2000000 - | grgsm_decode -c 45 -s 2000000 -o /tmp/capture.cfile
# -c = ARFCN number

# Feed decoded frames to Wireshark for protocol analysis:
# grgsm_livemon sends GSM frames to localhost UDP 4729
wireshark -k -Y gsmtap -i lo

# --- Kraken A5/1 attack (rainbow table crack) ---
# A5/1 rainbow tables: ~2TB, available via Cryptome / A51 cracking project
# Hardware: GPU cluster or dedicated FPGA (Rivyera S6-LX150)
# Process:
# 1. Capture enough A5/1 ciphertext frames (need ~26 known-plaintext pairs)
# 2. Use known GSM frame structure (known patterns in certain frame types)
# 3. Query rainbow table → recover session key Kc (64-bit)
# 4. Decrypt full call/SMS session

# OsmocomBB — phones for active GSM experimentation:
# Compatible phones: Motorola C118, C123, C155 (with Calypso baseband)
# Calypso baseband has open-source firmware: https://osmocom.org/projects/baseband
# Capabilities: active layer 1 access, raw frame capture
# Mobile suite: osmocon, mobile, l1ctl-sock for baseband communication
```

## SS7 (Signaling System 7) Vulnerabilities

SS7 is the signaling backbone of the global public telephone network, developed in the 1970s. It routes calls, SMS, and roaming between carriers worldwide. Despite its age, it handles billions of communications daily. The trust model is completely broken — any SS7 node can make requests for any subscriber globally, and there is no meaningful authentication between operators.

```
# SS7 attack prerequisites:
# - Direct SS7 network access (requires: being a licensed telco, compromising a telco,
#   purchasing access from a fraudulent SS7 provider, or using a test network)
# - This is NOT something achievable with consumer hardware
# - Academic research and nation-state actors are the primary practitioners

# Key SS7 attack categories:

# --- Location tracking (SendRoutingInfo for SM) ---
# Any SS7 node can query the Home Location Register (HLR) for a subscriber's location
# Message: MAP SendRoutingInfoForSM (SRI-for-SM)
# Response: HLR returns: current VLR address → identifies city/carrier area
#           Also returns: IMSI
# Precision: country or city level from HLR; combined with other queries → cell tower

# SigPloit framework (SS7 attack framework):
# https://github.com/SigPloiter/SigPloit
git clone https://github.com/SigPloiter/SigPloit
# Requires: SS7 network access (simulated with test environment)

# Location tracking via sendRoutingInfo:
python3 SigPloit.py
# → SS7 menu → Location Tracking → SendRoutingInfo
# Input: target MSISDN (phone number in E.164 format: +12125551234)

# --- SMS interception (ForwardSM attack) ---
# Attacker manipulates subscriber's SMS routing in the HLR
# Attack flow:
# 1. Send InsertSubscriberData to victim's HLR → update SMS gateway to attacker's node
# 2. SMS for victim now route through attacker's node
# 3. Attacker receives, reads, and optionally forwards SMS
# Impact: intercept SMS 2FA codes → bypass SMS-based authentication

# --- Call interception (RegisterSS) ---
# Attacker registers a supplementary service (call forwarding) on victim's number
# MAP RegisterSS with ForwardingData pointing to attacker's number
# All calls to victim forwarded to attacker's control number

# --- Tools ---
# SigPloit: https://github.com/SigPloiter/SigPloit
# SS7map: https://github.com/ernw/ss7map — SS7 network topology mapping
# Osmocom (open-source SS7 stack): http://osmocom.org
# pySS7: Python SS7 implementation for research

# Defensive measures:
# - SS7 Firewall (deployed by major carriers to block MAP message abuse)
# - SS7 anomaly detection (Cellusys, Mobileum — commercial SS7 security platforms)
# - GSMA FS.11 security guidelines for SS7 interconnect
```

## SIM Swapping

SIM swapping is a social engineering attack against mobile carriers. The attacker convinces a carrier's customer service to transfer the victim's phone number to a SIM the attacker controls. Once successful, the attacker receives all calls and SMS — including 2FA codes for bank accounts, email, and cryptocurrency.

```
# SIM swap attack chain:
#
# 1. OSINT: gather victim's full name, DOB, last 4 of SSN, account PIN
#    Sources: data breaches, LinkedIn, Facebook, public records, people-search sites
#
# 2. Contact carrier: call or visit store, impersonate victim
#    "I lost my phone, need to transfer my number to this new SIM"
#    Common verification: name + address + last 4 SSN + account PIN (or billing amount)
#
# 3. SIM transfer complete: victim's number now on attacker's SIM
#    Victim loses service immediately (carrier sends "Welcome to [Carrier]" to attacker's SIM)
#
# 4. Account takeover:
#    Trigger password reset on target account (bank, email, crypto)
#    2FA SMS received on attacker's SIM
#    → Full account access

# Notable SIM swap cases:
# - Jack Dorsey (Twitter CEO) phone hacked via SIM swap 2019
# - $24M cryptocurrency theft via SIM swap (SEC charges 2023)
# - Michael Terpin lawsuit: AT&T $224M verdict (2018, appeal)

# Defensive measures for personal/enterprise:
# - Enable carrier account PIN (separate from account password)
# - Request "SIM lock" / "port freeze" with carrier
# - Use authenticator apps (TOTP) instead of SMS for 2FA
# - Use hardware security keys (YubiKey) for critical accounts
# - Enterprise: use number-based MFA alternatives (Microsoft Authenticator phone sign-in)

# Red team applicability:
# SIM swapping may be in scope for social engineering engagements targeting executives
# Requires: explicit authorization covering social engineering against carrier
# Document: exact carrier contacted, script used, what verification was bypassed
```

## 5G NR Security Improvements

```
# What 5G NR actually improves over LTE:

# SUCI (Subscription Concealment Identifier):
# IMSI replaced by SUCI in all air interface transmissions
# SUCI = ECIES encryption of IMSI using home network's public key
# Only the home network can decrypt SUCI → attacker cannot extract IMSI from OTA capture
# Defeat: IMSI catchers cannot passively collect subscriber identities from 5G NR

# Improved AKA:
# 5G-AKA and EAP-AKA' both include proof of freshness
# Reduces IMSI catcher downgrade effectiveness at 5G layer

# Network slicing security:
# Logical network isolation via slices
# Each slice has independent authentication context
# Misconfigured slice isolation → cross-slice data access (emerging research)

# What is NOT fixed in 5G:
# NSA (Non-Standalone) mode: 5G NR radio + 4G LTE core
#   → Falls back to LTE security model, losing 5G improvements
# SS7 backhaul: 5G core may still interconnect with legacy SS7 infrastructure
# Diameter (4G signaling protocol): similar vulnerabilities to SS7, affects 5G VoNR
# Implementation flaws: vendor-specific bugs in 5G implementations (ongoing research)
# Tracking via GUTI: while IMSI protected, GUTI (Globally Unique Temp ID) changes
#   are sometimes infrequent → medium-term tracking still possible

# Emerging 5G attack research:
# 5GReasoner (2019): logic flaws in 5G NR protocols — authentication bypass, denial of service
# IMSI-trap attacks against 5G NSA mode deployments
# Diameter protocol attacks affecting 5G core interconnect
```

## Practical Red Team Scenarios

```
# Scenario 1: Executive tracking during physical pentest
# Objective: demonstrate physical security risk — verify target is on-site
# Method: IMSI catcher (authorized research device, authorized engagement)
# Scope requirement: explicit written authorization including IMSI catcher deployment
# Precautions: legal counsel review, limit to authorized personnel only

# Scenario 2: SS7 demonstration (in authorized isolated lab environment)
# Objective: demonstrate carrier-level attack risk to telecom client
# Method: isolated SS7 test environment (not connected to live SS7 network)
# Simulate: SRI-for-SM location disclosure, ForwardSM interception
# Deliverable: proof-of-concept with screenshots from lab environment

# Scenario 3: SIM swap in social engineering scope
# Objective: demonstrate multi-factor bypass via carrier social engineering
# Scope requirement: explicit SIM swap authorization, carrier identified in scope
# Method: call carrier, attempt to SIM swap pre-identified test phone number
# Document: call recording, representative name, what information they accepted

# Scenario 4: GSM downlink monitoring (authorized test lab)
# Objective: demonstrate GSM encryption weakness to enterprise client
# Method: RTL-SDR + gr-gsm capture BCCH frames from test SIM
# Deliverable: demonstration of unencrypted system information leakage
```
