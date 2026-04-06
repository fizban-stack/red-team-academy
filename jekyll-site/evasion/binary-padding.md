---
layout: training-page
title: "Binary Padding & Oversized Files — Red Team Academy"
module: "Evasion"
tags:
  - binary-padding
  - edr-bypass
  - av-evasion
  - obfuscation
  - t1027
page_key: "evasion-binary-padding"
render_with_liquid: false
---

# Binary Padding & Oversized Files (T1027.001)

Many AV/EDR engines enforce file size limits and archive recursion caps to protect performance. Adversaries abuse these limits by padding executables with junk bytes and delivering payloads as small compressed archives that expand massively on extraction. Trellix documented real campaigns where 77 KB ZIPs expanded to 664 MB executables, routinely bypassing size-limited scans.

MITRE ATT&CK: **T1027.001 — Obfuscated Files or Information: Binary Padding**

## How It Works

### Binary Padding

Padding appends garbage bytes (null bytes, repeated patterns) to a legitimate executable. The program still runs — the OS loader ignores trailing overlay data — but:

- **Hash changes**: defeats hash-based blocklists entirely
- **Size exceeds scanner budget**: many engines skip files above a threshold (commonly 100–500 MB)
- **Signatures break**: some AV signatures match on relative offsets that shift with padding

```bash
# Append 300 MB of zeros to a binary (Linux/macOS)
dd if=/dev/zero bs=1M count=300 >> target.exe
```

```powershell
# PowerShell equivalent
$padding = New-Object byte[] (300MB)
Add-Content -Path target.exe -Value $padding -Encoding Byte
```

### Compressed Delivery (ZIP Bomb Concept)

DEFLATE achieves >1000:1 compression on zero-filled data. This means:
- A 500 MB zero-padded executable compresses to ~500 KB
- AV scans the small ZIP → clean
- User extracts → 500 MB file beyond scanner budget

Real Trellix examples:
- **1.77 MB ZIP → 300 MB ISO → 300 MB EXE** (three-layer chain)
- **77 KB ZIP → 664 MB EXE** (single-layer, extreme ratio)

The classic zip bomb **42.zip** is 42 KB uncompressed, expanding to 4.5 PB — modern tools detect recursive bombs, but single-level high-ratio archives often pass gateway filters.

---

## Lab Demonstration (Benign Files Only)

### Step 1 — Create a Padded File

```bash
# Linux/macOS: 500 MB of zeros
dd if=/dev/zero of=padded.bin bs=1M count=500
```

```powershell
# Windows PowerShell
$fs = [System.IO.File]::Create("padded.bin")
$fs.SetLength(500MB)
$fs.Close()
```

### Step 2 — Compress and Observe Ratio

```bash
zip -9 compressed.zip padded.bin
ls -lh compressed.zip   # Expect < 1 MB
ls -lh padded.bin       # 500 MB
```

The DEFLATE compression ratio on zero-filled data exceeds 1000:1. A 500 MB file compresses to under 500 KB.

### Step 3 — Verify Expansion

```bash
unzip compressed.zip
ls -lh padded.bin   # Back to 500 MB
```

### Step 4 — Observe Scanner Behavior (Isolated Lab)

In a test environment with endpoint tools in monitor mode:
1. Scan `compressed.zip` — typically allowed due to small size
2. Extract and scan `padded.bin` — some engines log "skipped: file too large" or partial scan warnings
3. Compare on-access vs. on-demand scan results

### Step 5 — PE Overlay Padding

Append padding to an actual executable without breaking it:

```bash
# Append 300 MB junk to a harmless executable
dd if=/dev/zero bs=1M count=300 >> harmless.exe
```

Effects:
- Program still executes correctly
- Hash changes (bypasses hash blocklists)
- File size now exceeds most AV scanning budgets
- Static signatures that rely on file structure may no longer match

---

## Detection Evasion Mechanism

| Scanner Limit | Effect When Exceeded |
|---------------|---------------------|
| Max file size | File skipped entirely or partially scanned |
| Archive recursion depth | Nested layers after limit are not unpacked |
| Decompression budget | Extraction aborted; inner payload not scanned |
| CPU/time budget per file | Scan terminates early |

---

## Blue Team Detection

### 1. Flag Extreme Compression Ratios

Alert when a compressed archive contains files with >100:1 compression ratio. DEFLATE's >1000:1 on trivial data shows why small archives can hide very large payloads.

```
SIEM rule concept:
  trigger: archive extracted where uncompressed_size / compressed_size > 100
  action: quarantine and alert
```

### 2. PE Overlay Detection

A PE overlay is data appended after the end of the last PE section. Most legitimate executables have no overlay. Flag files with large overlays for manual review.

```
YARA rule concept:
  condition: pe.overlay.offset > 0 and pe.overlay.size > 10MB
```

### 3. Uniform-Byte Region Detection

Detect files with long runs of the same byte (a signature of padding):

```python
# Simplified entropy/uniformity check
def has_large_uniform_region(data, threshold_mb=50):
    chunk_size = 1024 * 1024  # 1 MB chunks
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        if len(set(chunk)) <= 2:  # Only 1-2 unique bytes
            count += 1
            if count * chunk_size > threshold_mb * 1024 * 1024:
                return True
    return False
```

### 4. Gateway and Email Filter Configuration

- Set maximum archive **decompression size limits** (e.g., reject archives expanding beyond 200 MB)
- Block or quarantine archives containing ISOs or executables above policy size
- Enable **scan-after-extract** mode on mail gateways

### 5. Memory-Centric Detection

Padding evades static scanning but not behavioral analysis. When the padded binary executes, behavioral signals (memory allocation patterns, process creation, network connections) remain detectable. Rely on:

- Runtime memory scanning (EDR memory protection)
- Process behavior analysis (API call sequences)
- Network indicators regardless of file size

### 6. Hunting Queries

```
# Splunk / KQL concept queries
PE_with_large_overlay:
  event_type=file_create
  | where pe_overlay_size > 10000000

Extreme_compression:
  event_type=archive_extract
  | where uncompressed_size / compressed_size > 200

Hash_churn_with_size_jump:
  event_type=file_modify
  | where file_size_delta > 100000000 AND time_window < 60s
```

---

## Attacker Workflow

```
1. Build payload (shellcode → PE → EXE)
2. Pad with zeros: dd / PowerShell SetLength
3. Compress: zip -9 delivery.zip payload.exe
4. Deliver via email / web / phishing
5. Victim extracts → large EXE beyond AV scan budget
6. Execution proceeds without static detection
```

---

## Resources

- Trellix Research — "SuperSize Me" (real campaign analysis) — `trellix.com/blogs/research/supersize-me/`
- MITRE ATT&CK T1027.001 — Binary Padding — `attack.mitre.org/techniques/T1027/001/`
- Unprotect.it — Binary Padding technique — `unprotect.it/technique/obfuscated-files-or-information-binary-padding/`
- inflate.py (research/lab padding tool) — `github.com/njcve/inflate.py`
- zlib Technical Details (compression ratios) — `zlib.net/zlib_tech.html`
