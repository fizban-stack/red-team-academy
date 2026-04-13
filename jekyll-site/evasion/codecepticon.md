---
layout: training-page
title: "Codecepticon — Source Code Obfuscator — Red Team Academy"
module: "Evasion"
tags:
  - obfuscation
  - source-code
  - csharp
  - vba
  - powershell
  - av-evasion
  - edr-evasion
page_key: "evasion-codecepticon"
render_with_liquid: false
---

# Codecepticon — Source Code Obfuscator

Codecepticon is a .NET application that obfuscates C#, VBA/VB6 (Office macros), and PowerShell source code for AV/EDR evasion. Unlike binary-level obfuscators (packers, crypters), Codecepticon targets the source code itself — renaming identifiers, rewriting strings with XOR or Base64, and restructuring code so that the compiled output has no recognizable string patterns or function names. The result is a fresh binary with no shared signatures with the original tool.

## Install & Prerequisites

```
# Requirements:
# - Visual Studio 2022 (Community or Pro) with .NET desktop workload
# - Roslyn compiler (installed with Visual Studio)
# - .NET Framework 4.8 or .NET 6+

# Clone:
git clone https://github.com/sadreck/Codecepticon.git
cd Codecepticon

# Open Codecepticon.sln in Visual Studio and compile in Release mode.
# Output binary: Codecepticon/bin/Release/Codecepticon.exe

# Two input methods:
# 1. Command line flags (generated via CommandLineGenerator.html in the repo)
Codecepticon.exe --action obfuscate --module csharp --path C:\src\Rubeus --mapping-file rubeus-mapping.html --verbose
# 2. XML config file
Codecepticon.exe --config C:\Tools\my_obfuscation.xml
```

## How Codecepticon Works

```
# String obfuscation methods (apply to ALL languages):
# Base64       — encode strings as Base64, decode at runtime
# XOR          — XOR-encrypt each string with a randomized per-string key
# Substitution — replace each character with a substitution cipher (randomized per run)
# Group        — map each ASCII byte to a random N-character group string

# Identifier obfuscation (rename variables, functions, classes):
# Random    — gibberish random names (e.g., ZxQpLmA)
# No Twins  — random names guaranteed to be unique across the codebase
# Dictionary — draw from a wordlist for human-looking but meaningless names
# Markov    — auto-generated English-sounding words from a Markov chain model
#             (produces names like "Tremblen", "Forsight" — looks like real code)

# Command line obfuscation:
# After obfuscation, all CLI flag names are renamed in the source.
# The HTML mapping file (output alongside the obfuscated project) lets you
# find the new name for each flag.
# Example: SharpHound.exe --CollectionMethods DCOnly
# → becomes: SharpHound.exe --AfjdklP ZxQmrL
# This defeats detections that scan for specific flag strings (e.g., "CollectionMethods")

# Supported profiles (pre-configured tweaks for specific tools):
# Certify, Rubeus, Seatbelt, SharpChrome, SharpDPAPI, SharpHound, SharpView
# Profiles are NOT required — Codecepticon works on any C# project
```

## C# Project Obfuscation

```
# Obfuscating a C# project (e.g., Rubeus):
# 1. Clone the target project independently and verify it compiles cleanly.
# 2. Run Codecepticon against the .sln file:

Codecepticon.exe --action obfuscate --module csharp ^
  --input C:\Tools\Rubeus\Rubeus.sln ^
  --output C:\Tools\Rubeus_obf\Rubeus.sln ^
  --mapping C:\Tools\rubeus_map.html ^
  --profile Rubeus ^
  --rename-everything ^
  --rename-method random ^
  --rename-variable random ^
  --rename-class random ^
  --string-obfuscation xor ^
  --verbose

# --rename-everything: renames ALL identifiers (most aggressive)
# --rename-method:     how to rename functions (random, dictionary, markov)
# --rename-variable:   how to rename variables/fields
# --rename-class:      how to rename classes and namespaces
# --string-obfuscation: how to obfuscate string literals (base64, xor, substitution)
# --mapping:           output HTML file mapping original names to obfuscated names
# --profile Rubeus:    apply Rubeus-specific patches

# 3. Open the output .sln in Visual Studio and compile.
# 4. Use the mapping HTML to translate CLI args back to obfuscated names.
```

## PowerShell Obfuscation

```
# Obfuscating a PowerShell script (e.g., PowerView):
Codecepticon.exe --action obfuscate --module powershell ^
  --input C:\Tools\PowerView.ps1 ^
  --output C:\Tools\PowerView_obf.ps1 ^
  --mapping C:\Tools\pv_map.html ^
  --rename-functions random ^
  --rename-variables random ^
  --string-obfuscation base64 ^
  --verbose

# Note: PowerShell obfuscation has edge cases — complex scripts like PowerView
# may not work perfectly. Test the output before use on an engagement.
# Simple scripts and custom payloads work reliably.

# What it does to PowerShell:
# - Renames function names: Get-DomainUser → ZxPlqR
# - Renames parameter names: -Domain → -AfjK
# - Base64-encodes string literals
# - Inserts decoding stubs at top of script

# AMSI evasion effect:
# AMSI signatures target specific function names ("Invoke-Mimikatz", "Get-DomainUser")
# After renaming, AMSI string-matching detections no longer fire
# Combined with an AMSI bypass, this provides layered coverage
```

## VBA / Office Macro Obfuscation

```
# VBA obfuscation works on the raw source code, NOT on a .docx/.xlsm file.
# Export the macro source first:
# 1. Open the Office document → Alt+F11 → right-click module → Export File
# 2. Save as .bas file

# Obfuscate the .bas file:
Codecepticon.exe --action obfuscate --module vba ^
  --input C:\Tools\macro.bas ^
  --output C:\Tools\macro_obf.bas ^
  --rename-functions random ^
  --rename-variables random ^
  --string-obfuscation xor ^
  --verbose

# Re-import the obfuscated .bas back into the document:
# Alt+F11 → File → Import File → select macro_obf.bas

# Common VBA targets: Meterpreter macro droppers, PowerShell launchers,
# certificate-steal macros, custom phishing payloads
# Codecepticon renames Sub/Function names and obfuscates strings —
# detections for "Auto_Open", "Shell", "CreateObject" string patterns are bypassed
```

## Obfuscating Command Line Arguments

```
# After obfuscation, all CLI argument names change.
# The mapping HTML file tracks these changes.
# Open mapping.html in a browser → search for each original argument name.

# Example workflow for SharpHound:
# Original: SharpHound.exe --CollectionMethods DCOnly --OutputDirectory C:\temp\
# After obfuscation: --CollectionMethods → --ZxPlqRmA, --OutputDirectory → --BjkLtPW
# New command: SharpHound_obf.exe --ZxPlqRmA DCOnly --BjkLtPW C:\temp\

# Automate argument lookup:
# Open C:\Tools\rubeus_map.html in browser → Ctrl+F → search "CollectionMethods"
# Find the "New Name" column entry → use that as the flag

# OPSEC note: the obfuscated argument names change every time Codecepticon runs.
# Regenerate and recompile on each engagement for a fresh signature.
```

## String Obfuscation Methods Compared

```
# Base64:
# Simplest — each string literal encoded as Base64, decoded at runtime.
# Detection: AMSI/AV may flag base64 blobs of known strings statically.
# Effective against: signature-based static analysis.

# XOR:
# Each string XOR-encrypted with a random per-string key.
# Key is stored inline in the decryption template code.
# No two runs produce the same output — randomized per execution.
# Effective against: both static and memory scanning.

# Single Substitution:
# Simple substitution cipher — each ASCII value maps to another.
# Mapping is randomized on each Codecepticon run.
# Lightweight decryption stub.

# Group Substitution:
# Each byte mapped to an N-character random group string.
# Significantly increases file size but produces maximally unrecognizable output.
# Useful when signature scanners target short encrypted blobs.

# Recommendation:
# Use XOR for strongest AV evasion (randomized per-run, no pattern in ciphertext).
# Use Group Substitution when all else fails — produces unique binaries every run.
```

## Effective Target Tools

```
# Codecepticon works best with these C# offensive tools:
# - Rubeus        — Kerberos attacks (with --profile Rubeus)
# - SharpHound    — AD enumeration (with --profile SharpHound)
# - Certify       — AD CS attacks (with --profile Certify)
# - Seatbelt      — host recon (with --profile Seatbelt)
# - SharpDPAPI    — credential extraction (with --profile SharpDPAPI)
# - SharpView     — PowerView-equivalent in C# (with --profile SharpView)
# - Custom tools  — any C# project compiles cleanly

# For tools NOT in the profile list:
# 1. Run without --profile, with --rename-everything
# 2. If compilation fails after obfuscation: check error messages
#    Most common issue: reflection-based code referencing original method names
#    Fix: add the method to a profile exception list or obfuscate selectively
# 3. Create an issue on the Codecepticon repo to request a profile

# Workflow before a real engagement:
# 1. Obfuscate target tool with Codecepticon
# 2. Test compilation and functionality in a lab VM
# 3. Upload to antiscan.me (no distribution scanning) to verify bypass
# 4. Test against live AV in a sacrificial VM
# 5. Deploy on engagement
```

## Resources

- Codecepticon — `github.com/sadreck/Codecepticon`
- CommandLineGenerator.html — included in the repo, use to build command lines without memorizing flags
- SharpCollection (C# tools to obfuscate) — `github.com/Flangvik/SharpCollection`
- Related: [AV / EDR Evasion](/evasion/av-edr-evasion/)
- Related: [PE Obfuscation & Packing](/evasion/pe-obfuscation/)
- Related: [AMSI Bypass](/evasion/amsi-bypass/)
