---
layout: training-page
title: "Zip Slip — Red Team Academy"
module: "Web Hacking"
tags:
  - zip-slip
  - path-traversal
  - file-upload
  - rce
page_key: "web-zip-slip"
render_with_liquid: false
---

# Zip Slip

Zip Slip is a critical vulnerability in archive extraction logic. By crafting an archive containing files with directory traversal sequences in their paths (e.g., `../../shell.php`), an attacker can write files outside the intended extraction directory — overwriting executable files, web shells into document roots, or modifying system files. The vulnerability affects applications that extract archives without sanitizing the file paths inside them.

## Tools

- **evilarc** — Creates tar/zip archives with directory traversal paths — `github.com/ptoomey3/evilarc`
- **slipit** — Utility for creating ZipSlip archives — `github.com/usdAG/slipit`

## Affected Archive Formats

Zip Slip affects multiple archive formats:

- ZIP
- TAR / TAR.GZ / TAR.BZ2
- JAR / WAR (Java)
- CPIO
- APK (Android)
- RAR
- 7Z

## How It Works

A vulnerable extraction routine iterates over archive entries and writes each file to the destination directory by joining the destination path with the entry name. If entry names are not sanitized, a path like `../../../../etc/passwd` resolves outside the intended directory.

Example malicious archive structure:

```
malicious.zip
  ├── ../../../../etc/passwd
  ├── ../../../../usr/local/bin/malicious_script.sh
  └── normal_file.txt
```

When a vulnerable application extracts this archive, the first two files are written to `/etc/passwd` and `/usr/local/bin/malicious_script.sh` rather than being contained in the extraction directory.

## Creating a Malicious Archive

### Using evilarc

Create a ZIP archive that places a PHP web shell in the web root, traversing up 15 directories:

```
python evilarc.py shell.php -o unix -f shell.zip -p var/www/html/ -d 15
```

Parameters:

- `-o unix` — use Unix path separators
- `-f shell.zip` — output filename
- `-p var/www/html/` — target path relative to traversal root
- `-d 15` — depth of traversal (number of `../` sequences)

### Using Symlinks in ZIP

An alternative approach uses a symbolic link inside the archive. When extracted, the symlink points outside the extraction directory, and subsequent reads/writes follow the link:

```
ln -s ../../../index.php symindex.txt
zip --symlinks test.zip symindex.txt
```

## Vulnerable Code Patterns

The following Python pattern is vulnerable — it uses `os.path.join` but does not check whether the result stays within the destination directory:

```
# Vulnerable extraction (Python)
import zipfile, os

def extract(zip_path, dest):
    with zipfile.ZipFile(zip_path) as zf:
        for entry in zf.namelist():
            target = os.path.join(dest, entry)  # NOT safe
            zf.extract(entry, target)

# Safe extraction — validate each path
def safe_extract(zip_path, dest):
    with zipfile.ZipFile(zip_path) as zf:
        for entry in zf.namelist():
            target = os.path.realpath(os.path.join(dest, entry))
            if not target.startswith(os.path.realpath(dest)):
                raise Exception("Zip Slip detected: " + entry)
            zf.extract(entry, dest)
```

## Impact

- Write web shells into the document root for remote code execution
- Overwrite server-side scripts or binaries executed by scheduled tasks
- Overwrite configuration files (e.g., SSH authorized_keys, sudoers)
- Corrupt application files to cause denial of service

## Resources

- evilarc — `github.com/ptoomey3/evilarc`
- slipit — `github.com/usdAG/slipit`
- Zip Slip Vulnerability — Snyk Research — `github.com/snyk/zip-slip-vulnerability`
- Affected libraries list — `github.com/snyk/zip-slip-vulnerability`
