---
layout: training-page
title: "Secrets Scanning — Red Team Academy"
module: "Reconnaissance"
tags:
  - secrets
  - trufflehog
  - gitrob
  - cloud-recon
  - email-enum
  - spoofcheck
page_key: "recon-secrets-scanning"
render_with_liquid: false
---

# Secrets Scanning

## The Credential Gold Mine

Developers commit secrets. API keys, passwords, private certificates, AWS credentials — they end up in git repositories, public S3 buckets, pastebin dumps, and Docker image layers. For a red teamer, finding one leaked credential can collapse an entire engagement timeline from weeks to hours.

Secrets scanning is systematic: scan git history (not just current code), enumerate public cloud resources, check for domain spoofing posture, and enumerate email users. Each discipline feeds the next.

## TruffleHog — Git History Secret Scanning

TruffleHog scans git repositories — including full commit history — for high-entropy strings and known credential patterns. Version 3 uses verified detectors: it finds a string that looks like an AWS key and *actually tries to authenticate with it* to confirm validity.

### Installation

```bash
# Binary release (recommended)
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Docker
docker pull trufflesecurity/trufflehog:latest

# Go
go install github.com/trufflesecurity/trufflehog/v3@latest
```

### Scanning Git Repositories

```bash
# Scan a public GitHub repo (full history)
trufflehog git https://github.com/targetorg/targetrepo

# Scan with verification (confirms credentials are valid)
trufflehog git https://github.com/targetorg/repo --only-verified

# Scan a local repo
trufflehog git file:///path/to/local/repo

# Scan all branches
trufflehog git https://github.com/org/repo --branch=all

# JSON output for parsing
trufflehog git https://github.com/org/repo --json 2>/dev/null | jq .
```

### Scanning GitHub Organizations

```bash
# Scan entire GitHub organization
trufflehog github --org=targetorganization --token=ghp_yourtoken

# Scan including wiki and issues
trufflehog github --org=targetorg --token=ghp_yourtoken \
  --include-repos --include-members

# Filter to only verified findings
trufflehog github --org=targetorg --token=ghp_yourtoken --only-verified
```

### Scanning Docker Images

```bash
# Scan Docker image layers for secrets
trufflehog docker --image=targetorg/targetapp:latest

# Scan from a registry
trufflehog docker --image=registry.example.com/app:v1.2.3
```

### Scanning S3 Buckets

```bash
# Scan S3 bucket contents
trufflehog s3 --bucket=target-backup-bucket

# With specific AWS credentials
AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
  trufflehog s3 --bucket=target-bucket
```

### What TruffleHog Finds

Verified detectors for 700+ credential types including:

- AWS Access Keys (`AKIA...`)
- GitHub/GitLab tokens
- Slack webhooks and tokens
- Stripe, Twilio, SendGrid API keys
- Private SSH keys
- JWT tokens
- Database connection strings
- Google Cloud service account keys

## Gitrob — GitHub Organization Recon

Gitrob maps all repositories in a GitHub organization and flags files with names suggesting sensitive content (passwords, private keys, configs) without full content scanning. It's faster than TruffleHog for initial triage.

### Installation

```bash
go install github.com/michenriksen/gitrob@latest
```

### Setup

```bash
# Requires a GitHub personal access token
export GITROB_ACCESS_TOKEN=ghp_yourtokenhere
```

### Usage

```bash
# Scan an organization
gitrob targetorganization

# Scan a specific user
gitrob --users targetuser

# Output to file
gitrob targetorganization -save /tmp/gitrob-session.json

# Load and analyze a saved session
gitrob -load /tmp/gitrob-session.json

# Increase number of repos to scan
gitrob targetorganization -repos-concurrency 20
```

Gitrob flags files matching patterns like:

- `*.pem`, `*.key`, `id_rsa`, `id_dsa`
- `*.p12`, `*.pfx`
- `config.php`, `database.yml`, `settings.py`
- `.env`, `.env.local`, `.env.production`
- `credentials`, `secrets`, `password`
- `wp-config.php`, `sftp-config.json`

## certSniff — Certificate Transparency Monitoring

certSniff monitors Certificate Transparency logs in real-time for new certificates matching your target. Attackers use this offensively to discover new subdomains as they're provisioned — including staging and dev environments that often have weaker security.

### Installation

```bash
git clone https://github.com/A-poc/certSniff
cd certSniff
pip3 install -r requirements.txt
```

### Usage

```bash
# Monitor for new certs matching a domain
python3 certSniff.py -d target.com

# Multiple domains
python3 certSniff.py -d target.com -d targetcorp.io

# Save to file
python3 certSniff.py -d target.com -o certs.txt

# Monitor indefinitely (passive recon during engagement)
python3 certSniff.py -d target.com 2>&1 | tee -a cert-monitor.log &
```

### Historical CT Logs (crt.sh)

```bash
# Query historical certificates without monitoring
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
  jq -r '.[].name_value' | \
  sort -u | \
  grep -v '\*' > ct-subdomains.txt

# Including wildcards and SANs
curl -s "https://crt.sh/?q=target.com&output=json" | \
  jq -r '.[].name_value' | \
  tr ',' '\n' | \
  sort -u
```

## AWSBucketDump — S3 Bucket Enumeration

AWSBucketDump enumerates and checks public accessibility of S3 buckets derived from a target's name. Forgotten public buckets containing backups, source code, or customer data are a common finding.

### Installation

```bash
git clone https://github.com/jordanpotti/AWSBucketDump
cd AWSBucketDump
pip3 install -r requirements.txt
```

### Usage

```bash
# Basic enumeration using target name
python3 AWSBucketDump.py -D target -l bucket-names.txt

# Use keyword list derived from company name
python3 AWSBucketDump.py -D targetcorp -l /opt/SecLists/Discovery/S3/bucket-names.txt

# Download interesting files automatically
python3 AWSBucketDump.py -D target -l wordlist.txt -g "*.sql,*.bak,*.env,*.key"

# Keywords from company analysis
python3 AWSBucketDump.py \
  -D targetcorp \
  -l wordlist.txt \
  -g "*.sql,*.csv,*.tar.gz,*.config,*.env"
```

### Generating Target-Specific Bucket Names

```bash
# Generate variations of company name for bucket testing
TARGET="targetcorp"
cat > bucket-variations.txt << EOF
${TARGET}
${TARGET}-backup
${TARGET}-dev
${TARGET}-staging
${TARGET}-prod
${TARGET}-data
${TARGET}-files
${TARGET}-assets
${TARGET}-logs
${TARGET}-archive
backup-${TARGET}
dev-${TARGET}
${TARGET}2024
${TARGET}-internal
EOF

python3 AWSBucketDump.py -D ${TARGET} -l bucket-variations.txt
```

### Manual S3 Checks

```bash
# Check if a bucket is public
curl -s https://TARGET-BUCKET.s3.amazonaws.com/ | head -50

# List bucket contents (if public)
aws s3 ls s3://target-bucket --no-sign-request

# Download public bucket contents
aws s3 sync s3://target-bucket /tmp/bucket-dump/ --no-sign-request

# Check for ACL misconfigurations
aws s3api get-bucket-acl --bucket target-bucket --no-sign-request
```

## Spoofcheck — Email Spoofing Assessment

Spoofcheck analyzes a domain's DNS records (SPF, DKIM, DMARC) to determine if it can be spoofed. A domain with no DMARC record or a DMARC policy of `p=none` is spoofable — you can send email appearing to come from `@targetcompany.com`.

### Installation

```bash
pip3 install spoofcheck
# or
git clone https://github.com/BishopFox/spoofcheck
cd spoofcheck
pip3 install -r requirements.txt
```

### Usage

```bash
# Check a domain for spoofing posture
python3 spoofcheck.py target.com

# Check multiple domains
for domain in target.com subsidiary.com partner.com; do
  echo "=== $domain ===" && python3 spoofcheck.py $domain
done

# Check output meanings:
# [+] Email spoofing not possible — properly protected
# [-] Spoofing possible — SPF/DMARC missing or misconfigured
```

### Manual DNS-Based Assessment

```bash
# SPF record (controls who can send on behalf of domain)
dig TXT target.com | grep "v=spf1"
# No SPF = fully spoofable
# "+all" = fully spoofable (explicitly allows any sender)
# "~all" (softfail) = may be spoofable depending on DMARC

# DMARC record (policy for failed auth)
dig TXT _dmarc.target.com
# None/missing = spoofable regardless of SPF
# p=none = monitoring only, not blocking — spoofable
# p=quarantine/reject = protected

# DKIM (you won't have the private key, but check if it exists)
dig TXT default._domainkey.target.com
dig TXT google._domainkey.target.com

# MX records — who handles their email (targeting for phishing)
dig MX target.com
```

### Using Spoofing Results

If `p=none` or no DMARC:

```bash
# Send a spoofed email (for authorized testing)
# Using swaks (Swiss Army Knife SMTP)
swaks \
  --from "ceo@target.com" \
  --to "victim@target.com" \
  --server mail.yoursmtp.com \
  --body "Test spoofed email" \
  --header "Subject: Spoofing Test"

# Or via Python smtplib
python3 -c "
import smtplib
from email.mime.text import MIMEText
msg = MIMEText('Spoofed email body')
msg['Subject'] = 'Test'
msg['From'] = 'ceo@target.com'
msg['To'] = 'victim@target.com'
s = smtplib.SMTP('your-smtp.com')
s.sendmail('ceo@target.com', ['victim@target.com'], msg.as_string())
"
```

## smtp-user-enum — SMTP User Enumeration

If you have SMTP access to a mail server (common in internal assessments), smtp-user-enum identifies valid email addresses using VRFY, EXPN, and RCPT commands.

### Installation

```bash
apt install smtp-user-enum
# or
git clone https://github.com/cytopia/smtp-user-enum
```

### Usage

```bash
# Enumerate users via VRFY
smtp-user-enum -M VRFY -U /opt/SecLists/Usernames/top-usernames-shortlist.txt \
  -t 10.10.10.50

# Enumerate via RCPT TO (most commonly allowed)
smtp-user-enum -M RCPT -D target.com \
  -U /opt/SecLists/Usernames/names.txt \
  -t 10.10.10.50 \
  -p 25

# Enumerate via EXPN (mailing lists)
smtp-user-enum -M EXPN -U users.txt -t target.com

# Specify port (e.g., submission port)
smtp-user-enum -M RCPT -U users.txt -t 10.10.10.50 -p 587

# Test single user
smtp-user-enum -M VRFY -u admin -t 10.10.10.50
```

## CloudBrute — Multi-Cloud Asset Discovery

CloudBrute discovers company assets across AWS, Azure, and GCP by brute-forcing resource names (S3 buckets, Azure blobs, GCP buckets, Azure subdomains).

### Installation

```bash
go install github.com/0xsha/CloudBrute@latest
```

### Usage

```bash
# Enumerate AWS S3 buckets
cloudbrute -d target.com -k targetcorp -m aws -o aws-results.txt

# Enumerate Azure resources
cloudbrute -d target.com -k targetcorp -m azure -o azure-results.txt

# Enumerate GCP buckets
cloudbrute -d target.com -k targetcorp -m gcp -o gcp-results.txt

# All cloud providers
cloudbrute -d target.com -k targetcorp -m all -o cloud-results.txt

# Custom wordlist
cloudbrute -d target.com -k targetcorp -m aws \
  -w /opt/SecLists/Discovery/S3/bucket-names.txt

# Increase threads
cloudbrute -d target.com -k targetcorp -m all -t 50
```

## Integrated Secrets Hunting Workflow

```bash
#!/usr/bin/env bash
TARGET=$1
DOMAIN=$2

echo "=== Phase 1: Git Secret Scanning ==="
trufflehog github --org=$TARGET --token=$GITHUB_TOKEN --only-verified

echo "=== Phase 2: File Pattern Scanning ==="
gitrob $TARGET

echo "=== Phase 3: Cloud Asset Discovery ==="
cloudbrute -d $DOMAIN -k $TARGET -m all -o /tmp/cloud-$TARGET.txt

echo "=== Phase 4: S3 Bucket Dump ==="
python3 ~/AWSBucketDump/AWSBucketDump.py -D $TARGET \
  -l /opt/SecLists/Discovery/S3/bucket-names.txt \
  -g "*.sql,*.env,*.key,*.bak,*.config"

echo "=== Phase 5: Email Spoofing Check ==="
python3 ~/spoofcheck/spoofcheck.py $DOMAIN

echo "=== Phase 6: Certificate Monitoring (background) ==="
python3 ~/certSniff/certSniff.py -d $DOMAIN &

echo "[+] Complete"
```

## What Good Findings Look Like

| Finding | Impact | Next Step |
|---|---|---|
| Verified AWS key in git | Critical — cloud account takeover | Enumerate IAM permissions immediately |
| Public S3 bucket with backups | High — data exfil or credential extraction | Download, search for credentials |
| DMARC p=none | Medium — phishing enabler | Combine with user list from SMTP enum |
| Valid email list | Low-Medium | Password spray, phishing |
| Private key committed | Critical | Use for SSH/TLS authentication |
| DB connection string | Critical | Connect to database directly |
