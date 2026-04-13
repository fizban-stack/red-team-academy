---
layout: training-page
title: "API Key Leaks — Red Team Academy"
module: "Web Hacking"
tags:
  - api-keys
  - secrets
  - reconnaissance
  - github
  - trufflehog
page_key: "web-api-key-leaks"
render_with_liquid: false
---

# API Key Leaks

API keys and tokens are authentication credentials used to control access to services. Leaked keys can lead to unauthorized access, data breaches, financial charges, and full account compromise. They are frequently found in public repositories, Docker images, configuration files, and JavaScript bundles.

## Tools

- **truffleHog** — Find credentials in git history, filesystems, and cloud sources — `github.com/trufflesecurity/truffleHog`
- **trivy** — General purpose scanner that also detects API keys and secrets — `github.com/aquasecurity/trivy`
- **badsecrets** — Detects known or weak secrets across many platforms — `github.com/blacklanternsecurity/badsecrets`
- **crapsecrets** — Detects known secrets across web frameworks — `github.com/irsdl/crapsecrets`
- **secrets-patterns-db** — Largest open-source database of regex patterns for detecting secrets — `github.com/mazen160/secrets-patterns-db`
- **keyhacks** — Quick validation methods for API keys from bug bounty programs — `github.com/streaak/keyhacks`
- **KeyFinder** — Browser extension to find keys while surfing — `github.com/momenbasel/KeyFinder`
- **nuclei-templates** — Token spray templates to test API tokens against many services — `github.com/projectdiscovery/nuclei-templates`
- **SignSaboteur** — Burp extension for editing, signing, and verifying signed web tokens — `github.com/d0ge/sign-saboteur`
- **gitleaks** — Detect hardcoded secrets in git repos — `github.com/gitleaks/gitleaks`
- **semgrep** — Static analysis for secrets and security patterns — `github.com/returntocorp/semgrep`

## Common Causes of Leaks

### Hardcoded in Source Code

Developers accidentally commit keys directly into application code:

```
# Python example of hardcoded API key
api_key = "1234567890abcdef"
stripe_secret = "sk_live_AbCdEfGhIjKlMnOpQrStUv"
```

### Public Repositories

Keys committed to public GitHub repositories — even in old commits — are frequently scraped by automated tools. Scan entire organizations and repositories including issues and pull requests:

```
# Scan a GitHub organization
docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --org=trufflesecurity

# Scan a GitHub repository including issues and pull requests
docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github \
  --repo https://github.com/trufflesecurity/test_keys \
  --issue-comments --pr-comments
```

### Docker Images

API keys baked into Docker image layers during build time persist even if removed in later layers. Scan public images from DockerHub or private registries:

```
# Scan a Docker image for verified secrets
docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest docker \
  --image trufflesecurity/secrets
```

### Configuration Files

Keys and tokens frequently appear in publicly accessible configuration files:

- `.env` files committed to version control
- `config.json`, `settings.py`, `appsettings.json`
- `.aws/credentials` in home directories
- CI/CD pipeline configuration files

### Logs and Debug Output

Keys and tokens accidentally printed in debug logs, error messages, or verbose output from applications or CI/CD pipelines.

## Identifying the Service Behind a Token

Use `secrets-patterns-db` to identify which service generated a token using regex patterns:

```
patterns:
  - pattern:
      name: AWS API Gateway
      regex: '[0-9a-z]+.execute-api.[0-9a-z._-]+.amazonaws.com'
      confidence: low
  - pattern:
      name: AWS API Key
      regex: AKIA[0-9A-Z]{16}
      confidence: high
```

## Validating API Keys

Use `keyhacks` or the service's documentation to verify a key is still valid before reporting. Test quickly before the key is rotated:

```
# Validate a Telegram Bot API token
curl https://api.telegram.org/bot<TOKEN>/getMe

# Test API keys with nuclei token-spray templates
nuclei -t token-spray/ -var token=token_list.txt
```

## Reducing Exposure

Add pre-commit hooks to automatically detect secrets before they are committed:

```
# .pre-commit-config.yaml
-   repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v3.2.0
    hooks:
    -   id: detect-aws-credentials
    -   id: detect-private-key
```

Additional mitigations:

- Use environment variables or a dedicated secrets manager (AWS Secrets Manager, HashiCorp Vault)
- Rotate any key that may have been exposed immediately
- Apply least-privilege scopes to API keys
- Enable usage monitoring and alerts on API keys
- Set expiry dates on tokens where the service supports it

---

## Discovery Methodology

### JavaScript Files

Modern single-page applications bundle API keys into their JavaScript. Keys are often placed in:
- Environment variable injection at build time (`process.env.REACT_APP_API_KEY`)
- Configuration objects in bundle files
- Initialization code for third-party SDKs (Firebase, Stripe, Mapbox)

Extract and search JS files:

```bash
# Download all JS files from the target
wget -r -np -nd -A "*.js" https://target.com/static/js/

# Search for common key patterns
grep -oP "(?:api[_-]?key|apikey|access[_-]?token|secret|authorization)['\"\s:=]+['\"]?[A-Za-z0-9_\-\.]{16,}" *.js

# Search for AWS key pattern
grep -oP "AKIA[0-9A-Z]{16}" *.js

# Search for Bearer tokens
grep -oP "Bearer [A-Za-z0-9._\-]+" *.js
```

### Git Repositories

Even after a key is removed from the current codebase, it remains in git history:

```bash
# Clone the target repo
git clone https://github.com/target-org/target-repo

# Search git history with trufflehog
trufflehog git file://./target-repo --only-verified

# Search git history with gitleaks
gitleaks detect --source ./target-repo --log-opts="--all"

# Manual git log search
git log --all --oneline | head -100
git show COMMIT_HASH -- path/to/file | grep -i "api_key\|secret\|token\|password"
```

### Mobile App Decompilation

APKs and IPAs often contain hardcoded keys:

```bash
# Decompile APK
apktool d target.apk -o target-decompiled

# Search for common key patterns
grep -r "api_key\|apiKey\|API_KEY\|secret\|token\|password" target-decompiled/
grep -r "AKIA[0-9A-Z]{16}" target-decompiled/

# For Android — extract strings from compiled resources
aapt dump badging target.apk
```

---

## GitHub Dorking Queries

GitHub's code search can be used to find exposed keys in public repositories. These queries are for authorized security research and bug bounty programs only.

### General Secret Searches

```
# Find .env files with API keys
filename:.env "API_KEY"
filename:.env "SECRET_KEY"
filename:.env "ACCESS_TOKEN"
filename:.env "DATABASE_URL"

# Find hardcoded API keys in Python
"api_key" site:github.com language:python
"api_key =" language:python

# Find AWS keys
"AKIA" site:github.com
filename:credentials aws_access_key_id

# Find generic secrets
"Authorization: Bearer" filename:*.py
"password" filename:config.json
```

### Organization-Specific Searches

```
# Limit to specific organization
org:target-company "api_key"
org:target-company filename:.env
org:target-company "AWS_SECRET_ACCESS_KEY"

# Search in specific file types
org:target-company extension:yaml "password"
org:target-company extension:json "secret"
```

### Using gh CLI for GitHub Dorking

```bash
# Search code across GitHub
gh search code "AKIA" --owner target-org --language python

# Search with filename filter
gh search code "api_key" --owner target-org --filename .env

# Search for AWS credentials in all repos of an org
gh search code "aws_access_key_id" --owner target-org
```

---

## Automated Scanning Tools

### truffleHog

```bash
# Scan a GitHub org
trufflehog github --org=target-org --token=$GITHUB_TOKEN

# Scan a specific repo (with full history)
trufflehog git https://github.com/target-org/target-repo

# Scan a local filesystem
trufflehog filesystem /path/to/code

# Only report verified (actively valid) secrets
trufflehog github --org=target-org --only-verified

# Scan Docker image
trufflehog docker --image target-image:latest
```

### gitleaks

```bash
# Scan current git repo
gitleaks detect

# Scan with verbose output
gitleaks detect -v

# Scan a specific repo
gitleaks detect --source /path/to/repo

# Scan git log (all branches/history)
gitleaks detect --source /path/to/repo --log-opts="--all"

# Generate report
gitleaks detect --report-format json --report-path gitleaks-report.json
```

### semgrep

```bash
# Run secrets ruleset
semgrep --config "p/secrets" /path/to/code

# Run specific AWS secrets rules
semgrep --config "p/aws-security-audit" /path/to/code

# Run all security rules
semgrep --config "p/security-audit" /path/to/code
```

---

## Common Key Patterns by Service

| Service | Pattern | Example |
| --- | --- | --- |
| AWS Access Key | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` |
| AWS Secret Key | 40-char alphanumeric | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` |
| Stripe Live Secret | `sk_live_[0-9a-zA-Z]{24}` | `sk_live_AbCdEfGhIjKlMnOp` |
| Stripe Test Secret | `sk_test_[0-9a-zA-Z]{24}` | `sk_test_AbCdEfGhIjKlMnOp` |
| Twilio Account SID | `AC[a-z0-9]{32}` | `AC1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d` |
| Twilio Auth Token | 32-char hex | `1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d` |
| GitHub Token (PAT) | `ghp_[A-Za-z0-9]{36}` | `ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` |
| GitHub OAuth | `gho_[A-Za-z0-9]{36}` | `gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` |
| Slack Token | `xox[baprs]-[0-9A-Za-z\-]+` | `xoxb-12345-67890-abcdefghijklmno` |
| SendGrid | `SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}` | `SG.xxxxx.xxxxxx` |
| Google API Key | `AIza[0-9A-Za-z\-_]{35}` | `AIzaSyD-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` |
| Firebase | `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}` | `AAAAxxxxxx:...` |
| Mailgun API Key | `key-[0-9a-zA-Z]{32}` | `key-xxxxxxxxxxxxxxxxxxxxxxxxxxx` |
| HubSpot API Key | `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` | UUID format |
| Shopify Token | `shpat_[a-fA-F0-9]{32}` | `shpat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` |

---

## Post-Discovery Exploitation Workflow

### AWS Keys

Once AWS access/secret key pair is found, verify identity and enumerate permissions:

```bash
# Set environment variables
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Verify identity — who am I?
aws sts get-caller-identity

# List attached policies
aws iam list-attached-user-policies --user-name $(aws iam get-user --query 'User.UserName' --output text)

# Enumerate S3 buckets
aws s3 ls

# Enumerate EC2 instances
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,State.Name,PublicIpAddress]' --output table

# Check for secrets in SSM Parameter Store
aws ssm describe-parameters
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption

# Enumerate IAM users
aws iam list-users

# Check Lambda functions
aws lambda list-functions
```

### Stripe Keys

```bash
# List customers (read-only test)
curl https://api.stripe.com/v1/customers \
  -u sk_live_KEYHERE:

# List charges
curl https://api.stripe.com/v1/charges \
  -u sk_live_KEYHERE:

# List subscription data
curl https://api.stripe.com/v1/subscriptions \
  -u sk_live_KEYHERE:
```

### Twilio Keys

```bash
# Verify key is valid
curl -X GET "https://api.twilio.com/2010-04-01/Accounts/ACCOUNT_SID.json" \
  -u ACCOUNT_SID:AUTH_TOKEN

# List phone numbers
curl -X GET "https://api.twilio.com/2010-04-01/Accounts/ACCOUNT_SID/IncomingPhoneNumbers.json" \
  -u ACCOUNT_SID:AUTH_TOKEN

# List call logs
curl -X GET "https://api.twilio.com/2010-04-01/Accounts/ACCOUNT_SID/Calls.json" \
  -u ACCOUNT_SID:AUTH_TOKEN
```

### Slack Tokens

```bash
# Verify token and get workspace info
curl -H "Authorization: Bearer xoxb-TOKEN" \
  https://slack.com/api/auth.test

# List channels
curl -H "Authorization: Bearer xoxb-TOKEN" \
  https://slack.com/api/conversations.list

# Read messages from a channel
curl -H "Authorization: Bearer xoxb-TOKEN" \
  "https://slack.com/api/conversations.history?channel=CHANNEL_ID"

# List users
curl -H "Authorization: Bearer xoxb-TOKEN" \
  https://slack.com/api/users.list

# Post a message (for PoC — use responsibly in authorized testing)
curl -X POST -H "Authorization: Bearer xoxb-TOKEN" \
  -H "Content-type: application/json" \
  --data '{"channel":"CHANNEL_ID","text":"Security test message"}' \
  https://slack.com/api/chat.postMessage
```

### GitHub Tokens

```bash
# Verify token
curl -H "Authorization: token ghp_TOKENHERE" \
  https://api.github.com/user

# List repositories (including private)
curl -H "Authorization: token ghp_TOKENHERE" \
  https://api.github.com/user/repos?type=all&per_page=100

# List organizations
curl -H "Authorization: token ghp_TOKENHERE" \
  https://api.github.com/user/orgs

# List private gists
curl -H "Authorization: token ghp_TOKENHERE" \
  https://api.github.com/gists

# Check token scopes (returned in response headers)
curl -I -H "Authorization: token ghp_TOKENHERE" \
  https://api.github.com/user
# Look for X-OAuth-Scopes header in response
```

---

## Responsible Disclosure vs. Exploitation Context

When you discover a leaked API key:

**In an authorized bug bounty program:**
1. Document the location where the key was found (URL, file path, commit SHA).
2. Perform minimal verification (e.g., `aws sts get-caller-identity`) to prove the key is valid.
3. Do NOT access, download, or exfiltrate any data beyond what's needed to prove impact.
4. Report immediately with clear reproduction steps.
5. Do NOT use the key for any purpose beyond validation.

**Key validation without data access:**
```bash
# AWS — identity only, no data access
aws sts get-caller-identity

# Stripe — check key validity (doesn't list customer data)
curl https://api.stripe.com/v1/balance -u sk_live_KEY:

# GitHub — check scopes only
curl -I -H "Authorization: token TOKEN" https://api.github.com/user
```

**Rate limiting:** Many services log and rate-limit validation requests. Excessive validation attempts may cause the key to be flagged and rotated before your report is submitted — which reduces the impact you can demonstrate.

---

## Resources

- truffleHog — `github.com/trufflesecurity/truffleHog`
- secrets-patterns-db — `github.com/mazen160/secrets-patterns-db`
- keyhacks — `github.com/streaak/keyhacks`
- nuclei-templates token-spray — `github.com/projectdiscovery/nuclei-templates`
- Finding Hidden API Keys & How to Use Them — Sumit Jain
- Introducing SignSaboteur — PortSwigger Research
- gitleaks — `github.com/gitleaks/gitleaks`
- semgrep secrets rules — `semgrep.dev/p/secrets`
- GitGuardian Public API Key Exposure Report — `gitguardian.com/state-of-secrets-sprawl`
- HackerOne — Top Disclosed API Key Leaks — `hackerone.com/hacktivity`
