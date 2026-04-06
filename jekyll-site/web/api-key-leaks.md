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

## Resources

- truffleHog — `github.com/trufflesecurity/truffleHog`
- secrets-patterns-db — `github.com/mazen160/secrets-patterns-db`
- keyhacks — `github.com/streaak/keyhacks`
- nuclei-templates token-spray — `github.com/projectdiscovery/nuclei-templates`
- Finding Hidden API Keys & How to Use Them — Sumit Jain
- Introducing SignSaboteur — PortSwigger Research
