---
layout: training-page
title: "GenAI for Offensive Security — Practitioner Workflow"
module: "AI Agents"
tags:
  - genai
  - llm
  - ai-workflow
  - payload-mutation
  - reconnaissance
  - lure-generation
  - offensive-ai
  - red-team-workflow
page_key: "ai-agents-genai-offensive-workflow"
render_with_liquid: false
---

# GenAI for Offensive Security — Practitioner Workflow

LLMs are changing red team work the same way IDEs changed software development — not by replacing skilled practitioners, but by compressing the time between idea and execution. This page covers where GenAI is genuinely useful in a red team workflow, where it falls short, and how to integrate it responsibly.

**Core principle:** LLMs are a force multiplier for practitioners who already know what they're doing. They are not a replacement for technique knowledge.

---

## Reconnaissance Assistance

### Processing Large Data Sets

```
# Example: Parse 50,000 lines of scope DNS records for interesting patterns
# Without AI: manual grep, regex, intuition
# With AI: describe patterns, let LLM write the analysis logic

# Prompt pattern for recon processing:
"I have a list of DNS records from a target organization. 
Write a Python script that:
1. Groups by subdomain pattern (e.g., dev-*, staging-*, api-*)
2. Flags entries that resolve to cloud providers (AWS, Azure, GCP)
3. Identifies potential internal naming conventions
4. Outputs a prioritized list of interesting targets
Input format: subdomain,ip,ttl one per line"

# LLM output: usable Python script in ~30 seconds vs 30 minutes of writing
```

### OSINT Research Synthesis

```
# Prompt: synthesize job postings into technology fingerprint
"Here are 15 job postings from [company]. Identify:
- Technology stack (specific versions where mentioned)
- Security tools they use (SIEM, EDR, WAF mentioned in JD requirements)
- Development practices (CI/CD tools, source control)
- Internal team structure clues
- Any specific software/frameworks mentioned

Format as: Technology | Evidence | Confidence Level"

# Useful for: pre-engagement tech stack fingerprinting
# without touching the target
```

---

## Phishing Lure Generation

LLMs excel at generating contextually appropriate pretexts once you provide the context.

```
# Prompt pattern for lure generation:
"Generate a spear phishing email for an authorized red team engagement.
Target profile: [job title] at [industry] company
Pretext: [IT security notification / HR policy update / vendor security alert]
Goal: convince recipient to click a link and enter credentials
Requirements:
- Match corporate email tone for [industry]
- Plausible sender name/department
- Urgency without panic
- One clear call-to-action
- No grammatical errors
Do not include any actual malicious links — use PLACEHOLDER_URL"

# Iteration: paste draft back and ask for critique
"Review this phishing email for red flags a security-aware employee would catch.
Then revise to address each issue."

# Generate multiple variants:
"Create 5 variations of this pretext targeting different personality types:
1. Authority-driven (compliance officer)
2. Urgency-driven (IT helpdesk)
3. Curiosity-driven (new policy announcement)
4. Fear-driven (security incident notification)
5. Social proof (team announcement)"
```

---

## Payload Mutation and Evasion Assistance

### Script and Payload Transformation

```
# Use case: transform a known PoC into a less-signatured variant
# Prompt pattern (for authorized use on engagement systems):

"Rewrite this PowerShell script to:
1. Replace all variable names with random alphanumeric names
2. Add junk operations that don't change output (mathematical no-ops)
3. Split string literals into concatenated substrings
4. Randomize whitespace and comment placement
5. Produce functionally identical code
Preserve exact behavior — only change appearance.

Original script: [paste script]"

# Note: LLMs are useful for syntactic transformation
# They cannot guarantee AMSI/AV bypass — test results empirically

# YARA rule bypass brainstorming:
"Here is a YARA rule:
[paste rule]
List the specific string patterns and byte sequences this rule detects.
For each pattern, suggest 3 alternative ways to express the same functionality
without triggering the exact match."
```

### Understanding Existing Tools

```
# Rapid tool comprehension:
"Explain what this Cobalt Strike Malleable C2 profile does, section by section.
Highlight which settings affect JA3 fingerprint, User-Agent, and beacon timing.
[paste profile]"

# Technique translation:
"Translate this Metasploit module's core payload technique into a standalone
Python PoC. Don't use Metasploit libraries. Focus on the core technique only."

# Debugging:
"This shellcode runner crashes with access violation at [address].
Given the context [paste code], identify the likely cause and suggest a fix."
```

---

## Report Writing Assistance

The most consistently useful and lowest-risk GenAI application in red teaming:

```
# Turning technical notes into executive findings:
"Convert this technical finding into an executive summary paragraph:
- Finding: NTLM relay via Responder on flat network segment
- Impact: Obtained domain admin credentials within 4 minutes
- Conditions required: network access + SMB signing disabled
Write for a non-technical board audience. Explain the real-world business risk.
Maximum 150 words."

# Remediation recommendation generation:
"Generate a remediation recommendation for: [finding name + technical details]
Format:
- Root cause (1 sentence)
- Recommended fix (specific, actionable, technology-specific)
- Interim mitigations if full fix requires time
- Verification steps (how to confirm remediation is complete)"

# Executive summary template filling:
"Using these red team findings [paste list], write a 1-page executive summary.
Include: overall risk rating, top 3 findings with business impact,
trend vs. last engagement if data provided, and recommended priority actions."
```

---

## Code Generation for Red Team Tooling

```
# Build custom enumeration scripts quickly:
"Write a Python script to:
- Read a list of domain names from domains.txt
- For each domain, check if MX records exist
- Query those MX servers for open relay (send MAIL FROM: test@test.com)
- Output: domain,mx_server,open_relay (true/false)
- Handle timeouts gracefully, parallel processing with 10 threads"

# Parse complex output formats:
"Write a parser for Nmap XML output that:
- Extracts hosts with port 445 open
- For each, notes OS guess if available
- Groups by subnet (/24)
- Outputs to CSV: ip,hostname,os_guess,subnet"

# Build custom Burp extensions (BChecks):
"Write a Burp Suite BCheck for detecting JWT algorithm confusion vulnerabilities.
The check should: send a request with alg:none token, compare response
to legitimate token response, flag if access granted."
```

---

## Where LLMs Fall Short (Know the Limits)

```
# LLMs cannot reliably:
# 1. Guarantee bypassing specific AV/EDR versions — always test empirically
# 2. Generate working 0-day exploits — they hallucinate vulnerability details
# 3. Know current patch states, live IOCs, or real-time threat intel
# 4. Replace manual code review for complex logic chains
# 5. Produce novel techniques — they recombine known techniques

# Common failure modes:
# - Confident wrong answers about specific API versions/signatures
# - Syntactically valid but logically broken exploit code
# - Missing edge cases in parsing code (truncated responses, encoding issues)
# - Outdated tool syntax (tools change, training data has a cutoff)

# Mitigation:
# Treat all LLM-generated code as a first draft requiring review
# Test every payload in a controlled lab environment first
# Cross-reference with primary documentation for tool flags and API calls
```

---

## Operational Security with GenAI Tools

```
# What NOT to paste into commercial LLM APIs during an engagement:

# NEVER share:
# - Client names, IP addresses, or domain names in prompts
# - Actual captured credentials or hashes
# - Exfiltrated data
# - Proprietary internal documents from the target
# - Active exploit code targeting identified CVEs in the target's environment

# Safe practices:
# - Anonymize prompts: replace "acme.com" with "target.example.com"
# - Use local models for sensitive work:
#   Ollama + CodeLlama/DeepSeek-Coder for local code assistance
#   No data leaves the machine

# Local model setup for sensitive engagements:
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull deepseek-coder:6.7b
ollama run deepseek-coder:6.7b
# Quality: ~70-80% of commercial models for coding tasks
# Privacy: 100% local
```

---

## Practical Integration Examples

```
# tmux + LLM workflow for active engagement:
# Pane 1: terminal (active tools)
# Pane 2: LLM chat (code/analysis help)

# Claude CLI for quick questions:
claude "What Mimikatz command dumps cached Kerberos tickets from memory?"
claude "Write a one-liner to base64-decode and execute this PowerShell command: [cmd]"

# Integration with note-taking:
# After each finding: paste raw notes, ask LLM to structure into finding format
# Before report delivery: paste full draft, ask for consistency review

# Reconnaissance automation:
# Write prompt template files for repeatable workflows:
cat recon_prompt.txt
"You are analyzing DNS enumeration output. 
Given the following DNS records, identify:
[TEMPLATE SLOT: paste records here]
Analysis requested: [TEMPLATE SLOT: specify task]"
```

---

## Resources

- Using LLMs in offensive security research — `arxiv.org/abs/2312.04038`
- Fabric — LLM-powered framework for security analysis — `github.com/danielmiessler/fabric`
- Ollama — local LLM inference — `ollama.com`
- DeepSeek-Coder — strong local coding model — `github.com/deepseek-ai/DeepSeek-Coder`
- PrivateGPT — local RAG over documents — `github.com/zylon-ai/private-gpt`
- LLM CTF techniques — `github.com/jxmorris12/ctf`
