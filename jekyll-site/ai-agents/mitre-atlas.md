---
layout: training-page
title: "MITRE ATLAS — Red Team Academy"
module: "AI Red Team Agents"
tags:
  - mitre-atlas
  - ai-security
  - threat-modeling
  - adversarial-ml
  - tactics
  - techniques
  - case-studies
page_key: "ai-mitre-atlas"
render_with_liquid: false
---

# MITRE ATLAS

MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) is the authoritative knowledge base for adversary tactics, techniques, and real-world case studies against AI and ML systems. It mirrors the structure of MITRE ATT&amp;CK but is scoped to ML pipelines, inference endpoints, training data, and deployed models. Red teams use ATLAS to plan operations against AI-enabled targets; blue teams use it to build detection and mitigation coverage.

## Why ATLAS Matters in 2025-2026

Traditional MITRE ATT&amp;CK does not cover attacks that exploit the *statistical* nature of ML models — evasion, poisoning, model stealing, inversion, and prompt injection. ATLAS fills that gap and now integrates LLM-specific tactics (prompt injection, LLM jailbreak, LLM plugin compromise, LLM meta prompt extraction) introduced in the ATLAS 4.x updates.

Use ATLAS when:

- Scoping a red team engagement against an AI-enabled application
- Mapping observed offensive capabilities to a standardized language
- Cross-walking findings into ATT&amp;CK for executive-audience reporting
- Training detection engineers on adversarial ML indicators

## ATLAS Tactics (Top-Level Kill Chain)

ATLAS currently defines 14 tactics — the "why" of each step in an AI-focused attack:

<pre><code>Reconnaissance          — learn about the target model/system
Resource Development    — build capabilities (adversarial datasets, proxy models)
Initial Access          — gain entry to the ML pipeline or inference API
ML Model Access         — obtain query or white-box access to the model
Execution               — run adversarial code / inference manipulation
Persistence             — maintain foothold in training or deployment pipeline
Privilege Escalation    — elevate within the ML platform / MLOps stack
Defense Evasion         — evade guardrails, filters, detection layers
Credential Access       — steal API keys, model weights, training credentials
Discovery               — enumerate model architecture, training data, endpoints
Collection              — gather data for extraction / poisoning
ML Attack Staging       — prepare adversarial inputs or poisoned artifacts
Exfiltration            — extract weights, training data, or outputs
Impact                  — cause misclassification, denial of ML, IP theft, harm</code></pre>

## Core Techniques Red Teams Use

### Reconnaissance Techniques

- **AML.T0000 — Search for Victim's Publicly Available Research Materials**: arXiv papers, company engineering blogs, model cards on HuggingFace
- **AML.T0001 — Search for Publicly Available Adversarial Vulnerability Analysis**: prior ATLAS case studies, bug bounty writeups, existing jailbreak libraries
- **AML.T0003 — Victim-Owned ML Artifacts**: scrape HuggingFace orgs, GitHub releases, public Kaggle datasets

### ML Model Access

- **AML.T0040 — ML Model Inference API Access**: query rate, pricing, auth = decide between black-box adversarial or gradient-free attacks
- **AML.T0041 — Physical Environment Access**: attack sensor pipelines (cameras, mics) feeding the model
- **AML.T0044 — Full ML Model Access**: obtain weights via leaked repo, insider, or model stealing

### ML Attack Staging

- **AML.T0043 — Craft Adversarial Data**: generate evasion samples (FGSM, PGD, C&amp;W, adversarial patches)
- **AML.T0018 — Backdoor ML Model**: insert trigger-activated behavior via poisoned fine-tuning
- **AML.T0020 — Poison Training Data**: upload poisoned samples to public datasets that downstream models scrape

### LLM-Specific Techniques (ATLAS 4.x additions)

- **AML.T0051 — LLM Prompt Injection**: direct and indirect injection; see `/ai-agents/prompt-injection/`
- **AML.T0053 — LLM Meta Prompt Extraction**: leak system prompts via prompt leaking techniques
- **AML.T0054 — LLM Jailbreak**: bypass alignment/guardrails (Crescendo, PAIR, Skeleton Key, Many-Shot — see `/ai-agents/llm-jailbreaks-2025/`)
- **AML.T0055 — LLM Plugin Compromise**: abuse connected tools/actions/functions
- **AML.T0059 — LLM Trusted Output Components Manipulation**: forge markdown/citations/image URLs the user auto-trusts

### Exfiltration

- **AML.T0024 — Exfiltration via ML Inference API**: membership inference, training data extraction
- **AML.T0025 — Exfiltration via Cyber Means**: classic data theft from MLOps infra (DVC, MLflow, SageMaker, Vertex AI)

### Impact

- **AML.T0015 — Evade ML Model**: misclassification of malware, phishing, spam
- **AML.T0031 — Erode ML Model Integrity**: slow drift via sustained poisoning
- **AML.T0048 — External Harms**: reputational/financial damage from manipulated outputs

## ATLAS Case Studies (Selected)

Real incidents documented in the ATLAS case-study library — useful for engagement storytelling and executive reports:

- **ClearviewAI Misconfiguration** — leaked facial recognition model and dataset
- **Tay Poisoning** — Microsoft chatbot coordinated poisoning
- **Evasion of Deep Learning Detector for Malware C&amp;C Traffic** — adversarial traffic flows
- **Bypassing Cylance AI Malware Detection** — concatenation evasion attack on commercial EDR
- **GPT-2 Model Replication** — model extraction via query access
- **Botnet Domain Generation Algorithm (DGA) Detection Evasion**
- **ProofPoint Evasion** — adversarial email content bypassing ML spam filter
- **Compromised PyTorch Dependency Chain** — 2022 torchtriton nightly compromise (maps to AML.T0010 ML Supply Chain Compromise)
- **Achieving Code Execution in MathGPT via Prompt Injection** — LLM plugin compromise via injected calculator code
- **PoisonGPT** — distributing a covertly poisoned open-source LLM (maps to AML.T0018 Backdoor ML Model)

## Using ATLAS in a Red Team Engagement

### Pre-engagement mapping

Build a threat profile by asking:

<pre><code># Questions for scoping
1. Does the target use self-hosted or hosted (OpenAI/Anthropic/etc.) models?
2. Is fine-tuning involved? What training data is used?
3. What tools/plugins does the AI have? (file system, email, internet, code exec)
4. What is the attack surface: API, chat UI, agent, RAG, embedded assistant?
5. What safety/alignment controls exist? (system prompt, guardrails, classifiers)</code></pre>

Map answers to ATLAS tactics — each yes unlocks candidate techniques.

### Attack matrix planning

Create a matrix of ATLAS techniques × engagement objectives. Example fragment:

<pre><code>Objective: Exfiltrate system prompt from customer chatbot
- AML.T0000 Recon             → find public model card, chatbot URL
- AML.T0040 Inference Access  → hit /chat endpoint, measure rate limits
- AML.T0053 Meta Prompt Ext.  → prompt leaking payloads (ignore previous, repeat)
- AML.T0054 Jailbreak          → Crescendo escalation if direct leaking fails
- AML.T0024 Exfil via API     → encode captured prompt into markdown image URL</code></pre>

### ATLAS Navigator

The ATLAS Navigator (analog to ATT&amp;CK Navigator) overlays techniques onto a tactic grid. Export a JSON layer, share with the customer's blue team, and use heat mapping to show detection coverage gaps.

## Cross-Walking ATLAS to ATT&amp;CK

Many ATLAS techniques have ATT&amp;CK analogs — useful when writing reports for audiences comfortable with the older framework:

<pre><code>ATLAS                             → ATT&amp;CK
AML.T0010 ML Supply Chain Comp.   → T1195 Supply Chain Compromise
AML.T0012 Valid Accounts          → T1078 Valid Accounts
AML.T0044 Full ML Model Access    → T1530 Data from Cloud Storage Object
AML.T0024 Exfil via ML API        → T1041 Exfiltration Over C2 Channel
AML.T0051 LLM Prompt Injection    → T1059 Command and Scripting Interpreter
                                    (logical analog — code exec via prompt)
AML.T0055 LLM Plugin Compromise   → T1554 Compromise Client Software Binary</code></pre>

## Mitigations (from the ATLAS M-catalog)

ATLAS mitigations give red teams a preview of what well-tuned blue teams will deploy — helpful for opsec and alternative-pathway planning:

- **AML.M0000 Limit Release of Public Information** — less recon surface
- **AML.M0004 Restrict Number of ML Model Queries** — throttles extraction
- **AML.M0005 Control Access to ML Models and Data** — RBAC on weights
- **AML.M0013 Code Signing / Provenance** — limits AML.T0010 supply chain
- **AML.M0014 Verify ML Artifacts** — hash pinning of model weights
- **AML.M0015 Adversarial Input Detection** — Llama Guard, Rebuff, Lakera
- **AML.M0017 Model Distillation** — harder extraction target
- **AML.M0018 User Training** — downstream humans less likely to trust injected outputs

## Operational Tips

- Reference techniques by ID (`AML.T0054`) in reports — it makes them greppable and machine-parseable by downstream tooling.
- Use ATLAS for **pre-engagement scoping docs** and **findings taxonomy**, not as a literal kill chain — real attacks skip tactics constantly.
- Combine with the **MITRE AI Incident Sharing (AIIS)** community for fresh techniques not yet in the stable catalog.
- When a technique does not exist yet, propose one via the public contribution process — ATLAS accepts external submissions.

## Resources

- MITRE ATLAS — `atlas.mitre.org`
- ATLAS Navigator — `mitre-atlas.github.io/atlas-navigator`
- ATLAS GitHub — `github.com/mitre-atlas/atlas-data`
- MITRE AI Incident Sharing (AIIS) — `ai.mitre.org`
- MITRE ATT&amp;CK cross-walk — `attack.mitre.org`
- ATLAS case study library — `atlas.mitre.org/studies`
