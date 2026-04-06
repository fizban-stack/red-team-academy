---
layout: training-page
title: "AI-Powered OSINT and Recon — Red Team Academy"
module: "AI Red Team Agents"
tags:
  - ai
  - osint
  - recon
  - langchain
  - embeddings
  - shodan
  - rag
page_key: "ai-osint-recon"
render_with_liquid: false
---

# AI-Powered OSINT and Recon

LLMs and embedding-based retrieval significantly enhance reconnaissance operations — reducing multi-hour correlation tasks to seconds, enabling semantic search across leaked data, and automating structured intelligence gathering. This page covers AI-enhanced OSINT use cases, building recon agents with LangChain, embedding-based data search, and a hands-on recon lab walkthrough.

## AI Enhancement of Traditional OSINT Tasks

| Task | Traditional Method | AI-Augmented Method |
|------|------------------|---------------------|
| Subdomain Enumeration | Amass, Subfinder | LLM-based correlation and deduplication |
| WHOIS Analysis | WHOIS CLI | LLM summarization and ownership correlation |
| GitHub Leakage Detection | Gitleaks, TruffleHog | Embedding-based search and pattern recognition |
| Company Footprint Mapping | Manual multi-source scraping | LLM summarization + entity resolution |
| Infrastructure Correlation | IP/ASN lookup | LLM + vector search for reused infrastructure |
| Social Engineering Prep | Manual LinkedIn/Google dorking | LLM persona extraction from profiles |

### Advantages of AI in OSINT

- **Speed**: Reduce multi-hour correlation tasks to seconds
- **Semantic Understanding**: Go beyond keyword matching ("github token" vs "AWS key")
- **Scalability**: Run parallel recon tasks with multiple LLM agents
- **Contextualization**: Connect data points into attack narratives
- **Automation**: Create autonomous or semi-autonomous recon agents

## Key OSINT Sources to Feed AI Agents

| Source Type | Examples |
|-------------|---------|
| Public APIs | Shodan, Censys, SecurityTrails, GitHub, Hunter.io |
| Web scraping | Pastebin, social media, company sites |
| Domain data | WHOIS, DNSDB, Subfinder outputs |
| Leaks/Secrets | GitHub commits, paste leaks |
| Metadata | Job posts, documents, image EXIF |

## LLM-Based Recon Examples

### Passive DNS Analysis

```
Prompt: "Given the passive DNS records below, identify likely phishing domains."
Context: ["login-paypal.accountsecurity-updates.net", "appleid-verification.com", "secure.tesla-login.io"]

Output: "These domains resemble common phishing patterns. They mimic legitimate brands
and use typosquatting. High risk."
```

### OSINT Prompt Pipelines

```
# Enumerate emails and correlate org chart
prompt = "Enumerate emails and LinkedIn URLs for Acme Corp employees in cybersecurity roles."

# Passive subdomain discovery
"Find all subdomains of acme-corp.com using certificate transparency and DNS history."

# Technology fingerprinting from job postings
"Based on these 10 job listings from acme-corp.com, infer their internal tech stack."
```

## Embedding-Based Recon

Embeddings convert text into vectors. Use cosine similarity to find semantic matches across large datasets — far more powerful than keyword search.

### GitHub Recon via Embedding Search

1. Embed thousands of repo file names and contents into FAISS
2. Query: `"api_key AND slack"`
3. Output: Links to exact files containing hardcoded Slack tokens across multiple repos

### Credential Correlation

Use cosine similarity to match a leaked email/password combination with internal access tokens across multiple repositories. This identifies credential reuse across different platforms.

### Setting Up Embedding Search

```python
# Install dependencies
pip install langchain openai faiss-cpu chromadb

# Create a FAISS index from scraped GitHub content
from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores import FAISS

embeddings = OpenAIEmbeddings()

# Embed keywords to search for
queries = [
    "acme internal repo",
    "vpn access",
    "admin panel",
    "dev credentials"
]

# Build and query the vector store
vectorstore = FAISS.from_texts(corpus_texts, embeddings)
results = vectorstore.similarity_search("aws secret key", k=5)
```

## AI-Driven Reconnaissance Lab

### Environment Setup

```
# Required tools
pip install langchain openai shodan requests

# Set environment variables
OPENAI_API_KEY=sk-...
SHODAN_API_KEY=...
SERPER_API_KEY=...

# Alternative: use LocalAI, LLaMA.cpp, or OpenLLM for fully local operation
```

### LangChain Recon Agent Design

The agent takes a **target domain** and performs automated recon:

```python
from langchain.agents import initialize_agent, Tool
from langchain.llms import OpenAI

# Define tools the agent can call
tools = [
    Tool(name="shodan_lookup", func=shodan_lookup,
         description="Query Shodan for open ports and services on an IP"),
    Tool(name="whois_lookup", func=whois_lookup,
         description="Get WHOIS registration data for a domain"),
    Tool(name="subdomain_enum", func=subfinder_run,
         description="Enumerate subdomains using certificate transparency"),
    Tool(name="search_web", func=serper_search,
         description="Search for recent indexed pages about a target"),
]

agent = initialize_agent(tools, OpenAI(), agent="zero-shot-react-description", verbose=True)

# Run the agent
agent.run("""
You are an OSINT recon agent.
Your target is: acme-corp.com

1. Find subdomains.
2. Get WHOIS info.
3. Pull recent indexed pages.
4. Query Shodan for open services.

Respond with results in JSON format.
""")
```

### Example Shodan Tool Implementation

```python
import shodan

SHODAN_API_KEY = "your_api_key"
api = shodan.Shodan(SHODAN_API_KEY)

def shodan_lookup(query: str) -> dict:
    try:
        results = api.search(query)
        return {
            "total": results["total"],
            "hosts": [
                {
                    "ip": match["ip_str"],
                    "ports": match.get("port"),
                    "org": match.get("org", "N/A"),
                    "hostnames": match.get("hostnames", [])
                }
                for match in results["matches"][:10]
            ]
        }
    except Exception as e:
        return {"error": str(e)}
```

### Realistic Recon Workflow

Target: `acme-corp.com`

| Task | Output |
|------|--------|
| Google search scraping | 10+ recent links mentioning acme-corp.com |
| Subdomain discovery | vpn.acme-corp.com, dev.acme-corp.com |
| WHOIS | Created 2017, hosted by AWS, contact hidden via PrivacyGuard |
| Shodan | Port 80/443, Port 8080 exposed on vpn.acme-corp.com |
| GitHub semantic OSINT | Repo: acme-devops-scripts with hardcoded credentials |

### Structured JSON Output Format

```json
{
  "target": "acme-corp.com",
  "subdomains": ["dev.acme-corp.com", "vpn.acme-corp.com"],
  "whois": {
    "created": "2017-08-14",
    "registrar": "NameCheap",
    "privacy": "enabled"
  },
  "shodan": {
    "vpn.acme-corp.com": {
      "open_ports": [80, 443, 8080],
      "technologies": ["nginx", "OpenVPN"]
    }
  },
  "recent_links": [
    "https://news.com/article?id=acme-corp-breach",
    "https://pastebin.com/leak_acme"
  ],
  "github_findings": [
    {
      "repo": "acme-devops-scripts",
      "file": "deploy.sh",
      "issue": "hardcoded AWS credentials"
    }
  ]
}
```

## Building an OSINT LLM from a Custom Knowledge Base

### Choosing the Right Model Architecture

| Approach | When to Use | Tools |
|----------|-------------|-------|
| RAG + Base LLM | Large static knowledge bases, frequent updates | LangChain + FAISS/Chroma |
| Fine-tuned model | Consistent domain-specific output, offline use | Axolotl, QLoRA, HuggingFace |
| Prompt engineering | Rapid prototyping, closed-source models | GPT-4, Claude API |
| Hybrid (RAG + LoRA) | Best of both: memory + specialization | LangChain + Ollama + LoRA adapters |

### Collecting and Structuring OSINT Data

Curate data from:
- Breach databases (properly handled)
- CVE/NVD feeds
- Shodan/Censys historical data
- GitHub commit histories
- Job posting corpora
- Forum/Pastebin archives

Structure as JSONL for fine-tuning or chunked text for embedding:
```json
{"prompt": "What is the tech stack used by acme-corp.com?",
 "completion": "Based on job listings and headers: nginx, React, PostgreSQL, AWS EC2"}
```

### Embedding Models for Searchable Knowledge

```python
# Lightweight embedding models for local use
# BAAI/bge-base-en-v1.5 — good balance of speed and accuracy
# intfloat/e5-base — strong for retrieval tasks
# all-MiniLM-L6-v2 — fast, lower memory

from sentence_transformers import SentenceTransformer
model = SentenceTransformer("BAAI/bge-base-en-v1.5")
embeddings = model.encode(corpus_texts)

# Store in FAISS for fast similarity search
import faiss
import numpy as np

dimension = embeddings.shape[1]
index = faiss.IndexFlatL2(dimension)
index.add(np.array(embeddings))
```

### Lightweight Recon Stack

```
# Fully local recon agent stack:

# 1. Local LLM via Ollama
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull mistral
ollama pull codellama

# 2. LangChain + local Ollama endpoint
from langchain.llms import Ollama
llm = Ollama(model="mistral")

# 3. Local vector store
from langchain.vectorstores import Chroma
vectorstore = Chroma(persist_directory="./recon_db", embedding_function=embeddings)

# 4. Passive tools (no active probing)
subfinder -d target.com -silent | tee subdomains.txt
amass enum -passive -d target.com | tee amass.txt
theHarvester -d target.com -b all | tee emails.txt
```

## Challenges and Mitigations

| Challenge | Solution |
|-----------|---------|
| Model hallucination | Use RAG with vector DBs — ground responses in real data |
| Privacy and legality of data | Adhere to OSINT scope and policies |
| Data freshness | Automate scraping and re-indexing pipelines |
| Prompt injection risks | Use controlled prompt templates and access filters |

## Strategic Use Cases

- **Attack Surface Mapping**: LLM + OSINT tools to generate organizational exposure reports
- **Red Team Report Automation**: Use model to generate exec summaries from recon results
- **Adversary Emulation**: Align recon with TTPs from known threat groups using MITRE ATT&CK
- **Social Engineering Prep**: Extract persona details and communication style from public profiles

## Lab Extensions

```
# Visualize discovered infrastructure
pip install networkx matplotlib

# Store recon data in persistent knowledge base
pip install chromadb

# Integrate subfinder and amass as callable agent tools
# Call them via subprocess and parse output as structured data

# Example: subfinder as LangChain tool
import subprocess
def run_subfinder(domain: str) -> str:
    result = subprocess.run(
        ["subfinder", "-d", domain, "-silent"],
        capture_output=True, text=True
    )
    return result.stdout
```

## Resources

- Shodan API — `developer.shodan.io`
- Hunter.io — `hunter.io/api`
- SecurityTrails — `securitytrails.com/corp/api`
- theHarvester — `github.com/laramies/theHarvester`
- Amass — `github.com/owasp-amass/amass`
- Subfinder — `github.com/projectdiscovery/subfinder`
- FAISS — `github.com/facebookresearch/faiss`
- ChromaDB — `github.com/chroma-core/chroma`
- Ollama — `ollama.ai`
