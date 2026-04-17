---
layout: training-page
title: "Source Code Auditing with CodeQL & Semgrep — Red Team Academy"
module: "Vulnerability Research"
tags:
  - codeql
  - semgrep
  - static-analysis
  - taint-tracking
  - sast
  - code-audit
  - joern
page_key: "vuln-research-audit-tooling"
render_with_liquid: false
---

# Source Code Auditing with CodeQL & Semgrep

Static Application Security Testing (SAST) tools automate the discovery of vulnerability patterns across large codebases. CodeQL, Semgrep, and Joern bring different strengths — CodeQL's taint tracking finds data-flow vulnerabilities like SQL injection and command injection end-to-end; Semgrep's AST-based pattern matching excels at finding dangerous API usage; Joern's code property graph enables deep interprocedural analysis for C/C++ and Java. This page covers practical usage for vulnerability research and offensive security.

---

## CodeQL Setup and Basics

CodeQL (acquired by GitHub from Semmle in 2019) represents a program as a database of facts and uses a Datalog-like query language to express security properties. It supports C/C++, Java, Python, JavaScript, Go, C#, Ruby, and Swift.

### Installation

```bash
# Download CodeQL CLI
# https://github.com/github/codeql-cli-binaries/releases
wget https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip
unzip codeql-linux64.zip -d /opt/codeql
export PATH="/opt/codeql:$PATH"

# Clone CodeQL queries (community library)
git clone https://github.com/github/codeql.git /opt/codeql-queries

# Verify
codeql version
```

### Creating a CodeQL Database

The database creation step compiles the target project while CodeQL intercepts the build:

```bash
# C/C++ project
cd /path/to/target_source
codeql database create target-db \
  --language=cpp \
  --command="make -j$(nproc)" \
  --source-root=.

# Java project (Maven)
codeql database create target-db \
  --language=java \
  --command="mvn clean compile" \
  --source-root=.

# Python project (no compilation needed)
codeql database create target-db \
  --language=python \
  --source-root=.

# JavaScript/TypeScript
codeql database create target-db \
  --language=javascript \
  --source-root=.
```

### Running Pre-Built Queries

```bash
# Run all security queries against the database
codeql database analyze target-db \
  /opt/codeql-queries/cpp/ql/src/Security/ \
  --format=sarif-latest \
  --output=results.sarif

# Or run against a specific query pack
codeql pack download codeql/cpp-queries
codeql database analyze target-db codeql/cpp-queries \
  --format=csv \
  --output=results.csv

# View results
cat results.csv | head -20
# Or use VS Code CodeQL extension for GUI view
```

### CodeQL Query Language

CodeQL QL is a logic programming language where you describe *what you're looking for* rather than *how to find it*:

```ql
/**
 * @name Command injection via user input
 * @description User input flows to a shell command execution
 * @kind path-problem
 * @tags security
 *       external/cwe/cwe-078
 */
import cpp
import semmle.code.cpp.security.CommandExecution
import semmle.code.cpp.dataflow.TaintTracking

// Define what counts as "user input" (source)
class UserInputSource extends DataFlow::Node {
  UserInputSource() {
    // Read from stdin
    exists(FunctionCall fc |
      fc.getTarget().hasName("fgets") or
      fc.getTarget().hasName("read") or
      fc.getTarget().hasName("recv") |
      this.asExpr() = fc.getArgument(0)
    )
  }
}

// Define what counts as "command execution" (sink)
class CommandSink extends DataFlow::Node {
  CommandSink() {
    exists(FunctionCall fc |
      fc.getTarget().hasName("system") or
      fc.getTarget().hasName("execve") or
      fc.getTarget().hasName("popen") |
      this.asExpr() = fc.getArgument(0)
    )
  }
}

// Taint tracking configuration
class CommandInjectionConfig extends TaintTracking::Configuration {
  CommandInjectionConfig() { this = "CommandInjection" }
  override predicate isSource(DataFlow::Node node) { node instanceof UserInputSource }
  override predicate isSink(DataFlow::Node node) { node instanceof CommandSink }
}

// Show all paths from source to sink
from CommandInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Command injection: user input $@ flows to command.", source.getNode(), "here"
```

```bash
# Run the query
codeql query run cmd_injection.ql \
  --database=target-db \
  --output=results.bqrs

# Decode results
codeql bqrs decode results.bqrs --format=csv
```

### Taint Tracking — Finding SQL Injection

```ql
/**
 * @name SQL injection via string concatenation
 * @kind path-problem
 */
import java
import semmle.code.java.security.QueryInjection
import semmle.code.java.dataflow.TaintTracking

class SqlInjectionConfig extends TaintTracking::Configuration {
  SqlInjectionConfig() { this = "SQLInjection" }
  
  // Sources: HTTP request parameters, cookies, headers
  override predicate isSource(DataFlow::Node node) {
    exists(MethodAccess ma |
      ma.getMethod().hasName("getParameter") or
      ma.getMethod().hasName("getCookies") or
      ma.getMethod().hasName("getHeader") |
      node.asExpr() = ma
    )
  }
  
  // Sinks: JDBC execute methods
  override predicate isSink(DataFlow::Node node) {
    exists(MethodAccess ma |
      ma.getMethod().hasName("execute") or
      ma.getMethod().hasName("executeQuery") or
      ma.getMethod().hasName("executeUpdate") |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement") |
      node.asExpr() = ma.getArgument(0)
    )
  }
  
  // Sanitizers: parameterized queries
  override predicate isSanitizer(DataFlow::Node node) {
    exists(MethodAccess ma |
      ma.getMethod().hasName("prepareStatement") |
      node.asExpr() = ma
    )
  }
}

from SqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, source, sink, "SQL injection: $@ reaches query.", source, "user input"
```

### Writing Custom CodeQL Queries

```ql
/**
 * @name Dangerous use of memcpy with user-controlled length
 * @kind alert
 */
import cpp

from FunctionCall fc, Variable lenVar
where
  fc.getTarget().hasName("memcpy") and
  fc.getArgument(2) = lenVar.getAnAccess() and
  // Length variable comes from an external source
  exists(FunctionCall src |
    src.getTarget().hasName("recv") or
    src.getTarget().hasName("read") or
    src.getTarget().hasName("fread") |
    // Simplified: lenVar appears in same function, after external read
    src.getEnclosingFunction() = fc.getEnclosingFunction()
  )
select fc, "memcpy with potentially user-controlled length $@", lenVar, lenVar.getName()
```

---

## Semgrep

Semgrep matches patterns against Abstract Syntax Trees (ASTs), making it faster to write rules than CodeQL but less capable of deep data flow analysis.

### Installation

```bash
pip install semgrep
# Or
brew install semgrep

semgrep --version
```

### YAML Rule Format

```yaml
# semgrep-rule.yaml — basic dangerous function detection
rules:
  - id: dangerous-strcpy
    patterns:
      - pattern: strcpy($DST, $SRC)
    message: |
      strcpy() has no bounds checking. Use strncpy() or strlcpy().
      Destination: $DST, Source: $SRC
    severity: ERROR
    languages: [c, cpp]
    metadata:
      cwe: CWE-120
      owasp: A1:2017-Injection
```

```bash
# Run against target
semgrep --config semgrep-rule.yaml /path/to/source/

# Run community rulesets
semgrep --config p/security-audit /path/to/source/
semgrep --config p/owasp-top-ten /path/to/source/
semgrep --config p/r2c-security-audit /path/to/source/

# Output formats
semgrep --config p/security-audit --json /path/to/source/ | jq .results
semgrep --config p/security-audit --sarif /path/to/source/ > results.sarif
```

### Pre-Built Semgrep Rulesets

| Ruleset | Command | Focus |
|---------|---------|-------|
| Security audit | `p/security-audit` | General security anti-patterns |
| OWASP Top 10 | `p/owasp-top-ten` | Web vulnerabilities |
| Insecure defaults | `p/insecure-transport` | TLS, crypto misconfigs |
| CI/CD security | `p/ci` | Pipeline secrets, misconfigs |
| Secrets detection | `p/secrets` | API keys, passwords in code |
| Supply chain | `p/supply-chain` | Dependency confusion risks |

```bash
# Run multiple rulesets at once
semgrep --config p/security-audit \
        --config p/owasp-top-ten \
        --config p/secrets \
        --exclude "*.test.*" \
        --exclude "vendor/" \
        /path/to/source/
```

### Semgrep Taint Mode

Semgrep's taint mode tracks data flow from sources to sinks:

```yaml
rules:
  - id: taint-command-injection
    mode: taint
    pattern-sources:
      - patterns:
          - pattern: request.args.get(...)
          - pattern: request.form.get(...)
          - pattern: request.json.get(...)
    pattern-sinks:
      - patterns:
          - pattern: subprocess.run($CMD, ...)
          - pattern: os.system($CMD)
          - pattern: os.popen($CMD)
    pattern-sanitizers:
      - patterns:
          - pattern: shlex.quote($X)
    message: |
      Command injection: user input from $SOURCE flows to shell command $SINK
    severity: ERROR
    languages: [python]
```

### Writing Custom Semgrep Rules for Target Codebase

```yaml
# Target-specific rule: detect use of internal unsafe API
rules:
  - id: custom-unsafe-api
    patterns:
      - pattern: InternalLib.dangerousMethod($USER_INPUT, ...)
      - pattern-not: InternalLib.dangerousMethod(CONSTANT_VALUE, ...)
    message: "Unsafe InternalLib.dangerousMethod called with non-constant arg"
    severity: WARNING
    languages: [java]

  # Find hardcoded credentials in config files
  - id: hardcoded-password
    patterns:
      - pattern: |
          password = "..."
      - pattern-not: |
          password = ""
      - pattern-not: |
          password = os.environ.get(...)
    message: "Hardcoded password detected"
    severity: ERROR
    languages: [python, javascript]
```

### CI/CD Integration

```yaml
# .github/workflows/semgrep.yml
name: Semgrep Security Scan
on: [push, pull_request]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/owasp-top-ten
          generateSarif: true
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: semgrep.sarif
```

**Offensive use of CI monitoring**: Monitor a target organization's public CI/CD runs to detect when they add security-related dependencies or scan their own code — often signals awareness of a bug they're fixing.

---

## grep / ripgrep for Manual Source Audit

Before automated tools, grep-based pattern search remains invaluable for quick triage:

```bash
# Find dangerous function calls
rg "strcpy|strcat|sprintf|gets|scanf\s*\(" --type c -n

# Find SQL string concatenation
rg "SELECT.*\+|\".*SELECT.*\"\s*\+" --type java -n

# Find command execution with variable arguments
rg "subprocess\.run\(|os\.system\(|exec\(" --type py -n

# Find hardcoded credentials
rg -i "(password|passwd|pwd|secret|api_key|token)\s*=\s*['\"][^'\"]{6,}" -n

# Find TODO/FIXME/HACK security notes from developers
rg "TODO.*[Ss]ec|FIXME.*[Ss]ec|HACK.*[Aa]uth|SECURITY:|VULNERABLE" -n

# Find deserialization points
rg "pickle\.loads|yaml\.load\(|JSON\.parse|deserialize|fromXML" -n

# Find file operations with user-controlled paths
rg "open\(.*request\.|fopen\(.*argv|readFile\(.*req\." -n

# Find JWT/crypto misuse
rg "algorithm.*none|verify.*false|validateJWT.*skip" -n

# Recursive ripgrep with context
rg -A 3 -B 3 "memcpy\s*\([^,]+,[^,]+,\s*[a-z_]*len" --type c
```

---

## Joern: Code Property Graphs

Joern builds Code Property Graphs (CPG) — a unified representation of AST, CFG (Control Flow Graph), PDG (Program Dependence Graph), and call graph — enabling deep interprocedural analysis.

### Installation

```bash
# Prerequisites: Java 11+
brew install joern  # macOS
# Or manual install:
wget https://github.com/joernio/joern/releases/latest/download/joern-install.sh
chmod +x joern-install.sh
./joern-install.sh
```

### Analyzing C/C++ with Joern

```bash
# Create CPG for C project
joern-parse /path/to/c_source/ --output cpg.bin

# Start Joern shell
joern --import cpg.bin
```

```scala
// Joern Scala shell queries

// Find all calls to strcpy
cpg.call("strcpy").location.toList

// Find all parameters that are user-controlled (reach from main argv)
cpg.method("main").parameter.name("argv")
  .reachableBy(cpg.call.name("strcpy").argument(1))
  .location.toList

// Find all functions that call memcpy with a length argument
// that originates from an external source
cpg.call("memcpy").where(_.argument(3).isCallTo("recv")).location.toList

// Find all heap allocations where size comes from external input
cpg.call("malloc").where { call =>
  call.argument(0).reachableBy(cpg.call("recv").argument(3))
}.location.toList

// Trace data flow from network receive to format string
val src = cpg.call("recv").argument(1)  // Buffer argument
val sink = cpg.call("printf").argument(0)  // Format string argument
sink.reachableBy(src).location.toList
```

### Joern for Java Analysis

```bash
joern-parse target.jar --output cpg.bin
joern --import cpg.bin
```

```scala
// Find all HttpServletRequest.getParameter() calls
cpg.call("getParameter").location.toList

// Trace from HTTP parameters to JDBC execute
val httpSource = cpg.call("getParameter")
val jdbcSink = cpg.call("execute|executeQuery")
jdbcSink.argument.reachableBy(httpSource).location.toList

// Find all classes implementing Serializable (deserialization targets)
cpg.typeDecl.filter(_.inheritsFromTypeFullName.contains("java.io.Serializable"))
   .name.toList
```

---

## Practical Workflow: Auditing a New Target

### Reconnaissance Phase

```bash
# 1. Get a feel for the codebase size and languages
cloc /path/to/source --by-file-by-lang | head -30

# 2. Identify the attack surface (entry points)
# For web apps:
grep -r "@RequestMapping\|@GetMapping\|@PostMapping" --include="*.java" -l
grep -r "router\.\|app\.get\|app\.post" --include="*.js" -l

# For native apps:
grep -r "main\|WinMain\|DllMain" --include="*.c" --include="*.cpp" -l

# 3. Quick dangerous function audit
rg "strcpy|strcat|sprintf|gets|system\|exec\|popen" --type c | wc -l
rg "eval\|exec\|subprocess\|os\.system" --type py | wc -l
```

### Automated Analysis Phase

```bash
# Run both CodeQL and Semgrep for maximum coverage
# CodeQL: deep data flow
codeql database create target-db --language=cpp --command="make"
codeql database analyze target-db codeql/cpp-queries --format=sarif --output=codeql.sarif

# Semgrep: quick pattern matching
semgrep --config p/security-audit --config p/owasp-top-ten \
  --json /path/to/source/ > semgrep.json

# Merge and prioritize results
python3 - << 'EOF'
import json, sarif_om

# Parse CodeQL SARIF
with open("codeql.sarif") as f:
    sarif = json.load(f)
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            print(f"[CodeQL] {result['ruleId']}: {result['message']['text'][:80]}")

# Parse Semgrep JSON
with open("semgrep.json") as f:
    semgrep = json.load(f)
    for result in semgrep.get("results", []):
        if result["severity"] == "ERROR":
            print(f"[Semgrep] {result['check_id']}: {result['path']}:{result['start']['line']}")
EOF
```

### Manual Review Phase

Focus manual effort on the highest-impact findings:
1. All `EXPLOITABLE` CodeQL results
2. Custom business logic (not covered by generic rules)
3. Authentication and authorization paths
4. Cryptographic operations
5. Deserialization entry points
