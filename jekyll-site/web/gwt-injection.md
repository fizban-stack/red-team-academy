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

## Tools

- [FSecureLABS/GWTMap](https://github.com/FSecureLABS/GWTMap) — Map the attack surface of GWT applications, generate and probe RPC payloads
- [GDSSecurity/GWT-Penetration-Testing-Toolset](https://github.com/GDSSecurity/GWT-Penetration-Testing-Toolset) — Tools for intercepting and manipulating GWT-RPC traffic

## Resources

- From Serialized to Shell: Exploiting GWT with EL Injection — Steven Seeley — `srcincite.io/blog/2017/05/22/from-serialized-to-shell-auditing-google-web-toolkit-with-el-injection.html`
- Hacking a Google Web Toolkit Application — thehackerish — `thehackerish.com/hacking-a-google-web-toolkit-application/`
