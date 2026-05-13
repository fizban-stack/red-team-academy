"""
One smoke test per shell language. Each language must:
- accept a ShellOptions instance
- produce a non-empty command string
- thread the supplied lhost/lport into the output
- be deterministic when a seed is provided
"""
import pytest

from generators import REGISTRY, SUPPORTED_LANGUAGES
from generators.base import ShellOptions

LHOST = "10.0.0.5"
LPORT = 4444


def _build(language: str, obfuscate: bool = False, seed: int | None = None):
    opts = ShellOptions(
        lhost=LHOST, lport=LPORT, arch="any",
        obfuscate=obfuscate, seed=seed,
    )
    return REGISTRY[language]().generate(opts)


import base64
import re

_B64_RE = re.compile(r"[A-Za-z0-9+/=]{16,}")


def _contains_anywhere(command: str, needle: str) -> bool:
    """
    Some generators base64-encode their source (golang, csharp, lolbins-mshta,
    etc.) — sometimes as UTF-8, sometimes as UTF-16LE for PowerShell's
    -EncodedCommand. Scan literal text first, then every base64-looking blob
    in both encodings.
    """
    if needle in command:
        return True
    for blob in _B64_RE.findall(command):
        for encoding in ("utf-8", "utf-16-le"):
            try:
                decoded = base64.b64decode(blob, validate=False).decode(encoding, errors="replace")
            except Exception:
                continue
            if needle in decoded:
                return True
    return False


@pytest.mark.parametrize("language", SUPPORTED_LANGUAGES)
def test_generator_produces_command(language):
    result = _build(language, obfuscate=False)
    assert result.command, f"{language} produced empty command"
    assert _contains_anywhere(result.command, LHOST), f"{language} did not include lhost {LHOST}"
    assert _contains_anywhere(result.command, str(LPORT)), f"{language} did not include lport {LPORT}"


@pytest.mark.parametrize("language", SUPPORTED_LANGUAGES)
def test_generator_seeded_is_deterministic(language):
    a = _build(language, obfuscate=True, seed=42)
    b = _build(language, obfuscate=True, seed=42)
    assert a.command == b.command, f"{language} not deterministic with seed=42"


def test_powershell_variants_obfuscate_changes_form():
    a = _build("powershell", obfuscate=False, seed=1).command
    b = _build("powershell", obfuscate=True, seed=1).command
    assert a != b, "obfuscate=True must change powershell output"


def test_unknown_language_rejected():
    assert "definitely-not-a-language" not in REGISTRY
