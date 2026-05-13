"""Per-request payload encoding."""
import pytest

from generators.encode import SUPPORTED_TECHNIQUES, encode_command


@pytest.mark.parametrize("technique", SUPPORTED_TECHNIQUES)
def test_encode_technique_returns_string_command(technique):
    out, key = encode_command("echo hi", technique, "bash")
    assert isinstance(out, str) and out
    assert isinstance(key, str)


def test_encode_xor_envelope_includes_python3_decode():
    out, key = encode_command("id", "xor", "bash")
    assert "python3 -c" in out
    assert int(key, 16) >= 1


def test_encode_b64_powershell_is_idempotent_for_encoded_command():
    base, _ = encode_command("whoami", "b64", "powershell")
    second, _ = encode_command(base, "b64", "powershell")
    # Re-encoding a payload already containing -EncodedCommand should be a no-op.
    assert second == base


def test_unknown_technique_raises():
    with pytest.raises(ValueError):
        encode_command("x", "nope", "bash")
