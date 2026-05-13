"""Obfuscation helpers."""
import random

from generators.obfuscate import (
    bash_base64_pipe, bash_hex_encode, bash_octal_encode, bash_split_keyword,
    ps_amsi_bypass, ps_char_array, ps_concat_split, ps_etw_bypass,
    ps_invoke_expression_alt, ps_tick_marks,
)


def test_bash_hex_encode_roundtrip():
    assert bash_hex_encode("/bin/bash") == "$'\\x2f\\x62\\x69\\x6e\\x2f\\x62\\x61\\x73\\x68'"


def test_bash_base64_pipe_envelope_contains_b64():
    out = bash_base64_pipe("echo hi")
    assert out.startswith("echo ") and "base64 -d|bash" in out


def test_bash_split_keyword_returns_assignment_and_reference():
    setup, ref = bash_split_keyword("bash")
    # ref must dereference two vars that, joined, reconstitute the keyword.
    assert ref.startswith("$") and "$" in ref[1:]


def test_bash_octal_encode_emits_octals():
    assert bash_octal_encode("a") == "$'\\141'"


def test_ps_tick_marks_obfuscates_every_occurrence():
    random.seed(123)
    out = ps_tick_marks("System.Net.Sockets.System.Net.System")
    # Every 'System' should now carry a tick — none should remain bare.
    assert "System" not in out.replace("`", "")[:6] or True  # always true; below is the real check
    # Stronger: no run of 6 alpha chars 'System' is present without a tick inside.
    import re
    bare = re.findall(r"\bSystem\b", out)
    assert bare == [], f"unticked 'System' remained: {bare}"


def test_ps_char_array_round_trips_chars():
    out = ps_char_array("hi")
    assert "104,105" in out  # ord('h'), ord('i')


def test_ps_concat_split_preserves_content():
    parts = ps_concat_split("HelloWorld", min_chunk=2, max_chunk=3)
    # Strip the quoting/+ and recompose.
    pieces = parts.replace("'", "").split("+")
    assert "".join(pieces) == "HelloWorld"


def test_ps_amsi_bypass_includes_amsi_init_failed_marker():
    plain = ps_amsi_bypass(obfuscate=False)
    assert "amsiInitFailed" in plain


def test_ps_etw_bypass_outputs_marshal_writebyte():
    plain = ps_etw_bypass(obfuscate=False)
    assert "WriteByte" in plain


def test_ps_invoke_expression_alt_returns_one_of_known_forms():
    out = ps_invoke_expression_alt("d")
    assert any(x in out for x in ("ScriptBlock", "Invoke-Expression", "iex"))
