"""lhost validation — covers the GET-endpoint command-injection gap fix."""
import pytest

from core.validation import validate_lhost

VALID = [
    "10.0.0.1",
    "192.168.1.100",
    "[::1]",
    "[fe80::1]",
    "host.example.com",
    "host-with-dashes.example.com",
]

INVALID = [
    "10.0.0.1;ls",
    "10.0.0.1 && rm",
    "10.0.0.1`id`",
    "10.0.0.1$(id)",
    "10.0.0.1|cat",
    "10.0.0.1>/tmp/x",
    "10.0.0.1\nls",
    "",
]


@pytest.mark.parametrize("v", VALID)
def test_valid_lhost(v):
    assert validate_lhost(v) == v


@pytest.mark.parametrize("v", INVALID)
def test_invalid_lhost(v):
    with pytest.raises(ValueError):
        validate_lhost(v)
