"""Unit tests for spray internals."""
import json
from pathlib import Path

import pytest

from spray import (
    _build_pairs, _build_proxies, _build_ua_pool, _load_lines,
    _load_state, _save_state,
)


def test_build_pairs_orders_password_outer_user_inner():
    pairs = _build_pairs(["alice", "bob"], ["Pass1", "Pass2"])
    assert pairs == [
        ("alice", "Pass1"), ("bob", "Pass1"),
        ("alice", "Pass2"), ("bob", "Pass2"),
    ]


def test_build_pairs_empty_inputs():
    assert _build_pairs([], ["p"]) == []
    assert _build_pairs(["u"], []) == []


def test_load_lines_strips_blanks(tmp_path):
    f = tmp_path / "users.txt"
    f.write_text("alice\n\nbob\n  charlie  \n\n")
    assert _load_lines(str(f)) == ["alice", "bob", "charlie"]


def test_state_roundtrip(tmp_path):
    path = tmp_path / ".state.json"
    _save_state(path, {"alice:Pass1", "bob:Pass1"})
    loaded = _load_state(path)
    assert loaded == {"alice:Pass1", "bob:Pass1"}


def test_load_state_missing_returns_empty(tmp_path):
    assert _load_state(tmp_path / "missing.json") == set()


def test_build_proxies_returns_none_when_unset():
    assert _build_proxies(None) is None
    assert _build_proxies("") is None


def test_build_proxies_wraps_url():
    out = _build_proxies("http://127.0.0.1:8080")
    assert out == {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}


def test_ua_pool_defaults_when_unset():
    pool = _build_ua_pool(None)
    assert len(pool) >= 3
    assert all("Mozilla" in ua for ua in pool)


def test_ua_pool_loads_from_file(tmp_path):
    f = tmp_path / "uas.txt"
    f.write_text("UA1\nUA2\n")
    pool = _build_ua_pool(str(f))
    assert pool == ["UA1", "UA2"]


def test_ua_pool_string_used_as_literal():
    pool = _build_ua_pool("MyCustomAgent/1.0")
    assert pool == ["MyCustomAgent/1.0"]
