"""Tests for the generators/stack_diff.py module (Phase C)."""
import pytest

from generators.evasion_stack import SUPPORTED_EDRS
from generators.stack_diff import StackDiffResult, diff_stacks

LHOST = "10.10.10.10"
LPORT = 4444


# ── Basic smoke tests ─────────────────────────────────────────────────────────

def test_diff_returns_result_object():
    r = diff_stacks("defender", "crowdstrike", LHOST, LPORT)
    assert isinstance(r, StackDiffResult)


def test_diff_edr_names_preserved():
    r = diff_stacks("defender", "sentinelone", LHOST, LPORT)
    assert r.edr_a == "defender"
    assert r.edr_b == "sentinelone"


def test_diff_summary_nonempty():
    r = diff_stacks("defender", "crowdstrike", LHOST, LPORT)
    assert r.summary


def test_diff_counts_match_list_lengths():
    r = diff_stacks("defender", "crowdstrike", LHOST, LPORT)
    assert r.shared_count == len(r.shared)
    assert r.only_a_count == len(r.only_a)
    assert r.only_b_count == len(r.only_b)


# ── Partition correctness ─────────────────────────────────────────────────────

def test_diff_shared_techniques_in_both():
    """Every technique in shared must appear in both stacks."""
    from generators.evasion_stack import build_stack
    r = diff_stacks("defender", "crowdstrike", LHOST, LPORT)
    sa = {e.technique for e in build_stack(edrs="defender", lhost=LHOST, lport=LPORT).chain}
    sb = {e.technique for e in build_stack(edrs="crowdstrike", lhost=LHOST, lport=LPORT).chain}
    for item in r.shared:
        assert item.technique in sa, f"{item.technique} claimed shared but absent from defender stack"
        assert item.technique in sb, f"{item.technique} claimed shared but absent from crowdstrike stack"


def test_diff_only_a_not_in_b():
    """Every technique in only_a must NOT appear in edr_b's stack."""
    from generators.evasion_stack import build_stack
    r = diff_stacks("defender", "crowdstrike", LHOST, LPORT)
    sb = {e.technique for e in build_stack(edrs="crowdstrike", lhost=LHOST, lport=LPORT).chain}
    for item in r.only_a:
        assert item.technique not in sb, f"{item.technique} in only_a but also in crowdstrike"


def test_diff_only_b_not_in_a():
    """Every technique in only_b must NOT appear in edr_a's stack."""
    from generators.evasion_stack import build_stack
    r = diff_stacks("defender", "crowdstrike", LHOST, LPORT)
    sa = {e.technique for e in build_stack(edrs="defender", lhost=LHOST, lport=LPORT).chain}
    for item in r.only_b:
        assert item.technique not in sa, f"{item.technique} in only_b but also in defender"


def test_diff_no_duplicate_across_sets():
    """A technique must appear in exactly one of shared/only_a/only_b."""
    r = diff_stacks("defender", "crowdstrike", LHOST, LPORT)
    shared_t = {i.technique for i in r.shared}
    only_a_t = {i.technique for i in r.only_a}
    only_b_t = {i.technique for i in r.only_b}
    assert not (shared_t & only_a_t), f"Overlap shared∩only_a: {shared_t & only_a_t}"
    assert not (shared_t & only_b_t), f"Overlap shared∩only_b: {shared_t & only_b_t}"
    assert not (only_a_t & only_b_t), f"Overlap only_a∩only_b: {only_a_t & only_b_t}"


# ── Determinism ───────────────────────────────────────────────────────────────

def test_diff_is_deterministic():
    r1 = diff_stacks("defender", "crowdstrike", LHOST, LPORT)
    r2 = diff_stacks("defender", "crowdstrike", LHOST, LPORT)
    assert [i.technique for i in r1.shared] == [i.technique for i in r2.shared]
    assert [i.technique for i in r1.only_a] == [i.technique for i in r2.only_a]
    assert [i.technique for i in r1.only_b] == [i.technique for i in r2.only_b]


def test_diff_is_commutative_in_counts():
    """Swapping edr_a and edr_b should swap only_a and only_b counts."""
    r1 = diff_stacks("defender", "crowdstrike", LHOST, LPORT)
    r2 = diff_stacks("crowdstrike", "defender", LHOST, LPORT)
    assert r1.shared_count == r2.shared_count
    assert r1.only_a_count == r2.only_b_count
    assert r1.only_b_count == r2.only_a_count


# ── Self-diff ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("edr", SUPPORTED_EDRS)
def test_self_diff_all_shared(edr):
    """Diffing an EDR against itself must yield all shared and nothing unique."""
    r = diff_stacks(edr, edr, LHOST, LPORT)
    assert r.only_a_count == 0, f"{edr} vs {edr}: expected 0 only_a, got {r.only_a_count}"
    assert r.only_b_count == 0, f"{edr} vs {edr}: expected 0 only_b, got {r.only_b_count}"
    assert r.shared_count > 0, f"{edr} vs {edr}: expected shared > 0"


# ── Module categorization ─────────────────────────────────────────────────────

def test_diff_items_have_valid_modules():
    r = diff_stacks("defender", "crowdstrike", LHOST, LPORT)
    valid_modules = {"sandbox_evasion", "evasion", "shell", "anti_forensics"}
    all_items = r.shared + r.only_a + r.only_b
    for item in all_items:
        assert item.module in valid_modules, f"{item.technique} has unexpected module '{item.module}'"


def test_diff_shared_items_have_both_rationales():
    r = diff_stacks("defender", "crowdstrike", LHOST, LPORT)
    for item in r.shared:
        assert item.rationale_a, f"Shared item {item.technique} missing rationale_a"
        assert item.rationale_b, f"Shared item {item.technique} missing rationale_b"


def test_diff_only_a_has_rationale_a_but_not_b():
    r = diff_stacks("defender", "crowdstrike", LHOST, LPORT)
    for item in r.only_a:
        assert item.rationale_a, f"only_a item {item.technique} missing rationale_a"
        assert item.rationale_b is None, f"only_a item {item.technique} should have no rationale_b"


def test_diff_only_b_has_rationale_b_but_not_a():
    r = diff_stacks("defender", "crowdstrike", LHOST, LPORT)
    for item in r.only_b:
        assert item.rationale_b, f"only_b item {item.technique} missing rationale_b"
        assert item.rationale_a is None, f"only_b item {item.technique} should have no rationale_a"


# ── Cross-EDR coverage ────────────────────────────────────────────────────────

@pytest.mark.parametrize("pair", [
    ("defender", "crowdstrike"),
    ("defender", "sentinelone"),
    ("defender", "carbonblack"),
    ("crowdstrike", "sentinelone"),
    ("crowdstrike", "carbonblack"),
    ("sentinelone", "carbonblack"),
])
def test_cross_edr_diff_has_nonzero_unique(pair):
    """Two different EDRs should always have at least one unique technique each."""
    r = diff_stacks(pair[0], pair[1], LHOST, LPORT)
    assert r.only_a_count > 0 or r.only_b_count > 0, (
        f"{pair[0]} vs {pair[1]}: expected at least one difference"
    )
