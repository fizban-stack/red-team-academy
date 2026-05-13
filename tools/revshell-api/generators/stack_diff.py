"""
EDR stack comparator.

Given two EDR names, build both stacks and compute:
  - shared techniques (appear in both stacks)
  - only_a (appear in edr_a's stack but not edr_b's)
  - only_b (appear in edr_b's stack but not edr_a's)

Categorizes results by module (sandbox_evasion / evasion / shell / anti_forensics)
and provides per-technique rationales from the originating stack.

Deterministic — same (edr_a, edr_b) pair always returns the same result.
"""
from dataclasses import dataclass, field

from .evasion_stack import build_stack, EvasionStackResult, StackEntry


@dataclass
class DiffItem:
    technique: str
    module: str
    rationale_a: str | None = None
    rationale_b: str | None = None


@dataclass
class StackDiffResult:
    edr_a: str
    edr_b: str
    shared: list[DiffItem] = field(default_factory=list)
    only_a: list[DiffItem] = field(default_factory=list)
    only_b: list[DiffItem] = field(default_factory=list)
    summary: str = ""

    @property
    def shared_count(self) -> int:
        return len(self.shared)

    @property
    def only_a_count(self) -> int:
        return len(self.only_a)

    @property
    def only_b_count(self) -> int:
        return len(self.only_b)


def _module_order(module: str) -> int:
    return {"sandbox_evasion": 0, "evasion": 1, "shell": 2, "anti_forensics": 3}.get(module, 99)


def diff_stacks(
    edr_a: str,
    edr_b: str,
    lhost: str = "192.168.1.100",
    lport: int = 4444,
    language: str = "powershell",
    obfuscate: bool = True,
) -> StackDiffResult:
    """
    Build both stacks and compute the symmetric difference.

    Returns StackDiffResult with three lists:
        shared  — techniques present in both stacks
        only_a  — techniques present only in edr_a's stack
        only_b  — techniques present only in edr_b's stack

    Each list is sorted by module order (sandbox first) then technique name.
    """
    stack_a: EvasionStackResult = build_stack(
        edrs=edr_a, lhost=lhost, lport=lport, language=language, obfuscate=obfuscate,
    )
    stack_b: EvasionStackResult = build_stack(
        edrs=edr_b, lhost=lhost, lport=lport, language=language, obfuscate=obfuscate,
    )

    # Build lookup dicts: technique -> StackEntry for each stack
    map_a: dict[str, StackEntry] = {e.technique: e for e in stack_a.chain}
    map_b: dict[str, StackEntry] = {e.technique: e for e in stack_b.chain}

    all_techniques = sorted(set(map_a) | set(map_b))

    shared: list[DiffItem] = []
    only_a: list[DiffItem] = []
    only_b: list[DiffItem] = []

    for tech in all_techniques:
        in_a = tech in map_a
        in_b = tech in map_b
        module = (map_a.get(tech) or map_b.get(tech)).module  # type: ignore[union-attr]
        rat_a = map_a[tech].rationale if in_a else None
        rat_b = map_b[tech].rationale if in_b else None

        item = DiffItem(technique=tech, module=module, rationale_a=rat_a, rationale_b=rat_b)
        if in_a and in_b:
            shared.append(item)
        elif in_a:
            only_a.append(item)
        else:
            only_b.append(item)

    def _sort_key(d: DiffItem) -> tuple[int, str]:
        return (_module_order(d.module), d.technique)

    shared.sort(key=_sort_key)
    only_a.sort(key=_sort_key)
    only_b.sort(key=_sort_key)

    summary = (
        "Stack comparison: " + edr_a + " vs " + edr_b + ". "
        + str(len(shared)) + " shared technique(s), "
        + str(len(only_a)) + " unique to " + edr_a + ", "
        + str(len(only_b)) + " unique to " + edr_b + ". "
        "Shared techniques represent your common baseline; unique techniques show "
        "where the two EDRs have distinct telemetry priorities."
    )

    return StackDiffResult(
        edr_a=edr_a,
        edr_b=edr_b,
        shared=shared,
        only_a=only_a,
        only_b=only_b,
        summary=summary,
    )
