"""
Constraint-driven evasion technique recommender.

Operator describes their situation (admin? target OS? what AMSI blocks them?
which EDRs are on the box?) and the recommender returns an ordered list of
techniques that fit, with rationale.

Decoupled from /stack: /stack is opinionated per-EDR; /recommend is a
constraint solver across the technique catalog.
"""
from dataclasses import dataclass, field

SUPPORTED_OS = ("windows10", "windows11", "windows-server", "any")
SUPPORTED_AMSI_BLOCKS = ("string_signature", "behavioral", "cloud_lookup", "none")


@dataclass
class TechniqueProfile:
    """
    Per-technique constraint metadata. Used by the recommender to filter the
    catalog. The 'name' must match a /evasion technique identifier.
    """
    name: str
    requires_admin: bool = False
    requires_user_interaction: bool = False
    works_on: tuple[str, ...] = ("any",)  # OS tags from SUPPORTED_OS
    bypasses_amsi: bool = False
    bypasses_etw: bool = False
    bypasses_userland_hooks: bool = False
    bypasses_memory_scanner: bool = False
    bypasses_callstack_inspection: bool = False
    works_against: tuple[str, ...] = ()       # EDR identifiers
    breaks_under: tuple[str, ...] = ()        # EDR identifiers (won't help here)
    family: str = "evasion"                   # evasion / injection / persistence / hardening
    risk: str = "HIGH"
    description: str = ""


# ── Catalog ───────────────────────────────────────────────────────────────────
# Hand-curated metadata for the techniques worth recommending. Not every
# /evasion technique is here — some (like `obfuscate_base64`) are too primitive
# to recommend as a standalone choice; they're applied automatically by the
# shell generator.

_CATALOG: dict[str, TechniqueProfile] = {
    "amsi_reflection": TechniqueProfile(
        "amsi_reflection",
        bypasses_amsi=True, family="hardening",
        works_against=("carbonblack", "generic"),
        breaks_under=("defender", "sentinelone"),  # modern Defender catches the AmsiUtils reflection signature
        description="Classic reflection-based AMSI bypass — works against older AMSI integrations",
    ),
    "amsi_patch_clr": TechniqueProfile(
        "amsi_patch_clr",
        bypasses_amsi=True, family="hardening", risk="CRITICAL",
        works_against=("carbonblack", "generic"),
        breaks_under=("defender",),
        description="Byte-patch AmsiScanBuffer with `xor eax, eax; ret` — defeated by Defender image-integrity scan",
    ),
    "amsi_hwbp": TechniqueProfile(
        "amsi_hwbp", bypasses_amsi=True, bypasses_memory_scanner=True,
        works_on=("windows10", "windows11", "windows-server"),
        works_against=("defender", "sentinelone", "carbonblack", "generic"),
        family="hardening", risk="CRITICAL",
        description="Patchless AMSI via hardware breakpoint — no bytes modified",
    ),
    "etw_hwbp": TechniqueProfile(
        "etw_hwbp", bypasses_etw=True,
        works_against=("defender", "crowdstrike", "sentinelone", "generic"),
        family="hardening", risk="CRITICAL",
        description="Patchless ETW silencing for the current process",
    ),
    "etw_patch": TechniqueProfile(
        "etw_patch", bypasses_etw=True,
        works_against=("carbonblack", "generic"),
        breaks_under=("defender", "crowdstrike", "sentinelone"),
        family="hardening",
        description="Byte-patch EtwEventWrite — older EDRs only",
    ),
    "ntdll_unhook": TechniqueProfile(
        "ntdll_unhook", bypasses_userland_hooks=True,
        works_against=("defender", "sentinelone", "carbonblack", "generic"),
        breaks_under=("crowdstrike",),  # Falcon re-hooks aggressively
        family="hardening", risk="HIGH",
        description="Refresh ntdll.dll .text from disk — wipes userland hooks",
    ),
    "direct_syscalls": TechniqueProfile(
        "direct_syscalls", bypasses_userland_hooks=True,
        works_against=("defender", "sentinelone", "carbonblack", "generic"),
        breaks_under=("crowdstrike",),  # Falcon does callstack inspection
        family="injection", risk="CRITICAL",
        description="HellsGate-style direct syscalls — caller skips ntdll entirely",
    ),
    "indirect_syscalls": TechniqueProfile(
        "indirect_syscalls",
        bypasses_userland_hooks=True, bypasses_callstack_inspection=True,
        works_against=("defender", "crowdstrike", "sentinelone", "carbonblack", "generic"),
        family="injection", risk="CRITICAL",
        description="SysWhispers3 — syscall via ntdll's own gadget keeps callstack clean",
    ),
    "rop_sleep": TechniqueProfile(
        "rop_sleep", bypasses_memory_scanner=True,
        works_against=("crowdstrike", "sentinelone", "defender", "generic"),
        family="hardening", risk="CRITICAL",
        description="ROP-chain sleep mask — encrypts process memory during sleep",
    ),
    "ppid_spoof": TechniqueProfile(
        "ppid_spoof",
        works_against=("defender", "sentinelone", "carbonblack", "generic"),
        family="injection",
        description="Spoof parent PID to explorer.exe — defeats process-tree detection",
    ),
    "process_hollowing": TechniqueProfile(
        "process_hollowing",
        works_against=("carbonblack", "generic"),
        breaks_under=("defender", "crowdstrike", "sentinelone"),  # all flag the 5-step pattern
        family="injection", risk="CRITICAL",
        description="Classic process hollowing — well-known, most XDRs flag it",
    ),
    "module_stomping": TechniqueProfile(
        "module_stomping",
        works_against=("defender", "sentinelone", "carbonblack", "generic"),
        family="injection", risk="CRITICAL",
        description="Overwrite a signed DLL's .text — image-backed memory check passes",
    ),
    "thread_hijack": TechniqueProfile(
        "thread_hijack",
        works_against=("carbonblack", "generic"),
        family="injection", risk="CRITICAL",
        description="Suspend → SetThreadContext → Resume — flagged by CrowdStrike",
    ),
    "early_bird_apc": TechniqueProfile(
        "early_bird_apc", bypasses_userland_hooks=True,
        works_against=("crowdstrike", "sentinelone", "defender", "generic"),
        family="injection", risk="CRITICAL",
        description="APC queued before userland hooks load — fires during ntdll init",
    ),
    "apc_injection": TechniqueProfile(
        "apc_injection",
        works_against=("carbonblack", "generic"),
        family="injection",
        description="Classic NtQueueApcThread — needs another bypass for modern EDRs",
    ),
    "set_windows_hook_loader": TechniqueProfile(
        "set_windows_hook_loader", requires_user_interaction=True,
        works_against=("carbonblack", "generic"),
        family="injection",
        description="SetWindowsHookEx DLL injection — requires GUI thread on target",
    ),
    "com_rot_injection": TechniqueProfile(
        "com_rot_injection", requires_user_interaction=True,
        works_against=("carbonblack", "generic"),
        family="injection",
        description="COM Running Object Table abuse — needs Office automation consumer",
    ),
    "environment_keying": TechniqueProfile(
        "environment_keying", bypasses_memory_scanner=True,
        works_against=("defender", "crowdstrike", "sentinelone", "carbonblack", "generic"),
        family="hardening", risk="CRITICAL",
        description="Payload only decrypts on the target host — sandboxes get garbage",
    ),
    "in_memory_pe_loader": TechniqueProfile(
        "in_memory_pe_loader",
        works_against=("defender", "carbonblack", "generic"),
        breaks_under=("crowdstrike", "sentinelone"),  # both scan loaded assemblies
        family="injection", risk="CRITICAL",
        description="Reflective PE loader — Assembly.Load(byte[])",
    ),
    "dll_sideload": TechniqueProfile(
        "dll_sideload",
        works_against=("defender", "carbonblack", "generic"),
        family="injection",
        description="Sideload via signed binary (OneDrive, dbghelp, ...) — hijacklibs.net",
    ),
    "heaven_gate": TechniqueProfile(
        "heaven_gate", bypasses_userland_hooks=True,
        works_against=("defender", "carbonblack", "sentinelone", "generic"),
        breaks_under=("crowdstrike",),  # Falcon's kernel callbacks catch the 64-bit syscalls
        family="injection", risk="CRITICAL",
        description="WoW64 → 64-bit native syscall pivot",
    ),
    "process_ghosting": TechniqueProfile(
        "process_ghosting",
        works_against=("carbonblack", "generic"),
        breaks_under=("defender", "sentinelone"),
        family="injection", risk="CRITICAL",
        description="Process with no on-disk image — modern XDRs flag NULL image path",
    ),
    "process_doppelganging": TechniqueProfile(
        "process_doppelganging",
        works_against=("carbonblack", "generic"),
        family="injection", risk="CRITICAL",
        description="TxF transactional hollowing — Microsoft deprecated TxF but still works",
    ),
    "process_herpaderping": TechniqueProfile(
        "process_herpaderping",
        works_against=("carbonblack", "generic"),
        breaks_under=("defender", "crowdstrike"),
        family="injection", risk="CRITICAL",
        description="Write malicious PE → map → overwrite with benign PE",
    ),
    "peb_unlink": TechniqueProfile(
        "peb_unlink", bypasses_memory_scanner=True,
        works_against=("carbonblack", "generic"),
        family="hardening",
        description="Hide module from PEB->Ldr — defeats Ldr-iterating scanners",
    ),
    "phantom_dll_hollow": TechniqueProfile(
        "phantom_dll_hollow", bypasses_memory_scanner=True,
        works_against=("defender", "sentinelone", "carbonblack", "generic"),
        family="injection", risk="CRITICAL",
        description="Map signed DLL fresh + overwrite .text — memory checks see image-backed",
    ),
    "threadless_injection": TechniqueProfile(
        "threadless_injection",
        works_against=("defender", "crowdstrike", "sentinelone", "carbonblack", "generic"),
        family="injection", risk="CRITICAL",
        description="Hijack function-pointer dispatch instead of creating a thread",
    ),
    "stack_spoof": TechniqueProfile(
        "stack_spoof", bypasses_callstack_inspection=True,
        works_against=("crowdstrike", "defender", "sentinelone", "generic"),
        family="hardening", risk="CRITICAL",
        description="Fabricate clean call frames — defeats callstack walkers",
    ),
    "manual_map_header_erase": TechniqueProfile(
        "manual_map_header_erase", bypasses_memory_scanner=True,
        works_against=("defender", "sentinelone", "carbonblack", "generic"),
        family="hardening", risk="CRITICAL",
        description="Manual map + zero PE headers — hides from string-search scans",
    ),
    "function_level_encryption": TechniqueProfile(
        "function_level_encryption", bypasses_memory_scanner=True,
        works_against=("defender", "sentinelone", "carbonblack", "generic"),
        breaks_under=("crowdstrike",),  # Falcon page-flap detector
        family="hardening", risk="CRITICAL",
        description="Decrypt-execute-re-encrypt per function — beats memory scanners",
    ),
}


@dataclass
class Recommendation:
    technique: str
    rationale: str
    family: str
    risk: str
    counters: list[str] = field(default_factory=list)


@dataclass
class RecommenderResult:
    constraints_summary: str
    recommendations: list[Recommendation]
    total: int


def recommend(
    has_admin: bool = True,
    target_os: str = "any",
    blocks_amsi: bool = False,
    blocks_etw: bool = False,
    has_userland_hooks: bool = False,
    has_memory_scanner: bool = False,
    has_callstack_inspection: bool = False,
    target_edrs: list[str] | None = None,
    families: list[str] | None = None,
    max_techniques: int = 10,
) -> RecommenderResult:
    """
    Score each technique against the constraints and return the top N.

    Scoring:
        +2  every "bypasses_X" capability the operator asked for
        +1  per target EDR the technique is "works_against"
        −5  per target EDR the technique "breaks_under" (drop it entirely)
        +1  matches requested family
        +0  default catch-all

    target_edrs filters by "works_against" intersection. families filters by
    family tag.

    Returns techniques in descending score order, capped at max_techniques.
    """
    target_edrs = target_edrs or []
    families = families or []

    scored: list[tuple[int, TechniqueProfile]] = []
    for prof in _CATALOG.values():
        # Hard filters first.
        if not has_admin and prof.requires_admin:
            continue
        if target_os != "any" and target_os not in prof.works_on and "any" not in prof.works_on:
            continue
        if families and prof.family not in families:
            continue
        if target_edrs and not (set(target_edrs) & set(prof.works_against)):
            # Technique doesn't help against any requested EDR — skip.
            continue
        if target_edrs and (set(target_edrs) & set(prof.breaks_under)):
            # Disqualified against one of the target EDRs.
            continue

        score = 0
        if blocks_amsi and prof.bypasses_amsi:
            score += 2
        if blocks_etw and prof.bypasses_etw:
            score += 2
        if has_userland_hooks and prof.bypasses_userland_hooks:
            score += 2
        if has_memory_scanner and prof.bypasses_memory_scanner:
            score += 2
        if has_callstack_inspection and prof.bypasses_callstack_inspection:
            score += 2
        score += len(set(target_edrs) & set(prof.works_against))
        if families and prof.family in families:
            score += 1

        scored.append((score, prof))

    # Highest score first, then alphabetical for determinism.
    scored.sort(key=lambda kv: (-kv[0], kv[1].name))
    top = scored[:max_techniques]

    recommendations = [
        Recommendation(
            technique=p.name,
            rationale=p.description,
            family=p.family,
            risk=p.risk,
            counters=[e for e in target_edrs if e in p.works_against],
        )
        for _, p in top
    ]

    constraints = []
    constraints.append(f"admin={'yes' if has_admin else 'no'}")
    constraints.append(f"os={target_os}")
    if blocks_amsi: constraints.append("amsi_blocking")
    if blocks_etw: constraints.append("etw_blocking")
    if has_userland_hooks: constraints.append("userland_hooks")
    if has_memory_scanner: constraints.append("memory_scanner")
    if has_callstack_inspection: constraints.append("callstack_inspection")
    if target_edrs: constraints.append(f"edrs={','.join(target_edrs)}")
    if families: constraints.append(f"families={','.join(families)}")

    return RecommenderResult(
        constraints_summary=" | ".join(constraints),
        recommendations=recommendations,
        total=len(recommendations),
    )
