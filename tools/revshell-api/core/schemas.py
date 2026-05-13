"""
Pydantic request/response models. Shared across routers so the API surface stays
declarative and testable.

The `/chain` step models use pydantic discriminated unions so request validation
catches mismatched parameters at the API boundary instead of inside the dispatcher.
"""
from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field, field_validator

from generators import REGISTRY, SUPPORTED_LANGUAGES
from generators.c2profile import SUPPORTED_PLATFORMS
from generators.cloud import SUPPORTED_TECHNIQUES as CLOUD_TECHNIQUES
from generators.encode import SUPPORTED_TECHNIQUES as ENCODE_TECHNIQUES
from generators.adattack import SUPPORTED_TECHNIQUES as ADATTACK_TECHNIQUES
from generators.anti_forensics import SUPPORTED_TECHNIQUES as ANTI_FORENSICS_TECHNIQUES
from generators.evasion import SUPPORTED_TECHNIQUES as EVASION_TECHNIQUES
from generators.evasion_stack import SUPPORTED_EDRS
from generators.sandbox_evasion import SUPPORTED_TECHNIQUES as SANDBOX_EVASION_TECHNIQUES
from generators.harvest import SUPPORTED_TECHNIQUES as HARVEST_TECHNIQUES
from generators.initial_access import SUPPORTED_TECHNIQUES as INITIAL_ACCESS_TECHNIQUES
from generators.lateral import SUPPORTED_TECHNIQUES as LATERAL_TECHNIQUES
from generators.linux_harvest import SUPPORTED_TECHNIQUES as LINUX_HARVEST_TECHNIQUES
from generators.linux_persist import SUPPORTED_TECHNIQUES as LINUX_PERSIST_TECHNIQUES
from generators.linux_privesc import SUPPORTED_TECHNIQUES as LINUX_PRIVESC_TECHNIQUES
from generators.persist import SUPPORTED_TECHNIQUES as PERSIST_TECHNIQUES
from generators.privesc import SUPPORTED_TECHNIQUES as PRIVESC_TECHNIQUES
from generators.webshell import SUPPORTED_VARIANTS as WEBSHELL_VARIANTS

from .validation import validate_lhost

ARCH_VALUES = Literal["x86", "x64", "arm", "arm64", "mips", "any"]


# ── Shell ──────────────────────────────────────────────────────────────────────

class ShellRequest(BaseModel):
    lhost: str = Field(..., min_length=1, description="Listener host IP or hostname (IPv4/IPv6/FQDN)")
    lport: int = Field(..., ge=1, le=65535, description="Listener port (1-65535)")
    language: str = Field(..., description="Shell language")
    arch: ARCH_VALUES = Field(default="any", description="Target architecture")
    obfuscate: bool = Field(default=True, description="Apply variable randomisation and deep obfuscation")
    retry: bool = Field(default=False, description="Wrap payload in reconnect loop (30s interval)")
    egress_port: int | None = Field(default=None, ge=1, le=65535, description="Egress port for download cradles (defaults to lport)")
    encode: str | None = Field(default=None, description=f"Post-generation encoding technique: {', '.join(ENCODE_TECHNIQUES)}")
    c2_platform: str | None = Field(default=None, description=f"Generate C2 profile for platform: {', '.join(SUPPORTED_PLATFORMS)}")
    seed: int | None = Field(default=None, description="Deterministic seed for reproducible output (testing/docs)")

    @field_validator("lhost")
    @classmethod
    def _validate_lhost(cls, v: str) -> str:
        return validate_lhost(v)

    @field_validator("language")
    @classmethod
    def _validate_language(cls, v: str) -> str:
        normalized = v.lower()
        if normalized not in REGISTRY:
            raise ValueError(
                f"Unsupported language '{v}'. Supported: {', '.join(SUPPORTED_LANGUAGES)}"
            )
        return normalized

    @field_validator("encode")
    @classmethod
    def _validate_encode(cls, v: str | None) -> str | None:
        if v is not None and v not in ENCODE_TECHNIQUES:
            raise ValueError(
                f"Unsupported encode technique '{v}'. Supported: {', '.join(ENCODE_TECHNIQUES)}"
            )
        return v

    @field_validator("c2_platform")
    @classmethod
    def _validate_c2(cls, v: str | None) -> str | None:
        if v is not None and v not in SUPPORTED_PLATFORMS:
            raise ValueError(
                f"Unsupported C2 platform '{v}'. Supported: {', '.join(SUPPORTED_PLATFORMS)}"
            )
        return v


class C2ProfileResponse(BaseModel):
    platform: str
    havoc_profile: str | None = None
    cobalt_strike_profile: str | None = None
    sliver_profile: str | None = None
    mythic_profile: str | None = None


class ShellResponse(BaseModel):
    command: str
    language: str
    arch: str
    lhost: str
    lport: int
    variant: str
    listener: str | None = None
    tty_upgrade: str | None = None
    msf_compat: str | None = None
    listener_setup: dict | None = None
    encode_key: str | None = None
    c2_profile: C2ProfileResponse | None = None
    techniques: list[str] = []
    risk: str = "MEDIUM"
    detections: list[str] = []


# ── Redirector ────────────────────────────────────────────────────────────────

class RedirectorRequest(BaseModel):
    platform: str = Field(..., description=f"C2 platform to mimic: {', '.join(SUPPORTED_PLATFORMS)}")
    lhost: str = Field(..., min_length=1, description="C2 server host")
    lport: int = Field(..., ge=1, le=65535, description="C2 server port")
    decoy: str = Field(..., min_length=1, description="Decoy URL for non-matching traffic")

    @field_validator("lhost")
    @classmethod
    def _v(cls, v: str) -> str:
        return validate_lhost(v)

    @field_validator("platform")
    @classmethod
    def _vp(cls, v: str) -> str:
        if v not in SUPPORTED_PLATFORMS:
            raise ValueError(f"Unsupported platform '{v}'. Supported: {', '.join(SUPPORTED_PLATFORMS)}")
        return v


class RedirectorResponse(BaseModel):
    platform: str
    apache_htaccess: str
    nginx_config: str


# ── Module request bases (DRY) ────────────────────────────────────────────────

class _TechniqueBase(BaseModel):
    """Common fields for technique-driven endpoints."""
    obfuscate: bool = Field(default=True, description="Apply obfuscation")


class HarvestRequest(_TechniqueBase):
    technique: str = Field(..., description=f"Harvest technique: {', '.join(HARVEST_TECHNIQUES)}")
    outfile: str = Field(default="C:\\Windows\\Temp\\lsass.dmp")
    lhost: str = Field(default="192.168.1.100")
    lport: int = Field(default=8080, ge=1, le=65535)

    @field_validator("lhost")
    @classmethod
    def _v(cls, v: str) -> str:
        return validate_lhost(v)

    @field_validator("technique")
    @classmethod
    def _vt(cls, v: str) -> str:
        if v not in HARVEST_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(HARVEST_TECHNIQUES)}")
        return v


class PersistRequest(_TechniqueBase):
    technique: str = Field(..., description=f"Persistence technique: {', '.join(PERSIST_TECHNIQUES)}")
    payload: str = Field(default="C:\\Windows\\Temp\\payload.exe")
    name: str = Field(default="WindowsUpdater")

    @field_validator("technique")
    @classmethod
    def _vt(cls, v: str) -> str:
        if v not in PERSIST_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(PERSIST_TECHNIQUES)}")
        return v


class LateralRequest(_TechniqueBase):
    technique: str = Field(..., description=f"Lateral movement technique: {', '.join(LATERAL_TECHNIQUES)}")
    target: str = Field(default="TARGET_HOST")
    command: str = Field(default="whoami")
    username: str = Field(default="DOMAIN\\USER")
    password: str = Field(default="PASS")
    hash_nt: str = Field(default="")
    lhost: str = Field(default="192.168.1.100")
    lport: int = Field(default=8080, ge=1, le=65535)

    @field_validator("lhost")
    @classmethod
    def _v(cls, v: str) -> str:
        return validate_lhost(v)

    @field_validator("technique")
    @classmethod
    def _vt(cls, v: str) -> str:
        if v not in LATERAL_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(LATERAL_TECHNIQUES)}")
        return v


class ADAttackRequest(_TechniqueBase):
    technique: str = Field(..., description=f"AD attack technique: {', '.join(ADATTACK_TECHNIQUES)}")
    domain: str = Field(default="DOMAIN.LOCAL")
    dc_host: str = Field(default="DC01")
    dc_ip: str | None = Field(default=None, description="DC IP — required for zerologon_check")
    username: str = Field(default="USER")
    password: str = Field(default="PASS")
    hash_nt: str = Field(default="")
    outfile: str = Field(default="C:\\Windows\\Temp\\ad_out.txt")
    lhost: str = Field(default="192.168.1.100")
    lport: int = Field(default=8080, ge=1, le=65535)

    @field_validator("lhost")
    @classmethod
    def _v(cls, v: str) -> str:
        return validate_lhost(v)

    @field_validator("technique")
    @classmethod
    def _vt(cls, v: str) -> str:
        if v not in ADATTACK_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(ADATTACK_TECHNIQUES)}")
        return v


class PrivescRequest(_TechniqueBase):
    technique: str = Field(..., description=f"PrivEsc technique: {', '.join(PRIVESC_TECHNIQUES)}")
    payload: str = Field(default="C:\\Windows\\Temp\\payload.exe")
    name: str = Field(default="WindowsUpdate")

    @field_validator("technique")
    @classmethod
    def _vt(cls, v: str) -> str:
        if v not in PRIVESC_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(PRIVESC_TECHNIQUES)}")
        return v


class EvasionRequest(_TechniqueBase):
    technique: str = Field(..., description=f"Evasion technique: {', '.join(EVASION_TECHNIQUES)}")
    payload: str = Field(default="powershell.exe")
    lhost: str = Field(default="192.168.1.100")
    lport: int = Field(default=8080, ge=1, le=65535)

    @field_validator("lhost")
    @classmethod
    def _v(cls, v: str) -> str:
        return validate_lhost(v)

    @field_validator("technique")
    @classmethod
    def _vt(cls, v: str) -> str:
        if v not in EVASION_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(EVASION_TECHNIQUES)}")
        return v


class WebShellRequest(_TechniqueBase):
    variant: str = Field(..., description=f"Web shell variant: {', '.join(WEBSHELL_VARIANTS)}")
    token: str = Field(default="S3cr3tT0k3n", min_length=6)

    @field_validator("variant")
    @classmethod
    def _vv(cls, v: str) -> str:
        if v not in WEBSHELL_VARIANTS:
            raise ValueError(f"Unsupported variant '{v}'. Supported: {', '.join(WEBSHELL_VARIANTS)}")
        return v


class LinuxPersistRequest(_TechniqueBase):
    technique: str = Field(..., description=f"Persistence technique: {', '.join(LINUX_PERSIST_TECHNIQUES)}")
    payload: str = Field(default="/tmp/payload.sh")
    name: str = Field(default="sysupdate")
    lhost: str = Field(default="192.168.1.100")
    lport: int = Field(default=4444, ge=1, le=65535)

    @field_validator("lhost")
    @classmethod
    def _v(cls, v: str) -> str:
        return validate_lhost(v)

    @field_validator("technique")
    @classmethod
    def _vt(cls, v: str) -> str:
        if v not in LINUX_PERSIST_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(LINUX_PERSIST_TECHNIQUES)}")
        return v


class LinuxHarvestRequest(_TechniqueBase):
    technique: str = Field(..., description=f"Harvest technique: {', '.join(LINUX_HARVEST_TECHNIQUES)}")
    outfile: str = Field(default="/tmp/loot.txt")
    lhost: str = Field(default="192.168.1.100")
    lport: int = Field(default=8080, ge=1, le=65535)

    @field_validator("lhost")
    @classmethod
    def _v(cls, v: str) -> str:
        return validate_lhost(v)

    @field_validator("technique")
    @classmethod
    def _vt(cls, v: str) -> str:
        if v not in LINUX_HARVEST_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(LINUX_HARVEST_TECHNIQUES)}")
        return v


class LinuxPrivescRequest(_TechniqueBase):
    technique: str = Field(..., description=f"PrivEsc technique: {', '.join(LINUX_PRIVESC_TECHNIQUES)}")
    payload: str = Field(default="/tmp/payload.sh")
    name: str = Field(default="sysupdate")

    @field_validator("technique")
    @classmethod
    def _vt(cls, v: str) -> str:
        if v not in LINUX_PRIVESC_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(LINUX_PRIVESC_TECHNIQUES)}")
        return v


class CloudRequest(_TechniqueBase):
    technique: str = Field(..., description=f"Cloud technique: {', '.join(CLOUD_TECHNIQUES)}")
    outfile: str = Field(default="/tmp/cloud_loot.json")
    lhost: str = Field(default="192.168.1.100")

    @field_validator("lhost")
    @classmethod
    def _v(cls, v: str) -> str:
        return validate_lhost(v)

    @field_validator("technique")
    @classmethod
    def _vt(cls, v: str) -> str:
        if v not in CLOUD_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(CLOUD_TECHNIQUES)}")
        return v


class InitialAccessRequest(_TechniqueBase):
    technique: str = Field(..., description=f"Initial access technique: {', '.join(INITIAL_ACCESS_TECHNIQUES)}")
    lhost: str = Field(..., min_length=1)
    lport: int = Field(..., ge=1, le=65535)

    @field_validator("lhost")
    @classmethod
    def _v(cls, v: str) -> str:
        return validate_lhost(v)

    @field_validator("technique")
    @classmethod
    def _vt(cls, v: str) -> str:
        if v not in INITIAL_ACCESS_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(INITIAL_ACCESS_TECHNIQUES)}")
        return v


# ── Generic technique response (shared across most modules) ───────────────────

class TechniqueResponse(BaseModel):
    command: str
    technique: str
    notes: str
    techniques: list[str] = []
    risk: str = "MEDIUM"
    detections: list[str] = []


class WebShellResponse(BaseModel):
    shell: str
    variant: str
    upload_hint: str
    access_example: str
    techniques: list[str] = []
    risk: str = "CRITICAL"
    detections: list[str] = []


class InitialAccessResponse(BaseModel):
    payload: str
    technique: str
    delivery_hint: str
    notes: str
    techniques: list[str] = []
    risk: str = "HIGH"
    detections: list[str] = []


class CloudResponse(TechniqueResponse):
    platform: str


# ── Batch + chain ─────────────────────────────────────────────────────────────

class BatchGenerateRequest(BaseModel):
    requests: list[ShellRequest] = Field(..., min_length=1, max_length=20)


class _StepBase(BaseModel):
    pass


class GenerateStep(_StepBase):
    module: Literal["generate"]
    technique: str = "default"
    language: str = "bash"
    obfuscate: bool = True


class HarvestStep(_StepBase):
    module: Literal["harvest"]
    technique: str
    outfile: str = "C:\\Windows\\Temp\\lsass.dmp"
    obfuscate: bool = True


class PersistStep(_StepBase):
    module: Literal["persist"]
    technique: str
    payload: str = "C:\\Windows\\Temp\\payload.exe"
    name: str = "WindowsUpdater"
    obfuscate: bool = True


class ADAttackStep(_StepBase):
    module: Literal["adattack"]
    technique: str
    domain: str = "DOMAIN.LOCAL"
    dc_host: str = "DC01"
    dc_ip: str | None = None
    username: str = "USER"
    password: str = "PASS"
    hash_nt: str = ""
    outfile: str = "C:\\Windows\\Temp\\ad_out.txt"
    obfuscate: bool = True


class LinuxPersistStep(_StepBase):
    module: Literal["linux_persist"]
    technique: str
    payload: str = "/tmp/payload.sh"
    name: str = "sysupdate"


class CloudStep(_StepBase):
    module: Literal["cloud"]
    technique: str
    outfile: str = "/tmp/cloud_loot.json"


class InitialAccessStep(_StepBase):
    module: Literal["initial_access"]
    technique: str
    obfuscate: bool = True


class LateralStep(_StepBase):
    module: Literal["lateral"]
    technique: str
    target: str = "TARGET_HOST"
    command: str = "whoami"
    username: str = "DOMAIN\\USER"
    password: str = "PASS"
    hash_nt: str = ""
    obfuscate: bool = True


class EvasionStep(_StepBase):
    module: Literal["evasion"]
    technique: str
    payload: str = "powershell.exe"
    obfuscate: bool = True


# ── Anti-forensics ────────────────────────────────────────────────────────────

class AntiForensicsRequest(_TechniqueBase):
    technique: str = Field(..., description=f"Anti-forensics technique: {', '.join(ANTI_FORENSICS_TECHNIQUES)}")
    target: str = Field(default="auto", description="Optional target path (used by time_stomp, ads_hide_payload)")

    @field_validator("technique")
    @classmethod
    def _vt(cls, v: str) -> str:
        if v not in ANTI_FORENSICS_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(ANTI_FORENSICS_TECHNIQUES)}")
        return v


class AntiForensicsStep(_StepBase):
    module: Literal["anti_forensics"]
    technique: str
    target: str = "auto"
    obfuscate: bool = True


# ── Sandbox evasion ───────────────────────────────────────────────────────────

class SandboxEvasionRequest(_TechniqueBase):
    technique: str = Field(..., description=f"Sandbox evasion technique: {', '.join(SANDBOX_EVASION_TECHNIQUES)}")
    threshold: int = Field(default=0, ge=0, description=(
        "Per-technique threshold (seconds, GB, pixels, file count). 0 = use technique default."
    ))

    @field_validator("technique")
    @classmethod
    def _vt(cls, v: str) -> str:
        if v not in SANDBOX_EVASION_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(SANDBOX_EVASION_TECHNIQUES)}")
        return v


class SandboxEvasionStep(_StepBase):
    module: Literal["sandbox_evasion"]
    technique: str
    threshold: int = 0
    obfuscate: bool = True


AnyStep = Annotated[
    Union[
        GenerateStep, HarvestStep, PersistStep, ADAttackStep,
        LinuxPersistStep, CloudStep, InitialAccessStep, LateralStep, EvasionStep,
        AntiForensicsStep, SandboxEvasionStep,
    ],
    Field(discriminator="module"),
]


class ChainRequest(BaseModel):
    lhost: str = Field(..., min_length=1)
    lport: int = Field(..., ge=1, le=65535)
    steps: list[AnyStep] = Field(..., min_length=1, max_length=10)

    @field_validator("lhost")
    @classmethod
    def _v(cls, v: str) -> str:
        return validate_lhost(v)


class ChainStep(BaseModel):
    step: int
    module: str
    technique: str
    command: str
    notes: str = ""
    techniques: list[str] = []
    risk: str = "MEDIUM"


class ChainResponse(BaseModel):
    lhost: str
    lport: int
    steps: list[ChainStep]
    total_steps: int


# ── /stack — EDR-aware evasion stack orchestrator ─────────────────────────────

class StackRequest(BaseModel):
    edr: str | None = Field(default=None, description=f"Target EDR vendor (legacy single field): {', '.join(SUPPORTED_EDRS)}")
    edrs: list[str] | None = Field(default=None, description="Multiple target EDRs — stack counters all of them (union, deduped)")
    lhost: str = Field(..., min_length=1)
    lport: int = Field(..., ge=1, le=65535)
    language: str = Field(default="powershell", description="Shell language for the payload step")
    obfuscate: bool = Field(default=True)
    include_anti_forensics: bool = Field(default=True)
    include_sandbox_evasion: bool = Field(default=True)
    seed: int | None = Field(default=None, description="Deterministic seed for reproducible output")

    @field_validator("edr")
    @classmethod
    def _ve(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in SUPPORTED_EDRS:
            raise ValueError(f"Unsupported EDR '{v}'. Supported: {', '.join(SUPPORTED_EDRS)}")
        return v

    @field_validator("edrs")
    @classmethod
    def _ves(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        if not v:
            raise ValueError("edrs cannot be an empty list — supply at least one EDR or use the `edr` field")
        for e in v:
            if e not in SUPPORTED_EDRS:
                raise ValueError(f"Unsupported EDR '{e}'. Supported: {', '.join(SUPPORTED_EDRS)}")
        return v

    @field_validator("lhost")
    @classmethod
    def _vl(cls, v: str) -> str:
        return validate_lhost(v)

    @field_validator("language")
    @classmethod
    def _vlang(cls, v: str) -> str:
        normalized = v.lower()
        if normalized not in REGISTRY:
            raise ValueError(f"Unsupported language '{v}'. Supported: {', '.join(SUPPORTED_LANGUAGES)}")
        return normalized

    def resolved_edrs(self) -> list[str]:
        """Normalize edr + edrs into a single list (edrs wins if both set)."""
        if self.edrs:
            return self.edrs
        if self.edr:
            return [self.edr]
        raise ValueError("Either `edr` or `edrs` must be provided.")


class StackEntryResponse(BaseModel):
    step: int
    module: str
    technique: str
    command: str
    rationale: str
    techniques: list[str] = []
    counters: list[str] = []
    risk: str = "HIGH"


class StackResponse(BaseModel):
    edr: str
    listener: str
    chain: list[StackEntryResponse]
    total_steps: int
    summary: str


# ── /recommend — constraint-driven technique selector ──────────────────────────

class RecommendRequest(BaseModel):
    has_admin: bool = Field(default=True, description="Operator has local admin / SYSTEM on the target")
    target_os: str = Field(default="any", description="OS tag: windows10 / windows11 / windows-server / any")
    blocks_amsi: bool = Field(default=False, description="Target environment blocks unsigned PowerShell via AMSI")
    blocks_etw: bool = Field(default=False, description="Target environment relies on ETW for behavioral telemetry")
    has_userland_hooks: bool = Field(default=False, description="EDR has userland inline hooks on NTAPI")
    has_memory_scanner: bool = Field(default=False, description="EDR runs a memory scanner during process lifetime")
    has_callstack_inspection: bool = Field(default=False, description="EDR walks callstack on syscall entry")
    target_edrs: list[str] | None = Field(default=None, description=f"Target EDRs from: {', '.join(SUPPORTED_EDRS)}")
    families: list[str] | None = Field(default=None, description="Restrict to families: evasion / injection / hardening")
    max_techniques: int = Field(default=10, ge=1, le=50)

    @field_validator("target_edrs")
    @classmethod
    def _vte(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        for e in v:
            if e not in SUPPORTED_EDRS:
                raise ValueError(f"Unsupported EDR '{e}'. Supported: {', '.join(SUPPORTED_EDRS)}")
        return v


class RecommendationItem(BaseModel):
    technique: str
    rationale: str
    family: str
    risk: str
    counters: list[str] = []


class RecommendResponse(BaseModel):
    constraints_summary: str
    recommendations: list[RecommendationItem]
    total: int
