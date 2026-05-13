import dataclasses
import os
import re
from typing import Annotated, Literal

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from generators import REGISTRY, SUPPORTED_LANGUAGES
from generators.base import ShellOptions
from generators.c2profile import SUPPORTED_PLATFORMS, generate_profile
from generators.cloud import SUPPORTED_TECHNIQUES as CLOUD_TECHNIQUES, generate_cloud
from generators.encode import SUPPORTED_TECHNIQUES, encode_command
from generators.adattack import SUPPORTED_TECHNIQUES as ADATTACK_TECHNIQUES, generate_adattack
from generators.evasion import SUPPORTED_TECHNIQUES as EVASION_TECHNIQUES, generate_evasion
from generators.harvest import SUPPORTED_TECHNIQUES as HARVEST_TECHNIQUES, generate_harvest
from generators.initial_access import SUPPORTED_TECHNIQUES as INITIAL_ACCESS_TECHNIQUES, generate_initial_access
from generators.lateral import SUPPORTED_TECHNIQUES as LATERAL_TECHNIQUES, generate_lateral
from generators.linux_harvest import SUPPORTED_TECHNIQUES as LINUX_HARVEST_TECHNIQUES, generate_linux_harvest
from generators.linux_persist import SUPPORTED_TECHNIQUES as LINUX_PERSIST_TECHNIQUES, generate_linux_persist
from generators.linux_privesc import SUPPORTED_TECHNIQUES as LINUX_PRIVESC_TECHNIQUES, generate_linux_privesc
from generators.persist import SUPPORTED_TECHNIQUES as PERSIST_TECHNIQUES, generate_persist
from generators.privesc import SUPPORTED_TECHNIQUES as PRIVESC_TECHNIQUES, generate_privesc
from generators.redirector import generate_redirector
from generators.webshell import SUPPORTED_VARIANTS as WEBSHELL_VARIANTS, generate_webshell

_LHOST_RE = re.compile(r"^[a-zA-Z0-9.\-:\[\]]+$")  # brackets for IPv6


def _validate_lhost(v: str) -> str:
    if not _LHOST_RE.match(v):
        raise ValueError("lhost must contain only alphanumeric characters, dots, hyphens, colons, or brackets")
    return v

ARCH_VALUES = Literal["x86", "x64", "arm", "arm64", "mips", "any"]

app = FastAPI(
    title="RevShell API",
    description="Reverse shell and red team command generator for authorized red team exercises.",
    version="4.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ── Request / Response Models ──────────────────────────────────────────────────

class ShellRequest(BaseModel):
    lhost: str = Field(..., min_length=1, description="Listener host IP or hostname (IPv4/IPv6/FQDN)")
    lport: int = Field(..., ge=1, le=65535, description="Listener port (1-65535)")
    language: str = Field(..., description="Shell language")
    arch: ARCH_VALUES = Field(default="any", description="Target architecture")
    obfuscate: bool = Field(default=True, description="Apply variable randomisation and deep obfuscation")
    retry: bool = Field(default=False, description="Wrap payload in reconnect loop (30s interval)")
    egress_port: int | None = Field(default=None, ge=1, le=65535, description="Egress port for download cradles (defaults to lport)")
    encode: str | None = Field(default=None, description=f"Post-generation encoding technique: {', '.join(SUPPORTED_TECHNIQUES)}")
    c2_platform: str | None = Field(default=None, description=f"Generate C2 profile for platform: {', '.join(SUPPORTED_PLATFORMS)}")

    @field_validator("lhost")
    @classmethod
    def validate_lhost(cls, v: str) -> str:
        return _validate_lhost(v)

    @field_validator("language")
    @classmethod
    def validate_language(cls, v: str) -> str:
        normalized = v.lower()
        if normalized not in REGISTRY:
            raise ValueError(
                f"Unsupported language '{v}'. Supported: {', '.join(SUPPORTED_LANGUAGES)}"
            )
        return normalized

    @field_validator("encode")
    @classmethod
    def validate_encode(cls, v: str | None) -> str | None:
        if v is not None and v not in SUPPORTED_TECHNIQUES:
            raise ValueError(
                f"Unsupported encode technique '{v}'. Supported: {', '.join(SUPPORTED_TECHNIQUES)}"
            )
        return v

    @field_validator("c2_platform")
    @classmethod
    def validate_c2_platform(cls, v: str | None) -> str | None:
        if v is not None and v not in SUPPORTED_PLATFORMS:
            raise ValueError(
                f"Unsupported C2 platform '{v}'. Supported: {', '.join(SUPPORTED_PLATFORMS)}"
            )
        return v


class RedirectorRequest(BaseModel):
    platform: str = Field(..., description=f"C2 platform to mimic: {', '.join(SUPPORTED_PLATFORMS)}")
    lhost: str = Field(..., min_length=1, description="C2 server host")
    lport: int = Field(..., ge=1, le=65535, description="C2 server port")
    decoy: str = Field(..., min_length=1, description="Decoy URL for non-matching traffic")

    @field_validator("lhost")
    @classmethod
    def validate_lhost(cls, v: str) -> str:
        return _validate_lhost(v)

    @field_validator("platform")
    @classmethod
    def validate_platform(cls, v: str) -> str:
        if v not in SUPPORTED_PLATFORMS:
            raise ValueError(f"Unsupported platform '{v}'. Supported: {', '.join(SUPPORTED_PLATFORMS)}")
        return v


class RedirectorResponse(BaseModel):
    platform: str
    apache_htaccess: str
    nginx_config: str


class HarvestRequest(BaseModel):
    technique: str = Field(..., description=f"Harvest technique: {', '.join(HARVEST_TECHNIQUES)}")
    outfile: str = Field(default="C:\\Windows\\Temp\\lsass.dmp", description="Output path for the dump file")
    obfuscate: bool = Field(default=True, description="Apply PS obfuscation")
    lhost: str = Field(default="192.168.1.100", description="Staging server IP for tool downloads")
    lport: int = Field(default=8080, ge=1, le=65535, description="Staging server port")

    @field_validator("technique")
    @classmethod
    def validate_technique(cls, v: str) -> str:
        if v not in HARVEST_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(HARVEST_TECHNIQUES)}")
        return v


class HarvestResponse(BaseModel):
    command: str
    technique: str
    notes: str
    techniques: list[str] = []
    risk: str = "HIGH"
    detections: list[str] = []


class PersistRequest(BaseModel):
    technique: str = Field(..., description=f"Persistence technique: {', '.join(PERSIST_TECHNIQUES)}")
    payload: str = Field(default="C:\\Windows\\Temp\\payload.exe", description="Path to the payload on the target")
    name: str = Field(default="WindowsUpdater", description="Registry value / task / service name")
    obfuscate: bool = Field(default=True, description="Apply PS obfuscation")

    @field_validator("technique")
    @classmethod
    def validate_technique(cls, v: str) -> str:
        if v not in PERSIST_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(PERSIST_TECHNIQUES)}")
        return v


class PersistResponse(BaseModel):
    command: str
    technique: str
    notes: str


class LateralRequest(BaseModel):
    technique: str = Field(..., description=f"Lateral movement technique: {', '.join(LATERAL_TECHNIQUES)}")
    target: str = Field(default="TARGET_HOST", description="Target hostname or IP")
    command: str = Field(default="whoami", description="Command to execute on the target")
    username: str = Field(default="DOMAIN\\USER", description="Username (DOMAIN\\user format)")
    password: str = Field(default="PASS", description="Plaintext password")
    hash_nt: str = Field(default="", description="NT hash for pass-the-hash techniques (32-char hex)")
    obfuscate: bool = Field(default=True, description="Apply PS obfuscation")

    @field_validator("technique")
    @classmethod
    def validate_technique(cls, v: str) -> str:
        if v not in LATERAL_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(LATERAL_TECHNIQUES)}")
        return v


class LateralResponse(BaseModel):
    command: str
    technique: str
    notes: str


class ADAttackRequest(BaseModel):
    technique: str = Field(..., description=f"AD attack technique: {', '.join(ADATTACK_TECHNIQUES)}")
    domain: str = Field(default="DOMAIN.LOCAL", description="Target AD domain FQDN")
    dc_host: str = Field(default="DC01", description="Domain controller hostname")
    username: str = Field(default="USER", description="Username")
    password: str = Field(default="PASS", description="Plaintext password")
    hash_nt: str = Field(default="", description="NT hash (32-char hex)")
    outfile: str = Field(default="C:\\Windows\\Temp\\ad_out.txt", description="Output file path on target")
    obfuscate: bool = Field(default=True, description="Apply PS obfuscation")
    lhost: str = Field(default="192.168.1.100", description="Staging server IP serving tools (PowerView, Rubeus, etc.)")
    lport: int = Field(default=8080, ge=1, le=65535, description="Staging server port")

    @field_validator("technique")
    @classmethod
    def validate_technique(cls, v: str) -> str:
        if v not in ADATTACK_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(ADATTACK_TECHNIQUES)}")
        return v


class ADAttackResponse(BaseModel):
    command: str
    technique: str
    notes: str
    techniques: list[str] = []
    risk: str = "HIGH"
    detections: list[str] = []


class PrivescRequest(BaseModel):
    technique: str = Field(..., description=f"PrivEsc technique: {', '.join(PRIVESC_TECHNIQUES)}")
    payload: str = Field(default="C:\\Windows\\Temp\\payload.exe", description="Payload path or command to run after escalation")
    name: str = Field(default="WindowsUpdate", description="Service / task name used by applicable techniques")
    obfuscate: bool = Field(default=True, description="Apply PS obfuscation")

    @field_validator("technique")
    @classmethod
    def validate_technique(cls, v: str) -> str:
        if v not in PRIVESC_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(PRIVESC_TECHNIQUES)}")
        return v


class PrivescResponse(BaseModel):
    command: str
    technique: str
    notes: str


class EvasionRequest(BaseModel):
    technique: str = Field(..., description=f"Evasion technique: {', '.join(EVASION_TECHNIQUES)}")
    payload: str = Field(default="powershell.exe", description="Command / script to execute or encode")
    obfuscate: bool = Field(default=True, description="Apply PS obfuscation")

    @field_validator("technique")
    @classmethod
    def validate_technique(cls, v: str) -> str:
        if v not in EVASION_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(EVASION_TECHNIQUES)}")
        return v


class EvasionResponse(BaseModel):
    command: str
    technique: str
    notes: str


class C2ProfileResponse(BaseModel):
    platform: str
    havoc_profile: str
    cobalt_strike_profile: str


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


class WebShellRequest(BaseModel):
    """Generate a server-side web shell (PHP/ASPX/JSP/CGI) for upload to a compromised web server."""
    variant: str = Field(..., description=f"Web shell variant: {', '.join(WEBSHELL_VARIANTS)}")
    obfuscate: bool = Field(default=True, description="Apply obfuscation to shell code")
    token: str = Field(default="S3cr3tT0k3n", min_length=6, description="Authentication token embedded in the shell")

    @field_validator("variant")
    @classmethod
    def validate_variant(cls, v: str) -> str:
        if v not in WEBSHELL_VARIANTS:
            raise ValueError(f"Unsupported variant '{v}'. Supported: {', '.join(WEBSHELL_VARIANTS)}")
        return v


class WebShellResponse(BaseModel):
    shell: str
    variant: str
    upload_hint: str
    access_example: str
    techniques: list[str] = []
    risk: str = "CRITICAL"
    detections: list[str] = []


class LinuxPersistRequest(BaseModel):
    """Generate Linux/macOS persistence commands."""
    technique: str = Field(..., description=f"Persistence technique: {', '.join(LINUX_PERSIST_TECHNIQUES)}")
    payload: str = Field(default="/tmp/payload.sh", description="Path to payload or command to persist")
    name: str = Field(default="sysupdate", description="Service/cron/key name identifier")
    lhost: str = Field(default="192.168.1.100", description="Attacker host (used by some techniques)")
    lport: int = Field(default=4444, ge=1, le=65535, description="Attacker port")

    @field_validator("technique")
    @classmethod
    def validate_technique(cls, v: str) -> str:
        if v not in LINUX_PERSIST_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(LINUX_PERSIST_TECHNIQUES)}")
        return v


class LinuxPersistResponse(BaseModel):
    command: str
    technique: str
    notes: str
    techniques: list[str] = []
    risk: str = "HIGH"
    detections: list[str] = []


class LinuxHarvestRequest(BaseModel):
    """Generate Linux credential harvesting commands."""
    technique: str = Field(..., description=f"Harvest technique: {', '.join(LINUX_HARVEST_TECHNIQUES)}")
    outfile: str = Field(default="/tmp/loot.txt", description="Output file path for collected data")
    lhost: str = Field(default="192.168.1.100", description="Attacker exfiltration host")
    lport: int = Field(default=8080, ge=1, le=65535, description="Attacker exfiltration port")

    @field_validator("technique")
    @classmethod
    def validate_technique(cls, v: str) -> str:
        if v not in LINUX_HARVEST_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(LINUX_HARVEST_TECHNIQUES)}")
        return v


class LinuxHarvestResponse(BaseModel):
    command: str
    technique: str
    notes: str
    techniques: list[str] = []
    risk: str = "HIGH"
    detections: list[str] = []


class LinuxPrivescRequest(BaseModel):
    """Generate Linux privilege escalation commands."""
    technique: str = Field(..., description=f"PrivEsc technique: {', '.join(LINUX_PRIVESC_TECHNIQUES)}")
    payload: str = Field(default="/tmp/payload.sh", description="Payload to execute after escalation")
    name: str = Field(default="sysupdate", description="Binary/service name for path hijacking techniques")

    @field_validator("technique")
    @classmethod
    def validate_technique(cls, v: str) -> str:
        if v not in LINUX_PRIVESC_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(LINUX_PRIVESC_TECHNIQUES)}")
        return v


class LinuxPrivescResponse(BaseModel):
    command: str
    technique: str
    notes: str
    techniques: list[str] = []
    risk: str = "HIGH"
    detections: list[str] = []


class CloudRequest(BaseModel):
    """Generate cloud environment attack commands (AWS/Azure/GCP/Kubernetes)."""
    technique: str = Field(..., description=f"Cloud technique: {', '.join(CLOUD_TECHNIQUES)}")
    outfile: str = Field(default="/tmp/cloud_loot.json", description="Output file for harvested data")
    lhost: str = Field(default="192.168.1.100", description="Attacker host for exfiltration")

    @field_validator("technique")
    @classmethod
    def validate_technique(cls, v: str) -> str:
        if v not in CLOUD_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(CLOUD_TECHNIQUES)}")
        return v


class CloudResponse(BaseModel):
    command: str
    technique: str
    platform: str
    notes: str
    techniques: list[str] = []
    risk: str = "HIGH"
    detections: list[str] = []


class InitialAccessRequest(BaseModel):
    """Generate initial access payloads (VBA macros, HTML smuggling, HTA, LNK shortcuts)."""
    technique: str = Field(..., description=f"Initial access technique: {', '.join(INITIAL_ACCESS_TECHNIQUES)}")
    lhost: str = Field(..., min_length=1, description="Attacker listener host")
    lport: int = Field(..., ge=1, le=65535, description="Attacker listener port")
    obfuscate: bool = Field(default=True, description="Apply obfuscation to payload")

    @field_validator("lhost")
    @classmethod
    def validate_lhost(cls, v: str) -> str:
        return _validate_lhost(v)

    @field_validator("technique")
    @classmethod
    def validate_technique(cls, v: str) -> str:
        if v not in INITIAL_ACCESS_TECHNIQUES:
            raise ValueError(f"Unsupported technique '{v}'. Supported: {', '.join(INITIAL_ACCESS_TECHNIQUES)}")
        return v


class InitialAccessResponse(BaseModel):
    payload: str
    technique: str
    delivery_hint: str
    notes: str
    techniques: list[str] = []
    risk: str = "HIGH"
    detections: list[str] = []


class BatchGenerateRequest(BaseModel):
    """Generate multiple shell payloads in one call."""
    requests: list[ShellRequest] = Field(..., min_length=1, max_length=20, description="List of shell generation requests (max 20)")


class ChainRequest(BaseModel):
    """Build an ordered execution chain across multiple technique modules."""
    lhost: str = Field(..., min_length=1, description="Attacker listener/staging host")
    lport: int = Field(..., ge=1, le=65535, description="Attacker listener port")
    steps: list[dict] = Field(
        ...,
        min_length=1,
        max_length=10,
        description=(
            "Ordered list of chain steps. Each step: "
            "{module: str, technique: str, ...extra_params}. "
            "Modules: generate, harvest, persist, adattack, linux_persist, cloud, initial_access."
        ),
    )


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


# ── Helper Functions ───────────────────────────────────────────────────────────

def _build_shell(req: ShellRequest) -> ShellResponse:
    opts = ShellOptions(
        lhost=req.lhost,
        lport=req.lport,
        arch=req.arch,
        obfuscate=req.obfuscate,
        retry=req.retry,
        egress_port=req.egress_port,
    )
    generator = REGISTRY[req.language]()
    result = generator.generate(opts)

    command = result.command
    encode_key: str | None = None
    if req.encode:
        command, encode_key = encode_command(command, req.encode, req.language)
        encode_key = encode_key or None

    c2_resp: C2ProfileResponse | None = None
    if req.c2_platform:
        profile = generate_profile(req.c2_platform, req.lhost, req.lport)
        c2_resp = C2ProfileResponse(**dataclasses.asdict(profile))

    listener_setup: dict | None = None
    if result.listener_setup is not None:
        listener_setup = dataclasses.asdict(result.listener_setup)

    return ShellResponse(
        command=command,
        language=result.language,
        arch=result.arch,
        lhost=req.lhost,
        lport=req.lport,
        variant=result.variant,
        listener=result.listener,
        tty_upgrade=result.tty_upgrade,
        msf_compat=result.msf_compat,
        listener_setup=listener_setup,
        encode_key=encode_key,
        c2_profile=c2_resp,
        techniques=result.techniques,
        risk=result.risk,
        detections=result.detections,
    )


# ── Core Endpoints ─────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "version": "4.0.0"}


@app.get("/languages")
def list_languages():
    return {"languages": SUPPORTED_LANGUAGES}


@app.get("/generate", response_model=ShellResponse)
def generate_get(
    lhost: Annotated[str, Query(min_length=1, description="Listener host IP")],
    lport: Annotated[int, Query(ge=1, le=65535, description="Listener port")],
    language: Annotated[str, Query(description="Shell language")],
    arch: Annotated[ARCH_VALUES, Query(description="Target architecture")] = "any",
    obfuscate: Annotated[bool, Query(description="Apply obfuscation")] = True,
    retry: Annotated[bool, Query(description="Wrap in reconnect loop")] = False,
    egress_port: Annotated[int | None, Query(ge=1, le=65535, description="Egress port for cradles")] = None,
    encode: Annotated[str | None, Query(description=f"Encode technique: {', '.join(SUPPORTED_TECHNIQUES)}")] = None,
    c2_platform: Annotated[str | None, Query(description=f"C2 platform: {', '.join(SUPPORTED_PLATFORMS)}")] = None,
):
    normalized = language.lower()
    if normalized not in REGISTRY:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported language '{language}'. Supported: {', '.join(SUPPORTED_LANGUAGES)}",
        )
    req = ShellRequest(
        lhost=lhost, lport=lport, language=normalized, arch=arch,
        obfuscate=obfuscate, retry=retry, egress_port=egress_port,
        encode=encode, c2_platform=c2_platform,
    )
    return _build_shell(req)


@app.post("/generate", response_model=ShellResponse)
def generate_post(req: ShellRequest):
    return _build_shell(req)


@app.post("/batch/generate", response_model=list[ShellResponse])
def batch_generate(req: BatchGenerateRequest):
    """Generate multiple shell payloads in a single call. Max 20 requests per batch."""
    return [_build_shell(r) for r in req.requests]


@app.post("/chain", response_model=ChainResponse)
def chain_build(req: ChainRequest):
    """
    Build an ordered attack chain across multiple technique modules.
    Each step specifies a module and technique to generate, producing a sequenced playbook.
    """
    if not _LHOST_RE.match(req.lhost):
        raise HTTPException(status_code=422, detail="Invalid lhost.")

    results: list[ChainStep] = []
    for i, step in enumerate(req.steps, 1):
        module = step.get("module", "")
        technique = step.get("technique", "")
        if not module or not technique:
            raise HTTPException(status_code=422, detail=f"Step {i}: 'module' and 'technique' are required.")

        try:
            if module == "generate":
                lang = step.get("language", "bash")
                if lang not in REGISTRY:
                    raise ValueError(f"Unsupported language: {lang}")
                shell_req = ShellRequest(
                    lhost=req.lhost, lport=req.lport, language=lang,
                    obfuscate=step.get("obfuscate", True),
                )
                resp = _build_shell(shell_req)
                results.append(ChainStep(
                    step=i, module=module, technique=resp.variant,
                    command=resp.command, notes=f"{lang} reverse shell",
                    techniques=resp.techniques, risk=resp.risk,
                ))

            elif module == "harvest":
                r = generate_harvest(
                    technique, step.get("outfile", "C:\\Windows\\Temp\\lsass.dmp"),
                    step.get("obfuscate", True), req.lhost, req.lport,
                )
                results.append(ChainStep(
                    step=i, module=module, technique=r.technique,
                    command=r.command, notes=r.notes,
                    techniques=r.techniques, risk=r.risk,
                ))

            elif module == "persist":
                r = generate_persist(
                    technique, step.get("payload", "C:\\Windows\\Temp\\payload.exe"),
                    step.get("name", "WindowsUpdater"), step.get("obfuscate", True),
                )
                results.append(ChainStep(
                    step=i, module=module, technique=r.technique,
                    command=r.command, notes=r.notes,
                ))

            elif module == "adattack":
                r = generate_adattack(
                    technique, step.get("domain", "DOMAIN.LOCAL"),
                    step.get("dc_host", "DC01"), step.get("username", "USER"),
                    step.get("password", "PASS"), step.get("hash_nt", ""),
                    step.get("outfile", "C:\\Windows\\Temp\\ad_out.txt"),
                    step.get("obfuscate", True), req.lhost, req.lport,
                )
                results.append(ChainStep(
                    step=i, module=module, technique=r.technique,
                    command=r.command, notes=r.notes,
                    techniques=r.techniques, risk=r.risk,
                ))

            elif module == "linux_persist":
                r = generate_linux_persist(
                    technique, step.get("payload", "/tmp/payload.sh"),
                    step.get("name", "sysupdate"), req.lhost, req.lport,
                )
                results.append(ChainStep(
                    step=i, module=module, technique=r.technique,
                    command=r.command, notes=r.notes,
                    techniques=r.techniques, risk=r.risk,
                ))

            elif module == "cloud":
                r = generate_cloud(
                    technique, step.get("outfile", "/tmp/cloud_loot.json"), req.lhost,
                )
                results.append(ChainStep(
                    step=i, module=module, technique=r.technique,
                    command=r.command, notes=r.notes,
                    techniques=r.techniques, risk=r.risk,
                ))

            elif module == "initial_access":
                r = generate_initial_access(
                    technique, req.lhost, req.lport, step.get("obfuscate", True),
                )
                results.append(ChainStep(
                    step=i, module=module, technique=r.technique,
                    command=r.payload, notes=r.notes,
                    techniques=r.techniques, risk=r.risk,
                ))

            else:
                raise HTTPException(status_code=422, detail=f"Step {i}: unknown module '{module}'.")

        except ValueError as e:
            raise HTTPException(status_code=422, detail=f"Step {i}: {e}")

    return ChainResponse(
        lhost=req.lhost, lport=req.lport,
        steps=results, total_steps=len(results),
    )


@app.get("/c2profile", response_model=C2ProfileResponse)
def c2profile_get(
    platform: Annotated[str, Query(description=f"SaaS platform to mimic: {', '.join(SUPPORTED_PLATFORMS)}")],
    lhost: Annotated[str, Query(min_length=1, description="C2 listener host")],
    lport: Annotated[int, Query(ge=1, le=65535, description="C2 listener port")],
):
    if not _LHOST_RE.match(lhost):
        raise HTTPException(status_code=422, detail="Invalid lhost.")
    if platform not in SUPPORTED_PLATFORMS:
        raise HTTPException(status_code=422, detail=f"Unsupported platform '{platform}'. Supported: {', '.join(SUPPORTED_PLATFORMS)}")
    profile = generate_profile(platform, lhost, lport)
    return C2ProfileResponse(
        platform=profile.platform,
        havoc_profile=profile.havoc_profile,
        cobalt_strike_profile=profile.cobalt_strike_profile,
    )


@app.get("/redirector", response_model=RedirectorResponse)
def redirector_get(
    platform: Annotated[str, Query(description=f"C2 platform: {', '.join(SUPPORTED_PLATFORMS)}")],
    lhost: Annotated[str, Query(min_length=1, description="C2 server host")],
    lport: Annotated[int, Query(ge=1, le=65535, description="C2 server port")],
    decoy: Annotated[str, Query(min_length=1, description="Decoy URL for non-matching traffic")],
):
    if not _LHOST_RE.match(lhost):
        raise HTTPException(status_code=422, detail="Invalid lhost.")
    if platform not in SUPPORTED_PLATFORMS:
        raise HTTPException(status_code=422, detail=f"Unsupported platform '{platform}'. Supported: {', '.join(SUPPORTED_PLATFORMS)}")
    result = generate_redirector(platform, lhost, lport, decoy)
    return RedirectorResponse(
        platform=result.platform,
        apache_htaccess=result.apache_htaccess,
        nginx_config=result.nginx_config,
    )


@app.post("/redirector", response_model=RedirectorResponse)
def redirector_post(req: RedirectorRequest):
    result = generate_redirector(req.platform, req.lhost, req.lport, req.decoy)
    return RedirectorResponse(
        platform=result.platform,
        apache_htaccess=result.apache_htaccess,
        nginx_config=result.nginx_config,
    )


# ── Windows Post-Exploitation ──────────────────────────────────────────────────

@app.get("/harvest", response_model=HarvestResponse)
def harvest_get(
    technique: Annotated[str, Query(description=f"Harvest technique: {', '.join(HARVEST_TECHNIQUES)}")],
    outfile: Annotated[str, Query(description="Output path for dump file")] = "C:\\Windows\\Temp\\lsass.dmp",
    obfuscate: Annotated[bool, Query(description="Apply PS obfuscation")] = True,
    lhost: Annotated[str, Query(description="Staging server IP")] = "192.168.1.100",
    lport: Annotated[int, Query(ge=1, le=65535, description="Staging server port")] = 8080,
):
    if technique not in HARVEST_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'. Supported: {', '.join(HARVEST_TECHNIQUES)}")
    result = generate_harvest(technique, outfile, obfuscate, lhost, lport)
    return HarvestResponse(
        command=result.command, technique=result.technique, notes=result.notes,
        techniques=result.techniques, risk=result.risk, detections=result.detections,
    )


@app.post("/harvest", response_model=HarvestResponse)
def harvest_post(req: HarvestRequest):
    result = generate_harvest(req.technique, req.outfile, req.obfuscate, req.lhost, req.lport)
    return HarvestResponse(
        command=result.command, technique=result.technique, notes=result.notes,
        techniques=result.techniques, risk=result.risk, detections=result.detections,
    )


@app.get("/persist", response_model=PersistResponse)
def persist_get(
    technique: Annotated[str, Query(description=f"Persistence technique: {', '.join(PERSIST_TECHNIQUES)}")],
    payload: Annotated[str, Query(description="Payload path on target")] = "C:\\Windows\\Temp\\payload.exe",
    name: Annotated[str, Query(description="Registry value / task / service name")] = "WindowsUpdater",
    obfuscate: Annotated[bool, Query(description="Apply PS obfuscation")] = True,
):
    if technique not in PERSIST_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'. Supported: {', '.join(PERSIST_TECHNIQUES)}")
    result = generate_persist(technique, payload, name, obfuscate)
    return PersistResponse(command=result.command, technique=result.technique, notes=result.notes)


@app.post("/persist", response_model=PersistResponse)
def persist_post(req: PersistRequest):
    result = generate_persist(req.technique, req.payload, req.name, req.obfuscate)
    return PersistResponse(command=result.command, technique=result.technique, notes=result.notes)


@app.get("/lateral", response_model=LateralResponse)
def lateral_get(
    technique: Annotated[str, Query(description=f"Lateral movement technique: {', '.join(LATERAL_TECHNIQUES)}")],
    target: Annotated[str, Query(description="Target hostname or IP")] = "TARGET_HOST",
    command: Annotated[str, Query(description="Command to execute on target")] = "whoami",
    username: Annotated[str, Query(description="Username")] = "DOMAIN\\USER",
    password: Annotated[str, Query(description="Plaintext password")] = "PASS",
    hash_nt: Annotated[str, Query(description="NT hash for PTH techniques")] = "",
    obfuscate: Annotated[bool, Query(description="Apply PS obfuscation")] = True,
):
    if technique not in LATERAL_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'. Supported: {', '.join(LATERAL_TECHNIQUES)}")
    result = generate_lateral(technique, target, command, username, password, hash_nt, obfuscate)
    return LateralResponse(command=result.command, technique=result.technique, notes=result.notes)


@app.post("/lateral", response_model=LateralResponse)
def lateral_post(req: LateralRequest):
    result = generate_lateral(req.technique, req.target, req.command, req.username, req.password, req.hash_nt, req.obfuscate)
    return LateralResponse(command=result.command, technique=result.technique, notes=result.notes)


@app.get("/adattack", response_model=ADAttackResponse)
def adattack_get(
    technique: Annotated[str, Query(description=f"AD attack technique: {', '.join(ADATTACK_TECHNIQUES)}")],
    domain: Annotated[str, Query(description="Target AD domain FQDN")] = "DOMAIN.LOCAL",
    dc_host: Annotated[str, Query(description="Domain controller hostname")] = "DC01",
    username: Annotated[str, Query(description="Username")] = "USER",
    password: Annotated[str, Query(description="Plaintext password")] = "PASS",
    hash_nt: Annotated[str, Query(description="NT hash (32-char hex)")] = "",
    outfile: Annotated[str, Query(description="Output file path on target")] = "C:\\Windows\\Temp\\ad_out.txt",
    obfuscate: Annotated[bool, Query(description="Apply PS obfuscation")] = True,
    lhost: Annotated[str, Query(description="Staging server IP")] = "192.168.1.100",
    lport: Annotated[int, Query(ge=1, le=65535, description="Staging server port")] = 8080,
):
    if technique not in ADATTACK_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'. Supported: {', '.join(ADATTACK_TECHNIQUES)}")
    result = generate_adattack(technique, domain, dc_host, username, password, hash_nt, outfile, obfuscate, lhost, lport)
    return ADAttackResponse(
        command=result.command, technique=result.technique, notes=result.notes,
        techniques=result.techniques, risk=result.risk, detections=result.detections,
    )


@app.post("/adattack", response_model=ADAttackResponse)
def adattack_post(req: ADAttackRequest):
    result = generate_adattack(
        req.technique, req.domain, req.dc_host, req.username, req.password,
        req.hash_nt, req.outfile, req.obfuscate, req.lhost, req.lport,
    )
    return ADAttackResponse(
        command=result.command, technique=result.technique, notes=result.notes,
        techniques=result.techniques, risk=result.risk, detections=result.detections,
    )


@app.get("/privesc", response_model=PrivescResponse)
def privesc_get(
    technique: Annotated[str, Query(description=f"PrivEsc technique: {', '.join(PRIVESC_TECHNIQUES)}")],
    payload: Annotated[str, Query(description="Payload path or command after escalation")] = "C:\\Windows\\Temp\\payload.exe",
    name: Annotated[str, Query(description="Service / task name")] = "WindowsUpdate",
    obfuscate: Annotated[bool, Query(description="Apply PS obfuscation")] = True,
):
    if technique not in PRIVESC_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'. Supported: {', '.join(PRIVESC_TECHNIQUES)}")
    result = generate_privesc(technique, payload, name, obfuscate)
    return PrivescResponse(command=result.command, technique=result.technique, notes=result.notes)


@app.post("/privesc", response_model=PrivescResponse)
def privesc_post(req: PrivescRequest):
    result = generate_privesc(req.technique, req.payload, req.name, req.obfuscate)
    return PrivescResponse(command=result.command, technique=result.technique, notes=result.notes)


@app.get("/evasion", response_model=EvasionResponse)
def evasion_get(
    technique: Annotated[str, Query(description=f"Evasion technique: {', '.join(EVASION_TECHNIQUES)}")],
    payload: Annotated[str, Query(description="Command / script to execute or encode")] = "powershell.exe",
    obfuscate: Annotated[bool, Query(description="Apply PS obfuscation")] = True,
):
    if technique not in EVASION_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'. Supported: {', '.join(EVASION_TECHNIQUES)}")
    result = generate_evasion(technique, payload, obfuscate)
    return EvasionResponse(command=result.command, technique=result.technique, notes=result.notes)


@app.post("/evasion", response_model=EvasionResponse)
def evasion_post(req: EvasionRequest):
    result = generate_evasion(req.technique, req.payload, req.obfuscate)
    return EvasionResponse(command=result.command, technique=result.technique, notes=result.notes)


# ── Web Shells ─────────────────────────────────────────────────────────────────

@app.post("/webshell", response_model=WebShellResponse)
def webshell_post(req: WebShellRequest):
    """Generate a web shell for upload to a compromised web server (PHP/ASPX/JSP/CGI)."""
    result = generate_webshell(req.variant, req.obfuscate, req.token)
    return WebShellResponse(
        shell=result.shell, variant=result.variant,
        upload_hint=result.upload_hint, access_example=result.access_example,
        techniques=result.techniques, risk=result.risk, detections=result.detections,
    )


@app.get("/webshell", response_model=WebShellResponse)
def webshell_get(
    variant: Annotated[str, Query(description=f"Web shell variant: {', '.join(WEBSHELL_VARIANTS)}")],
    obfuscate: Annotated[bool, Query(description="Apply obfuscation")] = True,
    token: Annotated[str, Query(min_length=6, description="Auth token embedded in shell")] = "S3cr3tT0k3n",
):
    """Generate a web shell (GET variant)."""
    if variant not in WEBSHELL_VARIANTS:
        raise HTTPException(status_code=422, detail=f"Unsupported variant '{variant}'. Supported: {', '.join(WEBSHELL_VARIANTS)}")
    result = generate_webshell(variant, obfuscate, token)
    return WebShellResponse(
        shell=result.shell, variant=result.variant,
        upload_hint=result.upload_hint, access_example=result.access_example,
        techniques=result.techniques, risk=result.risk, detections=result.detections,
    )


# ── Linux Endpoints ────────────────────────────────────────────────────────────

@app.post("/linux/persist", response_model=LinuxPersistResponse)
def linux_persist_post(req: LinuxPersistRequest):
    """Generate Linux/macOS persistence commands."""
    result = generate_linux_persist(req.technique, req.payload, req.name, req.lhost, req.lport)
    return LinuxPersistResponse(
        command=result.command, technique=result.technique, notes=result.notes,
        techniques=result.techniques, risk=result.risk, detections=result.detections,
    )


@app.get("/linux/persist", response_model=LinuxPersistResponse)
def linux_persist_get(
    technique: Annotated[str, Query(description=f"Persistence technique: {', '.join(LINUX_PERSIST_TECHNIQUES)}")],
    payload: Annotated[str, Query(description="Payload path or command")] = "/tmp/payload.sh",
    name: Annotated[str, Query(description="Identifier name")] = "sysupdate",
    lhost: Annotated[str, Query(description="Attacker host")] = "192.168.1.100",
    lport: Annotated[int, Query(ge=1, le=65535, description="Attacker port")] = 4444,
):
    if technique not in LINUX_PERSIST_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'. Supported: {', '.join(LINUX_PERSIST_TECHNIQUES)}")
    result = generate_linux_persist(technique, payload, name, lhost, lport)
    return LinuxPersistResponse(
        command=result.command, technique=result.technique, notes=result.notes,
        techniques=result.techniques, risk=result.risk, detections=result.detections,
    )


@app.post("/linux/harvest", response_model=LinuxHarvestResponse)
def linux_harvest_post(req: LinuxHarvestRequest):
    """Generate Linux credential harvesting commands."""
    result = generate_linux_harvest(req.technique, req.outfile, req.lhost, req.lport)
    return LinuxHarvestResponse(
        command=result.command, technique=result.technique, notes=result.notes,
        techniques=result.techniques, risk=result.risk, detections=result.detections,
    )


@app.get("/linux/harvest", response_model=LinuxHarvestResponse)
def linux_harvest_get(
    technique: Annotated[str, Query(description=f"Harvest technique: {', '.join(LINUX_HARVEST_TECHNIQUES)}")],
    outfile: Annotated[str, Query(description="Output file")] = "/tmp/loot.txt",
    lhost: Annotated[str, Query(description="Attacker host")] = "192.168.1.100",
    lport: Annotated[int, Query(ge=1, le=65535, description="Attacker port")] = 8080,
):
    if technique not in LINUX_HARVEST_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'. Supported: {', '.join(LINUX_HARVEST_TECHNIQUES)}")
    result = generate_linux_harvest(technique, outfile, lhost, lport)
    return LinuxHarvestResponse(
        command=result.command, technique=result.technique, notes=result.notes,
        techniques=result.techniques, risk=result.risk, detections=result.detections,
    )


@app.post("/linux/privesc", response_model=LinuxPrivescResponse)
def linux_privesc_post(req: LinuxPrivescRequest):
    """Generate Linux privilege escalation commands."""
    result = generate_linux_privesc(req.technique, req.payload, req.name)
    return LinuxPrivescResponse(
        command=result.command, technique=result.technique, notes=result.notes,
        techniques=result.techniques, risk=result.risk, detections=result.detections,
    )


@app.get("/linux/privesc", response_model=LinuxPrivescResponse)
def linux_privesc_get(
    technique: Annotated[str, Query(description=f"PrivEsc technique: {', '.join(LINUX_PRIVESC_TECHNIQUES)}")],
    payload: Annotated[str, Query(description="Payload to execute")] = "/tmp/payload.sh",
    name: Annotated[str, Query(description="Binary/service name")] = "sysupdate",
):
    if technique not in LINUX_PRIVESC_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'. Supported: {', '.join(LINUX_PRIVESC_TECHNIQUES)}")
    result = generate_linux_privesc(technique, payload, name)
    return LinuxPrivescResponse(
        command=result.command, technique=result.technique, notes=result.notes,
        techniques=result.techniques, risk=result.risk, detections=result.detections,
    )


# ── Cloud Endpoints ────────────────────────────────────────────────────────────

@app.post("/cloud", response_model=CloudResponse)
def cloud_post(req: CloudRequest):
    """Generate cloud environment attack commands (AWS/Azure/GCP/Kubernetes)."""
    result = generate_cloud(req.technique, req.outfile, req.lhost)
    return CloudResponse(
        command=result.command, technique=result.technique,
        platform=result.platform, notes=result.notes,
        techniques=result.techniques, risk=result.risk, detections=result.detections,
    )


@app.get("/cloud", response_model=CloudResponse)
def cloud_get(
    technique: Annotated[str, Query(description=f"Cloud technique: {', '.join(CLOUD_TECHNIQUES)}")],
    outfile: Annotated[str, Query(description="Output file for harvested data")] = "/tmp/cloud_loot.json",
    lhost: Annotated[str, Query(description="Attacker host")] = "192.168.1.100",
):
    if technique not in CLOUD_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'. Supported: {', '.join(CLOUD_TECHNIQUES)}")
    result = generate_cloud(technique, outfile, lhost)
    return CloudResponse(
        command=result.command, technique=result.technique,
        platform=result.platform, notes=result.notes,
        techniques=result.techniques, risk=result.risk, detections=result.detections,
    )


# ── Initial Access Endpoints ───────────────────────────────────────────────────

@app.post("/initial_access", response_model=InitialAccessResponse)
def initial_access_post(req: InitialAccessRequest):
    """Generate initial access payloads: VBA macros, HTML smuggling, HTA droppers, LNK shortcuts."""
    result = generate_initial_access(req.technique, req.lhost, req.lport, req.obfuscate)
    return InitialAccessResponse(
        payload=result.payload, technique=result.technique,
        delivery_hint=result.delivery_hint, notes=result.notes,
        techniques=result.techniques, risk=result.risk, detections=result.detections,
    )


@app.get("/initial_access", response_model=InitialAccessResponse)
def initial_access_get(
    technique: Annotated[str, Query(description=f"Initial access technique: {', '.join(INITIAL_ACCESS_TECHNIQUES)}")],
    lhost: Annotated[str, Query(min_length=1, description="Attacker listener host")],
    lport: Annotated[int, Query(ge=1, le=65535, description="Attacker listener port")],
    obfuscate: Annotated[bool, Query(description="Apply obfuscation")] = True,
):
    if not _LHOST_RE.match(lhost):
        raise HTTPException(status_code=422, detail="Invalid lhost.")
    if technique not in INITIAL_ACCESS_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'. Supported: {', '.join(INITIAL_ACCESS_TECHNIQUES)}")
    result = generate_initial_access(technique, lhost, lport, obfuscate)
    return InitialAccessResponse(
        payload=result.payload, technique=result.technique,
        delivery_hint=result.delivery_hint, notes=result.notes,
        techniques=result.techniques, risk=result.risk, detections=result.detections,
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    host = os.environ.get("HOST", "127.0.0.1")
    uvicorn.run("main:app", host=host, port=port, reload=False)
