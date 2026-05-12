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
from generators.encode import SUPPORTED_TECHNIQUES, encode_command
from generators.adattack import SUPPORTED_TECHNIQUES as ADATTACK_TECHNIQUES, generate_adattack
from generators.evasion import SUPPORTED_TECHNIQUES as EVASION_TECHNIQUES, generate_evasion
from generators.harvest import SUPPORTED_TECHNIQUES as HARVEST_TECHNIQUES, generate_harvest
from generators.lateral import SUPPORTED_TECHNIQUES as LATERAL_TECHNIQUES, generate_lateral
from generators.persist import SUPPORTED_TECHNIQUES as PERSIST_TECHNIQUES, generate_persist
from generators.privesc import SUPPORTED_TECHNIQUES as PRIVESC_TECHNIQUES, generate_privesc
from generators.redirector import generate_redirector

_LHOST_RE = re.compile(r"^[a-zA-Z0-9.\-:\[\]]+$")  # brackets for IPv6


def _validate_lhost(v: str) -> str:
    if not _LHOST_RE.match(v):
        raise ValueError("lhost must contain only alphanumeric characters, dots, hyphens, colons, or brackets")
    return v

ARCH_VALUES = Literal["x86", "x64", "arm", "arm64", "mips", "any"]

app = FastAPI(
    title="RevShell API",
    description="Reverse shell command generator for authorized red team exercises.",
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


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
    )


@app.get("/health")
def health():
    return {"status": "ok", "version": "3.0.0"}


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


@app.get("/harvest", response_model=HarvestResponse)
def harvest_get(
    technique: Annotated[str, Query(description=f"Harvest technique: {', '.join(HARVEST_TECHNIQUES)}")],
    outfile: Annotated[str, Query(description="Output path for dump file")] = "C:\\Windows\\Temp\\lsass.dmp",
    obfuscate: Annotated[bool, Query(description="Apply PS obfuscation")] = True,
):
    if technique not in HARVEST_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'. Supported: {', '.join(HARVEST_TECHNIQUES)}")
    result = generate_harvest(technique, outfile, obfuscate)
    return HarvestResponse(command=result.command, technique=result.technique, notes=result.notes)


@app.post("/harvest", response_model=HarvestResponse)
def harvest_post(req: HarvestRequest):
    result = generate_harvest(req.technique, req.outfile, req.obfuscate)
    return HarvestResponse(command=result.command, technique=result.technique, notes=result.notes)


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
):
    if technique not in ADATTACK_TECHNIQUES:
        raise HTTPException(status_code=422, detail=f"Unsupported technique '{technique}'. Supported: {', '.join(ADATTACK_TECHNIQUES)}")
    result = generate_adattack(technique, domain, dc_host, username, password, hash_nt, outfile, obfuscate)
    return ADAttackResponse(command=result.command, technique=result.technique, notes=result.notes)


@app.post("/adattack", response_model=ADAttackResponse)
def adattack_post(req: ADAttackRequest):
    result = generate_adattack(req.technique, req.domain, req.dc_host, req.username, req.password, req.hash_nt, req.outfile, req.obfuscate)
    return ADAttackResponse(command=result.command, technique=result.technique, notes=result.notes)


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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    host = os.environ.get("HOST", "127.0.0.1")
    uvicorn.run("main:app", host=host, port=port, reload=False)
