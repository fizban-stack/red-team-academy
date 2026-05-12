import os
import re
from typing import Annotated, Literal

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from generators import REGISTRY, SUPPORTED_LANGUAGES
from generators.base import ShellOptions

_LHOST_RE = re.compile(r"^[a-zA-Z0-9.\-:\[\]]+$")  # brackets for IPv6

ARCH_VALUES = Literal["x86", "x64", "arm", "arm64", "mips", "any"]

app = FastAPI(
    title="RevShell API",
    description="Reverse shell command generator for authorized red team exercises.",
    version="2.0.0",
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

    @field_validator("lhost")
    @classmethod
    def validate_lhost(cls, v: str) -> str:
        if not _LHOST_RE.match(v):
            raise ValueError("lhost must contain only alphanumeric characters, dots, hyphens, colons, or brackets")
        return v

    @field_validator("language")
    @classmethod
    def validate_language(cls, v: str) -> str:
        normalized = v.lower()
        if normalized not in REGISTRY:
            raise ValueError(
                f"Unsupported language '{v}'. Supported: {', '.join(SUPPORTED_LANGUAGES)}"
            )
        return normalized


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
    return ShellResponse(
        command=result.command,
        language=result.language,
        arch=result.arch,
        lhost=req.lhost,
        lport=req.lport,
        variant=result.variant,
        listener=result.listener,
        tty_upgrade=result.tty_upgrade,
        msf_compat=result.msf_compat,
    )


@app.get("/health")
def health():
    return {"status": "ok", "version": "2.0.0"}


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
    )
    return _build_shell(req)


@app.post("/generate", response_model=ShellResponse)
def generate_post(req: ShellRequest):
    return _build_shell(req)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    host = os.environ.get("HOST", "127.0.0.1")
    uvicorn.run("main:app", host=host, port=port, reload=False)
