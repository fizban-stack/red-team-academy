# RevShell API

Python FastAPI server that generates obfuscated reverse shell commands for authorized red team exercises.

## Quick Start

```bash
pip install -r requirements.txt
python main.py
# Server starts on http://0.0.0.0:8080
# Override port: PORT=9000 python main.py
```

Interactive docs: http://localhost:8080/docs

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Server health check |
| GET | `/languages` | List supported shell languages |
| GET | `/generate` | Generate shell via query params |
| POST | `/generate` | Generate shell via JSON body |

## Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `lhost` | string | yes | Listener IP or hostname |
| `lport` | int | yes | Listener port (1–65535) |
| `language` | string | yes | Shell type (see `/languages`) |
| `arch` | string | no | Target arch: `x86`, `x64`, `arm`, `arm64`, `mips`, `any` (default: `any`) |
| `obfuscate` | bool | no | Randomize variable names and select variant (default: `true`) |

## Supported Languages

`awk`, `bash`, `lua`, `nc`, `netcat`, `perl`, `php`, `powershell`, `ps`, `python3`, `ruby`

## Example

```bash
# GET
curl "http://localhost:8080/generate?lhost=10.10.14.5&lport=4444&language=bash"

# POST
curl -X POST http://localhost:8080/generate \
  -H "Content-Type: application/json" \
  -d '{"lhost":"10.10.14.5","lport":4444,"language":"powershell","arch":"x64","obfuscate":true}'
```

## Randomness / Obfuscation

When `obfuscate=true` (default):

- Variable names are replaced with random 4–8 character strings
- Bash randomly selects between `/dev/tcp`, `exec`-redirect, and `mkfifo` variants
- PowerShell randomly chooses plain or base64-encoded (`-EncodedCommand`) delivery
- NetCat randomly selects between `-e`, `mkfifo`, and `ncat` forms
- File descriptor numbers are randomized where applicable

The generated commands are functionally identical — randomization only affects surface signatures.

## Architecture Notes

- `x64` + PowerShell → always produces `-EncodedCommand` (UTF-16LE base64)
- `arch` has no effect on POSIX shell languages (bash/perl/python/etc.)
