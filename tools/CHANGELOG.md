# Changelog

## v4.1.0 — 2026-05-13

### Bug fixes
- **spray**: fix `NameError: name 'locked_out' is not defined` that crashed every successful run on completion (`spray.py:207`).
- **spray**: replace deprecated `datetime.utcnow()` with `datetime.now(timezone.utc)`.
- **webshell**: rename dead `_AUTH_TOKEN="X-Auth"` constant — webshells actually use `X-Token`. Constant now matches reality.
- **powershell generator**: remove duplicate `random.choice(_VARIANTS)` call at the top of `_generate` — the first call was dead code.
- **adattack/zerologon**: thread `dc_ip` parameter through instead of hardcoding the placeholder `DC_IP_ADDRESS`.
- **cloud/aws_imds**: extract step now reads from `{outfile}` instead of a hardcoded `credentials.json`.
- **lateral/psexec, evasion/lolbas_***: every generator now threads `lhost`/`lport` — no more hardcoded `ATTACKER` placeholder.

### Security
- **Bearer token auth**: optional, env-driven (`API_TOKEN`). When unset, auth is disabled (dev-friendly). When set, every endpoint requires `Authorization: Bearer <token>` via `hmac.compare_digest`.
- **CORS**: defaults to localhost only; comma-separated `CORS_ORIGINS` env for overrides.
- **lhost validation everywhere**: all GET endpoints now validate `lhost` via `_LHOST_RE` (closes command-injection surface in shell-embedded f-strings).
- **TLS verification**: spray now defaults to verify=True. Use `--insecure` to opt out.
- **Rate limiting**: slowapi-backed, per-IP. Configurable via `RATE_LIMIT_DEFAULT` and `RATE_LIMIT_GENERATE`.
- **Signal handling**: spray now saves state on SIGINT/SIGTERM so Ctrl+C never loses progress.

### Architecture
- **main.py refactored** from 1,040 lines to ~85 lines. Domain endpoints live in `routers/{shell,c2,windows_postex,linux_postex,cloud,webshell,initial_access,chain,reporting}.py`.
- **Shared infrastructure** in `core/{settings,validation,auth,audit,ratelimit,schemas}.py`.
- **Typed chain steps**: `/chain` now uses pydantic discriminated unions — unknown modules and mismatched parameters fail at request validation, not inside the dispatcher.

### Consistency
- **MITRE techniques + risk + detections** now uniform across `persist`, `lateral`, `privesc`, `evasion` (previously absent on those four; present on the rest).
- **ps_tick_marks** now obfuscates every occurrence of every keyword (was: only first), and the keyword set grew (Runspace, Pipeline, Runtime, Marshal, Reflection, Assembly).

### New functionality
- **Seed parameter** (`?seed=N`) for reproducible payloads — essential for tests, docs, and training labs. Threaded through every generator via `ShellOptions.seed`.
- **Engagement tracking**: send `X-Engagement-ID: <id>` header — recorded in audit log for client deliverables.
- **Audit log** (`AUDIT_LOG=/path/to/audit.jsonl`): append-only JSONL of every payload generated (route, module, technique, redacted params, payload SHA-256, client IP). Passwords/tokens/hashes are redacted.
- **`/report` endpoint**: renders a markdown summary of the audit log, optionally filtered by `?engagement_id=`. Pipe directly into client deliverables.
- **Sliver + Mythic C2 profiles**: in addition to existing Havoc + Cobalt Strike.
- **Modern initial access**: `iso_container` (MotW-bypass ISO build script), `onenote_dropper` (.one workflow with embedded payload), `clickonce_manifest` (ClickOnce phishing manifest).
- **Spray expansion**: new targets `adfs`, `citrix` (auto-detects StoreFront vs NetScaler), `globalprotect`. Detects `MFA_required` / `MFA_enrollment_required` for O365.
- **Spray opsec features**: `--proxy` (HTTP/SOCKS), `--user-agents` (rotation from file or single literal), `--insecure`, `--engagement-id`, `--max-attempts`.

### Tests
- 99 tests in `revshell-api/tests/` covering generators, encoding, obfuscation, validation, API, auth, audit.
- 10 tests in `spray/tests/` covering pair-building, state I/O, proxy + UA helpers.

### Packaging
- `pyproject.toml` with `requires-python = ">=3.10"`.
- `requirements.txt` pinned to exact versions.
- `Dockerfile` (Python 3.12 slim, non-root user, health check).
- `compose.yaml` for revshell-api + spray CLI.
- `.env.example` template.

### Documentation
- Full README rewrite covering all endpoints, auth, audit, engagement workflow, Docker quickstart, spray usage.
- New `spray/README.md`.
