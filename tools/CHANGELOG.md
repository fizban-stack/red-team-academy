# Changelog

## v4.3.0 — 2026-05-13

### Elite tradecraft (12 → 43 evasion techniques)

12 new advanced techniques added to `/evasion`:

- **`rop_sleep`** — ROP-chain sleep mask via NtContinue. Defeats memory scanners and callstack-based sleep detection.
- **`set_windows_hook_loader`** — SetWindowsHookEx DLL injection. Available since Windows 3.0 and many EDRs still trip over it.
- **`com_rot_injection`** — COM Running Object Table abuse. Subtle persistence + lateral via Office automation hooks.
- **`environment_keying`** — Payload key derived from BIOS serial + manufacturer + user domain. Sandboxes decrypt to garbage.
- **`in_memory_pe_loader`** — Reflective PE loader stub (Assembly.Load + manual mapping references).
- **`dll_sideload`** — Proxy-DLL template for sideloading via signed binaries (OneDrive, dbghelp, etc.). hijacklibs.net referenced.
- **`apc_injection`** — Classic NtQueueApcThread injection template.
- **`early_bird_apc`** — APC queued before main thread runs; bypasses userland hooks loaded post-init.
- **`heaven_gate`** — WoW64 → 64-bit native syscall pivot. Bypasses EDRs that only hook 64-bit NTDLL.
- **`process_ghosting`** — File deleted before section is mapped (Elastic, 2021).
- **`process_doppelganging`** — TxF-based hollowing; on-disk file unchanged, in-memory section is the payload (Black Hat EU 2017).
- **`process_herpaderping`** — Write malicious PE → map → overwrite with benign PE → CreateProcess (jxy-s, 2020).

### New endpoint: `/stack` — EDR-aware orchestrator

Given `{edr, lhost, lport, language}`, returns an ordered evasion playbook tuned
to the named vendor. Each step ships with a rationale.

5 EDR profiles:
- `defender` — patchless AMSI/ETW, WLDP downgrade, NTDLL unhook, PPID spoof
- `crowdstrike` — indirect syscalls (clean callstacks), Early-Bird APC, ROP sleep, ETW patchless
- `sentinelone` — patchless AMSI, NTDLL unhook, ROP sleep, module stomping
- `carbonblack` — DLL sideloading, classic AMSI/ETW bypass, PPID spoof
- `generic` — vendor-agnostic best effort

Flags: `include_anti_forensics`, `include_sandbox_evasion`, `seed`. Order is
load-bearing: sandbox gates → evasion bypasses → payload → cleanup. Output is
deterministic per `(edr, options)`.

### Tests

- 225 revshell-api tests (was 173 → +52)
- New: `test_evasion_elite.py` (13 tests covering each new technique + metadata)
- New: `test_stack.py` (15 tests covering builder, every EDR profile, ordering invariants, flags, seed determinism, lhost validation)

### Docs

- README documents `/stack` with example request, response, and the full
  per-EDR profile table.

---

## v4.2.0 — 2026-05-13

### Evasion catalog growth (12 → 31 techniques)

**Patchless AMSI / ETW** — hardware-breakpoint bypasses that don't write any bytes
to amsi.dll or ntdll.dll, defeating module-integrity scans:
- `amsi_hwbp` — DR0 on AmsiScanBuffer + VEH rewriting RAX.
- `etw_hwbp` — DR1 on EtwEventWrite + VEH skipping the function body.
- `amsi_provider_unregister` — wipe AMSI provider COM registration.
- `amsi_wldp_downgrade` — flip WLDP into audit mode.

**Direct & indirect syscalls** — C# stub templates:
- `direct_syscalls` — HellsGate-style resolution from a fresh on-disk NTDLL copy.
- `indirect_syscalls` — SysWhispers3-style; callstack lands inside ntdll.dll for legitimacy.
- `ntdll_unhook` — KnownDlls-style refresh of the .text section to wipe userland EDR hooks.

**Sleep masking & process tradecraft:**
- `sleep_obfuscation_ekko` — Timer-Queue RC4 mask during beacon sleep.
- `ppid_spoof` — parent-PID spoofing via UpdateProcThreadAttribute.
- `process_hollowing`, `module_stomping`, `thread_hijack` — C# templates for the
  three classic injection patterns, threaded with `lhost`/`lport`.

**More LOLBAS:**
- `lolbas_msbuild` — MSBuild inline-task XML.
- `lolbas_installutil` — InstallUtil /U abuse via the Uninstall override.
- `lolbas_cmstp` — INF-based execution via cmstp.exe.
- `lolbas_msxsl`, `lolbas_wmic_xsl` — XSL transform JScript execution.
- `lolbas_syncappv` — SyncAppvPublishingServer.vbs argument injection.
- `lolbas_pubprn` — pubprn.vbs `script:` URL pivot.

**Backfilled MITRE metadata** on the 9 legacy evasion techniques — every one of
the 31 now returns `techniques` + `risk` + `detections`.

### New module: `/anti_forensics` (12 techniques)

Post-engagement artifact cleanup, separate from `/evasion` (which targets
real-time detection during operations):
- `clear_event_logs` — Security / System / Application / PowerShell / Sysmon / TaskScheduler.
- `disable_usn_journal` — wipe $UsnJrnl on all volumes.
- `clear_prefetch` — wipe + disable Prefetcher.
- `clear_recent_files` — Recent + Office MRU + RecentDocs + TypedPaths + RunMRU.
- `clear_recycle_bin` — all drives.
- `time_stomp` — copy kernel32.dll timestamps onto a target file.
- `ads_hide_payload` — store binary in NTFS Alternate Data Stream.
- `self_delete` — C# SetFileInformationByHandle + FileDispositionInfo stub.
- `clear_shellbags` — wipe ShellBag registry trees.
- `clear_amcache` — disable PcaSvc + rename Amcache.hve.
- `clear_jumplists` — AutomaticDestinations + CustomDestinations.
- `clear_powershell_history` — PSReadLine history + session.

### New module: `/sandbox_evasion` (12 techniques)

Environmental gates that make payload execution conditional. Operator wraps the
real payload inside the `if (check) { ... }` branch:
- `vm_detect_cpuid`, `vm_detect_wmi`, `vm_detect_artifacts` — VM detection layers.
- `sandbox_check_uptime` — minimum uptime threshold (default 20 min).
- `sandbox_check_ram` — minimum RAM (default 4 GB).
- `sandbox_check_user_interaction` — mouse-movement gate via WinForms.Cursor.
- `sandbox_check_recent_files` — minimum recent-files count.
- `sandbox_check_domain_joined` — require AD domain membership.
- `sandbox_geofence` — IP geolocation allow-list via ifconfig.io + ipapi.co.
- `sandbox_time_delay` — wall-clock DO-UNTIL loop that defeats sleep-NOP sandboxes.
- `anti_debug` — IsDebuggerPresent + CheckRemoteDebuggerPresent + PEB hint.
- `sandbox_screen_resolution` — minimum display dimensions.

### Chain endpoint

`/chain` now accepts `anti_forensics` and `sandbox_evasion` step types via the
discriminated-union schema. Single chain: sandbox gate → evasion stack → payload →
cleanup.

### Spray-side evasion

- `--xff-rotate` — random public IPv4 `X-Forwarded-For` per request.
- `--header KEY:VALUE` (repeatable) — custom headers (e.g. `X-Forwarded-Host`).
- `_random_public_ipv4()` helper excludes RFC1918, loopback, link-local, multicast.

### Tests

- 173 revshell-api tests (was 99) — every new evasion / anti-forensics /
  sandbox-evasion technique has parametrized smoke + at least one targeted assertion.
- 12 spray tests (was 10) — XFF generator covered.

### Docs

- README documents all three new endpoints with a full evasion-stack chain example.
- Spray README documents `--xff-rotate` and `--header`.

---

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
