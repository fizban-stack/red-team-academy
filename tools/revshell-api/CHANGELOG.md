# Changelog

All notable changes to the RevShell API are documented here.

---

## [4.5.0] — 2026-05-13

### Added

#### Phase A — Modern C2 channel generators (`generators/c2_channels.py`, `routers/c2_channels.py`)
- New `GET /c2_channel` endpoint lists 8 supported transport channels
- New `POST /c2_channel` and `GET /c2_channel/{channel}` endpoints generate complete profiles:
  - **`doh_c2`** — DNS-over-HTTPS beacon; encodes commands as subdomain labels, responses in TXT records. Supports Cloudflare, Google, Quad9, and operator-hosted resolvers.
  - **`domain_fronting`** — CDN-routed HTTPS; connects to front domain, routes to real C2 via Host header inside TLS.
  - **`named_pipe_c2`** — SMB named pipe inter-host C2; mimics Chromium mojo pipe names, supports token impersonation.
  - **`icmp_tunnel`** — ICMP echo tunneling of TCP streams; integrates with ptunnel-ng, icmpsh, and Hans.
  - **`websocket_c2`** — Long-lived WebSocket beacon; mimics socket.io/stomp subprotocols, per-frame AES-256-GCM.
  - **`cloud_blend_discord`** — Discord webhook/bot C2; polls task channel, no persistent connection.
  - **`cloud_blend_s3`** — AWS S3 dead-drop task queue; short HTTPS GET/PUT calls to s3.amazonaws.com.
  - **`cloud_blend_github`** — GitHub gist/issue tasking; private gists as C2 dead drops.
- Each channel returns: `implant_config`, `listener_setup`, `notes`, MITRE `techniques`, `risk`, `detections`
- All channels: no hardcoded credentials/tokens — load from environment at runtime

#### Phase B — Advanced evasion tradecraft (`generators/evasion.py`)
- **`call_stack_desync`** (T1106, T1027, T1620 — CRITICAL): Combines indirect syscalls with CFG-inconsistent fabricated return addresses to confuse EDR callstack walkers
- **`byovd`** (T1068, T1562.001, T1014 — CRITICAL): Bring Your Own Vulnerable Driver — loads WHQL-signed exploitable driver, gains ring-0, nulls EDR kernel callbacks
- **`dll_redirection`** (T1574.001, T1574.002 — HIGH): .local file + SxS manifest abuse to redirect DLL search order without touching System32
- **`peb_imagepath_spoof`** (T1036.003, T1055.012 — HIGH): Rewrites PEB->ProcessParameters->ImagePathName to disguise process identity from userland enumeration

#### Phase C — Stack diff comparator (`generators/stack_diff.py`, `routers/diff.py`)
- New `POST /stack/diff` endpoint compares two EDR stacks:
  - Returns `shared` (both stacks), `only_a` (unique to edr_a), `only_b` (unique to edr_b)
  - Each item includes technique name, module category, and per-EDR rationale
  - Deterministic — same `(edr_a, edr_b)` pair always returns identical results
  - Verified: self-diff returns 0 unique items; commutative counts

#### Phase D — Quality, tests, docs
- `core/schemas.py`: Added `C2ChannelRequest`, `C2ChannelResponse`, `StackDiffRequest`, `StackDiffResponse`, `DiffTechniqueItem`
- `tests/test_c2_channels.py`: 40 tests — one per channel smoke + content assertions
- `tests/test_tradecraft_extra.py`: 18 tests — metadata + content per v4.5 technique
- `tests/test_stack_diff.py`: 22 tests — partition correctness, determinism, self-diff, cross-EDR
- `tests/test_api.py`: 12 new API smoke tests for `/c2_channel` and `/stack/diff`
- Total: **418 tests** (was 276)
- Version bumped to `4.5.0` throughout

### Changed
- `main.py`: wired `c2_channels` and `diff` routers; bumped version to 4.5.0
- `README.md`: documented `/c2_channel` and `/stack/diff` endpoints with examples; updated architecture table and test count

---

## [4.4.0] — 2026-05-13

### Added
- v4.4 frontier evasion: `peb_unlink`, `phantom_dll_hollow`, `threadless_injection`, `stack_spoof`, `manual_map_header_erase`, `function_level_encryption`
- Multi-EDR stack support (`edrs: list[str]`) in `/stack` — union + dedup with per-step `counters` field
- `/recommend` constraint-driven technique selector with scoring
- `/ioc_export` Sigma rule export from audit log
- `/chain` discriminated-union step dispatcher with 11 module types
- `seed` parameter for deterministic payload generation

## [4.3.0] — 2026-05-13

### Added
- Elite tradecraft: `rop_sleep`, `set_windows_hook_loader`, `com_rot_injection`, `environment_keying`, `in_memory_pe_loader`, `dll_sideload`, `apc_injection`, `early_bird_apc`, `heaven_gate`, `process_ghosting`, `process_doppelganging`, `process_herpaderping`
- `/anti_forensics` (12 techniques) and `/sandbox_evasion` (12 techniques) endpoints
- Bearer-token auth via `API_TOKEN` env (optional)
- JSONL audit log via `AUDIT_LOG` env with engagement tagging
- `/ioc_export` Sigma rule generator from audit log

## [4.0.0] — 2026-05-12

### Added
- Initial modular FastAPI refactor from monolithic Flask
- Router-based architecture with 13+ routers
- Direct/indirect syscall profiles, NTDLL unhook, HWBP bypasses
- Spray tool with proxy, UA rotation, XFF rotation, custom headers
