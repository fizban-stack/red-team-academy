---
layout: training-page
title: "Rust Red Team Cheatsheet — Red Team Academy"
module: "Programming"
tags:
  - rust
  - cheatsheet
  - red-team
  - offensive-programming
page_key: "prog-rust-cheatsheet"
render_with_liquid: false
---

# Rust Red Team Cheatsheet

A fast-reference guide for offensive Rust programming. Assumes familiarity with Rust basics; focused on patterns that appear repeatedly in red team tooling: networking, Windows API, async concurrency, cross-compilation, and binary hardening.

---

## 1. Project Setup & Cargo

### Cargo.toml — Offensive Baseline

```toml
[package]
name = "tool"
version = "0.1.0"
edition = "2021"

[dependencies]
# Async runtime
tokio = { version = "1", features = ["full"] }

# HTTP client — use rustls to avoid OpenSSL dependency
reqwest = { version = "0.12", default-features = false, features = [
    "json",
    "rustls-tls",
    "multipart",
    "stream",
] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Windows API (kernel32, ntdll, advapi32, etc.)
windows-sys = { version = "0.59", features = [
    "Win32_Foundation",
    "Win32_System_Memory",
    "Win32_System_Threading",
    "Win32_System_Diagnostics_Debug",
    "Win32_Security",
    "Win32_System_LibraryLoader",
    "Win32_Networking_WinSock",
] }

# CLI argument parsing
clap = { version = "4", features = ["derive"] }

# Logging
env_logger = "0.11"
log = "0.4"

# Encoding
base64 = "0.22"
hex = "0.4"

# Error handling
anyhow = "1"
thiserror = "2"

# Crypto (RustCrypto)
aes = "0.8"
cbc = { version = "0.1", features = ["alloc"] }
rand = "0.8"

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

### Workspace Setup (multi-crate tool suite)

```toml
# Cargo.toml (workspace root)
[workspace]
members = [
    "scanner",
    "beacon",
    "loader",
    "common",
]
resolver = "2"

# Shared deps go in each crate's Cargo.toml
# Or use workspace.dependencies (Cargo 1.64+):
[workspace.dependencies]
tokio   = { version = "1", features = ["full"] }
serde   = { version = "1", features = ["derive"] }
anyhow  = "1"
```

### build.rs — Custom Linking

```rust
// build.rs — runs before compilation
fn main() {
    // Tell cargo to re-run only when this file changes
    println!("cargo:rerun-if-changed=build.rs");

    // Link a static C library bundled with the crate
    println!("cargo:rustc-link-search=native=libs/");
    println!("cargo:rustc-link-lib=static=helper");

    // Windows: link against specific system libs
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-lib=ntdll");
        println!("cargo:rustc-link-lib=kernel32");
    }

    // Embed a resource file (icon, manifest) on Windows
    #[cfg(target_os = "windows")]
    {
        let mut res = winres::WindowsResource::new();
        res.set_manifest_file("manifest.xml");
        res.compile().expect("Failed to compile resources");
    }
}
```

---

## 2. Cross-Compilation

### Target Setup

```bash
# List installed targets
rustup target list --installed

# Add common targets
rustup target add x86_64-pc-windows-gnu     # Windows 64-bit (MinGW)
rustup target add i686-pc-windows-gnu       # Windows 32-bit
rustup target add x86_64-pc-windows-msvc   # Windows MSVC (needs VS)
rustup target add aarch64-unknown-linux-musl # ARM64 Linux static
rustup target add x86_64-unknown-linux-musl  # x86_64 Linux static

# Install MinGW cross-linker on Debian/Ubuntu
sudo apt-get install gcc-mingw-w64-x86-64

# Build Windows PE from Linux
cargo build --release --target x86_64-pc-windows-gnu
```

### .cargo/config.toml — Linker Config

```toml
# .cargo/config.toml (project root)

[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-gcc"
ar     = "x86_64-w64-mingw32-ar"

[target.aarch64-unknown-linux-musl]
linker = "aarch64-linux-gnu-gcc"

# Global rustflags — strip symbols in all release builds
[profile.release]
rustflags = ["-C", "strip=symbols"]

# Or per-target:
[target.x86_64-pc-windows-gnu]
rustflags = [
    "-C", "link-arg=-Wl,--strip-all",
    "-C", "link-arg=-Wl,--subsystem,windows",  # no console window
]
```

### Strip Symbols at Build Time

```bash
# Via RUSTFLAGS env var
RUSTFLAGS="-C strip=symbols" cargo build --release

# Or add to Cargo.toml [profile.release]
# strip = "symbols"   # strip debug symbols only
# strip = true        # strip everything (equivalent to "debuginfo")

# After build, use system strip tool
strip target/release/tool
x86_64-w64-mingw32-strip target/x86_64-pc-windows-gnu/release/tool.exe

# Check binary size
ls -lh target/release/tool
```

---

## 3. Async Networking with Tokio

### TCP Client with Timeout

```rust
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let addr = "192.168.1.1:4444";

    // Attempt connection with timeout
    let stream = timeout(
        Duration::from_secs(3),
        TcpStream::connect(addr),
    )
    .await??; // double ? — one for timeout::Elapsed, one for io::Error

    let (mut reader, mut writer) = tokio::io::split(stream);

    writer.write_all(b"hello\n").await?;

    let mut buf = vec![0u8; 4096];
    let n = timeout(
        Duration::from_secs(5),
        reader.read(&mut buf),
    )
    .await??;

    println!("Received: {:?}", &buf[..n]);
    Ok(())
}
```

### TCP Listener (Handler per Connection)

```rust
use tokio::net::TcpListener;
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:4444").await?;
    log::info!("Listening on :4444");

    loop {
        let (socket, peer) = listener.accept().await?;
        log::info!("Connection from {peer}");

        tokio::spawn(async move {
            let reader = BufReader::new(socket);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                println!("[{peer}] {line}");
            }
        });
    }
}
```

### Semaphore for Concurrency Limiting

```rust
use std::sync::Arc;
use tokio::sync::Semaphore;
use futures::future::join_all;

async fn scan_with_limit(targets: Vec<String>, max_concurrency: usize) {
    let sem = Arc::new(Semaphore::new(max_concurrency));
    let mut handles = Vec::new();

    for target in targets {
        let permit = Arc::clone(&sem).acquire_owned().await.unwrap();
        let handle = tokio::spawn(async move {
            let _permit = permit; // dropped at end of task
            probe(&target).await
        });
        handles.push(handle);
    }

    let results: Vec<_> = join_all(handles).await;
    for r in results {
        if let Ok(Ok(result)) = r {
            println!("{result:?}");
        }
    }
}

async fn probe(target: &str) -> anyhow::Result<String> {
    // do work
    Ok(target.to_string())
}
```

### join_all / select! Patterns

```rust
use tokio::select;

// Run two async tasks, take whichever completes first
async fn race_example() {
    select! {
        result = connect_primary() => {
            println!("Primary won: {result:?}");
        }
        result = connect_fallback() => {
            println!("Fallback won: {result:?}");
        }
    }
}

async fn connect_primary() -> anyhow::Result<()> { Ok(()) }
async fn connect_fallback() -> anyhow::Result<()> { Ok(()) }
```

---

## 4. Windows API with windows-sys

### Common Imports

```rust
use windows_sys::Win32::Foundation::{
    HANDLE, BOOL, FALSE, INVALID_HANDLE_VALUE, CloseHandle,
};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualProtect,
    MEM_COMMIT, MEM_RESERVE, MEM_RELEASE,
    PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, CreateRemoteThread, WaitForSingleObject,
    PROCESS_ALL_ACCESS, INFINITE,
};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleHandleA, GetProcAddress,
};
```

### Error Handling with GetLastError

```rust
use windows_sys::Win32::Foundation::GetLastError;
use std::ptr;

fn check_handle(h: HANDLE) -> anyhow::Result<HANDLE> {
    if h == 0 || h == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        anyhow::bail!("WinAPI call failed with error code: {:#010x}", err);
    }
    Ok(h)
}

// Usage
fn open_target(pid: u32) -> anyhow::Result<HANDLE> {
    let handle = unsafe {
        OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)
    };
    check_handle(handle)
}
```

### VirtualAlloc / WriteProcessMemory Pattern

```rust
use std::ffi::c_void;

unsafe fn alloc_and_write(pid: u32, data: &[u8]) -> anyhow::Result<*mut c_void> {
    let proc = check_handle(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid))?;

    // Allocate RW memory in target process
    let remote_buf = VirtualAlloc(
        ptr::null(),
        data.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );

    if remote_buf.is_null() {
        anyhow::bail!("VirtualAlloc failed: {:#x}", GetLastError());
    }

    // Write data
    let mut written = 0usize;
    let ok = WriteProcessMemory(
        proc,
        remote_buf,
        data.as_ptr() as *const c_void,
        data.len(),
        &mut written,
    );

    if ok == FALSE {
        anyhow::bail!("WriteProcessMemory failed: {:#x}", GetLastError());
    }

    // Change protection to RX
    let mut old_protect = 0u32;
    VirtualProtect(remote_buf, data.len(), PAGE_EXECUTE_READ, &mut old_protect);

    CloseHandle(proc);
    Ok(remote_buf)
}
```

### Dynamic Function Resolution

```rust
use std::ffi::CString;

unsafe fn get_proc(module: &str, func: &str) -> anyhow::Result<unsafe extern "system" fn() -> isize> {
    let mod_name = CString::new(module)?;
    let func_name = CString::new(func)?;

    let hmod = GetModuleHandleA(mod_name.as_ptr() as *const u8);
    if hmod == 0 {
        anyhow::bail!("Module {} not found", module);
    }

    let addr = GetProcAddress(hmod, func_name.as_ptr() as *const u8);
    addr.ok_or_else(|| anyhow::anyhow!("Function {} not found", func))
}
```

---

## 5. FFI and Unsafe Patterns

### extern Blocks

```rust
// Calling a C library function
extern "C" {
    fn strlen(s: *const i8) -> usize;
    fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8;
}

// Windows calling convention (stdcall)
extern "system" {
    fn MessageBoxA(hwnd: isize, text: *const u8, caption: *const u8, utype: u32) -> i32;
}

fn show_msgbox() {
    use std::ffi::CString;
    let text = CString::new("Hello").unwrap();
    let cap  = CString::new("Caption").unwrap();
    unsafe {
        MessageBoxA(0, text.as_ptr() as _, cap.as_ptr() as _, 0);
    }
}
```

### Raw Pointers & from_raw_parts

```rust
fn slice_from_raw(ptr: *const u8, len: usize) -> &'static [u8] {
    // SAFETY: caller guarantees ptr is valid for len bytes and lives long enough
    unsafe { std::slice::from_raw_parts(ptr, len) }
}

fn mutate_raw(ptr: *mut u8, len: usize) {
    let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
    for b in slice.iter_mut() {
        *b ^= 0xAA; // XOR each byte
    }
}
```

### MaybeUninit for Uninitialized Buffers

```rust
use std::mem::MaybeUninit;

fn read_into_uninit() {
    // Avoid zero-initializing a large buffer
    let mut buf: [MaybeUninit<u8>; 4096] = unsafe { MaybeUninit::uninit().assume_init() };

    // Fill it (e.g., via a C API call that writes to the buffer)
    // ... FFI call writes into buf.as_mut_ptr() ...

    // Assume initialized after the call
    let initialized: &[u8] = unsafe {
        std::slice::from_raw_parts(buf.as_ptr() as *const u8, 4096)
    };
    println!("First byte: {:#x}", initialized[0]);
}
```

### transmute (Use Sparingly)

```rust
// Cast a function pointer received as usize back to a callable
unsafe fn call_shellcode(addr: usize) {
    // transmute the address to a function pointer
    let f: extern "C" fn() = std::mem::transmute(addr);
    f();
}

// Reinterpret bytes as a struct (must match alignment/size exactly)
#[repr(C)]
struct Header {
    magic: u32,
    length: u32,
}

unsafe fn parse_header(bytes: &[u8]) -> Header {
    debug_assert!(bytes.len() >= std::mem::size_of::<Header>());
    std::ptr::read_unaligned(bytes.as_ptr() as *const Header)
}
```

---

## 6. HTTP Client (reqwest)

### Client Builder

```rust
use reqwest::{Client, Proxy};
use std::time::Duration;
use anyhow::Result;

fn build_client() -> Result<Client> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        // Route through SOCKS5 proxy
        .proxy(Proxy::all("socks5://127.0.0.1:9050")?)
        // Accept invalid certs (useful for internal infra)
        .danger_accept_invalid_certs(true)
        // Custom user-agent
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        // Disable system root store, use embedded certs
        .tls_built_in_root_certs(true)
        .build()?;
    Ok(client)
}
```

### Async GET / POST

```rust
use reqwest::Client;
use serde_json::Value;

async fn get_json(client: &Client, url: &str) -> anyhow::Result<Value> {
    let resp = client.get(url)
        .header("Authorization", "Bearer secrettoken")
        .send()
        .await?
        .error_for_status()?;  // returns Err on 4xx/5xx

    Ok(resp.json::<Value>().await?)
}

async fn post_data(client: &Client, url: &str, body: &Value) -> anyhow::Result<Vec<u8>> {
    let bytes = client.post(url)
        .json(body)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    Ok(bytes.to_vec())
}
```

### Custom Headers & Multipart

```rust
use reqwest::multipart;

async fn upload_file(client: &Client, url: &str, data: Vec<u8>) -> anyhow::Result<()> {
    let part = multipart::Part::bytes(data)
        .file_name("loot.zip")
        .mime_str("application/octet-stream")?;

    let form = multipart::Form::new().part("file", part);

    client.post(url)
        .multipart(form)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}
```

---

## 7. Serialization (serde)

### Derive Macros

```rust
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
struct ScanResult {
    host: String,
    port: u16,
    open: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    banner: Option<String>,
    #[serde(rename = "timestamp_utc")]
    timestamp: u64,
}
```

### serde_json — Value and Dynamic JSON

```rust
use serde_json::{json, Value};

fn build_payload(id: &str, data: &[u8]) -> Value {
    json!({
        "id": id,
        "output": base64::engine::general_purpose::STANDARD.encode(data),
        "ts": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    })
}

fn parse_arbitrary(raw: &str) -> anyhow::Result<()> {
    let v: Value = serde_json::from_str(raw)?;
    if let Some(cmd) = v["command"].as_str() {
        println!("Command: {cmd}");
    }
    Ok(())
}
```

### Pretty-Print Output for Tools

```rust
fn print_results<T: serde::Serialize>(results: &[T]) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    println!("{json}");
    Ok(())
}
```

---

## 8. Build Optimization for Evasion

### profile.release Settings

```toml
[profile.release]
# Optimization level: "z" = size, "s" = slightly larger but faster, 3 = speed
opt-level    = "z"
# Link-time optimization (slower build, smaller/faster binary)
lto          = true
# Single codegen unit — required for full LTO
codegen-units = 1
# abort on panic instead of unwinding (removes panic infrastructure)
panic        = "abort"
# Strip debug symbols
strip        = true
# Enable incremental builds only for dev
incremental  = false
```

### Reducing PE Size Further

```bash
# After cross-compiling, UPX-pack the binary (adds one layer of packing)
upx --best --lzma tool.exe

# Remove RTTI, exception handling tables (MSVC target — via rustflags)
# For GNU target, pass linker flags:
RUSTFLAGS="-C link-arg=-Wl,--gc-sections -C link-arg=-Wl,--strip-all" \
    cargo build --release --target x86_64-pc-windows-gnu

# Check what's in the binary — look for strings, imports
strings tool.exe | grep -i "rust\|panic\|cargo"
objdump -d tool.exe | head -100
```

### no_std Considerations

```rust
// For a no_std binary (kernel drivers, embedded — rare in red team but possible)
#![no_std]
#![no_main]

// Must provide panic handler
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Entry point for Windows no_std
#[no_mangle]
pub unsafe extern "system" fn DllMain(_: *mut u8, _: u32, _: *mut u8) -> i32 { 1 }
```

---

## 9. Error Handling Patterns

### anyhow::Result — Quick & Flexible

```rust
use anyhow::{Result, Context, bail, anyhow};

fn parse_port(s: &str) -> Result<u16> {
    s.parse::<u16>()
        .context(format!("Invalid port number: '{s}'"))
}

fn require_env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("Missing env var: {key}"))
}

fn check_range(n: u16) -> Result<u16> {
    if n == 0 {
        bail!("Port cannot be 0");
    }
    Ok(n)
}
```

### thiserror — Typed Errors for Libraries

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("Connection to {host}:{port} failed: {source}")]
    Connect { host: String, port: u16, #[source] source: std::io::Error },

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Command execution failed with exit code {0}")]
    ExecFailed(i32),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Request(#[from] reqwest::Error),
}
```

### ? in Async Contexts

```rust
// ? works the same in async fn as in sync fn
async fn fetch_and_parse(url: &str) -> anyhow::Result<Vec<String>> {
    let client = reqwest::Client::new();
    let text = client.get(url).send().await?.text().await?;
    let lines: Vec<String> = text.lines().map(String::from).collect();
    Ok(lines)
}
```

---

## 10. Useful Patterns

### CLI with clap Derive

```rust
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "scanner", about = "Port scanner")]
struct Args {
    /// Target host or CIDR range
    #[arg(short = 'H', long)]
    host: String,

    /// Port range, e.g. "1-1024" or "22,80,443"
    #[arg(short, long, default_value = "1-1024")]
    ports: String,

    /// Max concurrent connections
    #[arg(short = 'c', long, default_value_t = 500)]
    concurrency: usize,

    /// Connection timeout in milliseconds
    #[arg(short, long, default_value_t = 1000)]
    timeout_ms: u64,

    /// Output file for JSON results
    #[arg(short, long)]
    output: Option<String>,
}

fn main() {
    let args = Args::parse();
    println!("Scanning {}:{}", args.host, args.ports);
}
```

### Logging with env_logger

```rust
fn setup_logging() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    )
    .format_timestamp_millis()
    .init();
}

// Usage: RUST_LOG=debug ./tool
// log::info!, log::warn!, log::error!, log::debug!
```

### In-Memory Execution via memfd (Linux)

```rust
#[cfg(target_os = "linux")]
mod memfd_exec {
    use std::ffi::CString;
    use std::os::unix::io::FromRawFd;
    use std::fs::File;
    use std::io::Write;

    pub fn exec_in_memory(elf_bytes: &[u8]) -> anyhow::Result<()> {
        // Create anonymous file descriptor
        let name = CString::new("").unwrap();
        let fd = unsafe {
            libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 1u32) as i32
        };
        if fd < 0 {
            anyhow::bail!("memfd_create failed");
        }

        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(elf_bytes)?;
        drop(file); // keep fd alive via /proc

        let path = format!("/proc/self/fd/{fd}");
        let args: Vec<CString> = vec![CString::new(path.clone())?];
        let env: Vec<CString> = vec![];

        // execve replaces the process
        nix::unistd::execve(
            &CString::new(path)?,
            &args,
            &env,
        )?;

        unreachable!()
    }
}
```

### Base64 Encode / Decode

```rust
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

fn encode(data: &[u8]) -> String {
    B64.encode(data)
}

fn decode(s: &str) -> anyhow::Result<Vec<u8>> {
    Ok(B64.decode(s)?)
}
```

### AES-256-CBC Encrypt / Decrypt (RustCrypto)

```rust
use aes::Aes256;
use cbc::{Encryptor, Decryptor};
use cbc::cipher::{BlockEncryptMut, BlockDecryptMut, KeyIvInit};
use rand::RngCore;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    // Pad to block boundary (PKCS7)
    let padded_len = ((plaintext.len() / 16) + 1) * 16;
    let mut buf = plaintext.to_vec();
    let pad = (padded_len - plaintext.len()) as u8;
    buf.resize(padded_len, pad);

    let ct = Aes256CbcEnc::new(key.into(), &iv.into())
        .encrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buf, plaintext.len())
        .map_err(|e| anyhow::anyhow!("Encrypt error: {e}"))?
        .to_vec();

    // Prepend IV
    let mut out = iv.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    if ciphertext.len() < 16 {
        anyhow::bail!("Ciphertext too short");
    }
    let (iv, ct) = ciphertext.split_at(16);
    let iv: [u8; 16] = iv.try_into()?;

    let mut buf = ct.to_vec();
    let pt = Aes256CbcDec::new(key.into(), &iv.into())
        .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buf)
        .map_err(|e| anyhow::anyhow!("Decrypt error: {e}"))?
        .to_vec();

    Ok(pt)
}
```

---

## Quick Reference: Common Cargo Commands

```bash
# Build debug (fast, larger, has symbols)
cargo build

# Build release (slow, smaller, optimized)
cargo build --release

# Cross-compile Windows 64-bit PE from Linux
cargo build --release --target x86_64-pc-windows-gnu

# Check without building (fast syntax check)
cargo check

# Run tests
cargo test

# Show dependency tree
cargo tree

# Audit for known vulnerabilities
cargo audit

# Update dependencies
cargo update

# Show binary size breakdown
cargo bloat --release

# Format code
cargo fmt

# Run clippy (linter)
cargo clippy -- -D warnings
```

---

## Resources

- Rust Book: https://doc.rust-lang.org/book/
- Rust Reference: https://doc.rust-lang.org/reference/
- tokio documentation: https://docs.rs/tokio/latest/tokio/
- reqwest crate: https://docs.rs/reqwest/latest/reqwest/
- windows-sys crate: https://docs.rs/windows-sys/latest/windows_sys/
- RustCrypto GitHub: https://github.com/RustCrypto
- serde documentation: https://serde.rs/
- clap crate: https://docs.rs/clap/latest/clap/
- anyhow crate: https://docs.rs/anyhow/latest/anyhow/
- thiserror crate: https://docs.rs/thiserror/latest/thiserror/
- Rust Cross-Compilation Guide: https://rust-lang.github.io/rustup/cross-compilation.html
- crates.io: https://crates.io/
