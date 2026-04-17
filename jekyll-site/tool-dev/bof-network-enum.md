---
layout: training-page
title: "Network Enumeration BOFs — Red Team Academy"
module: "Tool Development"
tags:
  - bof
  - network-enumeration
  - opsec
  - port-scan
  - arp-scan
  - netstat-bof
  - dns-bof
page_key: "tool-dev-bof-network-enum"
render_with_liquid: false
---

# Network Enumeration BOFs

Network enumeration in post-exploitation traditionally spawns well-known binaries — `ipconfig.exe`, `netstat.exe`, `net.exe`, `nslookup.exe` — all of which generate process creation events logged by EDR and SIEM systems. Network enumeration BOFs perform identical tasks by calling Windows API functions directly from within the Beacon process, producing no child processes and leaving no command-line artifacts in process telemetry. MITRE ATT&CK: T1016, T1046, T1049, T1018.

---

## Why Network BOFs Matter

EDR telemetry comparison for common network tasks:

| Command | Process Created | Command Line Visible | Parent-Child Anomaly |
|---------|---------------|---------------------|---------------------|
| `ipconfig /all` | ipconfig.exe | YES | Beacon → ipconfig |
| ipconfig BOF | NONE | NO | None |
| `netstat -ano` | netstat.exe | YES | Beacon → netstat |
| netstat BOF | NONE | NO | None |
| `net view \\server` | net.exe | YES | Beacon → net |
| netshareenum BOF | NONE | NO | None |
| `nslookup target` | nslookup.exe | YES | Beacon → nslookup |
| DNS BOF | NONE | NO | None |
| `arp -a` | arp.exe | YES | Beacon → arp |
| arp BOF | NONE | NO | None |

---

## ipconfig BOF: GetAdaptersInfo

**MITRE ATT&CK: T1016 — System Network Configuration Discovery**

```c
// ipconfig_bof.c — Network adapter enumeration via Windows IP Helper API
#include "beacon.h"
#include <iphlpapi.h>

DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetAdaptersInfo(PIP_ADAPTER_INFO, PULONG);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetAdaptersAddresses(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetNetworkParams(PFIXED_INFO, PULONG);

void go(char *args, int args_len) {
    ULONG buf_size = sizeof(IP_ADAPTER_INFO) * 16;
    PIP_ADAPTER_INFO adapter_info = (PIP_ADAPTER_INFO)KERNEL32$HeapAlloc(
        KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, buf_size
    );
    
    DWORD ret = IPHLPAPI$GetAdaptersInfo(adapter_info, &buf_size);
    
    if (ret == ERROR_BUFFER_OVERFLOW) {
        // Reallocate with correct size
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, adapter_info);
        adapter_info = (PIP_ADAPTER_INFO)KERNEL32$HeapAlloc(
            KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, buf_size
        );
        ret = IPHLPAPI$GetAdaptersInfo(adapter_info, &buf_size);
    }
    
    if (ret != NO_ERROR) {
        BeaconPrintf(CALLBACK_ERROR, "GetAdaptersInfo failed: %d\n", ret);
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, adapter_info);
        return;
    }
    
    PIP_ADAPTER_INFO adapter = adapter_info;
    while (adapter) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "\nAdapter: %s\n"
            "  Description: %s\n"
            "  MAC: %02x-%02x-%02x-%02x-%02x-%02x\n"
            "  IP:  %s\n"
            "  Mask:%s\n"
            "  GW:  %s\n"
            "  DHCP Server: %s\n",
            adapter->AdapterName,
            adapter->Description,
            adapter->Address[0], adapter->Address[1], adapter->Address[2],
            adapter->Address[3], adapter->Address[4], adapter->Address[5],
            adapter->IpAddressList.IpAddress.String,
            adapter->IpAddressList.IpMask.String,
            adapter->GatewayList.IpAddress.String,
            adapter->DhcpEnabled ? adapter->DhcpServer.IpAddress.String : "DHCP Disabled"
        );
        
        adapter = adapter->Next;
    }
    
    // Also get DNS server info
    ULONG fixed_size = sizeof(FIXED_INFO) * 2;
    PFIXED_INFO fixed_info = (PFIXED_INFO)KERNEL32$HeapAlloc(
        KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, fixed_size
    );
    
    if (IPHLPAPI$GetNetworkParams(fixed_info, &fixed_size) == NO_ERROR) {
        BeaconPrintf(CALLBACK_OUTPUT, "\nDNS Servers:\n  Primary: %s\n",
                     fixed_info->DnsServerList.IpAddress.String);
    }
    
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, adapter_info);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, fixed_info);
}
```

---

## netstat BOF: TCP/UDP Connection Table

**MITRE ATT&CK: T1049 — System Network Connections Discovery**

```c
// netstat_bof.c — Active network connections via GetExtendedTcpTable
#include "beacon.h"
#include <iphlpapi.h>
#include <in6addr.h>

DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetExtendedTcpTable(PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetExtendedUdpTable(PVOID, PDWORD, BOOL, ULONG, UDP_TABLE_CLASS, ULONG);

const char *tcp_state_str(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED:     return "CLOSED";
        case MIB_TCP_STATE_LISTEN:     return "LISTENING";
        case MIB_TCP_STATE_SYN_SENT:   return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:   return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB:      return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1:  return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2:  return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:    return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK:   return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        default:                        return "UNKNOWN";
    }
}

void enum_tcp4(void) {
    DWORD table_size = 0;
    DWORD ret = IPHLPAPI$GetExtendedTcpTable(
        NULL, &table_size, TRUE, AF_INET,
        TCP_TABLE_OWNER_PID_ALL, 0
    );
    
    PMIB_TCPTABLE_OWNER_PID table = (PMIB_TCPTABLE_OWNER_PID)KERNEL32$HeapAlloc(
        KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, table_size
    );
    
    ret = IPHLPAPI$GetExtendedTcpTable(
        table, &table_size, TRUE, AF_INET,
        TCP_TABLE_OWNER_PID_ALL, 0
    );
    
    if (ret == NO_ERROR) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n%-23s %-23s %-12s %-8s\n",
                     "Local Address", "Remote Address", "State", "PID");
        BeaconPrintf(CALLBACK_OUTPUT, "%-23s %-23s %-12s %-8s\n",
                     "-------------", "--------------", "-----", "---");
        
        for (DWORD i = 0; i < table->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID *row = &table->table[i];
            
            struct in_addr local_in, remote_in;
            local_in.S_un.S_addr  = row->dwLocalAddr;
            remote_in.S_un.S_addr = row->dwRemoteAddr;
            
            char local_str[64], remote_str[64];
            MSVCRT$sprintf(local_str,  "%d.%d.%d.%d:%d",
                (row->dwLocalAddr >> 0)  & 0xFF,
                (row->dwLocalAddr >> 8)  & 0xFF,
                (row->dwLocalAddr >> 16) & 0xFF,
                (row->dwLocalAddr >> 24) & 0xFF,
                MSVCRT$ntohs((u_short)row->dwLocalPort));
            
            MSVCRT$sprintf(remote_str, "%d.%d.%d.%d:%d",
                (row->dwRemoteAddr >> 0)  & 0xFF,
                (row->dwRemoteAddr >> 8)  & 0xFF,
                (row->dwRemoteAddr >> 16) & 0xFF,
                (row->dwRemoteAddr >> 24) & 0xFF,
                MSVCRT$ntohs((u_short)row->dwRemotePort));
            
            BeaconPrintf(CALLBACK_OUTPUT, "%-23s %-23s %-12s %-8d\n",
                local_str, remote_str,
                tcp_state_str(row->dwState), row->dwOwningPid);
        }
    }
    
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, table);
}

void go(char *args, int args_len) {
    BeaconPrintf(CALLBACK_OUTPUT, "=== TCP Connections (IPv4) ===\n");
    enum_tcp4();
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Enumerated via GetExtendedTcpTable BOF\n");
}
```

---

## Port Scan BOF

**MITRE ATT&CK: T1046 — Network Service Discovery**

A connect-scan BOF that avoids spawning nmap.exe or any scanner process:

```c
// portscan_bof.c — TCP connect scan via Windows sockets in BOF
#include "beacon.h"
#include <winsock2.h>
#include <ws2tcpip.h>

DECLSPEC_IMPORT int WINAPI WS2_32$WSAStartup(WORD, LPWSADATA);
DECLSPEC_IMPORT int WINAPI WS2_32$WSACleanup(void);
DECLSPEC_IMPORT SOCKET WINAPI WS2_32$socket(int, int, int);
DECLSPEC_IMPORT int WINAPI WS2_32$connect(SOCKET, const struct sockaddr *, int);
DECLSPEC_IMPORT int WINAPI WS2_32$closesocket(SOCKET);
DECLSPEC_IMPORT int WINAPI WS2_32$WSAGetLastError(void);
DECLSPEC_IMPORT DWORD WINAPI WS2_32$inet_addr(const char *);
DECLSPEC_IMPORT u_short WINAPI WS2_32$htons(u_short);
DECLSPEC_IMPORT int WINAPI WS2_32$ioctlsocket(SOCKET, long, u_long *);
DECLSPEC_IMPORT int WINAPI WS2_32$select(int, fd_set *, fd_set *, fd_set *, const struct timeval *);

BOOL tcp_connect_scan(const char *target_ip, USHORT port, int timeout_ms) {
    SOCKET sock = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return FALSE;
    
    struct sockaddr_in target;
    target.sin_family      = AF_INET;
    target.sin_addr.s_addr = WS2_32$inet_addr(target_ip);
    target.sin_port        = WS2_32$htons(port);
    
    // Set non-blocking
    u_long nonblocking = 1;
    WS2_32$ioctlsocket(sock, FIONBIO, &nonblocking);
    
    // Connect attempt (returns immediately in non-blocking)
    WS2_32$connect(sock, (struct sockaddr *)&target, sizeof(target));
    
    // Wait for connection with select() timeout
    fd_set write_fds;
    FD_ZERO(&write_fds);
    FD_SET(sock, &write_fds);
    
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    int result = WS2_32$select(0, NULL, &write_fds, NULL, &tv);
    
    WS2_32$closesocket(sock);
    
    return (result > 0);  // > 0 means socket is writable = connected
}

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);
    
    char *target_ip = BeaconDataExtract(&parser, NULL);  // "192.168.1.1"
    int port_start  = BeaconDataInt(&parser);             // 1
    int port_end    = BeaconDataInt(&parser);             // 1024
    int timeout_ms  = BeaconDataInt(&parser);             // 500
    
    // Initialize Winsock
    WSADATA wsa;
    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "WSAStartup failed\n");
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Scanning %s ports %d-%d (timeout: %dms)\n",
                 target_ip, port_start, port_end, timeout_ms);
    
    int open_count = 0;
    
    for (int port = port_start; port <= port_end; port++) {
        if (tcp_connect_scan(target_ip, (USHORT)port, timeout_ms)) {
            BeaconPrintf(CALLBACK_OUTPUT, "  [OPEN] %s:%d\n", target_ip, port);
            open_count++;
        }
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Scan complete: %d open ports found\n", open_count);
    
    WS2_32$WSACleanup();
}
```

---

## ARP Scan BOF

**MITRE ATT&CK: T1018 — Remote System Discovery**

```c
// arp_scan_bof.c — ARP table and subnet discovery via SendARP
#include "beacon.h"
#include <iphlpapi.h>

DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$SendARP(IPAddr, IPAddr, PULONG, PULONG);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetIpNetTable(PMIB_IPNETTABLE, PULONG, BOOL);

void enum_arp_cache(void) {
    ULONG table_size = sizeof(MIB_IPNETTABLE) + sizeof(MIB_IPNETROW) * 256;
    PMIB_IPNETTABLE arp_table = (PMIB_IPNETTABLE)KERNEL32$HeapAlloc(
        KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, table_size
    );
    
    if (IPHLPAPI$GetIpNetTable(arp_table, &table_size, TRUE) == NO_ERROR) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n=== ARP Cache ===\n");
        BeaconPrintf(CALLBACK_OUTPUT, "%-20s %-20s %s\n", "IP Address", "MAC Address", "Type");
        
        for (DWORD i = 0; i < arp_table->dwNumEntries; i++) {
            MIB_IPNETROW *row = &arp_table->table[i];
            
            char ip[16];
            MSVCRT$sprintf(ip, "%d.%d.%d.%d",
                (row->dwAddr >> 0)  & 0xFF,
                (row->dwAddr >> 8)  & 0xFF,
                (row->dwAddr >> 16) & 0xFF,
                (row->dwAddr >> 24) & 0xFF);
            
            char mac[18];
            MSVCRT$sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                row->bPhysAddr[0], row->bPhysAddr[1], row->bPhysAddr[2],
                row->bPhysAddr[3], row->bPhysAddr[4], row->bPhysAddr[5]);
            
            const char *type;
            switch (row->dwType) {
                case MIB_IPNET_TYPE_STATIC:  type = "static";  break;
                case MIB_IPNET_TYPE_DYNAMIC: type = "dynamic"; break;
                case MIB_IPNET_TYPE_INVALID: type = "invalid"; break;
                default:                     type = "other";
            }
            
            BeaconPrintf(CALLBACK_OUTPUT, "%-20s %-20s %s\n", ip, mac, type);
        }
    }
    
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, arp_table);
}

void arp_ping_subnet(const char *subnet_base, int last_octet_start, int last_octet_end) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n=== ARP Ping Sweep: %s.%d-%d ===\n",
                 subnet_base, last_octet_start, last_octet_end);
    
    for (int i = last_octet_start; i <= last_octet_end; i++) {
        char target[16];
        MSVCRT$sprintf(target, "%s.%d", subnet_base, i);
        
        IPAddr src_ip = 0;  // 0 = any source
        DWORD dest_ip = WS2_32$inet_addr(target);
        
        ULONG mac[2] = {0};
        ULONG mac_size = sizeof(mac);
        
        DWORD ret = IPHLPAPI$SendARP(dest_ip, src_ip, mac, &mac_size);
        
        if (ret == NO_ERROR) {
            BYTE *mac_bytes = (BYTE *)mac;
            BeaconPrintf(CALLBACK_OUTPUT, "  [UP] %s  %02x:%02x:%02x:%02x:%02x:%02x\n",
                target,
                mac_bytes[0], mac_bytes[1], mac_bytes[2],
                mac_bytes[3], mac_bytes[4], mac_bytes[5]);
        }
    }
}

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);
    
    char *subnet = BeaconDataExtract(&parser, NULL);  // "192.168.1"
    int start    = BeaconDataInt(&parser);             // 1
    int end      = BeaconDataInt(&parser);             // 254
    
    // Show existing ARP cache first
    enum_arp_cache();
    
    // ARP ping sweep
    arp_ping_subnet(subnet, start, end);
}
```

---

## DNS Resolution BOF

**MITRE ATT&CK: T1018 — Remote System Discovery**

```c
// dns_bof.c — DNS resolution without spawning nslookup.exe
#include "beacon.h"
#include <windns.h>

DECLSPEC_IMPORT DNS_STATUS WINAPI DNSAPI$DnsQuery_A(
    PCSTR, WORD, DWORD, PVOID, PDNS_RECORD *, PVOID *);
DECLSPEC_IMPORT VOID WINAPI DNSAPI$DnsRecordListFree(PDNS_RECORD, DNS_FREE_TYPE);

void dns_lookup(const char *hostname) {
    PDNS_RECORD dns_records = NULL;
    
    DNS_STATUS status = DNSAPI$DnsQuery_A(
        hostname,
        DNS_TYPE_A,      // Query for A records (IPv4)
        DNS_QUERY_STANDARD,
        NULL,            // Extra servers (NULL = use system DNS)
        &dns_records,
        NULL
    );
    
    if (status == 0 && dns_records) {
        PDNS_RECORD record = dns_records;
        while (record) {
            if (record->wType == DNS_TYPE_A) {
                struct in_addr addr;
                addr.S_un.S_addr = record->Data.A.IpAddress;
                BeaconPrintf(CALLBACK_OUTPUT, "  %s → %d.%d.%d.%d (TTL: %d)\n",
                    hostname,
                    record->Data.A.IpAddress & 0xFF,
                    (record->Data.A.IpAddress >> 8) & 0xFF,
                    (record->Data.A.IpAddress >> 16) & 0xFF,
                    (record->Data.A.IpAddress >> 24) & 0xFF,
                    record->dwTtl);
            }
            record = record->pNext;
        }
        DNSAPI$DnsRecordListFree(dns_records, DnsFreeRecordList);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "  %s → [no result / status: %d]\n", hostname, status);
    }
}

void dns_reverse_lookup(const char *ip_str) {
    PDNS_RECORD dns_records = NULL;
    
    // Build reverse lookup name: "192.168.1.10" → "10.1.168.192.in-addr.arpa"
    int a, b, c, d;
    MSVCRT$sscanf(ip_str, "%d.%d.%d.%d", &a, &b, &c, &d);
    
    char reverse_name[64];
    MSVCRT$sprintf(reverse_name, "%d.%d.%d.%d.in-addr.arpa", d, c, b, a);
    
    DNS_STATUS status = DNSAPI$DnsQuery_A(
        reverse_name, DNS_TYPE_PTR, DNS_QUERY_STANDARD,
        NULL, &dns_records, NULL
    );
    
    if (status == 0 && dns_records) {
        if (dns_records->wType == DNS_TYPE_PTR) {
            BeaconPrintf(CALLBACK_OUTPUT, "  %s → %ls\n", ip_str, dns_records->Data.PTR.pNameHost);
        }
        DNSAPI$DnsRecordListFree(dns_records, DnsFreeRecordList);
    }
}

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);
    
    char *query = BeaconDataExtract(&parser, NULL);
    int query_type = BeaconDataInt(&parser);  // 0=forward, 1=reverse
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] DNS query: %s\n", query);
    
    if (query_type == 0) {
        dns_lookup(query);
    } else {
        dns_reverse_lookup(query);
    }
}
```

---

## SMB Share Enumeration BOF

**MITRE ATT&CK: T1135 — Network Share Discovery**

```c
// netshareenum_bof.c — SMB share enumeration via NetShareEnum
#include "beacon.h"

// NetAPI declarations
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetShareEnum(
    LPWSTR, DWORD, LPBYTE *, DWORD, LPDWORD, LPDWORD, LPDWORD);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NETAPI32$NetApiBufferFree(LPVOID);

void enum_shares(const wchar_t *server) {
    SHARE_INFO_1 *share_info = NULL;
    DWORD entries_read = 0, total_entries = 0, resume_handle = 0;
    
    NET_API_STATUS status = NETAPI32$NetShareEnum(
        (LPWSTR)server,     // NULL = local machine, or L"\\\\server"
        1,                  // Info level 1: name, type, comment
        (LPBYTE *)&share_info,
        MAX_PREFERRED_LENGTH,
        &entries_read,
        &total_entries,
        &resume_handle
    );
    
    if (status == NERR_Success || status == ERROR_MORE_DATA) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Shares on %ls (%d found):\n",
                     server ? server : L"localhost", entries_read);
        BeaconPrintf(CALLBACK_OUTPUT, "%-25s %-10s %s\n", "Share Name", "Type", "Comment");
        BeaconPrintf(CALLBACK_OUTPUT, "%-25s %-10s %s\n", "----------", "----", "-------");
        
        for (DWORD i = 0; i < entries_read; i++) {
            const char *type_str;
            switch (share_info[i].shi1_type & ~STYPE_SPECIAL) {
                case STYPE_DISKTREE: type_str = "Disk";    break;
                case STYPE_PRINTQ:   type_str = "Print";   break;
                case STYPE_DEVICE:   type_str = "Device";  break;
                case STYPE_IPC:      type_str = "IPC";     break;
                default:             type_str = "Unknown";
            }
            
            BeaconPrintf(CALLBACK_OUTPUT, "%-25ls %-10s %ls\n",
                share_info[i].shi1_netname,
                type_str,
                share_info[i].shi1_remark ? share_info[i].shi1_remark : L""
            );
        }
        
        NETAPI32$NetApiBufferFree(share_info);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "NetShareEnum failed: %d\n", status);
    }
}

void go(char *args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);
    char *server_arg = BeaconDataExtract(&parser, NULL);  // "" = local, else hostname
    
    // Convert to wide string for NetAPI
    wchar_t server_w[256] = {0};
    if (server_arg && server_arg[0]) {
        MSVCRT$mbstowcs(server_w, server_arg, 255);
        enum_shares(server_w);
    } else {
        enum_shares(NULL);  // Enumerate local shares
    }
}
```

---

## WMI Query BOF

**MITRE ATT&CK: T1047 — Windows Management Instrumentation**

Direct WMI without spawning wmic.exe:

```c
// wmi_bof.c — WMI query via COM interfaces (no wmic.exe)
// Note: requires COM initialization — more complex BOF
// Full implementation via IWbemServices:

// Simplified approach using Windows Script Host
// (wscript.exe still spawned — full COM approach preferred for OPSEC)

// Production BOF pattern:
// 1. CoInitializeEx (COM init)
// 2. CoInitializeSecurity
// 3. CoCreateInstance(CLSID_WbemLocator, ...)
// 4. IWbemLocator::ConnectServer("ROOT\\CIMV2")
// 5. IWbemServices::ExecQuery("SELECT * FROM Win32_Process")
// 6. Enumerate IEnumWbemClassObject results
// 7. CoUninitialize

// The TrustedSec BOF collection includes a working WMI query BOF:
// https://github.com/trustedsec/CS-Situational-Awareness-BOF/tree/master/src/SA/wmi

void go(char *args, int args_len) {
    BeaconPrintf(CALLBACK_OUTPUT, 
        "[*] WMI BOF: Use TrustedSec's wmi BOF for full implementation\n"
        "[*] This BOF demonstrates the pattern — production code uses COM\n"
    );
}
```
