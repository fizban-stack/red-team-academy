---
layout: training-page
title: "Linux eBPF Evasion — Red Team Academy"
module: "Evasion"
tags:
  - linux
  - ebpf
  - rootkits
  - edr-bypass
page_key: "evasion-ebpf"
---
<h1>Linux eBPF Evasion</h1>
<p>Extended Berkeley Packet Filter (eBPF) has revolutionized Linux networking, observability, and security. However, since its widespread adoption by EDRs (like Falcon CWP and Tracee), threat actors and red teams consistently abuse eBPF in 2025 and 2026 to create nearly invisible kernel-level rootkits, intercept network traffic, and silently bypass detection.</p>

<h2>eBPF Rootkit Capabilities</h2>
<p>Unlike traditional Loadable Kernel Modules (LKMs), eBPF programs do not require loading module signatures checked by Secure Boot in the same way, creating a "visibility gap" for legacy security scanners. Advanced frameworks like <em>KernelGhost</em> and <em>TripleCross</em> leverage eBPF to achieve deep stealth.</p>

<h3>1. Syscall Hooking & Process Hiding</h3>
<p>By attaching eBPF programs to <code>kprobes</code> or <code>tracepoints</code>, an attacker can modify the return values of system calls before they reach user space. For example, hooking <code>sys_getdents64</code> allows an attacker to hide malicious PIDs from commands like <code>ps</code> or <code>top</code>.</p>
<pre><code>// Example eBPF C code hooking getdents64 to hide a PID
SEC("kretprobe/sys_getdents64")
int bpf_prog(struct pt_regs *ctx) {
    // Filter out directory entries matching the malicious PID
    // Returns altered buffer to userland
    return 0;
}</code></pre>

<h3>2. XDP & TC Magic Packets (Network Evasion)</h3>
<p>eBPF allows packet manipulation at the XDP (eXpress Data Path) or TC (Traffic Control) layers, dropping or altering packets before `tcpdump` or iptables even sees them. The 2025 "LinkPro" rootkit abused this to listen for "magic packets" triggering a reverse shell, while appearing entirely silent to host-based network monitors.</p>
<pre><code># Compiling and loading an eBPF XDP hook
clang -O2 -target bpf -c xdp_c2.c -o xdp_c2.o
ip link set dev eth0 xdp obj xdp_c2.o sec xdp_hook</code></pre>

<h2>Bypassing eBPF Observers</h2>
<p>Defenders rely on eBPF to monitor the <code>bpf()</code> syscall itself. Red teams can evade this by:</p>
<ul>
    <li><strong>Blinding the EDR:</strong> Detaching the EDR's eBPF programs by overriding the kprobe links if elevated privileges are achieved.</li>
    <li><strong>Exploiting the Verifier:</strong> Using logic bugs in the eBPF verifier (still occasionally found in 2026) to achieve out-of-bounds Read/Write capabilities inside the kernel, allowing modification of kernel structures directly to disable telemetry.</li>
</ul>

<h2>Resources</h2>
<ul>
  <li>TripleCross eBPF Rootkit — <code>github.com/h3xduck/TripleCross</code></li>
  <li>ebpfkit (Offensive Framework) — <code>github.com/Gui774ume/ebpfkit</code></li>
  <li>KernelGhost — <code>github.com/R3d-T3am/KernelGhost</code></li>
</ul>
