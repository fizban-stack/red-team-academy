---
layout: training-page
title: "Ludus — Self-Hosted Red Team Range — Red Team Academy"
module: "Red Team Tools"
tags:
  - ludus
  - proxmox
  - red-team-range
  - lab-automation
  - active-directory
  - goad
  - range-automation
page_key: "tools-ludus"
render_with_liquid: false
---

# Ludus — Self-Hosted Red Team Range on Proxmox

Ludus (Bad Sector Labs) is the modern standard for automated red team range management. It builds on Proxmox to deliver isolated, multi-tenant, fully-provisioned AD environments that snap, revert, and rebuild deterministically. The defining feature — **testing mode** — auto-reverts every VM to a clean snapshot after each test run, making Ludus the ideal substrate for repeatable Atomic Red Team campaigns, CALDERA operations, and purple-team exercises.

**Status (2025):** Ludus 2 — actively developed, GNU AGPLv3. GitLab canonical (`gitlab.com/badsectorlabs/ludus`), GitHub mirror. CISA runs a fork for federal range automation. Bad Sector Labs added an Enterprise subscription tier in 2025 (Mythic role, WireGuard enhancements).

## Post-Install Setup

After Proxmox + Ludus install completes:

<pre><code># Configure your API key (printed at end of install):
ludus apikey                          # interactive — writes to ~/.config/ludus/config.yml
ludus version                         # confirm CLI talks to server on :8080

# Check available OS templates (Packer-built base images):
ludus templates list

# Build any missing templates (long-running — 20-60 min per template):
ludus templates build

# Add a custom Packer template from local directory:
ludus templates add -d ./my-custom-template/

# Add Ansible roles from Galaxy (roles are per-user):
ludus ansible role add badsectorlabs.ludus_adcs
ludus ansible role add badsectorlabs.ludus_elastic_container
ludus ansible role add netpenguins.ludus_sliver

# Add a local role:
ludus ansible role add -d ./ludus_child_domain/
</code></pre>

## Range Config YAML

Everything about a range is declared in a single YAML file. The `{{ range_id }}` jinja substitution namespaces all VMs per-user — the same config works for 50 students in parallel without collision.

<pre><code>ludus:
  # Domain controller
  - vm_name: "{{ range_id }}-DC01"
    hostname: "{{ range_id }}-DC01"
    template: win2019-server-x64-template
    vlan: 10
    ip_last_octet: 11
    ram_gb: 8
    cpus: 4
    windows:
      gpos:
        - disable_defender
    domain:
      fqdn: lab.internal
      role: primary-dc

  # Domain-joined workstation
  - vm_name: "{{ range_id }}-WS01"
    hostname: "{{ range_id }}-WS01"
    template: win11-22h2-x64-enterprise-template
    vlan: 10
    ip_last_octet: 21
    ram_gb: 8
    cpus: 4
    windows:
      autologon_user: labuser
      install_chocolatey: true
    domain:
      fqdn: lab.internal
      role: member
    ansible_groups: [workstations]

  # Attacker box (separate VLAN, internet allowed)
  - vm_name: "{{ range_id }}-kali"
    hostname: "{{ range_id }}-kali"
    template: kali-x64-desktop-template
    vlan: 99
    ip_last_octet: 1
    ram_gb: 8
    cpus: 4
    linux: true
    testing:
      snapshot: false
      block_internet: false

  # Visibility (Splunk or Elastic on separate VM)
  - vm_name: "{{ range_id }}-splunk"
    hostname: "{{ range_id }}-splunk"
    template: debian-12-x64-server-template
    vlan: 10
    ip_last_octet: 100
    ram_gb: 16
    cpus: 4
    linux: true
    roles: [p4t12ick.ludus_ar_splunk]

router:
  vm_name: "{{ range_id }}-router"
  ram_gb: 2
  cpus: 2

network:
  inter_vlan_default: REJECT
  rules:
    - { name: "Domain internal", vlan_src: 10, vlan_dst: 10, protocol: all, ports: all, action: ACCEPT }
    - { name: "Kali to Domain", vlan_src: 99, vlan_dst: 10, protocol: all, ports: all, action: ACCEPT }

defaults:
  ad_domain_admin: admin
  ad_domain_admin_password: P@ssw0rd
  timezone: America/New_York
</code></pre>

## Deployment Workflow

<pre><code># 1. Push your config to the server:
ludus range config get &gt; range.yml    # fetch current config (optional baseline)
$EDITOR range.yml
ludus range config set -f range.yml

# 2. Deploy (triggers Proxmox VM creation + Ansible provisioning):
ludus range deploy

# 3. Watch progress:
ludus range logs -f         # tail Ansible output in real time

# 4. Check status:
ludus range status          # table: power state, IP addresses, VLANs, roles applied
ludus range errors          # show only failures from the last run

# 5. Targeted re-runs (huge time saver when iterating):
ludus range deploy -t vm-deploy              # only VM provisioning, skip role configuration
ludus range deploy --limit DC01,WS01         # only specific hosts
ludus range deploy --limit "{{ range_id }}-kali"
</code></pre>

## Testing Mode (Snapshot + Auto-Revert)

This is Ludus's killer feature for repeatable detonation testing. Testing mode snapshots all VMs, locks down internet egress by default, and **automatically reverts every VM to the clean snapshot** when testing ends.

<pre><code># 1. Take a clean snapshot manually (before any test activity):
ludus snapshots create clean-ad "After GOAD ansible converges, pre-attack state"
ludus snapshots list

# 2. Enter testing mode:
#    - Snapshots all VMs that don't have snapshot:false in config
#    - Cuts internet egress (Windows VMs get a green wallpaper as visual indicator)
ludus testing start
ludus testing status

# 3. Open selective egress if your tools need it:
ludus testing allow -d microsoft.com          # allow specific domain
ludus testing allow -i 192.168.100.5          # allow specific IP
ludus testing allow -f /opt/allowlist.txt     # allow list from file

# 4. Execute your test:
# Invoke-AtomicTest T1003.001 — PurpleSharp, CALDERA, manual attack, etc.

# 5. Observe telemetry in SIEM, Velociraptor, etc.

# 6. END testing mode — AUTO-REVERTS ALL VMs to clean snapshot:
ludus testing stop
# VMs are now clean, ready for the next test iteration

# Manual snapshot management:
ludus snapshots rollback clean-ad              # manual revert
ludus snapshots rollback clean-ad --vmids 104  # revert single VM
</code></pre>

The `testing start` / `testing stop` loop is the primitive that makes Ludus the right substrate for detection engineering campaigns — you can detonate, observe, revert, and repeat indefinitely without rebuilding the range.

## User Management and Multi-Tenancy

<pre><code># Admin operations:
ludus user add --name "Alice" --userid alice
ludus user add --name "Bob" --userid bob --admin
ludus user apikey --userid alice             # generate/rotate API key
ludus --user alice range config get          # admin: operate as another user's range

# Each user gets:
# - Isolated VLAN range (10.&lt;userVlanBase&gt;.0.0/16)
# - Own Proxmox pool and storage namespace
# - Independent Ansible role library
# - Independent firewall rules
</code></pre>

This isolation model is what makes Ludus work for training environments — every student gets a real, full-stack AD range without sharing anything.

## Prebuilt Range Templates

| Template | What It Deploys |
|----------|----------------|
| **GOAD** | Game of Active Directory — 5 VMs, 2 domains (NORTH + SEVENKINGDOMS), multiple AD misconfigs for attack practice |
| **GOAD-Light** | 2 VMs, 1 domain — lighter footprint, same attack surface |
| **GOAD-SCCM** | GOAD + SCCM/ConfigMgr for SCCM attack scenarios |
| **NHA (5-VM 2-domain)** | Ninja Hacking Arena variant |
| **Splunk Attack Range** | Splunk + instrumented Windows targets for telemetry-focused purple teaming |
| **Elastic Container Project** | Elastic Stack + agents for Elastic-centric detection validation |
| **Atomic Red Team range** | `cyberbuff/ludus-atomic-red-team` — purpose-built range for running ART campaigns |

Deploy GOAD in Ludus:

<pre><code># Clone the GOAD repo and use the Ludus provisioner:
git clone https://github.com/Orange-Cyberdefense/GOAD
cd GOAD
./goad.sh -t install -l GOAD -p ludus

# GOAD's provisioner calls ludus range config set + ludus range deploy automatically
</code></pre>

## C2 Framework Integration

### Sliver

<pre><code>ludus ansible role add netpenguins.ludus_sliver

# Add to your range YAML:
- vm_name: "{{ range_id }}-sliver"
  template: ubuntu-22.04-x64-server-template
  vlan: 20
  ip_last_octet: 1
  linux: true
  roles: [ludus_sliver]
</code></pre>

### Mythic

<pre><code>ludus ansible role add geerlingguy.docker geerlingguy.pip gantsign.golang

# Enterprise subscription role (or community: haha150.ludus_mythic):
ludus subscription-roles install -n ludus_mythic

# Add to range YAML:
- vm_name: "{{ range_id }}-mythic"
  template: debian-12-x64-server-template
  vlan: 20
  ip_last_octet: 1
  linux: true
  roles: [ludus_mythic]
  role_vars:
    mythic_admin_user: opadmin
    mythic_admin_password: Ch@ngeMe!
    mythic_admin_port: 7443
    mythic_agents_config:
      - { name: apollo, repo: "https://github.com/MythicAgents/apollo", version: HEAD }
    mythic_c2_profiles:
      - { name: http, repo: "https://github.com/MythicC2Profiles/http", version: HEAD }
</code></pre>

### Elastic Stack

<pre><code>ludus ansible role add badsectorlabs.ludus_elastic_container
ludus ansible role add badsectorlabs.ludus_elastic_agent

# Add to range YAML — Elastic on a dedicated VM, agent on all Windows hosts:
- vm_name: "{{ range_id }}-elastic"
  template: ubuntu-22.04-x64-server-template
  vlan: 10
  ip_last_octet: 200
  linux: true
  roles: [ludus_elastic_container]

# Windows VMs: add ludus_elastic_agent to their roles list
</code></pre>

## CI/CD Integration

Ludus's testing mode is purpose-built for automated detonation pipelines:

<pre><code># Example GitLab CI / GitHub Actions pattern:
stages: [deploy-range, run-tests, verify-detections, teardown]

deploy-range:
  script:
    - ludus --url $LUDUS_URL --api-key $LUDUS_KEY range config set -f range.yml
    - ludus range deploy
    - ludus range status --json | jq '.success == true'

run-atomics:
  script:
    - ludus testing start
    - ssh kali "pwsh -c 'Invoke-AtomicTest T1003.001'"
    - sleep 30   # allow telemetry to propagate

verify-detections:
  script:
    - curl -s -k -u admin:changeme https://splunk.lab.internal:8000/services/search/jobs \
        -d "search=index=wineventlog EventCode=10 SourceImage=*lsass*" | jq '.results | length &gt; 0'

teardown:
  script:
    - ludus testing stop   # auto-reverts all VMs
  when: always
</code></pre>

CISA runs their fork (`github.com/cisagov/Ludus`) with a similar CI/CD pipeline for federal CCDC-style range automation.

## DetectionLab (Historical Reference)

Before Ludus, **DetectionLab** (Chris Long) was the standard "fully instrumented Windows lab" — 4 VMs with Splunk, Velociraptor, Zeek, Suricata, and Sysmon pre-configured on `windomain.local`. Still functional via Vagrant/VirtualBox, still an excellent reference for what a fully-instrumented Windows domain looks like.

**However:** DetectionLab has been unmaintained since January 2023. For new range builds in 2025, use Ludus with the Splunk Attack Range role or Elastic Container role — you get the same instrumentation with active maintenance, multi-user isolation, and the testing mode revert loop.

## Teardown

<pre><code># Destroy the entire range (irreversible):
ludus range rm

# Power off without destroying:
ludus range power-off

# Power back on:
ludus range power-on
</code></pre>

## Resources

- Ludus documentation — `docs.ludus.cloud`
- Ludus GitLab — `gitlab.com/badsectorlabs/ludus`
- Ludus GitHub mirror — `github.com/badsectorlabs/ludus`
- GOAD (Game of Active Directory) — `github.com/Orange-Cyberdefense/GOAD`
- Ludus ART range role — `github.com/cyberbuff/ludus-atomic-red-team`
- Ludus Sliver role — `github.com/NetPenguins/ludus_sliver`
- CISA Ludus fork — `github.com/cisagov/Ludus`
- Splunk Attack Range — `github.com/splunk/attack_range`
- DetectionLab (historical) — `github.com/clong/DetectionLab`
- Self-hosted tools overview — `tools/self-hosted-tools/`
