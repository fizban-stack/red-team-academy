---
layout: training-page
title: "Detection Lab Setup — Red Team Academy"
module: "Purple Team"
tags:
  - purple-team
  - elastic-stack
  - sysmon
  - detection-lab
  - velociraptor
  - winlogbeat
  - docker
page_key: "purple-team-detection-lab-setup"
render_with_liquid: false
---

<h1>Detection Lab Setup</h1>

<p>A self-hosted detection lab gives you a closed-loop environment where you can execute attack techniques and immediately validate whether your SIEM catches them. This page walks through building a complete purple team lab from hardware selection through log collection, SIEM deployment, and connecting your attack lab. The goal is a lab where you can fire a Cobalt Strike beacon or run an Atomic Red Team test and watch the alert appear in Kibana within seconds.</p>

<h2>Hardware and VM Requirements</h2>

<pre><code># Minimum specifications for a functional detection lab:
#
# HOST MACHINE (bare metal or Type-1 hypervisor)
# ----------------------------------------------
# RAM:    32 GB minimum (64 GB recommended for comfortable operation)
# CPU:    8 cores minimum (AMD Ryzen 9 / Intel i9 / Xeon recommended)
# Disk:   1 TB SSD minimum (NVMe preferred — Elasticsearch is I/O intensive)
# OS:     Proxmox VE, VMware ESXi, or Linux with KVM/libvirt
#
# VM ALLOCATION (baseline — 32 GB RAM host)
# ------------------------------------------
# SIEM VM (Elastic Stack):
#   RAM:  16 GB
#   CPU:  4 vCPUs
#   Disk: 300 GB (Elasticsearch index storage — grows with log volume)
#   OS:   Ubuntu 22.04 LTS
#
# Windows Domain Controller (for AD attack scenarios):
#   RAM:  4 GB
#   CPU:  2 vCPUs
#   Disk: 60 GB
#   OS:   Windows Server 2019/2022
#
# Windows Workstation (attack target):
#   RAM:  4 GB
#   CPU:  2 vCPUs
#   Disk: 60 GB
#   OS:   Windows 10/11 (21H2+)
#
# Kali Linux (attack platform):
#   RAM:  4 GB
#   CPU:  2 vCPUs
#   Disk: 80 GB
#   OS:   Kali Linux 2024.x
#
# Networking:
#   VLAN 10:  Management (host, SIEM) — 10.10.10.0/24
#   VLAN 20:  Lab targets (Windows VMs) — 10.10.20.0/24
#   VLAN 30:  Attack platform (Kali) — 10.10.30.0/24
#   All VLANs have IP connectivity for log forwarding to SIEM
#
# GOAD (Game of Active Directory) users:
#   - GOAD requires an additional 12-16 GB RAM for 3-5 DCs + workstations
#   - Recommend 64 GB host for GOAD + detection stack</code></pre>

<h2>Elastic Stack Deployment via Docker Compose</h2>

<p>The Elastic Stack (Elasticsearch + Kibana + Fleet) is the recommended SIEM for a detection lab. The Docker Compose setup below deploys a production-like single-node cluster suitable for lab use.</p>

<h3>Prerequisites</h3>

<pre><code># Install Docker and Docker Compose on Ubuntu 22.04
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Set vm.max_map_count — required for Elasticsearch
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p</code></pre>

<h3>docker-compose.yml</h3>

<pre><code># Save as /opt/elastic-lab/docker-compose.yml
version: '3.8'

services:
  setup:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.12.0
    user: "0"
    command: >
      bash -c '
        echo "Setting up passwords...";
        until curl -s --cacert config/certs/ca/ca.crt https://elasticsearch:9200 | grep -q "missing authentication"; do
          sleep 10;
        done;
        echo "Setting kibana_system password...";
        curl -s -X POST --cacert config/certs/ca/ca.crt -u "elastic:${ELASTIC_PASSWORD}" \
          -H "Content-Type: application/json" \
          https://elasticsearch:9200/_security/user/kibana_system/_password \
          -d "{\"password\":\"${KIBANA_PASSWORD}\"}";
        echo "All done!";
      '
    volumes:
      - certs:/usr/share/elasticsearch/config/certs
    depends_on:
      elasticsearch:
        condition: service_healthy

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.12.0
    container_name: elasticsearch
    environment:
      - node.name=elasticsearch
      - cluster.name=lab-cluster
      - discovery.type=single-node
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
      - bootstrap.memory_lock=true
      - xpack.security.enabled=true
      - xpack.security.http.ssl.enabled=true
      - xpack.security.http.ssl.key=certs/elasticsearch/elasticsearch.key
      - xpack.security.http.ssl.certificate=certs/elasticsearch/elasticsearch.crt
      - xpack.security.http.ssl.certificate_authorities=certs/ca/ca.crt
      - xpack.security.transport.ssl.enabled=true
      - xpack.security.transport.ssl.key=certs/elasticsearch/elasticsearch.key
      - xpack.security.transport.ssl.certificate=certs/elasticsearch/elasticsearch.crt
      - xpack.security.transport.ssl.certificate_authorities=certs/ca/ca.crt
      - xpack.security.transport.ssl.verification_mode=certificate
      - xpack.license.self_generated.type=basic
      - ES_JAVA_OPTS=-Xms8g -Xmx8g
    mem_limit: 12g
    ulimits:
      memlock:
        soft: -1
        hard: -1
    healthcheck:
      test: ["CMD-SHELL", "curl -s --cacert config/certs/ca/ca.crt https://localhost:9200 | grep -q 'missing authentication'"]
      interval: 10s
      timeout: 10s
      retries: 120
    volumes:
      - certs:/usr/share/elasticsearch/config/certs
      - esdata:/usr/share/elasticsearch/data
    ports:
      - 9200:9200
    networks:
      - elastic

  kibana:
    image: docker.elastic.co/kibana/kibana:8.12.0
    container_name: kibana
    environment:
      - SERVERNAME=kibana
      - ELASTICSEARCH_HOSTS=https://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=kibana_system
      - ELASTICSEARCH_PASSWORD=${KIBANA_PASSWORD}
      - ELASTICSEARCH_SSL_CERTIFICATEAUTHORITIES=config/certs/ca/ca.crt
      - XPACK_SECURITY_ENCRYPTIONKEY=${ENCRYPTION_KEY}
      - XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=${ENCRYPTION_KEY}
      - XPACK_REPORTING_ENCRYPTIONKEY=${ENCRYPTION_KEY}
    mem_limit: 2g
    healthcheck:
      test: ["CMD-SHELL", "curl -s -I http://localhost:5601 | grep -q 'HTTP/1.1 302 Found'"]
      interval: 10s
      timeout: 10s
      retries: 120
    volumes:
      - certs:/usr/share/kibana/config/certs
      - kibanadata:/usr/share/kibana/data
    ports:
      - 5601:5601
    networks:
      - elastic
    depends_on:
      elasticsearch:
        condition: service_healthy

  fleet-server:
    image: docker.elastic.co/beats/elastic-agent:8.12.0
    container_name: fleet-server
    user: root
    environment:
      - FLEET_ENROLL=1
      - FLEET_SERVER_ENABLE=1
      - FLEET_SERVER_ELASTICSEARCH_HOST=https://elasticsearch:9200
      - FLEET_SERVER_ELASTICSEARCH_CA=/certs/ca/ca.crt
      - FLEET_SERVER_SERVICE_TOKEN=${FLEET_SERVER_SERVICE_TOKEN}
      - FLEET_SERVER_POLICY_ID=fleet-server-policy
      - FLEET_URL=https://fleet-server:8220
    volumes:
      - certs:/certs
    ports:
      - 8220:8220
    networks:
      - elastic
    depends_on:
      kibana:
        condition: service_healthy

volumes:
  certs:
  esdata:
  kibanadata:

networks:
  elastic:
    driver: bridge

# .env file — create alongside docker-compose.yml
# ELASTIC_PASSWORD=ChangeMe123!
# KIBANA_PASSWORD=ChangeMe456!
# ENCRYPTION_KEY=a_32_character_encryption_key_here</code></pre>

<h3>Starting the Stack</h3>

<pre><code"># Start the stack
cd /opt/elastic-lab
docker compose up -d

# Watch startup logs
docker compose logs -f

# Verify Elasticsearch is healthy
curl -s --cacert /opt/elastic-lab/certs/ca.crt \
  -u elastic:ChangeMe123! \
  https://localhost:9200/_cluster/health | python3 -m json.tool

# Access Kibana
# http://localhost:5601
# Username: elastic
# Password: ChangeMe123!</code></pre>

<h2>Winlogbeat Configuration for Windows Event Forwarding</h2>

<p>Winlogbeat ships Windows Event Log data to Elasticsearch. Deploy it on each Windows target in the lab.</p>

<pre><code># winlogbeat.yml — deploy to C:\Program Files\Winlogbeat\winlogbeat.yml
# on Windows target systems

winlogbeat.event_logs:
  # Security log — authentication, privilege use, object access
  - name: Security
    event_id: 4624, 4625, 4648, 4656, 4662, 4663, 4672, 4688, 4697,
              4698, 4702, 4720, 4726, 4732, 4756, 1102
    ignore_older: 72h
    processors:
      - add_fields:
          target: winlog
          fields:
            category: security

  # System log — service installs (7045), boot events
  - name: System
    event_id: 7045, 7034, 7035, 7036, 104
    ignore_older: 72h

  # PowerShell operational — script block logging
  - name: Microsoft-Windows-PowerShell/Operational
    event_id: 4103, 4104, 4105, 4106
    ignore_older: 72h

  # Windows Defender
  - name: Microsoft-Windows-Windows Defender/Operational
    event_id: 1116, 1117, 1006, 1007
    ignore_older: 72h

  # Sysmon operational — process creation, network, registry, etc.
  - name: Microsoft-Windows-Sysmon/Operational
    ignore_older: 72h

  # Task Scheduler — scheduled task operations
  - name: Microsoft-Windows-TaskScheduler/Operational
    event_id: 106, 140, 141, 200, 201
    ignore_older: 72h

  # WMI activity
  - name: Microsoft-Windows-WMI-Activity/Operational
    event_id: 5857, 5858, 5860, 5861
    ignore_older: 72h

output.elasticsearch:
  hosts: ["https://10.10.10.10:9200"]
  username: "winlogbeat_writer"
  password: "${WINLOGBEAT_PASSWORD}"
  ssl.certificate_authorities:
    - "C:/Program Files/Winlogbeat/ca.crt"
  index: "winlogbeat-%{+yyyy.MM.dd}"

setup.kibana:
  host: "https://10.10.10.10:5601"
  username: "elastic"
  password: "${ELASTIC_PASSWORD}"
  ssl.certificate_authorities:
    - "C:/Program Files/Winlogbeat/ca.crt"

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_fields:
      target: lab
      fields:
        environment: purple-team-lab

logging.level: info
logging.to_files: true
logging.files:
  path: C:/ProgramData/winlogbeat/logs</code></pre>

<pre><code"># Install and start Winlogbeat on Windows (PowerShell as Admin)
# Download from: https://www.elastic.co/downloads/beats/winlogbeat

cd "C:\Program Files\Winlogbeat"

# Copy ca.crt from Elastic Stack
# Copy winlogbeat.yml (configured above)

# Test configuration
.\winlogbeat.exe test config -c winlogbeat.yml

# Install as Windows service
.\install-service-winlogbeat.ps1

# Start the service
Start-Service winlogbeat

# Check logs
Get-Content "C:\ProgramData\winlogbeat\logs\winlogbeat" -Tail 50</code></pre>

<h2>Sysmon Deployment with SwiftOnSecurity Config</h2>

<pre><code># Download Sysmon from Sysinternals
# https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

# Download SwiftOnSecurity Sysmon config (widely used baseline)
# https://github.com/SwiftOnSecurity/sysmon-config

# Install Sysmon with config (PowerShell as Admin)
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive Sysmon.zip -DestinationPath C:\Tools\Sysmon

Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
  -OutFile "C:\Tools\Sysmon\sysmonconfig.xml"

# Install
cd C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml

# Verify installation
Get-Service Sysmon64

# Update config after modifications
.\Sysmon64.exe -c sysmonconfig.xml

# Check Sysmon event log
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20 | Format-List

# Sysmon key event IDs generated:
# ID  1  — Process creation (includes hash, parent, command line)
# ID  2  — File creation time changed
# ID  3  — Network connection
# ID  5  — Process terminated
# ID  7  — Image (DLL) loaded
# ID  8  — CreateRemoteThread (process injection indicator)
# ID  10 — Process accessed (LSASS reads go here)
# ID  11 — File created
# ID  12 — Registry key created or deleted
# ID  13 — Registry value set
# ID  17 — Pipe created
# ID  18 — Pipe connected
# ID  22 — DNS query
# ID  23 — File delete
# ID  25 — Process tampering (hollowing, herpaderping)</code></pre>

<h2>Velociraptor for Artifact Collection</h2>

<pre><code># Velociraptor — live endpoint forensics and artifact collection
# https://github.com/Velocidex/velociraptor

# --- SERVER SETUP (on SIEM VM or dedicated Ubuntu VM) ---

# Download latest release
VR_VERSION="0.72.3"
wget "https://github.com/Velocidex/velociraptor/releases/download/v${VR_VERSION}/velociraptor-v${VR_VERSION}-linux-amd64"
chmod +x velociraptor-v${VR_VERSION}-linux-amd64
sudo mv velociraptor-v${VR_VERSION}-linux-amd64 /usr/local/bin/velociraptor

# Generate server config
velociraptor config generate -i > /etc/velociraptor/server.config.yaml

# Key config fields to set during generation:
# - Public DNS name: IP/hostname of the server (e.g., 10.10.10.10)
# - Frontend port: 8000
# - GUI port: 8889
# - Datastore directory: /var/lib/velociraptor/

# Create admin user
velociraptor --config /etc/velociraptor/server.config.yaml \
  user add admin --role administrator

# Run as systemd service
cat > /etc/systemd/system/velociraptor.service << 'EOF'
[Unit]
Description=Velociraptor Server
After=network.target

[Service]
ExecStart=/usr/local/bin/velociraptor --config /etc/velociraptor/server.config.yaml frontend
Restart=always
User=velociraptor

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now velociraptor

# Access GUI: https://10.10.10.10:8889

# --- CLIENT SETUP (on Windows targets) ---
# Generate client MSI from server
# In Velociraptor GUI: Server Artifacts → Server.Utils.CreateMSI
# Deploy MSI to Windows targets via GPO or manual install

# Velociraptor use in purple team exercises:
# - Hunt for process artifacts after attack execution
# - Collect memory artifacts (prefetch, shimcache, amcache)
# - Run VQL (Velociraptor Query Language) hunts across all endpoints
# - Example: find all processes that accessed lsass.exe in last hour</code></pre>

<h2>Attack Simulation with Atomic Red Team</h2>

<pre><code"># Atomic Red Team — attack simulation for purple team exercises
# Invoke-AtomicRedTeam PowerShell module

# Install on Windows attack VM or test target (PowerShell as Admin)
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force

# Import the module
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"

# List all available tests for a technique
Invoke-AtomicTest T1003.001 -ShowDetailsBrief

# Execute test 1 for LSASS credential dumping
Invoke-AtomicTest T1003.001 -TestNumbers 1

# Get prerequisites before running (installs dependencies)
Invoke-AtomicTest T1059.001 -GetPrereqs

# Execute and clean up
Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup

# Log execution to CSV for tracking
Invoke-AtomicTest T1059.001 -LoggingModule "Attire-ExecutionLogger" -ExecutionLogPath "C:\ART-results\log.csv"

# Purple team workflow with ART:
# 1. Decide on technique list for the exercise
# 2. Red team operator executes: Invoke-AtomicTest T1055.001 -TestNumbers 1
# 3. Notes exact time of execution, test number, system
# 4. Blue team analyst queries SIEM for that time window
# 5. Both teams review what was caught and what was missed</code></pre>

<h2>Wazuh as a Lightweight Alternative</h2>

<p>For labs with limited resources (less than 32 GB RAM), Wazuh is an excellent open-source SIEM alternative that consumes significantly less memory than Elastic Stack while still providing Windows event collection, Sysmon support, and detection rules.</p>

<pre><code># Wazuh all-in-one installation (requires 4-8 GB RAM for lab use)
# https://documentation.wazuh.com/current/deployment-options/

# Quick install with Wazuh install assistant (Ubuntu 22.04)
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml

# Edit config.yml with your node names and IPs
nano config.yml

# Run the assistant
sudo bash wazuh-install.sh -a

# Access: https://localhost:443
# Default credentials displayed at end of installation

# Wazuh Windows agent deployment
# Download MSI from: https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.3-1.msi
# Install with manager IP:
msiexec.exe /i wazuh-agent-4.7.3-1.msi /q WAZUH_MANAGER="10.10.10.10" WAZUH_REGISTRATION_PASSWORD="your_password"

# Start agent
net start WazuhSvc

# Wazuh Sysmon integration
# Add to /var/ossec/etc/ossec.conf on Wazuh manager:
# <localfile>
#   <location>Microsoft-Windows-Sysmon/Operational</location>
#   <log_format>eventchannel</log_format>
# </localfile>

# Wazuh vs Elastic comparison for lab use:
# Wazuh:  4-8 GB RAM, simpler setup, good for learning
# Elastic: 16+ GB RAM, more powerful queries, better visualization
# Both support Sigma rule conversion and ATT&CK mapping</code></pre>

<h2>Connecting Your Red Team Lab to the Detection Lab</h2>

<pre><code># Network topology for connected attack + detection lab:
#
#  [Kali / Attack VM] ─────────────────────────────────────────────┐
#       10.10.30.5                                                  │
#                                                                   ▼
#  [SIEM VM: Elasticsearch/Kibana] ◄── Winlogbeat ── [Windows VMs (targets)]
#       10.10.10.10                                      10.10.20.10
#                                                        10.10.20.11
#                                  ◄── Velociraptor client
#
# GOAD integration (Game of Active Directory):
# If using GOAD for a realistic AD environment:
# git clone https://github.com/Orange-Cyberdefense/GOAD.git
# cd GOAD
# # Follow provider-specific setup (Virtualbox/VMware/Proxmox)
# python3 goad.py -t install -l GOAD -p vmware
#
# GOAD creates a 5-VM AD environment:
# - NORTH (DC01) — 192.168.56.10
# - SOUTH (DC02) — 192.168.56.11
# - ESSOS (DC03) — 192.168.56.12
# - MEEREEN (SRV02) — 192.168.56.22
# - BRAAVOS (SRV03) — 192.168.56.23
#
# Deploy Winlogbeat and Sysmon to all GOAD VMs
# Point output to your SIEM VM
# Now attack GOAD with Impacket/BloodHound/CrackMapExec
# and watch detections fire in Kibana</code></pre>

<h2>Resources</h2>

<ul>
  <li>Elastic Stack Docker Documentation — <code>elastic.co/guide/en/elasticsearch/reference/current/docker.html</code></li>
  <li>Sysmon — <code>learn.microsoft.com/en-us/sysinternals/downloads/sysmon</code></li>
  <li>SwiftOnSecurity Sysmon Config — <code>github.com/SwiftOnSecurity/sysmon-config</code></li>
  <li>sysmon-modular (Olaf Hartong) — <code>github.com/olafhartong/sysmon-modular</code></li>
  <li>Velociraptor — <code>github.com/Velocidex/velociraptor</code></li>
  <li>Atomic Red Team — <code>github.com/redcanaryco/atomic-red-team</code></li>
  <li>Wazuh — <code>wazuh.com</code></li>
  <li>GOAD (Game of Active Directory) — <code>github.com/Orange-Cyberdefense/GOAD</code></li>
</ul>
