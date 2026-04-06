---
layout: training-page
title: "BloodHound / SharpHound — Red Team Academy"
module: "Active Directory"
tags:
  - bloodhound
  - sharphound
  - attack-paths
  - neo4j
page_key: "ad-bloodhound"
render_with_liquid: false
---

# BloodHound / SharpHound

## What BloodHound Does

BloodHound maps Active Directory into a graph database and finds attack paths that would take a human analyst days to discover manually. It shows relationships between users, groups, computers, GPOs, and OUs — and highlights the shortest path from any owned node to Domain Admin. It doesn't just tell you *who* is in DA; it shows you the chain of permissions and trusts that gets you there from where you are.

![BloodHound attack path: owned user MemberOf group, group AdminTo workstation, workstation HasSession with DA, steal token](/images/active-directory/bloodhound-path.svg)  
*// bloodhound attack path — chaining relationships to Domain Admin*

## BloodHound CE Setup

BloodHound Community Edition (CE) is the current maintained version from SpecterOps. It runs as a web application backed by Neo4j and PostgreSQL, easiest deployed via Docker Compose.

```
# Install Docker and Docker Compose:
sudo apt install docker.io docker-compose-v2

# Download BloodHound CE docker-compose file:
curl -L https://ghst.ly/getbhce -o docker-compose.yml
# Or directly from SpecterOps:
# https://github.com/SpecterOps/BloodHound/blob/main/examples/docker-compose/docker-compose.yml

# Start BloodHound CE:
sudo docker compose up -d

# Default URL: http://localhost:8080
# Default credentials: admin / (random password printed in logs on first run)

# View initial password:
sudo docker compose logs | grep "Initial Password Set To:"

# Change password on first login (forced)
# Then upload SharpHound/BloodHound-Python JSON files via the web UI
```

## Legacy BloodHound (4.x) Setup

```
# Legacy BloodHound uses Neo4j graph database + Electron app:
# Install Neo4j:
sudo apt install neo4j
sudo neo4j start
# Default Neo4j: http://localhost:7474
# Default creds: neo4j / neo4j — change on first login

# Download BloodHound GUI:
# https://github.com/BloodHoundAD/BloodHound/releases
# Run the AppImage:
chmod +x BloodHound-linux-x64
./BloodHound-linux-x64 --no-sandbox

# Connect BloodHound GUI to Neo4j (bolt://localhost:7687)
# Database: neo4j, Password: (what you set)
```

## SharpHound — Windows Collection

SharpHound is the C# data collector for BloodHound. Run it from a domain-joined Windows machine (or via evil-winrm/psexec session). It queries AD via LDAP and SMB to map every relationship.

```
# Download SharpHound:
# https://github.com/BloodHoundAD/SharpHound/releases

# Full collection (recommended — all methods):
SharpHound.exe -c All --outputdirectory C:\Windows\Temp\bh\

# Specific collection methods:
SharpHound.exe -c Default           # Users, groups, computers, GPOs, trusts
SharpHound.exe -c DCOnly            # Only DC queries — fast, minimal noise
SharpHound.exe -c All,GPOLocalGroup # All + GPO-derived local group membership
SharpHound.exe -c Session           # Active sessions — where users are logged in
SharpHound.exe -c LoggedOn          # Who's logged on (requires admin on targets)
SharpHound.exe -c ACL               # ACL/ACE relationships
SharpHound.exe -c Trusts            # Domain trust relationships

# Run as different domain user:
SharpHound.exe -c All --ldapusername 'jon.snow' --ldappassword 'iknownothing'

# Target specific domain:
SharpHound.exe -c All --domain 'north.sevenkingdoms.local'

# Stealth options — avoid logging excessive sessions:
SharpHound.exe -c DCOnly --stealth    # Query only DCs, skip computer sessions

# Output: ZIP file containing multiple JSON files
# Transfer back to Kali and upload to BloodHound UI
```

## BloodHound-Python — Linux Collection (No Windows Needed)

```
# Install (BloodHound CE — use bloodhound-ce-python):
pip3 install bloodhound-ce
# or (Kali):
sudo apt install bloodhound-ce-python

# Note: 'pip3 install bloodhound' installs the LEGACY version (for BH 4.x only)

# Basic collection — all methods (CE):
bloodhound-ce-python \
  -d 'north.sevenkingdoms.local' \
  -u 'hodor' \
  -p 'hodor' \
  -ns 192.168.56.10 \
  -c All \
  --zip

# With hash (Pass-the-Hash):
bloodhound-ce-python \
  -d 'north.sevenkingdoms.local' \
  -u 'administrator' \
  --hashes 'aad3b435b51404eeaad3b435b51404ee:NTLM_HASH' \
  -ns 192.168.56.10 \
  -c All \
  --zip

# Stealth — DC only (no lateral host queries):
bloodhound-ce-python -d 'sevenkingdoms.local' \
  -u 'hodor@north.sevenkingdoms.local' \
  -p 'hodor' \
  -ns 192.168.56.11 \
  -c DCOnly \
  --zip

# Upload ZIP to BloodHound CE web UI:
# http://localhost:8080 → File Ingest → drag ZIP file
```

## Using BloodHound — Key Analysis Queries

BloodHound CE has pre-built queries under the "Analysis" tab. These are the most useful for red teams:

### Pre-Built Queries

```
># In BloodHound CE web UI — Analysis tab:

# "Find Shortest Paths to Domain Admins"
# Shows all attack paths from any node to Domain Admins group
# → Start here after collection

# "Find Principals with DCSync Rights"
# Users/computers with Replicating Directory Changes permissions
# → These accounts can perform DCSync

# "Find All Paths from Domain Users to High Value Targets"
# Broadest attack surface view

# "Find Computers Where Domain Admins Are Logged In"
# DA active sessions — high value for credential harvesting

# "Find Shortest Path from Owned Principals"
# After marking owned nodes — shows your specific attack path

# "Find All Kerberoastable Users"
# SPNs set on users — cross-reference with your kerberoast results

# "Find AS-REP Roastable Users"
# Pre-auth disabled users

# "Find Users with Foreign Domain Group Membership"
# Cross-forest attack surface
```

### Marking Owned Nodes

```
# Right-click any node → "Mark as Owned"
# Mark every account/computer you have credentials or shells for

# After marking owned nodes:
# Analysis → "Find Shortest Path from Owned Principals to Domain Admins"
# BloodHound draws the exact path from YOUR owned nodes to DA

# Color coding:
# Orange ring = owned
# Red fill = high value target (Domain Admins, DCs)
# The edges (arrows) show the relationship type:
# MemberOf, AdminTo, HasSession, GenericAll, GenericWrite,
# ForceChangePassword, AddMember, WriteDACL, etc.
```

### Key Cypher Queries

```
# Run custom Cypher in BloodHound CE: Analysis → Custom Query

# Find all users with local admin on any computer:
MATCH (u:User)-[:AdminTo]->(c:Computer) RETURN u.name,c.name

# Find all Kerberoastable users with a path to DA:
MATCH (u:User {hasspn:true})-[r:MemberOf|AdminTo*1..5]->(g:Group {name:"DOMAIN ADMINS@NORTH.SEVENKINGDOMS.LOCAL"})
RETURN u.name

# Find computers with unconstrained delegation:
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name

# Find all groups with GenericAll on other groups:
MATCH p=(g1:Group)-[:GenericAll]->(g2:Group) RETURN p

# Find path from specific user to DA:
MATCH p=shortestPath((u:User {name:"HODOR@NORTH.SEVENKINGDOMS.LOCAL"})-[*1..]->(g:Group {name:"DOMAIN ADMINS@NORTH.SEVENKINGDOMS.LOCAL"}))
RETURN p

# Find ACL edges pointing to DA members:
MATCH (n)-[r:GenericAll|GenericWrite|WriteDacl|ForceChangePassword]->(u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@NORTH.SEVENKINGDOMS.LOCAL"})
RETURN n.name,type(r),u.name
```

## BloodHound Attack Path Workflow

1. Run BloodHound-Python from Kali with any domain credentials
2. Upload generated JSON files to BloodHound CE
3. Run "Find Shortest Paths to Domain Admins" — study all paths
4. Mark every node you currently own (right-click → Mark Owned)
5. Run "Find Shortest Path from Owned Principals" — this is YOUR path
6. Follow the edge labels to understand what attack each step requires
7. Execute each step, mark new nodes owned, repeat

## Key Resources

- `https://github.com/SpecterOps/BloodHound` — BloodHound CE repository
- `https://github.com/BloodHoundAD/SharpHound` — SharpHound collector
- `https://github.com/fox-it/BloodHound.py` — BloodHound-Python
- `https://support.bloodhoundenterprise.io/hc/en-us/articles/17481394564251` — CE installation guide
- `https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/` — Cypher query cheatsheet
