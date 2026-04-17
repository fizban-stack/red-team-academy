---
layout: training-page
title: "Burp Suite Bambdas — Custom Scripts — Red Team Academy"
module: "Web Hacking"
tags:
  - burp-suite
  - bambdas
  - web-testing
  - automation
  - java
page_key: "web-burp-bambdas"
render_with_liquid: false
---

# Burp Suite Bambdas

Bambdas are single-function Java lambdas that run inside Burp Suite (2023.10+). They let you write custom logic for filtering proxy history, adding custom columns to the HTTP history table, creating custom scan checks, and building automated custom actions in Repeater. Bambdas replaced the older Burp Extensions for many lightweight filtering/column tasks — they require no IDE, no compiled JAR, and run directly in the Burp UI.

## Bambda Types and Locations

```
# Where Bambdas are used:
# 1. Proxy → HTTP History → Filter bar → "Filter by Bambda"
# 2. Proxy → HTTP History → Columns → "Add custom column"
# 3. Scanner → Custom scan checks (active/passive)
# 4. Repeater → Custom Actions

# Language: Java lambda syntax
# Full Burp Montoya API access (requestResponse, request, response, utilities, etc.)
# Return types depend on context:
# - Filter bambdas: return boolean (true = show, false = hide)
# - Column bambdas: return String (displayed in column)
# - Scan check bambdas: return AuditResult
# - Action bambdas: void (perform action on request)
```

## Proxy Filter Bambdas

Filter bambdas return a boolean. The item is shown in history when the bambda returns `true`.

```
// Show only requests with specific parameter names:
// Filter to find all requests containing a "url" parameter (SSRF hunting)
requestResponse.request().parameters().stream()
  .anyMatch(p -> p.name().equalsIgnoreCase("url") ||
                 p.name().equalsIgnoreCase("redirect") ||
                 p.name().equalsIgnoreCase("next") ||
                 p.name().equalsIgnoreCase("path"))

// Show only requests where response contains interesting strings:
requestResponse.hasResponse() &&
requestResponse.response().body().toString().contains("password")

// Filter to 4xx and 5xx responses only:
requestResponse.hasResponse() &&
requestResponse.response().statusCode() >= 400

// Show only in-scope items with a specific response header:
requestResponse.hasResponse() &&
requestResponse.request().isInScope() &&
requestResponse.response().headers().stream()
  .anyMatch(h -> h.name().equalsIgnoreCase("X-Debug-Token"))

// Find requests where response body is larger than the request body
// (useful for finding data exfil points or verbose error responses):
requestResponse.hasResponse() &&
requestResponse.response().body().length() > 10000 &&
requestResponse.response().statusCode() == 200
```

## Bypass First Request Validation

Sends an innocent GET / before the actual attack request on the same connection — useful for bypassing server-level first-request validation logic.

```
// Author: James Kettle (albinowax)
// Use in Repeater as a Custom Action bambda
var connectionId = utilities().randomUtils().randomString(8);
var options = RequestOptions.requestOptions()
  .withConnectionId(connectionId)
  .withHttpMode(HttpMode.HTTP_1);

// Send innocent GET / on the same connection first:
var url = requestResponse.request().url();
var precursorRequest = HttpRequest.httpRequestFromUrl(url);
precursorRequest = precursorRequest
  .withPath("/")
  .withHeader("Connection", "keep-alive");

api().http().sendRequest(precursorRequest, options);

// Then send the actual attack request and update the response pane:
var response = api().http().sendRequest(requestResponse.request(), options);
httpEditor.responsePane().set(response.response().toByteArray());
```

## Custom Scan Check Bambdas

Custom scan checks run during active or passive scanning and can raise custom audit issues.

### CORS Misconfiguration Detector

```
// Active scan check — detects arbitrary origin reflection
// Returns HIGH if ACAO reflects arbitrary origin with ACAC: true
if (!requestResponse.hasResponse()) { return null; }

var evilHttps = "https://" + api().utilities().randomUtils().randomString(6)
              + "." + api().utilities().randomUtils().randomString(3);
var evilHttp  = "http://"  + api().utilities().randomUtils().randomString(6)
              + "." + api().utilities().randomUtils().randomString(3);

for (var origin : new String[]{evilHttps, evilHttp}) {
  var rr = http.sendRequest(requestResponse.request().withAddedHeader("Origin", origin));
  if (!rr.hasResponse()) continue;

  var headers = rr.response().headers().toString().toLowerCase();
  var creds   = headers.contains("access-control-allow-credentials: true");
  var reflect = headers.contains("access-control-allow-origin: " + origin.toLowerCase());
  var vary    = headers.contains("vary: origin");

  if (reflect) {
    var severity = creds ? AuditIssueSeverity.HIGH : AuditIssueSeverity.MEDIUM;
    var note     = vary ? "" : " (missing Vary: Origin)";
    return AuditResult.auditResult(
      AuditIssue.auditIssue(
        "CORS: arbitrary origin reflection" + note,
        "Reflected Origin: " + origin + "; credentials=" + creds,
        "Use strict allowlist; include Vary: Origin.",
        rr.request().url(), severity, AuditIssueConfidence.FIRM,
        "", "", severity, rr
      )
    );
  }
}
return AuditResult.auditResult();
```

### SSTI Sampler

Active scan check. Injects math probes for the most common template engines and flags responses
that echo back the evaluated result (`49` = 7×7).

```java
// SSTI active scan check — injects math probes across template engine syntaxes
// Detects: Jinja2, Twig, Mako, Smarty, FreeMarker, Velocity, ERB, Pebble
List<String> probes = List.of(
  "{{7*7}}",         // Jinja2 / Twig
  "${7*7}",          // FreeMarker / Spring EL
  "#{7*7}",          // Pebble / Thymeleaf
  "<%= 7*7 %>",      // ERB (Ruby)
  "${{7*7}}",        // Twig (alternate)
  "*{7*7}",          // Spring EL (alternate)
  "{{7*'7'}}",       // Jinja2 string multiply → 7777777
  "{% 7*7 %}"       // Twig block syntax
);

String marker = "49";   // expected evaluated result for 7*7
String markerAlt = "7777777";  // Jinja2 string multiply result

for (String probe : probes) {
  var req = requestResponse.request();
  // Inject probe into every parameter value
  var modifiedReq = req;
  for (var param : req.parameters()) {
    modifiedReq = modifiedReq.withUpdatedParameters(
      HttpParameter.parameter(param.name(), probe, param.type())
    );
  }
  var result = http.sendRequest(modifiedReq);
  if (!result.hasResponse()) continue;
  String body = result.response().bodyToString();
  if (body.contains(marker) || body.contains(markerAlt)) {
    return AuditResult.auditResult(
      AuditIssue.auditIssue(
        "Server-Side Template Injection (SSTI)",
        "The response evaluated the expression `" + probe + "` and returned `" +
          (body.contains(marker) ? marker : markerAlt) + "`. " +
          "SSTI allows arbitrary code execution on the server.",
        "Do not render user input inside template expressions. " +
          "Use a sandboxed template context or treat user data as plain text.",
        req.url(),
        AuditIssueSeverity.HIGH,
        AuditIssueConfidence.FIRM,
        "", "", AuditIssueSeverity.HIGH, result
      )
    );
  }
}
return AuditResult.auditResult();
```

### Missing CSP Header (Passive)

```
// Passive scan check — flag responses missing Content-Security-Policy header
if (!requestResponse.hasResponse()) { return null; }

var hasCSP = requestResponse.response().headers().stream()
  .anyMatch(h -> h.name().equalsIgnoreCase("Content-Security-Policy"));

if (!hasCSP && requestResponse.response().mimeType() == MimeType.HTML) {
  return AuditResult.auditResult(
    AuditIssue.auditIssue(
      "Missing Content-Security-Policy header",
      "No CSP header found on HTML response.",
      "Add a Content-Security-Policy header to restrict script sources.",
      requestResponse.request().url(),
      AuditIssueSeverity.LOW,
      AuditIssueConfidence.CERTAIN,
      "", "", AuditIssueSeverity.LOW, requestResponse
    )
  );
}
return AuditResult.auditResult();
```

## Custom Action Bambdas (Repeater)

```
// Retry request without cookies — useful for testing auth bypass:
// Add as Repeater → Extensions → Custom Actions
var requestWithoutCookies = requestResponse.request().withRemovedHeader("Cookie");
var response = api().http().sendRequest(requestWithoutCookies);
httpEditor.responsePane().set(response.response().toByteArray());

// Retry until a success condition is met (race conditions):
for (int i = 0; i < 10; i++) {
  var rr = api().http().sendRequest(requestResponse.request());
  if (rr.hasResponse() && rr.response().statusCode() == 200) {
    httpEditor.responsePane().set(rr.response().toByteArray());
    break;
  }
}

// Probe for race condition — send 20 requests in rapid succession:
var requests = new java.util.ArrayList<HttpRequest>();
for (int i = 0; i < 20; i++) {
  requests.add(requestResponse.request());
}
// Use Burp's parallel send capability for last-byte sync technique
```

## Custom Column Bambdas

```
// Add a column showing response time (milliseconds):
// Returns String for display in proxy history column
if (!requestResponse.hasResponse()) return "";
var ms = requestResponse.timingData()
  .map(t -> t.timeBetweenRequestSentAndResponseComplete().toMillis())
  .map(Object::toString)
  .orElse("");
return ms + "ms";

// Column showing JWT presence:
var authHeader = requestResponse.request().headers().stream()
  .filter(h -> h.name().equalsIgnoreCase("Authorization"))
  .findFirst();
if (authHeader.isEmpty()) return "";
var val = authHeader.get().value();
return val.startsWith("Bearer ey") ? "JWT" : val.substring(0, Math.min(val.length(), 15));

// Column for response content type:
if (!requestResponse.hasResponse()) return "";
return requestResponse.response().headers().stream()
  .filter(h -> h.name().equalsIgnoreCase("Content-Type"))
  .map(h -> h.value().split(";")[0])
  .findFirst().orElse("");
```

## Workflow: Bug Hunting with Bambdas

```
# Typical bambda-assisted bug hunting session:

# 1. Spider / browse target normally with Proxy recording everything

# 2. Apply filter bambda to find SSRF candidates:
# Show requests where any parameter name suggests URL redirect
# requestResponse.request().parameters().stream()
#   .anyMatch(p -> List.of("url","next","redirect","dest","target","path","return","callback")
#   .contains(p.name().toLowerCase()))

# 3. Add custom column to show parameter count:
# requestResponse.request().parameters().size() + ""

# 4. Run SSTI sampler scan check on all text input fields

# 5. Run CORS check on all authenticated API endpoints

# 6. Use "Bypass First Request Validation" action on requests that return 403

# Repository of ready-to-use bambdas:
# github.com/PortSwigger/bambdas
```

## Resources

- PortSwigger Bambdas repo — `github.com/PortSwigger/bambdas`
- Burp Montoya API docs — `portswigger.net/burp/extender/api/`
- Bambda documentation — `portswigger.net/burp/documentation/desktop/tools/proxy/http-history/bambdas`
- Custom scan checks with Bambdas — `portswigger.net/burp/documentation/desktop/scanning/custom-scan-checks`
