---
title: "SAML 2.0 Explained: How Enterprise SSO Actually Works"
description: "SAML 2.0 powers enterprise single sign-on across thousands of organisations. Learn how assertions work, the difference between SP-initiated and IdP-initiated flows, attribute mapping, and how SAML compares to OIDC."
pubDate: 2026-06-03
author: "Khashayar Parhami"
tags: ["security", "guide", "identity"]
image: "/images/og/saml-explained.png"
featured: false
---

SAML 2.0 is the protocol behind "Sign in with your company account" buttons in enterprise software. It predates OAuth and OIDC by years, yet it remains the dominant SSO standard in corporate environments — embedded in Okta, Azure AD, ADFS, PingFederate, and every major enterprise identity provider. If you're building software that enterprise customers need to integrate with their IT infrastructure, you'll encounter SAML.

This guide explains how it actually works — not the 300-page spec, but the concepts and flows you need to build and debug integrations.

## The Core Idea

SAML stands for Security Assertion Markup Language. The core idea is simple: a trusted third party (the **Identity Provider**) vouches for a user's identity to another system (the **Service Provider**), and communicates that identity via a signed XML document called an **assertion**.

The three participants:

- **Identity Provider (IdP)** — authenticates the user and issues assertions. Examples: Okta, Azure AD, Google Workspace, ADFS, OneLogin.
- **Service Provider (SP)** — the application the user wants to access. Examples: Salesforce, GitHub Enterprise, your SaaS product.
- **Principal** — the user.

The IdP and SP never share credentials. The SP trusts the IdP's assertions because they're cryptographically signed with a certificate the SP already knows about.

## SAML Assertions

A SAML assertion is an XML document signed by the IdP's private key. It contains three types of statements:

**Authentication statement** — confirms that the IdP authenticated the user, when, and how.

**Attribute statement** — carries user attributes (email, name, groups, department) that the SP can use.

**Authorisation decision statement** — less common, states whether a user is permitted to access a specific resource.

A simplified assertion looks like this:

```xml
<saml:Assertion
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_abc123"
  IssueInstant="2026-06-03T09:00:00Z"
  Version="2.0">

  <saml:Issuer>https://idp.example.com</saml:Issuer>

  <ds:Signature><!-- RSA-SHA256 signature over this document --></ds:Signature>

  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
      alice@example.com
    </saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData
        InResponseTo="_req_xyz"
        Recipient="https://app.example.com/saml/acs"
        NotOnOrAfter="2026-06-03T09:05:00Z" />
    </saml:SubjectConfirmation>
  </saml:Subject>

  <saml:Conditions
    NotBefore="2026-06-03T08:59:30Z"
    NotOnOrAfter="2026-06-03T09:05:00Z">
    <saml:AudienceRestriction>
      <saml:Audience>https://app.example.com</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>

  <saml:AttributeStatement>
    <saml:Attribute Name="email">
      <saml:AttributeValue>alice@example.com</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="groups">
      <saml:AttributeValue>engineering</saml:AttributeValue>
      <saml:AttributeValue>admins</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>

</saml:Assertion>
```

Key fields to understand:

| Field | Purpose |
|---|---|
| `Issuer` | The IdP's identifier — must match what the SP has configured |
| `NameID` | The user identifier passed to the SP |
| `InResponseTo` | Ties the assertion to a specific authentication request (replay protection) |
| `Recipient` | The SP's Assertion Consumer Service URL — must match exactly |
| `NotOnOrAfter` | Expiry — the assertion is invalid after this time |
| `Audience` | The SP's entity ID — assertion is only valid for this SP |
| `Signature` | RSA or EC signature over the assertion using the IdP's private key |

## SP-Initiated Flow

This is the most common flow — the user starts at the service provider (your application).

```
1. User visits https://app.example.com and clicks "Sign in with SSO"

2. SP generates an AuthnRequest and redirects user to IdP:
   GET https://idp.example.com/sso?SAMLRequest=<base64-encoded-xml>&RelayState=<return-url>

3. IdP authenticates the user (password, MFA, existing session)

4. IdP generates a signed Assertion, wraps it in a SAMLResponse,
   and POST it to the SP's Assertion Consumer Service (ACS):
   POST https://app.example.com/saml/acs
   Body: SAMLResponse=<base64-encoded-xml>&RelayState=<return-url>

5. SP validates the SAMLResponse:
   - Verify XML signature against IdP's certificate
   - Check Issuer matches configured IdP
   - Check Audience matches SP's entity ID
   - Check NotOnOrAfter has not passed
   - Check InResponseTo matches the AuthnRequest ID
   - Check Recipient matches the ACS URL

6. SP extracts NameID and attributes, creates a local session
7. SP redirects user to RelayState (original destination)
```

The `RelayState` parameter carries the URL the user was trying to reach — so after authentication they land back where they started, not on a generic dashboard.

## IdP-Initiated Flow

In IdP-initiated flow, the user starts at the identity provider's portal — typically a dashboard showing all their connected apps.

```
1. User logs into https://idp.example.com and clicks the app tile

2. IdP generates a signed SAMLResponse (no AuthnRequest)
   and POST it directly to the SP's ACS URL

3. SP validates the response (same checks as above,
   except there is no InResponseTo to verify)

4. SP creates a session and lands the user on a default page
```

The absence of `InResponseTo` is a security consideration — IdP-initiated assertions can be replayed, since they're not tied to a specific request. Some SPs disable IdP-initiated flow for this reason. If you support it, implement nonce tracking or tight assertion replay prevention.

## The AuthnRequest

The SP's authentication request is also XML, base64-encoded, and optionally deflated (compressed) before being sent as a query parameter:

```xml
<samlp:AuthnRequest
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  ID="_req_xyz"
  Version="2.0"
  IssueInstant="2026-06-03T09:00:00Z"
  Destination="https://idp.example.com/sso"
  AssertionConsumerServiceURL="https://app.example.com/saml/acs"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">

  <saml:Issuer>https://app.example.com</saml:Issuer>

  <samlp:NameIDPolicy
    Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    AllowCreate="true" />

</samlp:AuthnRequest>
```

The `ID` from this request must appear as `InResponseTo` in the assertion — this is how replay attacks are prevented in SP-initiated flow.

## Metadata

SAML configuration is exchanged via **metadata documents** — XML files that describe an IdP or SP. They contain:

- Entity ID (the unique identifier)
- SSO endpoint URLs (for the IdP) or ACS URL (for the SP)
- X.509 signing certificates

Setting up a SAML integration typically means:
1. The SP provides its metadata to the IdP (or enters the details manually in the IdP dashboard)
2. The IdP provides its metadata to the SP (or the SP fetches it from a URL)

Most enterprise IdPs publish metadata at a standard URL:
```
https://idp.example.com/federationmetadata/2007-06/federationmetadata.xml  // ADFS
https://tenant.okta.com/app/appname/sso/saml/metadata                       // Okta
```

## Attribute Mapping

SAML assertions carry user attributes, but the attribute names are not standardised across IdPs. The same piece of data might arrive as:

```
email          (Okta default)
http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress  (Azure AD / ADFS)
urn:oid:0.9.2342.19200300.100.1.3  (LDAP attribute OID)
```

Your SP needs to be configured (or flexible enough) to accept the attribute format the IdP sends. This is one of the most common sources of SAML integration failures.

Best practice: document the exact attribute names your SP expects, provide IdP admins with a mapping table, and test with real assertions from their IdP before declaring the integration complete.

## Validating a SAMLResponse — What You Must Check

```javascript
import { validateSamlResponse } from 'your-saml-library';

async function handleACS(req, res) {
  const { SAMLResponse, RelayState } = req.body;

  const result = await validateSamlResponse(SAMLResponse, {
    // Must match the IdP's signing certificate (from metadata)
    idpCert: process.env.IDP_CERTIFICATE,
    // Must match your SP's entity ID
    audience: 'https://app.example.com',
    // Must match your ACS URL
    recipient: 'https://app.example.com/saml/acs',
    // The ID from your original AuthnRequest
    inResponseTo: session.samlRequestId,
  });

  if (!result.isValid) {
    return res.status(401).send('Invalid SAML response');
  }

  const { nameId, attributes } = result;

  // Create or update local user record
  const user = await upsertUser({
    email: nameId,
    groups: attributes.groups ?? [],
  });

  req.session.userId = user.id;
  res.redirect(RelayState ?? '/dashboard');
}
```

Never skip any of these checks. An assertion with a valid signature but a wrong `Audience` or expired `NotOnOrAfter` is still an invalid assertion.

## SAML vs OIDC

If you're designing a new SSO integration from scratch, OIDC is almost always the better choice. But SAML isn't going away — existing enterprise IdP configurations, legacy systems, and customer IT policies keep it relevant.

| | SAML 2.0 | OIDC |
|---|---|---|
| Token format | Signed XML | JWT (JSON) |
| Transport | HTTP Redirect / POST | REST / JSON |
| Setup complexity | High (XML, certificates, metadata) | Moderate |
| Mobile / native apps | Poor | Native |
| Enterprise IdP support | Universal | Broad (growing) |
| Attribute flexibility | High | High (custom claims) |
| Debugging | Hard (base64 XML in browser) | Easier (JSON, standard tools) |
| Spec age | 2005 | 2014 |

Some enterprise customers will require SAML specifically — their IT policy, their IdP configuration, or their compliance requirements may not support OIDC. For those cases, SAML support is a sales requirement, not an engineering preference.

## Common Integration Mistakes

**Wrong ACS URL in IdP configuration** — the IdP must POST to exactly the URL registered in the SP's metadata. A trailing slash difference will cause silent failures.

**Certificate mismatch** — IdPs rotate signing certificates. If your SP has the old certificate hardcoded, validation fails immediately after rotation. Always fetch metadata from the IdP's metadata URL dynamically, or have a process to update certificates before rotation.

**Clock skew** — `NotBefore` and `NotOnOrAfter` are evaluated against the SP's system clock. More than a few minutes of clock drift causes valid assertions to be rejected. Keep NTP in sync.

**Not validating `InResponseTo`** — skipping this check allows assertion replay attacks. Always tie the assertion back to a specific `AuthnRequest`.

**Accepting IdP-initiated flow without replay protection** — assertions without `InResponseTo` can be reused. Track assertion IDs and reject duplicates within the assertion validity window.

## Further Reading

- [What Is OpenID Connect?](/blog/openid-connect-explained) — the modern alternative to SAML for new integrations
- [Amazon Cognito vs Okta](/blog/cognito-vs-okta) — how enterprise IdPs like Okta manage SAML at scale
- [RBAC vs ABAC](/blog/rbac-vs-abac) — authorisation models that sit above the SSO layer
