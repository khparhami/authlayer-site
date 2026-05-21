---
title: "One Phone Call, $100 Million: The Scattered Spider Attack on MGM Resorts"
description: "In September 2023, a threat actor called MGM's IT help desk, spent 10 minutes impersonating an employee, and walked away with Okta super-admin credentials. What followed was 10 days of operational chaos, $100M in losses, and one of the most instructive identity attacks ever documented."
pubDate: 2026-05-21
author: "AuthLayer Team"
tags: ["social-engineering", "okta", "identity", "ransomware", "incident-response"]
image: "/images/og/scattered-spider-mgm.jpg"
featured: false
---

In September 2023, someone called the MGM Resorts IT help desk. The call lasted about 10 minutes. The caller claimed to be an MGM employee. By the end of the call, they had convinced the help desk to reset the Okta credentials for a highly privileged account.

What followed was 10 days of operational catastrophe: slot machines locked, hotel room keys failing, reservation systems offline, restaurant point-of-sale systems down. MGM's own estimate of the financial damage was $100 million. The attackers' total investment in the initial access: a LinkedIn search and a phone call.

This is not a story about a sophisticated zero-day or a nation-state adversary. It's a story about what happens when an identity system is technically configured well but procedurally broken — and about why the help desk is now one of the highest-value attack surfaces in enterprise security.

## Who Scattered Spider is

Scattered Spider (also tracked as UNC3944, 0ktapus, and Muddled Libra) is a loosely organised cybercrime collective, predominantly young English-speaking members, many believed to be based in the US and UK. They are not a nation-state actor. They don't use custom exploit code or advanced malware of their own creation. Their signature capability is social engineering — specifically, an ability to convincingly impersonate employees and IT staff in high-pressure phone conversations.

The group first came to wide attention in the 2022 0ktapus campaign, which compromised over 130 organisations through SMS phishing for Okta credentials. By 2023, their techniques had evolved: instead of phishing for credentials, they were calling help desks and talking their way into credential resets. They don't need to steal your password if they can convince your IT team to replace it with one they control.

Their targets in the MGM and Caesars campaigns were not random. They specifically sought organisations with Okta as their identity provider, heavy cloud footprints (Azure, AWS), and large SaaS environments — because compromising the IdP means compromising everything downstream.

## Phase 1: The LinkedIn recon

Before the phone call, there was a search. Scattered Spider operators used LinkedIn to identify an MGM Resorts employee whose job title and tenure suggested they would have a high-privileged Okta account — someone in IT operations, identity management, or a senior technical role.

LinkedIn is a complete OSINT directory for this kind of targeting. A public profile tells an attacker:

- Full name (needed to impersonate the employee to the help desk)
- Job title (confirms likely access level)
- Employer and tenure (confirms they're current, not a former employee)
- Location (time zone context for the call)
- Sometimes: direct manager, team structure, and recent internal projects

This is not sophisticated. It requires no tools, no exploits, and no insider access. It requires a free LinkedIn account and 20 minutes.

The attacker now has a name, a role, and a plausible identity to assert. The next step is a phone call.

## Phase 2: The help desk call

The attacker called MGM's IT help desk. They identified themselves using the employee's name and likely provided additional authenticating information — employee ID formats, last four of a Social Security Number, department details — that can be assembled from data broker sites, previous breach data, or LinkedIn context.

The social engineering script for this kind of call is not elaborate. The caller doesn't need to be technical. They need to sound frustrated, time-pressured, and plausible. A typical pattern:

> "Hi, this is [employee name] from [department]. I'm locked out of my account — I think something happened when I tried to log in from home this morning. I've got a deadline in an hour and I can't access any of my systems. Can you reset my Okta password and MFA?"

Help desks at large organisations process hundreds of these requests per day. The cognitive load is high, the pressure to resolve tickets quickly is constant, and the verification process — particularly for identity confirmation over the phone — is often the weakest part of the chain.

The call worked. The help desk reset the Okta account. The attacker now controlled a highly privileged identity inside MGM's IdP.

## Phase 3: Okta super-admin compromise

Okta is the central nervous system for identity at most large enterprises. An Okta super-admin can:

- Reset passwords and MFA for any user in the tenant
- Create new user accounts with any permissions
- Modify Okta policies, including MFA enrollment requirements
- Access the Okta system log — which means they can also see what they should cover up
- Provision access to any SAML or OIDC application integrated with Okta

With super-admin access, Scattered Spider didn't just have one account. They effectively had every account. They could reset the MFA for a cloud administrator, log in as that person, and pivot to Azure. They could create net-new service accounts that looked legitimate. They could modify authentication policies to lower MFA requirements for specific users or apps.

The Okta super-admin account is the master key to the entire enterprise identity plane. In MGM's case, the help desk handed it over in a 10-minute call.

## Phase 4: Azure pivot and VMware access

From Okta, the attackers moved laterally into MGM's Azure environment. The exact path isn't fully public, but the pattern documented by Mandiant and CrowdStrike across Scattered Spider's broader campaign activity follows a consistent sequence:

1. **Okta → Azure AD / Entra ID**: Okta federates with Azure AD in many enterprise environments. A super-admin can manipulate federation trust or directly access Azure-integrated applications. From there, the attacker escalates to Azure AD roles.

2. **Azure AD → Azure subscriptions**: With sufficient Azure AD role access, the attacker can reach Azure resource groups, Key Vault secrets, storage accounts, and virtual machine management.

3. **VMware vCenter access**: MGM's environment included on-premises VMware infrastructure. vCenter credentials stored in Azure Key Vault or accessible to cloud admins gave Scattered Spider the ability to manage virtual machines directly — a prerequisite for ransomware deployment at scale.

4. **Credential harvest from secrets stores**: Throughout this phase, the attackers extracted credentials from Key Vault, environment variables, configuration files, and any other secrets stores reachable from the cloud identity they controlled.

This phase took hours, not days. By the time MGM's security team identified the initial intrusion, the attackers had already established presence across multiple layers of the environment.

## Phase 5: ALPHV/BlackCat ransomware deployment

Scattered Spider partnered with the ALPHV (also known as BlackCat) ransomware-as-a-service operation. ALPHV provided the encryption payload; Scattered Spider provided the initial access and lateral movement capability. This kind of access broker / ransomware operator partnership is now standard in the cybercrime ecosystem.

The ransomware encrypted systems across MGM's environment, including infrastructure that controlled casino floor operations. The operational impact was immediate and visible:

- Slot machines stopped working
- Hotel room electronic locks lost connectivity
- Reservation and check-in systems went offline
- Digital payment systems at restaurants and retail went down
- MGM.com and the MGM app experienced outages

MGM chose not to pay the ransom. Recovery took approximately 10 days and involved rebuilding significant portions of the environment from backup. The $100M loss figure cited in MGM's SEC disclosure covers system restoration costs, business disruption, and the cost of the investigation.

## The Caesars contrast

Scattered Spider hit Caesars Entertainment in the weeks before the MGM attack, using the same initial access method — a social engineering call targeting a third-party IT vendor that had help desk access to Caesars' environment.

Caesars' response was different: they paid approximately $15 million of a reported $30 million ransom demand, and the attackers decrypted their systems. The attack was disclosed in a quiet SEC filing. No operational disruption was publicly visible.

Neither outcome is a good outcome. Paying the ransom funds the next attack and provides no guarantee that the attackers haven't retained copies of stolen data (Caesars' personal data for tens of millions of loyalty program members was already exfiltrated before payment). Not paying, as MGM demonstrated, produces 10 days of public operational chaos.

The correct outcome is prevention. Both attacks used the same entry point.

## What broke down: the five failure points

Reviewing the public record of the MGM attack, five distinct control failures enabled or amplified the damage.

**1. No strong identity verification for help desk requests.**
The help desk accepted caller-provided information — name, possibly employee ID or SSN fragment — as sufficient proof of identity to reset an Okta account. This information is trivially obtainable from breach databases and public sources. Verification by knowledge is not verification.

**2. Super-admin accounts enrolled in standard MFA.**
Okta super-admin accounts should require phishing-resistant MFA — a FIDO2 hardware key, not a TOTP app or push notification. If MFA reset can be performed by the help desk over a phone call, then MFA on the super-admin account is a speed bump, not a control.

**3. No privileged access workstation (PAW) requirement for IdP administration.**
Super-admin operations in Okta should require authentication from a managed, compliant device on a controlled network segment. An attacker who resets credentials and logs in from an unknown IP on a personal machine should fail a device compliance check before they can do anything.

**4. Okta's "Super Administrator" role too broadly assigned.**
A principle of least privilege applied to Okta means that routine identity operations — password resets, MFA resets for ordinary users — should not require super-admin. If the account the help desk reset had been scoped to a lower Okta role, the blast radius would have been contained. The attacker would have had one account, not every account.

**5. No anomaly detection on Okta admin operations.**
Okta's system log records every administrative action. Resetting MFA and changing the password for a high-privileged account, immediately followed by a new login from an unrecognised device and IP, is a detectable sequence. An alert on "admin MFA reset followed by first-time device login within 60 minutes" would have fired. No alert fired.

## What defenders should do

These are the controls that specifically address the Scattered Spider attack pattern. They're ordered by impact.

**Implement identity verification for all account recovery operations.**

Any request that resets credentials or MFA factors must verify the requester's identity through a channel that doesn't depend on caller-provided information. Effective options:

- Video verification with live ID presentation
- Out-of-band callback to the employee's registered mobile number from a verified directory (not a number provided by the caller)
- Manager approval workflow before any privileged account change is processed
- Hardware key possession verification — if the employee can prove they hold their registered FIDO2 key, they can reset their own account without help desk involvement

The standard in high-assurance environments: treat any account recovery request as potentially adversarial until the requester proves something they physically possess.

**Require FIDO2/WebAuthn for all privileged Okta roles.**

```
Okta Admin Console → Security → Authenticators
→ Create new Enrollment Policy for roles: Super Administrator, Org Administrator, Application Administrator
→ Required authenticators: FIDO2 WebAuthn hardware key
→ Allowed authenticators: Hardware key only (remove TOTP, push, SMS)
```

FIDO2 authentication is origin-bound and phishing-resistant. A help desk cannot reset a FIDO2 hardware key over a phone call — they can only disable it and require physical key re-enrollment, which itself should require in-person verification.

**Enforce device compliance for Okta admin access.**

Okta's network zone and device trust features can restrict admin console access to managed devices enrolled in your MDM:

```
Okta Admin Console → Security → Network → Add Zone
→ Name: "Corp Managed Devices"
→ Apply Okta FastPass device trust requirement
→ Attach to Sign-On Policy for Admin roles: block any session not meeting device trust
```

An attacker who resets credentials but logs in from a personal machine on a residential ISP fails device trust before they reach the admin console.

**Alert on the post-reset login pattern in Okta.**

Okta's system log exposes the events needed to detect this attack. The key sequence: admin credential reset → new device login within a short window.

```javascript
// Okta System Log filter — alert on this event sequence
// Event 1: user.mfa.factor.deactivate OR user.account.reset_password
//   where target user has privileged Okta role
// Event 2: user.session.start from new device/IP within 30 minutes of Event 1

{
  "filter": "eventType eq \"user.session.start\"",
  "condition": "device.isManaged eq false AND transaction.detail.requestApiTokenId eq null",
  "correlate_with": "user.mfa.factor.deactivate within 30m for same target.id"
}
```

Feed this to your SIEM or use Okta Workflows to trigger an automated account suspension and analyst alert when the pattern fires.

**Scope Okta roles to the minimum required.**

Review every account holding Super Administrator. Most help desk functions — routine password resets, MFA resets for standard users, application assignment — can be performed with Group Administrator, Help Desk Administrator, or custom roles scoped to specific groups. Super Administrator should be reserved for a small number of accounts with hardware key MFA and PAW requirements.

```
Okta Admin Console → Security → Administrators
→ Audit current Super Administrator list
→ For each: can this person's job function be performed with a lower role?
→ Create custom role with only the permissions required
→ Remove Super Administrator from accounts that don't need it
```

**Treat Caesars and MGM as your tabletop scenario.**

Run a red team exercise where the starting move is a help desk call impersonating an employee with a plausible social engineering script. Test whether your help desk verification process would stop it. Test whether the Okta admin audit events would generate an alert. Test how long it takes your security team to detect a super-admin login from an unknown device.

The MGM attack wasn't detected at the initial access phase. It was detected after significant lateral movement had already occurred. The tabletop should answer: at which step would we have caught this?

## The structural lesson

The MGM attack is studied because it's clarifying. There was no zero-day. There was no novel malware technique. There was a phone call, a help desk, and a process that prioritised ticket resolution speed over identity assurance.

The identity perimeter has moved. It is no longer the network edge. It is the identity provider. Whoever controls the IdP controls the environment — every SaaS application, every cloud subscription, every downstream system that trusts the IdP's assertions.

Securing the IdP used to mean configuring MFA. It now means securing the administrative plane of the IdP itself: who can reach it, from what devices, with what authenticators, under what verification conditions. And it means securing the human process layer — because an attacker who can convince your help desk to hand over the keys doesn't need to bypass any of your technical controls.

Scattered Spider didn't hack MGM. They called them.

---

*Primary sources: MGM Resorts 8-K filing (September 2023), Mandiant UNC3944 threat intelligence report, CrowdStrike SCATTERED SPIDER adversary profile, CISA/FBI advisory AA23-320A on Scattered Spider TTPs, SEC disclosure by Caesars Entertainment (Form 8-K, September 2023). ALPHV/BlackCat analysis by Recorded Future.*


