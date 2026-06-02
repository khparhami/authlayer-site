---
title: "AI Found the Hole: The First Documented AI-Generated 2FA Bypass Used in the Wild"
description: "Google TAG identified a cybercrime group using an AI-generated zero-day to bypass 2FA on a widely-used web admin tool — the first documented case of AI-assisted vulnerability discovery in an active mass-exploitation campaign."
pubDate: 2026-05-12
author: "Khashayar Parhami"
tags: ["mfa", "identity", "vulnerabilities", "threats"]
image: "/images/og/ai-2fa-bypass.jpg"
featured: false
---

Last week, Google's Threat Analysis Group identified something that security researchers have been anticipating and dreading in equal measure: a cybercrime group using an AI-generated zero-day exploit to bypass two-factor authentication on a popular web-based administration tool — and running mass exploitation campaigns with it.

It's the first documented case of AI-assisted vulnerability discovery deployed in active criminal operations. The technique isn't theoretical anymore.

---

## What Happened

Google TAG attributed the campaign to an unknown cybercrime group. The target was a widely-used open-source, web-based system administration tool — the specific platform hasn't been fully named in public disclosures, but the vulnerability was in the tool's 2FA implementation, delivered via a Python script.

The group used AI to discover and write the exploit. The resulting code bypassed the 2FA check entirely, giving attackers authenticated access without completing the second factor.

This landed the same week that Instructure confirmed the ShinyHunters group had defaced Canvas login portals at hundreds of universities, and that cPanel CVE-2026-41940 — an authentication bypass — was already being hammered by over 2,000 attacker source IPs worldwide. Authentication infrastructure is having a bad week.

---

## How 2FA Bypass Vulnerabilities Work

To understand what was broken, it helps to see what a correctly implemented 2FA check looks like compared to common failure modes.

### The normal flow

```
  User                  Web App                 Auth Backend
   │                       │                         │
   │── username+password ─>│                         │
   │                       │── validate credentials ─>│
   │                       │<── credentials valid ────│
   │                       │                         │
   │<── "enter your code" ─│                         │
   │                       │                         │
   │── OTP code ──────────>│                         │
   │                       │── validate OTP ─────────>│
   │                       │<── OTP valid ────────────│
   │                       │                         │
   │<── session token ─────│                         │
   │   (authenticated)     │                         │
```

Two round trips. The session token is only issued after both factors pass.

### Where implementations fail

Most 2FA bypasses fall into one of four categories:

```
  BYPASS TYPE           HOW IT WORKS                      EXAMPLE
  ─────────────────────────────────────────────────────────────────
  State skipping        /verify-otp accessible without    Direct URL
                        completing /login first            navigation

  Token issued early    Session token granted after        Token in
                        password, OTP check optional       first response

  Race condition        OTP validation and session         Concurrent
                        creation run in parallel           requests

  Logic inversion       Error in conditional: OTP         if err == nil
                        invalid treated as valid           vs if err != nil
```

The AI-generated exploit likely targeted the first or fourth class — these are the most amenable to automated analysis of Python source code, where an LLM can read the authentication flow, identify the state transition logic, and generate a proof-of-concept that exercises the flaw.

---

## What "AI-Generated Exploit" Actually Means

It's worth being precise about what this represents, because the phrase can mean several different things.

```
  LEVEL    WHAT AI DOES                         ATTACKER DOES
  ──────────────────────────────────────────────────────────────────
  1        Explains a known CVE                 Everything else

  2        Suggests what code to look at        Reads it, finds bug,
                                                writes exploit manually

  3        Identifies vulnerability class       Writes exploit with
           in provided source                   AI assistance

  4  ★     Given source, generates working      Reviews output,
           PoC autonomously                     deploys it

  5        Discovers 0-day in closed binary     Not yet documented
           without source access
```

What Google TAG documented is Level 4. The group fed the tool's source code to an AI model, which produced a working exploit for a vulnerability the attackers didn't have to find or understand manually. The human role was deployment, not discovery.

That's a meaningful shift. Offensive security has always been gated partly by the expertise required to read and understand code at the right level of detail. Level 4 removes that gate.

---

## The cPanel Wave: What Mass Exploitation Looks Like Right Now

Running in parallel this week: CVE-2026-41940, an authentication bypass in cPanel and Web Host Manager (WHM), the web-based hosting control panel running on a very large fraction of shared hosting infrastructure globally.

The attack statistics are striking:

| Metric | Detail |
|--------|--------|
| Attacker source IPs | 2,000+ worldwide |
| Attack type | Automated, continuous |
| Attribution | Mr_Rot13 (initial wave) |
| Post-exploitation | Crypto mining, ransomware, botnet, backdoors |
| Patch status | Fix available, not widely applied |

The exploitation chain looks like this:

```
  Attacker                    cPanel Server
     │                              │
     │── GET /login ───────────────>│
     │                              │
     │<── login page ───────────────│
     │                              │
     │── POST /login                │
     │   [malformed auth request] ─>│  ← CVE-2026-41940
     │                              │   auth bypass triggered
     │                              │
     │<── session granted ──────────│  ← no valid credentials
     │   (authenticated as admin)   │
     │                              │
     │── deploy Filemanager backdoor│
     │── install crypto miner       │
     │── establish persistence ─────│
```

2,000 IPs running this simultaneously means any unpatched cPanel instance visible to the internet is being tried continuously. Automated scanning, automated exploitation, automated payload deployment.

---

## Why Web Admin Panels Are a Persistent Auth Weakness

Web-based admin panels (cPanel, Webmin, phpMyAdmin, Grafana, Jenkins, the Kubernetes dashboard) represent a specific risk class that deserves its own mental model.

```
  RISK PROPERTY              ADMIN PANELS          STANDARD WEB APPS
  ─────────────────────────────────────────────────────────────────────
  Default exposure           Often internet-facing  Usually behind auth
  Credential defaults        Frequently unchanged   Usually forced change
  Patch cadence              Irregular              Controlled deployment
  Auth implementation        Custom, varied         Standardised (OAuth)
  Post-compromise impact     Full server control    Application access
  Attack surface age         10-15+ year codebases  Newer, reviewed more
```

The combination of internet exposure, older codebases, and full-server post-compromise impact makes them high-value targets. The AI 2FA bypass story involves exactly this class of software.

---

## What Changes When AI Can Write the Exploit

The traditional timeline from vulnerability disclosure to mass exploitation has been compressing for years. AI accelerates specific phases:

```
  PHASE                   TRADITIONAL    AI-ASSISTED    CHANGE
  ──────────────────────────────────────────────────────────────
  Vulnerability discovery  Days–weeks     Hours          -90%
  PoC development          Hours–days     Minutes        -95%
  Weaponisation            Days           Hours          -75%
  Mass exploitation        Days after PoC Days after PoC  ~same
```

The discovery and PoC phases are where the most compression is happening. The exploitation infrastructure — scanning, deployment, payload hosting — still requires human operation, which is why mass exploitation timelines haven't shrunk as dramatically.

The practical implication: the window between a vulnerability existing and it being weaponised is getting shorter. For defenders, this tightens the patch window considerably. If a zero-day can go from source code to working exploit in hours, the relevant question isn't "how quickly can we patch after disclosure" — it's "what compensating controls are in place before we know there's something to patch."

---

## What to Do

**For admin panel exposure specifically:**

- Restrict access to admin panels to known IPs or VPN. There is no good reason for a cPanel, Webmin, or phpMyAdmin instance to be reachable from the public internet.
- Apply CVE-2026-41940 patches now. cPanel has released fixes; the 2,000-IP exploitation wave means unpatched instances are being found and hit continuously.
- Enforce MFA on admin panels using hardware keys or passkeys where possible. TOTP-based 2FA can be bypassed as this week demonstrates; phishing-resistant factors cannot.

**For 2FA implementation specifically:**

The four bypass classes listed above have corresponding fixes:

| Bypass Class | Fix |
|---|---|
| State skipping | Enforce session state machine — OTP endpoint checks that password step completed |
| Token issued early | Never issue session token until all factors pass |
| Race condition | Atomic check-and-issue in a single transaction |
| Logic inversion | Code review; automated test cases for invalid OTP returning 401 |

**For the AI exploit timeline problem:**

Compensating controls matter more when the patch window shrinks. Web application firewalls with virtual patching, anomaly detection on authentication endpoints, and automatic session termination on unusual access patterns all buy time when a zero-day is being mass-exploited before a fix is available.

The underlying shift — AI as an offensive research tool — isn't reversible. The response has to be architectural: reduce the blast radius when authentication is bypassed, not just harden the authentication itself.

---

*CVE-2026-41940 cPanel advisory and patched versions are published on cPanel's security page. Google TAG's AI exploit attribution is documented in their May 2026 threat intelligence report.*
