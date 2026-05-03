---
title: "npm install and the Credential Harvest: Supply Chain Attacks Are Now Identity Attacks"
description: "A wave of malicious packages across npm, PyPI, and Packagist is specifically targeting developer credentials — .env files, AWS keys, GitHub tokens, CI/CD secrets. The package installs clean. The malware runs on import."
pubDate: 2026-05-01
author: "AuthLayer Team"
tags: ["supply-chain", "security", "credentials", "developer", "identity"]
image: "/images/og/supply-chain.jpg"
featured: false
---

A malicious PyPI package executes credential-stealing code the moment you import it. An npm package impersonating a popular UI library uses its postinstall script to exfiltrate your `.env` file. A worm spreading across npm and Packagist downloads unverified binaries from GitHub and runs them inside your CI/CD pipeline.

These aren't isolated incidents. In the past week alone, Socket identified active campaigns targeting PyPI's `lightning` package (versions 2.6.2 and 2.6.3), the `intercom-client` npm package, a TanStack impersonator stealing `.env` files, SAP CAP npm packages executing unverified binaries, and a cross-ecosystem DPRK campaign targeting developers across five package registries simultaneously.

The pattern is consistent: supply chain attacks have shifted focus. The target isn't your application's end users. It's you — the developer — and specifically your credentials.

## Why developer credentials are worth more than application data

A compromised developer machine or CI/CD environment is a higher-value target than most application databases. Consider what a typical developer has access to:

- AWS, GCP, or Azure credentials with broad permissions (developers frequently have production access)
- GitHub tokens that can read private repos across the org, push to branches, trigger Actions
- npm publish tokens — if stolen, allows publishing malicious versions of legitimate packages under your namespace
- Terraform state files with infrastructure credentials embedded
- Database connection strings for production, staging, and dev environments
- Third-party API keys: Stripe, Twilio, SendGrid, Slack, every SaaS integration your team uses

A single `.env` file from a developer's machine is often equivalent to a full set of skeleton keys. And because developers install dozens of packages per week, the attack surface is enormous.

## How the attacks work

The mechanics across recent campaigns follow recognizable patterns:

**Malware-on-import** is the Lightning PyPI technique. The malicious package looks legitimate — the metadata, README, and API surface are copied from the real package. The payload executes when the module is first imported, not during installation. This bypasses some naive "scan on install" approaches and catches developers who install packages in automated pipelines and don't run explicit install-time checks.

**Postinstall script exfiltration** is the TanStack brand-squat approach. npm's `package.json` allows arbitrary shell commands to run via lifecycle hooks — `preinstall`, `install`, `postinstall`. The malicious TanStack impersonator used `postinstall` to locate and exfiltrate `.env` files to an attacker-controlled endpoint. The install appears to succeed normally. You don't know anything happened.

```json
// What a malicious package.json postinstall looks like
{
  "scripts": {
    "postinstall": "node ./scripts/setup.js"
  }
}
```

```javascript
// setup.js — what it actually does
const fs = require('fs');
const path = require('path');
const https = require('https');

const targets = ['.env', '.env.local', '.env.production', '~/.aws/credentials', '~/.npmrc'];
targets.forEach(t => {
  try {
    const content = fs.readFileSync(path.resolve(process.env.HOME, t), 'utf8');
    // POST to attacker server
  } catch (_) {}
});
```

**Binary download and execution** is the SAP CAP npm pattern. The package's install script downloads a platform-specific binary from GitHub (or another hosting service) and executes it immediately. The binary is the actual payload — arbitrary code, compiled and obfuscated, doing whatever the attacker wants. This evades static analysis of the npm package itself because the malicious code isn't in the package.

**Ecosystem worms** are the Mini Shai-Hulud approach: a campaign that spreads across registries. Start with a compromised npm package; the payload contains code that also infects Packagist (PHP), then potentially Cargo, PyPI, or others. A developer working across languages pulls the infection into multiple project contexts.

## What's being stolen

Based on observed campaigns, the priority targets are:

| Credential type | Why it's targeted |
|---|---|
| AWS/GCP/Azure credentials | Direct access to cloud infrastructure; can be used for cryptomining, data exfiltration, or pivoting |
| GitHub tokens | Access to private source code; ability to push malicious commits or publish packages |
| npm tokens | Can publish malicious versions of legitimate packages — extending the supply chain attack |
| `.env` files | Contains everything else — database URLs, API keys, third-party secrets |
| `~/.npmrc` | Contains npm auth token plus registry configuration |
| `~/.aws/credentials` | Long-lived AWS access keys |
| SSH private keys | Access to servers, git remotes, deployment targets |
| Browser-stored credentials | Infostealers also sweep browser credential stores |

The DPRK-linked "Contagious Interview" campaign has been particularly aggressive about completeness — the payloads sweep for all of the above and exfiltrate everything they find, then establish persistent access for ongoing harvesting.

## Why CI/CD environments are the real prize

A developer laptop is valuable. A CI/CD runner is more valuable because:

1. It has secrets injected as environment variables by design — that's how CI/CD works
2. It runs with trusted permissions to deploy to production
3. It's often less monitored than production systems
4. It has access to the full source tree, including generated files that may contain embedded credentials

GitHub Actions secrets, CircleCI environment variables, and similar mechanisms are all stored as env vars at runtime. A malicious package that runs during `npm install` in a CI pipeline sees those secrets.

The Checkmarx incident from March is illustrative: attackers compromised the Bitwarden CLI package as part of a campaign targeting developer tooling. Bitwarden CLI is installed in CI/CD pipelines at many organizations to inject secrets at deploy time. Compromising it gives attackers access to the secrets vault credentials themselves — a single point of compromise for everything downstream.

## Defences that work

**Use lockfiles and verify them.** `package-lock.json`, `yarn.lock`, and `poetry.lock` pin exact package versions and hashes. Commit them. Verify them. If your lockfile says `lightning==2.6.1` and something is trying to install `2.6.2`, that's a signal. Don't use `--no-lockfile` or auto-update in production pipelines.

**Block postinstall scripts in production installs.** npm supports `--ignore-scripts` which prevents lifecycle hooks from running:

```bash
npm ci --ignore-scripts
```

This breaks some packages that legitimately need postinstall (native addons, etc.), but for most pure-JavaScript dependencies it works fine. Audit which packages actually need scripts and allowlist only those.

**Use a package analysis tool before installing.** Socket (socket.dev) and similar tools analyse packages for suspicious patterns — network calls in postinstall, obfuscated code, binary downloads, new maintainers — before you install. Integrate into your CI pipeline:

```bash
npx @socketsecurity/cli check package-lock.json
```

**Scope your CI/CD secrets to the minimum necessary.** The npm token your CI pipeline uses should only be able to publish to your specific packages, not have full account access. AWS credentials in CI should use role-based access with least privilege, not long-lived IAM user keys. Rotate them on a schedule short enough to limit the window a stolen credential stays valid.

**Audit `~/.npmrc` and `~/.aws/credentials` regularly.** These files contain credentials that don't expire on their own. Know what's in them. Long-lived credentials that don't rotate are a standing gift to any malware that can read the filesystem.

**Enable GitHub's push protection and secret scanning.** If a credential does get committed or exfiltrated and used, GitHub's secret scanning can detect known credential patterns and alert you. Push protection blocks commits that contain known secret formats before they reach the remote.

**Monitor for anomalous API usage.** A stolen AWS key will eventually be used. CloudTrail logs will show it. Set up alerts for:
- API calls from new IP addresses / ASNs
- Calls to regions you don't operate in
- Unusual service access patterns (a key that normally only touches S3 suddenly calling EC2)

## The deeper problem

Package registries were built for convenience, not security. The npm publish model — anyone can publish, anyone can update — was a feature when the ecosystem was small. At millions of packages and billions of weekly downloads, it's a massive attack surface.

Recent initiatives help: npm now requires 2FA for popular package maintainers, and both npm and PyPI have added automated malware scanning. But the detection gap is real — the Lightning and TanStack packages were live and downloadable before detection. The SAP packages were installed in unknown numbers of CI/CD pipelines before the campaign was identified.

The mental model shift that helps: treat every package install as running untrusted code with your credentials in scope. Because that's what it is. A postinstall script runs with the same filesystem access as your shell session. If you're logged into AWS in that shell, the postinstall script can read your AWS credentials.

That doesn't mean stop using packages. It means: pin versions, use lockfiles, run with `--ignore-scripts` where possible, and treat your developer machine's credential store as a high-value target that needs the same protection you'd give a production secret.

The attackers already figured this out. The question is whether your install pipeline has caught up.
