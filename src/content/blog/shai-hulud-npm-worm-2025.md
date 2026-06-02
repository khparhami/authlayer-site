---
title: "Shai-Hulud: The Self-Replicating Worm That Spread Through Millions of Developer Tools"
description: "In 2025, a self-replicating malware named after the sandworms of Dune spread across 187 npm packages — including CrowdStrike's own security tooling. It didn't just steal credentials. It copied itself. Here's how it worked, why it matters to everyone, and what it revealed about the software supply chain."
pubDate: 2026-05-23
author: "Khashayar Parhami"
tags: ["supply-chain", "malware", "npm", "developer-security", "credentials"]
image: "/images/og/shai-hulud-supply-chain.jpg"
featured: false
---

In Frank Herbert's *Dune*, Shai-Hulud is the great sandworm — a creature that consumes everything in its path, that cannot be stopped by walls or weapons, and that hides beneath the surface until it erupts. Developers who discovered this malware decided the name fit.

They were right.

In September 2025, a self-replicating worm spread silently across 187 JavaScript packages in npm — the registry that serves as the beating heart of the modern web. Every web developer in the world depends on npm. And for a brief, alarming window, npm was spreading malware on its own.

## What npm is, and why you've never heard of it

If you've ever used a web app, a banking portal, a streaming service, or a ride-sharing app, you've used code that came from npm. It stands for Node Package Manager, and it's a public repository of over two million open-source code packages — small, reusable pieces of software that developers include in their projects instead of writing everything from scratch.

Think of it this way: building software without npm would be like building a house without any pre-made materials — no bricks, no plumbing fixtures, no electrical wire. Every contractor would need to manufacture everything themselves. Instead, developers "install" packages the way a contractor orders supplies.

The problem with this model is trust. When you install a package, you're running code written by someone you've never met, from a company you may never have heard of, on your computer or your company's servers. Most of the time that's fine. Sometimes it isn't.

Shai-Hulud was one of the times it wasn't.

## How Shai-Hulud worked

What made the Shai-Hulud worm distinct from ordinary malware wasn't just what it stole — it was how it reproduced.

Most malicious npm packages are passive. They sit in the registry, wait to be installed, run their payload, and stop there. The victim's system is compromised, but the package itself doesn't spread. Shai-Hulud changed that calculus entirely.

Here's what happened when a developer installed an infected package:

**Step 1 — Credential harvest.** The package executed code at install time that scanned the developer's machine for stored credentials: npm authentication tokens, GitHub personal access tokens, SSH keys, `.env` files containing database passwords or API keys, and cloud provider credentials for AWS, Google Cloud, and Azure.

**Step 2 — Credential exfiltration.** Those credentials were immediately transmitted to an attacker-controlled server. The developer wouldn't see this — it looked like a normal package install.

**Step 3 — The worm propagates.** This is what set Shai-Hulud apart. Using the stolen npm authentication tokens, the worm automatically published trojanized versions of *other* packages the developer had publish access to. It spread itself through the developer's identity. One infected developer could silently poison dozens of other packages, whose maintainers had no idea anything had changed.

**Step 4 — Acceleration.** As more developers installed those poisoned packages, more credentials were stolen, more packages were compromised. The worm's spread was not linear — it was exponential, bounded only by how many infected developers had npm publish rights.

At its peak, researchers at Socket identified 187 infected packages across npm before registries could respond with mass takedowns.

## The detail that made security researchers stop and read

Here's the part of the story that traveled fastest when it broke.

Among the packages infected by the Shai-Hulud worm were components from **CrowdStrike's own developer tooling**.

CrowdStrike is one of the largest and most respected cybersecurity companies in the world. Their endpoint detection software is deployed on millions of corporate machines specifically to *stop* malware. And for a brief window in September 2025, their npm packages were distributing it.

This wasn't a commentary on CrowdStrike's competence — it was a demonstration of how supply chain attacks work. CrowdStrike developers, like all developers, use npm. One of them installed an infected package. The worm harvested their npm token. The worm published a trojanized version of a CrowdStrike package. Every developer who then installed a CrowdStrike tool had their credentials exfiltrated too.

The attacker didn't need to breach CrowdStrike. They just needed to infect someone who had publish rights to a CrowdStrike package.

## What happened to the stolen credentials

The credentials harvested by Shai-Hulud didn't just disappear. They were put to use.

npm tokens were used to publish more infected packages, accelerating the worm's spread. GitHub tokens were used to access private repositories — source code, internal documentation, deployment configurations. Once inside a private GitHub repo, attackers could read CI/CD pipeline files, find embedded secrets, access production infrastructure, and understand exactly how a company's software was built and deployed.

This matters because a CI/CD pipeline secret isn't just a password to one system. It's often a key that can deploy code to thousands of servers simultaneously, push updates to mobile apps used by millions of people, or access every environment from development through production. Compromising a pipeline credential is, in some ways, more serious than compromising a single production database.

Several affected organizations published post-mortems confirming that private source code had been accessed. The full downstream impact — whether any trojanized software reached end users — remained under investigation as of late 2025.

## May 2026: the worm evolves

The story didn't end in September 2025.

In May 2026, security researchers identified what they called **Mini Shai-Hulud**: a follow-on campaign that used the same propagation technique but targeted a specific cluster of packages in the `@antv` ecosystem — a widely-used data visualization library family with individual packages reaching up to 1.1 million weekly downloads.

Targeted packages included `echarts-for-react`, `g2`, `g6`, `x6`, `l7`, and `s2`. If you've ever seen an interactive data chart on a Chinese tech platform, a dashboard tool, or a modern analytics interface, there's a reasonable chance it was rendered by one of these packages.

Mini Shai-Hulud was contained faster than the original — the security community was watching for it. But its existence confirmed something uncomfortable: the technique works well enough that attackers kept coming back to refine it.

## Why this affects people who have never heard of npm

You might reasonably be thinking: *I'm not a developer. I don't install npm packages. Why should I care?*

Here's the chain that connects you to this story.

The apps on your phone, the websites you use for banking, the internal tools your company runs on — most of them were built by developers who use npm. If a developer at your bank installed a poisoned package, credentials for your bank's deployment systems could have been exfiltrated. If a developer at a healthcare platform was infected, private infrastructure access could have been compromised.

You never interact with npm directly. But the software you depend on was built by people who do. The supply chain attack model is effective precisely because it targets the construction phase, before the product reaches you. By the time you use the app, the damage was already done months earlier, in a developer's terminal window, during what looked like a routine package install.

## What organizations and developers can do

Supply chain attacks are not a problem that individual vigilance can fully solve — the scale is too large and the packages too numerous. But several controls make a meaningful difference:

**For developers:**
- Audit your npm publish rights. If you have publish access to packages you no longer maintain, revoke it. A token you aren't using is just an attack surface you forgot about.
- Enable npm two-factor authentication for publish operations. This would not have stopped Shai-Hulud entirely, but it raises the cost of token-based propagation significantly.
- Use tools like Socket or Snyk to scan packages for suspicious behavior before installation — not just known malware signatures, but behavioral patterns like credential scanning or unexpected network calls.
- Review your `.npmrc`, `~/.gitconfig`, and environment variables regularly. These are exactly where worms like Shai-Hulud look first.

**For organizations:**
- Rotate all npm, GitHub, and CI/CD tokens on a regular schedule. A compromised token that was rotated last week is far less useful than one that hasn't changed in two years.
- Implement least-privilege access for CI/CD pipelines. A pipeline that deploys to production should not also have read access to every private repository in your organization.
- Monitor for anomalous package publish events across your organization's npm scope. A package that suddenly gains a new version from an unexpected IP address is worth investigating before anyone installs it.
- Use a private package registry with allowlist controls. Instead of pulling directly from the public npm registry, mirror approved packages internally and block unapproved ones entirely.

## The thing the worm's name gets right

The developers who named this malware Shai-Hulud weren't being dramatic. The sandworm in *Dune* is a force of nature, not a weapon. It doesn't have an off switch. You don't negotiate with it. You can divert it, navigate around it, understand its patterns — but you can't simply decide it isn't a threat and go back to the surface.

The software supply chain has the same quality. The openness that makes it powerful — millions of developers sharing code freely, building on each other's work, accelerating what would otherwise take decades — is also what makes attacks like this possible. You cannot fully close the ecosystem without breaking it.

What you can do is make it harder. Rotate your tokens. Audit your access. Scan before you install. Treat your publish rights as carefully as you treat your production credentials.

Because somewhere out there, a worm is waiting beneath the sand.

---

*Shai-Hulud was documented by Socket Security, npm Security, and the GitHub Security Lab in September 2025. The Mini Shai-Hulud follow-on campaign was identified in May 2026 targeting the @antv visualization ecosystem. CVE assignments were pending as of publication.*
