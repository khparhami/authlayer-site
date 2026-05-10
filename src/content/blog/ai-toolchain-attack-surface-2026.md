---
title: "Trusted by Design: How Attackers Are Weaponising Your AI Toolchain"
description: "This week attackers abused Hugging Face, Claude.ai shared chats, and Google Ads to deliver infostealers — while a CVSS 9.1 flaw in Ollama exposed 300,000 self-hosted servers to memory leaks. The AI toolchain is now a primary credential theft vector."
pubDate: 2026-05-11
author: "AuthLayer Team"
tags: ["identity", "threats", "supply-chain", "security"]
image: "/images/og/ai-toolchain.jpg"
featured: false
---

Three separate campaigns broke this week that don't look related at first. A fake OpenAI repository on Hugging Face. A Google Ads campaign pointing to malicious instructions hosted inside Claude.ai. A critical memory leak in Ollama affecting 300,000+ self-hosted servers.

They're related. The common thread is that attackers have identified AI tooling — model registries, AI chat platforms, self-hosted inference servers — as a high-yield, low-scrutiny vector for credential theft. The trust developers place in these platforms is exactly what's being exploited.

## Hugging Face as a malware distribution platform

On May 7th, researchers at HiddenLayer identified a repository named `Open-OSS/privacy-filter` on Hugging Face, impersonating an OpenAI privacy tool. Before removal, it had reached the number one trending position on the platform and accumulated 244,000 downloads — though researchers noted the counter may have been artificially inflated to boost visibility.

The payload delivery was layered:

1. A `loader.py` script — the kind of thing any ML engineer would run to bootstrap a project — contained obfuscated code that disabled SSL verification, decoded a base64 URL, and fetched a JSON payload from an external server
2. That payload executed a PowerShell command
3. PowerShell ran a batch file that triggered privilege escalation and downloaded the final stage

The final stage was a Rust-based infostealer. Rust makes sense here: it compiles to small, fast, hard-to-analyse binaries. The payload came with extensive anti-analysis features — VM detection, sandbox checks, debugger detection — and targeted a wide credential footprint: browser cookies and passwords, Discord tokens, cryptocurrency wallets, SSH/FTP/VPN credentials, and system screenshots. Everything went to a C2 server at `recargapopular[.]com`.

The mechanism is worth sitting with. This wasn't a typosquatted PyPI package or a malicious npm module. It was a repository on the ML community's primary model-sharing platform, trending at number one, with a name designed to invoke OpenAI's brand. Developers who reviewed it briefly would have seen a Python file with ML-adjacent imports. Nothing visually alarming until you read the obfuscated loader carefully.

## Claude.ai shared conversations as a payload host

A separate campaign this week targeted macOS users searching for "Claude mac download" via Google. The sponsored results pointed to legitimate `claude.ai` domains — but landing on malicious shared chat interfaces that had been created by the attackers and were publicly accessible through Claude's own sharing infrastructure.

Those shared chats contained instructions "attributed to Apple Support," with base64-encoded terminal commands the user was told to run to complete installation.

The payload was a multi-stage shell script delivered by a server that generated a uniquely obfuscated version on each request, making signature-based detection ineffective. The script ran entirely in-memory, used `osascript` for execution to avoid deploying traditional binaries, and implemented victim profiling: it checked for Russian or CIS-region keyboard configurations and silently exited if detected — a targeting filter that suggests a specific intended victim population.

The delivered malware, identified as a MacSync variant, harvested browser credentials, session cookies, and macOS Keychain contents.

Two things are notable here. First, the attacker's infrastructure was hosted on `claude.ai`. The malicious instructions were served from a URL the victim had no reason to distrust. Second, the Google Ads pointed at the legitimate domain — meaning the domain in the ad matched the domain the user arrived at. The deception was entirely in the shared content, not the URL.

This is a different kind of abuse than domain spoofing. Shared-content platforms — Notion, Confluence, Google Docs, and now AI chat interfaces — have become hosting infrastructure for social engineering because they're both trusted and indexed.

## CVE-2026-7482: Bleeding Llama

While those campaigns targeted end users, a third attack surface this week was purely infrastructure: a critical vulnerability (CVE-2026-7482, CVSS 9.1) in Ollama, the open-source framework used to self-host LLMs. Researchers named it Bleeding Llama.

The vulnerability is in the GGUF model loader. The `/api/create` endpoint accepts attacker-supplied GGUF files, which declare tensor offsets and sizes in their headers. During quantization operations in `fs/ggml/gguf.go` and `server/quantization.go`, those declared values aren't validated against the actual file length. An attacker can supply a GGUF file that declares offsets exceeding the file's actual size — triggering a heap out-of-bounds read that leaks the entire process memory.

Ollama has over 171,000 GitHub stars. Researchers estimate more than 300,000 instances are deployed globally. The same prior research on self-hosted AI infrastructure noted earlier this month found a significant proportion of these instances exposed to the internet without authentication.

The combination is straightforward: unauthenticated `/api/create` endpoint, plus a malicious GGUF file, equals full process memory disclosure on a machine that's likely also running model weights, API keys, and configuration with credentials for downstream services. On a developer's machine or a shared inference server, that process memory can contain quite a lot.

## What's actually being stolen

Across all three campaigns, the credential targets are consistent and worth listing explicitly:

- Browser session cookies (as discussed in our last article — these bypass MFA entirely)
- Saved passwords and autofill data
- `~/.npmrc` — npm publish tokens
- `~/.pypirc` — PyPI upload credentials
- `~/.git-credentials` — Git authentication
- `~/.aws/credentials` — AWS access keys
- `~/.kube/config` — Kubernetes cluster access
- `~/.docker/config.json` — container registry credentials
- Vault tokens, Terraform state credentials, GitHub CLI tokens
- `.env` files — often containing API keys, database URLs, OAuth secrets

That list is a developer's entire infrastructure footprint. Credentials from this set don't just compromise a single account — they enable package poisoning on npm/PyPI, cloud infrastructure access, CI/CD pipeline control, and lateral movement through every service that trusts those credentials.

The Quasar Linux RAT campaign disclosed separately this week specifically targeted this developer credential set, deploying implants that exfiltrated these files and enabled downstream malicious package deployment to public registries. If you control an npm token, you can push a malicious update to a package with millions of downloads.

## The structural problem

All three of this week's campaigns exploit the same property: developers have been trained to trust AI platforms. Hugging Face is where you get models. Claude.ai is where you run AI. Ollama is what you install for local inference. These tools are used routinely, often with reduced scrutiny, and they sit inside development environments that contain the most sensitive credentials an organisation has.

The response from security teams has been to treat AI tools as a productivity question rather than an infrastructure security question. That's the wrong frame. Self-hosted inference servers should be treated like any other internal service: network-segmented, authenticated, patched on the same cadence as your web servers. Model registries should be treated like package registries: provenance matters, you don't run `pip install` from a trending repository without reading the source, and you don't `curl | bash` instructions from a shared chat link.

For Ollama specifically: patch to the version that addresses CVE-2026-7482, and if you're running a public-facing instance, the `/api/create` endpoint should not be reachable from untrusted networks. If you're not sure whether your instance is exposed, `curl http://localhost:11434/api/tags` from outside your internal network will tell you.

The pattern of this week's campaigns isn't going to reverse. If anything, as AI tooling becomes more embedded in development workflows, the credential surface it sits next to grows. The trust developers extend to these tools is a feature that attackers have noticed and are actively working.

---

*Bleeding Llama (CVE-2026-7482) technical analysis by the Ollama security team. Hugging Face campaign research by HiddenLayer. Claude.ai malvertising campaign analysis published via BleepingComputer.*
