---
title: "Password Hashing Explained: bcrypt, Argon2, and scrypt"
description: "Why MD5 and SHA-1 are catastrophically wrong for passwords, how modern slow-hash functions work, and how to choose and configure bcrypt, Argon2, and scrypt correctly in production."
pubDate: 2026-06-03
author: "Khashayar Parhami"
tags: ["security", "guide"]
image: "/images/og/password-hashing-explained.png"
featured: false
---

Every week another breach surfaces, and every breach includes a password dump. The outcome — whether those passwords are cracked in hours or never — comes down to one decision made by developers: how the passwords were stored. The difference between a bad choice and a good one is not subtle. It's the difference between every password in the dump being recoverable within days and none of them being recoverable at all.

## Why You Cannot Store Passwords in Plaintext or with Encryption

Plaintext storage is obvious: if the database is compromised, every password is immediately known.

Encryption seems better but has a fatal flaw: encryption is reversible. Whoever has the decryption key can recover every password. The key must be stored somewhere accessible to the application, which means a server compromise often yields both the key and the encrypted data.

The right primitive is a **one-way function**: something that transforms a password into a stored value from which the original cannot be recovered, even by the system that stored it. That's a hash.

## Why MD5 and SHA-1 Are Catastrophically Wrong for Passwords

MD5 and SHA-1 are cryptographic hash functions designed to be fast — as fast as possible. That's exactly the wrong property for password storage.

Speed is the attacker's best friend. An attacker with a GPU and the leaked hash database can try billions of password candidates per second:

| Algorithm | Speed (single GPU) | Time to crack 8-char password |
|---|---|---|
| MD5 | ~60 billion/sec | Seconds to minutes |
| SHA-1 | ~20 billion/sec | Minutes |
| SHA-256 | ~10 billion/sec | Minutes to hours |
| bcrypt (cost 12) | ~20,000/sec | Years to centuries |
| Argon2id (t=3, m=65536) | ~300/sec | Practically infeasible |

The speed gap is not marginal. It's eight to nine orders of magnitude.

A second problem: fast hashes have no **salt** built in. Without a salt — a random value prepended to each password before hashing — attackers can use **rainbow tables**: precomputed tables mapping hashes back to passwords. An attacker who has MD5 rainbow tables can look up every hash in the dump instantly, with no per-password computation at all.

**Never use MD5, SHA-1, SHA-256, or any general-purpose hash function for passwords.** They were not designed for this and are not safe for this, regardless of how many times you hash or how you combine them.

## What Makes a Password Hash Function Safe

Three properties matter:

**1. Slowness (work factor)** — the function is deliberately expensive to compute. Legitimate authentication runs it once. An attacker trying a billion candidates runs it a billion times. Each order of magnitude of slowness costs the attacker a year of GPU time.

**2. Salting** — a unique random value is generated per password and combined with it before hashing. This means identical passwords produce different hashes, eliminates rainbow table attacks, and forces the attacker to crack each password individually.

**3. Memory hardness (Argon2, scrypt)** — the function requires large amounts of memory to compute efficiently. GPUs can run billions of hash operations in parallel because each operation requires almost no memory. Memory-hard functions force a trade-off: parallelism costs proportionally more memory, capping the attacker's throughput.

---

## bcrypt

bcrypt was designed in 1999 specifically for password hashing. It remains widely used and is a safe choice for most applications.

### How it works

bcrypt uses a **cost factor** (also called work factor or rounds) that controls how slow it is. Each increment doubles the computation time. The cost factor is stored in the hash output alongside the salt, so verification always uses the correct cost:

```
$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewYVz4JBqF.5dKlO
 ^  ^  ^                                                         
 |  |  +-- 22-char base64 salt                                  
 |  +-- cost factor (12 = 2^12 = 4096 rounds)
 +-- algorithm version
```

### Choosing a cost factor

Target **250–500ms** for a single hash on your production hardware. Start at 12 and benchmark:

```javascript
import bcrypt from 'bcrypt';

// Benchmark to find the right cost for your hardware
async function benchmarkBcrypt() {
  for (let cost = 10; cost <= 14; cost++) {
    const start = Date.now();
    await bcrypt.hash('benchmark', cost);
    console.log(`Cost ${cost}: ${Date.now() - start}ms`);
  }
}

// Typical results on modern hardware:
// Cost 10: ~65ms
// Cost 11: ~130ms
// Cost 12: ~260ms  ← common choice
// Cost 13: ~520ms
// Cost 14: ~1040ms
```

Use cost 12 as a baseline. If your servers are newer or you have headroom, go to 13.

### Hashing and verifying

```javascript
import bcrypt from 'bcrypt';

const COST = 12;

// On registration — hash the password
async function hashPassword(plaintext) {
  return bcrypt.hash(plaintext, COST);
}

// On login — verify the password
async function verifyPassword(plaintext, storedHash) {
  return bcrypt.compare(plaintext, storedHash);
  // Returns true/false — never compare the raw hash directly
}

// Usage
const hash = await hashPassword('correct horse battery staple');
// Store hash in database — never store plaintext

const isValid = await verifyPassword('correct horse battery staple', hash);
// true

const isInvalid = await verifyPassword('wrong password', hash);
// false
```

### bcrypt's limitations

bcrypt has a **72-byte input limit**. Passwords longer than 72 bytes are silently truncated. Most users won't hit this, but if you allow passphrases, be aware. Some implementations pre-hash with SHA-256 before bcrypt to handle longer inputs — this is safe if done correctly.

bcrypt is also not memory-hard. It's slow, but parallelisable on GPUs and ASICs in ways that Argon2 resists.

---

## Argon2

Argon2 won the Password Hashing Competition in 2015 and is the current recommended algorithm for new systems. It's memory-hard, configurable, and has a clean modern design.

### Three variants

- **Argon2d** — fastest, but vulnerable to side-channel attacks. Use for cryptocurrency or applications without side-channel risk.
- **Argon2i** — resistant to side-channel attacks, but weaker against GPU cracking.
- **Argon2id** — hybrid of the two. **Use this one** for password hashing.

### Parameters

Argon2id has three cost parameters:

| Parameter | What it controls | Recommended minimum |
|---|---|---|
| `t` (time cost) | Number of iterations | 3 |
| `m` (memory cost) | Memory in kibibytes | 65536 (64 MB) |
| `p` (parallelism) | Number of threads | 4 |

The memory cost is the key differentiator from bcrypt. Requiring 64 MB per hash means an attacker can run at most ~1,000 parallel hashes on a 64 GB GPU — far fewer than bcrypt.

```javascript
import argon2 from 'argon2';

const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 65536,  // 64 MB
  timeCost: 3,
  parallelism: 4,
};

// Hash
async function hashPassword(plaintext) {
  return argon2.hash(plaintext, ARGON2_OPTIONS);
}
// Output: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>

// Verify
async function verifyPassword(plaintext, storedHash) {
  return argon2.verify(storedHash, plaintext);
}
```

The hash output includes all parameters and the salt — you store the single string, and verification extracts everything it needs from it.

### When to increase the parameters

Benchmark on your production hardware and target 300–500ms. If you can afford more memory, increase `m` first — memory hardness is Argon2's primary advantage. If login time allows, increase `t` next.

---

## scrypt

scrypt predates Argon2 and introduced memory hardness to password hashing. It's still widely used (it's Node.js's built-in password hashing function) and is a solid choice.

### Parameters

| Parameter | What it controls |
|---|---|
| `N` (cost factor) | CPU and memory cost — must be a power of 2 |
| `r` (block size) | Memory block size — affects memory bandwidth |
| `p` (parallelism) | Parallelisation factor |

Memory used ≈ 128 × N × r bytes. With `N=131072, r=8`: 128 MB.

```javascript
import { scrypt, randomBytes, timingSafeEqual } from 'crypto';
import { promisify } from 'util';

const scryptAsync = promisify(scrypt);

const SALT_LENGTH = 32;
const KEY_LENGTH = 64;
const SCRYPT_PARAMS = { N: 131072, r: 8, p: 1 }; // 128 MB

async function hashPassword(plaintext) {
  const salt = randomBytes(SALT_LENGTH);
  const hash = await scryptAsync(plaintext, salt, KEY_LENGTH, SCRYPT_PARAMS);
  // Store salt + hash together
  return `${salt.toString('hex')}:${hash.toString('hex')}`;
}

async function verifyPassword(plaintext, stored) {
  const [saltHex, hashHex] = stored.split(':');
  const salt = Buffer.from(saltHex, 'hex');
  const storedHash = Buffer.from(hashHex, 'hex');
  const hash = await scryptAsync(plaintext, salt, KEY_LENGTH, SCRYPT_PARAMS);
  // Use timing-safe comparison to prevent timing attacks
  return timingSafeEqual(hash, storedHash);
}
```

Note: unlike bcrypt and Argon2, Node's built-in `scrypt` doesn't encode the salt and parameters into the output — you manage that yourself, as shown above.

---

## Comparison

| | bcrypt | Argon2id | scrypt |
|---|---|---|---|
| Designed | 1999 | 2015 | 2009 |
| Memory-hard | No | Yes | Yes |
| GPU resistance | Moderate | High | High |
| Input limit | 72 bytes | None | None |
| Built into Node.js | No (npm) | No (npm) | Yes |
| PHC winner | No | Yes | No |
| Use for new systems | ✓ acceptable | ✓ recommended | ✓ acceptable |

**Recommendation:** Use Argon2id for new systems. Use bcrypt (cost ≥ 12) if Argon2 isn't available in your language/framework. Never use scrypt's default parameters — they're set too low.

---

## Migrating an Existing Hash Database

If your system currently stores MD5, SHA-1, or unsalted hashes, migration is urgent but doesn't require a forced password reset.

### Online migration (transparent to users)

On each successful login, the user's plaintext is available for a moment. Use it to re-hash with the new algorithm and update the stored value:

```javascript
async function login(email, plaintext) {
  const user = await db.users.findByEmail(email);
  if (!user) return null;

  let isValid = false;

  // Check which algorithm was used
  if (user.hashVersion === 'md5') {
    const md5Hash = md5(plaintext); // legacy check
    isValid = md5Hash === user.passwordHash;
    if (isValid) {
      // Upgrade to Argon2id on the fly
      user.passwordHash = await argon2.hash(plaintext, ARGON2_OPTIONS);
      user.hashVersion = 'argon2id';
      await db.users.save(user);
    }
  } else if (user.hashVersion === 'argon2id') {
    isValid = await argon2.verify(user.passwordHash, plaintext);
  }

  return isValid ? user : null;
}
```

Users who haven't logged in after a set period can be required to reset their password before the legacy hashes are deleted.

### Double-hashing legacy hashes

If you can't wait for user logins, wrap existing hashes: `argon2id(md5_hash)`. This is less ideal (MD5 hashes are shorter and have a constrained character set) but immediately protects the stored values from bulk cracking. Document the migration clearly so future developers understand the format.

---

## Common Mistakes

**Using a global salt** — a single salt shared across all passwords eliminates the protection salting provides. Every password hash function described here generates a unique salt per hash automatically. Never reuse salts.

**Comparing hashes with `==`** — use a timing-safe comparison function. String equality short-circuits on the first mismatched character, leaking timing information. In Node.js: `crypto.timingSafeEqual()`. bcrypt and Argon2 libraries do this internally.

**Ignoring pepper** — a pepper is a server-side secret concatenated with the password before hashing, stored in application config (not the database). If the database is leaked but the config isn't, peppered hashes can't be cracked at all. Useful for high-assurance contexts:

```javascript
const PEPPER = process.env.PASSWORD_PEPPER; // 32+ random bytes, stored in secrets manager
const hash = await argon2.hash(plaintext + PEPPER, ARGON2_OPTIONS);
```

**Setting cost too low** — a bcrypt cost of 4 or 6 (common in test configs that leak to production) is barely slower than SHA-256. Set minimums in code and assert them on startup.

---

## Further Reading

- [API Security Checklist](/blog/api-security-checklist) — password endpoint protections (rate limiting, lockout)
- [Session vs Token Authentication](/blog/session-vs-token-authentication) — what happens after a password is verified
- [MFA Complete Guide](/blog/mfa-complete-guide) — adding a second factor so a cracked password isn't game over
