# Anthem — TryHackMe Writeup

**Difficulty:** Easy  
**OS:** Windows  
**Tags:** OSINT, Web, RDP, Windows, Umbraco

---

## Overview

Anthem is a beginner-friendly Windows machine on TryHackMe focused on web reconnaissance, OSINT, and basic Windows enumeration. The attack path involves discovering credentials and flags through website analysis, then gaining access via RDP and escalating privileges by finding a hidden backup file.

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -Pn -p- <TARGET_IP>
```

> **Note:** The `-Pn` flag is required because the Windows machine blocks ICMP ping probes.

**Open Ports:**

| Port | Service | Details |
|------|---------|---------|
| 80   | HTTP    | Microsoft HTTPAPI httpd 2.0 |
| 3389 | RDP     | Microsoft Terminal Services |

**Key findings from Nmap:**
- Machine name: `WIN-LU09299160F`
- OS: Windows Server 2019 (build 10.0.17763)

---

## Web Enumeration

### robots.txt

```
http://<TARGET_IP>/robots.txt
```

Contents revealed:
- **Potential password:** `UmbracoIsTheBest!`
- **Disallowed directories:** `/bin/`, `/config/`, `/umbraco/`, `/umbraco_client/`
- **CMS identified:** Umbraco

### Website Analysis

The website is a blog running on **Umbraco CMS** with the domain **Anthem.com**.

#### Post 1: "We are hiring"

- **Author:** Jane Doe
- **Email found:** `JD@anthem.com`
- **Flag in `og:description` meta tag:** `THM{L0L_WH0_US3S_M3T4}`

#### Post 2: "A cheers to our IT department"

- **Author:** James Orchard Halliwell (real-life author of the "Solomon Grundy" nursery rhyme)
- **Flag in `og:description` meta tag:** `THM{AN0TH3R_M3TA}`
- The post contains a poem dedicated to the **admin** — the poem is "Solomon Grundy", hinting that the admin's name is **Solomon Grundy**

#### Search Bar (present on every page)

- **Flag hidden in the search placeholder:** `THM{G!T_G00D}`

#### Author Profile: `/authors/jane-doe/`

- **Flag in the Website field:** `THM{L0L_WH0_D15}`

### OSINT — Deriving Admin Credentials

1. Email pattern observed: **Jane Doe** → `JD@anthem.com` (initials + domain)
2. Admin name identified: **Solomon Grundy** (from the nursery rhyme)
3. Admin email derived: **`SG@anthem.com`**
4. Password from `robots.txt`: **`UmbracoIsTheBest!`**

---

## Initial Access — RDP

Connected to the machine using the discovered credentials:

```bash
xfreerdp /u:SG /p:'UmbracoIsTheBest!' /v:<TARGET_IP>
```

### User Flag

```cmd
type C:\Users\SG\Desktop\user.txt
```

**Flag:** `THM{N00T_NO0T}`

---

## Privilege Escalation

### Finding the Admin Password

A hidden directory was found at the root of the C: drive:

```cmd
dir /a C:\
```

This revealed a `C:\backup` directory containing `restore.txt`. The file was not readable by the current user:

```cmd
C:\backup> type restore.txt
Access is denied.
```

Used `icacls` to grant read permissions:

```cmd
icacls C:\backup\restore.txt /grant SG:R
```

```cmd
C:\backup> type restore.txt
ChangeMeBaby1MoreTime
```

**Admin password:** `ChangeMeBaby1MoreTime`

### Root Flag

Connected via RDP as Administrator:

```bash
xfreerdp /u:Administrator /p:'ChangeMeBaby1MoreTime' /v:<TARGET_IP>
```

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

**Flag:** `THM{Y0U_4R3_1337}`

---

## Summary

| Item | Value |
|------|-------|
| Domain | Anthem.com |
| CMS | Umbraco |
| Admin Name | Solomon Grundy |
| Admin Email | SG@anthem.com |
| User Password | UmbracoIsTheBest! |
| Admin Password | ChangeMeBaby1MoreTime |
| Flag 1 | THM{L0L_WH0_US3S_M3T4} |
| Flag 2 | THM{G!T_G00D} |
| Flag 3 | THM{AN0TH3R_M3TA} |
| Flag 4 | THM{L0L_WH0_D15} |
| User Flag | THM{N00T_NO0T} |
| Root Flag | THM{Y0U_4R3_1337} |

---

## Key Takeaways

- **Always check `robots.txt`** — it can contain sensitive information beyond just crawl directives.
- **Inspect HTML source and meta tags** — flags and credentials are often hidden in places not visible on the rendered page.
- **OSINT matters** — recognizing the "Solomon Grundy" poem led to identifying the admin's name and deriving their email.
- **Check for hidden files and directories** — Windows hidden folders (`dir /a`) can contain sensitive data.
- **Windows ACLs can be modified** — `icacls` allows changing file permissions when direct access is denied.
