# TryHackMe — Ninja Skills

**Room:** [Ninja Skills](https://tryhackme.com/room/dvwa)  
**Difficulty:** Easy  
**Category:** Linux Fundamentals

## Overview

This room tests your ability to work with Linux command-line tools to locate files, inspect their properties, and extract information. You are given a list of 12 filenames scattered across the filesystem and must answer questions about their ownership, contents, permissions, and metadata.

### Target Files

```
8V2L  bny0  c4ZX  D8B3  FHl1  oiMO  PFbD  rmfX  SRSq  uqyw  v2Vb  X1Uy
```

---

## Task Solutions

### 1. Which files are owned by the group `best-group`?

Used `find` with the `-group` flag to filter files by group ownership:

```bash
find / -type f \( -name "8V2L" -o -name "bny0" -o -name "c4ZX" -o -name "D8B3" -o -name "FHl1" -o -name "oiMO" -o -name "PFbD" -o -name "rmfX" -o -name "SRSq" -o -name "uqyw" -o -name "v2Vb" -o -name "X1Uy" \) -group best-group 2>/dev/null
```

**Output:**
```
/mnt/D8B3
/home/v2Vb
```

**Answer:** `D8B3 v2Vb`

---

### 2. Which file contains an IP address?

Used `find` combined with `-exec grep` to search inside each file for an IP address pattern:

```bash
find / -type f \( -name "8V2L" -o -name "bny0" -o -name "c4ZX" -o -name "D8B3" -o -name "FHl1" -o -name "oiMO" -o -name "PFbD" -o -name "rmfX" -o -name "SRSq" -o -name "uqyw" -o -name "v2Vb" -o -name "X1Uy" \) 2>/dev/null -exec grep -l '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' {} \;
```

**Output:**
```
/opt/oiMO
```

**Answer:** `oiMO`

---

### 3. Which file has the SHA1 hash `9d54da7584015647ba052173b84d45e8007eba94`?

Computed SHA1 hashes for all files and filtered for the target hash:

```bash
find / -type f \( -name "8V2L" -o -name "bny0" -o -name "c4ZX" -o -name "D8B3" -o -name "FHl1" -o -name "oiMO" -o -name "PFbD" -o -name "rmfX" -o -name "SRSq" -o -name "uqyw" -o -name "v2Vb" -o -name "X1Uy" \) 2>/dev/null -exec sha1sum {} \; | grep 9d54da7584015647ba052173b84d45e8007eba94
```

**Answer:** *(insert result from your machine)*

---

### 4. Which file has 230 lines?

Counted lines in all files using `wc -l`:

```bash
find / -type f \( -name "8V2L" -o -name "bny0" -o -name "c4ZX" -o -name "D8B3" -o -name "FHl1" -o -name "oiMO" -o -name "PFbD" -o -name "rmfX" -o -name "SRSq" -o -name "uqyw" -o -name "v2Vb" -o -name "X1Uy" \) 2>/dev/null -exec wc -l {} +
```

All found files showed 209 lines. The file `bny0` was not found on the filesystem, making it the answer by elimination.

**Answer:** `bny0`

---

### 5. Which file's owner has an ID of 502?

Listed all files with numeric UID/GID using `ls -ln`:

```bash
find / -type f \( -name "8V2L" -o -name "bny0" -o -name "c4ZX" -o -name "D8B3" -o -name "FHl1" -o -name "oiMO" -o -name "PFbD" -o -name "rmfX" -o -name "SRSq" -o -name "uqyw" -o -name "v2Vb" -o -name "X1Uy" \) 2>/dev/null -exec ls -ln {} + | grep " 502 "
```

**Output:**
```
-rw-rw-r-- 1 501 502 13545 Oct 23  2019 /home/v2Vb
-rw-rw-r-- 1 501 502 13545 Oct 23  2019 /mnt/D8B3
-rw-rw-r-- 1 502 501 13545 Oct 23  2019 /X1Uy
```

The format is `UID GID` — only `/X1Uy` has **UID 502**.

**Answer:** `X1Uy`

---

### 6. Which file is executable by everyone?

Used `find` with `-perm -o=x` to locate files with the execute bit set for others:

```bash
find / -type f \( -name "8V2L" -o -name "bny0" -o -name "c4ZX" -o -name "D8B3" -o -name "FHl1" -o -name "oiMO" -o -name "PFbD" -o -name "rmfX" -o -name "SRSq" -o -name "uqyw" -o -name "v2Vb" -o -name "X1Uy" \) -perm -o=x 2>/dev/null
```

**Output:**
```
/etc/8V2L
```

**Answer:** `8V2L`

---

## Key Takeaways

- **`find` is extremely versatile** — combining it with `-exec` allows running any command against found files, eliminating the need to manually locate each one.
- **`-group`**, **`-perm`**, and **`-exec ls -ln`** are powerful filters for ownership and permission questions.
- **`grep -l`** returns only filenames (not matched lines), which is useful when scanning many files.
- **Process of elimination** works when a file cannot be found on the filesystem — if the question asks "which file has X" and one file is missing, it's likely the answer.
