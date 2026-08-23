Overview

Breakme is a multi-stage boot2root machine on TryHackMe. The attack surface spans a WordPress installation, a localhost-only PHP administration panel, a SUID binary with a race condition, and a Python sandbox running under sudo. Each stage requires a distinct exploitation technique and introduces a progressively harder defensive control to bypass.

The machine's name is a literal invitation: every defensive measure on the box is broken in a non-obvious way.
