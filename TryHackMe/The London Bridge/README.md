Overview

The London Bridge is a medium-difficulty boot2root CTF room on TryHackMe. The attack chain involves discovering a Server-Side Request Forgery (SSRF) vulnerability with a trivially bypassable loopback filter, leveraging it to access an internal HTTP file server that exposes SSH keys, escalating privileges via a Linux kernel user namespace vulnerability (CVE-2018-18955), and extracting saved browser credentials from a Firefox profile.
