Tags: SSH Key Cracking, Source Code Disclosure, LXD Privilege Escalation, Container Escape
Overview
A beginner-friendly Boot2Root box themed around a gaming community website ("House of Danak"). The attack chain involves finding an encrypted SSH private key exposed in a web directory, discovering the username in an HTML comment, cracking the key passphrase with a wordlist conveniently left on the server, and escalating privileges via LXD group membership to achieve full root access.
