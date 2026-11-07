Executive Summary

A demo vehicle's CAN bus is exposed over TCP. The provided key fob can Lock, Horn, and toggle the Immobiliser — but has no Unlock button. The manufacturer claims the rolling code "can't be copied." In reality, the scheme uses trivial XOR masking rather than proper cryptographic rolling codes (KeeLoq, AUT64, Hitag2). A live counter broadcast in the clear on the bus, combined with the auth formula leaking from every legitimate press, allows full key recovery from a single sniffed frame and forgery of arbitrary commands — including the missing Unlock.

Vulnerability Class: CWE-327 (Use of a Broken Cryptographic Algorithm), CWE-306 (Missing Authentication for Critical Function)
ATT&CK (ICS): T0855 (Unauthorized Command Message), T0843 (Program Download)
CVSS 3.1: 8.1 (AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H)
