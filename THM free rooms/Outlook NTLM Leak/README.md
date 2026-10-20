Vulnerability Overview
CVE-2023-23397 is a zero-click elevation of privilege vulnerability in Microsoft Outlook for Windows, patched in the March 2023 Patch Tuesday release. It was actively exploited in the wild by APT28 (Fancy Bear) against defense and financial sector targets in Europe prior to disclosure.

The vulnerability allows an attacker to coerce a victim's Outlook client into performing NTLM authentication against an attacker-controlled server, leaking the victim's Net-NTLMv2 hash — with absolutely no user interaction required.
