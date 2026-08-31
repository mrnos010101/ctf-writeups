Summary

WhyHackMe is a multi-stage boot2root challenge that chains together anonymous FTP information disclosure, stored XSS via an unsanitised registration username field (leveraged as a client-side SSRF to exfiltrate localhost-restricted credentials), firewall manipulation through sudo iptables, TLS traffic decryption of a PCAP file using a world-readable SSL private key, and finally abuse of an encrypted CGI webshell left behind by a previous attacker — all the way to root via unrestricted sudo privileges on the www-data account.
