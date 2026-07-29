TL;DR — Attack chain
vhost/SAN recon
   └─▶ netops-dev "Firewall" panel  (UFW web front-end, allowlist-gated)
        └─▶ legit function abuse:  sudo ufw allow ftp   → opens the deliberately-denied port 21
             └─▶ anonymous FTP (active mode)  → world-readable id_rsa_backup
                  └─▶ ssh challenger  → user.txt
                       └─▶ posts.php leaks cobra's SSH password (world-readable source)
                            └─▶ su cobra
                                 └─▶ sudo NOPASSWD /usr/bin/apt  (GTFOBins) → root.txt
