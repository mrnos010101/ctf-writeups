TL;DR

The application defends a PHP login and message board with a multi-layer WAF but has no application-level controls behind it. The chain:

Excessive Data Exposure — the login API leaks a password_hint field the UI deliberately hides.
WAF bypass #1 — spoof a browser User-Agent to defeat non-browser blocking.
WAF bypass #2 — rotate X-Forwarded-For to defeat per-IP rate-limiting and brute-force a user password from its hint.
Stored XSS — the moderation queue renders raw input in an admin bot's browser.
WAF bypass #3 — eval(atob('<base64>')) + bracket notation to defeat content/tag signatures.
Session hijacking — steal the admin PHPSESSID (no HttpOnly) and replay it to reach /admin.php.
