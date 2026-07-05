Category: Web Application / API Abuse
Difficulty: Medium
Skills: SSRF filter bypass, OS command injection, authentication-flow abuse (mass assignment), source-backup disclosure, incomplete-filter analysis



MediaHub presents itself as an internal portal for journalists. The real story is in how the front end talks to its back-end APIs: the access controls live in the wrong layer, and a series of small request changes walks an unauthenticated visitor all the way to remote code execution.
