#!/usr/bin/env python3
"""Password-lock a static page for GitHub Pages.

The page HTML is encrypted with AES-256-GCM (key from PBKDF2-SHA256).
The published file holds only the ciphertext plus a small unlock screen;
the browser decrypts it after the visitor enters the password.

Usage:
  python3 tools/lock.py lock   SOURCE.html  OUTPUT.html   # encrypt
  python3 tools/lock.py unlock LOCKED.html  SOURCE.html   # decrypt for editing

The password is read from the LOCK_PASSWORD environment variable,
or asked for interactively. It is never stored in the repo.
"""
import base64, getpass, json, os, re, sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 600_000
MARKER = "LOCKED_PAYLOAD"


def derive(password, salt, iterations=ITERATIONS):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password.encode("utf-8"))


def b64(b):
    return base64.b64encode(b).decode()


def get_password():
    return os.environ.get("LOCK_PASSWORD") or getpass.getpass("Password: ")


GATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>__TITLE__</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex">
  <link href="images/favicon.png" rel="shortcut icon" type="image/x-icon">
  <link href="images/webclip.png" rel="apple-touch-icon">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;700&display=swap" rel="stylesheet">
  <style>
    *{box-sizing:border-box}
    html,body{height:100%;margin:0}
    body{font-family:"DM Sans",sans-serif;background:#fff;color:#1a1b1f;display:flex;align-items:center;justify-content:center;padding:24px}
    .gate{width:100%;max-width:360px;text-align:center}
    .gate img{height:40px;margin-bottom:32px}
    h1{font-size:28px;font-weight:700;margin:0 0 8px}
    p{font-size:16px;line-height:1.5;color:#5c5d62;margin:0 0 24px}
    input{width:100%;font:inherit;font-size:16px;padding:14px 16px;border:1px solid #d1d3d8;border-radius:10px;outline:none}
    input:focus{border-color:#1a1b1f}
    button{width:100%;margin-top:12px;font:inherit;font-size:16px;font-weight:500;padding:14px 16px;border:0;border-radius:10px;background:#1a1b1f;color:#fff;cursor:pointer}
    button:disabled{opacity:.6;cursor:default}
    .err{min-height:24px;margin-top:12px;font-size:14px;color:#c0392b}
    a{color:inherit}
  </style>
</head>
<body>
  <form class="gate" id="gate">
    <img src="images/byAM_headerlogo.svg" alt="Alexey Mamay">
    <h1>Alexey Mamay</h1>
    <p>This portfolio is password protected.<br>Contact <a href="mailto:alexey.mamay@icloud.com">alexey.mamay@icloud.com</a> for access.</p>
    <input id="pw" type="password" placeholder="Password" autocomplete="current-password" autofocus required>
    <button id="go" type="submit">View portfolio</button>
    <div class="err" id="err"></div>
  </form>
  <script>
  var LOCKED_PAYLOAD = __PAYLOAD__;
  (function () {
    var P = LOCKED_PAYLOAD, STORE = "am_unlock_" + P.salt.slice(0, 8);
    function fromB64(s) { return Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); }); }
    function toB64(b) { return btoa(String.fromCharCode.apply(null, new Uint8Array(b))); }
    function show(html) { document.open(); document.write(html); document.close(); }
    function decryptWith(rawKey) {
      return crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["decrypt"]).then(function (key) {
        return crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(P.iv) }, key, fromB64(P.data));
      }).then(function (buf) { return new TextDecoder().decode(buf); });
    }
    function deriveKey(pw) {
      return crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveBits"]).then(function (base) {
        return crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: fromB64(P.salt), iterations: P.iter }, base, 256);
      });
    }
    var err = document.getElementById("err"), go = document.getElementById("go");
    if (!window.crypto || !crypto.subtle) { err.textContent = "Please open this page over https."; return; }
    var saved = null;
    try { saved = localStorage.getItem(STORE); } catch (e) {}
    if (saved) {
      decryptWith(fromB64(saved)).then(show, function () { try { localStorage.removeItem(STORE); } catch (e) {} });
    }
    document.getElementById("gate").addEventListener("submit", function (e) {
      e.preventDefault();
      err.textContent = ""; go.disabled = true; go.textContent = "Unlocking…";
      var raw;
      deriveKey(document.getElementById("pw").value).then(function (bits) {
        raw = bits; return decryptWith(bits);
      }).then(function (html) {
        try { localStorage.setItem(STORE, toB64(raw)); } catch (e) {}
        show(html);
      }, function () {
        err.textContent = "Incorrect password. Please try again.";
        go.disabled = false; go.textContent = "View portfolio";
      });
    });
  })();
  </script>
</body>
</html>
"""


def lock(src, out):
    page = open(src, encoding="utf-8").read()
    m = re.search(r"<title>(.*?)</title>", page, re.S)
    title = m.group(1).strip() if m else "Protected page"
    salt, iv = os.urandom(16), os.urandom(12)
    ct = AESGCM(derive(get_password(), salt)).encrypt(iv, page.encode("utf-8"), None)
    payload = json.dumps({"v": 1, "iter": ITERATIONS, "salt": b64(salt), "iv": b64(iv), "data": b64(ct)})
    gate = GATE.replace("__TITLE__", title).replace("__PAYLOAD__", payload)
    open(out, "w", encoding="utf-8").write(gate)
    print(f"Locked {src} -> {out}")


def unlock(locked, out):
    text = open(locked, encoding="utf-8").read()
    m = re.search(MARKER + r" = (\{.*?\});", text)
    if not m:
        sys.exit("No locked payload found.")
    p = json.loads(m.group(1))
    key = derive(get_password(), base64.b64decode(p["salt"]), p["iter"])
    page = AESGCM(key).decrypt(base64.b64decode(p["iv"]), base64.b64decode(p["data"]), None)
    open(out, "w", encoding="utf-8").write(page.decode("utf-8"))
    print(f"Unlocked {locked} -> {out}")


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] not in ("lock", "unlock"):
        sys.exit(__doc__)
    {"lock": lock, "unlock": unlock}[sys.argv[1]](sys.argv[2], sys.argv[3])
