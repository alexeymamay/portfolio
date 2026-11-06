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


GATE_STYLE = """
  <meta name="robots" content="noindex">
  <style>
    body.body{background:#fff}
    .hero-heading-right-2{padding-top:80px;padding-bottom:80px;margin-bottom:0}
    .hero-wrapper-2{align-items:flex-start;margin-bottom:0}
    .hero-split-2 .heading{margin-top:0}
    .hero-split-2 .heading,.hero-split-2 .heading-copy,.hero-split-2 .margin-bottom-24px,.hero-split-2 .title-small-2,.hero-split-2 .footer-link-2{text-align:left;margin-left:0;margin-right:0}
    .hero-split-2+.hero-split-2{display:grid;grid-template-columns:auto 1fr auto 1fr;column-gap:0;align-items:start}
    .hero-split-2+.hero-split-2>*{grid-column:1/-1}
    .hero-split-2+.hero-split-2>.title-small-2{grid-column:1;grid-row:4}
    .hero-split-2+.hero-split-2>.footer-link-2{grid-column:1;grid-row:5}
    .hero-split-2+.hero-split-2>.footer-wrapper-three{grid-column:3;grid-row:4/6;align-self:center;padding-top:0;margin:0}
    .hero-split-2+.hero-split-2>.gate-form{grid-column:1/-1;grid-row:6}
    .hero-split-2 .footer-social-block-three{margin:0;padding-top:0;justify-content:flex-start;align-items:center}
    .hero-split-2 .footer-social-link-three{padding-left:0;padding-right:30px}
    .hero-split-2 .footer-social-link-three:last-child{padding-right:0}
    .hero-split-2 .footer-social-link-three img{width:36px;height:36px}
    .hero-split-2 .heading{font-size:32px;line-height:34px}
    .hero-split-2 .heading-copy{font-size:30px;line-height:30px}
    .hero-split-2+.hero-split-2>.title-small-2{margin-top:12px;margin-bottom:0;padding-top:0}
    .hero-split-2+.hero-split-2>.footer-link-2{margin-top:6px}
    .gate-form{width:100%;margin-top:24px;display:flex;flex-direction:column}
    .gate-input{width:100%;font-family:"DM Sans",sans-serif;font-size:14px;font-weight:500;letter-spacing:2px;text-transform:uppercase;text-align:center;height:48px;padding:0 16px;border:1px solid #1a1b1f;border-radius:0;outline:none;background:#fff;-webkit-appearance:none;appearance:none}
    .gate-input::placeholder{color:#8a8b90}
    .gate-input:focus{box-shadow:inset 0 0 0 1px #1a1b1f}
    .gate-input:focus::placeholder{color:transparent}
    .gate-form .button-primary{margin:12px 0 0;width:100%;height:48px;padding:14px 25px;border:0;cursor:pointer;text-align:center}
    .gate-form .button-primary:disabled{opacity:.6;cursor:default}
    .gate-form{position:relative}
    .gate-err{position:absolute;top:100%;left:0;right:0;min-height:22px;margin-top:10px;font-family:"DM Sans",sans-serif;font-size:14px;color:#c0392b;text-align:center}
    @keyframes gateFadeIn{from{opacity:0}to{opacity:1}}
    .hero-split-2+.hero-split-2>.title-small-2,.hero-split-2+.hero-split-2>.footer-link-2,.hero-split-2+.hero-split-2>.footer-wrapper-three,.gate-input,.gate-form .button-primary{animation:gateFadeIn 1s ease both}
    .hero-split-2+.hero-split-2>.title-small-2{animation-delay:1.05s}
    .hero-split-2+.hero-split-2>.footer-link-2{animation-delay:1.15s}
    .hero-split-2+.hero-split-2>.footer-wrapper-three{animation-delay:1.25s}
    .gate-input{animation-delay:1.4s}
    .gate-form .button-primary{animation-delay:1.5s}
    @media (prefers-reduced-motion:reduce){.hero-split-2 *,.gate-form *{animation:none!important}}
    @media screen and (min-width:768px){.hero-split-2+.hero-split-2{grid-template-columns:auto 1fr auto 3fr}}
    @media screen and (min-width:992px){.hero-wrapper-2{align-items:stretch}.hero-split-2:first-child{justify-content:flex-end}}
    @media screen and (max-width:991px){.hero-heading-right-2{padding-top:0}}
    @media screen and (max-width:767px){.hero-heading-right-2{padding:0 15px 60px}.hero-split-2 .heading{font-size:30px;line-height:32px}.hero-split-2 .heading-copy{font-size:24px;line-height:26px}.hero-split-2{max-width:100%;width:100%}.hero-split-2 .heading{margin-top:20px;padding-top:0}}
  </style>
"""

GATE_FORM = """<form class="gate-form" id="gate">
            <input class="gate-input" id="pw" type="password" placeholder="Enter password" aria-label="Password" autocomplete="current-password" required>
            <button class="button-primary" id="go" type="submit">Access portfolio</button>
            <div class="gate-err" id="err"></div>
          </form>"""

GATE_SCRIPT = """  <script>
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
        go.disabled = false; go.textContent = "Access portfolio";
      });
    });
  })();
  </script>
"""


def build_gate(page, payload):
    """Password page = the source page's head + its hero section + the unlock form."""
    head_end = page.index("</head>")
    hero_start = page.index('<section id="Heading"')
    hero_end = page.index("</section>", hero_start) + len("</section>")
    hero = page[hero_start:hero_end].replace("<!-- GATE_FORM -->", GATE_FORM)
    scripts = "\n".join(re.findall(r'<script src="[^"]*(?:jquery|webflow)[^"]*"[^>]*></script>', page[hero_end:]))
    return (page[:head_end] + GATE_STYLE + "</head>\n<body class=\"body\">\n  " + hero + "\n  " + scripts + "\n"
            + GATE_SCRIPT.replace("__PAYLOAD__", payload) + "</body>\n</html>\n")



def lock(src, out):
    page = open(src, encoding="utf-8").read()
    salt, iv = os.urandom(16), os.urandom(12)
    ct = AESGCM(derive(get_password(), salt)).encrypt(iv, page.encode("utf-8"), None)
    payload = json.dumps({"v": 1, "iter": ITERATIONS, "salt": b64(salt), "iv": b64(iv), "data": b64(ct)})
    if "<!-- GATE_FORM -->" not in page:
        sys.exit("Source page needs a <!-- GATE_FORM --> marker in the hero section.")
    gate = build_gate(page, payload)
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
