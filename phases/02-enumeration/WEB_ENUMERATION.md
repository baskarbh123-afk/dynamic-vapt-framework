# Web Application Enumeration

## Objective
Deep-dive into the web application structure: map all pages, forms, parameters, and functional areas.

---

## 1. Sitemap Construction

### Automated Crawling
```bash
# Use Burp Suite Spider or ZAP Spider in passive mode
# Configure scope to match scope/targets.md
# Export discovered URLs to targets/endpoints.md
```

### Manual Browsing
Navigate through the application as each role defined in credentials/accounts.md:
1. Anonymous (unauthenticated)
2. Low-privilege user
3. Admin user

Document every:
- Page URL and purpose
- Form action and parameters
- JavaScript-triggered requests (XHR/Fetch)
- WebSocket connections
- File download/upload endpoints

---

## 2. Form & Parameter Inventory

| # | URL | Method | Parameters | Type | Input Validation | Notes |
|---|-----|--------|------------|------|-----------------|-------|
| 1 | /login | POST | username, password, _csrf | Form | Client-side | |
| 2 | /search | GET | q | Query | None observed | |
| 3 | /profile | PUT | name, email, bio | JSON | Server-side | |

*(Document every form and parameter)*

---

## 3. Input Vector Mapping

For each parameter, classify the input vector:

| Vector Type | Parameters | Risk |
|-------------|-----------|------|
| URL path parameters | /users/{id} | IDOR, path traversal |
| Query parameters | ?search=, ?page= | XSS, SQLi |
| POST body (form) | username, password | SQLi, auth bypass |
| POST body (JSON) | {"role": "user"} | Mass assignment |
| HTTP headers | X-Forwarded-For, Referer | Header injection |
| Cookie values | session, preferences | Session tampering |
| File upload | avatar, document | RCE, XSS |

---

## 4. Error Handling Enumeration

```bash
# Trigger various error conditions
curl -s "https://<target>/nonexistent-page-12345"          # 404
curl -s "https://<target>/api/v1/users/invalid"            # Invalid input
curl -s -X POST "https://<target>/api/v1/login" -d '{}'    # Empty body
curl -s "https://<target>/api/v1/users/-1"                 # Negative ID
curl -s "https://<target>/api/v1/users/999999999"          # Large ID
```

Note: Do error pages reveal stack traces, framework info, or internal paths?

---

## 5. Client-Side Analysis

### JavaScript Review
```bash
# Download and analyze main JS bundles
curl -s "https://<target>/static/js/main.js" | \
  grep -Eo '(api_key|apiKey|secret|password|token|auth)["\s]*[:=]["\s]*"[^"]*"'

# Look for hardcoded credentials, API keys, debug flags
curl -s "https://<target>/static/js/main.js" | \
  grep -Eo '(DEBUG|VERBOSE|TEST_MODE|DEV)\s*[:=]\s*(true|false|1|0)'
```

### Local/Session Storage
Check browser DevTools for sensitive data in:
- localStorage
- sessionStorage
- IndexedDB

---

## Results

Update the following files with enumeration data:
- targets/endpoints.md — Full endpoint inventory
- targets/attack_surface.md — Input vectors and entry points

---

## Checklist
- [ ] Application crawled as each role
- [ ] All forms and parameters documented
- [ ] Input vectors classified
- [ ] Error handling behavior noted
- [ ] Client-side JavaScript reviewed
- [ ] Results transferred to targets/
