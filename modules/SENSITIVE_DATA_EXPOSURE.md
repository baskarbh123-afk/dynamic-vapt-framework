# Sensitive Data Exposure Testing

## Objective

Identify locations where the application inadvertently exposes sensitive data — including PII in API responses, credentials in source/config files, secrets in JavaScript, debug output, logs, and error messages.

---

## 1. API Response Over-Exposure

### Check What Fields Are Returned

```bash
TOKEN="USER_TOKEN"

# Profile endpoint — check for unexpected sensitive fields
curl -s https://target/api/v1/me \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool | grep -iE \
  "password|hash|secret|token|ssn|dob|national_id|tax_id|credit_card|cvv|internal|debug|admin"

# User list — check what data is exposed about other users
curl -s "https://target/api/v1/users?limit=5" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool | grep -iE \
  "password|hash|phone|address|dob|ssn"

# Order history — check financial data exposure
curl -s https://target/api/v1/orders \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool | grep -iE \
  "card_number|cvv|full_card|bank_account|routing"
```

---

## 2. JavaScript Source Analysis

```bash
# Download all JS files referenced in HTML
curl -s https://target/ | grep -oE '"[^"]+\.js"' | tr -d '"' | while read JS; do
  # Handle relative URLs
  [[ "$JS" != http* ]] && JS="https://target$JS"
  echo "Scanning: $JS"
  curl -s "$JS" | grep -iE \
    "(api_key|apiKey|secret|password|token|aws_|private_key|auth_token|client_secret)\s*[:=]\s*['\"][^'\"]{6,}" \
    | head -5
done

# Search for hardcoded credentials patterns
curl -s https://target/static/app.js | grep -iE \
  "AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{48}|ghp_[a-zA-Z0-9]{36}|eyJ[a-zA-Z0-9]"
```

---

## 3. Source Code & Configuration Files

```bash
# Check for exposed files
SENSITIVE_FILES=(
  "/.env"
  "/.env.local"
  "/.env.production"
  "/.env.development"
  "/config/database.yml"
  "/config/secrets.yml"
  "/app/config/application.yml"
  "/settings.py"
  "/config.php"
  "/web.config"
  "/appsettings.json"
  "/application.properties"
  "/application.yml"
  "/.git/config"
  "/.git/HEAD"
  "/backup.sql"
  "/database.sql"
  "/dump.sql"
  "/debug.log"
  "/error.log"
  "/access.log"
  "/composer.lock"
  "/package-lock.json"
  "/yarn.lock"
  "/Gemfile.lock"
)

for FILE in "${SENSITIVE_FILES[@]}"; do
  RESP=$(curl -si "https://target$FILE" -o /dev/null -w "%{http_code}")
  if [[ "$RESP" == "200" ]]; then
    CONTENT=$(curl -s "https://target$FILE" | head -3)
    echo "EXPOSED [$RESP]: $FILE"
    echo "  Preview: $CONTENT"
    echo ""
  fi
  sleep 0.1
done
```

---

## 4. Error Message Analysis

```bash
# Trigger errors and analyze information disclosure

# SQL error
curl -si "https://target/api/users?id='" | grep -iE \
  "sql|mysql|postgresql|ora-|syntax|query|database|exception|stack"

# Path disclosure
curl -si "https://target/page?file=../../../../../nonexistent" | grep -iE \
  "/var/www|/home|/app|/usr/share|no such file|failed to open"

# Stack trace
curl -si -X POST "https://target/api/process" \
  -H "Content-Type: application/json" \
  -d '{}' | grep -iE "at [A-Z]|\.java:|\.py:|\.php:|traceback|exception"

# Version information in errors
curl -si "https://target/api/nonexistent" | grep -iE \
  "version|release|build|framework|express|flask|rails|spring"
```

---

## 5. HTTP Response Headers Disclosure

```bash
curl -si https://target/ | python3 << 'EOF'
import sys

print("\n=== INFORMATION DISCLOSURE IN HEADERS ===\n")
disclosure_headers = {
    'server': 'Web server type and version',
    'x-powered-by': 'Backend framework and version',
    'x-aspnet-version': '.NET version',
    'x-aspnetmvc-version': 'ASP.NET MVC version',
    'x-generator': 'CMS/generator',
    'x-drupal-cache': 'Drupal CMS detected',
    'x-magento-vary': 'Magento CMS detected',
    'x-pingback': 'WordPress pingback URL',
    'via': 'Proxy server information',
}

for line in sys.stdin:
    line = line.strip()
    if ': ' in line:
        header, value = line.split(': ', 1)
        h = header.lower()
        if h in disclosure_headers:
            print(f"⚠  {header}: {value}")
            print(f"   Risk: {disclosure_headers[h]}")
EOF
```

---

## 6. Cache & Browser Storage

```bash
# Check if sensitive responses are cacheable
SENSITIVE_ENDPOINTS=(
  "/dashboard"
  "/profile"
  "/api/v1/me"
  "/api/v1/payment-methods"
  "/account/settings"
)

for EP in "${SENSITIVE_ENDPOINTS[@]}"; do
  echo "=== $EP ==="
  curl -si "https://target$EP" \
    -H "Cookie: session=USER_TOKEN" | grep -iE \
    "cache-control|pragma|expires|etag"
  echo ""
done
```

**Vulnerable** if no `Cache-Control: no-store` on authenticated/sensitive endpoints.

---

## 7. Backup File Discovery

```bash
# Common backup file patterns
TARGET_FILES=("index.php" "login.php" "config.php" "admin.php" "db.php")
BACKUP_EXTS=(".bak" ".old" ".orig" ".backup" "~" ".swp" ".tmp" ".copy")

for FILE in "${TARGET_FILES[@]}"; do
  for EXT in "${BACKUP_EXTS[@]}"; do
    URL="https://target/$FILE$EXT"
    RESP=$(curl -si "$URL" -o /dev/null -w "%{http_code}")
    [[ "$RESP" == "200" ]] && echo "FOUND: $URL"
    sleep 0.1
  done
done
```

---

## 8. Internal Path Disclosure

```bash
# Check 404 and 500 error pages for path disclosure
curl -si "https://target/totally_nonexistent_path_xyz123" | grep -iE \
  "/var/www|/home/|/app/|/usr/share/nginx|documentroot|realpath"

# Check debug info
curl -si "https://target/api/debug" | grep HTTP
curl -si "https://target/actuator/env" | grep HTTP
```

---

## 9. Git Repository Exposure

```bash
# Check for exposed .git directory
curl -si https://target/.git/config | grep -iE "url|remote|origin"

# If exposed, reconstruct repository
# (Document finding — do NOT actually download repo content)
# Tool: git-dumper (documentation reference only)
# git-dumper https://target/.git /tmp/dumped_repo
```

---

## Evidence to Capture

- The exposed file/endpoint URL
- First 5 lines of content (blur actual credential values — show field names only)
- HTTP response showing 200 for sensitive file
- API response showing unexpectedly sensitive fields

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| .env file exposed | Pass/Fail | Critical |
| API returns password/hash fields | Pass/Fail | High |
| SQL error with query details | Pass/Fail | Medium |
| Stack trace with file paths | Pass/Fail | Low-Medium |
| Git repository exposed | Pass/Fail | High |
| Hardcoded secret in JS file | Pass/Fail | Critical |
| Sensitive response without Cache-Control | Pass/Fail | Medium |
| AWS/API key in JS source | Pass/Fail | Critical |
