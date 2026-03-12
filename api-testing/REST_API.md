# REST API Security Testing

## Objective

Systematically test REST API endpoints for authentication/authorization flaws, input validation issues, information leakage, and improper HTTP method handling.

---

## 1. API Recon & Endpoint Discovery

### Documentation Endpoints
```bash
# Check for OpenAPI / Swagger documentation
for EP in /swagger-ui.html /swagger-ui/ /api-docs /v2/api-docs /v3/api-docs \
           /openapi.json /openapi.yaml /swagger.json /swagger.yaml /api/docs; do
  RESP=$(curl -si "https://target$EP" -o /dev/null -w "%{http_code}")
  [[ "$RESP" == "200" ]] && echo "FOUND: $EP (HTTP $RESP)"
  sleep 0.1
done

# If Swagger is found, extract all endpoints
curl -s https://target/v3/api-docs | python3 -c "
import sys, json
data = json.load(sys.stdin)
for path, methods in data.get('paths',{}).items():
    for method in methods:
        print(f'{method.upper()} {path}')
" | sort
```

### JS File Endpoint Extraction
```bash
# Extract API endpoints from JS bundles
for JSFILE in $(curl -s https://target/ | grep -oE 'src="[^"]+\.js"' | cut -d'"' -f2); do
  curl -s "https://target$JSFILE" | grep -oE '"/api/[^"]+' | sort -u
done
```

---

## 2. HTTP Method Testing

For every discovered endpoint, test all HTTP methods:

```bash
API_ENDPOINT="/api/v1/users/1"
TOKEN="USER_TOKEN"

for METHOD in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
  RESP=$(curl -si -X $METHOD "https://target$API_ENDPOINT" \
    -H "Authorization: Bearer $TOKEN" \
    -w "\n%{http_code}" 2>/dev/null | tail -1)
  echo "$METHOD $API_ENDPOINT → HTTP $RESP"
  sleep 0.2
done
```

**Interesting findings:**
- `OPTIONS` returning allowed methods with unexpected entries
- `TRACE` enabled (XST — Cross-Site Tracing)
- `DELETE` on a collection endpoint

---

## 3. Authentication Testing on API

```bash
# Test each endpoint without authentication
API_ENDPOINTS=(
  "GET /api/v1/users"
  "GET /api/v1/users/1"
  "POST /api/v1/users"
  "GET /api/v1/admin/settings"
  "GET /api/v1/reports"
)

for EP_DEF in "${API_ENDPOINTS[@]}"; do
  METHOD=$(echo $EP_DEF | cut -d' ' -f1)
  EP=$(echo $EP_DEF | cut -d' ' -f2)
  RESP=$(curl -si -X $METHOD "https://target$EP" -w "%{http_code}" | tail -1)
  echo "$METHOD $EP → HTTP $RESP (no auth)"
  sleep 0.2
done
```

---

## 4. Parameter Tampering

### Query Parameter Manipulation
```bash
# Test with extra/unexpected parameters
curl -si "https://target/api/v1/users?admin=true&role=admin&debug=1" \
  -H "Authorization: Bearer USER_TOKEN" | grep -E "HTTP|admin|debug"

# Type confusion
curl -si "https://target/api/v1/users?id[]=1&id[]=2" \
  -H "Authorization: Bearer USER_TOKEN" | grep HTTP

# Array injection
curl -si "https://target/api/v1/users?id=1,2,3,4,5" \
  -H "Authorization: Bearer USER_TOKEN" | grep HTTP
```

### Body Parameter Injection
```bash
# Test mass assignment — add extra fields
curl -si -X PUT https://target/api/v1/profile \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test User",
    "isAdmin": true,
    "role": "admin",
    "credits": 99999,
    "verified": true
  }' | grep HTTP
```

---

## 5. Content-Type Confusion

```bash
# API expects JSON — test with form encoding
curl -si -X POST https://target/api/v1/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin" | grep HTTP

# API expects JSON — test with XML
curl -si -X POST https://target/api/v1/users \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><user><name>test</name></user>' | grep HTTP

# API expects JSON — test with no Content-Type
curl -si -X POST https://target/api/v1/login \
  -d '{"username":"admin","password":"admin"}' | grep HTTP
```

---

## 6. Pagination & Filtering Abuse

```bash
# Test for data over-fetching
# Large page size
curl -si "https://target/api/v1/users?limit=99999&page=1" \
  -H "Authorization: Bearer USER_TOKEN" | grep HTTP

# Negative page
curl -si "https://target/api/v1/users?limit=10&page=-1" \
  -H "Authorization: Bearer USER_TOKEN" | grep HTTP

# SQL injection in sort/filter parameters
curl -si "https://target/api/v1/users?sort=name';--" \
  -H "Authorization: Bearer USER_TOKEN" | grep HTTP

curl -si "https://target/api/v1/users?filter=email LIKE '%'" \
  -H "Authorization: Bearer USER_TOKEN" | grep HTTP
```

---

## 7. API Versioning Testing

```bash
# Test deprecated API versions
for VERSION in v1 v2 v3 v0 beta alpha; do
  RESP=$(curl -si "https://target/api/$VERSION/users" \
    -o /dev/null -w "%{http_code}")
  [[ "$RESP" != "404" ]] && echo "API /$VERSION exists: HTTP $RESP"
done

# Older versions may lack security controls
curl -si https://target/api/v1/admin/users \
  -H "Authorization: Bearer USER_TOKEN" | grep HTTP
# vs
curl -si https://target/api/v2/admin/users \
  -H "Authorization: Bearer USER_TOKEN" | grep HTTP
```

---

## 8. Response Data Analysis

Check API responses for unintended data exposure:

```bash
# Profile endpoint — check what fields are returned
curl -s https://target/api/v1/me \
  -H "Authorization: Bearer USER_TOKEN" | python3 -m json.tool | grep -iE \
  "password|hash|secret|key|token|ssn|dob|internal|debug"

# User list endpoint
curl -s "https://target/api/v1/users?limit=5" \
  -H "Authorization: Bearer USER_TOKEN" | python3 -m json.tool
```

---

## 9. Error Message Analysis

```bash
# Trigger various error conditions and analyze messages
# Invalid type
curl -si "https://target/api/v1/users/abc" \
  -H "Authorization: Bearer USER_TOKEN" | grep -iE "exception|error|sql|trace"

# Special characters
curl -si "https://target/api/v1/users/1%27" \
  -H "Authorization: Bearer USER_TOKEN" | grep -iE "sql|syntax|exception"

# Very large payload
python3 -c "print('A'*50000)" | curl -si -X POST https://target/api/v1/users \
  -H "Content-Type: application/json" --data-binary @- | grep -iE "error|HTTP"
```

---

## 10. API Rate Limiting

See `modules/RATE_LIMITING.md` for detailed testing.

```bash
# Quick check — 30 rapid requests
for i in $(seq 1 30); do
  RESP=$(curl -si "https://target/api/v1/search?q=test" \
    -H "Authorization: Bearer USER_TOKEN" -w "%{http_code}" | tail -1)
  echo "Request $i: HTTP $RESP"
  [[ "$RESP" == "429" ]] && echo "Rate limit at $i" && break
done
```

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| Unauthenticated API access | Pass/Fail | High-Critical |
| Mass assignment via API | Pass/Fail | High |
| Deprecated API version bypass | Pass/Fail | Medium-High |
| SQL injection in API parameters | Pass/Fail | Critical |
| Sensitive data in API responses | Pass/Fail | Medium-High |
| TRACE method enabled | Pass/Fail | Medium |
| No API rate limiting | Pass/Fail | Medium |
