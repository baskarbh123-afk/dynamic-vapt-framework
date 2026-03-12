# Business Logic Vulnerability Testing

## Objective

Identify flaws in the application's business logic — vulnerabilities that arise from incorrect assumptions about workflow, state, or data processing that cannot be detected by generic security scanners.

---

## 1. Price & Value Manipulation

### 1.1 Negative / Zero Quantity
```bash
# Test cart/order with negative quantity
curl -si -X POST https://target/api/cart \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"product_id":"PROD_001","quantity":-1}' | grep -E "HTTP|total|price"

# Zero quantity
curl -si -X POST https://target/api/cart \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"product_id":"PROD_001","quantity":0}' | grep HTTP
```

### 1.2 Price Parameter Manipulation
```bash
# Intercept checkout and change price
curl -si -X POST https://target/api/checkout \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"product_id":"PROD_001","quantity":1,"price":0.01}' | grep HTTP

# Test with negative price (credit / refund?)
curl -si -X POST https://target/api/checkout \
  -d '{"product_id":"PROD_001","quantity":1,"price":-99.99}' | grep HTTP
```

### 1.3 Currency Manipulation
```bash
# Change currency to a weaker one
curl -si -X POST https://target/api/checkout \
  -d '{"amount":100,"currency":"JPY"}' | grep HTTP
# $100 USD changed to 100 JPY (~$0.66)
```

### 1.4 Coupon / Discount Abuse
```bash
# Apply same coupon multiple times
for i in $(seq 1 5); do
  curl -si -X POST https://target/api/apply-coupon \
    -H "Authorization: Bearer USER_TOKEN" \
    -d 'coupon=SAVE20' | grep -E "HTTP|discount|error"
done

# Apply coupon from another user's account
curl -si -X POST https://target/api/apply-coupon \
  -H "Authorization: Bearer USER_A_TOKEN" \
  -d 'coupon=OTHER_USER_COUPON' | grep HTTP
```

---

## 2. Workflow / State Machine Bypass

### 2.1 Skip Workflow Steps
```bash
# Normal flow: /checkout/step1 → /checkout/step2 → /checkout/payment → /checkout/confirm
# Test: jump directly to /checkout/confirm
curl -si https://target/checkout/confirm \
  -H "Cookie: session=USER_TOKEN" | grep HTTP

# Test: access step 3 without completing step 2
curl -si https://target/api/checkout/step3 \
  -H "Authorization: Bearer USER_TOKEN" | grep HTTP
```

### 2.2 Email Verification Bypass
```bash
# After registration, try accessing protected features before verifying email
curl -si https://target/dashboard \
  -H "Cookie: session=UNVERIFIED_USER_SESSION" | grep HTTP

# Try API calls without email verification
curl -si https://target/api/create-post \
  -H "Authorization: Bearer UNVERIFIED_TOKEN" | grep HTTP
```

### 2.3 Order State Manipulation
```bash
# Cancel a completed/shipped order
curl -si -X POST https://target/api/orders/COMPLETED_ORDER_ID/cancel \
  -H "Authorization: Bearer USER_TOKEN" | grep HTTP

# Re-use a consumed redemption code
curl -si -X POST https://target/api/redeem \
  -d 'code=ALREADY_USED_CODE' | grep HTTP
```

---

## 3. Race Conditions

Test for TOCTOU (Time of Check / Time of Use) vulnerabilities:

### 3.1 Coupon Race Condition
```bash
# Apply the same coupon simultaneously via parallel requests
# Limit to 5 parallel requests
for i in $(seq 1 5); do
  curl -si -X POST https://target/api/apply-coupon \
    -H "Authorization: Bearer USER_TOKEN" \
    -d 'coupon=SINGLE_USE_CODE' &
done
wait
```

### 3.2 Double Spend (Transfer Race)
```bash
# Send duplicate transfer requests simultaneously
for i in $(seq 1 3); do
  curl -si -X POST https://target/api/transfer \
    -H "Authorization: Bearer USER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"to":"RECIPIENT","amount":100}' &
done
wait
```

---

## 4. Referral / Loyalty Program Abuse

```bash
# Self-referral
curl -si -X POST https://target/api/register \
  -H "Content-Type: application/json" \
  -d '{"email":"newuser@test.com","referral_code":"YOUR_OWN_REFERRAL_CODE"}' | grep HTTP

# Referral credit before referee fulfills condition
curl -si https://target/api/referrals/status \
  -H "Authorization: Bearer USER_TOKEN" | grep HTTP
```

---

## 5. Quantity & Stock Limit Bypass

```bash
# Bypass "max 1 per customer" limit
curl -si -X POST https://target/api/cart \
  -H "Authorization: Bearer USER_TOKEN" \
  -d '{"product_id":"LIMITED_ITEM","quantity":99}' | grep HTTP

# Test via separate orders
curl -si -X POST https://target/api/order \
  -H "Authorization: Bearer USER_TOKEN" \
  -d '{"product_id":"LIMITED_ITEM","quantity":1}' | grep HTTP
# ... repeat 5 times
```

---

## 6. Response Manipulation for Business Logic

```bash
# Intercept a "payment declined" response and change to "approved"
# (Requires proxy — Burp Suite)
# Example — if the app relies on a client-side success field:
# Response: {"status":"declined","transaction_id":"txn_001"}
# Modify: {"status":"approved","transaction_id":"txn_001"}
# Submit modified response and check if order is placed
```

---

## 7. Free / Premium Feature Access

```bash
# Test premium features with free account
PREMIUM_ENDPOINTS=(
  "/api/export/full"
  "/api/reports/advanced"
  "/api/team-collaboration"
  "/api/unlimited-projects"
)

for EP in "${PREMIUM_ENDPOINTS[@]}"; do
  echo "Testing: $EP"
  curl -si "https://target$EP" \
    -H "Authorization: Bearer FREE_TIER_TOKEN" | grep -E "HTTP|upgrade|premium"
  sleep 0.2
done
```

---

## 8. Account Deletion & Data Retention

```bash
# After account deletion, test if:
# 1. Active session tokens still work
# 2. Shared content is still accessible
# 3. API key still works

# Delete account
curl -si -X DELETE https://target/api/account \
  -H "Authorization: Bearer USER_TOKEN" | grep HTTP

# Test token after deletion (wait 5 seconds)
sleep 5
curl -si https://target/api/me \
  -H "Authorization: Bearer $USER_TOKEN" | grep HTTP
```

---

## Evidence to Capture

- The normal workflow / expected behavior documentation
- The bypass step performed (skipped step, manipulated value)
- Before and after state (e.g., balance before and after race condition)
- HTTP requests and responses showing the bypass

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| Negative price manipulation | Pass/Fail | High |
| Workflow step bypass | Pass/Fail | Medium-High |
| Race condition on coupon/transfer | Pass/Fail | High |
| Email verification bypass | Pass/Fail | Medium |
| Coupon reuse / stacking | Pass/Fail | Medium |
| Self-referral abuse | Pass/Fail | Low-Medium |
| Deleted account token still valid | Pass/Fail | High |
