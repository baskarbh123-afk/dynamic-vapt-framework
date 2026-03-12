# API Enumeration

## Objective
Discover, document, and analyze all API endpoints including REST, GraphQL, and WebSocket interfaces.

---

## 1. API Documentation Discovery

```bash
# Check for exposed API docs
for path in /swagger /swagger-ui /swagger-ui.html /swagger.json \
  /api-docs /api/docs /openapi.json /openapi.yaml \
  /.well-known/openapi.json /v1/api-docs /v2/api-docs \
  /graphql /graphiql /playground /altair; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://<target>$path")
  if [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ]; then
    echo "[FOUND] $path → $STATUS"
  fi
  sleep 0.2
done
```

### Download API Schema
```bash
# OpenAPI / Swagger
curl -s "https://<target>/openapi.json" | python3 -m json.tool > evidence/api_schema.json

# GraphQL introspection
curl -s -X POST "https://<target>/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}' \
  | python3 -m json.tool > evidence/graphql_schema.json
```

---

## 2. REST API Enumeration

### Version Discovery
```bash
# Check for API versioning
for ver in v1 v2 v3 api/v1 api/v2; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://<target>/$ver/")
  echo "$ver: $STATUS"
done
```

### Endpoint Brute Force
```bash
ffuf -w /usr/share/wordlists/api-endpoints.txt \
  -u "https://<target>/api/v1/FUZZ" \
  -mc 200,201,301,302,401,403,405 \
  -rate 10 \
  -H "Authorization: Bearer TOKEN" \
  -o evidence/http-logs/api_fuzz.json
```

### Method Testing Per Endpoint
```bash
# For each discovered endpoint, test all methods
ENDPOINT="https://<target>/api/v1/users"
for METHOD in GET POST PUT PATCH DELETE OPTIONS; do
  RESP=$(curl -s -o /dev/null -w "%{http_code}" -X $METHOD "$ENDPOINT" \
    -H "Authorization: Bearer TOKEN" \
    -H "Content-Type: application/json")
  echo "$METHOD $ENDPOINT → $RESP"
done
```

---

## 3. GraphQL Enumeration

### Introspection Query
```bash
curl -s -X POST "https://<target>/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind fields { name args { name type { name } } type { name kind ofType { name } } } } } }"}' \
  | python3 -m json.tool
```

### Field Discovery
```bash
# List all queries
curl -s -X POST "https://<target>/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name description args { name type { name } } } } } }"}' \
  | python3 -m json.tool
```

---

## 4. WebSocket Enumeration

```bash
# Check for WebSocket endpoints
curl -si -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  "https://<target>/ws"
```

Look for WebSocket at: `/ws`, `/socket`, `/socket.io`, `/hub`, `/signalr`

---

## API Endpoint Inventory

| # | Method | Endpoint | Auth | Params | Response | Notes |
|---|--------|----------|------|--------|----------|-------|
| 1 | | | | | | |

---

## Checklist
- [ ] API documentation endpoints checked
- [ ] API schema downloaded (if available)
- [ ] REST endpoints enumerated and methods tested
- [ ] GraphQL introspection tested
- [ ] WebSocket endpoints checked
- [ ] API versions identified
- [ ] Results documented in targets/endpoints.md
