# Authentication Testing

## Objective

Identify flaws in authentication mechanisms that allow attackers to gain unauthorized access, bypass login, enumerate valid credentials, or subvert account recovery flows.

---

## 1. Username Enumeration

### Test Method
Submit login requests with a valid username + wrong password, then an invalid username + wrong password. Compare responses for differences.

```bash
# Valid user
curl -si -X POST https://target/login \
  -d "username=admin@target.com&password=wrongpass" | grep -E "HTTP|body|error"

# Invalid user
curl -si -X POST https://target/login \
  -d "username=notauser@target.com&password=wrongpass" | grep -E "HTTP|body|error"
```

**Indicators of enumeration vulnerability:**
- Different HTTP response codes (200 vs 302 vs 401)
- Different response body text ("Invalid password" vs "User not found")
- Different response sizes or timing
- Response includes "email not found" vs "incorrect password"

**Also test on:**
- Password reset form: "We sent a reset link" vs "No account found"
- Registration form: "Email already in use"

---

## 2. Password Policy Assessment

### Test Procedure
1. Register a new account with weak passwords and observe what is accepted:
   - `a` — single character
   - `12345678` — numeric only
   - `password` — dictionary word
   - `Password1` — common pattern
   - `abc@123` — minimal complexity

2. Check if policy is enforced server-side or client-side only:
   - Intercept registration request and modify `Content-Type` / bypass JS validation
   - Submit directly via API if available

**Expected:** Minimum 12 characters, complexity requirements, server-side enforcement.

---

## 3. Account Lockout Testing

### Test Procedure
```bash
# Attempt 20 logins with wrong password (manual, low-rate)
for i in $(seq 1 20); do
  curl -si -X POST https://target/login \
    -d "username=testuser@target.com&password=wrongpass$i" \
    | grep -E "HTTP|locked|attempts"
  sleep 0.5
done
```

**Indicators of missing lockout:**
- No lockout after 10+ failed attempts
- No CAPTCHA challenge triggered
- No temporary IP block
- No alert sent to account owner

**Caution:** Use only a test account. Do not lockout real user accounts.

---

## 4. Password Reset Flow Testing

### 4.1 Password Reset Token Analysis
```bash
# Request two reset tokens for the same account
# Compare tokens for predictability
TOKEN1="first_token_from_email"
TOKEN2="second_token_from_email"
echo "Token1: $TOKEN1"
echo "Token2: $TOKEN2"
```

**Test cases:**
- Is the reset token sufficiently random (≥128 bits entropy)?
- Does the token expire after use?
- Does the token expire after a set time (15-60 min)?
- Can the same token be used multiple times?
- Is the token sent in the URL (visible in server logs)?

### 4.2 Host Header Injection in Password Reset
```http
POST /forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

**Vulnerable:** If the reset link in the email uses the `Host` header value, the link will point to `attacker.com`, allowing token interception.

### 4.3 Password Reset Token Leakage via Referer
After clicking a reset link:
1. Check if the application redirects to an external page after password reset
2. The reset token in the URL may be sent in the `Referer` header to that external page

---

## 5. MFA Bypass Testing

### 5.1 Direct Post-Auth URL Access
1. Start login with MFA-enabled account
2. After username/password verified but before MFA step, copy the session cookie
3. In a new browser, use that cookie to directly access the dashboard URL
4. **Vulnerable:** If MFA step is skipped and dashboard loads

### 5.2 OTP Reuse
1. Complete MFA with a valid OTP — note the OTP value
2. Log out and log in again
3. Submit the previously used OTP
4. **Vulnerable:** If previously used OTP is accepted

### 5.3 OTP Brute Force (Safe Test)
1. Trigger OTP (email/SMS)
2. Submit 5 wrong OTPs and observe response
3. Is there rate limiting or lockout after failed OTP attempts?

### 5.4 Response Manipulation
1. Intercept the MFA verification request
2. Observe the response when MFA fails (e.g., `{"success":false}`)
3. Modify the response to `{"success":true}` and observe if access is granted

---

## 6. Default / Hardcoded Credentials

```bash
# Test common default credentials
for cred in "admin:admin" "admin:password" "admin:admin123" "root:root" "test:test"; do
  USER=$(echo $cred | cut -d: -f1)
  PASS=$(echo $cred | cut -d: -f2)
  curl -si -X POST https://target/login \
    -d "username=$USER&password=$PASS" \
    | grep -E "HTTP|dashboard|Welcome"
  sleep 0.3
done
```

---

## 7. Authentication Bypass via Parameter Tampering

### Test Procedure
1. Intercept login request
2. Attempt parameter modifications:
   - Add `&admin=true` or `&role=admin`
   - Change `username=admin` without a password field
   - Submit empty password field
   - Inject SQL into username: `admin'--`
   - Inject NoSQL operators: `{"username":{"$ne":""},"password":{"$ne":""}}`

---

## Evidence to Capture

For each finding:
- Full HTTP request (method, URL, headers, body)
- Full HTTP response (status code, headers, body)
- Screenshot of successful bypass or enumeration
- Session token obtained (first 8 chars only for documentation)

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| Username enumeration via login | Pass/Fail | Medium |
| Username enumeration via reset | Pass/Fail | Low-Medium |
| Weak password policy | Pass/Fail | Medium |
| No account lockout | Pass/Fail | Medium |
| Reset token weak/reusable | Pass/Fail | High |
| Host header injection in reset | Pass/Fail | High |
| MFA bypass (direct URL) | Pass/Fail | Critical |
| MFA bypass (response tamper) | Pass/Fail | Critical |
| Default credentials accepted | Pass/Fail | Critical |
