# Subdomain Takeover Testing

## Objective

Identify dangling DNS records pointing to deprovisioned or unclaimed third-party services, allowing an attacker to claim the service and serve malicious content under the victim's subdomain — enabling cookie theft, phishing, CSP bypass, and credential harvesting.

---

## 1. How Subdomain Takeover Works

1. Target sets: `blog.target.com CNAME blog-service.example.com`
2. Target deletes/closes their account on `blog-service.example.com`
3. The CNAME DNS record is never removed
4. Attacker registers account on `blog-service.example.com` and claims `blog.target.com`
5. Attacker now controls content served at `blog.target.com`

**Impact:** Cookie theft (if `Domain=.target.com`), phishing on trusted domain, CSP/CORS bypass, OAuth redirect_uri claim.

---

## 2. Subdomain Enumeration

```bash
# Passive enumeration
subfinder -d target.com -silent -o /tmp/subs_passive.txt
echo "Passive subdomains: $(wc -l < /tmp/subs_passive.txt)"

# Amass passive
amass enum -passive -d target.com -o /tmp/subs_amass.txt

# Certificate transparency logs
curl -s "https://crt.sh/?q=%.target.com&output=json" \
  | python3 -c "import sys,json; [print(e['name_value']) for e in json.load(sys.stdin)]" \
  | sort -u > /tmp/subs_crt.txt

# Combine all sources
cat /tmp/subs_passive.txt /tmp/subs_amass.txt /tmp/subs_crt.txt | sort -u > /tmp/all_subs.txt
echo "Total unique subdomains: $(wc -l < /tmp/all_subs.txt)"
```

---

## 3. DNS Resolution & CNAME Analysis

```bash
# Resolve all subdomains and identify CNAME chains
dnsx -l /tmp/all_subs.txt -resp -silent -o /tmp/resolved.txt

# Find CNAMEs specifically
while read SUB; do
  CNAME=$(dig +short CNAME "$SUB" 2>/dev/null)
  if [[ -n "$CNAME" ]]; then
    echo "$SUB → CNAME → $CNAME"
    # Check if CNAME target resolves (if not → dangling CNAME)
    RESOLVED=$(dig +short "$CNAME" 2>/dev/null)
    if [[ -z "$RESOLVED" ]]; then
      echo "  ⚠ DANGLING CNAME: $CNAME does not resolve"
    fi
  fi
done < /tmp/all_subs.txt
```

---

## 4. Service-Based Takeover Fingerprints

When a CNAME points to a third-party service, check the HTTP response for "unclaimed" indicators:

```bash
# Check HTTP response on dangling subdomain
CANDIDATES=(
  "dev.target.com"
  "blog.target.com"
  "status.target.com"
  "help.target.com"
)

# Service-specific "not found" fingerprints
FINGERPRINTS=(
  "There isn't a GitHub Pages site here"        # GitHub Pages
  "NoSuchBucket"                                  # AWS S3
  "The specified bucket does not exist"          # AWS S3
  "404 Not Found"                                # Generic
  "Repository not found"                         # Bitbucket
  "The thing you were looking for is no longer"  # Tumblr
  "This shop is currently unavailable"           # Shopify
  "There is no portal here"                      # Azure
  "404 Page Not Found"                           # Fastly
  "Please renew your subscription"               # Squarespace
  "This domain is not configured"                # HubSpot
)

for SUB in "${CANDIDATES[@]}"; do
  RESP=$(curl -s --connect-timeout 5 --max-time 10 "https://$SUB" 2>/dev/null)
  for FP in "${FINGERPRINTS[@]}"; do
    if echo "$RESP" | grep -q "$FP"; then
      echo "POTENTIAL TAKEOVER: $SUB → $FP"
      break
    fi
  done
done
```

---

## 5. Service-Specific Takeover Procedures

### 5.1 GitHub Pages

**Fingerprint:** "There isn't a GitHub Pages site here"

```bash
# 1. Confirm CNAME value
dig CNAME subdomain.target.com
# → xyz.github.io  (or org.github.io)

# 2. Verify no GitHub repository claims this CNAME
# Check: https://github.com/[org]/[repo] — does it exist?

# 3. If unclaimed:
# - Create a GitHub repo with the correct name
# - Add a CNAME file: echo "subdomain.target.com" > CNAME
# - Enable GitHub Pages
# → subdomain.target.com now serves attacker's content

# Document at this step — DO NOT actually claim in production engagements
# Get explicit written authorization before demonstrating claimed takeover
```

### 5.2 AWS S3

**Fingerprint:** "NoSuchBucket" or "The specified bucket does not exist"

```bash
# 1. Identify bucket name from CNAME
dig CNAME subdomain.target.com
# → bucket-name.s3.amazonaws.com
# → bucket-name.s3-website-us-east-1.amazonaws.com

# 2. Confirm bucket doesn't exist
aws s3 ls s3://bucket-name 2>&1 | grep "NoSuchBucket"

# Document at this step — confirm and report
```

### 5.3 Azure / App Service

**Fingerprint:** "404 Web Site not found"

```bash
dig CNAME subdomain.target.com
# → something.azurewebsites.net

curl -si "https://something.azurewebsites.net" | grep "404"
# If 404 → slot may be unclaimed
```

### 5.4 Heroku

**Fingerprint:** "No such app"

```bash
dig CNAME subdomain.target.com
# → something.herokuapp.com

curl -si "https://something.herokuapp.com" | grep "No such app"
```

---

## 6. Automated Takeover Scanning

```bash
# subjack — automated subdomain takeover checker
subjack -w /tmp/all_subs.txt -t 100 -timeout 30 -ssl -c fingerprints.json -v 3

# subzy
subzy run --targets /tmp/all_subs.txt --verify --https

# nuclei — subdomain takeover templates
nuclei -l /tmp/all_subs.txt -t takeovers/ -silent
```

---

## 7. NS (Nameserver) Takeover

Less common but high severity — dangling NS records pointing to registrar:

```bash
# Find nameservers for target.com
dig NS target.com

# Check if the listed nameservers are actually registered/active
for NS in $(dig NS target.com +short); do
  echo "NS: $NS"
  # Check if NS domain is registered
  whois "${NS%%.}" 2>/dev/null | grep -iE "registrar|expiry|status"
done
```

---

## Evidence to Capture

- `dig CNAME subdomain.target.com` output showing the dangling CNAME
- HTTP response from the subdomain showing "unclaimed" fingerprint
- The specific third-party service the CNAME points to
- Do NOT actually claim the service — document the confirmed unclaimed state

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| Dangling CNAME with unclaimed fingerprint | Pass/Fail | High |
| GitHub Pages subdomain takeover | Pass/Fail | High |
| AWS S3 bucket takeover | Pass/Fail | High |
| Azure App Service takeover | Pass/Fail | High |
| NS record pointing to unregistered domain | Pass/Fail | Critical |
| Subdomain used in OAuth redirect_uri | Pass/Fail | Critical |
