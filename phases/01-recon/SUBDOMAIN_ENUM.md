# Subdomain Enumeration

## Objective
Discover all subdomains associated with the target domain to expand the attack surface within authorized scope.

---

## 1. Passive Subdomain Discovery

### subfinder
```bash
subfinder -d <domain> -silent -o evidence/subdomains_subfinder.txt
```

### amass (passive mode)
```bash
amass enum -passive -d <domain> -o evidence/subdomains_amass.txt
```

### Certificate Transparency
```bash
curl -s "https://crt.sh/?q=%25.<domain>&output=json" | \
  python3 -c "import sys,json; [print(x['name_value']) for x in json.load(sys.stdin)]" | \
  sort -u > evidence/subdomains_crt.txt
```

### Merge & Deduplicate
```bash
cat evidence/subdomains_*.txt | sort -u > evidence/subdomains_all.txt
wc -l evidence/subdomains_all.txt
```

---

## 2. DNS Resolution

```bash
# Resolve discovered subdomains
dnsx -l evidence/subdomains_all.txt -silent -o evidence/subdomains_resolved.txt

# Check for wildcard DNS
dig +short random-nonexistent-sub.<domain>
# If this returns an IP, wildcard DNS is enabled — filter accordingly
```

---

## 3. Subdomain Takeover Check

```bash
# Check for dangling CNAME records
for sub in $(cat evidence/subdomains_resolved.txt); do
  CNAME=$(dig +short CNAME $sub)
  if [ -n "$CNAME" ]; then
    echo "$sub → $CNAME"
  fi
done

# Automated check with subjack (if installed)
subjack -w evidence/subdomains_resolved.txt -t 20 -timeout 30 -ssl -v
```

### Known Takeover Signatures
| Service | CNAME Pattern | Indicator |
|---------|--------------|-----------|
| GitHub Pages | *.github.io | 404 "There isn't a GitHub Pages site here" |
| Heroku | *.herokuapp.com | "No such app" |
| AWS S3 | *.s3.amazonaws.com | "NoSuchBucket" |
| Azure | *.azurewebsites.net | "404 Web Site not found" |
| Shopify | *.myshopify.com | "Sorry, this shop is currently unavailable" |

---

## 4. Scope Filtering

After discovery, filter subdomains against scope:

```bash
# Compare against in-scope list
while read sub; do
  # Check if subdomain is in scope — update targets/domain.md
  echo "$sub — IN SCOPE / OUT OF SCOPE"
done < evidence/subdomains_resolved.txt
```

---

## Results

| # | Subdomain | IP | CNAME | In Scope | Purpose |
|---|-----------|-----|-------|----------|---------|
| 1 | | | | | |

---

## Checklist

- [ ] Passive subdomain enumeration complete (subfinder, amass, crt.sh)
- [ ] Results merged and deduplicated
- [ ] DNS resolution performed
- [ ] Wildcard DNS checked
- [ ] Subdomain takeover indicators checked
- [ ] Results filtered against scope
- [ ] In-scope subdomains added to targets/domain.md
