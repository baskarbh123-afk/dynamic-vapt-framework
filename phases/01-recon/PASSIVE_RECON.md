# Passive Reconnaissance

## Objective
Collect publicly available information about the target without sending any traffic directly to the target infrastructure.

---

## 1. DNS Reconnaissance

### DNS Record Enumeration
```bash
# A, AAAA, MX, NS, TXT, SOA records
dig +noall +answer <domain> ANY
dig +noall +answer <domain> A
dig +noall +answer <domain> AAAA
dig +noall +answer <domain> MX
dig +noall +answer <domain> NS
dig +noall +answer <domain> TXT
dig +noall +answer <domain> SOA
dig +noall +answer <domain> CNAME

# Reverse DNS
dig -x <IP_ADDRESS> +short

# Zone transfer attempt (usually blocked)
dig axfr @<nameserver> <domain>
```

### Certificate Transparency Logs
```bash
# Search crt.sh for issued certificates
curl -s "https://crt.sh/?q=%25.<domain>&output=json" | \
  python3 -c "import sys,json; [print(x['name_value']) for x in json.load(sys.stdin)]" | \
  sort -u
```

---

## 2. WHOIS & Registration Data

```bash
whois <domain>
# Note: registrant, nameservers, registration dates, registrar
```

### Key Data Points
| Field | Value | Notes |
|-------|-------|-------|
| Registrar | | |
| Registration Date | | |
| Expiry Date | | |
| Nameservers | | |
| DNSSEC | | |

---

## 3. Search Engine Dorking

### Google Dorks
```
site:<domain> filetype:pdf
site:<domain> filetype:xlsx OR filetype:csv
site:<domain> inurl:admin
site:<domain> inurl:login
site:<domain> inurl:api
site:<domain> intitle:"index of"
site:<domain> ext:env OR ext:config OR ext:yml
site:<domain> "password" OR "api_key" OR "secret"
```

### GitHub/GitLab Dorking
```
"<domain>" filename:.env
"<domain>" filename:config
"<domain>" password OR secret OR api_key
org:<org_name> filename:.env
```

---

## 4. Public Data Sources

### Wayback Machine
```bash
# Historical snapshots
curl -s "https://web.archive.org/cdx/search/cdx?url=<domain>/*&output=text&fl=original&collapse=urlkey" | \
  head -100
```

### Shodan (if authorized)
```bash
# Check for exposed services
shodan host <IP_ADDRESS>
```

---

## 5. Social Media & Job Postings

Look for technology stack hints in:
- LinkedIn job postings (tech requirements reveal stack)
- Company engineering blogs
- Conference talks by employees
- GitHub organization repositories

---

## Findings Log

| # | Finding | Source | Relevance | Notes |
|---|---------|--------|-----------|-------|
| 1 | | | | |
| 2 | | | | |

---

## Checklist

- [ ] DNS records enumerated
- [ ] Certificate transparency searched
- [ ] WHOIS data collected
- [ ] Search engine dorking complete
- [ ] Public data sources checked
- [ ] Findings logged to logs/engagement.log
