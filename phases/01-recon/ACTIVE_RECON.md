# Active Reconnaissance

## Objective
Directly interact with the target application to fingerprint technologies, discover endpoints, and map the application structure.

> **Note**: This module sends traffic to the target. Ensure scope confirmation before executing.

---

## 1. Technology Fingerprinting

### HTTP Header Analysis
```bash
# Capture response headers
curl -sI https://<target> | grep -iE "server|x-powered-by|x-aspnet|x-generator|x-drupal|x-framework"

# Full header dump
curl -si -o /dev/null -D - https://<target>
```

### Automated Fingerprinting
```bash
# Wappalyzer / WhatWeb
whatweb -a 3 https://<target>

# Nuclei technology detection
nuclei -u https://<target> -t technologies/ -silent -rate-limit 5

# WAF detection
wafw00f https://<target>
```

### Manual Indicators
| Indicator | Where to Check | Example |
|-----------|----------------|---------|
| Server header | Response headers | `nginx/1.24` |
| X-Powered-By | Response headers | `Express`, `PHP/8.1` |
| Cookie names | Set-Cookie | `JSESSIONID` (Java), `laravel_session` (PHP) |
| Error pages | Trigger 404/500 | Stack trace reveals framework |
| Meta tags | HTML source | `<meta name="generator">` |
| JS libraries | HTML source / JS files | React, Vue, Angular |
| URL patterns | URLs | `/wp-admin` (WordPress) |

### Results

| Field | Value | Evidence |
|-------|-------|----------|
| Backend Language | | |
| Framework | | |
| Web Server | | |
| Frontend Framework | | |
| Database (inferred) | | |
| WAF | | |

---

## 2. Endpoint Discovery

### Directory Brute Force
```bash
# dirsearch (rate-limited)
dirsearch -u https://<target> \
  -e php,asp,aspx,js,json,html,txt,bak,config,env,yml \
  -t 5 --delay=0.5 \
  --exclude-status=400,404

# ffuf (rate-limited)
ffuf -w /usr/share/wordlists/dirb/common.txt \
  -u https://<target>/FUZZ \
  -mc 200,301,302,403 \
  -rate 10 \
  -o evidence/http-logs/ffuf_dirs.json
```

### JavaScript File Analysis
```bash
# Extract JS file URLs from HTML source
curl -s https://<target> | grep -oP 'src="[^"]*\.js"' | sort -u

# Extract endpoints from JS files
curl -s https://<target>/static/app.js | \
  grep -Eo '"(/[a-zA-Z0-9_/{}.-]+)"' | sort -u

# Extract API routes from JS bundles
curl -s https://<target>/static/app.js | \
  grep -Eo '(api|v[0-9]+)/[a-zA-Z0-9_/{}.-]+' | sort -u
```

### Parameter Discovery
```bash
ffuf -w /usr/share/wordlists/params.txt \
  -u "https://<target>/endpoint?FUZZ=test" \
  -mc 200,301,302 \
  -rate 10
```

---

## 3. Application Mapping

### Sitemap & Robots
```bash
curl -s https://<target>/robots.txt
curl -s https://<target>/sitemap.xml
curl -s https://<target>/.well-known/security.txt
```

### Common Sensitive Paths
```bash
# Check for exposed files
for path in .env .git/config .git/HEAD .svn/entries \
  wp-config.php web.config appsettings.json \
  .DS_Store Thumbs.db package.json composer.json \
  /swagger-ui/ /api-docs /graphql /.well-known/openapi.json; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://<target>/$path")
  echo "$STATUS — /$path"
  sleep 0.2
done
```

---

## 4. SSL/TLS Analysis

```bash
# sslyze scan
sslyze --regular <target>:443

# Quick cipher check
nmap --script ssl-enum-ciphers -p 443 <target>
```

---

## Discovered Endpoints

| # | Path | Method | Status | Auth | Notes |
|---|------|--------|--------|------|-------|
| 1 | | | | | |

*(Transfer confirmed endpoints to targets/endpoints.md)*

---

## Checklist

- [ ] Technology stack fingerprinted
- [ ] WAF detected/confirmed
- [ ] Directory brute force completed
- [ ] JS files analyzed for hidden endpoints
- [ ] robots.txt / sitemap.xml checked
- [ ] Sensitive file paths checked
- [ ] SSL/TLS configuration assessed
- [ ] Results logged and transferred to targets/
