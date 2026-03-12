# Service Enumeration

## Objective
Identify all services, open ports, and protocols running on in-scope targets.

---

## 1. Port Scanning (Authorized Scope Only)

> Only scan targets listed in scope/targets.md. Use rate-limited, non-aggressive scans.

### Web Application Ports
```bash
# Check common web ports
for PORT in 80 443 8080 8443 8000 8888 3000 5000 9090; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "https://<target>:$PORT/" 2>/dev/null || echo "CLOSED")
  echo "Port $PORT: $STATUS"
done
```

### Service Version Detection
```bash
# Targeted version detection on known open ports
curl -sI "https://<target>" | head -20
curl -sI "http://<target>" | head -20
```

---

## 2. HTTP Method Enumeration

```bash
# Test allowed HTTP methods
for METHOD in GET POST PUT DELETE PATCH OPTIONS HEAD TRACE; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X $METHOD "https://<target>/api/")
  echo "$METHOD: $STATUS"
done
```

### OPTIONS Response Analysis
```bash
curl -si -X OPTIONS "https://<target>/api/" | grep -i "allow\|access-control"
```

---

## 3. Virtual Host Discovery

```bash
# Test for virtual hosts
ffuf -w /usr/share/wordlists/vhosts.txt \
  -u "https://<target_IP>/" \
  -H "Host: FUZZ.<domain>" \
  -mc 200,301,302,403 \
  -rate 10
```

---

## Results

| # | Service | Port | Protocol | Version | Notes |
|---|---------|------|----------|---------|-------|
| 1 | | | | | |

---

## Checklist
- [ ] Common web ports checked
- [ ] HTTP methods enumerated
- [ ] Virtual hosts tested
- [ ] Service versions noted
- [ ] Results logged to targets/endpoints.md
