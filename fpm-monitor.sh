#!/bin/bash
# Server health monitor - logs key metrics every 3 minutes
# Keeps max 12 hours of data (240 entries at 3min intervals)
# Sends email alert when thresholds are breached (max once per 30 min)
# When load > threshold: also enables Cloudflare Under Attack Mode

source "$(dirname "$0")/.env"
FPM_WARN=$(( FPM_MAX * FPM_WARN_PCT / 100 ))

LOGFILE="${LOG_DIR}/server-monitor.log"
ALERTFILE="${LOG_DIR}/last-alert"
FPM_MEM_COUNT_FILE="${LOG_DIR}/fpm-mem-high-count"
FPM_WORKERS_COUNT_FILE="${LOG_DIR}/fpm-workers-high-count"
CF_UNDER_ATTACK_FILE="${LOG_DIR}/cf-under-attack-active"
LOW_LOAD_SINCE_FILE="${LOG_DIR}/low-load-since"

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# PHP-FPM workers
FPM_WORKERS=$(ps aux | grep "php-fpm: pool $FPM_POOL" | grep -v grep | wc -l)
FPM_MEM=$(ps -C php-fpm -o rss --no-headers 2>/dev/null | awk '{sum+=$1} END {printf "%d", sum/1024}')

# System memory & swap (MB)
read MEM_USED MEM_AVAIL SWAP_USED <<< $(free -m | awk '/^Mem:/{u=$3; a=$7} /^Swap:/{s=$3} END {print u, a, s}')

# Load average
LOAD=$(cat /proc/loadavg | cut -d' ' -f1-3)
LOAD1=$(echo "$LOAD" | cut -d' ' -f1)

# Network connections
CONN_ESTAB=$(ss -t state established | wc -l)
CONN_TIMEWAIT=$(ss -t state time-wait | wc -l)
CONN_TOTAL=$(ss -t | wc -l)

# Apache
HTTPD_WORKERS=$(ps -C httpd --no-headers 2>/dev/null | wc -l)

# MySQL thread count
MYSQL_CONN=$(ps -eL | grep -c mysqld 2>/dev/null || echo "0")

# Sphinx
SPHINX_UP=$(pgrep -c searchd 2>/dev/null || echo 0)

LOGLINE="${TIMESTAMP} fpm=${FPM_WORKERS} fpm_mem=${FPM_MEM}M mem_used=${MEM_USED}M mem_avail=${MEM_AVAIL}M swap=${SWAP_USED}M load=${LOAD} tcp_estab=${CONN_ESTAB} tcp_tw=${CONN_TIMEWAIT} tcp_total=${CONN_TOTAL} httpd=${HTTPD_WORKERS} mysql_threads=${MYSQL_CONN} sphinx=${SPHINX_UP}"

echo "$LOGLINE" >> "$LOGFILE"

# Trim to max lines
CURRENT=$(wc -l < "$LOGFILE" 2>/dev/null || echo 0)
if [ "$CURRENT" -gt "$MAX_LINES" ]; then
    tail -n "$MAX_LINES" "$LOGFILE" > "${LOGFILE}.tmp" && mv "${LOGFILE}.tmp" "$LOGFILE"
fi

# --- Cloudflare helpers ------------------------------------------------------

cf_set_under_attack() {
    curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$CF_ZONE/settings/security_level" \
        -H "Authorization: Bearer $CF_TOKEN" \
        -H "Content-Type: application/json" \
        --data '{"value":"under_attack"}' | \
        python3 -c "
import json,sys
d=json.load(sys.stdin)
print('success' if d.get('success') else 'FAILED: '+str(d.get('errors',d)))
" 2>/dev/null || echo "FAILED: curl error"
}

cf_set_normal() {
    curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$CF_ZONE/settings/security_level" \
        -H "Authorization: Bearer $CF_TOKEN" \
        -H "Content-Type: application/json" \
        --data '{"value":"medium"}' | \
        python3 -c "
import json,sys
d=json.load(sys.stdin)
print('success' if d.get('success') else 'FAILED: '+str(d.get('errors',d)))
" 2>/dev/null || echo "FAILED: curl error"
}

cf_top_ips() {
    local since until
    since=$(date -u -d '5 minutes ago' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -v-5M '+%Y-%m-%dT%H:%M:%SZ')
    until=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    curl -s -X POST "https://api.cloudflare.com/client/v4/graphql" \
        -H "Authorization: Bearer $CF_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"query\":\"{ viewer { zones(filter: {zoneTag: \\\"$CF_ZONE\\\"}) { httpRequestsAdaptiveGroups(limit: 10, filter: {datetime_geq: \\\"$since\\\", datetime_leq: \\\"$until\\\"}, orderBy: [count_DESC]) { count dimensions { clientIP clientCountryName } } } } }\"}" | \
        python3 -c "
import json,sys
try:
    groups=json.load(sys.stdin)['data']['viewer']['zones'][0]['httpRequestsAdaptiveGroups']
    for g in groups:
        print('  %5d reqs  %-42s %s' % (g['count'], g['dimensions']['clientIP'], g['dimensions']['clientCountryName']))
except Exception as e:
    print('  (unavailable: %s)' % e)
" 2>/dev/null
}

cf_top_useragents() {
    local since until
    since=$(date -u -d '5 minutes ago' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -v-5M '+%Y-%m-%dT%H:%M:%SZ')
    until=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    curl -s -X POST "https://api.cloudflare.com/client/v4/graphql" \
        -H "Authorization: Bearer $CF_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"query\":\"{ viewer { zones(filter: {zoneTag: \\\"$CF_ZONE\\\"}) { httpRequestsAdaptiveGroups(limit: 5, filter: {datetime_geq: \\\"$since\\\", datetime_leq: \\\"$until\\\"}, orderBy: [count_DESC]) { count dimensions { userAgent } } } } }\"}" | \
        python3 -c "
import json,sys
try:
    groups=json.load(sys.stdin)['data']['viewer']['zones'][0]['httpRequestsAdaptiveGroups']
    for g in groups:
        ua = g['dimensions']['userAgent'] or '(empty)'
        print('  %5d  %s' % (g['count'], ua[:120]))
except Exception as e:
    print('  (unavailable: %s)' % e)
" 2>/dev/null
}

cf_top_urls() {
    local since until
    since=$(date -u -d '5 minutes ago' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -v-5M '+%Y-%m-%dT%H:%M:%SZ')
    until=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    curl -s -X POST "https://api.cloudflare.com/client/v4/graphql" \
        -H "Authorization: Bearer $CF_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"query\":\"{ viewer { zones(filter: {zoneTag: \\\"$CF_ZONE\\\"}) { httpRequestsAdaptiveGroups(limit: 20, filter: {datetime_geq: \\\"$since\\\", datetime_leq: \\\"$until\\\"}, orderBy: [count_DESC]) { count dimensions { clientRequestPath clientRequestQuery clientRequestHTTPMethodName } } } } }\"}" | \
        python3 -c "
import json,sys
try:
    groups=json.load(sys.stdin)['data']['viewer']['zones'][0]['httpRequestsAdaptiveGroups']
    for g in groups:
        d = g['dimensions']
        q = ('?' + d['clientRequestQuery']) if d.get('clientRequestQuery') else ''
        print('  %5d  %-6s %s%s' % (g['count'], d['clientRequestHTTPMethodName'], d['clientRequestPath'], q))
except Exception as e:
    print('  (unavailable: %s)' % e)
" 2>/dev/null
}

cf_top_asns() {
    local since until
    since=$(date -u -d '5 minutes ago' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -v-5M '+%Y-%m-%dT%H:%M:%SZ')
    until=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    curl -s -X POST "https://api.cloudflare.com/client/v4/graphql" \
        -H "Authorization: Bearer $CF_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"query\":\"{ viewer { zones(filter: {zoneTag: \\\"$CF_ZONE\\\"}) { httpRequestsAdaptiveGroups(limit: 5, filter: {datetime_geq: \\\"$since\\\", datetime_leq: \\\"$until\\\"}, orderBy: [count_DESC]) { count dimensions { clientAsn clientASNDescription } } } } }\"}" | \
        python3 -c "
import json,sys
try:
    groups=json.load(sys.stdin)['data']['viewer']['zones'][0]['httpRequestsAdaptiveGroups']
    for g in groups:
        print('  %5d  ASN%-7s %s' % (g['count'], g['dimensions']['clientAsn'], g['dimensions']['clientASNDescription'] or '(unknown)'))
except Exception as e:
    print('  (unavailable: %s)' % e)
" 2>/dev/null
}

# --- Alerting ----------------------------------------------------------------
ALERTS=""
LOAD_HIGH=0
FPM_HIGH=0

# PHP-FPM near or at max — trigger at FPM_WARN_PCT%; at max fires immediately, below max requires 3 rounds
if [ "$FPM_WORKERS" -ge "$FPM_MAX" ]; then
    echo 0 > "$FPM_WORKERS_COUNT_FILE"
    ALERTS="${ALERTS}- PHP-FPM workers: ${FPM_WORKERS}/${FPM_MAX} (at max_children)\n"
    FPM_HIGH=1
elif [ "$FPM_WORKERS" -ge "$FPM_WARN" ]; then
    FPM_WORKERS_COUNT=$(( $(cat "$FPM_WORKERS_COUNT_FILE" 2>/dev/null || echo 0) + 1 ))
    echo "$FPM_WORKERS_COUNT" > "$FPM_WORKERS_COUNT_FILE"
    if [ "$FPM_WORKERS_COUNT" -ge 3 ]; then
        ALERTS="${ALERTS}- PHP-FPM workers: ${FPM_WORKERS}/${FPM_MAX} (near max for ${FPM_WORKERS_COUNT} consecutive rounds)\n"
        FPM_HIGH=1
    fi
else
    echo 0 > "$FPM_WORKERS_COUNT_FILE"
fi

# PHP-FPM memory over threshold — requires 3 consecutive rounds (~9 min)
if [ "$FPM_MEM" -gt "$FPM_MEM_THRESHOLD_MB" ]; then
    FPM_MEM_COUNT=$(( $(cat "$FPM_MEM_COUNT_FILE" 2>/dev/null || echo 0) + 1 ))
    echo "$FPM_MEM_COUNT" > "$FPM_MEM_COUNT_FILE"
    if [ "$FPM_MEM_COUNT" -ge 3 ]; then
        ALERTS="${ALERTS}- PHP-FPM total memory: ${FPM_MEM}MB (high for ${FPM_MEM_COUNT} consecutive rounds)\n"
    fi
else
    echo 0 > "$FPM_MEM_COUNT_FILE"
fi

# Available memory under threshold
if [ "$MEM_AVAIL" -lt "$MEM_AVAIL_THRESHOLD_MB" ]; then
    ALERTS="${ALERTS}- Available memory: ${MEM_AVAIL}MB (low)\n"
fi

# Swap over threshold
if [ "$SWAP_USED" -gt "$SWAP_THRESHOLD_MB" ]; then
    ALERTS="${ALERTS}- Swap usage: ${SWAP_USED}MB (high)\n"
fi

# Load average over threshold — also triggers CF Under Attack Mode
if [ "$(echo "$LOAD1 > $LOAD_HIGH_THRESHOLD" | bc 2>/dev/null)" = "1" ]; then
    ALERTS="${ALERTS}- Load average: ${LOAD} (high)\n"
    LOAD_HIGH=1
fi

# TCP established connections over threshold
if [ "$CONN_ESTAB" -gt "$TCP_ESTAB_THRESHOLD" ]; then
    ALERTS="${ALERTS}- TCP established: ${CONN_ESTAB} (spike)\n"
fi

# Apache workers over threshold
if [ "$HTTPD_WORKERS" -gt "$HTTPD_THRESHOLD" ]; then
    ALERTS="${ALERTS}- Apache workers: ${HTTPD_WORKERS} (high)\n"
fi

# MySQL threads over threshold
if [ "$MYSQL_CONN" -gt "$MYSQL_THRESHOLD" ]; then
    ALERTS="${ALERTS}- MySQL threads: ${MYSQL_CONN} (high)\n"
fi

# Sphinx down
if [ "$SPHINX_UP" -eq 0 ]; then
    ALERTS="${ALERTS}- Sphinx searchd is DOWN\n"
fi

# Send alert if any issues detected (with cooldown)
if [ -n "$ALERTS" ]; then
    LAST_ALERT=$(cat "$ALERTFILE" 2>/dev/null || echo 0)
    NOW=$(date +%s)
    ELAPSED=$((NOW - LAST_ALERT))

    if [ "$ELAPSED" -ge "$ALERT_COOLDOWN" ]; then
        echo "$NOW" > "$ALERTFILE"

        CF_SECTION=""
        SUBJECT="${SERVER_NAME} - Server Alert"

        if [ "$LOAD_HIGH" = "1" ]; then
            CF_RESULT=$(cf_set_under_attack)
            date +%s > "$CF_UNDER_ATTACK_FILE"
            rm -f "$LOW_LOAD_SINCE_FILE"
            TOP_IPS=$(cf_top_ips)
            TOP_URLS=$(cf_top_urls)
            TOP_UAS=$(cf_top_useragents)
            TOP_ASNS=$(cf_top_asns)
            SUBJECT="${SERVER_NAME} - HIGH LOAD (${LOAD1}) - CF Under Attack Mode ENABLED"
            CF_SECTION="=== CLOUDFLARE ACTION ===\nUnder Attack Mode: ENABLED at ${TIMESTAMP}\nCF API result: ${CF_RESULT}\nWill be disabled automatically once load stays below ${LOAD_LOW_THRESHOLD} for 10+ minutes.\nManage: ${CF_DASH_URL}\n\n=== TOP CLIENT IPs (10) — last 5 min ===\n${TOP_IPS}\n\n=== TOP REQUESTED URLs — last 5 min ===\n${TOP_URLS}\n\n=== TOP USER AGENTS (5) — last 5 min ===\n${TOP_UAS}\n\n=== TOP ASNs (5) — last 5 min ===\n${TOP_ASNS}\n\n"
        elif [ "$FPM_HIGH" = "1" ]; then
            TOP_IPS=$(cf_top_ips)
            TOP_URLS=$(cf_top_urls)
            TOP_UAS=$(cf_top_useragents)
            TOP_ASNS=$(cf_top_asns)
            SUBJECT="${SERVER_NAME} - FPM WORKERS HIGH (${FPM_WORKERS}/${FPM_MAX}) - load ${LOAD1}"
            CF_SECTION="=== TOP CLIENT IPs (10) — last 5 min ===\n${TOP_IPS}\n\n=== TOP REQUESTED URLs — last 5 min ===\n${TOP_URLS}\n\n=== TOP USER AGENTS (5) — last 5 min ===\n${TOP_UAS}\n\n=== TOP ASNs (5) — last 5 min ===\n${TOP_ASNS}\n\n"
        fi

        BODY="Server health alert on ${SERVER_NAME} at ${TIMESTAMP}\n\nIssues detected:\n${ALERTS}\n${CF_SECTION}Full status:\n${LOGLINE}\n\nRecent history (last 5 entries):\n$(tail -5 "$LOGFILE")"
        (echo "Subject: ${SUBJECT}"; echo "To: ${ALERT_EMAIL}"; echo "From: ${ALERT_FROM}"; echo; echo -e "$BODY") | /usr/sbin/sendmail "$ALERT_EMAIL"
    fi
fi

# --- CF Under Attack auto-disable (load < 1.0 for 10+ consecutive minutes) ----
if [ -f "$CF_UNDER_ATTACK_FILE" ]; then
    LOW_LOAD=$(awk "BEGIN {print ($LOAD1 < $LOAD_LOW_THRESHOLD) ? 1 : 0}")
    if [ "$LOW_LOAD" = "1" ]; then
        if [ ! -f "$LOW_LOAD_SINCE_FILE" ]; then
            date +%s > "$LOW_LOAD_SINCE_FILE"
        else
            LOW_SINCE=$(cat "$LOW_LOAD_SINCE_FILE")
            NOW=$(date +%s)
            if [ $((NOW - LOW_SINCE)) -ge 600 ]; then
                ATTACK_STARTED=$(cat "$CF_UNDER_ATTACK_FILE")
                ATTACK_DURATION_SEC=$((NOW - ATTACK_STARTED))
                ATTACK_DURATION_MIN=$((ATTACK_DURATION_SEC / 60))
                ATTACK_DURATION_FMT="${ATTACK_DURATION_MIN}m $((ATTACK_DURATION_SEC % 60))s"
                CF_RESULT=$(cf_set_normal)
                rm -f "$CF_UNDER_ATTACK_FILE" "$LOW_LOAD_SINCE_FILE"
                BODY="CF Under Attack Mode has been automatically DISABLED on ${SERVER_NAME} at ${TIMESTAMP}\n\nDuration: ${ATTACK_DURATION_FMT}\nLoad has been below ${LOAD_LOW_THRESHOLD} for 10+ minutes (current: ${LOAD1}).\nCF API result: ${CF_RESULT}\n\nFull status:\n${LOGLINE}"
                (echo "Subject: ${SERVER_NAME} - CF Under Attack Mode DISABLED (auto) — was active ${ATTACK_DURATION_FMT}"; echo "To: ${ALERT_EMAIL}"; echo "From: ${ALERT_FROM}"; echo; echo -e "$BODY") | /usr/sbin/sendmail "$ALERT_EMAIL"
            fi
        fi
    else
        rm -f "$LOW_LOAD_SINCE_FILE"
    fi
fi
