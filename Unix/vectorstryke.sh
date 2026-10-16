#!/usr/bin/env sh
# VectorStryke - Lightweight Anti-Ransomware sensor for POSIX Unix
# Real-time process heuristics + optional central console heartbeat.
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"
DATA="$ROOT/data"
LOG="$ROOT/logs/engine.log"
STATUS="$DATA/status"
PIDFILE="$DATA/vectorstryke.pid"
ALERTS="$DATA/alerts"
CONFIG="$ROOT/config/engine.conf"

mkdir -p "$DATA" "$ROOT/logs" "$ALERTS" "$ROOT/config"

CONSOLE_ENABLED=0
CONSOLE_URL=""
TENANT_ID="default"
AGENT_ID=""
ENROLL_TOKEN=""
AGENT_ENABLED=1
AUTO_APPROVE=0
AUTO_APPROVE_KILL=0
POLL_SEC=15
HIGH_RSS_KB=700000

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$1] $2" | tee -a "$LOG"; }

write_default_config() {
    cat > "$CONFIG" <<EOF
# VectorStryke Unix sensor config
CONSOLE_ENABLED=0
CONSOLE_URL=
TENANT_ID=default
AGENT_ID=
ENROLL_TOKEN=
AGENT_ENABLED=1
AUTO_APPROVE=0
AUTO_APPROVE_KILL=0
POLL_SEC=15
HIGH_RSS_KB=700000
EOF
}

load_config() {
    [ -f "$CONFIG" ] || write_default_config
    # shellcheck disable=SC1090
    . "$CONFIG"
    CONSOLE_ENABLED=${CONSOLE_ENABLED:-0}
    CONSOLE_URL=${CONSOLE_URL:-}
    TENANT_ID=${TENANT_ID:-default}
    AGENT_ID=${AGENT_ID:-}
    ENROLL_TOKEN=${ENROLL_TOKEN:-}
    AGENT_ENABLED=${AGENT_ENABLED:-1}
    AUTO_APPROVE=${AUTO_APPROVE:-0}
    AUTO_APPROVE_KILL=${AUTO_APPROVE_KILL:-0}
    POLL_SEC=${POLL_SEC:-15}
    HIGH_RSS_KB=${HIGH_RSS_KB:-700000}
}

machine_fp() {
    if [ -r /etc/machine-id ]; then
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum /etc/machine-id 2>/dev/null | awk '{print substr($1,1,12)}'
            return
        fi
        if command -v md5sum >/dev/null 2>&1; then
            md5sum /etc/machine-id 2>/dev/null | awk '{print substr($1,1,12)}'
            return
        fi
    fi
    echo "$(hostname 2>/dev/null || echo host)$(uname -m 2>/dev/null || echo x)" | tr -cd 'a-zA-Z0-9' | cut -c1-12
}

ensure_agent_id() {
    if [ -z "$AGENT_ID" ]; then
        AGENT_ID="unix-$(machine_fp)"
        tmp="$CONFIG.tmp"
        if grep -q '^AGENT_ID=' "$CONFIG" 2>/dev/null; then
            sed "s/^AGENT_ID=.*/AGENT_ID=$AGENT_ID/" "$CONFIG" > "$tmp" && mv "$tmp" "$CONFIG"
        else
            echo "AGENT_ID=$AGENT_ID" >> "$CONFIG"
        fi
    fi
}

http_post_json() {
    url="$1"; body="$2"
    if command -v curl >/dev/null 2>&1; then
        if [ -n "$ENROLL_TOKEN" ]; then
            curl -sS -m 5 -X POST -H "Content-Type: application/json" -H "X-Enrollment-Token: $ENROLL_TOKEN" -d "$body" "$url" 2>/dev/null || true
        else
            curl -sS -m 5 -X POST -H "Content-Type: application/json" -d "$body" "$url" 2>/dev/null || true
        fi
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O - --timeout=5 --header="Content-Type: application/json" --post-data="$body" "$url" 2>/dev/null || true
    fi
}

console_enroll() {
    [ "$CONSOLE_ENABLED" = "1" ] || return 0
    [ -n "$CONSOLE_URL" ] || return 0
    ensure_agent_id
    host="$(hostname 2>/dev/null || echo unix-node)"
    body="{\"TenantId\":\"$TENANT_ID\",\"AgentId\":\"$AGENT_ID\",\"Hostname\":\"$host\",\"Platform\":\"Unix\",\"Version\":\"1.5.0-unix\"}"
    http_post_json "${CONSOLE_URL%/}/api/enroll" "$body" >/dev/null
    log INFO "Console enroll attempted as $AGENT_ID"
}

console_heartbeat() {
    [ "$CONSOLE_ENABLED" = "1" ] || return 0
    [ -n "$CONSOLE_URL" ] || return 0
    ensure_agent_id
    host="$(hostname 2>/dev/null || echo unix-node)"
    findings="$1"; pending="$2"; mode="$3"; issues="$4"
    body="{\"TenantId\":\"$TENANT_ID\",\"AgentId\":\"$AGENT_ID\",\"Hostname\":\"$host\",\"Platform\":\"Unix\",\"Version\":\"1.5.0-unix\",\"Status\":{\"Engine\":\"Running\",\"Mode\":\"$mode\",\"FindingsCount\":$findings,\"PendingAlerts\":$pending,\"Issues\":$issues,\"Config\":{\"AutoApproveEnabled\":$AUTO_APPROVE,\"AutoApproveRemovals\":$AUTO_APPROVE_KILL,\"AgentEnabled\":$AGENT_ENABLED}}}"
    http_post_json "${CONSOLE_URL%/}/api/heartbeat" "$body" >/dev/null
}

is_running() {
    [ -f "$PIDFILE" ] || return 1
    pid=$(cat "$PIDFILE")
    kill -0 "$pid" 2>/dev/null
}

run_detect() {
    findings=0; pending=0; mode="Idle"
    if [ "$AGENT_ENABLED" != "1" ]; then
        echo "0 0 Idle"; return
    fi
    SUSP="xmrig|minerd|cpuminer|encrypt|ransom|mimikatz|cobalt|vssadmin|wbadmin"

    HIGH=$(ps -eo pid,rss,comm 2>/dev/null | awk -v lim="$HIGH_RSS_KB" 'NR>1 && $2+0 > lim {print $1,$2,$3}' | head -20) || HIGH=""
    if [ -n "$HIGH" ]; then
        echo "$HIGH" | while read -r pid rss name; do
            [ -z "$pid" ] && continue
            score=70
            reasons="HighRSS=${rss}KB"
            echo "$name" | grep -Eqi "$SUSP" && score=90 && reasons="$reasons;SuspiciousName"
            alert_file="$ALERTS/hm_${pid}.txt"
            echo "score=$score name=$name pid=$pid reasons=$reasons ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$alert_file"
            log WARN "Threat signal: $name pid=$pid score=$score ($reasons)"
            if [ "$AUTO_APPROVE" = "1" ] && [ "$AUTO_APPROVE_KILL" = "1" ] && [ "$score" -ge 80 ]; then
                kill "$pid" 2>/dev/null && log HIGH "AUTO-KILL pid=$pid name=$name" || true
            fi
        done
        mode="Alert"
    fi

    ps -eo pid,comm 2>/dev/null | awk 'NR>1 {print $1,$2}' | while read -r pid name; do
        echo "$name" | grep -Eqi "$SUSP" || continue
        alert_file="$ALERTS/nm_${pid}.txt"
        [ -f "$alert_file" ] && continue
        echo "score=85 name=$name pid=$pid reasons=SuspiciousName ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$alert_file"
        log WARN "Suspicious process name: $name pid=$pid"
        if [ "$AUTO_APPROVE" = "1" ] && [ "$AUTO_APPROVE_KILL" = "1" ]; then
            kill "$pid" 2>/dev/null && log HIGH "AUTO-KILL pid=$pid name=$name" || true
        fi
        mode="Alert"
    done

    pending=$(ls "$ALERTS" 2>/dev/null | wc -l | tr -d ' ')
    [ -z "$pending" ] && pending=0
    findings=$pending
    [ "$pending" -gt 0 ] 2>/dev/null && mode="Alert"
    echo "$findings $pending $mode"
}

cmd_status() {
    load_config; ensure_agent_id
    echo ""; echo "=== VECTORSTRYKE Unix STATUS ==="; echo ""
    if is_running; then echo "  Status     : ONLINE"; echo "  PID        : $(cat "$PIDFILE")"; else echo "  Status     : STOPPED"; fi
    echo "  AgentId    : $AGENT_ID"
    echo "  TenantId   : $TENANT_ID"
    echo "  Console    : enabled=$CONSOLE_ENABLED url=$CONSOLE_URL"
    echo "  AutoApprove: $AUTO_APPROVE  Kill=$AUTO_APPROVE_KILL  Enabled=$AGENT_ENABLED"
    [ -f "$STATUS" ] && { echo "  ---"; cat "$STATUS"; }
    echo "  Alerts: $(ls "$ALERTS" 2>/dev/null | wc -l | tr -d ' ')"
}

cmd_start() {
    load_config; ensure_agent_id
    if is_running; then echo "Already running"; exit 0; fi
    echo $$ > "$PIDFILE"
    log INFO "Unix sensor started PID=$$ agent=$AGENT_ID poll=${POLL_SEC}s"
    console_enroll
    while true; do
        load_config; ensure_agent_id
        result=$(run_detect)
        findings=$(echo "$result" | awk '{print $1}')
        pending=$(echo "$result" | awk '{print $2}')
        mode=$(echo "$result" | awk '{print $3}')
        [ -z "$findings" ] && findings=0
        [ -z "$pending" ] && pending=0
        [ -z "$mode" ] && mode="Idle"
        issues="[]"
        [ "$pending" -gt 0 ] 2>/dev/null && issues="[\"pending_approvals\",\"active_findings\"]"
        {
            echo "LastCycle=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            echo "Mode=$mode"; echo "Platform=Unix"; echo "AgentId=$AGENT_ID"; echo "TenantId=$TENANT_ID"
            echo "FindingsCount=$findings"; echo "PendingAlerts=$pending"
            echo "AutoApprove=$AUTO_APPROVE"; echo "AutoApproveKill=$AUTO_APPROVE_KILL"; echo "AgentEnabled=$AGENT_ENABLED"
        } > "$STATUS"
        console_heartbeat "$findings" "$pending" "$mode" "$issues"
        sleep "$POLL_SEC"
    done
}

cmd_stop() {
    if is_running; then kill "$(cat "$PIDFILE")" 2>/dev/null || true; rm -f "$PIDFILE"; log INFO "Stopped"; echo "Stopped"
    else echo "Not running"; fi
}

cmd_set_auto() {
    load_config
    val=0
    case "$1" in on|1|true|yes) val=1 ;; esac
    tmp="$CONFIG.tmp"
    sed -e "s/^AUTO_APPROVE=.*/AUTO_APPROVE=$val/" -e "s/^AUTO_APPROVE_KILL=.*/AUTO_APPROVE_KILL=$val/" "$CONFIG" > "$tmp" && mv "$tmp" "$CONFIG"
    echo "AUTO_APPROVE=$val AUTO_APPROVE_KILL=$val"
}

case "${1:-help}" in
    start) cmd_start ;;
    stop) cmd_stop ;;
    status) cmd_status ;;
    logs) tail -n 40 "$LOG" 2>/dev/null || echo "No logs yet" ;;
    auto-on) cmd_set_auto on ;;
    auto-off) cmd_set_auto off ;;
    *) cat <<EOF
VectorStryke Unix sensor — real-time detection + console + auto-approve toggle
Usage: $0 {start|stop|status|logs|auto-on|auto-off}
Config: $CONFIG
EOF
    ;;
esac
