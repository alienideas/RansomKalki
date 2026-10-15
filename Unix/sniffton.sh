#!/usr/bin/env sh
# Sniffton - Lightweight Anti-Ransomware sensor + status for POSIX Unix
# Copyright © Sniffton
# Pure POSIX sh + common utilities (ps, grep, awk, find). No bashisms required.
# For fuller features use the Linux Python version when python3 is available.

set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"
DATA="$ROOT/data"
LOG="$ROOT/logs/engine.log"
STATUS="$DATA/status"
PIDFILE="$DATA/sniffton.pid"
ALERTS="$DATA/alerts"

mkdir -p "$DATA" "$ROOT/logs" "$ALERTS"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$1] $2" | tee -a "$LOG"
}

is_running() {
    [ -f "$PIDFILE" ] || return 1
    pid=$(cat "$PIDFILE")
    kill -0 "$pid" 2>/dev/null
}

cmd_status() {
    echo ""
    echo "┌────────────────────────────────────────────────────────────┐"
    echo "│           SNIFFTON STATUS (Unix/POSIX)                     │"
    echo "└────────────────────────────────────────────────────────────┘"
    echo ""
    if is_running; then
        echo "  Status : ONLINE"
        echo "  PID    : $(cat "$PIDFILE")"
        if [ -f "$STATUS" ]; then
            cat "$STATUS"
        fi
    else
        echo "  Status : STOPPED"
        echo "  Start  : $0 start"
    fi
    echo ""
    echo "  Pending alerts:"
    ls "$ALERTS" 2>/dev/null | head -10 || echo "    (none)"
    echo ""
}

cmd_start() {
    if is_running; then
        echo "Already running"
        exit 0
    fi
    echo $$ > "$PIDFILE"
    log INFO "Sniffton Unix sensor started (PID $$)"

    while true; do
        # Simple high-memory process check
        # Portable: ps -eo pid,rss,comm (RSS in KB on most systems)
        HIGH=$(ps -eo pid,rss,comm 2>/dev/null | awk '$2 > 700000 {print $1,$2,$3}' | head -5)
        if [ -n "$HIGH" ]; then
            log WARN "High memory processes detected"
            echo "$HIGH" | while read -r pid rss name; do
                echo "  PID=$pid RSS=${rss}KB NAME=$name"
                # Create a simple alert file
                echo "HighMem $name pid=$pid rss=$rss $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$ALERTS/highmem_${pid}.txt"
            done
        fi

        # Snapshot / backup deletion patterns (from shadow-backup-hunter ideas)
        if command -v ausearch >/dev/null 2>&1; then
            :
        fi

        # Write minimal status
        {
            echo "LastCycle=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            echo "Mode=Idle"
            echo "Platform=Unix"
        } > "$STATUS"

        sleep 60
    done
}

cmd_stop() {
    if is_running; then
        kill "$(cat "$PIDFILE")" 2>/dev/null || true
        rm -f "$PIDFILE"
        log INFO "Stopped"
        echo "Stopped"
    else
        echo "Not running"
    fi
}

case "${1:-help}" in
    start)  cmd_start ;;
    stop)   cmd_stop ;;
    status) cmd_status ;;
    logs)   tail -n 40 "$LOG" 2>/dev/null || echo "No logs yet" ;;
    *)
        cat <<EOF
Sniffton Unix/POSIX lightweight sensor
Copyright © Sniffton

Usage: $0 {start|stop|status|logs}

This is a minimal POSIX version. For full features (approval workflow,
rich detection, quarantine) use the Linux Python implementation when
python3 is available.

EOF
        ;;
esac
