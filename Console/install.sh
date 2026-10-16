#!/usr/bin/env sh
# VectorStryke Central Console — install script (Linux / Unix with systemd or no-systemd)
# Usage: sudo ./install.sh [--port 9000] [--host 0.0.0.0] [--token SECRET]

set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"
PORT=9000
HOST="0.0.0.0"
TOKEN="${VECTORSTRYKE_ENROLL_TOKEN:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --host) HOST="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

echo "=== VectorStryke Central Console Install ==="
echo "  Root : $ROOT"
echo "  Bind : $HOST:$PORT"
echo ""

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required."
  exit 1
fi

mkdir -p "$ROOT/data"
chmod +x "$ROOT/console.py" 2>/dev/null || true

# Default console.env
ENV_FILE="$ROOT/console.env"
if [ ! -f "$ENV_FILE" ]; then
  cat > "$ENV_FILE" <<EOF
# VectorStryke Console environment
VECTORSTRYKE_CONSOLE_HOST=$HOST
VECTORSTRYKE_CONSOLE_PORT=$PORT
VECTORSTRYKE_ENROLL_TOKEN=$TOKEN
EOF
  echo "  [+] Wrote $ENV_FILE"
else
  echo "  [=] $ENV_FILE exists (kept)"
fi

# systemd unit when root + systemd available
SYSTEMD_OK=0
if [ "$(id -u)" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
  if systemctl daemon-reload >/dev/null 2>&1; then SYSTEMD_OK=1; fi
fi
if [ "$SYSTEMD_OK" -eq 1 ]; then
  UNIT=/etc/systemd/system/vectorstryke-console.service
  cat > "$UNIT" <<EOF
[Unit]
Description=VectorStryke Central Multi-Tenant Console
After=network.target

[Service]
Type=simple
WorkingDirectory=$ROOT
EnvironmentFile=-$ENV_FILE
Environment=VECTORSTRYKE_ENROLL_TOKEN=$TOKEN
ExecStart=/usr/bin/python3 $ROOT/console.py --host $HOST --port $PORT
Restart=on-failure
RestartSec=3
Nice=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl enable vectorstryke-console >/dev/null 2>&1 || true
  systemctl restart vectorstryke-console >/dev/null 2>&1 || true
  echo "  [+] systemd unit: $UNIT"
else
  echo "  [!] systemd not available — start manually:"
  echo "      cd $ROOT && python3 console.py --host $HOST --port $PORT"
  [ -n "$TOKEN" ] && echo "      export VECTORSTRYKE_ENROLL_TOKEN='$TOKEN'"
fi

echo ""
echo "Dashboard:  http://<this-host>:$PORT/"
echo "Health:     http://<this-host>:$PORT/api/health"
echo ""
echo "On each agent set:"
echo "  ConsoleEnabled = true"
echo "  ConsoleUrl     = http://<this-host>:$PORT"
echo "  TenantId       = <your-tenant>"
if [ -n "$TOKEN" ]; then
  echo "  EnrollmentToken = $TOKEN"
fi
echo ""
echo "Install complete."
