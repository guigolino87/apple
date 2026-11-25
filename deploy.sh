#!/usr/bin/env bash
# ============================================================
# PiNAPPLE code deploy (existing install, no reinstall)
# ============================================================
# Copies the dashboard code and helper tools from this repo to the
# installed locations and restarts ONLY the dashboard.
#
#     sudo bash deploy.sh
#
# Use this after pulling/editing code. It never touches the AP, DHCP,
# the portal or the wlan1 monitor, so clients stay connected.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: run with sudo (sudo bash deploy.sh)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
DEST=/opt/pinapple
PY="$DEST/venv/bin/python3"

if [[ ! -x "$PY" ]]; then
    echo "Error: $PY not found. Run install.sh first." >&2
    exit 1
fi

echo "==> Syntax check"
"$PY" -m py_compile app.py extensions.py ext_helpers.py portal_handler.py tools/pinapple-monitor

echo "==> Installing dashboard code"
install -m 0644 app.py extensions.py ext_helpers.py portal_handler.py "$DEST/"
mkdir -p "$DEST/portal"
if [[ -d portal ]]; then
    for f in portal/*.html; do
        [[ -e "$f" ]] && install -m 0644 "$f" "$DEST/portal/"
    done
fi

echo "==> Installing helper tools"
install -m 0755 tools/pinapple-* /usr/local/bin/

echo "==> Installing dashboard unit"
install -m 0644 pinapple-dashboard.service /etc/systemd/system/pinapple-dashboard.service
systemctl daemon-reload

echo "==> Restarting dashboard"
systemctl restart pinapple-dashboard

# app.py re-applies network flags and reconciles wlan1 before it binds, so the
# listener can take several seconds to appear. Poll instead of assuming.
code=000
for _ in $(seq 1 20); do
    sleep 1
    code=$(curl -s -o /dev/null -m 2 -w '%{http_code}' http://127.0.0.1:8080/ || echo 000)
    [[ "$code" == "401" || "$code" == "200" ]] && break
done
if ! systemctl is-active --quiet pinapple-dashboard; then
    echo "FAILED: dashboard did not start" >&2
    journalctl -u pinapple-dashboard -n 40 --no-pager >&2 || true
    exit 1
fi
if [[ "$code" == "401" || "$code" == "200" ]]; then
    echo "OK: dashboard active, HTTP $code on 127.0.0.1:8080"
else
    echo "WARNING: dashboard active but HTTP $code on 127.0.0.1:8080" >&2
    journalctl -u pinapple-dashboard -n 30 --no-pager >&2 || true
    exit 1
fi
echo "Done. AP, DHCP, portal and the wlan1 monitor were left untouched."
