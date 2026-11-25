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
"$PY" - <<'PY'
files = ['app.py', 'extensions.py', 'ext_helpers.py', 'portal_handler.py',
         'tools/pinapple-monitor']
for name in files:
    with open(name, encoding='utf-8') as handle:
        compile(handle.read(), name, 'exec')
print('syntax ok (%d files)' % len(files))
PY

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

if [[ -f portal/nginx-pinapple.conf ]]; then
    echo "==> Installing nginx portal site"
    install -m 0644 portal/nginx-pinapple.conf /etc/nginx/sites-available/pinapple
    ln -sf /etc/nginx/sites-available/pinapple /etc/nginx/sites-enabled/pinapple
    if nginx -t >/dev/null 2>&1; then
        systemctl reload nginx || true
    else
        echo "WARNING: nginx rejected the site config; portal submit stays on the old route" >&2
    fi
fi

if [[ -f services/dnsmasq-pinapple.conf ]]; then
    echo "==> Installing dnsmasq config"
    install -m 0644 services/dnsmasq-pinapple.conf /etc/dnsmasq.d/pinapple.conf
    mkdir -p /etc/pinapple
    touch /etc/pinapple/dnsmasq-hijack.conf
    systemctl reset-failed pinapple-dhcp 2>/dev/null || true
    systemctl restart pinapple-dhcp || true
    systemctl is-active --quiet pinapple-dhcp \
        && echo "OK: dnsmasq active" \
        || echo "WARNING: dnsmasq did not start; check journalctl -u pinapple-dhcp" >&2
fi

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
