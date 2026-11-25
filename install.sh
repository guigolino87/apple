#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# PiNAPPLE Linux installer
# ============================================================
# On a fresh Raspberry Pi (Pi 4, Raspberry Pi OS Lite / Debian-based),
# running exactly ONE command installs everything, verifies, and reboots:
#
#     sudo bash install.sh
#
# After reboot the Pi broadcasts its own WiFi hotspot on wlan0 and serves
# the Flask dashboard at http://10.0.0.1:8080.
# wlan1 (USB adapter) is reserved for monitor/attack features; NetworkManager
# is told to leave it alone so it cannot fight the monitor.
#
# Idempotent: safe to re-run. Steps that can legitimately fail on a re-run
# are guarded with "|| true".

# 1. Root check
if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: This script must be run as root (use sudo)." >&2
    exit 1
fi

# 2. Banner
echo "==================================================="
echo "           PiNAPPLE installer"
echo "==================================================="

# 3. apt-get update
apt-get update

# 4. apt-get install system dependencies
apt-get install -y hostapd dnsmasq aircrack-ng hcxdumptool hcxtools \
    macchanger iw wireless-tools net-tools rfkill usbutils nginx iptables ieee-data \
    logrotate python3 python3-pip python3-venv network-manager

# mdk4 is packaged separately from aircrack-ng and is not present on every
# image. Fall back to a source build so beacon flooding works out of the box.
apt-get install -y mdk4 || echo "WARNING: mdk4 package unavailable; trying a source build."
if ! command -v mdk4 >/dev/null 2>&1; then
    apt-get install -y build-essential git libpcap-dev || true
    BUILD_DIR="$(mktemp -d)"
    if git clone --depth 1 https://github.com/aircrack-ng/mdk4 "$BUILD_DIR/mdk4" 2>/dev/null; then
        if make -C "$BUILD_DIR/mdk4" -j"$(nproc)" >/dev/null 2>&1; then
            install -m 0755 "$BUILD_DIR/mdk4/mdk4" /usr/local/bin/mdk4
            echo "OK: mdk4 built from source."
        else
            echo "WARNING: mdk4 source build failed; beacon flooding will be unavailable."
        fi
    else
        echo "WARNING: could not download mdk4 source; beacon flooding will be unavailable."
    fi
    rm -rf "$BUILD_DIR"
fi

# 5. Anchor in the project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 6. Ensure the project directory exists on the Pi
mkdir -p /opt/pinapple

# 7. Copy the project files into place
cp -f "$SCRIPT_DIR/app.py" "$SCRIPT_DIR/extensions.py" "$SCRIPT_DIR/ext_helpers.py" /opt/pinapple/
cp -f "$SCRIPT_DIR/portal_handler.py" /opt/pinapple/
mkdir -p /opt/pinapple/portal
for f in creds hotel splash success coffee airport library gym; do
    cp -f "$SCRIPT_DIR/portal/$f.html" /opt/pinapple/portal/
done
# Keep an existing portal selection (a symlink created by Settings).
if [ ! -L /opt/pinapple/portal/index.html ]; then
    cp -f "$SCRIPT_DIR/portal/index.html" /opt/pinapple/portal/index.html
fi

# 7b. Install the WLAN1 helper scripts used by the dashboard
mkdir -p /usr/local/bin
install -m 0755 "$SCRIPT_DIR/tools/pinapple-beacon-flood" /usr/local/bin/pinapple-beacon-flood
install -m 0755 "$SCRIPT_DIR/tools/pinapple-deauth" /usr/local/bin/pinapple-deauth
install -m 0755 "$SCRIPT_DIR/tools/pinapple-handshake" /usr/local/bin/pinapple-handshake
install -m 0755 "$SCRIPT_DIR/tools/pinapple-monitor" /usr/local/bin/pinapple-monitor
install -m 0755 "$SCRIPT_DIR/tools/pinapple-status" /usr/local/bin/pinapple-status
install -m 0755 "$SCRIPT_DIR/tools/pinapple-internet" /usr/local/bin/pinapple-internet
install -m 0755 "$SCRIPT_DIR/tools/pinapple-portal" /usr/local/bin/pinapple-portal

# 8. Sanity check that app.py binds 0.0.0.0
if grep -q "app.run(host='0.0.0.0'" /opt/pinapple/app.py || grep -q 'app.run(host="0.0.0.0"' /opt/pinapple/app.py; then
    echo "OK: app.py binds 0.0.0.0"
else
    echo "WARNING: app.py does not appear to bind 0.0.0.0. The phone will not reach the dashboard. Fix app.py and re-run."
fi

# 9. Create a virtual environment if one does not already exist
if [[ ! -d /opt/pinapple/venv ]]; then
    python3 -m venv /opt/pinapple/venv
fi

# 10. Upgrade pip
/opt/pinapple/venv/bin/pip install --upgrade pip

# 11. Install Python project dependencies from requirements.txt
/opt/pinapple/venv/bin/pip install -r "$SCRIPT_DIR/requirements.txt"

# 12. Ensure the log and state directories exist
mkdir -p /var/log/pinapple /etc/pinapple /var/lib/pinapple/saved /var/run
chmod 0755 /var/log/pinapple /etc/pinapple /var/lib/pinapple /var/lib/pinapple/saved
if [ -f /var/log/pinapple/creds.log ]; then
    chmod 0600 /var/log/pinapple/creds.log
fi

cat > /etc/logrotate.d/pinapple <<'EOF'
/var/log/pinapple/*.log {
    weekly
    rotate 4
    missingok
    notifempty
    compress
    copytruncate
}
EOF

# 12b. Verify the wireless tooling the beacon/deauth/handshake helpers rely on
for tool in mdk4 iw airodump-ng aireplay-ng hcxdumptool hcxpcapngtool nmcli; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "OK: $tool found at $(command -v "$tool")"
    else
        echo "WARNING: $tool is missing; the related wireless feature will report an error until it is installed."
    fi
done

# 12c. Captive portal: nginx site and the local submit handler
install -m 0644 "$SCRIPT_DIR/portal/nginx-pinapple.conf" /etc/nginx/sites-available/pinapple
ln -sf /etc/nginx/sites-available/pinapple /etc/nginx/sites-enabled/pinapple
rm -f /etc/nginx/sites-enabled/default
if nginx -t; then
    systemctl enable nginx
    systemctl restart nginx
else
    echo "WARNING: nginx config test failed; the captive portal will not be served."
fi

install -m 0644 "$SCRIPT_DIR/services/pinapple-portal.service" /etc/systemd/system/pinapple-portal.service
systemctl daemon-reload
systemctl enable pinapple-portal || true
systemctl restart pinapple-portal || echo "WARNING: portal handler service failed to start."

# 13. Install the systemd unit
cp -f "$SCRIPT_DIR/pinapple-dashboard.service" /etc/systemd/system/pinapple-dashboard.service
systemctl daemon-reload
systemctl enable pinapple-dashboard

# 14. wlan0 is owned by hostapd, not NetworkManager. Keep NM for eth0/wlan1.
systemctl disable --now dhcpcd 2>/dev/null || true
systemctl enable NetworkManager
systemctl unmask hostapd 2>/dev/null || true
systemctl disable --now hostapd 2>/dev/null || true
systemctl disable --now dnsmasq 2>/dev/null || true

# 15. Remove legacy "unmanaged" rules that might exclude wlan0.
#     wlan0 is re-marked unmanaged deliberately in 15b.
candidates=(
    /etc/NetworkManager/NetworkManager.conf
    /etc/NetworkManager/conf.d/*.conf
    /usr/lib/NetworkManager/conf.d/*.conf
)
for f in "${candidates[@]}"; do
    [ -f "$f" ] || continue
    if grep -q "unmanaged-devices" "$f" && grep -q "wlan" "$f"; then
        echo "Neutralizing legacy unmanaged-devices rule in $f"
        sed -i '/unmanaged-devices.*wlan/s/^/# P I N A P P L E _ D I S A B L E D /' "$f"
    fi
done

# 15b. hostapd owns wlan0. NetworkManager must leave it alone.
install -m 0644 "$SCRIPT_DIR/services/99-pinapple-unmanaged.conf" \
    /etc/NetworkManager/conf.d/99-pinapple-unmanaged.conf
nmcli device set wlan0 managed no 2>/dev/null || true
nmcli device set wlan1 managed no 2>/dev/null || true
systemctl restart NetworkManager || true

# 15c. Hostapd + dnsmasq stack (no NetworkManager hotspot dependency).
install -m 0644 "$SCRIPT_DIR/services/pinapple-ap.service" /etc/systemd/system/pinapple-ap.service
install -m 0644 "$SCRIPT_DIR/services/pinapple-dhcp.service" /etc/systemd/system/pinapple-dhcp.service
install -m 0644 "$SCRIPT_DIR/services/pinapple-monitor.service" /etc/systemd/system/pinapple-monitor.service
mkdir -p /etc/hostapd /etc/dnsmasq.d /var/lib/misc /etc/pinapple
if [ ! -f /etc/hostapd/hostapd.conf ]; then
    install -m 0644 "$SCRIPT_DIR/services/hostapd.conf" /etc/hostapd/hostapd.conf
else
    # Keep the user's SSID/channel but replace HT40 settings that some
    # drivers reject with a safe 20 MHz capability set.
    sed -i 's/^ht_capab=.*/ht_capab=[SHORT-GI-20][DSSS_CCK-40]/' /etc/hostapd/hostapd.conf
fi
install -m 0644 "$SCRIPT_DIR/services/dnsmasq-pinapple.conf" /etc/dnsmasq.d/pinapple.conf
[ -f /etc/pinapple/dnsmasq-hijack.conf ] || : > /etc/pinapple/dnsmasq-hijack.conf
chmod 0644 /etc/pinapple/dnsmasq-hijack.conf
# dnsmasq drops privileges; make its lease and log files writable up front.
touch /var/lib/misc/dnsmasq.leases /var/log/pinapple/dnsmasq.log
chmod 0644 /var/lib/misc/dnsmasq.leases
chmod 0640 /var/log/pinapple/dnsmasq.log
chown dnsmasq:dnsmasq /var/lib/misc/dnsmasq.leases /var/log/pinapple/dnsmasq.log 2>/dev/null || true
rfkill unblock wlan 2>/dev/null || true
systemctl daemon-reload
systemctl enable pinapple-ap pinapple-dhcp pinapple-monitor
systemctl restart pinapple-ap || true
sleep 2
systemctl restart pinapple-dhcp || true
systemctl restart pinapple-monitor || true

# 15d. Wait for the AP address, then persist the gateway IP.
WLAN0_IP="10.0.0.1"
for i in $(seq 1 10); do
    if ip -4 -o addr show wlan0 2>/dev/null | grep -q '10\.0\.0\.1/'; then
        break
    fi
    sleep 1
done
echo "$WLAN0_IP" > /opt/pinapple/hotspot_ip.txt
echo "PiNAPPLE AP gateway: $WLAN0_IP"
if ! systemctl is-active --quiet pinapple-ap; then
    echo "WARNING: pinapple-ap is not running. Recent log:"
    journalctl -u pinapple-ap -n 20 --no-pager || true
fi
if ! systemctl is-active --quiet pinapple-dhcp; then
    echo "WARNING: pinapple-dhcp is not running. Recent log:"
    journalctl -u pinapple-dhcp -n 20 --no-pager || true
fi

# 16. Start/restart the dashboard
systemctl restart pinapple-dashboard || true

# 18a. Read-only wlan1 (USB adapter) status check
echo "=== wlan1 (USB adapter) status ==="
if ip link show wlan1 >/dev/null 2>&1; then
    echo "wlan1 detected."
    iw dev wlan1 info 2>/dev/null | grep -E "type|channel" || true
else
    echo "wlan1 NOT detected. Plug in the USB adapter (TL-WN722N v1) after reboot."
fi
echo "==================================="

# 18. Verification summary
echo "=== Verification ==="
echo "Dashboard service:"
systemctl is-active pinapple-dashboard || true
echo "AP service:"
systemctl is-active pinapple-ap || true
echo "DHCP/DNS service:"
systemctl is-active pinapple-dhcp || true
echo "Portal handler:"
systemctl is-active pinapple-portal || true
echo "wlan1 monitor:"
systemctl is-active pinapple-monitor || true
echo "nginx:"
systemctl is-active nginx || true
echo "wlan0 address:"
ip -4 -o addr show wlan0 2>/dev/null || echo "(no wlan0 address)"
echo "===================="

# 19. Final instructions
echo "PiNAPPLE install complete."
echo "Rebooting in 10 seconds so the AP, DHCP and dashboard start cleanly."
echo "After reboot: connect your phone to WiFi SSID 'PiNAPPLE' (password 'pinapple123')."
echo "Open http://${WLAN0_IP:-10.0.0.1}:8080 on your phone."
echo "If the page does not load, check: ip addr show wlan0"
echo "Manage dashboard: sudo systemctl status|start|stop|restart pinapple-dashboard"
echo "Manage AP: sudo systemctl status|restart pinapple-ap pinapple-dhcp"
echo "AP config: /etc/hostapd/hostapd.conf"

sleep 10
reboot

