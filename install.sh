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
# the Flask dashboard at http://10.42.0.1:8080.
# wlan1 (USB adapter) is reserved for attack features and is NEVER touched.
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
    macchanger iw wireless-tools net-tools rfkill usbutils \
    python3 python3-pip python3-venv network-manager

# 5. Anchor in the project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 6. Ensure the project directory exists on the Pi
mkdir -p /opt/pinapple

# 7. Copy the project files into place
cp -f "$SCRIPT_DIR/app.py" "$SCRIPT_DIR/extensions.py" "$SCRIPT_DIR/ext_helpers.py" /opt/pinapple/

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

# 12. Ensure the log directory exists
mkdir -p /var/log/pinapple
chmod 0755 /var/log/pinapple

# 13. Install the systemd unit
cp -f "$SCRIPT_DIR/pinapple-dashboard.service" /etc/systemd/system/pinapple-dashboard.service
systemctl daemon-reload
systemctl enable pinapple-dashboard

# 14. Disable dhcpcd so it doesn't fight NetworkManager for wlan0
systemctl disable --now dhcpcd 2>/dev/null || true
systemctl enable NetworkManager

# 15. Ensure wlan0 is NOT marked "unmanaged" by NetworkManager.
#     Some images put the rule in /etc/NetworkManager/NetworkManager.conf,
#     others in /etc/NetworkManager/conf.d/*.conf, and some in
#     /usr/lib/NetworkManager/conf.d/*.conf. For every such file, comment
#     out the offending line in place with sed (idempotent: re-running is
#     harmless because the line is already commented), then restart NM.
candidates=(
    /etc/NetworkManager/NetworkManager.conf
    /etc/NetworkManager/conf.d/*.conf
    /usr/lib/NetworkManager/conf.d/*.conf
)
for f in "${candidates[@]}"; do
    [ -f "$f" ] || continue
    if grep -q "unmanaged-devices" "$f" && grep -q "wlan" "$f"; then
        echo "Neutralizing unmanaged-devices rule in $f"
        sed -i '/unmanaged-devices.*wlan/s/^/# P I N A P P L E _ D I S A B L E D /' "$f"
    fi
done
systemctl restart NetworkManager || true

# 16. Wait for NetworkManager to be ready, then create the hotspot
for i in $(seq 1 10); do
    nmcli -t -f RUNNING general >/dev/null 2>&1 && break
    sleep 1
done
nmcli device wifi hotspot ssid PiNAPPLE password pinapple123 ifname wlan0 || true

# 16b. Detect and persist the actual hotspot gateway IP
WLAN0_IP="$(ip -4 -o addr show wlan0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 || true)"
if [ -n "$WLAN0_IP" ]; then
    echo "$WLAN0_IP" > /opt/pinapple/hotspot_ip.txt
    echo "Detected hotspot gateway IP: $WLAN0_IP"
else
    echo "10.42.0.1" > /opt/pinapple/hotspot_ip.txt
    echo "Could not detect wlan0 IP; defaulting to 10.42.0.1"
fi

# 17. Start/restart the dashboard
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
echo "Hotspot connection:"
nmcli -t -f NAME connection show | grep -i hotspot || echo "(no hotspot connection found)"
echo "wlan0 state:"
nmcli -t -f DEVICE,STATE device status | grep wlan0 || echo "(wlan0 not listed)"
echo "===================="

# 19. Final instructions
echo "PiNAPPLE install complete."
echo "Rebooting in 10 seconds so the hotspot and dashboard start cleanly."
echo "After reboot: connect your phone to WiFi SSID 'PiNAPPLE' (password 'pinapple123')."
echo "Open http://${WLAN0_IP:-10.42.0.1}:8080 on your phone."
echo "If the page does not load, check the IP with: ip addr show wlan0"
echo "Manage dashboard: sudo systemctl status|start|stop|restart pinapple-dashboard"
echo "Manage hotspot: sudo nmcli connection show / sudo nmcli device wifi hotspot ..."

sleep 10
reboot

