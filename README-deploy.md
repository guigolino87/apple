# PiNAPPLE Deployment (Raspberry Pi 4, Raspberry Pi OS Lite)

## First-time setup (one SSH session)
1. Flash Raspberry Pi OS Lite 64-bit via Raspberry Pi Imager.
2. In Imager: enable SSH, set user/password, and enter your home WiFi
   (temporary, first boot only).
3. SSH in once: `ssh <user>@<pi-ip>`
4. Clone the repo: `git clone <repo-url> ~/PiNAPPLE && cd ~/PiNAPPLE`
5. Install: `sudo bash install.sh`
6. The installer runs everything, prints a verification block, then reboots
   automatically after 10 seconds.

## Daily use (no SSH needed)
1. Power on the Pi.
2. On your phone: connect to WiFi SSID `PiNAPPLE`, password `pinapple123`.
3. Open `http://<gateway-ip>:8080` (default `10.0.0.1` — the installer prints
   the actual IP and saves it to `/opt/pinapple/hotspot_ip.txt`).
4. Plug in the TL-WN722N v1 USB adapter before using WLAN1 features.

## Interface layout
- `wlan0` (built-in): broadcasts the PiNAPPLE hotspot via hostapd/dnsmasq
  on `10.0.0.1`. Managed by `pinapple-ap` + `pinapple-dhcp`; do not use
  NetworkManager for this interface.
- `wlan1` (USB, TL-WN722N v1): used by the monitor and WLAN1 tools. NetworkManager
  leaves it unmanaged and the dashboard never hands it over. Rescan is passive:
  it waits for the monitor's next channel pass and reads `scan.json`, so the
  attack adapter is never taken down while the AP is serving clients.

## Verifying the install
1. Run `pinapple-status`. All services should be `active`, wlan0 should have
   `10.0.0.1`, and wlan1 should show `monitor` when the USB adapter is present.
2. Open the dashboard. The Overview **System check** lists missing tools and
   the AP/Monitor cards should show Running.
3. If the dashboard is unreachable: SSH in and run `ip addr show wlan0`; the
   gateway should be `10.0.0.1`.
4. AP control, Evil Twin, and DNS hijack are available because the installer
   uses the hostapd/dnsmasq stack (not a NetworkManager hotspot).

## Updating an existing install
```bash
cd ~/PiNAPPLE
git pull
sudo bash install.sh
```
The installer is idempotent: it replaces the app, helpers and units, keeps
`/etc/hostapd/hostapd.conf`, keeps saved captures, restarts every service, and
reboots. Re-run it after every `git pull`.

## Useful commands
- `pinapple-status` (or `--json`)
- `sudo systemctl status|restart pinapple-dashboard`
- `sudo systemctl status|restart pinapple-ap pinapple-dhcp pinapple-monitor pinapple-portal nginx`
- `sudo journalctl -u pinapple-dashboard -n 100`
- `sudo journalctl -u pinapple-ap -n 100`
- `ip addr show wlan0`
- `iw dev wlan1 info`
- `sudo tail -n 100 /var/log/pinapple/events.log`