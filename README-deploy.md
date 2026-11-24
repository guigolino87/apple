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
3. Open `http://<gateway-ip>:8080` (default `10.42.0.1` — the installer prints
   the actual IP and saves it to `/opt/pinapple/hotspot_ip.txt`).
4. Plug in the TL-WN722N v1 USB adapter before using WLAN1 features.

## Interface layout
- `wlan0` (built-in): broadcasts the PiNAPPLE hotspot. Managed by
  NetworkManager. Do not touch.
- `wlan1` (USB, TL-WN722N v1): used by WLAN1 features. Do not use for AP.

## Verifying the install
1. After reboot, open the WLAN1 tab. A mode badge should show `managed`
   (green). If it shows `missing`, plug in the USB adapter and hit Refresh.
2. If the dashboard is unreachable: SSH in and run `ip addr show wlan0` to
   find the real gateway IP.
3. If the badge toggles between `monitor` (red) and `managed` (green) when
   you click the Managed/Monitor buttons, mode management is working.

## Useful commands
- `sudo systemctl status|restart pinapple-dashboard`
- `sudo journalctl -u pinapple-dashboard -n 100`
- `sudo nmcli connection show`
- `ip addr show wlan0`
- `iw dev wlan1 info`