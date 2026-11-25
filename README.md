# 🍍 PiNAPPLE
### A DIY WiFi auditing platform built on a Raspberry Pi 4 — for $30 instead of $200.

![Hardware](https://img.shields.io/badge/Hardware-Raspberry%20Pi%204-c51a4a?style=flat-square&logo=raspberry-pi)
![OS](https://img.shields.io/badge/OS-Pi%20OS%20Bookworm-darkgreen?style=flat-square)
![Python](https://img.shields.io/badge/Backend-Python%20Flask-3776AB?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Stardance](https://img.shields.io/badge/Hack%20Club-Stardance%202026-FF6B6B?style=flat-square)

---

> ⚠️ **For authorized testing, CTF competitions, and home lab use only.**  
> Never use on networks you don't own or have explicit written permission to test.

---

## What is PiNAPPLE?

The [Hak5 WiFi Pineapple](https://shop.hak5.org/products/wifi-pineapple) is a professional WiFi auditing tool used by pentesters worldwide. It costs $100–$200. PiNAPPLE replicates its core functionality on a Raspberry Pi 4 using open source tools — for the cost of a USB dongle.

Built from scratch as a learning project to understand how rogue APs, captive portals, DNS hijacking, and WiFi recon actually work at the protocol level.

---

## Features

| Feature | Status |
|---|---|
| 🔴 Rogue Access Point (hostapd) | ✅ |
| 📡 Monitor Mode Scanning (AR9271) | ✅ |
| 🌐 Captive Portal (7 templates + custom upload) | ✅ |
| 🔀 DNS Hijacking (dnsmasq) | ✅ |
| 🔁 Internet Passthrough (NAT) | ✅ |
| 📊 Web Dashboard (Flask + Waitress) | ✅ |
| 💾 Saved captures and snapshots | ✅ |
| 📝 Activity and per-source logs | ✅ |
| ⚡ Deauth / Handshake / PMKID / Evil Twin / Beacon Flood | ✅ |
| 🔄 Auto-start on boot (systemd) | ✅ |

---

## Hardware

| Component | Role |
|---|---|
| Raspberry Pi 4 (1GB) | Main compute |
| AR9271 USB WiFi dongle | Monitor mode + scanning |
| BCM43455 (onboard) | Rogue AP |
| Ethernet cable | Internet from laptop + management channel |

**Total cost:** ~$30 (just the dongle, if you already have a Pi)  
**Pineapple cost:** $100–$200

---

## Architecture

```
Internet → Router → Your Laptop (WiFi)
                         │
                    Ethernet cable
                    (ICS + SSH + Dashboard access)
                         │
                    Pi eth0 (DHCP from laptop)
                         │
          ┌──────────────┴──────────────┐
          │                             │
   wlan0 BCM43455               wlan1 AR9271
   Rogue AP (10.0.0.1)          Monitor Mode
   Targets connect here          Passive scanning
```

Your laptop shares internet to the Pi over ethernet. Both WiFi interfaces are completely free for auditing. SSH in from your laptop, hit the dashboard from your browser — no separate management network needed.

---

## Dashboard

A custom dark-themed Flask web UI. Connect to the `PiNAPPLE` hotspot and open `http://10.0.0.1:8080`.

### Local UI preview on Windows

From the repository folder, run `py preview.py` and open <http://127.0.0.1:8080/>.
Fieldsignal runs on Python's standard library. Overview, Clients, Networks, and Activity use sample data. The desktop sidebar lists the other original sections, which are under More on phones. AP Control and Settings show read-only examples. Docs describes the preview.
Edit the markup in `preview.py` and restart the server. Refresh the browser after changing `preview_ui/fields.css`.
The Raspberry Pi dashboard has its own templates. Hardware controls, live scans, and captive portal features are outside the preview.
Press `Ctrl+C` to stop it, or use `py preview.py --port 8081` if port 8080 is in use.

**Pages:**
- **Overview** — service status, clients, toggles, system check, recent activity
- **AP Control** — SSID, channel, security mode, TX power, start/stop the AP
- **Clients** — connected devices with vendor lookup
- **Recon** — nearby networks with vendor, channel, security, signal
- **Credentials** — captured portal submissions with CSV export
- **Saved** — handshakes, PMKID hashes and JSON snapshots
- **Logs** — per-source logs with in-place clearing
- **Settings** — portal templates, custom upload, dashboard password
- **WLAN1 Attacks** — Probes, Tracker, Deauth, Handshake, Evil Twin, PMKID, Beacon Flood

### WLAN1 attack tuning

The **WLAN1 → Beacon Flood** panel is built for phones. Enter a name or phrase, choose how many copies to broadcast, and press **Start flooding**. Each copy gets an incrementing number (`Cafe WiFi 1`, `Cafe WiFi 2`, …) so the phone lists them as separate networks. The live card shows the packet rate, channel, uptime, and the exact SSIDs currently on the air; **Stop** ends the helper and restores `wlan1`.

Behind the UI, the helper keeps **one long-running mdk4 process on a single channel** (default `6`) instead of restarting on every channel change. That matters because iOS listens for only ~100 ms per channel during a scan: a continuous stream on one channel lets every SSID be heard, while channel hopping resets mdk4's sequence and drops most names. The default rate is auto-tuned to *10 packets/sec per network* (200–500 pps), which puts each SSID on the air about once per 100 ms. Beacons are managed/AP only, WPA2/AES, and 54 Mbit, which is what iOS displays most reliably.

The **Advanced settings** section is for coverage experiments, not speed:

| Setting | Default | Notes |
| --- | --- | --- |
| Rate | `0` (auto) | `0` = 10 × networks, clamped to 200–500 pps. |
| Channel(s) | `6` | One channel is fastest. Commas enable rotating coverage. |
| Beacons / SSID | `1` | mdk4 reads the file in a loop, so `1` is enough. |
| Dwell | `8` | Seconds per channel in multi-channel mode. |

Multi-channel mode partitions the SSIDs across channels and keeps each BSSID on its own channel, then rotates with a longer dwell. Use it when you need to cover phones parked on a non-default channel, not when you want the fastest listing.

Only one feature can own `wlan1` at a time: starting a beacon flood stops deauth, PMKID, and Evil Twin jobs first (and vice versa). The `pinapple-monitor` recon service is paused while an attack owns the radio, because its channel hopping would otherwise move the adapter off the flood channel and silently discard most beacons. It resumes when the attack stops. The helper logs to `/var/log/pinapple/beacon-flood.log`, and the dashboard shows the tail of that log when something fails.

**Deauth** validates MAC addresses, resolves the target channel from the last recon scan (or accepts an explicit channel), and exposes a rate control. Continuous deauth jobs are tracked, stopped by process group, and cleaned up through a PID file if the dashboard restarts; the WLAN1 mode badge and Evil Twin stop button are wired up again.

All helpers are installed to `/usr/local/bin/` by `install.sh` and use only the Python standard library.

### Mobile dashboard

The dashboard is designed to be used from a phone:

- The hamburger drawer is width-capped, has a close button, and every nav row is a full touch target.
- On **WLAN1 Attacks** a horizontal tab strip (Probes, Client Tracker, Deauth, Handshake, Evil Twin, PMKID, Beacon Flood) is always visible, so you do not need to reopen the drawer to switch tools. The wlan1 mode/owner bar sits above the tabs and is visible on every tab.
- Long tables (clients, recon, credentials, probes, tracker, scan results) turn into labelled cards on narrow screens instead of forcing side-scrolling.
- Every action reports through a toast, a status card, or both. Destructive actions (stop AP, stop flood, start deauth/evil twin/PMKID) ask for confirmation first. The AP stop dialog warns that the phone will disconnect.
- Inputs use a 16 px font on mobile so iOS does not zoom the page when a field is focused.
- Background polling pauses when the page is hidden.

The dashboard is still protected by HTTP Basic auth (the browser prompt). There is no session login page or logout button yet.

### Console status

For SSH or a headless setup, `pinapple-status` prints a short readable overview:

- Services and their state
- wlan0/wlan1 addresses and modes
- Active wlan1 jobs and monitor packet counts
- Saved item count, free disk, and the last activity lines

Use `pinapple-status --json` for automation. Per-source logs remain available in the dashboard's **Logs** tab.

### Saved data

The **Saved** page keeps the valuable outputs, not raw logs:

- Handshakes are saved automatically as `.pcap` files with the SSID, BSSID, channel, client and timestamp.
- PMKID conversions are saved automatically as `.hc22000` hash files with the line count and source capture.
- **Save snapshot** buttons write small readable JSON files for recon networks, probe requests, the client tracker, connected clients, and captured credentials. Credentials can also be exported as CSV.
- Every item can be downloaded or deleted from the page. The index lives at `/var/lib/pinapple/saved.json` and files at `/var/lib/pinapple/saved/`; the library is capped at 200 items.

The WPA2 handshake helper is now part of the repository (`tools/pinapple-handshake`), installed to `/usr/local/bin/`, and uses airodump-ng/aireplay-ng to capture and verify a real EAPOL handshake rather than reporting success for an empty capture.

### Status, activity, and logs

- Every page has a top-bar radio chip showing the wlan1 mode and what currently owns the radio (beacon, deauth, handshake, PMKID, Evil Twin, monitor). Tap it to jump to the relevant WLAN1 tab.
- Starting an action immediately switches buttons into a busy state, shows a status card, and reports errors through toasts instead of failing silently.
- The Overview has a **System check** for required tools and the USB adapter, plus a **Recent activity** feed.
- The Logs tab has sources for Activity, the wlan1 monitor, beacon flood, deauth bursts, dnsmasq, credentials, the scanner, and the dashboard journal. Each source can be cleared in place; credentials are protected and managed from Saved.
- Beacon status reports a stalled heartbeat if its helper stops updating.
- Vendor OUI lookup is included for clients, probes, trackers, and recon networks (from `ieee-data` when installed).

### AP, DHCP, and monitor stack

New installs use hostapd + dnsmasq on `wlan0` at `10.0.0.1`, with NetworkManager leaving both `wlan0` and `wlan1` unmanaged. `pinapple-ap`, `pinapple-dhcp`, and `pinapple-portal` are installed and enabled. The `pinapple-monitor` service owns `wlan1` in monitor mode and writes `probes.json`, `clients_seen.json`, `scan.json`, and `monitor_status.json`; it is paused automatically while an attack owns the radio and resumed afterwards. Rescan temporarily hands `wlan1` to NetworkManager for `nmcli`, then returns it; if NetworkManager is unavailable it falls back to a direct `iw` scan.

### Custom captive portal templates

The Settings page can switch between the bundled templates (Credentials, Hotel, Splash, Cafe, Airport, Library, Gym) and upload your own.

A custom template must be a single `.html` file, max 512 KB, containing:

```html
<form method="POST" action="/portal/submit">
  <input type="hidden" name="portal_type" value="my-template"> <!-- optional -->
  <input type="text" name="name">
  <input type="email" name="email">
  <input type="password" name="password">
  <button type="submit">Connect</button>
</form>
```

- Every input with a `name` is stored as a key/value pair in `creds.log`.
- `portal_type` is optional; if omitted, the active template name is inferred from the portal symlink.
- After submission the handler redirects to `/portal/success`.
- Templates are served from `/opt/pinapple/portal/`; the active one is selected by a symlink at `index.html`.
- Uploaded templates are listed in Settings and can be previewed at `http://10.0.0.1/` from a client on the AP.

---

## Captive Portal Variants

Seven bundled templates are switchable from **Settings**, plus custom upload:

1. **Credentials** — "Free WiFi, login to continue" (email + password capture)
2. **Cafe** — warm cafe-branded login (email + password)
3. **Airport** — terminal Wi-Fi login (email + password)
4. **Hotel** — room number + last name
5. **Library** — name + library card number
6. **Gym** — dark member login (email + password)
7. **Splash** — accept terms only, no credential capture

Upload your own `.html` form in Settings; the contract is documented above and every named field is captured.

---

## Setup

### Requirements
- Raspberry Pi 4 (1GB+ RAM)
- Pi OS Bookworm Lite 64-bit (**not Trixie** — BCM43455 firmware crash bug on kernel 6.12)
- AR9271-based USB WiFi adapter (TP-Link TL-WN722N v1 or similar)
- Laptop with ethernet port and internet sharing capability

### Install

```bash
# SSH into your Pi
ssh <user>@<pi-ip>

# Clone the repo
git clone https://github.com/Doge128/PiNAPPLE.git ~/PiNAPPLE
cd ~/PiNAPPLE

# Run the installer
sudo bash install.sh
```

The installer handles everything: packages, hostapd/dnsmasq, nginx and the portal handler, the wlan1 monitor, systemd units, iptables helpers, Python dependencies, and a final verification summary. It finishes with a reboot.

### Verify

```bash
pinapple-status
```

Then connect to WiFi `PiNAPPLE` and open `http://10.0.0.1:8080`. Default dashboard login: `admin / pinapple` (change this immediately in Settings).

`pinapple-status --json` prints the same information for scripting.

---

## Helper Scripts

| Script | Description |
|---|---|
| `pinapple-status` | Console summary of services, interfaces, radio jobs, saved items and recent activity |
| `pinapple-internet on\|off` | Toggle internet passthrough for AP clients |
| `pinapple-portal on\|off` | Toggle captive portal redirect |
| `pinapple-monitor` | wlan1 monitor mode, channel hop, probes/AP/device capture |
| `pinapple-deauth` | Raw 802.11 deauth injector (burst or continuous) |
| `pinapple-handshake` | WPA2 handshake capture with EAPOL verification |
| `pinapple-beacon-flood` | mdk4 beacon flood with stable BSSIDs |

All helpers use only the Python standard library. `install.sh` installs them to `/usr/local/bin/`.

---

## File Structure

```
/opt/pinapple/          # Flask app + templates
/etc/pinapple/          # Config files
/var/lib/pinapple/      # Saved index + saved captures/snapshots
/var/log/pinapple/      # Logs + scan results + captured creds
/usr/local/bin/         # Helper scripts
```

---

## Systemd Services

All services auto-start on boot in dependency order:

```
pinapple-ap       → hostapd AP on wlan0 (10.0.0.1)
pinapple-dhcp     → dnsmasq DHCP + DNS on wlan0
pinapple-portal   → captive portal submit handler (Waitress)
nginx             → serves the portal pages on port 80
pinapple-dashboard→ Waitress dashboard on :8080
pinapple-monitor  → wlan1 monitor mode, channel hopping, probes/AP/device capture
```

---

## Why Not Just Buy the Pineapple?

You could. But:

- You won't know *why* it works
- You can't modify it at the kernel/driver level
- You don't learn hostapd, dnsmasq, iptables, or how captive portals actually trick devices
- It costs $200

Building this taught me more about WiFi security in one night than months of reading.

---

## Roadmap

- [ ] KARMA attack support (hostapd-wpe)
- [x] Evil twin automation
- [ ] HackRF spectrum analysis integration
- [ ] Flipper Zero bridge
- [x] Mobile-responsive dashboard
- [x] Saved captures and JSON snapshots
- [x] Console status and per-source log management
- [ ] WireGuard VPN tunnel support
- [ ] Automated recon reporting
- [ ] Active capture resume after reboot

---

## Known gaps

- **Legacy NetworkManager installs.** New installs use hostapd + dnsmasq and keep `wlan0` and `wlan1` unmanaged by NetworkManager. If you are upgrading a Pi that previously used the NetworkManager hotspot, re-run `install.sh`; it moves `wlan0` to the hostapd stack and releases `wlan1` for the monitor.
- **Active attacks do not auto-restart after a reboot.** Any helper that survived a dashboard restart is detected, shown, and can be stopped; captures and snapshots already written to disk are kept.
- `extensions.py` contains PineAP, loot-manager, campaign, and help pages, but `register_extensions()` is never called. Those features are dormant and are not reachable from the running dashboard.
- Authentication is HTTP Basic only. This is acceptable for the private hotspot admin panel, but there is no CSRF token or login rate limiting.
- Deauth frames are unprotected 802.11 management frames; WPA3/PMF clients ignore them.
- `pinapple-portal.service` and the nginx site are included and installed, but the portal redirect only covers HTTP. HTTPS interception needs a certificate and explicit client trust.
- The portal submits credentials but does not automatically authorize the client through iptables; use Internet Passthrough if clients need real access after connecting.

---

## Built With

- [hostapd](https://w1.fi/hostapd/) — AP management
- [dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html) — DHCP + DNS
- [Flask](https://flask.palletsprojects.com/) + [Waitress](https://docs.pylonsproject.org/projects/waitress/) — Dashboard backend
- [nginx](https://nginx.org/) — Captive portal server
- [iptables](https://www.netfilter.org/) — NAT + traffic routing
- [Claude Code](https://claude.ai/code) — AI-assisted development

---

## Legal

This tool is for **authorized security testing only**. You are responsible for ensuring you have permission before testing any network. Unauthorized interception of network traffic is illegal in most jurisdictions.

---

## Author

**[@Hackshiz](https://github.com/Doge128)** — cybersec learner, Computer Geek, Outdoor Enthusiest

---

*"I am not in danger. I am the danger."* — Waltuh
