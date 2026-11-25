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
| 🕵️ HTTPS Downgrade (sslstrip) | ✅ |
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
- **Intercept** — HTTPS downgrade: captured plaintext requests per client and per host
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

**Deauth** validates MAC addresses, resolves the target channel from the last recon scan (or accepts an explicit channel), and exposes a rate control. Frames go both ways (AP→station and spoofed station→AP) and cycle reason codes 1/3/7. Before reporting success it reads `/sys/class/net/wlan1/statistics/tx_packets`: a driver that cannot inject is returned as an error, not as a started job. 5 GHz BSSIDs and 802.11w-required APs are refused with an explicit reason. Continuous deauth jobs are tracked, stopped by process group, and cleaned up through a PID file if the dashboard restarts; the WLAN1 mode badge and Evil Twin stop button are wired up again.

**Evil Twin** rebuilds `wlan0` into a clone of the target (SSID, channel and the scanned security profile: WPA/RSN, CCMP/TKIP, PMF, beacon interval, group cipher) and deauths the real AP from `wlan1` so clients look for the twin. The rebuild runs in a worker thread after the HTTP response, because stopping `pinapple-ap` also takes down the AP that serves the dashboard. Every step is verified: hostapd active, the SSID actually on the air, the channel actually set, DHCP running, portal answering, and deauth TX moving. If any of those fail the status card says *degraded* or *failed* with the failing check; it never says "ready" when the radio is not doing what it claims. A phone will only auto-join a clone whose security matches what it saved: cloning a WPA2 network as open makes iOS/Android prompt for the old password and fail ("unable to connect"). Supply the passphrase in the optional field to build a WPA2 twin that matches the saved profile, or target an SSID the device does not have saved (or forget the network first) for an open twin.

With the **Router Update** portal selected, a submitted Wi-Fi password is checked against the capture that already exists for this BSSID first: `pinapple-psk-verify` recomputes the PMK (`PBKDF2-HMAC-SHA1`, 4096 rounds) and the EAPOL MIC for that one candidate, in milliseconds, without touching either radio. That is a single-candidate check, not a wordlist crack: the operator never learns the key unless the user types it. If no capture exists, the portal falls back to a live check (`pinapple-psk-check` associates to the real BSSID; a correct PSK completes the 4-way handshake, PMF and SAE included). A wrong password gets an "incorrect password" page, a correct one is stored in Credentials, shown as the last Evil Twin capture, and the twin is shut down so the victim reconnects to the real AP.

Every handshake capture is now converted to a `.22000` automatically and saved beside the `.pcap`, so the offline path works as soon as a capture exists. The twin's AP profile is cloned from the scan (WPA vs RSN, CCMP/TKIP, PMF, beacon interval, group cipher), because clients match cipher suites and 802.11w capability, not just the SSID. 5 GHz BSSIDs are refused with an explicit error: the AR9271 is 2.4 GHz-only, so it cannot see or deauth them.

Deauth is bidirectional (AP→station and the spoofed station→AP) and cycles reason codes 1/3/7, which is what makes iOS, Android and Windows all act on it. It also verifies that the kernel TX counter moved before reporting success, refuses 802.11w-required APs instead of pretending, and reports a driver that cannot inject as a failure instead of "started".

All helpers are installed to `/usr/local/bin/` by `install.sh` and use only the Python standard library.

### What actually works, per security mode

This is the honest matrix, not marketing. "Works" means the PiNAPPLE path has a defined, tested failure mode when it does not.

| Target | Capture / verify | Notes |
| --- | --- | --- |
| **WEP** | Replay + `aircrack-ng` | Not wired into a tab yet; the tool is installed. |
| **WPA1 (TKIP)** | 4-way handshake, same as WPA2 | `hcxpcapngtool` emits a 22000 line; the verifier tries HMAC-MD5 and SHA1. |
| **WPA2-PSK** (your GOINTERNET router) | Handshake **and** PMKID | The core, reliable path. Deauth must land; see below. |
| **WPA2/WPA3 transition** | Downgrade to WPA2 | The twin mirrors the profile. A client that insists on SAE gets a twin with `sae_password` only if the passphrase is supplied. |
| **WPA3-SAE only** | **No offline attack** | SAE is a PAKE; there is no PMK to test offline. The live `pinapple-psk-check --wpa3` path can verify a typed password, and the twin can clone with a known passphrase. |
| **5 GHz BSSID** | **Not possible with the AR9271** | 2.4 GHz only. The dashboard refuses instead of silently failing. |
| **802.11w required (PMF)** | **Deauth refused** | Protected management frames; deauth is dropped. Dashboard reports this from the scan. |
| **WPS off** (your router) | Pixie Dust impossible | The monitor records `security.wps`; the preflight says so. |

Why a Kali attempt on a home network often "does nothing": adapter on 5 GHz, monitor mode not actually applied, wrong channel, driver that cannot inject (`aireplay-ng --test wlan1mon` is the decisive test), PMF enabled, or an incomplete handshake (M1+M2 with no valid MIC). PiNAPPLE now checks each of those before claiming success.

### Captive-portal speed

The portal is pushed by three mechanisms instead of one:

- `dnsmasq` advertises **DHCP option 114** (RFC 8910), so Android 11+ and recent iOS/macOS open the portal as soon as they join.
- nginx answers the OS probe endpoints (`/hotspot-detect.html`, `/library/test/success.html`, `/generate_204`, `/connecttest.txt`, `/ncsi.txt`) with a `302` to `http://10.0.0.1/` instead of a `200` page, which is the signal those OSes treat as "captive".
- The DNS hijack still catches every other plain-HTTP request.

The **Update firmware** template (`portal/wifi-psk.html`) is intentionally plain: one password field, `name="wifi_password"`, `action="/portal/submit"`, hidden `portal_type=wifi-psk`, and autocomplete/capitalisation disabled for mobile keyboards.

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

New installs use hostapd + dnsmasq on `wlan0` at `10.0.0.1`, with NetworkManager leaving both `wlan0` and `wlan1` unmanaged. `pinapple-ap`, `pinapple-dhcp`, and `pinapple-portal` are installed and enabled. The `pinapple-monitor` service owns `wlan1` in monitor mode and writes `probes.json`, `clients_seen.json`, `scan.json`, and `monitor_status.json`; it is paused automatically while an attack owns the radio and resumed afterwards. Rescan never reconfigures the radio: it waits for the monitor to finish a channel pass and reads `scan.json`. `wlan1` is never handed to NetworkManager and its mode is never flipped by a scan, because taking the attack adapter down also drops clients from the `wlan0` dashboard AP. Only an explicit mode switch in `wlan1` settings, or an attack claiming the radio, changes the interface.

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

## HTTPS Downgrade (Intercept)

The **Intercept** page turns every AP client's port 80 into a readable feed. It is a
stdlib-only reimplementation of [sslstrip](https://github.com/moxie0/sslstrip), built
around the one thing that makes this easy on PiNAPPLE: the Pi *is* the gateway.

Clients already route through the Pi (`pinapple-internet` NAT), so there is no ARP
spoofing and no ettercap. One rule is enough:

```bash
pinapple-strip on                      # wlan0 tcp/80 -> REDIRECT 127.0.0.1:10000
pinapple-strip on --https allow        # leave 443 alone instead of refusing it
pinapple-strip status                  # text summary (--json for scripts)
pinapple-strip off                     # remove the rules, stop the proxy
```

The proxy keeps the client on plain HTTP while it speaks TLS to the real server, so the
request line, headers and form bodies stay readable:

| Rewrite | Why |
|---|---|
| `301/302/307/308 https://…` → `http://…`, host pinned to TLS upstream | the browser re-requests the same http URL, which the proxy fetches over TLS and returns as http |
| drop `Strict-Transport-Security` | a client must never learn the site is HTTPS-only |
| drop `Alt-Svc` | no HTTP/3 upgrade path |
| un-`Secure` cookies | session cookies keep working over http |
| drop CSP `upgrade-insecure-requests` | subresources stay http |
| `https://` → `http://` in text bodies and `<meta>` CSP | links, forms and iframes stay http |
| answer captive probes locally | iOS/Android/Windows report "internet OK" instead of opening a captive sheet |
| log method, URL, query, cookies, form fields, Basic auth | this is what the demo shows |

### What it cannot do

Traffic the phone forces to HTTPS by itself cannot be downgraded without a certificate
the phone trusts, and PiNAPPLE does not install one:

- HSTS preload (compiled into the browser)
- HSTS cached in the browser from an earlier visit
- Chrome's *Always use secure connections*, Firefox HTTPS-Only, HTTPS-First
- a typed `https://` URL, a bookmark, or a PWA
- HTTP/3 (QUIC) over UDP 443
- DoH/DoT resolvers (irrelevant here, but they defeat DNS tricks)

By default `pinapple-strip on` refuses `udp/443` (so the browser falls back instead of
silently bypassing the proxy) and `tcp/443` (so a refused downgrade fails loudly).
`--https allow` leaves 443 alone: those flows stay encrypted and invisible. **TLS refused**
on the Intercept page counts the blocked flows — it is the only trace a site leaves when
it refuses to downgrade.

Even with `--https allow`, encryption does not hide where the traffic goes: the client's
DNS queries are still in `dnsmasq.log`, so you can show "encrypted, unreadable, but here
are the hosts and ports" as the honest counterpoint.

### Testing your own sites

Two commands per site you control:

```bash
curl -sI https://yoursite.tld | grep -iE 'strict-transport-security|upgrade-insecure|alt-svc'
curl -sI http://yoursite.tld        # 301/308 to https = it refuses to be downgraded
```

| Result | Meaning |
|---|---|
| `http://` answers 301/308 → https | rejects the downgrade; only the TLS counter moves |
| `http://` answers 200 | served plain; fully visible in the request log |
| HSTS header present | the browser pins HTTPS after its first visit |
| On the HSTS preload list | always rejected, forever, on every device |

### Demo checklist (before recording)

- AP security set to **Open** in AP Control, so a fresh device can join without a prompt.
- **Internet Passthrough ON**, **DNS Hijack OFF**, **Portal Redirect OFF**. Starting the
  downgrade turns the last two off automatically, because all three want port 80.
- Use a phone that has never visited the test domain, or clear site data. A cached HSTS
  entry survives everything the proxy does.
- Turn off *Always use secure connections* in Chrome (Android: Privacy and security).
- Prefer a test domain that is not on the HSTS preload list.
- Keep the dashboard on `:8080`; it is not redirected.

Expected first visit to an HTTPS-only site: the plain request gets a rewritten 301, the
browser asks for the same http URL, the proxy fetches it over TLS and returns it as http.
One extra request per host, then every page and form is readable.

### Limitations

- **POST bodies can be sent twice** to a site that answers a plain POST with a redirect to
  https. The proxy tries TLS first for POST/PUT/PATCH/DELETE to avoid it, but a form that
  posts to a plain-http endpoint still reaches both.
- **Certificate errors are not bypassed.** Upstream TLS is verified against the Pi's CA
  store (`ca-certificates`); `--insecure` disables verification and is not the default.
- The logs hold credentials and session cookies. `strip.log` and `strip.jsonl` are created
  `0600` — treat them as loot, and do not screen-share them by accident.
- The systemd unit `pinapple-strip.service` is installed but **not enabled**: it must not
  survive a reboot, because it leaves a port-80 redirect behind while running.

---

## Captive Portal Variants

Eight bundled templates are switchable from **Settings**, plus custom upload:

1. **Update firmware** — the Evil Twin default: one password field, validated against the target (offline capture first, live association second)
2. **Credentials** — "Free WiFi, login to continue" (email + password capture)
3. **Cafe** — warm cafe-branded login (email + password)
4. **Airport** — terminal Wi-Fi login (email + password)
5. **Hotel** — room number + last name
6. **Library** — name + library card number
7. **Gym** — dark member login (email + password)
8. **Splash** — accept terms only, no credential capture

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
| `pinapple-deauth` | Raw 802.11 deauth injector (bidirectional, reasons 1/3/7, TX verification) |
| `pinapple-handshake` | WPA2 handshake capture with EAPOL verification |
| `pinapple-psk-check` | Live PSK/SAE check against a real AP (association, PMF-aware) |
| `pinapple-psk-verify` | Offline check of **one** typed passphrase against a 22000 capture (no wordlist) |
| `pinapple-beacon-flood` | mdk4 beacon flood with stable BSSIDs |
| `pinapple-strip` | HTTPS downgrade proxy (sslstrip) for AP clients, with a plaintext request log |

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
pinapple-strip    → HTTPS downgrade proxy (started from the dashboard, not at boot)
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
- [x] HTTPS downgrade (sslstrip) with plaintext request log
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
- **Leftover Evil Twin portal (fixed).** Starting a twin used to leave DNS hijack + the port-80 redirect armed after it stopped, so a reboot still opened the "Update firmware" portal instead of the dashboard. The twin now snapshots and restores those settings, and a dashboard restart tears down any twin that outlived it. On an older build the manual recovery is: `sudo rm -f /etc/pinapple/dns_hijack_enabled /etc/pinapple/portal_redirect_enabled /var/lib/pinapple/eviltwin.json /var/run/pinapple-eviltwin.pid`, put `# DNS hijack disabled` in `/etc/pinapple/dnsmasq-hijack.conf`, run `sudo /usr/local/bin/pinapple-portal off`, then `sudo systemctl restart pinapple-ap pinapple-dhcp pinapple-dashboard`. Open the panel at `http://10.0.0.1:8080` (the portal owns port 80).
- `extensions.py` contains PineAP, loot-manager, campaign, and help pages, but `register_extensions()` is never called. Those features are dormant and are not reachable from the running dashboard.
- Authentication is HTTP Basic only. This is acceptable for the private hotspot admin panel, but there is no CSRF token or login rate limiting.
- Deauth frames are unprotected 802.11 management frames; WPA3/PMF clients ignore them.
- `pinapple-portal.service` and the nginx site are included and installed, but the portal redirect only covers HTTP. HTTPS interception needs a certificate and explicit client trust; the **Intercept** page (see [HTTPS Downgrade](#https-downgrade-intercept)) downgrades the session instead of terminating TLS.
- The portal submits credentials but does not automatically authorize the client through iptables; use Internet Passthrough if clients need real access after connecting.

---

## Built With

- [hostapd](https://w1.fi/hostapd/) — AP management
- [dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html) — DHCP + DNS
- [Flask](https://flask.palletsprojects.com/) + [Waitress](https://docs.pylonsproject.org/projects/waitress/) — Dashboard backend
- [nginx](https://nginx.org/) — Captive portal server
- [iptables](https://www.netfilter.org/) — NAT + traffic routing
- [sslstrip](https://github.com/moxie0/sslstrip) — the HTTPS downgrade technique (Moxie Marlinspike, 2009)
- [Claude Code](https://claude.ai/code) — AI-assisted development

---

## Legal

This tool is for **authorized security testing only**. You are responsible for ensuring you have permission before testing any network. Unauthorized interception of network traffic is illegal in most jurisdictions. The HTTPS downgrade captures credentials, cookies and form bodies from every device that joins the AP — use it on hardware you own, and delete the logs when you are done.

---

## Author

**[@Hackshiz](https://github.com/Doge128)** — cybersec learner, Computer Geek, Outdoor Enthusiest

---

*"I am not in danger. I am the danger."* — Waltuh
