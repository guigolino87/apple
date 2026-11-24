"""Serve the Fieldsignal design preview using local sample data."""

import argparse
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


ASSET_DIR = Path(__file__).resolve().parent / "preview_ui"
ASSETS = {
    "/assets/fields.css": ("fields.css", "text/css; charset=utf-8"),
    "/assets/fields.png": ("fields.png", "image/png"),
}
PRIMARY_NAV = (
    ("/", "Overview", "overview"), ("/clients", "Clients", "clients"),
    ("/recon", "Networks", "networks"), ("/logs", "Activity", "activity"),
)
MORE_GROUPS = (
    ("Monitor", (("/creds", "Credentials", "Portal submission history"),)),
    ("Access point", (
        ("/ap-control", "AP Control", "Sample access point status and configuration"),
        ("/settings", "Settings", "Preview configuration and device connection"),
    )),
    ("Attack tools", (
        ("/wlan1", "WLAN1 Attacks", "Unavailable in local preview"),
        ("/pineap", "PineAP Suite", "Unavailable in local preview"),
    )),
    ("Intel", (
        ("/loot", "Loot", "Saved artifacts"),
        ("/campaigns", "Campaigns", "Saved campaign records"),
    )),
    ("Help", (("/help", "Docs", "How to use the local preview"),)),
)
CLIENTS = (
    ("workbench-laptop", "192.0.2.11", "02:00:00:00:00:11", "11:45"),
    ("bench-tablet", "192.0.2.12", "02:00:00:00:00:12", "12:02"),
)
NETWORKS = (
    ("Workshop", "-43", "6", "WPA2", "02:00:00:00:00:01", "10:28"),
    ("Studio 5 GHz", "-54", "36", "WPA3", "02:00:00:00:00:02", "10:30"),
    ("Workshop Guest", "-67", "11", "Open", "02:00:00:00:00:03", "10:31"),
)
EVENTS = (
    ("10:35:21", "Warning", "Monitor is idle", "wlan1"),
    ("10:31:04", "Info", "Lease renewed for bench-tablet", "DHCP"),
    ("10:28:02", "Info", "Access point started", "wlan0"),
)


def icon(name):
    return f'<span class="icon icon-{name}" aria-hidden="true"></span>'


def nav_link(path, url, label, symbol=None, css_class=None, in_section=False):
    active = ' aria-current="page"' if path == url else ' aria-current="location"' if in_section else ""
    css = f' class="{css_class}"' if css_class else ""
    glyph = icon(symbol) if symbol else ""
    return f'<a href="{url}"{active}{css}>{glyph}<span>{label}</span></a>'


def nav(path):
    primary = "".join(nav_link(path, *item) for item in PRIMARY_NAV)
    more = nav_link(path, "/more", "More", "more", "mobile-more", path not in {item[0] for item in PRIMARY_NAV})
    groups = "".join(
        f'<div class="nav-group"><p>{group}</p>'
        + "".join(nav_link(path, url, label) for url, label, _ in items)
        + "</div>"
        for group, items in MORE_GROUPS
    )
    return f'<nav class="navigation" aria-label="Dashboard">{primary}{more}<div class="desktop-groups">{groups}</div></nav>'


def action(url, label, primary=False):
    variant = " button-primary" if primary else ""
    return f'<a class="button{variant}" href="{url}">{label}{icon("arrow")}</a>'


def status(label, tone="good"):
    return f'<span class="status status-{tone}">{label}</span>'


def fields(items):
    return '<dl class="fields">' + "".join(
        f"<div><dt>{escape(label)}</dt><dd>{escape(value)}</dd></div>" for label, value in items
    ) + "</dl>"


def disclosure(title, subtitle, trailing, extra):
    return f"""<details class="disclosure">
      <summary><span class="row-copy"><strong>{escape(title)}</strong><small>{escape(subtitle)}</small></span>
      <span class="row-end">{trailing}{icon('chevron')}</span></summary>
      <div class="disclosure-body">{fields(extra)}</div>
    </details>"""


def events(entries):
    if not entries:
        return '<p class="empty">No events match this filter.</p>'
    return '<ol class="event-list">' + "".join(
        f"""<li><time>{stamp}</time><div class="event-copy">
        <strong>{escape(message)}</strong><small>{escape(source)}</small></div>
        {status(level, 'warn' if level == 'Warning' else 'neutral')}</li>"""
        for stamp, level, message, source in entries
    ) + "</ol>"


def overview(_query):
    interfaces = (
        ("Ethernet", "eth0", "Up", "good", "192.0.2.4"),
        ("Access point", "wlan0", "Up", "good", "192.0.2.10"),
        ("Monitor", "wlan1", "Idle", "warn", "Unavailable"),
    )
    rows = "".join(
        f'<li><div class="row-copy"><strong>{name}</strong><small>{device}</small></div>'
        f'<span class="interface-ip">{address}</span>{status(label, tone)}</li>'
        for name, device, label, tone, address in interfaces
    )
    return f"""<section class="health" aria-labelledby="health-title">
      <div class="health-main">
        <div><p class="device-model">Raspberry Pi 4</p><h2 id="health-title">Bench node</h2>
        <p class="health-caption">Access point and DHCP are running.</p></div>
        {status('Monitor idle', 'warn')}
      </div>
      <dl class="metrics">
        <div><dt>Connected clients</dt><dd>{len(CLIENTS)}</dd></div>
        <div><dt>Nearby networks</dt><dd>{len(NETWORKS)}</dd></div>
        <div><dt>Uptime</dt><dd>2h 14m</dd></div>
      </dl>
    </section>
    <div class="section-grid">
      <section class="panel" aria-labelledby="interfaces-title">
        <div class="panel-heading"><h2 id="interfaces-title">Interfaces</h2></div>
        <ul class="interface-list">{rows}</ul>
      </section>
      <section class="panel" aria-labelledby="activity-title">
        <div class="panel-heading"><h2 id="activity-title">Recent activity</h2></div>
        {events(EVENTS[:2])}
        <div class="panel-footer">{action('/logs', 'View activity')}</div>
      </section>
    </div>"""


def clients(_query):
    rows = "".join(
        disclosure(name, address, status("Connected"), (("MAC address", mac), ("Lease expires", expires)))
        for name, address, mac, expires in CLIENTS
    )
    return f'<section class="panel list-panel" aria-label="Connected clients">{rows}</section>'


def networks(query):
    strongest = query.get("sort", ["signal"])[0] != "name"
    ordered = sorted(NETWORKS, key=lambda row: -int(row[1]) if strongest else row[0].casefold())
    filters = filter_links("/recon", "sort", "Sort networks", (("signal", "Signal strength"), ("name", "Name")), "signal" if strongest else "name")
    rows = "".join(
        disclosure(name, f"Channel {channel} · {security}", f'<span class="signal">{signal} <small>dBm</small></span>',
                   (("BSSID", mac), ("First seen", seen)))
        for name, signal, channel, security, mac, seen in ordered
    )
    return f'{filters}<section class="panel list-panel" aria-label="Nearby networks">{rows}</section>'


def filter_links(path, param, label, options, current):
    links = []
    for value, name in options:
        active = ' aria-current="true"' if value == current else ""
        links.append(f'<a class="button" href="{path}?{param}={value}"{active}>{name}</a>')
    return f'<nav class="filters" aria-label="{label}">' + "".join(links) + "</nav>"


def activity(query):
    level = query.get("level", ["all"])[0]
    options = (("all", "All events"), ("warning", "Warnings"), ("info", "Info"))
    filters = filter_links("/logs", "level", "Filter activity", options, level)
    entries = tuple(event for event in EVENTS if level == "all" or event[1].lower() == level)
    return f'{filters}<section class="panel" aria-label="System events">{events(entries)}</section>'


def more_pages(_query):
    return '<div class="more-groups">' + "".join(
        f'<section class="panel" aria-labelledby="group-{index}">'
        f'<div class="panel-heading"><h2 id="group-{index}">{group}</h2></div>'
        + "".join(
            f'<a class="directory-row" href="{url}"><span class="row-copy">'
            f'<strong>{label}</strong><small>{description}</small></span>{icon("arrow")}</a>'
            for url, label, description in items
        )
        + "</section>"
        for index, (group, items) in enumerate(MORE_GROUPS)
    ) + "</div>"


def info_panel(title, content):
    return f"""<section class="panel info-panel" aria-labelledby="info-title">
    <div class="panel-heading"><h2 id="info-title">{title}</h2></div>
    <div class="info-body">{content}</div>
    </section>"""


def access_point(_query):
    return info_panel("Workshop access point", fields((
        ("Interface", "wlan0"), ("Status", "Up"), ("Channel", "6"),
        ("Security", "WPA2"), ("Address", "192.0.2.10"),
    )))


def settings(_query):
    return info_panel("Preview configuration", fields((
        ("Data source", "Sample data"), ("Hardware connection", "Disconnected"),
        ("Dashboard address", "127.0.0.1"), ("Changes", "Read-only"),
    )))


def docs(_query):
    return info_panel("Using Fieldsignal", """<ul class="docs-list">
      <li><strong>Overview</strong> shows the status of the sample device and interfaces.</li>
      <li><strong>Clients</strong> and <strong>Networks</strong> show device and wireless details. Select a row to expand it.</li>
      <li><strong>Activity</strong> lets you filter sample events by severity.</li>
      <li><strong>More</strong> opens the rest of the original sidebar on phones.</li>
    </ul><p>From the repository folder, run <code>py preview.py</code> to start the Windows preview.</p>""")


def view_notice(title, message):
    def render_notice(_query):
        return info_panel(title, f"<p>{message}</p>")
    return render_notice


PAGES = {
    "/": ("Overview", "Device health and wireless activity.", overview),
    "/clients": ("Clients", f"{len(CLIENTS)} devices connected to the access point.", clients),
    "/recon": ("Networks", f"{len(NETWORKS)} nearby wireless networks.", networks),
    "/logs": ("Activity", "Events recorded by the bench node.", activity),
    "/more": ("More", "All dashboard sections and documentation.", more_pages),
    "/creds": ("Credentials", "Portal submission history.",
               view_notice("Unavailable in local preview", "The preview contains no portal submissions or credentials.")),
    "/ap-control": ("AP Control", "Read-only snapshot of the sample access point.", access_point),
    "/settings": ("Settings", "Configuration for this local session.", settings),
    "/wlan1": ("WLAN1 Attacks", "Original dashboard section.",
               view_notice("Unavailable in local preview", "This section requires Pi hardware and live tools.")),
    "/pineap": ("PineAP Suite", "Original dashboard section.",
                view_notice("Unavailable in local preview", "This section requires Pi hardware and live tools.")),
    "/loot": ("Loot", "Saved artifacts.",
              view_notice("No artifacts", "The preview contains no saved artifacts.")),
    "/campaigns": ("Campaigns", "Saved campaign records.",
                   view_notice("No campaigns", "The preview contains no saved campaign records.")),
    "/help": ("Docs", "Guide to the local dashboard.", docs),
}


def render(path, query):
    title, description, view = PAGES[path]
    shortcut = action("/recon", "Browse networks", primary=True) if path == "/" else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#131613">
<link rel="icon" href="/assets/fields.png" type="image/png">
<link rel="stylesheet" href="/assets/fields.css">
<title>{title} | Fieldsignal</title>
</head><body>
<a class="skip-link" href="#main">Skip to content</a>
<header class="brand">
  <a class="wordmark" href="/"><img src="/assets/fields.png" width="32" height="32" alt="">Fieldsignal</a>
  <span class="preview-label">Sample data</span>
</header>
{nav(path)}
<main id="main" tabindex="-1">
  <header class="page-heading"><div><h1>{title}</h1><p>{description}</p></div>{shortcut}</header>
  {view(query)}
</main>
</body></html>""".encode("utf-8")


class PreviewHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        target = urlsplit(self.path)
        if target.path in PAGES:
            body = render(target.path, parse_qs(target.query))
            content_type = "text/html; charset=utf-8"
        elif target.path in ASSETS:
            filename, content_type = ASSETS[target.path]
            try:
                body = (ASSET_DIR / filename).read_bytes()
            except FileNotFoundError:
                self.send_error(404)
                return
        else:
            self.send_error(404)
            return

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    with ThreadingHTTPServer(("127.0.0.1", args.port), PreviewHandler) as server:
        print(f"Fieldsignal preview at http://127.0.0.1:{server.server_port}/", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()

