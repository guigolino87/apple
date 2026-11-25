#!/usr/bin/env python3
"""Safe, RF-free regression tests for the PiNAPPLE attack helpers.

Run with:  python3 -m unittest discover -s tests -v
No Flask, Pi, or wireless hardware is required.
"""

import hashlib
import importlib.machinery
import importlib.util
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class BeaconHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load('beacon_helper', os.path.join(ROOT, 'tools', 'pinapple-beacon-flood'))

    def test_oui_is_unicast_and_normalized(self):
        self.assertEqual(self.mod.normalize_oui('AA-BB-CC'), 'aa:bb:cc')
        self.assertEqual(self.mod.normalize_oui('0d:00:5e'), '0c:00:5e')

    def test_channels_are_validated_and_deduplicated(self):
        self.assertEqual(self.mod.parse_channels('1,6,11,6'), [1, 6, 11])
        with self.assertRaises(SystemExit):
            self.mod.parse_channels('1,15')
        with self.assertRaises(SystemExit):
            self.mod.parse_channels('')

    def test_pairs_are_stable_and_repeated(self):
        pairs = self.mod.build_pairs(['Lab', 'Guest'], '00:11:22', 2)
        self.assertEqual(len(pairs), 4)
        self.assertEqual(pairs[0].split(' ', 1)[1], 'Lab')
        self.assertEqual(pairs[0].split(' ', 1)[0], pairs[1].split(' ', 1)[0])
        self.assertNotEqual(pairs[0].split(' ', 1)[0], pairs[2].split(' ', 1)[0])
        self.assertEqual(self.mod.build_pairs(['Lab'], '00:11:22', 2),
                         self.mod.build_pairs(['Lab'], '00:11:22', 2))


class HandshakeHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load('handshake_helper', os.path.join(ROOT, 'tools', 'pinapple-handshake'))

    def test_mac_validation(self):
        self.assertTrue(self.mod.valid_mac('AA:BB:CC:DD:EE:FF'))
        self.assertFalse(self.mod.valid_mac('not-a-mac'))


class MonitorHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load('monitor_helper', os.path.join(ROOT, 'tools', 'pinapple-monitor'))

    def test_radiotap_channel_and_signal(self):
        import struct
        header = (b'\x00\x00\x0d\x00' + struct.pack('<I', 0x28) +
                  struct.pack('<H', 2437) + b'\x00\x00' + struct.pack('<b', -42))
        length, channel, dbm = self.mod.parse_radiotap(header)
        self.assertEqual(length, 13)
        self.assertEqual(channel, 6)
        self.assertEqual(dbm, -42)

    def test_beacon_and_probe_parsing(self):
        import struct
        bssid = bytes.fromhex('aabbccddeeff')
        client = bytes.fromhex('001122334455')
        radiotap = b'\x00\x00\x08\x00\x00\x00\x00\x00'

        def frame(fc, a1, a2, a3, body):
            return (struct.pack('<H', fc) + b'\x00\x00' + a1 + a2 + a3 +
                    b'\x00\x00' + body)

        ssid = b'\x00\x03Lab'
        ds = b'\x03\x01\x06'
        rsn = b'\x30\x02\x01\x00'
        fixed = b'\x00' * 8 + b'\x64\x00' + b'\x01\x00'
        beacon = frame(0x0080, b'\xff' * 6, bssid, bssid, fixed + ssid + ds + rsn)
        parsed = self.mod.parse_frame(radiotap + beacon)
        self.assertEqual(parsed['kind'], 'beacon')
        self.assertEqual(parsed['ssid'], 'Lab')
        self.assertEqual(parsed['ap_channel'], 6)
        self.assertEqual(parsed['encryption'], 'WPA2')

        probe = frame(0x0040, b'\xff' * 6, client, b'\xff' * 6, ssid)
        parsed = self.mod.parse_frame(radiotap + probe)
        self.assertEqual(parsed['kind'], 'probe-req')
        self.assertEqual(parsed['ssid'], 'Lab')


class DeauthHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load('deauth_helper', os.path.join(ROOT, 'tools', 'pinapple-deauth'))

    def test_frame_layout(self):
        frame = self.mod.deauth_frame('FF:FF:FF:FF:FF:FF',
                                      'AA:BB:CC:DD:EE:FF',
                                      'AA:BB:CC:DD:EE:FF', 7)
        self.assertEqual(len(frame), 26)
        self.assertEqual(frame[0:2], b'\xc0\x00')
        self.assertEqual(frame[4:10], bytes.fromhex('ffffffffffff'))
        self.assertEqual(frame[10:16], bytes.fromhex('aabbccddeeff'))
        self.assertEqual(frame[16:22], bytes.fromhex('aabbccddeeff'))
        self.assertEqual(frame[22:24], (7 << 4).to_bytes(2, 'little'))
        self.assertEqual(frame[24:26], (1).to_bytes(2, 'little'))
        self.assertEqual(len(self.mod.RADIOTAP), 8)

    def test_cli_rejects_bad_mac(self):
        argv = sys.argv
        sys.argv = ['pinapple-deauth', 'not-a-mac', 'FF:FF:FF:FF:FF:FF', '10']
        try:
            with self.assertRaises(SystemExit):
                self.mod.main()
        finally:
            sys.argv = argv


class AppLogicTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        flask = types.ModuleType('flask')

        class Flask:
            def __init__(self, *a, **k):
                self.config = {}

            def route(self, *a, **k):
                return lambda f: f

        flask.Flask = Flask
        flask.request = types.SimpleNamespace(
            authorization=None,
            args=types.SimpleNamespace(get=lambda key, default=None: default))
        flask.jsonify = lambda *a, **k: a[0] if a else k
        flask.Response = lambda *a, **k: None
        flask.redirect = lambda *a, **k: None
        werkzeug = types.ModuleType('werkzeug')
        security = types.ModuleType('werkzeug.security')
        security.check_password_hash = lambda *a: True
        security.generate_password_hash = lambda x, **kw: x
        sys.modules['flask'] = flask
        sys.modules['werkzeug'] = werkzeug
        sys.modules['werkzeug.security'] = security
        sys.path.insert(0, ROOT)
        cls.app = load('pinapple_app', os.path.join(ROOT, 'app.py'))

    def test_mac_validation(self):
        self.assertTrue(self.app.valid_mac('AA:BB:CC:DD:EE:FF'))
        self.assertFalse(self.app.valid_mac('AA-BB-CC-DD-EE-GG'))

    def test_channel_parsing(self):
        self.assertEqual(self.app.parse_channel_list('1,6,11'), [1, 6, 11])
        self.assertEqual(self.app.parse_channel_list(['2', '3']), [2, 3])
        self.assertIsNone(self.app.parse_channel_list('1,bogus'))

    def test_nmcli_parser_handles_escaped_colons(self):
        line = r'My\:WiFi:AA\:BB\:CC\:DD\:EE\:FF:6:72:WPA2'
        self.assertEqual(self.app.split_nmcli_fields(line),
                         ['My:WiFi', 'AA:BB:CC:DD:EE:FF', '6', '72', 'WPA2'])
        self.assertEqual(self.app.split_nmcli_fields('plain:ssid:1:50:Open'),
                         ['plain', 'ssid', '1', '50', 'Open'])

    def test_nmcli_wifi_parser_normalizes_signal(self):
        text = (r'Lab\:Net:AA\:BB\:CC\:DD\:EE\:01:6:72:WPA2'
                '\nGuest:AA\\:BB\\:CC\\:DD\\:EE\\:02:11:30:Open')
        nets = self.app.parse_nmcli_wifi(text)
        self.assertEqual(len(nets), 2)
        self.assertEqual(nets[0]['ssid'], 'Lab:Net')
        self.assertEqual(nets[0]['channel'], 6)
        self.assertEqual(nets[0]['signal'], -64)
        self.assertEqual(nets[0]['signal_unit'], 'dBm')
        self.assertEqual(nets[0]['encryption'], 'WPA2')
        self.assertEqual(nets[1]['encryption'], 'Open')

    def test_iw_scan_parser(self):
        text = (
            'BSS aa:bb:cc:dd:ee:01(on wlan1)\n'
            '\tfreq: 2437\n'
            '\tsignal: -42.00 dBm\n'
            '\tcapability: ESS Privacy (0x0011)\n'
            '\tSSID: Lab\n'
            '\tRSN: * Version: 1\n'
            '\t\t * Authentication suites: PSK SAE\n'
            'BSS aa:bb:cc:dd:ee:02(on wlan1)\n'
            '\tfreq: 2462\n'
            '\tsignal: -70.00 dBm\n'
            '\tcapability: ESS (0x0001)\n'
            '\tSSID: Open Net\n')
        nets = self.app.parse_iw_scan(text)
        self.assertEqual(len(nets), 2)
        self.assertEqual(nets[0]['bssid'], 'aa:bb:cc:dd:ee:01')
        self.assertEqual(nets[0]['channel'], 6)
        self.assertEqual(nets[0]['signal'], -42)
        self.assertEqual(nets[0]['encryption'], 'WPA3')
        self.assertEqual(nets[1]['channel'], 11)
        self.assertEqual(nets[1]['encryption'], 'Open')

    def test_saved_library_roundtrip(self):
        import tempfile, shutil
        root = tempfile.mkdtemp(prefix='pinapple-saved-')
        old_dir, old_index = self.app.SAVED_DIR, self.app.SAVED_INDEX
        try:
            self.app.SAVED_DIR = os.path.join(root, 'saved')
            self.app.SAVED_INDEX = os.path.join(root, 'saved.json')
            item = self.app.saved_add('handshake', 'Lab network',
                                      payload=b'pcapbytes', ext='pcap',
                                      subtitle='AA:BB ch 6', meta={'channel': 6})
            self.assertTrue(item['id'])
            self.assertEqual(item['size'], 9)
            self.assertEqual(len(self.app.saved_items()), 1)
            path = self.app.saved_path(item)
            self.assertIsNotNone(path)
            with open(path, 'rb') as handle:
                self.assertEqual(handle.read(), b'pcapbytes')
            self.assertEqual(self.app.saved_find(item['id'])['title'], 'Lab network')
            self.assertTrue(self.app.saved_delete(item['id']))
            self.assertEqual(self.app.saved_items(), [])
            self.assertFalse(os.path.exists(path))
        finally:
            self.app.SAVED_DIR, self.app.SAVED_INDEX = old_dir, old_index
            shutil.rmtree(root, ignore_errors=True)

    def test_saved_snapshot_is_readable_json(self):
        import tempfile, shutil, json
        root = tempfile.mkdtemp(prefix='pinapple-snap-')
        old_dir, old_index = self.app.SAVED_DIR, self.app.SAVED_INDEX
        old_recon = self.app.get_recon
        try:
            self.app.SAVED_DIR = os.path.join(root, 'saved')
            self.app.SAVED_INDEX = os.path.join(root, 'saved.json')
            self.app.get_recon = lambda: [{'ssid': 'Lab', 'bssid': 'AA:BB:CC:DD:EE:FF'}]
            item = self.app.saved_snapshot('recon')
            self.assertEqual(item['type'], 'recon')
            path = self.app.saved_path(item)
            with open(path) as handle:
                data = json.load(handle)
            self.assertEqual(data['count'], 1)
            self.assertEqual(data['items'][0]['ssid'], 'Lab')
        finally:
            self.app.SAVED_DIR, self.app.SAVED_INDEX = old_dir, old_index
            self.app.get_recon = old_recon
            shutil.rmtree(root, ignore_errors=True)

    def test_record_loader_supports_array_and_jsonl(self):
        import tempfile, shutil
        root = tempfile.mkdtemp(prefix='pinapple-records-')
        path = os.path.join(root, 'records.json')
        try:
            with open(path, 'w') as handle:
                handle.write('[{"a": 1}]')
            self.assertEqual(self.app.load_records_file(path), [{'a': 1}])
            with open(path, 'w') as handle:
                handle.write('{"a": 1}\n{"a": 2}\n')
            self.assertEqual(len(self.app.load_records_file(path)), 2)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_portal_upload_contract(self):
        import tempfile, shutil
        root = tempfile.mkdtemp(prefix='pinapple-portal-')
        old_dir = self.app.PORTAL_DIR
        original = self.app.request

        class Upload:
            def __init__(self, filename, data):
                self.filename = filename
                self._data = data

            def read(self, size=-1):
                return self._data if size < 0 else self._data[:size]

        try:
            self.app.PORTAL_DIR = root
            good = (b'<!doctype html><form method="POST" action="/portal/submit">'
                    b'<input name="email"></form>')
            self.app.request = types.SimpleNamespace(
                method='POST', form={'action': 'upload_portal'}, json={},
                files={'portal_file': Upload('my portal.html', good)},
                args=types.SimpleNamespace(get=lambda k, d=None: d))
            self.app.settings_page.__wrapped__()
            names = os.listdir(root)
            self.assertEqual(len(names), 1)
            self.assertTrue(names[0].startswith('custom_my_portal_'))
            with open(os.path.join(root, names[0]), 'rb') as handle:
                self.assertEqual(handle.read(), good)

            bad = b'<html><body>no form</body></html>'
            self.app.request = types.SimpleNamespace(
                method='POST', form={'action': 'upload_portal'}, json={},
                files={'portal_file': Upload('bad.html', bad)},
                args=types.SimpleNamespace(get=lambda k, d=None: d))
            self.app.settings_page.__wrapped__()
            self.assertEqual(len(os.listdir(root)), 1)
        finally:
            self.app.PORTAL_DIR = old_dir
            self.app.request = original
            shutil.rmtree(root, ignore_errors=True)

    def test_commands_use_arrays_and_bounded_rate(self):
        cmd = self.app.deauth_command('AA:BB:CC:DD:EE:FF',
                                      'FF:FF:FF:FF:FF:FF', 6, 20,
                                      continuous=True)
        self.assertIsInstance(cmd, list)
        self.assertIn('--continuous', cmd)
        self.assertIn('--channel', cmd)
        self.assertIn('6', cmd)

    def test_rendered_page_has_new_controls(self):
        html = self.app.wlan1_page.__wrapped__()
        for needle in ('bf-phrase', 'bf-count', 'bf-live', 'bf-stat-count',
                       'bf-rate', 'bf-channels', 'bf-dwell', 'bf-repeat',
                       'da-channel', 'da-rate', 'da-jobs', 'da-status-card',
                       'wl-tabs', 'scan-tbody', 'hs-status-card',
                       'et-status-card', 'pmkid-status-card'):
            self.assertIn(needle, html)

    def test_beacon_ssids_are_numbered_and_bounded(self):
        ssids, trimmed = self.app.build_beacon_ssids('Lab', 3)
        self.assertEqual(ssids, ['Lab 1', 'Lab 2', 'Lab 3'])
        self.assertFalse(trimmed)

        long_name = 'x' * 40
        ssids, trimmed = self.app.build_beacon_ssids(long_name, 2)
        self.assertTrue(trimmed)
        for name in ssids:
            self.assertLessEqual(len(name.encode('utf-8')), 32)
            self.assertTrue(name.startswith('x'))

        self.assertEqual(self.app.build_beacon_ssids('Lab', 1)[0], ['Lab'])
        with self.assertRaises(ValueError):
            self.app.build_beacon_ssids('   ', 2)

    def test_beacon_ssids_strip_control_characters(self):
        ssids, _ = self.app.build_beacon_ssids('A\nB\tC', 1)
        self.assertEqual(ssids, ['A B C'])

    def test_auto_beacon_rate_covers_short_scan(self):
        self.assertEqual(self.app.auto_beacon_rate(25), 250)
        self.assertEqual(self.app.auto_beacon_rate(10), 200)
        self.assertEqual(self.app.auto_beacon_rate(200), 500)

    def test_beacon_start_validates_before_touching_radio(self):
        original = self.app.request
        try:
            self.app.request = types.SimpleNamespace(json={'ssid': '   ', 'count': 5})
            response = self.app.api_beacon_start.__wrapped__()
            self.assertFalse(response['ok'])
            self.assertIn('name', response['error'])

            self.app.request = types.SimpleNamespace(json={'ssid': 'Lab', 'count': 0})
            response = self.app.api_beacon_start.__wrapped__()
            self.assertFalse(response['ok'])
            self.assertIn('count', response['error'])

            self.app.request = types.SimpleNamespace(
                json={'ssid': 'Lab', 'count': 5, 'channels': '1,99'})
            response = self.app.api_beacon_start.__wrapped__()
            self.assertFalse(response['ok'])
            self.assertIn('channels', response['error'])
        finally:
            self.app.request = original

    def test_mode_switch_is_blocked_while_radio_busy(self):
        original = self.app.request
        previous = self.app._wlan1_owner[0]
        original_reconcile = self.app.reconcile_wlan1_owner
        try:
            self.app._wlan1_owner[0] = 'beacon'
            self.app.reconcile_wlan1_owner = lambda: 'beacon'
            self.app.request = types.SimpleNamespace(
                method='POST', json={'mode': 'managed'}, form={})
            response = self.app.api_wlan1_mode.__wrapped__()
            self.assertFalse(response['ok'])
            self.assertIn('Beacon Flood', response['error'])
        finally:
            self.app._wlan1_owner[0] = previous
            self.app.reconcile_wlan1_owner = original_reconcile
            self.app.request = original

    def test_recon_scan_refuses_while_radio_busy(self):
        original = self.app.request
        previous = self.app._wlan1_owner[0]
        original_reconcile = self.app.reconcile_wlan1_owner
        try:
            self.app._wlan1_owner[0] = 'deauth'
            self.app.reconcile_wlan1_owner = lambda: 'deauth'
            self.app.request = types.SimpleNamespace(json={}, form={}, method='POST')
            response = self.app.api_recon_scan.__wrapped__()
            self.assertFalse(response['ok'])
            self.assertIn('Deauth', response['error'])
        finally:
            self.app._wlan1_owner[0] = previous
            self.app.reconcile_wlan1_owner = original_reconcile
            self.app.request = original

    def test_deauth_burst_rejects_runaway_duration(self):
        original_helper = self.app.DEAUTH_HELPER
        previous = self.app._wlan1_owner[0]
        original_req = self.app.request
        try:
            self.app.DEAUTH_HELPER = os.path.join(ROOT, 'tools', 'pinapple-deauth')
            self.app._wlan1_owner[0] = None
            self.app.request = types.SimpleNamespace(
                json={'bssid': 'AA:BB:CC:DD:EE:FF', 'count': 500, 'rate': 1,
                      'channel': 6},
                form={}, method='POST')
            response = self.app.api_deauth.__wrapped__()
            self.assertFalse(response['ok'])
            self.assertIn('seconds', response['error'])
            self.assertIsNone(self.app._wlan1_owner[0])
        finally:
            self.app.DEAUTH_HELPER = original_helper
            self.app._wlan1_owner[0] = previous
            self.app.request = original_req

    def test_deauth_reports_unknown_channel(self):
        original_req = self.app.request
        original_recon = self.app.get_recon
        previous = self.app._wlan1_owner[0]
        try:
            self.app._wlan1_owner[0] = None
            self.app.get_recon = lambda: []
            self.app.request = types.SimpleNamespace(
                json={'bssid': 'AA:BB:CC:DD:EE:FF', 'count': 10, 'rate': 10},
                form={}, method='POST')
            response = self.app.api_deauth.__wrapped__()
            self.assertFalse(response['ok'])
            self.assertIn('channel unknown', response['error'])
            self.assertIsNone(self.app._wlan1_owner[0])
        finally:
            self.app._wlan1_owner[0] = previous
            self.app.get_recon = original_recon
            self.app.request = original_req

    def test_handshake_rejects_bad_bssid_before_claiming_radio(self):
        previous = self.app._wlan1_owner[0]
        original_req = self.app.request
        try:
            self.app._wlan1_owner[0] = None
            self.app.request = types.SimpleNamespace(
                json={'bssid': 'not-a-mac', 'channel': 6}, form={}, method='POST')
            response = self.app.api_handshake_start.__wrapped__()
            self.assertFalse(response['ok'])
            self.assertIsNone(self.app._wlan1_owner[0])
        finally:
            self.app._wlan1_owner[0] = previous
            self.app.request = original_req

    def test_job_status_endpoints_are_idle_safely(self):
        self.app._pmkid_proc[0] = None
        self.app._evil_twin_job[0] = None
        pmkid = self.app.api_pmkid_status.__wrapped__()
        twin = self.app.api_evil_twin_status.__wrapped__()
        self.assertFalse(pmkid['running'])
        self.assertFalse(twin['running'])

    def test_hcxdumptool_command_is_version_tolerant(self):
        cmd = self.app.hcxdumptool_command('wlan1', '/tmp/cap.pcapng')
        self.assertEqual(cmd[:2], ['hcxdumptool', '-i'])
        self.assertIn('wlan1', cmd)
        self.assertIn('/tmp/cap.pcapng', cmd)

    def test_reconcile_owner_on_non_linux_keeps_owner(self):
        previous = self.app._wlan1_owner[0]
        original_isdir = self.app.os.path.isdir
        try:
            self.app._wlan1_owner[0] = 'beacon'
            self.app.os.path.isdir = lambda p: False
            self.assertEqual(self.app.reconcile_wlan1_owner(), 'beacon')
        finally:
            self.app.os.path.isdir = original_isdir
            self.app._wlan1_owner[0] = previous

    def test_twin_portal_snapshot_and_restore(self):
        import json, shutil
        root = tempfile.mkdtemp(prefix='pinapple-portal-state-')
        names = ('FLAG_DNS', 'FLAG_PORTAL', 'DNSMASQ_HIJACK',
                 'EVILTWIN_PORTAL_STATE')
        old = {name: getattr(self.app, name) for name in names}
        try:
            self.app.FLAG_DNS = os.path.join(root, 'dns')
            self.app.FLAG_PORTAL = os.path.join(root, 'portal')
            self.app.DNSMASQ_HIJACK = os.path.join(root, 'hijack.conf')
            self.app.EVILTWIN_PORTAL_STATE = os.path.join(root, 'twin-portal.json')
            # The operator had the HTTP redirect on before the twin, DNS off.
            open(self.app.FLAG_PORTAL, 'w').close()
            calls = []

            def record(kind):
                return lambda value, *a, **k: calls.append((kind, value)) or True

            with mock.patch.object(self.app, '_active_portal_slug',
                                   return_value='creds'), \
                    mock.patch.object(self.app, 'set_active_portal',
                                      side_effect=record('portal')), \
                    mock.patch.object(self.app, 'set_dns_hijack',
                                      side_effect=record('dns')), \
                    mock.patch.object(self.app, 'set_portal_redirect',
                                      side_effect=record('redir')):
                self.app.prepare_twin_portal('wifi-psk')
                with open(self.app.EVILTWIN_PORTAL_STATE) as handle:
                    snapshot = json.load(handle)
                self.assertFalse(snapshot['dns_hijack'])
                self.assertTrue(snapshot['portal_redirect'])
                self.assertEqual(snapshot['portal'], 'creds')
                self.app.restore_twin_portal('test')
            self.assertIn(('dns', False), calls)
            self.assertNotIn(('redir', False), calls)
            self.assertIn(('portal', 'creds'), calls)
            self.assertFalse(os.path.exists(self.app.EVILTWIN_PORTAL_STATE))
        finally:
            for name, value in old.items():
                setattr(self.app, name, value)
            shutil.rmtree(root, ignore_errors=True)

    def test_legacy_twin_portal_hijack_is_cleared(self):
        import shutil
        root = tempfile.mkdtemp(prefix='pinapple-legacy-portal-')
        names = ('FLAG_DNS', 'FLAG_PORTAL', 'DNSMASQ_HIJACK',
                 'EVILTWIN_PORTAL_STATE', 'EVILTWIN_STATE', 'EVILTWIN_BACKUP',
                 'LEGACY_PORTAL_CLEANUP')
        old = {name: getattr(self.app, name) for name in names}
        try:
            self.app.FLAG_DNS = os.path.join(root, 'dns')
            self.app.FLAG_PORTAL = os.path.join(root, 'portal')
            self.app.DNSMASQ_HIJACK = os.path.join(root, 'hijack.conf')
            self.app.EVILTWIN_PORTAL_STATE = os.path.join(root, 'missing.json')
            self.app.EVILTWIN_STATE = os.path.join(root, 'no-state.json')
            self.app.EVILTWIN_BACKUP = os.path.join(root, 'no-backup.bak')
            self.app.LEGACY_PORTAL_CLEANUP = os.path.join(root, 'no-cleanup-marker')
            open(self.app.FLAG_DNS, 'w').close()
            open(self.app.FLAG_PORTAL, 'w').close()
            calls = []
            with mock.patch.object(self.app, '_active_portal_slug',
                                   return_value='wifi-psk'), \
                    mock.patch.object(self.app, 'set_active_portal'), \
                    mock.patch.object(self.app, 'set_dns_hijack',
                                      side_effect=lambda v, *a, **k:
                                      calls.append(('dns', v)) or True), \
                    mock.patch.object(self.app, 'set_portal_redirect',
                                      side_effect=lambda v, *a, **k:
                                      calls.append(('redir', v)) or True):
                self.assertTrue(self.app.restore_twin_portal('legacy'))
            self.assertIn(('dns', False), calls)
            self.assertIn(('redir', False), calls)
        finally:
            for name, value in old.items():
                setattr(self.app, name, value)
            shutil.rmtree(root, ignore_errors=True)

    def test_legacy_portal_cleanup_is_one_shot(self):
        import shutil
        root = tempfile.mkdtemp(prefix='pinapple-manual-portal-')
        names = ('FLAG_DNS', 'FLAG_PORTAL', 'DNSMASQ_HIJACK',
                 'EVILTWIN_PORTAL_STATE', 'EVILTWIN_STATE', 'EVILTWIN_BACKUP',
                 'LEGACY_PORTAL_CLEANUP')
        old = {name: getattr(self.app, name) for name in names}
        try:
            self.app.FLAG_DNS = os.path.join(root, 'dns')
            self.app.FLAG_PORTAL = os.path.join(root, 'portal')
            self.app.DNSMASQ_HIJACK = os.path.join(root, 'hijack.conf')
            self.app.EVILTWIN_PORTAL_STATE = os.path.join(root, 'missing.json')
            self.app.EVILTWIN_STATE = os.path.join(root, 'no-state.json')
            self.app.EVILTWIN_BACKUP = os.path.join(root, 'no-backup.bak')
            self.app.LEGACY_PORTAL_CLEANUP = os.path.join(root, 'cleanup-marker')
            open(self.app.FLAG_DNS, 'w').close()
            open(self.app.FLAG_PORTAL, 'w').close()
            open(self.app.LEGACY_PORTAL_CLEANUP, 'w').close()
            calls = []
            with mock.patch.object(self.app, '_active_portal_slug',
                                   return_value='wifi-psk'), \
                    mock.patch.object(self.app, 'set_active_portal'), \
                    mock.patch.object(self.app, 'set_dns_hijack',
                                      side_effect=lambda *a, **k:
                                      calls.append('dns') or True), \
                    mock.patch.object(self.app, 'set_portal_redirect',
                                      side_effect=lambda *a, **k:
                                      calls.append('redir') or True):
                self.assertFalse(self.app.restore_twin_portal('manual'))
            self.assertEqual(calls, [])
        finally:
            for name, value in old.items():
                setattr(self.app, name, value)
            shutil.rmtree(root, ignore_errors=True)

    def test_dns_hijack_only_advertises_option_114_while_active(self):
        import shutil
        root = tempfile.mkdtemp(prefix='pinapple-option114-')
        names = ('FLAG_DNS', 'DNSMASQ_HIJACK', 'PORTAL_ACTIVE')
        old = {name: getattr(self.app, name) for name in names}
        try:
            self.app.FLAG_DNS = os.path.join(root, 'dns')
            self.app.DNSMASQ_HIJACK = os.path.join(root, 'hijack.conf')
            self.app.PORTAL_ACTIVE = os.path.join(root, 'portal-active')
            with mock.patch.object(self.app.subprocess, 'run',
                                   return_value=mock.Mock(returncode=0)):
                self.assertTrue(self.app.set_dns_hijack(True, '10.0.0.1'))
                with open(self.app.DNSMASQ_HIJACK) as handle:
                    active = handle.read()
                self.assertIn('address=/#/10.0.0.1', active)
                self.assertIn('dhcp-option=114,http://10.0.0.1/', active)
                self.assertTrue(os.path.exists(self.app.FLAG_DNS))
                self.assertTrue(os.path.exists(self.app.PORTAL_ACTIVE))
                self.assertTrue(self.app.set_dns_hijack(False))
                with open(self.app.DNSMASQ_HIJACK) as handle:
                    inactive = handle.read()
                self.assertNotIn('dhcp-option=114', inactive)
                self.assertFalse(os.path.exists(self.app.FLAG_DNS))
                self.assertFalse(os.path.exists(self.app.PORTAL_ACTIVE))
        finally:
            for name, value in old.items():
                setattr(self.app, name, value)
            shutil.rmtree(root, ignore_errors=True)

    def test_reconcile_tears_down_live_twin_on_restart(self):
        import json, shutil
        root = tempfile.mkdtemp(prefix='pinapple-twin-reconcile-')
        names = ('EVILTWIN_STATE', 'EVILTWIN_BACKUP', 'EVILTWIN_PORTAL_STATE')
        old = {name: getattr(self.app, name) for name in names}
        try:
            self.app.EVILTWIN_STATE = os.path.join(root, 'eviltwin.json')
            self.app.EVILTWIN_BACKUP = os.path.join(root, 'backup.bak')
            self.app.EVILTWIN_PORTAL_STATE = os.path.join(root, 'portal.json')
            with open(self.app.EVILTWIN_STATE, 'w') as handle:
                json.dump({'pid': 999999, 'ssid': 'Target'}, handle)
            open(self.app.EVILTWIN_BACKUP, 'w').close()
            with mock.patch.object(self.app, 'restore_ap_after_eviltwin') as restore, \
                    mock.patch.object(self.app, 'release_wlan1') as release:
                self.app.reconcile_eviltwin_state()
            restore.assert_called_once()
            release.assert_called_once_with('eviltwin')
        finally:
            for name, value in old.items():
                setattr(self.app, name, value)
            shutil.rmtree(root, ignore_errors=True)

    def test_restore_ap_kills_surviving_twin_helper(self):
        import json, shutil
        root = tempfile.mkdtemp(prefix='pinapple-twin-restore-')
        names = ('EVILTWIN_STATE', 'EVILTWIN_PID', 'EVILTWIN_BACKUP',
                 'HOSTAPD_CONF')
        old = {name: getattr(self.app, name) for name in names}
        try:
            self.app.EVILTWIN_STATE = os.path.join(root, 'eviltwin.json')
            self.app.EVILTWIN_PID = os.path.join(root, 'eviltwin.pid')
            self.app.EVILTWIN_BACKUP = os.path.join(root, 'backup.bak')
            self.app.HOSTAPD_CONF = os.path.join(root, 'hostapd.conf')
            with open(self.app.EVILTWIN_STATE, 'w') as handle:
                json.dump({'pid': 4242, 'original_mac': ''}, handle)
            with open(self.app.EVILTWIN_PID, 'w') as handle:
                handle.write('4343')
            with open(self.app.EVILTWIN_BACKUP, 'w') as handle:
                handle.write('ssid=PiNAPPLE\n')
            with open(self.app.HOSTAPD_CONF, 'w') as handle:
                handle.write('ssid=Target\n')
            with mock.patch.object(self.app, 'safe_kill_pid') as kill, \
                    mock.patch.object(self.app, '_twin_capture_stop'), \
                    mock.patch.object(self.app, 'restore_twin_portal'), \
                    mock.patch.object(self.app, 'write_hostapd_conf'), \
                    mock.patch.object(self.app.subprocess, 'run',
                                      return_value=mock.Mock(returncode=0)):
                self.app.restore_ap_after_eviltwin('test')
            kill.assert_any_call(4242, 'pinapple-deauth')
            kill.assert_any_call(4343, 'pinapple-deauth')
        finally:
            for name, value in old.items():
                setattr(self.app, name, value)
            shutil.rmtree(root, ignore_errors=True)

    def test_iw_scan_captures_security_detail(self):
        text = """
BSS 20:b0:01:ea:10:4f(on wlan1)
\tfreq: 2437
\tbeacon interval: 100 TUs
\tcapability: ESS Privacy ShortSlotTime (0x0411)
\tsignal: -42.00 dBm
\tSSID: GOINTERNET-EA104F
\tRSN:\t * Version: 1
\t\t * Group cipher: CCMP
\t\t * Pairwise ciphers: CCMP
\t\t * Authentication suites: PSK
\t\t * Capabilities: 16-PTKSA-RC 1-GTKSA-RC MFP-capable (0x00c0)
\tWPS:\t * Version: 1.0
"""
        parsed = self.app.parse_iw_scan(text)[0]
        self.assertEqual(parsed['encryption'], 'WPA2')
        self.assertEqual(parsed['band'], '2.4')
        self.assertEqual(parsed['beacon_int'], 100)
        self.assertEqual(parsed['security']['pairwise'], ['CCMP'])
        self.assertEqual(parsed['security']['pmf'], 1)
        self.assertTrue(parsed['security']['wps'])

    def test_twin_config_clones_wpa2_ccmp(self):
        original = self.app.HOSTAPD_CONF
        original_country = self.app.read_country_code
        handle, path = tempfile.mkstemp(suffix='.conf')
        os.close(handle)
        try:
            self.app.HOSTAPD_CONF = path
            self.app.read_country_code = lambda: 'GB'
            self.app.write_hostapd_conf(
                'GOINTERNET-EA104F', 6, 'wpa2', None, 'correct horse',
                security={'rsn': True, 'psk': True, 'pairwise': ['CCMP'],
                          'group': 'CCMP', 'pmf': 0, 'beacon_int': 100})
            with open(path) as f:
                conf = f.read()
            self.assertIn('ssid=GOINTERNET-EA104F', conf)
            self.assertIn('wpa=2', conf)
            self.assertIn('wpa_key_mgmt=WPA-PSK', conf)
            self.assertIn('rsn_pairwise=CCMP', conf)
            self.assertIn('ieee80211w=0', conf)
            self.assertIn('country_code=GB', conf)
            self.assertNotIn('SAE', conf)
        finally:
            self.app.HOSTAPD_CONF = original
            self.app.read_country_code = original_country
            os.remove(path)

    def test_twin_config_mirrors_pmf_and_sae(self):
        original = self.app.HOSTAPD_CONF
        original_country = self.app.read_country_code
        handle, path = tempfile.mkstemp(suffix='.conf')
        os.close(handle)
        try:
            self.app.HOSTAPD_CONF = path
            self.app.read_country_code = lambda: ''
            self.app.write_hostapd_conf(
                'Mixed', 11, 'wpa2', None, 'correct horse',
                security={'rsn': True, 'psk': True, 'sae': True,
                          'pairwise': ['CCMP'], 'group': 'CCMP', 'pmf': 2})
            with open(path) as f:
                conf = f.read()
            self.assertIn('wpa_key_mgmt=WPA-PSK SAE', conf)
            self.assertIn('sae_password=correct horse', conf)
            self.assertIn('ieee80211w=2', conf)
            self.assertNotIn('country_code=', conf)
        finally:
            self.app.HOSTAPD_CONF = original
            self.app.read_country_code = original_country
            os.remove(path)

    def test_channel_12_needs_a_country(self):
        original = self.app.read_country_code
        try:
            self.app.read_country_code = lambda: ''
            ok, _ = self.app.hostapd_accepts_channel(12)
            self.assertFalse(ok)
            ok, _ = self.app.hostapd_accepts_channel(6)
            self.assertTrue(ok)
            self.app.read_country_code = lambda: 'GB'
            ok, _ = self.app.hostapd_accepts_channel(12)
            self.assertTrue(ok)
        finally:
            self.app.read_country_code = original

    def test_offline_verify_uses_saved_hash(self):
        original_dir = self.app.SAVED_DIR
        original_index = self.app.SAVED_INDEX
        original_helper = self.app.PSK_VERIFY_HELPER
        original_log = self.app.LOG_DIR
        tmp = tempfile.mkdtemp()
        try:
            self.app.SAVED_DIR = tmp
            self.app.SAVED_INDEX = os.path.join(tmp, 'saved.json')
            self.app.LOG_DIR = os.path.join(tmp, 'logs')
            self.app.PSK_VERIFY_HELPER = os.path.join(
                ROOT, 'tools', 'pinapple-psk-verify')
            name = 'vector.22000'
            with open(os.path.join(tmp, name), 'w') as handle:
                handle.write(PskVerifyTests.EAPOL + '\n')
            self.app.saved_write([{
                'id': 't1', 'type': 'hash', 'title': 'TP-LINK_HASHCAT_TEST',
                'subtitle': '', 'created': '2026-01-01T00:00:00',
                'file': name, 'size': os.path.getsize(os.path.join(tmp, name)),
                'meta': {'bssid': '64:66:B3:8E:C3:FC',
                         'ssid': 'TP-LINK_HASHCAT_TEST'},
            }])
            found = self.app.find_hash_for_bssid('64:66:B3:8E:C3:FC',
                                                'TP-LINK_HASHCAT_TEST')
            self.assertTrue(found)
            result = self.app.verify_psk_offline(
                'hashcat!', 'TP-LINK_HASHCAT_TEST', '64:66:B3:8E:C3:FC')
            self.assertEqual(result['result'], 'ok')
            self.assertEqual(result['method'], 'eapol')
            wrong = self.app.verify_psk_offline(
                'wrongpass', 'TP-LINK_HASHCAT_TEST', '64:66:B3:8E:C3:FC')
            self.assertEqual(wrong['result'], 'invalid')
        finally:
            self.app.SAVED_DIR = original_dir
            self.app.SAVED_INDEX = original_index
            self.app.PSK_VERIFY_HELPER = original_helper
            self.app.LOG_DIR = original_log
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_twin_start_refuses_5ghz_before_radio_claim(self):
        original_entry = self.app.recon_entry
        original_claim = self.app.claim_wlan1
        try:
            self.app.recon_entry = lambda bssid: {
                'ssid': 'GOINTERNET-EA104F', 'bssid': bssid, 'channel': 100,
                'band': '5', 'encryption': 'WPA2',
                'security': {'rsn': True, 'psk': True}}
            self.app.claim_wlan1 = lambda owner: self.fail('radio was claimed')
            self.app.request = types.SimpleNamespace(
                method='POST', json={'ssid': 'GOINTERNET-EA104F',
                                     'bssid': '22:B0:01:EA:10:57'}, form={},
                args=types.SimpleNamespace(get=lambda k, d=None: d))
            result = self.app.api_evil_twin_start.__wrapped__()
            self.assertEqual(result[0]['ok'], False)
            self.assertIn('5 GHz', result[0]['error'])
        finally:
            self.app.recon_entry = original_entry
            self.app.claim_wlan1 = original_claim

    def test_rendered_evil_twin_page_has_preflight(self):
        html = self.app.wlan1_page.__wrapped__()
        for needle in ('et-preflight', 'et-checks', 'refreshTwinPreflight',
                       'scheduleTwinPreflight', 'Update firmware'):
            self.assertIn(needle, html)


    def test_strip_page_renders(self):
        html = self.app.strip_page.__wrapped__()
        for needle in ('st-rows', 'st-host-rows', 'toggleStrip', 'st-mode-ctl',
                       'TLS refused', 'Per-host outcome', 'Demo checklist'):
            self.assertIn(needle, html)

    def test_strip_overview_toggle_present(self):
        html = self.app.overview.__wrapped__()
        self.assertIn('togStrip', html)
        self.assertIn('HTTPS Downgrade', html)

    def test_strip_host_summary_counts_downgrades(self):
        hosts = self.app.strip_host_summary([
            {'host': 'a.test', 'upstream': 'https', 'fields': {'u': '1'},
             'ts': '2026-01-01 10:00:00'},
            {'host': 'a.test', 'upstream': 'https', 'fields': {},
             'ts': '2026-01-01 10:00:01'},
            {'host': 'b.test', 'upstream': 'http', 'fields': {},
             'ts': '2026-01-01 10:00:02'},
        ])
        self.assertEqual([h['host'] for h in hosts], ['b.test', 'a.test'])
        a = [h for h in hosts if h['host'] == 'a.test'][0]
        self.assertEqual((a['requests'], a['https'], a['forms']), (2, 2, 1))
        self.assertEqual(a['verdict'], 'downgraded')
        b = [h for h in hosts if h['host'] == 'b.test'][0]
        self.assertEqual(b['verdict'], 'plain http')

    def test_strip_rows_escape_markup(self):
        html = self.app.strip_rows_html([{
            'ts': '2026-01-01 10:00:00', 'client': '10.0.0.5', 'method': 'GET',
            'url': 'http://x.test/<script>alert(1)</script>', 'status': 200,
            'upstream': 'https', 'fields': {'q': '<b>x</b>'}}])
        self.assertNotIn('<script>', html)
        self.assertIn('&lt;script&gt;', html)
        self.assertIn('&lt;b&gt;x&lt;/b&gt;', html)

    def test_strip_start_requires_helper(self):
        original = self.app.STRIP_HELPER
        original_req = self.app.request
        try:
            self.app.STRIP_HELPER = os.path.join(ROOT, 'tools', 'missing-strip')
            self.app.request = types.SimpleNamespace(json={}, form={}, method='POST')
            result = self.app.api_strip_start.__wrapped__()
            self.assertFalse(result['ok'])
            self.assertIn('install.sh', result['error'])
        finally:
            self.app.STRIP_HELPER = original
            self.app.request = original_req

    def test_strip_start_releases_port_80_and_dns(self):
        import shutil
        root = tempfile.mkdtemp(prefix='pinapple-strip-')
        names = ('STRIP_HELPER', 'FLAG_DNS', 'FLAG_PORTAL', 'FLAG_INTERNET')
        old = {name: getattr(self.app, name) for name in names}
        original_req = self.app.request
        calls = []
        try:
            self.app.STRIP_HELPER = os.path.join(ROOT, 'tools', 'pinapple-strip')
            self.app.FLAG_DNS = os.path.join(root, 'dns')
            self.app.FLAG_PORTAL = os.path.join(root, 'portal')
            self.app.FLAG_INTERNET = os.path.join(root, 'internet')
            open(self.app.FLAG_DNS, 'w').close()
            open(self.app.FLAG_PORTAL, 'w').close()
            open(self.app.FLAG_INTERNET, 'w').close()
            self.app.request = types.SimpleNamespace(json={'https': 'block'},
                                                     form={}, method='POST')
            with mock.patch.object(
                    self.app, 'set_dns_hijack',
                    side_effect=lambda v, *a, **k: calls.append(('dns', v)) or True), \
                    mock.patch.object(
                        self.app, 'set_portal_redirect',
                        side_effect=lambda v, *a, **k:
                        calls.append(('redirect', v)) or True), \
                    mock.patch.object(
                        self.app.subprocess, 'run',
                        return_value=mock.Mock(returncode=0, stdout='', stderr='')):
                result = self.app.api_strip_start.__wrapped__()
            self.assertTrue(result['ok'])
            self.assertIn(('dns', False), calls)
            self.assertIn(('redirect', False), calls)
            self.assertIn('DNS hijack off', result['changes'])
            self.assertIn('portal redirect off', result['changes'])
        finally:
            for name, value in old.items():
                setattr(self.app, name, value)
            self.app.request = original_req
            shutil.rmtree(root, ignore_errors=True)


    def test_strip_ssid_applies_and_keeps_security(self):
        import shutil
        root = tempfile.mkdtemp(prefix='pinapple-ssid-')
        names = ('HOSTAPD_CONF', 'ap_backend', 'read_ap_txpower')
        old = {name: getattr(self.app, name) for name in names}
        original_req = self.app.request
        try:
            conf = os.path.join(root, 'hostapd.conf')
            with open(conf, 'w') as handle:
                handle.write('interface=wlan0\nssid=Old Name\nchannel=6\n'
                             'auth_algs=1\nignore_broadcast_ssid=0\n')
            self.app.HOSTAPD_CONF = conf
            self.app.ap_backend = lambda: 'hostapd'
            self.app.read_ap_txpower = lambda: 'medium'

            self.app.request = types.SimpleNamespace(json={'ssid': '   '},
                                                     form={}, method='POST')
            result = self.app.api_strip_ssid.__wrapped__()
            self.assertFalse(result['ok'])
            self.assertIn('empty', result['error'])

            self.app.request = types.SimpleNamespace(json={'ssid': 'Free Cafe WiFi'},
                                                     form={}, method='POST')
            with mock.patch.object(self.app.subprocess, 'run',
                                   return_value=mock.Mock(returncode=0)), \
                    mock.patch.object(self.app, 'read_country_code',
                                      return_value=''):
                result = self.app.api_strip_ssid.__wrapped__()
            self.assertTrue(result['ok'], result)
            self.assertEqual(result['ssid'], 'Free Cafe WiFi')
            self.assertEqual(result['security'], 'open')
            with open(conf) as handle:
                written = handle.read()
            self.assertIn('ssid=Free Cafe WiFi', written)
            self.assertIn('channel=6', written)
            self.assertNotIn('wpa=', written)
        finally:
            for name, value in old.items():
                setattr(self.app, name, value)
            self.app.request = original_req
            shutil.rmtree(root, ignore_errors=True)

    def test_strip_ssid_refuses_non_hostapd_backend(self):
        names = ('ap_backend',)
        old = {name: getattr(self.app, name) for name in names}
        original_req = self.app.request
        try:
            self.app.ap_backend = lambda: 'networkmanager'
            self.app.request = types.SimpleNamespace(json={'ssid': 'Lab'},
                                                     form={}, method='POST')
            result = self.app.api_strip_ssid.__wrapped__()
            self.assertFalse(result['ok'])
            self.assertIn('AP Control', result['error'])
        finally:
            for name, value in old.items():
                setattr(self.app, name, value)
            self.app.request = original_req


class PskVerifyTests(unittest.TestCase):
    """Known-good hashcat 22000 vectors (password: hashcat!)."""

    @classmethod
    def setUpClass(cls):
        cls.mod = load('psk_verify', os.path.join(ROOT, 'tools', 'pinapple-psk-verify'))

    PMKID = ('WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*'
             'f4747f87f9f4*686173686361742d6573736964***')
    EAPOL = 'WPA*02*024022795224bffca545276c3762686f*6466b38ec3fc*225edc49b7aa*54502d4c494e4b5f484153484341545f54455354*10e3be3b005a629e89de088d6a2fdc489db83ad4764f2d186b9cde15446e972e*0103007502010a0000000000000000000148ce2ccba9c1fda130ff2fbbfb4fd3b063d1a93920b0f7df54a5cbf787b16171000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac028000*a2'

    def _verify(self, line, passphrase):
        fields = line.split('*')
        return self.mod.hash_matches(fields, passphrase, b'', b'', {})

    def test_pmkid_vector(self):
        status, method, _ = self._verify(self.PMKID, 'hashcat!')
        self.assertEqual(status, 'ok')
        self.assertEqual(method, 'pmkid')
        status, _, _ = self._verify(self.PMKID, 'wrongpass')
        self.assertEqual(status, 'invalid')

    def test_eapol_vector(self):
        status, method, _ = self._verify(self.EAPOL, 'hashcat!')
        self.assertEqual(status, 'ok')
        self.assertEqual(method, 'eapol')
        status, _, _ = self._verify(self.EAPOL, 'wrongpass')
        self.assertEqual(status, 'invalid')

    def test_wpa3_message_pair_is_unsupported(self):
        fields = self.EAPOL.split('*')
        fields[8] = 'a4'  # M3+M4: no SNonce in the stored frame
        status, _, detail = self.mod.hash_matches(fields, 'hashcat!', b'', b'', {})
        self.assertEqual(status, 'unsupported')
        self.assertIn('M2', detail)

    def test_prf_and_pmkid_are_deterministic(self):
        pmk = hashlib.pbkdf2_hmac('sha1', b'hashcat!', b'hashcat-essid', 4096, 32)
        self.assertEqual(self.mod.prf512(pmk, b'Pairwise key expansion', b'abc'),
                         self.mod.prf512(pmk, b'Pairwise key expansion', b'abc'))


class DeauthV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load('deauth_helper_v2',
                       os.path.join(ROOT, 'tools', 'pinapple-deauth'))

    def test_frames_cover_both_directions(self):
        frames = self.mod.build_frames('AA:BB:CC:DD:EE:FF',
                                       '11:22:33:44:55:66', 0, (1, 3, 7))
        self.assertEqual(len(frames), 6)
        # AP -> client
        self.assertEqual(frames[0][4:10], bytes.fromhex('112233445566'))
        self.assertEqual(frames[0][10:16], bytes.fromhex('aabbccddeeff'))
        # client -> AP (reverse) starts after the forward block
        self.assertEqual(frames[3][4:10], bytes.fromhex('aabbccddeeff'))
        self.assertEqual(frames[3][10:16], bytes.fromhex('112233445566'))
        self.assertEqual(frames[0][24:26], (1).to_bytes(2, 'little'))
        self.assertEqual(frames[1][24:26], (3).to_bytes(2, 'little'))
        self.assertEqual(frames[2][24:26], (7).to_bytes(2, 'little'))

    def test_broadcast_has_no_reverse_frames(self):
        frames = self.mod.build_frames('AA:BB:CC:DD:EE:FF',
                                       self.mod.BROADCAST, 0, (1, 3))
        self.assertEqual(len(frames), 2)

    def test_reason_parser(self):
        self.assertEqual(self.mod.parse_reasons('1,3,7,3'), [1, 3, 7])
        with self.assertRaises(SystemExit):
            self.mod.parse_reasons('1,abc')


class MonitorSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load('monitor_helper_security',
                       os.path.join(ROOT, 'tools', 'pinapple-monitor'))

    def _rsn(self, akm=2, caps=0x0040):
        pairwise = b'\x01\x00' + b'\x00\x0f\xac\x04'
        akms = b'\x01\x00' + b'\x00\x0f\xac' + bytes([akm])
        return (b'\x01\x00' + b'\x00\x0f\xac\x04' + pairwise + akms +
                caps.to_bytes(2, 'little'))

    def test_rsn_detail(self):
        body = b'\x30' + bytes([len(self._rsn())]) + self._rsn()
        detail = self.mod.parse_security(body)
        self.assertTrue(detail['rsn'])
        self.assertEqual(detail['pairwise'], ['CCMP'])
        self.assertEqual(detail['akm'], ['PSK'])
        self.assertEqual(detail['pmf'], 1)
        self.assertTrue(detail['psk'])
        self.assertFalse(detail['sae'])

    def test_sae_and_wps(self):
        rsn = self._rsn(akm=8, caps=0x0080)
        wps = b'\xdd\x04\x00\x50\xf2\x04'
        body = b'\x30' + bytes([len(rsn)]) + rsn + wps
        detail = self.mod.parse_security(body)
        self.assertTrue(detail['sae'])
        self.assertEqual(detail['pmf'], 2)
        self.assertTrue(detail['wps'])


class StripHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load('strip_helper', os.path.join(ROOT, 'tools', 'pinapple-strip'))

    def test_host_header_parsing(self):
        self.assertEqual(self.mod.parse_hostport('Example.COM'), ('example.com', 80))
        self.assertEqual(self.mod.parse_hostport('example.com:8080'),
                         ('example.com', 8080))
        self.assertEqual(self.mod.parse_hostport('[2001:db8::1]:8443'),
                         ('2001:db8::1', 8443))
        self.assertEqual(self.mod.parse_hostport(''), ('', 80))
        self.assertEqual(self.mod.host_header('a.test', 80, False), 'a.test')
        self.assertEqual(self.mod.host_header('a.test', 8080, False), 'a.test:8080')
        self.assertEqual(self.mod.host_header('a.test', 8080, True), 'a.test')

    def test_location_is_downgraded(self):
        self.assertEqual(self.mod.downgrade_url('https://a.test/x?q=1'),
                         'http://a.test/x?q=1')
        self.assertEqual(self.mod.downgrade_url('http://a.test:443/x'),
                         'http://a.test/x')
        self.assertEqual(self.mod.downgrade_url('/relative'), '/relative')

    def test_secure_cookie_is_stripped(self):
        self.assertEqual(
            self.mod.unsecure_cookie('sid=abc; Path=/; Secure; HttpOnly'),
            'sid=abc; Path=/; HttpOnly')
        self.assertEqual(self.mod.unsecure_cookie('a=1; secure'), 'a=1')
        # 'Secure' inside a value must survive.
        self.assertEqual(self.mod.unsecure_cookie('note=Secure-ish; Path=/'),
                         'note=Secure-ish; Path=/')

    def test_csp_upgrade_directive_is_dropped(self):
        self.assertEqual(
            self.mod.drop_upgrade_insecure(
                "default-src 'self'; upgrade-insecure-requests; img-src *"),
            "default-src 'self'; img-src *")
        self.assertEqual(self.mod.drop_upgrade_insecure('upgrade-insecure-requests'),
                         '')

    def test_body_rewrite(self):
        body = (b'<a href="https://x.test/a">a</a> '
                b'<form action="https://x.test:8443/login">'
                b'<meta http-equiv="Content-Security-Policy" '
                b'content="upgrade-insecure-requests">')
        out = self.mod.rewrite_body(body)
        self.assertNotIn(b'https://x.test', out)
        self.assertIn(b'http://x.test/a', out)
        self.assertIn(b'http://x.test/login', out)
        self.assertNotIn(b'upgrade-insecure-requests', out)
        self.assertEqual(self.mod.rewrite_body(b'no links here'),
                         b'no links here')

    def test_rewritable_types(self):
        self.assertTrue(self.mod.is_rewritable('text/html; charset=utf-8'))
        self.assertTrue(self.mod.is_rewritable('application/json'))
        self.assertFalse(self.mod.is_rewritable('image/png'))
        self.assertFalse(self.mod.is_rewritable(''))

    def test_gzip_body_is_decoded(self):
        import gzip as gz
        raw = b'<a href="https://x.test/">x</a>'
        data, leftover = self.mod.decode_content(gz.compress(raw), 'gzip')
        self.assertIsNone(leftover)
        self.assertEqual(data, raw)
        data, leftover = self.mod.decode_content(raw, 'br')
        self.assertEqual(leftover, 'br')
        self.assertEqual(data, raw)

    def test_form_fields_are_logged(self):
        self.assertEqual(
            self.mod.parse_form(b'user=demo&password=hunter2&remember=on',
                                'application/x-www-form-urlencoded'),
            {'user': 'demo', 'password': 'hunter2', 'remember': 'on'})
        self.assertEqual(
            self.mod.parse_form(b'{"u":"a","p":"b"}', 'application/json'),
            {'u': 'a', 'p': 'b'})
        self.assertEqual(self.mod.parse_form(b'\x00\x01binary', 'image/png'), {})
        self.assertEqual(self.mod.parse_form(b'q=x', ''), {'q': 'x'})
        self.assertEqual(self.mod.parse_form(b'', 'application/x-www-form-urlencoded'), {})

    def test_log_line_shows_method_url_and_form(self):
        line = self.mod.format_log_line({
            'ts': '2026-01-01 10:00:00', 'client': '10.0.0.5', 'method': 'POST',
            'url': 'http://shop.test/login', 'status': 200,
            'upstream': 'https', 'note': 'forced',
            'fields': {'user': 'demo', 'password': 'hunter2'}})
        self.assertIn('POST', line)
        self.assertIn('http://shop.test/login', line)
        self.assertIn('upstream https', line)
        self.assertIn('user=demo', line)
        self.assertIn('password=hunter2', line)

    def test_rules_are_built_as_arrays(self):
        rule = self.mod.redirect_rule('10.0.0.1', 10000)
        self.assertIsInstance(rule, list)
        self.assertEqual(rule[:3], ['-t', 'nat', 'PREROUTING'])
        self.assertIn('--to-ports', rule)
        self.assertEqual(rule[rule.index('!') + 1:rule.index('!') + 3],
                         ['-d', '10.0.0.1'])
        cmd = self.mod._rule_cmd('-C', rule)
        self.assertEqual(cmd[:2], ['-t', 'nat'])
        self.assertIn('-C', cmd)
        self.assertEqual(cmd[cmd.index('-C') + 1], 'PREROUTING')
        inserted = self.mod._rule_cmd('-I', self.mod.tls_rule(), 1)
        self.assertEqual(inserted[inserted.index('-I') + 1:][:2], ['FORWARD', '1'])


    def test_failed_request_is_logged_with_error(self):
        import shutil
        root = tempfile.mkdtemp(prefix='pinapple-strip-fail-')
        names = ('LOG_DIR', 'LOG_FILE', 'JSONL_FILE')
        old = {name: getattr(self.mod, name) for name in names}
        try:
            self.mod.LOG_DIR = root
            self.mod.LOG_FILE = os.path.join(root, 'strip.log')
            self.mod.JSONL_FILE = os.path.join(root, 'strip.jsonl')
            handler = object.__new__(self.mod.ProxyHandler)
            state = self.mod.ProxyState(10000, 'block')

            class Sink:
                def __init__(self):
                    self.data = b''

                def sendall(self, chunk):
                    self.data += chunk

            sink = Sink()
            handler._fail(state, sink, '10.0.0.5', 'GET', 'http://nope.test/', [],
                          error='DNS lookup failed')
            self.assertTrue(sink.data.startswith(b'HTTP/1.1 502'), sink.data[:40])
            records = self.mod.read_records(5)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]['status'], 502)
            self.assertEqual(records[0]['note'], 'failed')
            self.assertEqual(records[0]['error'], 'DNS lookup failed')
            with open(self.mod.LOG_FILE, encoding='utf-8') as handle:
                self.assertIn('error: DNS lookup failed', handle.read())
        finally:
            for name, value in old.items():
                setattr(self.mod, name, value)
            shutil.rmtree(root, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
