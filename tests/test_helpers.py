#!/usr/bin/env python3
"""Safe, RF-free regression tests for the PiNAPPLE attack helpers.

Run with:  python3 -m unittest discover -s tests -v
No Flask, Pi, or wireless hardware is required.
"""

import importlib.machinery
import importlib.util
import os
import sys
import types
import unittest

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
        try:
            self.app._wlan1_owner[0] = 'beacon'
            self.app.request = types.SimpleNamespace(
                method='POST', json={'mode': 'managed'}, form={})
            response = self.app.api_wlan1_mode.__wrapped__()
            self.assertFalse(response['ok'])
            self.assertIn('Beacon Flood', response['error'])
        finally:
            self.app._wlan1_owner[0] = previous
            self.app.request = original

    def test_recon_scan_refuses_while_radio_busy(self):
        original = self.app.request
        previous = self.app._wlan1_owner[0]
        try:
            self.app._wlan1_owner[0] = 'deauth'
            self.app.request = types.SimpleNamespace(json={}, form={}, method='POST')
            response = self.app.api_recon_scan.__wrapped__()
            self.assertFalse(response['ok'])
            self.assertIn('Deauth', response['error'])
        finally:
            self.app._wlan1_owner[0] = previous
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


if __name__ == '__main__':
    unittest.main()
