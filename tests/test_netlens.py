import csv
import json
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
from unittest.mock import patch

from netlens.capture import FIELDS, analyze_packets, owners_for_packet, new_endpoint
from netlens.discovery import certificate_names, ctlogs_certificates, discover, domain_name, network_info
from netlens.report import save_report
from netlens.suffixes import registrable_domain


class DiscoveryTests(unittest.TestCase):
    def test_registrable_domains_from_bundled_psl(self):
        examples = {
            'www.youtube.com': 'youtube.com',
            'a.b.youtube.com': 'youtube.com',
            'youtube.com': 'youtube.com',
            'a.b.example.co.uk': 'example.co.uk',
            'www.project.github.io': 'project.github.io',
            'a.b.ck': 'a.b.ck',
            'a.www.ck': 'www.ck',
            'www.city.kawasaki.jp': 'city.kawasaki.jp',
            'www.a.kawasaki.jp': 'www.a.kawasaki.jp',
            'www.пример.рф': 'пример.рф',
            'a.example.unknownsuffix': 'example.unknownsuffix',
        }
        for given, expected in examples.items():
            with self.subTest(domain=given):
                self.assertEqual(registrable_domain(domain_name(given)), domain_name(expected))

    def test_public_suffix_without_registrable_domain_rejected(self):
        for given in ('co.uk', 'github.io', 'a.ck'):
            with self.subTest(domain=given), self.assertRaises(ValueError):
                registrable_domain(domain_name(given))

    @patch('netlens.discovery.ctlogs_certificates', return_value=([
        {'match': 'm.youtube.com'}], {'provider': 'ctlogs.dev'}, []))
    @patch('netlens.discovery.resolve_name', side_effect=lambda n: {'domain': n, 'ips': [], 'cnames': [], 'errors': []})
    def test_subdomain_search_expands_to_root_and_retains_input(self, resolve, provider):
        report = discover('WWW.YouTube.COM.', networks=False, follow_redirects=False)
        self.assertEqual(report['input_domain'], 'www.youtube.com')
        self.assertEqual(report['root'], 'youtube.com')
        self.assertTrue(report['scope_expanded'])
        self.assertEqual(provider.call_args.args[0], 'youtube.com')
        self.assertEqual({r['domain'] for r in report['domains']}, {'youtube.com', 'www.youtube.com', 'm.youtube.com'})

    @patch('netlens.discovery.ctlogs_certificates')
    @patch('netlens.discovery.resolve_name', side_effect=lambda n: {'domain': n, 'ips': [], 'cnames': [], 'errors': []})
    def test_dns_only_keeps_exact_subdomain(self, resolve, provider):
        report = discover('www.youtube.com', use_ct=False, networks=False, follow_redirects=False)
        self.assertEqual(report['root'], 'www.youtube.com')
        self.assertFalse(report['scope_expanded'])
        provider.assert_not_called()
        resolve.assert_called_once_with('www.youtube.com')

    def test_domain_validation(self):
        self.assertEqual(domain_name('ПРИМЕР.РФ.'), 'xn--e1afmkfd.xn--p1ai')
        for bad in ['https://example.com/', 'example.com:443', '-a.com', '1.2.3.4']:
            with self.assertRaises(ValueError):
                domain_name(bad)

    def test_certificate_boundaries(self):
        found, related = certificate_names('example.com', [
            {'san_dns': ['*.example.com', 'api.example.com', 'other.net']},
            {'san_dns': ['notexample.com', 'foreign.net']}])
        self.assertIn('api.example.com', found)
        self.assertEqual(set(related), {'other.net'})
        self.assertNotIn('foreign.net', found)

    @patch('netlens.discovery.resolve_name', side_effect=lambda n: {'domain': n, 'ips': ['1.1.1.1'], 'cnames': [], 'errors': []})
    @patch('netlens.discovery.get_json', return_value={'rows': [{'match': 'a.example.com', 'san_dns': ['a.example.com', 'aaa.net']}]})
    def test_limits_prioritize_subdomains(self, *_):
        report = discover('example.com', limit=2, include_related=True, networks=False, follow_redirects=False)
        self.assertEqual([r['domain'] for r in report['domains']], ['a.example.com', 'example.com'])
        self.assertTrue(report['truncated'])

    @patch('netlens.discovery.get_json', side_effect=TimeoutError('offline'))
    @patch('netlens.discovery.resolve_name', return_value={'domain': 'example.com', 'ips': [], 'cnames': [], 'errors': []})
    def test_ct_failure_preserves_dns(self, *_):
        report = discover('example.com', networks=False, follow_redirects=False)
        self.assertEqual(len(report['domains']), 1)
        self.assertTrue(report['warnings'])

    @patch('netlens.discovery.get_json', side_effect=[
        {'rows': [{'match': 'a.example.com', 'id': 'one', 'san_count': 2}], 'has_next': True, 'next_cursor': 'opaque+/='},
        {'rows': [{'match': 'b.example.com', 'id': 'one', 'san_count': 2}], 'has_next': False},
        {'subject_cn': 'example.com', 'san_dns': ['example.com', 'other.net']},
    ])
    def test_ctlogs_pagination_and_san_deduplication(self, request):
        rows, metadata, warnings = ctlogs_certificates('example.com', 200)
        found, related = certificate_names('example.com', rows)
        self.assertEqual(set(found), {'example.com', 'a.example.com', 'b.example.com'})
        self.assertEqual(set(related), {'other.net'})
        self.assertEqual(metadata['pages'], 2)
        self.assertEqual(metadata['certificate_details'], 1)
        self.assertFalse(warnings)
        urls = [call.args[0] for call in request.call_args_list]
        self.assertEqual(urls[0], 'https://api.ctlogs.dev/v1/subdomains/example.com')
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlparse(urls[1]).query)['after'], ['opaque+/='])
        self.assertEqual(urls[2], 'https://api.ctlogs.dev/v1/cert/one')

    @patch('netlens.discovery.get_json', side_effect=[
        {'rows': [{'match': 'a.example.com'}], 'has_next': True, 'next_cursor': 'next'},
        urllib.error.HTTPError('https://api.ctlogs.dev/', 429, 'rate limited', {'Retry-After': '60'}, None),
    ])
    def test_ctlogs_rate_limit_preserves_first_page(self, _):
        rows, metadata, warnings = ctlogs_certificates('example.com', 200)
        self.assertEqual(rows[0]['match'], 'a.example.com')
        self.assertTrue(metadata['partial'])
        self.assertIn('429', warnings[0])
        self.assertIn('60', warnings[0])

    @patch('netlens.discovery.get_json', return_value={'rows': [{'match': 'a.example.com'}], 'has_next': True, 'next_cursor': 'same'})
    def test_ctlogs_repeated_cursor_is_bounded(self, request):
        _, metadata, warnings = ctlogs_certificates('example.com', 200)
        self.assertEqual(request.call_count, 2)
        self.assertTrue(metadata['partial'])
        self.assertIn('next_cursor', warnings[0])

    @patch('netlens.discovery.get_json', return_value={'rows': [{'match': 'a.example.com'}], 'history_window_days': 90, 'history_truncated': True})
    def test_ctlogs_history_limit_visible(self, _):
        _, metadata, warnings = ctlogs_certificates('example.com', 200)
        self.assertEqual(metadata['history_window_days'], 90)
        self.assertTrue(metadata['history_truncated'])
        self.assertTrue(warnings)

    @patch('netlens.discovery.get_json', return_value=[{'match': 'example.com'}])
    def test_ctlogs_rejects_unexpected_envelope(self, _):
        rows, metadata, warnings = ctlogs_certificates('example.com', 200)
        self.assertEqual(rows, [])
        self.assertTrue(metadata['partial'])
        self.assertIn('rows', warnings[0])

    @patch('netlens.discovery.get_json')
    def test_ctlogs_cancel_before_request(self, request):
        stop = threading.Event()
        stop.set()
        _, metadata, _ = ctlogs_certificates('example.com', 200, cancel=stop)
        request.assert_not_called()
        self.assertTrue(metadata['partial'])

    @patch('netlens.discovery.get_json', side_effect=[
        {'rows': [{'match': 'a.example.com', 'id': 'one', 'san_count': 2}]},
        TimeoutError('offline'),
    ])
    def test_ctlogs_details_failure_preserves_search_matches(self, _):
        rows, metadata, warnings = ctlogs_certificates('example.com', 200)
        self.assertIn('a.example.com', certificate_names('example.com', rows)[0])
        self.assertTrue(metadata['partial'])
        self.assertTrue(warnings)

    @patch('netlens.discovery.get_json', return_value={'data': {'prefix': '8.8.8.0/24', 'asns': [15169]}})
    def test_real_prefix_and_private(self, request):
        self.assertEqual(network_info('8.8.8.8')['prefix'], '8.8.8.0/24')
        self.assertIsNone(network_info('192.168.1.2')['prefix'])
        self.assertEqual(request.call_count, 1)


class CorrelationTests(unittest.TestCase):
    def analyze(self, rows, snapshots, endpoints=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'packets.tsv'
            with path.open('w', newline='', encoding='utf-8') as stream:
                csv.writer(stream, delimiter='\t', quoting=csv.QUOTE_NONE).writerows(rows)
            return analyze_packets(path, snapshots, {42}, endpoints or {})

    def packet(self, timestamp=100, proto='tcp', host='api.example.com'):
        row = [''] * len(FIELDS)
        row[0], row[1], row[3] = str(timestamp), '10.0.0.2', '1.1.1.1'
        row[5 if proto == 'tcp' else 7] = '50000'
        row[6 if proto == 'tcp' else 8] = '443'
        row[12] = host
        return row

    def test_tcp_sni_and_wrong_process(self):
        rows = [('tcp', ('10.0.0.2', 50000), ('1.1.1.1', 443), 42)]
        endpoints, stats = self.analyze([self.packet()], [(99.99, 100.01, rows, {42})])
        self.assertEqual(endpoints[0]['hostnames'][0]['source'], 'tls_sni')
        self.assertEqual(stats['attributed_packets'], 1)
        rows[0] = (*rows[0][:-1], 99)
        self.assertEqual(self.analyze([self.packet()], [(99.99, 100.01, rows, {42})])[0], [])

    def test_udp_shared_port_is_excluded(self):
        rows = [('udp', ('0.0.0.0', 50000), None, 42), ('udp', ('10.0.0.2', 50000), None, 99)]
        endpoints, stats = self.analyze([self.packet(proto='udp')], [(99.99, 100.01, rows, {42})])
        self.assertEqual(endpoints, [])
        self.assertEqual(stats['ambiguous_packets'], 1)

    def test_port_reuse_and_stale_sample(self):
        rows = [('udp', ('0.0.0.0', 50000), None, 42)]
        self.assertEqual(self.analyze([self.packet(timestamp=102, proto='udp')], [(99.99, 100.01, rows, {42})])[0], [])
        self.assertEqual(self.analyze([self.packet(proto='udp')], [(99.99, 100.01, rows, {99})])[0], [])

    def test_ipv6_udp(self):
        owners = owners_for_packet('udp', ('2001:db8::1', 50000), ('2001:db8::2', 443),
                                   [('udp', ('::', 50000), None, 42)])
        self.assertEqual(owners, {(42, ('2001:db8::2', 443))})

    def test_dns_is_only_candidate(self):
        packet = self.packet()
        dns = [''] * len(FIELDS)
        dns[0], dns[1], dns[3], dns[7], dns[8] = '99.9', '8.8.8.8', '10.0.0.2', '53', '60000'
        dns[9], dns[10] = 'shared.example.com', '1.1.1.1'
        rows = [('tcp', ('10.0.0.2', 50000), ('1.1.1.1', 443), 42)]
        endpoints, _ = self.analyze([dns, packet], [(99.99, 100.01, rows, {42})])
        self.assertIn('shared.example.com', endpoints[0]['dns_candidates'])
        self.assertNotIn('shared.example.com', [n['name'] for n in endpoints[0]['hostnames']])

    def test_export_uses_separate_candidate_list(self):
        with tempfile.TemporaryDirectory() as directory:
            save_report({'kind': 'capture', 'endpoints': [{'ip': '1.1.1.1', 'port': 443,
                'transport': 'tcp', 'hostnames': [], 'dns_candidates': ['maybe.example.com'], 'evidence': []}]}, directory)
            self.assertEqual((Path(directory) / 'domains.txt').read_text(), '')
            self.assertEqual((Path(directory) / 'dns-candidates.txt').read_text(), 'maybe.example.com')


if __name__ == '__main__':
    unittest.main()
