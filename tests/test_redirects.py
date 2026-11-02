import http.server
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.request

from netlens.discovery import discover
from netlens.redirects import NoRedirect, normalize_url, request_page, trace_redirects
from netlens.report import address_lists, save_report


def no_dns(name):
    addresses = {'example.com': '1.1.1.1', 'landing.other.net': '8.8.8.8',
                 'other.net': '8.8.4.4', 'cdn.other.net': '9.9.9.9'}
    return {'domain': name, 'ips': [addresses[name]] if name in addresses else [], 'cnames': [], 'errors': []}


class RedirectTests(unittest.TestCase):
    def test_chain_retains_intermediate_domains_on_failed_destination(self):
        responses = {
            'https://example.com/': (301, '/next', 'http'),
            'https://example.com/next': (307, '//landing.other.net/path', 'http'),
            'https://landing.other.net/path': TimeoutError('offline'),
        }
        def fetch(_, url, *args):
            response = responses.get(url, (200, None, None))
            if isinstance(response, Exception):
                raise response
            return response
        with patch('netlens.redirects.request_page', side_effect=fetch):
            result = trace_redirects(['example.com'])
        self.assertEqual(result['domains'], ['example.com', 'landing.other.net'])
        self.assertTrue(result['partial'])
        self.assertEqual(len(result['chains'][0]['hops']), 2)
        self.assertEqual(result['chains'][0]['final_url'], 'https://landing.other.net/path')

    def test_loop_and_global_request_limit(self):
        with patch('netlens.redirects.request_page', return_value=(302, '/', 'http')) as request:
            result = trace_redirects(['example.com'])
        self.assertEqual(request.call_count, 2)
        self.assertIn('Цикл', result['chains'][0]['error'])
        with patch('netlens.redirects.request_page', side_effect=lambda _, u, *a: (302, u + 'next', 'http')) as request:
            result = trace_redirects(['example.com'], max_requests=3)
        self.assertEqual(request.call_count, 3)
        self.assertTrue(result['partial'])

    def test_cancel_does_not_make_requests(self):
        stop = threading.Event()
        stop.set()
        with patch('netlens.redirects.request_page') as request:
            result = trace_redirects(['example.com'], cancel=stop)
        request.assert_not_called()
        self.assertTrue(result['partial'])

    def test_unsupported_schemes_credentials_idn_and_fragment(self):
        for url in ('file:///etc/passwd', 'javascript:alert(1)', 'https://user:pass@example.com/'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                normalize_url(url)
        url, host = normalize_url('https://пример.рф/путь#section')
        self.assertEqual(host, 'xn--e1afmkfd.xn--p1ai')
        self.assertEqual(url, 'https://xn--e1afmkfd.xn--p1ai/%D0%BF%D1%83%D1%82%D1%8C')

    @patch('netlens.discovery.resolve_name', side_effect=no_dns)
    @patch('netlens.ct.search_certificates')
    @patch('netlens.discovery.trace_redirects')
    def test_redirect_roots_get_ct_and_targets_are_exported_without_related_option(self, trace, ct, dns):
        trace.return_value = {'enabled': True, 'domains': ['landing.other.net'], 'ips': ['2001:db8::1'],
                             'chains': [], 'requests': 2, 'partial': False, 'warnings': []}
        ct.side_effect = lambda root, *a: ([{'match': 'cdn.other.net'}] if root == 'other.net' else [], {'provider':'test'}, [])
        report = discover('example.com', networks=False)
        self.assertEqual([c.args[0] for c in ct.call_args_list], ['example.com', 'other.net'])
        self.assertEqual(report['redirect_roots'], ['other.net'])
        self.assertIn('other.net', report['ct_by_root'])
        target = next(d for d in report['domains'] if d['domain'] == 'landing.other.net')
        self.assertEqual(target['relation'], 'redirect_target')
        self.assertIn('http_redirect', target['sources'])
        self.assertEqual(next(d for d in report['domains'] if d['domain'] == 'cdn.other.net')['relation'], 'redirect_subdomain')
        with tempfile.TemporaryDirectory() as temp:
            save_report(report, temp)
            self.assertEqual((Path(temp) / 'domains.txt').read_text().splitlines(), address_lists(report)['domains'])
            ips = (Path(temp) / 'ips.txt').read_text().splitlines()
            self.assertIn('8.8.8.8', ips)
            self.assertIn('2001:db8::1', ips)

    @patch('netlens.discovery.resolve_name', side_effect=no_dns)
    @patch('netlens.discovery.trace_redirects')
    def test_dns_only_includes_redirects_but_can_be_disabled(self, trace, dns):
        trace.return_value = {'enabled':True, 'domains':['landing.other.net'], 'ips':[],
                             'chains':[], 'requests':1, 'partial':False, 'warnings':[]}
        with patch('netlens.ct.search_certificates') as ct:
            report = discover('example.com', use_ct=False, networks=False)
            ct.assert_not_called()
        self.assertIn('landing.other.net', address_lists(report)['domains'])
        trace.reset_mock()
        report = discover('example.com', use_ct=False, networks=False, follow_redirects=False)
        trace.assert_not_called()
        self.assertEqual(address_lists(report)['domains'], ['example.com'])

    @patch('netlens.discovery.resolve_name', side_effect=no_dns)
    @patch('netlens.discovery.trace_redirects')
    def test_limit_prioritizes_redirect_over_ct_subdomains(self, trace, dns):
        trace.return_value = {'enabled':True, 'domains':['landing.other.net'], 'ips':[],
                             'chains':[], 'requests':1, 'partial':False, 'warnings':[]}
        with patch('netlens.ct.search_certificates', return_value=([{'match':'a.example.com'}], {}, [])):
            report = discover('example.com', limit=2, networks=False)
        self.assertEqual(address_lists(report)['domains'], ['example.com', 'landing.other.net'])
        self.assertTrue(report['truncated'])


class HttpIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                content = b''
                if self.path == '/':
                    if 'visited=yes' not in self.headers.get('Cookie', ''):
                        self.send_response(302)
                        self.send_header('Set-Cookie', 'visited=yes; Path=/')
                        self.send_header('Location', '/')
                    else:
                        self.send_response(301)
                        self.send_header('Location', '/first')
                elif self.path == '/first':
                    self.send_response(302)
                    self.send_header('Location', '/meta')
                elif self.path == '/meta':
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html')
                    content = b'<base href="/relative/"><meta http-equiv="Refresh" content="0; URL=../last?x=1&amp;y=2">'
                elif self.path == '/refresh':
                    self.send_response(200)
                    self.send_header('Refresh', '0; url="/last"')
                elif self.path == '/denied':
                    self.send_response(403)
                else:
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_real_get_http_redirect_meta_base_and_refresh_header(self):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        def fetch(path):
            return request_page(opener, self.base + path, 2, time.monotonic() + 3, None)
        self.assertEqual(fetch('/first'), (302, '/meta', 'http'))
        self.assertEqual(fetch('/meta'), (200, self.base + '/last?x=1&y=2', 'meta_refresh'))
        self.assertEqual(fetch('/refresh'), (200, '/last', 'refresh'))
        self.assertEqual(fetch('/denied'), (403, None, None))

    def test_trace_with_real_http_server_preserves_all_hops(self):
        result = trace_redirects([f'127.0.0.1:{self.server.server_port}'], timeout=1)
        chain = next(c for c in result['chains'] if c['start_url'].startswith('http:'))
        self.assertEqual(len(chain['hops']), 4)
        self.assertNotIn('error', chain)
        self.assertEqual(chain['final_url'], self.base + '/last?x=1&y=2')
        self.assertEqual(result['ips'], ['127.0.0.1'])


if __name__ == '__main__':
    unittest.main()
