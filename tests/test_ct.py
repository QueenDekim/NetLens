import io
import json
import threading
import unittest
import urllib.error
from unittest.mock import patch

from netlens import ct, discovery


def fail(code=429):
    return urllib.error.HTTPError('https://test.invalid/', code, 'error', {'Retry-After': '120'}, None)


class FailoverTests(unittest.TestCase):
    def setUp(self):
        ct.COOLDOWNS.clear()
        self.env = patch.dict('os.environ', {}, clear=True)
        self.env.start()

    def tearDown(self):
        self.env.stop()
        ct.COOLDOWNS.clear()

    @patch('netlens.ct.fetch', return_value={'hostnames': ['www.example.com'], 'next': None})
    @patch('netlens.discovery.ctlogs_certificates', side_effect=fail())
    def test_rate_limit_switch_and_cooldown(self, primary, secondary):
        rows, meta, _ = ct.search_certificates('example.com', 200)
        self.assertEqual(meta['provider'], 'sslboard')
        self.assertEqual(meta['attempts'][0]['http_status'], 429)
        self.assertEqual(rows[0]['_provider'], 'sslboard')
        _, again, _ = ct.search_certificates('example.com', 200)
        self.assertEqual(again['attempts'][0]['status'], 'cooldown')
        self.assertEqual(primary.call_count, 1)

    @patch('netlens.ct.fetch')
    @patch('netlens.discovery.ctlogs_certificates', side_effect=TimeoutError())
    def test_manual_service_with_fallback_disabled(self, primary, secondary):
        _, meta, _ = ct.search_certificates('example.com', 200, 'ctlogs.dev', False)
        self.assertEqual(meta['status'], 'unavailable')
        self.assertEqual(len(meta['attempts']), 1)
        secondary.assert_not_called()

    @patch('netlens.discovery.ctlogs_certificates', return_value=([], {'provider': 'ctlogs.dev'}, []))
    @patch('netlens.ct.fetch')
    def test_valid_empty_result_does_not_failover(self, other, primary):
        rows, meta, _ = ct.search_certificates('example.com', 200)
        self.assertEqual(rows, [])
        self.assertEqual(meta['status'], 'success')
        other.assert_not_called()

    @patch('netlens.ct.fetch', return_value={'hostnames': ['b.example.com']})
    @patch('netlens.discovery.ctlogs_certificates', return_value=(
        [{'match': 'a.example.com'}], {'provider': 'ctlogs.dev', 'partial': True, 'failure': True, 'http_status': 503}, ['unavailable']))
    def test_partial_results_from_failed_provider_are_retained(self, *_):
        rows, meta, _ = ct.search_certificates('example.com', 200)
        found, _ = discovery.certificate_names('example.com', rows)
        self.assertIn('ct:ctlogs.dev', found['a.example.com'])
        self.assertIn('ct:sslboard', found['b.example.com'])
        self.assertEqual(meta['provider'], 'sslboard')

    @patch('netlens.ct.fetch', side_effect=[
        {'hostnames': ['a.example.com'], 'tier': 'free', 'truncated': True},
        [{'id': '1', 'dns_names': ['b.example.com', 'other.net']}], [],
    ])
    @patch('netlens.discovery.ctlogs_certificates', return_value=([], {'provider': 'ctlogs.dev', 'failure': True}, []))
    def test_provider_cap_switches_to_next_service(self, *_):
        rows, meta, _ = ct.search_certificates('example.com', 200, 'sslboard')
        # SSLBoard cap -> ctlogs next in configured order, replaced for this test.
        self.assertTrue(meta['attempts'][0]['provider_limit'])
        self.assertEqual(meta['provider'], 'certspotter')
        self.assertIn('a.example.com', discovery.certificate_names('example.com', rows)[0])

    @patch('netlens.discovery.ctlogs_certificates', return_value=([], {'provider': 'ctlogs.dev', 'partial': True, 'local_limit': True}, []))
    @patch('netlens.ct.fetch')
    def test_local_safety_limit_does_not_spend_other_quotas(self, other, primary):
        ct.search_certificates('example.com', 1)
        other.assert_not_called()

    @patch('netlens.discovery.ctlogs_certificates', return_value=([], {'provider': 'ctlogs.dev'}, []))
    def test_missing_key_is_recorded_and_next_source_used(self, _):
        _, meta, _ = ct.search_certificates('example.com', 200, 'merklemap')
        self.assertEqual(meta['attempts'][0]['status'], 'missing_key')
        self.assertEqual(meta['provider'], 'ctlogs.dev')

    @patch('netlens.ct.fetch', side_effect=fail(503))
    @patch('netlens.discovery.ctlogs_certificates', side_effect=fail(503))
    def test_all_unavailable_is_not_an_empty_success(self, *_):
        _, meta, warnings = ct.search_certificates('example.com', 200)
        self.assertEqual(meta['status'], 'unavailable')
        self.assertEqual(len(meta['attempts']), 5)
        self.assertTrue(warnings)

    @patch('netlens.ct.fetch')
    def test_cancellation_stops_failover(self, fetch):
        stop = threading.Event()
        def primary(*args):
            stop.set()
            raise TimeoutError()
        with patch('netlens.discovery.ctlogs_certificates', side_effect=primary):
            _, meta, _ = ct.search_certificates('example.com', 200, cancel=stop)
        self.assertEqual(meta['status'], 'cancelled')
        fetch.assert_not_called()

    @patch('netlens.discovery.ctlogs_certificates', side_effect=ValueError('secret-token invalid'))
    def test_keys_are_not_exposed_in_reports(self, _):
        _, meta, warnings = ct.search_certificates('example.com', 200, fallback=False, api_keys={'ctlogs.dev': 'secret-token'})
        self.assertNotIn('secret-token', json.dumps([meta, warnings]))


class AdapterTests(unittest.TestCase):
    @patch('netlens.ct.fetch', side_effect=[
        [{'id': '1', 'dns_names': ['example.com', 'www.example.com', 'other.net']}], []])
    def test_certspotter_san_and_cursor(self, fetch):
        rows, meta, _ = ct.paged_provider('certspotter', 'example.com', 200, 'token', lambda _: None, None)
        self.assertEqual(meta['pages'], 2)
        self.assertIn('after=1', fetch.call_args_list[1].args[0])
        found, related = discovery.certificate_names('example.com', rows)
        self.assertIn('www.example.com', found)
        self.assertIn('other.net', related)

    @patch('netlens.ct.fetch', side_effect=[
        {'count': 2, 'results': [{'hostname': 'a.example.com', 'subject_common_name': 'other.net'}]},
        {'count': 2, 'results': [{'hostname': 'b.example.com', 'subject_common_name': 'b.example.com'}]},
    ])
    def test_merklemap_pagination(self, fetch):
        rows, meta, _ = ct.paged_provider('merklemap', 'example.com', 200, 'token', lambda _: None, None)
        self.assertEqual(len(rows), 2)
        self.assertEqual(meta['pages'], 2)
        self.assertIn('page=1', fetch.call_args_list[1].args[0])
        self.assertEqual(fetch.call_args.args[1], 'token')

    @patch('netlens.ct.fetch', side_effect=[
        {'hostnames': ['a.example.com'], 'next': 'a.example.com', 'tier': 'pro'},
        {'hostnames': ['b.example.com'], 'next': None, 'tier': 'pro'},
    ])
    def test_sslboard_paid_cursor(self, fetch):
        rows, meta, _ = ct.paged_provider('sslboard', 'example.com', 200, 'token', lambda _: None, None)
        self.assertEqual(meta['pages'], 2)
        self.assertIn('after=a.example.com', fetch.call_args.args[0])

    @patch('netlens.ct.fetch', return_value={'error': 'unavailable'})
    def test_invalid_schema_triggers_failure(self, _):
        _, meta, _ = ct.paged_provider('sslboard', 'example.com', 200, '', lambda _: None, None)
        self.assertTrue(meta['failure'])

    def test_enterno_structured_and_text_payloads(self):
        for payload in [
            {'structuredContent': {'subdomains': ['a.example.com']}},
            {'content': [{'type': 'text', 'text': json.dumps({'data': {'subdomains': [{'domain': 'a.example.com'}]}})}]},
        ]:
            self.assertEqual(ct.enterno_payload(payload), ['a.example.com'])
        with self.assertRaises(ct.ProviderError):
            ct.enterno_payload({'isError': True, 'content': []})

    @patch('netlens.ct.urllib.request.urlopen')
    def test_enterno_sse_response_and_auth_header(self, open_url):
        data = {'jsonrpc': '2.0', 'id': 1, 'result': {'structuredContent': {'subdomains': ['a.example.com']}}}
        open_url.return_value.__enter__.return_value = io.BytesIO(('event: message\ndata: ' + json.dumps(data) + '\n\n').encode())
        rows, meta, _ = ct.enterno('example.com', 'token', None)
        self.assertEqual(rows, [{'match': 'a.example.com'}])
        req = open_url.call_args.args[0]
        self.assertEqual(req.get_header('Authorization'), 'Bearer token')
        self.assertEqual(json.loads(req.data)['params']['arguments'], {'domain': 'example.com'})


if __name__ == '__main__':
    unittest.main()
