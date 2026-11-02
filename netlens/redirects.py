"""Bounded HTTP/HTML redirect discovery without running remote scripts."""
import http.cookiejar
from html.parser import HTMLParser
import ipaddress
import re
import time
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def normalize_url(value, base=''):
    from .discovery import domain_name
    value = urllib.parse.urljoin(base, value.strip())
    parts = urllib.parse.urlsplit(value)
    if parts.scheme.lower() not in ('http', 'https') or not parts.hostname:
        raise ValueError('Допустимы только HTTP/HTTPS-редиректы.')
    if parts.username is not None or parts.password is not None:
        raise ValueError('URL редиректа содержит данные авторизации.')
    host = parts.hostname.rstrip('.').lower()
    try:
        address = ipaddress.ip_address(host)
        host = str(address)
        authority = '[' + host + ']' if address.version == 6 else host
    except ValueError:
        host = authority = domain_name(host)
    port = parts.port
    if port and port != (443 if parts.scheme.lower() == 'https' else 80):
        authority += ':' + str(port)
    path = urllib.parse.quote(parts.path or '/', safe="/%:@!$&'()*+,;=-._~")
    query = urllib.parse.quote(parts.query, safe="%/?@!$&'()*+,;=:-._~")
    return urllib.parse.urlunsplit((parts.scheme.lower(), authority, path, query, '')), host


def refresh_target(value):
    match = re.fullmatch(r'\s*\d+(?:\.\d+)?\s*[;,]\s*(?:url\s*=\s*)?(.+?)\s*', value, re.I)
    return match[1].strip().strip('\"\'') if match else None


class RefreshHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.base = None
        self.target = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'base' and self.base is None and attrs.get('href'):
            self.base = attrs['href']
        if tag == 'meta' and self.target is None and (attrs.get('http-equiv') or '').lower() == 'refresh':
            self.target = refresh_target(attrs.get('content') or '')


def request_page(opener, url, timeout, deadline, cancel):
    request = urllib.request.Request(url, headers={
        'User-Agent': 'Mozilla/5.0 (compatible; NetLens/1.0; domain discovery)',
        'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
        'Accept-Encoding': 'identity'})
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        status, headers = response.code, response.headers
        if status in (301, 302, 303, 307, 308):
            return status, headers.get('Location'), 'http'
        if not 200 <= status < 300:
            return status, None, None
        target = refresh_target(headers.get('Refresh', ''))
        if target:
            return status, target, 'refresh'
        if headers.get_content_type() not in ('text/html', 'application/xhtml+xml'):
            return status, None, None
        raw = bytearray()
        while len(raw) < 65536 and time.monotonic() < deadline and not (cancel and cancel.is_set()):
            chunk = response.read1(min(8192, 65536 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
            if b'</head>' in raw.lower():
                break
        parser = RefreshHTML()
        try:
            text = raw.decode(headers.get_content_charset() or 'utf-8', 'replace')
        except LookupError:
            text = raw.decode('utf-8', 'replace')
        parser.feed(text)
        if parser.target:
            base = urllib.parse.urljoin(url, parser.base) if parser.base else url
            return status, urllib.parse.urljoin(base, parser.target), 'meta_refresh'
        return status, None, None


def trace_redirects(hosts, log=lambda _: None, cancel=None, timeout=5, budget=30,
                    max_hops=10, max_requests=32):
    result = {'enabled': True, 'domains': [], 'ips': [], 'chains': [], 'requests': 0,
              'partial': False, 'warnings': []}
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPCookieProcessor(cookies))
    deadline = time.monotonic() + budget
    domains, ips = set(), set()
    for host in dict.fromkeys(hosts):
        for scheme in ('https', 'http'):
            if cancel and cancel.is_set():
                result['partial'] = True
                break
            url, _ = normalize_url(scheme + '://' + host + '/')
            chain = {'start_url': url, 'final_url': url, 'hops': []}
            result['chains'].append(chain)
            seen = set()
            while True:
                if cancel and cancel.is_set():
                    result['partial'] = True
                    break
                # A cookie-setting redirect to the same URL can be legitimate.
                state = (url, tuple(sorted((c.domain, c.path, c.name, c.value) for c in cookies)))
                if state in seen:
                    chain['error'] = 'Цикл редиректов.'
                    result['partial'] = True
                    break
                seen.add(state)
                if len(chain['hops']) >= max_hops:
                    chain['error'] = 'Достигнут предел переходов.'
                    result['partial'] = True
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0 or result['requests'] >= max_requests:
                    chain['error'] = 'Достигнут общий лимит времени или запросов.'
                    result['partial'] = True
                    break
                try:
                    result['requests'] += 1
                    status, target, kind = request_page(opener, url, min(timeout, remaining), deadline, cancel)
                    chain['status'] = status
                    if not target:
                        if status >= 400 or status in (301, 302, 303, 307, 308):
                            chain['error'] = f'HTTP {status}'
                            result['partial'] = True
                        break
                    target_url, target_host = normalize_url(target, url)
                except Exception as exc:
                    chain['error'] = type(exc).__name__ + ': ' + str(exc)
                    result['partial'] = True
                    break
                chain['hops'].append({'from': url, 'to': target_url, 'status': status, 'type': kind})
                try:
                    ipaddress.ip_address(target_host)
                    ips.add(target_host)
                except ValueError:
                    domains.add(target_host)
                log(f'Редирект: {url} → {target_url}')
                url = chain['final_url'] = target_url
    result['domains'], result['ips'] = sorted(domains), sorted(ips)
    if result['partial']:
        result['warnings'].append('Редиректы проверены частично; причины и найденные переходы сохранены в redirects.chains.')
    return result
