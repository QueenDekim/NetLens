import concurrent.futures
import datetime as dt
import ipaddress
import json
import re
import urllib.parse
import urllib.request
import urllib.error

import dns.resolver

from .suffixes import registrable_domain
from .redirects import trace_redirects


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def domain_name(value):
    value = value.strip().rstrip('.').lower()
    if value.startswith('*.'):
        value = value[2:]
    value = value.encode('idna').decode('ascii')
    if len(value) > 253 or '.' not in value or not all(
        re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
        for part in value.split('.')
    ):
        raise ValueError('Укажите доменное имя без URL, пути и порта.')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('Нужен домен, а не IP-адрес.')


def get_json(url, timeout=15, max_bytes=24 * 1024 * 1024, headers=None):
    req = urllib.request.Request(url, headers={'User-Agent': 'NetLens/1.0', **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        raw = response.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError('Ответ сервиса превысил допустимый размер.')
    return json.loads(raw)


def certificate_names(root, rows):
    """SAN co-occurrence is a relationship hint, never proof of ownership."""
    found = {root: {'input'}}
    related = {}
    for row in rows:
        names = set()
        sans = row.get('san_dns')
        values = [row.get('match'), row.get('subject_cn')] + (sans if isinstance(sans, list) else [])
        for raw in values:
            if not isinstance(raw, str):
                continue
            try:
                names.add(domain_name(raw))
            except (ValueError, UnicodeError):
                pass
        if not any(n == root or n.endswith('.' + root) for n in names):
            continue
        for name in names:
            target = found if name == root or name.endswith('.' + root) else related
            source = 'passive_discovery' if row.get('_provider') == 'enterno' else 'certificate_transparency'
            target.setdefault(name, set()).add(source)
            if row.get('_provider'):
                target[name].add('ct:' + row['_provider'])
    return found, related


def ctlogs_certificates(root, limit, log=lambda _: None, cancel=None, api_key=None):
    """Sequential anonymous API access; preserve results on partial failures."""
    endpoint = 'https://api.ctlogs.dev/v1/subdomains/' + urllib.parse.quote(root, safe='')
    metadata = {'provider': 'ctlogs.dev', 'endpoint': endpoint, 'pages': 0,
                'certificate_details': 0, 'page_limit': 10, 'detail_limit': 40,
                'partial': False, 'history_truncated': False}
    rows, warnings, cursors = [], [], set()
    cursor = ''
    def fetch(url):
        if api_key:
            return get_json(url, timeout=25, headers={'Authorization': 'Bearer ' + api_key})
        return get_json(url, timeout=25)
    for page in range(metadata['page_limit']):
        if cancel and cancel.is_set():
            metadata['partial'] = True
            break
        log(f'ctlogs.dev: страница {page + 1}…')
        url = endpoint + ('?' + urllib.parse.urlencode({'after': cursor}) if cursor else '')
        try:
            data = fetch(url)
            if not isinstance(data, dict) or not isinstance(data.get('rows'), list) or not all(
                isinstance(row, dict) and isinstance(row.get('match'), str) for row in data['rows']
            ):
                raise ValueError('Некорректный формат ответа: ожидаются rows с полем match.')
            rows.extend(data['rows'])
            metadata['pages'] += 1
            metadata['history_truncated'] |= bool(data.get('history_truncated'))
            if 'history_window_days' in data:
                metadata['history_window_days'] = data['history_window_days']
            if not data.get('has_next'):
                break
            cursor = data.get('next_cursor')
            if not isinstance(cursor, str) or not cursor or cursor in cursors:
                raise ValueError('Некорректный или повторяющийся next_cursor.')
            cursors.add(cursor)
            found, _ = certificate_names(root, rows)
            if page + 1 == metadata['page_limit'] or len(found) >= limit:
                metadata['partial'] = True
                warnings.append('ctlogs.dev: поиск ограничен лимитом доменов или 10 страницами; доступны дополнительные записи.')
                break
        except Exception as exc:
            metadata['partial'] = True
            ctlogs_failure(metadata, exc)
            warnings.append(ctlogs_error(exc))
            # Do not spend more anonymous quota on details after a provider failure.
            return rows, metadata, warnings
    if metadata['history_truncated']:
        warnings.append('ctlogs.dev: старые сертификаты отсутствуют в доступном окне истории сервиса.')
    # A search match is not the complete SAN list. Fetch bounded, deduplicated
    # certificate records so shared-certificate relationships remain supported.
    details = {}
    for row in rows:
        ident = row.get('id')
        if isinstance(ident, str) and ident and isinstance(row.get('san_count'), int) and row['san_count'] > 1:
            details.setdefault(ident, row)
    for ident in list(details)[:metadata['detail_limit']]:
        if cancel and cancel.is_set():
            metadata['partial'] = True
            break
        log(f"ctlogs.dev: SAN сертификата {metadata['certificate_details'] + 1}/{min(len(details), metadata['detail_limit'])}…")
        try:
            data = fetch('https://api.ctlogs.dev/v1/cert/' + urllib.parse.quote(ident, safe=''))
            if not isinstance(data, dict) or not isinstance(data.get('san_dns'), list) or not all(
                isinstance(name, str) for name in data['san_dns']
            ):
                raise ValueError('Некорректный формат SAN сертификата.')
            rows.append(data)
            metadata['certificate_details'] += 1
        except Exception as exc:
            metadata['partial'] = True
            ctlogs_failure(metadata, exc)
            warnings.append(ctlogs_error(exc))
            break
    if len(details) > metadata['detail_limit']:
        metadata['partial'] = True
        warnings.append('ctlogs.dev: SAN проверены только у первых 40 уникальных сертификатов; список связанных имён может быть неполным.')
    return rows, metadata, warnings


def ctlogs_failure(metadata, exc):
    metadata['failure'] = True
    metadata['error'] = type(exc).__name__
    if isinstance(exc, urllib.error.HTTPError):
        metadata['http_status'] = exc.code
        metadata['error'] = f'HTTP {exc.code}'
        if exc.headers and exc.headers.get('Retry-After'):
            metadata['retry_after'] = exc.headers['Retry-After']


def ctlogs_error(exc):
    if isinstance(exc, urllib.error.HTTPError) and exc.code == 429:
        retry = exc.headers.get('Retry-After') if exc.headers else None
        return 'ctlogs.dev: HTTP 429, лимит запросов; частичный результат сохранён.' + (f' Retry-After: {retry}.' if retry else '')
    return f'ctlogs.dev: {exc}; сохранены доступные записи, DNS-разрешение продолжается.'


def resolve_name(name):
    result = {'domain': name, 'ips': [], 'cnames': [], 'errors': []}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4
    resolver.timeout = 2
    for kind in ('A', 'AAAA'):
        try:
            answer = resolver.resolve(name, kind, search=False)
            result['ips'].extend(str(r) for r in answer)
            for rrset in answer.response.answer:
                if rrset.rdtype == 5:
                    result['cnames'].extend(str(r.target).rstrip('.') for r in rrset)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except Exception as exc:
            result['errors'].append(f'{kind}: {exc}')
    result['ips'] = sorted(set(result['ips']))
    result['cnames'] = sorted(set(result['cnames']))
    return result


def network_info(address):
    ip = ipaddress.ip_address(address)
    result = {'ip': str(ip), 'prefix': None, 'asns': [], 'source': 'RIPEstat network-info'}
    if not ip.is_global:
        result['source'] = 'non_global_address'
        return result
    try:
        data = get_json('https://stat.ripe.net/data/network-info/data.json?' +
                        urllib.parse.urlencode({'resource': str(ip)}))['data']
        prefix = data.get('prefix')
        if prefix:
            network = ipaddress.ip_network(prefix)
            if network.version != ip.version or ip not in network:
                raise ValueError('Сервис вернул префикс, не содержащий IP.')
            result['prefix'] = str(network)
        result['asns'] = data.get('asns', [])
    except Exception as exc:
        result['error'] = str(exc)
    return result


def enrich_networks(addresses, log=lambda _: None, cancel=None):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        jobs = {pool.submit(network_info, ip): ip for ip in sorted(set(addresses))}
        for future in concurrent.futures.as_completed(jobs):
            if cancel and cancel.is_set():
                for job in jobs:
                    job.cancel()
                break
            results.append(future.result())
            log(f'Подсети: {len(results)}/{len(jobs)}')
    return sorted(results, key=lambda item: item['ip'])


def discover(root, limit=200, include_related=False, use_ct=True, networks=True,
             log=lambda _: None, cancel=None, ct_provider='auto', ct_fallback=True, api_keys=None,
             follow_redirects=True):
    input_domain = domain_name(root)
    root = registrable_domain(input_domain) if use_ct else input_domain
    if not 1 <= limit <= 5000:
        raise ValueError('Лимит доменов должен быть от 1 до 5000.')
    report = {'kind': 'discovery', 'created_at': utcnow(), 'root': root,
              'input_domain': input_domain, 'scope_expanded': root != input_domain, 'warnings': []}
    if root != input_domain:
        log(f'Поиск субдоменов: {input_domain} → {root}')
    found, related = {root: {'input'}}, {}
    redirect_domains, redirect_roots = set(), set()
    if follow_redirects:
        seeds = list(dict.fromkeys([input_domain, root]))
        try:
            root_is_registrable = root == registrable_domain(root)
        except ValueError:
            root_is_registrable = False
        if root_is_registrable and not root.startswith('www.'):
            seeds.append('www.' + root)
        log('Проверка редиректов HTTP/HTTPS…')
        report['redirects'] = trace_redirects(seeds, log, cancel)
        report['warnings'].extend(report['redirects']['warnings'])
        redirect_domains.update(report['redirects']['domains'])
        for name in sorted(redirect_domains):
            try:
                redirect_root = registrable_domain(name) if use_ct else name
            except ValueError:
                continue
            if redirect_root != root:
                redirect_roots.add(redirect_root)
    else:
        report['redirects'] = {'enabled': False, 'domains': [], 'ips': [], 'chains': [],
                               'requests': 0, 'partial': False, 'warnings': []}
    if use_ct:
        from .ct import search_certificates
        rows, report['ct'], ct_warnings = search_certificates(
            root, limit, ct_provider, ct_fallback, api_keys, log, cancel)
        report['warnings'].extend(ct_warnings)
        found, related = certificate_names(root, rows)
        report['ct_by_root'] = {root: report['ct']}
    for name in redirect_domains:
        found.setdefault(name, set()).add('http_redirect')
    for name in redirect_roots:
        found.setdefault(name, set()).add('redirect_root')
    report['redirect_roots'] = sorted(redirect_roots)
    if use_ct:
        for redirect_root in sorted(redirect_roots)[:4]:
            if cancel and cancel.is_set():
                break
            if limit <= len({root, input_domain} | redirect_domains | redirect_roots):
                break
            log(f'Субдомены редиректа: {redirect_root}')
            rows, metadata, warnings = search_certificates(
                redirect_root, max(1, limit // (len(redirect_roots) + 1)),
                ct_provider, ct_fallback, api_keys, log, cancel)
            report['ct_by_root'][redirect_root] = metadata
            report['warnings'].extend(warnings)
            extra, extra_related = certificate_names(redirect_root, rows)
            for name, sources in extra.items():
                found.setdefault(name, set()).update(sources - {'input'})
            for name, sources in extra_related.items():
                related.setdefault(name, set()).update(sources)
        if len(redirect_roots) > 4:
            report['warnings'].append('CT-поиск ограничен первыми четырьмя корневыми доменами редиректов; остальные цели разрешаются через DNS.')
    if root != input_domain:
        found[root].discard('input')
        found[root].add('registrable_domain')
        found.setdefault(input_domain, set()).add('input')
    # A redirect can promote a formerly speculative SAN name into a proven target.
    related = {n: s for n, s in related.items() if n not in found}
    candidates = dict(found)
    if include_related:
        candidates.update(related)
    names = [root] + ([input_domain] if input_domain != root else [])
    names += sorted((redirect_domains | redirect_roots) - set(names))
    names += sorted(n for n in found if n not in names)
    if include_related:
        names += sorted(related)
    report['discovered_count'] = len(names)
    report['truncated'] = len(names) > limit
    report['related_candidates'] = [{'domain': n, 'source': sorted(s)} for n, s in sorted(related.items())]
    report['domains'] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        jobs = {pool.submit(resolve_name, n): n for n in names[:limit]}
        for future in concurrent.futures.as_completed(jobs):
            if cancel and cancel.is_set():
                for job in jobs:
                    job.cancel()
                break
            item = future.result()
            item['sources'] = sorted(candidates[item['domain']])
            if item['domain'] in redirect_domains:
                item['relation'] = 'redirect_target'
            elif any(item['domain'] == n or item['domain'].endswith('.' + n) for n in redirect_roots):
                item['relation'] = 'redirect_subdomain'
            else:
                item['relation'] = 'subdomain' if item['domain'] in found else 'shared_certificate_candidate'
            report['domains'].append(item)
            log(f"DNS: {len(report['domains'])}/{len(jobs)} — {item['domain']}")
    report['domains'].sort(key=lambda item: item['domain'])
    # CNAMEs are useful related hosts with explicit evidence and independent resolution.
    aliases = sorted({n for item in report['domains'] for n in item['cnames']} - set(names[:limit]))
    report['cname_targets'] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        jobs = [pool.submit(resolve_name, alias) for alias in aliases[:limit]]
        for future in concurrent.futures.as_completed(jobs):
            if cancel and cancel.is_set():
                for job in jobs:
                    job.cancel()
                break
            item = future.result()
            item['sources'] = ['dns_cname']
            report['cname_targets'].append(item)
    report['cname_targets'].sort(key=lambda item: item['domain'])
    ips = {ip for item in report['domains'] + report['cname_targets'] for ip in item['ips']}
    ips.update(report['redirects']['ips'])
    report['networks'] = enrich_networks(ips, log, cancel) if networks else []
    report['cancelled'] = bool(cancel and cancel.is_set())
    return report
