"""CT source adapters, bounded pagination and failover without extra packages."""
import email.utils
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import discovery

PROVIDERS = {
    'ctlogs.dev': ('ctlogs.dev', 'CTLOGS_API_KEY', False),
    'sslboard': ('SSLBoard', 'SSLBOARD_API_KEY', False),
    'certspotter': ('Cert Spotter (SSLMate)', 'CERTSPOTTER_API_KEY', False),
    'merklemap': ('Merklemap', 'MERKLEMAP_API_KEY', True),
    'enterno': ('Enterno.io', 'ENTERNO_API_KEY', True),
}
COOLDOWNS = {}
COOLDOWN_LOCK = threading.Lock()


class ProviderError(Exception):
    pass


def keys_from_environment():
    return {name: os.environ.get(info[1], '').strip() for name, info in PROVIDERS.items()}


def fetch(url, key=None):
    headers = {'Authorization': 'Bearer ' + key} if key else None
    return discovery.get_json(url, timeout=20, headers=headers)


def string_list(value):
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ProviderError('Некорректный список доменов в ответе API.')
    return value


def http_failure(exc, key=''):
    info = {'failure': True}
    if isinstance(exc, urllib.error.HTTPError):
        info['http_status'] = exc.code
        info['error'] = f'HTTP {exc.code}'
        if exc.headers and exc.headers.get('Retry-After'):
            info['retry_after'] = exc.headers['Retry-After']
    elif isinstance(exc, (TimeoutError, urllib.error.URLError, OSError)):
        info['error'] = 'Сетевая ошибка или таймаут.'
    else:
        info['error'] = str(exc)
    if key:
        info['error'] = info['error'].replace(key, '[скрыто]')
    info['error'] = info['error'][:400]
    return info


def paged_provider(name, root, limit, key, log, cancel):
    rows, warnings = [], []
    meta = {'provider': name, 'pages': 0, 'partial': False}
    cursor, cursors, seen = '', set(), set()
    try:
        for page in range(10):
            if cancel and cancel.is_set():
                meta.update(cancelled=True, partial=True)
                break
            log(f'{PROVIDERS[name][0]}: страница {page + 1}…')
            if name == 'sslboard':
                params = {'q': root, 'format': 'json', 'limit': min(10000, limit)}
                if cursor:
                    params['after'] = cursor
                url = 'https://sslboard.com/api/v1/hostnames?' + urllib.parse.urlencode(params)
                data = fetch(url, key)
                names = string_list(data['hostnames'])
                batch = [{'match': n} for n in names]
                next_cursor = data.get('next')
                meta.update(tier=data.get('tier'), total=data.get('total'), history='valid_plus_15_days')
                if data.get('truncated') and not next_cursor:
                    meta.update(partial=True, provider_limit=True)
            elif name == 'certspotter':
                params = {'domain': root, 'include_subdomains': 'true', 'expand': 'dns_names'}
                if cursor:
                    params['after'] = cursor
                url = 'https://api.certspotter.com/v1/issuances?' + urllib.parse.urlencode(params)
                data = fetch(url, key)
                if not isinstance(data, list):
                    raise ProviderError('Cert Spotter: ожидается массив сертификатов.')
                batch = [{'san_dns': string_list(r['dns_names'])} for r in data]
                next_cursor = str(data[-1]['id']) if data else None
                meta['history'] = 'unexpired_certificates'
            else:
                params = {'query': '*.' + root, 'type': 'wildcard', 'page': page}
                url = 'https://api.merklemap.com/v1/search?' + urllib.parse.urlencode(params)
                data = fetch(url, key)
                if not isinstance(data.get('results'), list):
                    raise ProviderError('Merklemap: ожидается results.')
                batch = []
                for r in data['results']:
                    hostname = r['hostname']
                    if not isinstance(hostname, str):
                        raise ProviderError('Merklemap: некорректное имя хоста.')
                    # CN and hostname co-occur in this certificate row.
                    batch.append({'match': hostname, 'subject_cn': r.get('subject_common_name')})
                seen.update(r['match'] for r in batch)
                next_cursor = str(page + 1) if batch and len(seen) < int(data['count']) else None
            rows.extend(batch)
            meta['pages'] += 1
            if not next_cursor:
                break
            if next_cursor in cursors:
                raise ProviderError('Повторяющийся курсор; дальнейший поиск остановлен.')
            cursors.add(next_cursor)
            cursor = next_cursor
            found, _ = discovery.certificate_names(root, rows)
            if len(found) >= limit or page == 9:
                meta.update(partial=True, local_limit=True)
                break
    except Exception as exc:
        meta.update(partial=True, **http_failure(exc, key))
    if meta.get('partial'):
        warnings.append(f"{PROVIDERS[name][0]}: результат неполный; " + meta.get('error', 'достигнут лимит выдачи.'))
    return rows, meta, warnings


def enterno_payload(result):
    """Accept structured MCP output or JSON carried in a text content block."""
    if result.get('isError'):
        raise ProviderError('Enterno.io: инструмент отказал; проверьте ключ, тариф и квоту.')
    payload = result.get('structuredContent')
    if payload is None:
        for item in result.get('content', []):
            if item.get('type') == 'text':
                try:
                    payload = json.loads(item['text'])
                    break
                except (ValueError, KeyError):
                    pass
    if not isinstance(payload, dict):
        raise ProviderError('Enterno.io: не получен структурированный список субдоменов.')
    if isinstance(payload.get('data'), dict):
        payload = payload['data']
    if payload.get('error'):
        raise ProviderError('Enterno.io: ошибка поиска субдоменов.')
    names = payload.get('subdomains')
    if not isinstance(names, list):
        raise ProviderError('Enterno.io: отсутствует subdomains в результате.')
    return string_list([n.get('domain') or n.get('hostname') or n.get('name') if isinstance(n, dict) else n for n in names])


def enterno(root, key, cancel):
    # The official server supports direct tools/call without a session handshake.
    body = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
            'params': {'name': 'check_subdomain_enum', 'arguments': {'domain': root}}}
    req = urllib.request.Request('https://enterno.io/mcp', data=json.dumps(body).encode(),
          headers={'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream',
                   'Authorization': 'Bearer ' + key, 'User-Agent': 'NetLens/1.0'})
    with urllib.request.urlopen(req, timeout=25) as response:
        raw = response.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise ProviderError('Enterno.io: ответ слишком велик.')
    text = raw.decode('utf-8')
    if text.lstrip().startswith('{'):
        data = json.loads(text)
    else:
        data = None
        for block in text.replace('\r\n', '\n').split('\n\n'):
            chunk = '\n'.join(line[5:].lstrip() for line in block.splitlines() if line.startswith('data:'))
            if chunk:
                event = json.loads(chunk)
                if event.get('id') == 1:
                    data = event
                    break
    if not isinstance(data, dict) or data.get('error') or not isinstance(data.get('result'), dict):
        raise ProviderError('Enterno.io: ошибка JSON-RPC или недоступный инструмент.')
    names = enterno_payload(data['result'])
    return [{'match': n} for n in names], {'provider': 'enterno', 'pages': 1, 'partial': False,
            'data_scope': 'CT_and_passive_sources'}, []


def cooldown_seconds(value):
    try:
        return max(1, int(value))
    except (ValueError, TypeError):
        try:
            return max(1, int(email.utils.parsedate_to_datetime(value).timestamp() - time.time()))
        except (ValueError, TypeError, OverflowError):
            return 60


def search_certificates(root, limit, preferred='auto', fallback=True, api_keys=None,
                        log=lambda _: None, cancel=None):
    if preferred != 'auto' and preferred not in PROVIDERS:
        raise ValueError('Неизвестный CT-сервис: ' + preferred)
    keys = keys_from_environment()
    keys.update(api_keys or {})
    order = list(PROVIDERS)
    if preferred != 'auto':
        order.remove(preferred)
        order.insert(0, preferred)
    if not fallback:
        order = order[:1]
    result, warnings, attempts = [], [], []
    successful = None
    for name in order:
        if cancel and cancel.is_set():
            break
        key = keys.get(name, '')
        with COOLDOWN_LOCK:
            remaining = COOLDOWNS.get(name, 0) - time.monotonic()
        if remaining > 0:
            attempt = {'provider': name, 'status': 'cooldown', 'retry_in_seconds': int(remaining) + 1}
        elif PROVIDERS[name][2] and not key:
            attempt = {'provider': name, 'status': 'missing_key', 'error': f'Нужен {PROVIDERS[name][1]}.'}
        else:
            log(f'Certificate Transparency: {PROVIDERS[name][0]}…')
            try:
                if name == 'ctlogs.dev':
                    if key:
                        rows, attempt, notes = discovery.ctlogs_certificates(root, limit, log, cancel, api_key=key)
                    else:
                        rows, attempt, notes = discovery.ctlogs_certificates(root, limit, log, cancel)
                elif name == 'enterno':
                    rows, attempt, notes = enterno(root, key, cancel)
                else:
                    rows, attempt, notes = paged_provider(name, root, limit, key, log, cancel)
                for row in rows:
                    result.append({**row, '_provider': name})
                # Defensively redact even a provider error that echoes credentials.
                warnings.extend(note.replace(key, '[скрыто]') if key else note for note in notes)
                attempt['status'] = 'failed' if attempt.get('failure') else 'partial' if attempt.get('partial') else 'success'
                attempt['records'] = len(rows)
                if not attempt.get('failure') and not attempt.get('provider_limit'):
                    successful = name
            except Exception as exc:
                attempt = {'provider': name, 'status': 'failed', **http_failure(exc, key)}
            if attempt.get('http_status') == 429 or attempt.get('retry_after'):
                with COOLDOWN_LOCK:
                    COOLDOWNS[name] = time.monotonic() + cooldown_seconds(attempt.get('retry_after'))
        attempts.append(attempt)
        if successful or (cancel and cancel.is_set()):
            break
        reason = attempt.get('error') or attempt['status']
        warnings.append(f'{PROVIDERS[name][0]}: {reason}; ' + ('переход к следующему источнику.' if name != order[-1] else 'других источников нет.'))
        log(warnings[-1])
    metadata = {'provider': successful, 'requested_provider': preferred, 'fallback_enabled': fallback,
                'attempts': attempts, 'partial': any(a.get('partial') for a in attempts) or not successful,
                'status': 'cancelled' if cancel and cancel.is_set() else 'success' if successful else 'unavailable'}
    return result, metadata, warnings
