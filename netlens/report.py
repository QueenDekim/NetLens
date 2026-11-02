import csv
import json
from pathlib import Path


def address_lists(report):
    """Complete, deduplicated result lists shared by export and clipboard."""
    if report['kind'] == 'discovery':
        items = report['domains'] + report.get('cname_targets', [])
        domains = {item['domain'] for item in items}
        ips = {ip for item in items for ip in item['ips']}
        ips.update(report.get('redirects', {}).get('ips', []))
    else:
        domains = {host['name'] for item in report['endpoints'] for host in item['hostnames']}
        ips = {item['ip'] for item in report['endpoints']}
    return {'domains': sorted(domains), 'ips': sorted(ips)}


def save_report(report, directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    addresses = address_lists(report)
    rows = []
    if report['kind'] == 'discovery':
        for item in report['domains'] + report.get('cname_targets', []):
            for ip in item['ips'] or ['']:
                rows.append([item['domain'], ip, '', '', ', '.join(item['sources'])])
        rows.extend(['', ip, '', '', 'http_redirect'] for ip in report.get('redirects', {}).get('ips', []))
    else:
        for item in report['endpoints']:
            names = [n['name'] for n in item['hostnames']]
            rows.append([', '.join(names), item['ip'], item['port'], item['transport'], ', '.join(item['evidence'])])
        candidates = {n for item in report['endpoints'] for n in item['dns_candidates']}
        (directory / 'dns-candidates.txt').write_text('\n'.join(sorted(candidates)), encoding='utf-8')
    prefixes = {n['prefix'] for n in report.get('networks', []) if n.get('prefix')}
    for filename, values in [('ips.txt', addresses['ips']), ('domains.txt', addresses['domains']), ('subnets.txt', prefixes)]:
        (directory / filename).write_text('\n'.join(sorted(values)), encoding='utf-8')
    with (directory / 'endpoints.csv').open('w', encoding='utf-8-sig', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['domain', 'ip', 'port', 'transport', 'evidence'])
        # Escape spreadsheet formulas from external input.
        writer.writerows([["'" + str(v) if str(v).startswith(('=', '+', '-', '@')) else v for v in row] for row in rows])
    return directory
