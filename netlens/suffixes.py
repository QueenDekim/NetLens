"""Offline registrable-domain lookup using the bundled Public Suffix List."""
from functools import cache
from pathlib import Path

PSL_PATH = Path(__file__).resolve().parent.parent / 'third-party/public-suffix/public_suffix_list.dat'


@cache
def rules():
    text = PSL_PATH.read_text(encoding='utf-8')
    if '===BEGIN ICANN DOMAINS===' not in text or '===BEGIN PRIVATE DOMAINS===' not in text:
        raise ValueError('Повреждён комплект Public Suffix List.')
    exact, wildcard, exception = set(), set(), set()
    for line in text.splitlines():
        rule = line.split('//', 1)[0].strip()
        if not rule:
            continue
        target = exact
        if rule.startswith('!'):
            target, rule = exception, rule[1:]
        elif rule.startswith('*.'):
            target, rule = wildcard, rule[2:]
        target.add(rule.encode('idna').decode('ascii').lower())
    return exact, wildcard, exception


def registrable_domain(name):
    """Accept a validated ASCII domain. PRIVATE rules preserve hosted tenants."""
    exact, wildcard, exception = rules()
    labels = name.split('.')
    suffix_length = 1  # PSL's implicit wildcard for unknown TLDs.
    for index in range(len(labels)):
        suffix = '.'.join(labels[index:])
        length = len(labels) - index
        if suffix in exception:
            return suffix
        if suffix in exact:
            suffix_length = max(suffix_length, length)
        if index > 0 and suffix in wildcard:
            suffix_length = max(suffix_length, length + 1)
    if len(labels) <= suffix_length:
        raise ValueError('Укажите домен над публичным суффиксом, например example.co.uk вместо co.uk.')
    return '.'.join(labels[-suffix_length - 1:])
