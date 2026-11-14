"""Resolve source and packaged version metadata without requiring Git at runtime."""
import json
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'https://github.com/QueenDekim/NetLens'


def git_revision(root):
    directory = Path(root) / '.git'
    try:
        if directory.is_file():
            value = directory.read_text(encoding='utf-8').strip()
            if not value.startswith('gitdir: '):
                return None
            directory = (Path(root) / value[8:]).resolve()
        common = directory
        if (directory / 'commondir').is_file():
            common = (directory / (directory / 'commondir').read_text(encoding='utf-8').strip()).resolve()
        head = (directory / 'HEAD').read_text(encoding='ascii').strip()
        if head.startswith('ref: '):
            reference = head[5:]
            candidate = (common / reference).resolve()
            if not candidate.is_relative_to(common.resolve()):
                return None
            if candidate.exists():
                head = candidate.read_text(encoding='ascii').strip()
            else:
                packed = (common / 'packed-refs').read_text(encoding='ascii')
                head = next(line.split()[0] for line in packed.splitlines() if line.endswith(' ' + reference))
        return head if re.fullmatch(r'[0-9a-f]{40,64}', head) else None
    except (OSError, UnicodeError, StopIteration):
        return None


def build_info(revision=None, root=ROOT, base_version=None):
    root = Path(root)
    source = (root / 'VERSION').read_text(encoding='ascii').strip() if (root / 'VERSION').exists() else '1.0.0'
    metadata = Path(__file__).with_name('_build.json')
    cached = json.loads(metadata.read_text(encoding='utf-8')) if metadata.exists() else {}
    if revision is None:
        revision = os.environ.get('SOURCE_REVISION') or cached.get('revision') or git_revision(root)
    if revision and not re.fullmatch(r'[0-9a-f]{7,64}', revision):
        raise ValueError('Invalid source revision')
    history = root / 'release-history.json'
    releases = json.loads(history.read_text(encoding='utf-8'))['releases'] if history.exists() else []
    matches = [entry for entry in releases if revision and entry['revision'].startswith(revision)]
    if len(matches)>1:
        raise ValueError('Ambiguous source revision')
    base = base_version or (matches[0]['version'] if matches else None)
    if not base and revision and revision == cached.get('revision'):
        base = cached.get('base_version')
    base = base or source
    if not re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)', base):
        raise ValueError('Invalid base version; expected MAJOR.MINOR.PATCH')
    version = base + '-' + (revision[:7] if revision else 'unknown')
    return {'base_version':base, 'version':version, 'revision':revision, 'tag':version if revision else None,
            'url':REPOSITORY + ('/tree/' + version if revision else '/tags')}
