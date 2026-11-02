"""Verify runtime checksums and the public distribution file policy."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=ROOT/'third-party')
    args=parser.parse_args()
    root=args.root.resolve()
    manifest=json.loads((root/'manifest.json').read_text(encoding='utf-8'))
    if manifest.get('npcap_included') is not False:
        raise SystemExit('The public runtime must exclude Npcap binaries and installers')
    for entry in manifest['files']:
        path=(root/entry['path']).resolve()
        if not path.is_relative_to(root) or not path.is_file() or path.stat().st_size!=entry['size'] or hashlib.sha256(path.read_bytes()).hexdigest()!=entry['sha256']:
            raise SystemExit('Runtime verification failed: '+entry['path'])
    for path in root.rglob('*'):
        name=path.name.lower()
        if name in {'wpcap.dll','packet.dll','npcaphelper.exe'} or name.startswith('npcap-'):
            raise SystemExit('Restricted capture driver file: '+path.name)
    print(f'PASS: {len(manifest["files"])} runtime files verified')


if __name__=='__main__':
    main()
