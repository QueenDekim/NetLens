"""Build the Windows runtime from explicit Python and Wireshark installations."""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pefile

ROOT = Path(__file__).resolve().parents[1]
NPCAP_FILES = {'wpcap.dll', 'packet.dll', 'npcaphelper.exe'}


def copy(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def tree(source, destination, excluded=()):
    shutil.copytree(source, destination, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc', *excluded))


def copy_dependencies(seeds, source, destination, python_base):
    available = {p.name.lower(): p for p in source.glob('*.dll') if p.name.lower() not in NPCAP_FILES}
    for folder in [python_base, Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32']:
        for pattern in ['vcruntime140*.dll', 'msvcp140*.dll', 'concrt140.dll']:
            for path in folder.glob(pattern):
                available.setdefault(path.name.lower(), path)
    pending, seen, external = list(seeds), set(), set()
    while pending:
        path = pending.pop()
        if path.name.lower() in seen:
            continue
        seen.add(path.name.lower())
        copy(path, destination / path.name)
        with pefile.PE(str(path), fast_load=True) as binary:
            binary.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                                                      pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT']])
            for entry in getattr(binary, 'DIRECTORY_ENTRY_IMPORT', []) + getattr(binary, 'DIRECTORY_ENTRY_DELAY_IMPORT', []):
                name = entry.dll.decode('ascii').lower()
                if name in available:
                    pending.append(available[name])
                else:
                    external.add(name)
    return sorted(external)


def write_manifest(destination, metadata):
    files = []
    for path in sorted(destination.rglob('*')):
        if path.is_file() and path.name != 'manifest.json' and '__pycache__' not in path.parts and path.suffix != '.pyc':
            files.append({'path': path.relative_to(destination).as_posix(), 'size': path.stat().st_size,
                          'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    (destination / 'manifest.json').write_text(json.dumps(metadata | {'files': files}, indent=2)+'\n', encoding='utf-8')
    print(f'Runtime: {len(files)} files, {sum(f["size"] for f in files)/1024**2:.1f} MiB')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wireshark', required=True, type=Path)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/portable/third-party')
    args = parser.parse_args()
    if os.name != 'nt' or sys.maxsize <= 2**32:
        parser.error('Use 64-bit Python on Windows')
    base = Path(sys.base_prefix)
    for required in [base/'tcl', base/'DLLs/_tkinter.pyd', args.wireshark/'tshark.exe', args.wireshark/'dumpcap.exe']:
        if not required.exists():
            parser.error(f'Missing build input: {required}')
    destination = args.output.resolve()
    if destination.exists() and any(destination.iterdir()):
        parser.error('The output directory must be empty; choose another --output path')
    runtime = destination / 'python'
    for name in ['python.exe', 'pythonw.exe', 'LICENSE.txt']:
        copy(base/name, runtime/name)
    for path in base.glob('*.dll'):
        copy(path, runtime/path.name)
    tree(base/'Lib', runtime/'Lib', ['site-packages', 'test', 'tests', 'idlelib', 'ensurepip'])
    tree(base/'DLLs', runtime/'DLLs')
    tree(base/'tcl', runtime/'tcl')
    packages = {}
    for package in ['dnspython', 'psutil']:
        distribution = importlib.metadata.distribution(package)
        packages[package] = distribution.version
        for entry in distribution.files:
            if '..' not in entry.parts and '__pycache__' not in entry.parts and not str(entry).endswith('.pyc'):
                path = Path(distribution.locate_file(entry))
                if path.is_file():
                    copy(path, runtime/'Lib/site-packages'/entry)
    version = f'{sys.version_info.major}{sys.version_info.minor}'
    (runtime/f'python{version}._pth').write_text('.\nDLLs\nLib\nLib\\site-packages\n..\\..\n', encoding='ascii')
    capture = destination/'wireshark'
    external = copy_dependencies([args.wireshark/'tshark.exe', args.wireshark/'dumpcap.exe'], args.wireshark, capture, base)
    for folder in ['diameter', 'dtds', 'radius', 'snmp', 'wimaxasncp', 'tpncp', 'protobuf', 'profiles', 'licenses', 'LICENSES']:
        if (args.wireshark/folder).is_dir():
            tree(args.wireshark/folder, capture/folder)
    for pattern in ['COPYING*', 'README*', 'LICENSE*', 'tshark.html', 'dumpcap.html', 'wireshark-filter.html', 'ws.css']:
        for path in args.wireshark.glob(pattern):
            if path.is_file():
                copy(path, capture/path.name)
    tree(ROOT/'third-party/public-suffix', destination/'public-suffix')
    version_text = subprocess.run([str(args.wireshark/'tshark.exe'), '--version'], capture_output=True, text=True, check=True).stdout.splitlines()[0]
    lock = json.loads((ROOT/'packaging/dependencies.json').read_text())
    if lock['wireshark']['version'] not in version_text:
        parser.error('Wireshark version differs from packaging/dependencies.json')
    (capture/'SOURCE.txt').write_text('Corresponding source: '+lock['wireshark']['source_url']+'\nSHA256: '+lock['wireshark']['source_sha256']+'\nThe release includes the source archive as a separate asset.\n', encoding='utf-8')
    write_manifest(destination, {'format':1, 'python_version':sys.version.split()[0], 'packages':packages,
                                'wireshark_version':lock['wireshark']['version'], 'npcap_included':False,
                                'external_system_dlls':external})


if __name__ == '__main__':
    main()
