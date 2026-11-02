"""Download checksum-pinned Wireshark build inputs and extract the tools."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]


def download(url, checksum, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists() or hashlib.sha256(target.read_bytes()).hexdigest() != checksum:
        temporary = target.with_suffix(target.suffix+'.partial')
        with urlopen(Request(url,headers={'User-Agent':'NetLens-build/1'}), timeout=60) as response, temporary.open('wb') as output:
            shutil.copyfileobj(response, output)
        if hashlib.sha256(temporary.read_bytes()).hexdigest() != checksum:
            temporary.unlink()
            raise ValueError('Checksum mismatch: '+target.name)
        temporary.replace(target)
    return target


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache',type=Path,default=ROOT/'build/downloads')
    parser.add_argument('--extract',type=Path,default=ROOT/'build/wireshark')
    parser.add_argument('--source-only',action='store_true')
    args=parser.parse_args()
    dependency=json.loads((ROOT/'packaging/dependencies.json').read_text())['wireshark']
    source=download(dependency['source_url'],dependency['source_sha256'],args.cache/Path(dependency['source_url']).name)
    print('Source verified:',source.name)
    if args.source_only:
        return
    installer=download(dependency['url'],dependency['sha256'],args.cache/Path(dependency['url']).name)
    seven_zip=shutil.which('7z') or str(Path('C:/Program Files/7-Zip/7z.exe'))
    if not Path(seven_zip).is_file():
        parser.error('Install 7-Zip or add 7z to PATH to extract the Wireshark installer')
    args.extract.mkdir(parents=True,exist_ok=True)
    subprocess.run([seven_zip,'x','-y',str(installer),'-o'+str(args.extract)],check=True,stdout=subprocess.DEVNULL)
    if not (args.extract/'tshark.exe').exists():
        parser.error('The installer did not extract tshark.exe at the expected location')
    print('Wireshark tools extracted:',args.extract)


if __name__=='__main__':
    main()
