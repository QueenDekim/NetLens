"""Package verified Windows runtime files and application sources."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, default=ROOT/'build/portable/third-party')
    parser.add_argument('--output', type=Path, default=ROOT/'dist/NetLens-win-x64.zip')
    args=parser.parse_args()
    subprocess.run([sys.executable,str(ROOT/'scripts/verify_bundle.py'),'--root',str(args.runtime)],check=True)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    entries=[]
    for name,folder in [('netlens',ROOT/'netlens'),('third-party',args.runtime),('tests',ROOT/'tests'),('docs',ROOT/'docs')]:
        for path in sorted(folder.rglob('*')):
            if path.is_file() and '__pycache__' not in path.parts and path.suffix!='.pyc':
                entries.append((path,'NetLens/'+name+'/'+path.relative_to(folder).as_posix()))
    for name in ['README.md','LICENSE','NOTICE','THIRD_PARTY_NOTICES.md','CONTRIBUTING.md','SECURITY.md','CHANGELOG.md','NetLens.cmd','Start-NetLens.ps1','requirements.txt']:
        entries.append((ROOT/name,'NetLens/'+name))
    entries.append((ROOT/'scripts/verify_bundle.py','NetLens/scripts/verify_bundle.py'))
    entries.append((ROOT/'scripts/check_docs.py','NetLens/scripts/check_docs.py'))
    with zipfile.ZipFile(args.output,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
        for path,name in entries:
            # Fixed timestamps keep repeated packaging of the same input tree identical.
            info=zipfile.ZipInfo(name,date_time=(2020,1,1,0,0,0))
            info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=0o100644<<16
            archive.writestr(info,path.read_bytes())
    checksum=hashlib.sha256(args.output.read_bytes()).hexdigest()
    args.output.with_suffix(args.output.suffix+'.sha256').write_text(checksum+'  '+args.output.name+'\n',encoding='ascii')
    print(f'{args.output.name}: {args.output.stat().st_size/1024**2:.1f} MiB; SHA256 {checksum}')


if __name__=='__main__':
    main()
