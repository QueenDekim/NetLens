"""Verify a relocated release without Python, packages or Wireshark on PATH."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive',type=Path,default=ROOT/'dist/NetLens-win-x64.zip')
    args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='netlens-portable-') as temporary:
        stage=Path(temporary)/'NetLens переносимый'
        with zipfile.ZipFile(args.archive) as archive:
            assert len(archive.namelist())==len(set(archive.namelist())), 'Duplicate archive paths'
            assert not any(Path(name).name.lower() in {'wpcap.dll','packet.dll','npcaphelper.exe'} or Path(name).name.lower().startswith('npcap-') for name in archive.namelist())
            archive.extractall(stage)
        workspace=stage/'NetLens'
        runtime=workspace/'third-party/python/python.exe'
        environment=dict(os.environ)
        environment['PATH']=str(Path(os.environ.get('SystemRoot',r'C:\Windows'))/'System32')
        environment['PYTHONHOME']=str(stage/'absent-python')
        environment['PYTHONPATH']=str(stage/'absent-packages')
        environment.pop('NETLENS_TSHARK',None)
        environment.pop('TCL_LIBRARY',None)
        environment.pop('TK_LIBRARY',None)
        environment.pop('SOURCE_REVISION',None)
        version=json.loads((workspace/'netlens/_build.json').read_text(encoding='utf-8'))
        actual=subprocess.check_output([str(runtime),'-m','netlens','--version'],cwd=workspace,env=environment,text=True).strip()
        assert actual==version['version'] and version['version']=='1.0-'+version['revision'][:7]
        for language,caption in [('en','IP addresses, subnets'),('ru','IP, подсети')]:
            output=subprocess.check_output([str(runtime),'-X','utf8','-m','netlens','--language',language,'--help'],cwd=workspace,env=environment,encoding='utf-8')
            assert caption in output, (language,output)
        commands=[['scripts/verify_bundle.py'],['scripts/check_docs.py'],['-m','unittest','discover','-s','tests','-v'],
                  ['-m','netlens','--help'],['-c','from pathlib import Path; import tkinter, _tkinter, dns, psutil; t=tkinter.Tcl(); assert Path(t.eval("info library")).resolve().is_relative_to(Path.cwd()); print(t.eval("info patchlevel"))']]
        for command in commands:
            subprocess.run([str(runtime),*command],cwd=workspace,env=environment,check=True,timeout=120)
        subprocess.run([str(workspace/'third-party/wireshark/tshark.exe'),'--version'],cwd=workspace,
                       env=environment,check=True,timeout=15,stdout=subprocess.DEVNULL)
        print('RELOCATED PORTABLE / RU-EN / VERSION / CLI / UNIT TESTS / TCL / TSHARK PASS')


if __name__=='__main__':
    main()
