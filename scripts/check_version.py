"""Validate source version, historical mappings and a release tag."""
import argparse,json,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from netlens.version import build_info


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--tag');args=parser.parse_args()
    base=(ROOT/'VERSION').read_text(encoding='ascii').strip()
    info=build_info('f'*40,base_version=base)
    entries=json.loads((ROOT/'release-history.json').read_text(encoding='utf-8'))['releases']
    assert len({e['version'] for e in entries})==len(entries),'Duplicate historical version'
    assert len({e['revision'] for e in entries})==len(entries),'Duplicate historical revision'
    for entry in entries:
        assert re.fullmatch(r'[0-9a-f]{40,64}',entry['revision']),'Invalid historical revision'
        assert entry['tag']==entry['version']+'-'+entry['revision'][:7],'Invalid historical tag'
        assert build_info(entry['revision'])['tag']==entry['tag'],'Historical version mismatch'
    assert tuple(map(int,base.split('.')))>=max(tuple(map(int,e['version'].split('.'))) for e in entries)
    if args.tag:
        info=build_info();assert info['base_version']==base,'VERSION does not match source revision'
        assert args.tag==info['tag'],'Release tag does not match VERSION and commit SHA'
        tags=subprocess.check_output(['git','tag','--list',base+'-*'],cwd=ROOT,text=True).splitlines()
        assert not any(tag!=args.tag for tag in tags),'Version already released; bump VERSION'
    print('Version metadata and historical release mappings: PASS')


if __name__=='__main__':main()
