"""Advance the release number before committing a new release."""
import argparse,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('part',choices=['major','minor','patch']);args=parser.parse_args()
path=ROOT/'VERSION';current=path.read_text(encoding='ascii').strip()
if not re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)',current):parser.error('VERSION must contain MAJOR.MINOR.PATCH')
major,minor,patch=map(int,current.split('.'))
if args.part=='major':major+=1;minor=patch=0
elif args.part=='minor':minor+=1;patch=0
else:patch+=1
value=f'{major}.{minor}.{patch}';path.write_text(value+'\n',encoding='ascii');print(value)
