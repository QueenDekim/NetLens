"""Check local Markdown links and code-fence balance."""
from pathlib import Path
import re
from urllib.parse import unquote

ROOT=Path(__file__).resolve().parents[1]


def main():
    paths=list(ROOT.glob('*.md'))+list((ROOT/'docs').rglob('*.md'))
    errors=[]
    for path in paths:
        text=path.read_text(encoding='utf-8')
        if sum(line.startswith('```') for line in text.splitlines())%2:
            errors.append(f'{path.relative_to(ROOT)}: unbalanced code fence')
        for destination in re.findall(r'\[[^\]]+\]\(([^)]+)\)',text):
            if destination.startswith(('https://','http://','mailto:','#')):
                continue
            destination=unquote(destination.split('#',1)[0])
            if destination and not (path.parent/destination).exists():
                errors.append(f'{path.relative_to(ROOT)}: missing link target {destination}')
    if errors:
        raise SystemExit('\n'.join(errors))
    print(f'Documentation links and fences: {len(paths)} files checked')


if __name__=='__main__':
    main()
