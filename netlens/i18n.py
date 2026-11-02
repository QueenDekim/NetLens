"""Local translations and a language preference shared by the GUI and CLI."""
import json
import locale
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LANGUAGES = {'ru':'Русский', 'en':'English'}
CATALOG = json.loads((Path(__file__).parent / 'locales/en.json').read_text(encoding='utf-8'))
_language = 'ru'


class LocalizedText(str):
    def __new__(cls, value, source, args, kwargs):
        instance = super().__new__(cls, value)
        instance.source, instance.args, instance.kwargs = source, args, kwargs
        return instance


def language():
    return _language


def preferred_language():
    override = os.environ.get('NETLENS_LANGUAGE')
    if override in LANGUAGES:
        return override
    try:
        saved = json.loads((ROOT/'preferences.json').read_text(encoding='utf-8')).get('language')
        if saved in LANGUAGES:
            return saved
    except (OSError, ValueError, TypeError):
        pass
    return 'ru' if (locale.getlocale()[0] or '').lower().startswith('ru') else 'en'


def set_language(value, persist=False):
    global _language
    if value not in LANGUAGES:
        raise ValueError('Unsupported language')
    _language = value
    if persist:
        path = ROOT/'preferences.json'
        try:
            data = json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
            data['language'] = value
            temporary = path.with_name(path.name+'.tmp')
            temporary.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
            temporary.replace(path)
        except (OSError, ValueError, TypeError):
            pass


def tr(source, *args, **kwargs):
    if isinstance(source, LocalizedText):
        return tr(source.source, *source.args, **source.kwargs)
    canonical = source_text(source) or source
    template = CATALOG.get(canonical, canonical) if _language == 'en' else canonical
    if canonical == source and source not in CATALOG:
        for original, translated in sorted(CATALOG.items(), key=lambda item:len(item[0]), reverse=True):
            if not original.endswith(': '):
                continue
            if _language == 'en' and source.startswith(original):
                template = translated + source[len(original):]
                break
            if _language == 'ru' and source.startswith(translated):
                template = original + source[len(translated):]
                break
    render = lambda value: tr(value) if isinstance(value, LocalizedText) else value
    text = template.format(*(render(v) for v in args), **{k:render(v) for k,v in kwargs.items()}) if args or kwargs else template
    return LocalizedText(text, source, args, kwargs)


def source_text(value):
    if value in CATALOG:
        return value
    return next((source for source, translated in CATALOG.items() if translated == value), None)
