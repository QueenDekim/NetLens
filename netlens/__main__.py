from .i18n import tr, set_language, preferred_language, LANGUAGES, language
from .version import build_info
import argparse
import datetime
import json
import threading
import sys

from .capture import capture, interfaces
from .ct import PROVIDERS
from .discovery import discover
from .report import save_report


def main():
    preferences = argparse.ArgumentParser(add_help=False)
    preferences.add_argument('--language', choices=list(LANGUAGES))
    selected, _ = preferences.parse_known_args()
    set_language(selected.language or preferred_language())
    parser = argparse.ArgumentParser(description=tr('NetLens: домены, IP, подсети и сеть Windows-приложений'), parents=[preferences])
    parser.add_argument('--version', action='version', version=build_info()['version'])
    commands = parser.add_subparsers(dest='command')
    commands.add_parser('gui')
    commands.add_parser('interfaces')
    find = commands.add_parser('discover')
    find.add_argument('domain')
    find.add_argument('--limit', type=int, default=200)
    find.add_argument('--include-related', action='store_true')
    find.add_argument('--no-ct', action='store_true')
    find.add_argument('--no-networks', action='store_true')
    find.add_argument('--no-redirects', action='store_true', help=tr('Не проверять HTTP/HTML-редиректы'))
    find.add_argument('--ct-provider', choices=['auto', *PROVIDERS], default='auto', help=tr('Первый CT-сервис (по умолчанию auto)'))
    find.add_argument('--no-ct-fallback', action='store_true', help=tr('Отключить автоматическое переключение CT-сервисов'))
    find.add_argument('--output')
    cap = commands.add_parser('capture')
    cap.add_argument('--exe', required=True)
    cap.add_argument('-i', '--interface', action='append', required=True)
    cap.add_argument('--seconds', type=int, default=60)
    cap.add_argument('--attach', action='store_true')
    cap.add_argument('--no-children', action='store_true')
    cap.add_argument('--no-networks', action='store_true')
    cap.add_argument('--output')
    cap.add_argument('args', nargs=argparse.REMAINDER, help=tr('Аргументы приложения после --'))
    options = parser.parse_args()
    if options.command in (None, 'gui'):
        from .gui import run
        run(language=language())
        return
    try:
        if options.command == 'interfaces':
            print('\n'.join(interfaces()))
            return
        stop = threading.Event()
        import signal
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        log = lambda message: print(message, file=sys.stderr, flush=True)
        if options.command == 'discover':
            report = discover(options.domain, options.limit, options.include_related, not options.no_ct,
                              not options.no_networks, log, stop, ct_provider=options.ct_provider,
                              ct_fallback=not options.no_ct_fallback,
                              follow_redirects=not options.no_redirects)
        else:
            args = options.args[1:] if options.args[:1] == ['--'] else options.args
            report = capture(options.exe, options.interface, options.seconds, args,
                             not options.no_children, options.attach, not options.no_networks,
                             log=log, cancel=stop)
        destination = options.output or 'reports/' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
        print(save_report(report, destination).resolve())
        print(json.dumps({'warnings': report['warnings']}, ensure_ascii=False))
    except Exception as exc:
        print(tr('Ошибка: {0}', exc), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
