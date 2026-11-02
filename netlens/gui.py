from .i18n import tr, LocalizedText, LANGUAGES, language as current_language, preferred_language, set_language, source_text
import datetime
import json
from pathlib import Path
import queue
import threading
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk

from .capture import capture, interfaces
from .ct import PROVIDERS, keys_from_environment
from .discovery import discover
from .report import address_lists, save_report
from .drivers import npcap_status, NPCAP_DOWNLOAD_URL
from .version import build_info
from .runtime import configure_tk


class TextVar(tk.StringVar):
    def __init__(self, *args, value='', **kwargs):
        self.message = value
        super().__init__(*args, value=str(value), **kwargs)

    def set(self, value):
        self.message = value
        super().set(str(value))

    def translate(self):
        super().set(str(tr(self.message)))


def translate_widgets(widget):
    try:
        source = getattr(widget, '_translation_source', None) or source_text(widget.cget('text'))
        if source:
            widget._translation_source = source
            widget.configure(text=tr(source))
    except tk.TclError:
        pass
    if isinstance(widget, ttk.Notebook):
        for tab in widget.tabs():
            source = source_text(widget.tab(tab, 'text'))
            if source:
                widget.tab(tab, text=tr(source))
    if isinstance(widget, ttk.Treeview):
        for column in widget['columns']:
            source = source_text(widget.heading(column, 'text'))
            if source:
                widget.heading(column, text=tr(source))
    if isinstance(widget, (tk.Tk, tk.Toplevel)):
        source = source_text(widget.title())
        if source:
            widget.title(tr(source))
    for child in widget.winfo_children():
        translate_widgets(child)


class Window:
    def __init__(self, root, language=None):
        set_language(language or preferred_language())
        self.root = root
        root.title(tr('NetLens — домены и сеть приложений'))
        root.geometry('1120x780')
        root.minsize(850, 620)
        self.messages = queue.Queue()
        self.cancel = threading.Event()
        self.busy = False
        self.report = None
        outer = ttk.Frame(root, padding=12)
        outer.pack(fill='both', expand=True)
        heading = ttk.Frame(outer)
        heading.pack(fill='x')
        ttk.Label(heading, text='NetLens', font=('Segoe UI', 21, 'bold')).pack(side='left')
        self.language_choice = tk.StringVar(value=LANGUAGES[current_language()])
        self.language_select = ttk.Combobox(heading, textvariable=self.language_choice, values=list(LANGUAGES.values()), state='readonly', width=12)
        self.language_select.pack(side='right')
        ttk.Label(heading, text=tr('Язык')).pack(side='right', padx=8)
        self.language_select.bind('<<ComboboxSelected>>', self.change_language)
        ttk.Label(outer, text=tr('Домены · IPv4 / IPv6 · BGP-подсети · сетевые обращения процессов')).pack(anchor='w', pady=(0, 10))
        notebook = ttk.Notebook(outer)
        notebook.pack(fill='x')
        find = ttk.Frame(notebook, padding=12)
        cap = ttk.Frame(notebook, padding=12)
        notebook.add(find, text=tr('Поиск по домену'))
        notebook.add(cap, text=tr('Захват приложения'))
        self.domain = tk.StringVar(value='example.com')
        self.limit = tk.StringVar(value='200')
        self.related = tk.BooleanVar()
        self.ct = tk.BooleanVar(value=True)
        self.redirects = tk.BooleanVar(value=True)
        self.ct_service = tk.StringVar(value=tr('Авто (ctlogs.dev первым)'))
        self.ct_fallback = tk.BooleanVar(value=True)
        self.api_keys = keys_from_environment()
        self.ct_choices = {tr('Авто (ctlogs.dev первым)'): 'auto', **{v[0]: k for k, v in PROVIDERS.items()}}
        self.networks = tk.BooleanVar(value=True)
        ttk.Label(find, text=tr('Домен')).grid(row=0, column=0, sticky='w')
        ttk.Entry(find, textvariable=self.domain, width=55).grid(row=0, column=1, sticky='ew', padx=8)
        ttk.Label(find, text=tr('Лимит')).grid(row=0, column=2)
        ttk.Entry(find, textvariable=self.limit, width=7).grid(row=0, column=3, padx=8)
        ttk.Checkbutton(find, text=tr('Искать субдомены (Certificate Transparency)'), variable=self.ct).grid(row=1, column=1, sticky='w', pady=6)
        services = ttk.Frame(find)
        services.grid(row=2, column=1, columnspan=3, sticky='w', pady=(0, 6))
        ttk.Label(services, text=tr('CT-сервис:')).pack(side='left')
        self.provider_select = ttk.Combobox(services, textvariable=self.ct_service, values=list(self.ct_choices), state='readonly', width=26)
        self.provider_select.pack(side='left', padx=6)
        ttk.Checkbutton(services, text=tr('Автопереключение'), variable=self.ct_fallback).pack(side='left')
        ttk.Button(services, text=tr('API-ключи…'), command=self.edit_api_keys).pack(side='left', padx=8)
        ttk.Checkbutton(find, text=tr('Разрешать также кандидаты из общих сертификатов'), variable=self.related).grid(row=3, column=1, sticky='w')
        ttk.Checkbutton(find, text=tr('Учитывать редиректы сайта'), variable=self.redirects).grid(row=4, column=1, sticky='w', pady=(6, 0))
        ttk.Button(find, text=tr('Найти домены и IP'), command=self.start_discovery).grid(row=5, column=1, sticky='w', pady=(10, 0))
        self.search_scope = TextVar(value=tr('Субдомены автоматически ищутся от корневого домена.'))
        ttk.Label(find, textvariable=self.search_scope).grid(row=6, column=1, sticky='w', pady=(6, 0))
        find.columnconfigure(1, weight=1)
        self.exe = tk.StringVar()
        self.seconds = tk.StringVar(value='60')
        self.attach = tk.BooleanVar()
        self.children = tk.BooleanVar(value=True)
        ttk.Label(cap, text=tr('Приложение')).grid(row=0, column=0, sticky='w')
        ttk.Entry(cap, textvariable=self.exe).grid(row=0, column=1, sticky='ew', padx=8)
        ttk.Button(cap, text=tr('Выбрать EXE…'), command=self.select_exe).grid(row=0, column=2)
        ttk.Label(cap, text=tr('Интерфейсы\n(Ctrl — несколько)')).grid(row=1, column=0, sticky='nw', pady=8)
        self.interface_list = tk.Listbox(cap, height=4, selectmode='extended', exportselection=False)
        self.interface_list.grid(row=1, column=1, sticky='ew', padx=8, pady=8)
        self.interface_refresh = ttk.Button(cap, text=tr('Обновить'), command=self.refresh_interfaces)
        self.interface_refresh.grid(row=1, column=2)
        controls = ttk.Frame(cap)
        controls.grid(row=2, column=1, sticky='w')
        ttk.Label(controls, text=tr('Секунд:')).pack(side='left')
        ttk.Entry(controls, textvariable=self.seconds, width=7).pack(side='left', padx=6)
        ttk.Checkbutton(controls, text=tr('Дочерние процессы'), variable=self.children).pack(side='left')
        ttk.Checkbutton(controls, text=tr('Подключиться к запущенному'), variable=self.attach).pack(side='left', padx=6)
        self.capture_start = ttk.Button(cap, text=tr('Начать захват'), command=self.start_capture)
        self.capture_start.grid(row=3, column=1, sticky='w', pady=(10, 0))
        ttk.Label(cap, text=tr('Выберите сетевой адаптер с трафиком приложения. При запуске приложение останется открытым после захвата.'), wraplength=850).grid(row=4, column=0, columnspan=3, sticky='w', pady=(8, 0))
        cap.columnconfigure(1, weight=1)
        dependency = ttk.Frame(cap)
        dependency.grid(row=5, column=0, columnspan=3, sticky='ew', pady=(10, 0))
        self.capture_dependency = TextVar()
        ttk.Label(dependency, textvariable=self.capture_dependency, wraplength=650).pack(side='left', fill='x', expand=True)
        self.driver_download = ttk.Button(dependency, text=tr('Скачать Npcap'), command=lambda: webbrowser.open(NPCAP_DOWNLOAD_URL))
        self.driver_download.pack(side='left', padx=8)
        ttk.Button(dependency, text=tr('Проверить установку'), command=self.refresh_interfaces).pack(side='left')
        actions = ttk.Frame(outer)
        actions.pack(fill='x', pady=8)
        ttk.Checkbutton(actions, text=tr('Получать BGP-подсети (RIPEstat)'), variable=self.networks).pack(side='left')
        ttk.Button(actions, text=tr('Копировать домены'), command=lambda: self.copy_addresses('domains')).pack(side='left', padx=(12, 4))
        ttk.Button(actions, text=tr('Копировать IP'), command=lambda: self.copy_addresses('ips')).pack(side='left')
        ttk.Button(actions, text=tr('Остановить'), command=self.cancel.set).pack(side='right')
        ttk.Button(actions, text=tr('Экспортировать…'), command=self.export).pack(side='right', padx=8)
        self.status = TextVar(value=tr('Готово'))
        ttk.Label(outer, textvariable=self.status).pack(anchor='w')
        self.progress = ttk.Progressbar(outer, mode='indeterminate')
        self.progress.pack(fill='x', pady=5)
        results = ttk.Notebook(outer)
        results.pack(fill='both', expand=True)
        table = ttk.Frame(results)
        table.rowconfigure(0, weight=1)
        table.columnconfigure(0, weight=1)
        self.tree = ttk.Treeview(table, columns=('domain', 'ip', 'port', 'evidence'), show='headings')
        self.tree.grid(row=0, column=0, sticky='nsew')
        self.table_vertical = ttk.Scrollbar(table, orient='vertical', command=self.tree.yview)
        self.table_vertical.grid(row=0, column=1, sticky='ns')
        self.table_horizontal = ttk.Scrollbar(table, orient='horizontal', command=self.tree.xview)
        self.table_horizontal.grid(row=1, column=0, sticky='ew')
        self.tree.configure(yscrollcommand=self.table_vertical.set, xscrollcommand=self.table_horizontal.set)
        for col, title, width in [('domain', tr('Домен / имя'), 280), ('ip', 'IP', 220), ('port', tr('Порт / транспорт'), 110), ('evidence', tr('Источник / достоверность'), 300)]:
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, minwidth=width, stretch=False)
        results.add(table, text=tr('Адреса'))
        self.details = tk.Text(results, wrap='word', font=('Consolas', 10))
        results.add(self.details, text=tr('Полный отчёт / подсети'))
        self.log = tk.Text(results, wrap='word', height=8)
        results.add(self.log, text=tr('Журнал'))
        footer = ttk.Frame(outer)
        footer.pack(fill='x', pady=(8, 0))
        self.version_info = build_info()
        version = ttk.Label(footer, text=self.version_info['version'], cursor='hand2', takefocus=True, foreground='#315cca', font=('Segoe UI', 9, 'underline'))
        version.pack(side='left')
        for event in ['<Button-1>', '<Return>', '<space>']:
            version.bind(event, lambda _event: webbrowser.open(self.version_info['url']))
        root.protocol('WM_DELETE_WINDOW', self.close)
        root.after(100, self.pump)
        self.refresh_interfaces()

    def change_language(self, _event=None):
        provider = self.ct_choices.get(self.ct_service.get(), 'auto')
        selected = next(code for code, label in LANGUAGES.items() if label == self.language_choice.get())
        set_language(selected, persist=True)
        self.ct_choices = {tr('Авто (ctlogs.dev первым)'):'auto', **{value[0]:key for key,value in PROVIDERS.items()}}
        self.provider_select.configure(values=list(self.ct_choices))
        self.ct_service.set(next(label for label, key in self.ct_choices.items() if key == provider))
        translate_widgets(self.root)
        for variable in [self.status, self.search_scope, self.capture_dependency]:
            variable.translate()

    def edit_api_keys(self):
        dialog = tk.Toplevel(self.root)
        dialog.title(tr('API-ключи CT-сервисов'))
        dialog.transient(self.root)
        frame = ttk.Frame(dialog, padding=16)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text=tr('Ключи хранятся только до закрытия NetLens.\nДля постоянной настройки используйте переменные окружения.')).grid(row=0, column=0, columnspan=2, sticky='w', pady=(0, 12))
        variables = {}
        for row, (name, (label, env, required)) in enumerate(PROVIDERS.items(), 1):
            ttk.Label(frame, text=label + (tr(' (нужен ключ)') if required else tr(' (необязательно)'))).grid(row=row*2-1, column=0, sticky='w', padx=(0, 12))
            var = variables[name] = tk.StringVar(value=self.api_keys.get(name, ''))
            ttk.Entry(frame, textvariable=var, show='*', width=48).grid(row=row*2-1, column=1, sticky='ew')
            ttk.Label(frame, text=env).grid(row=row*2, column=1, sticky='w', pady=(0, 8))
        def save():
            self.api_keys = {name: var.get().strip() for name, var in variables.items()}
            dialog.destroy()
        ttk.Button(frame, text=tr('Применить'), command=save).grid(row=11, column=1, sticky='e', pady=(8, 0))
        dialog.grab_set()

    def select_exe(self):
        value = filedialog.askopenfilename(filetypes=[(tr('Приложение Windows'), '*.exe')])
        if value:
            self.exe.set(value)

    def refresh_interfaces(self):
        if not self.update_capture_dependency():
            return
        def work():
            try:
                self.messages.put(('interfaces', interfaces()))
            except Exception as exc:
                self.messages.put(('log', str(exc)))
        threading.Thread(target=work, daemon=True).start()

    def update_capture_dependency(self):
        status = npcap_status()
        self.capture_dependency.set(status.message)
        self.capture_start.state(['!disabled'] if status.available else ['disabled'])
        self.interface_refresh.state(['!disabled'] if status.available else ['disabled'])
        self.interface_list.configure(state='normal' if status.available else 'disabled')
        if status.available:
            self.driver_download.pack_forget()
        else:
            self.driver_download.pack(side='left', padx=8)
        return status.available

    def start(self, work):
        if self.busy:
            messagebox.showinfo('NetLens', tr('Дождитесь завершения текущей задачи или остановите её.'))
            return
        self.busy = True
        self.cancel.clear()
        self.progress.start()
        self.status.set(tr('Выполняется…'))
        def run():
            try:
                report = work()
                destination = Path(__file__).resolve().parent.parent / 'reports' / datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
                save_report(report, destination)
                self.messages.put(('log', tr('Отчёт сохранён: {0}', destination)))
                self.messages.put(('report', report))
            except Exception as exc:
                self.messages.put(('error', str(exc)))
            finally:
                self.messages.put(('done', None))
        threading.Thread(target=run, daemon=True).start()

    def start_discovery(self):
        try:
            values = (self.domain.get(), int(self.limit.get()), self.related.get(), self.ct.get(), self.networks.get())
            service, fallback, keys = self.ct_choices[self.ct_service.get()], self.ct_fallback.get(), dict(self.api_keys)
            redirects = self.redirects.get()
            self.start(lambda: discover(*values, log=self.emit_log, cancel=self.cancel,
                                       ct_provider=service, ct_fallback=fallback, api_keys=keys,
                                       follow_redirects=redirects))
        except ValueError as exc:
            messagebox.showerror(tr('Ошибка'), str(exc))

    def start_capture(self):
        if not self.update_capture_dependency():
            return
        try:
            ids = [self.interface_list.get(i).split('.', 1)[0] for i in self.interface_list.curselection()]
            values = (self.exe.get(), ids, int(self.seconds.get()))
            children, attach, networks = self.children.get(), self.attach.get(), self.networks.get()
            self.start(lambda: capture(*values, include_children=children, attach=attach, networks=networks,
                                       log=self.emit_log, cancel=self.cancel))
        except ValueError as exc:
            messagebox.showerror(tr('Ошибка'), str(exc))

    def emit_log(self, message):
        self.messages.put(('log', message))

    def pump(self):
        try:
            while True:
                kind, value = self.messages.get_nowait()
                if kind == 'interfaces':
                    self.interface_list.delete(0, 'end')
                    for line in value:
                        self.interface_list.insert('end', line)
                elif kind == 'log':
                    self.log.insert('end', value + '\n')
                    self.log.see('end')
                    self.status.set(value)
                elif kind == 'error':
                    self.log.insert('end', value + '\n')
                    messagebox.showerror('NetLens', value)
                elif kind == 'done':
                    self.busy = False
                    self.progress.stop()
                    self.status.set(tr('Задача завершена. Результат и предупреждения — в полном отчёте.'))
                elif kind == 'report':
                    self.show_report(value)
        except queue.Empty:
            pass
        self.root.after(100, self.pump)

    def show_report(self, report):
        self.report = report
        self.tree.delete(*self.tree.get_children())
        if report['kind'] == 'discovery':
            self.search_scope.set(tr('Поиск субдоменов: {0} → {1}', report.get('input_domain', report['root']), report['root']))
            for item in report['domains'] + report.get('cname_targets', []):
                self.tree.insert('', 'end', values=(item['domain'], ', '.join(item['ips']), '', ', '.join(item['sources'])))
            for ip in report.get('redirects', {}).get('ips', []):
                self.tree.insert('', 'end', values=('', ip, '', 'http_redirect'))
        else:
            for item in report['endpoints']:
                self.tree.insert('', 'end', values=(', '.join(n['name'] for n in item['hostnames']), item['ip'],
                    f"{item['port']} / {item['transport']}", ', '.join(item['evidence'])))
        self.details.delete('1.0', 'end')
        self.details.insert('end', json.dumps(report, ensure_ascii=False, indent=2))

    def copy_addresses(self, kind):
        if self.report is None:
            messagebox.showinfo('NetLens', tr('Сначала выполните поиск или захват.'))
            return
        values = address_lists(self.report)[kind]
        if not values:
            self.status.set(tr('Список пуст. Буфер обмена не изменён.'))
            return
        self.root.clipboard_clear()
        self.root.clipboard_append('\n'.join(values))
        label = tr('доменов') if kind == 'domains' else tr('IP-адресов')
        self.status.set(tr('Скопировано {0}: {1}', label, len(values)))

    def export(self):
        if self.report is None:
            messagebox.showinfo('NetLens', tr('Сначала выполните поиск или захват.'))
            return
        directory = filedialog.askdirectory()
        if directory:
            try:
                save_report(self.report, directory)
                self.status.set(tr('Экспортировано: {0}', directory))
            except OSError as exc:
                messagebox.showerror(tr('Ошибка экспорта'), str(exc))

    def close(self):
        self.cancel.set()
        if self.busy:
            self.status.set(tr('Остановка и сохранение отчёта перед закрытием…'))
            self.root.after(200, self.close)
        else:
            self.root.destroy()


def run(language=None):
    configure_tk()
    root = tk.Tk()
    if 'vista' in ttk.Style().theme_names():
        ttk.Style().theme_use('vista')
    Window(root, language=language)
    root.mainloop()
