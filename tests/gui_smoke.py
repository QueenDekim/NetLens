"""Exercise scrolling and full-list clipboard on a real Tk window."""
from pathlib import Path
import sys
import tkinter as tk

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from netlens.gui import Window
from netlens.report import address_lists

root = tk.Tk()
try:
    previous_clipboard = root.clipboard_get()
except tk.TclError:
    previous_clipboard = None
window = Window(root)
report = {'kind': 'discovery', 'root': 'example.com', 'input_domain': 'www.example.com',
          'domains': [{'domain': f'a{i:03}.example.com', 'ips': ['1.1.1.1', '2001:db8::1'],
                       'sources': ['test']} for i in range(300)], 'cname_targets': []}
try:
    root.geometry('850x700')
    window.show_report(report)
    root.update()
    assert window.table_vertical.winfo_ismapped()
    assert window.table_horizontal.winfo_ismapped()
    assert window.tree.yview()[1] < 1
    assert window.tree.xview()[1] < 1
    window.tree.yview_moveto(1)
    window.tree.xview_moveto(1)
    root.update()
    assert window.tree.yview()[0] > 0
    assert window.tree.xview()[0] > 0
    window.copy_addresses('domains')
    assert root.clipboard_get().splitlines() == address_lists(report)['domains']
    assert len(root.clipboard_get().splitlines()) == 300
    window.copy_addresses('ips')
    assert root.clipboard_get().splitlines() == ['1.1.1.1', '2001:db8::1']
    assert window.search_scope.get() == 'Поиск субдоменов: www.example.com → example.com'
    print('GUI SCROLL AND CLIPBOARD PASS')
finally:
    root.clipboard_clear()
    if previous_clipboard is not None:
        root.clipboard_append(previous_clipboard)
    root.update()
    root.destroy()
