"""Select bundled Tcl/Tk before creating a window with the portable interpreter."""
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]


def configure_tk(root=ROOT, executable=None):
    runtime=Path(root)/'third-party/python'
    if Path(executable or sys.executable).resolve().parent!=runtime.resolve():
        return False
    import _tkinter
    libraries={'TCL_LIBRARY':runtime/('tcl/tcl'+_tkinter.TCL_VERSION),
               'TK_LIBRARY':runtime/('tcl/tk'+_tkinter.TK_VERSION)}
    for variable,filename in [('TCL_LIBRARY','init.tcl'),('TK_LIBRARY','tk.tcl')]:
        if not (libraries[variable]/filename).is_file():
            raise RuntimeError('Bundled Tcl/Tk libraries are missing')
    for variable,directory in libraries.items():
        os.environ[variable]=str(directory.resolve())
    return True
