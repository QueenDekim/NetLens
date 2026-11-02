import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from netlens.runtime import configure_tk


class PortableTkTests(unittest.TestCase):
    def test_system_interpreter_keeps_existing_tcl_configuration(self):
        with tempfile.TemporaryDirectory() as directory,patch.dict(os.environ,{'TCL_LIBRARY':'system-tcl','TK_LIBRARY':'system-tk'}):
            root=Path(directory)
            self.assertFalse(configure_tk(root,root/'system/python.exe'))
            self.assertEqual(os.environ['TCL_LIBRARY'],'system-tcl')
            self.assertEqual(os.environ['TK_LIBRARY'],'system-tk')

    def test_portable_interpreter_overrides_external_libraries(self):
        with tempfile.TemporaryDirectory() as directory,patch.dict(os.environ,{'TCL_LIBRARY':'external-tcl','TK_LIBRARY':'external-tk'}):
            root=Path(directory);runtime=root/'third-party/python'
            for folder,filename in [('tcl8.6','init.tcl'),('tk8.6','tk.tcl')]:
                target=runtime/'tcl'/folder/filename
                target.parent.mkdir(parents=True);target.touch()
            with patch.dict('sys.modules',{'_tkinter':SimpleNamespace(TCL_VERSION='8.6',TK_VERSION='8.6')}):
                self.assertTrue(configure_tk(root,runtime/'python.exe'))
            self.assertEqual(Path(os.environ['TCL_LIBRARY']),(runtime/'tcl/tcl8.6').resolve())
            self.assertEqual(Path(os.environ['TK_LIBRARY']),(runtime/'tcl/tk8.6').resolve())

    def test_missing_bundle_fails_before_changing_environment(self):
        with tempfile.TemporaryDirectory() as directory,patch.dict(os.environ,{'TCL_LIBRARY':'external-tcl'}):
            root=Path(directory)
            with patch.dict('sys.modules',{'_tkinter':SimpleNamespace(TCL_VERSION='8.6',TK_VERSION='8.6')}):
                with self.assertRaisesRegex(RuntimeError,'Bundled Tcl/Tk'):
                    configure_tk(root,root/'third-party/python/python.exe')
            self.assertEqual(os.environ['TCL_LIBRARY'],'external-tcl')
