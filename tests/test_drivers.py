from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from netlens.drivers import DriverStatus, npcap_status
from netlens.gui import Window


class DriverTests(unittest.TestCase):
    @patch('netlens.drivers.WINDOWS', True)
    @patch('netlens.drivers.Path.is_file', return_value=False)
    def test_missing_driver_does_not_query_or_change_services(self, exists):
        with patch('netlens.drivers.subprocess.run') as run:
            self.assertFalse(npcap_status().available)
            run.assert_not_called()

    def window(self):
        window = Window.__new__(Window)
        for key in ['capture_dependency', 'capture_start', 'interface_refresh', 'interface_list', 'driver_download', 'start']:
            setattr(window, key, Mock())
        return window

    @patch('netlens.gui.npcap_status', return_value=DriverStatus(False, 'Install Npcap'))
    def test_capture_is_blocked_before_reading_inputs_or_starting_work(self, probe):
        window = self.window()
        window.start_capture()
        window.start.assert_not_called()
        window.capture_start.state.assert_called_with(['disabled'])
        window.interface_refresh.state.assert_called_with(['disabled'])
        window.driver_download.pack.assert_called_once()

    @patch('netlens.gui.npcap_status', return_value=DriverStatus(True, 'Ready'))
    def test_recheck_enables_capture_and_hides_download(self, probe):
        window = self.window()
        self.assertTrue(window.update_capture_dependency())
        window.capture_start.state.assert_called_with(['!disabled'])
        window.driver_download.pack_forget.assert_called_once()

    @patch('netlens.gui.npcap_status', return_value=DriverStatus(False, 'Install Npcap'))
    @patch('netlens.gui.discover', return_value={'kind': 'discovery'})
    def test_domain_discovery_does_not_depend_on_capture_driver(self, discover, probe):
        window = self.window()
        for key, value in {'domain':'example.com', 'limit':'50', 'related':False, 'ct':True,
                           'networks':True, 'redirects':True, 'ct_service':'Auto', 'ct_fallback':True}.items():
            setattr(window,key,Mock(get=lambda value=value:value))
        window.ct_choices={'Auto':'auto'};window.api_keys={};window.cancel=Mock()
        window.start_discovery()
        probe.assert_not_called()
        window.start.assert_called_once()
        window.start.call_args.args[0]()
        discover.assert_called_once()
