import ast
import json
from pathlib import Path
import tempfile
from string import Formatter
import unittest
from unittest.mock import patch,Mock

from netlens import i18n
from netlens.gui import Window
from netlens.version import build_info,git_revision

ROOT=Path(__file__).resolve().parents[1]


class LocalizationTests(unittest.TestCase):
    def tearDown(self):
        i18n.set_language('ru')

    def test_catalog_covers_application_messages_and_keeps_arguments(self):
        catalog=i18n.CATALOG
        for path in (ROOT/'netlens').glob('*.py'):
            tree=ast.parse(path.read_text(encoding='utf-8'))
            for node in ast.walk(tree):
                if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='tr' and node.args and isinstance(node.args[0],ast.Constant):
                    source=node.args[0].value
                    self.assertIn(source,catalog,(path.name,source))
        for source,target in catalog.items():
            self.assertTrue(target,source)
            fields=lambda value:sorted(name for _,name,_,_ in Formatter().parse(value) if name is not None)
            self.assertEqual(fields(source),fields(target),source)

    def test_switch_translates_dynamic_messages_and_preserves_user_values(self):
        original=i18n.tr('Отчёт сохранён: {0}','Пользовательский путь')
        i18n.set_language('en')
        self.assertEqual(i18n.tr(original),'Report saved: Пользовательский путь')
        self.assertEqual(i18n.tr('Захват: {0:.0f} с; процессов {1}; адресов {2}',12.4,2,5),'Capture: 12 s; 2 processes; 5 addresses')
        i18n.set_language('ru')
        self.assertEqual(i18n.tr(original),'Отчёт сохранён: Пользовательский путь')

    def test_preference_roundtrip_does_not_write_provider_keys(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(i18n,'ROOT',Path(directory)),patch.dict('os.environ',{'NETLENS_LANGUAGE':''}):
            i18n.set_language('en',persist=True)
            self.assertEqual(i18n.preferred_language(),'en')
            self.assertEqual(json.loads((Path(directory)/'preferences.json').read_text()),{'language':'en'})

    def test_language_change_preserves_provider_inputs_and_running_job(self):
        window=Window.__new__(Window)
        window.ct_choices={'SSLBoard':'sslboard'};window.ct_service=Mock(get=lambda:'SSLBoard')
        window.language_choice=Mock(get=lambda:'English');window.provider_select=Mock();window.root=Mock()
        window.status=Mock();window.search_scope=Mock();window.capture_dependency=Mock()
        window.busy=True;window.cancel=Mock()
        with patch('netlens.gui.translate_widgets'),patch('netlens.gui.set_language',side_effect=lambda value,persist:i18n.set_language(value)):
            window.change_language()
        window.ct_service.set.assert_called_with('SSLBoard')
        self.assertTrue(window.busy);window.cancel.set.assert_not_called()

    def test_version_uses_this_repository_and_short_commit(self):
        info=build_info(revision='a'*40)
        self.assertEqual(info['version'],'1.0-aaaaaaa')
        self.assertEqual(info['url'],'https://github.com/QueenDekim/NetLens/tree/1.0-aaaaaaa')
        with self.assertRaises(ValueError):build_info(revision='unsafe/ref')

    def test_git_metadata_supports_detached_head_and_submodule_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);git=root/'metadata';git.mkdir();worktree=root/'project';worktree.mkdir()
            (worktree/'.git').write_text('gitdir: ../metadata\n')
            (git/'HEAD').write_text('b'*40+'\n')
            self.assertEqual(git_revision(worktree),'b'*40)
            (git/'HEAD').write_text('ref: refs/heads/main\n')
            (git/'packed-refs').write_text('c'*40+' refs/heads/main\n')
            self.assertEqual(git_revision(worktree),'c'*40)
            shared=root/'common';shared.mkdir()
            (git/'commondir').write_text('../common\n')
            (shared/'packed-refs').write_text('d'*40+' refs/heads/main\n')
            self.assertEqual(git_revision(worktree),'d'*40)
