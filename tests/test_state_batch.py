import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'module_utils'))
import software_core as c


class StateBatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.cache = self.root / 'cache'
        self.cache.mkdir()
        self.dest = r'C:\Apps'
        self.db = c.normalize_state({})
        self.pattern = {'id': 'app', 'mode': 'exe', 'regex': r'app-.*\.exe$'}

    def artifact(self, name, content):
        path = self.source / name
        path.write_bytes(content)
        return path

    def plan(self, db=None, patterns=None, snapshot=None):
        return c.make_plan(c.merge([{'patterns': patterns or [self.pattern]}], self.dest),
                           c.index(self.source), str(self.source), snapshot or {'installed': []},
                           db if db is not None else self.db, self.dest, str(self.cache))

    def commit(self, op):
        verified = c.verify_package(op, {}, {'changed': True, 'rc': 0})
        return c.transition(self.db, op, 'done', op['files'], verified=dict(verified, installer_changed=True))

    def test_matrix(self):
        path = self.artifact('app-1.0.exe', b'a')
        db = self.commit(self.plan()['operations'][0])
        self.assertFalse(self.plan(db)['operations'])
        self.assertFalse(self.plan(db)['warnings'])
        renamed = path.rename(self.source / 'app-2.0.exe')
        result = self.plan(db)
        self.assertFalse(result['operations'])
        self.assertEqual(result['warnings'][0]['action'], 'skip')
        renamed.rename(path)
        path.write_bytes(b'b')
        result = self.plan(db)
        self.assertEqual(result['operations'][0]['action'], 'upgrade')
        self.assertEqual(result['warnings'][0]['status'], 'warning')
        path.rename(self.source / 'app-3.0.exe')
        result = self.plan(db)
        self.assertEqual(result['operations'][0]['action'], 'upgrade')
        self.assertFalse(result['warnings'])

    def test_unknown_version_and_missing_fields(self):
        path = self.artifact('app-latest.exe', b'a')
        op = self.plan()['operations'][0]
        self.assertIsNone(op['artifact']['version'])
        db = self.commit(op)
        self.assertFalse(self.plan(db)['operations'])
        for fields in (('artifact_version', 'version'), ('artifact_checksum', 'checksum')):
            incomplete = {'schema_version': 2, 'products': {'app': dict(db['products']['app'])}}
            for field in fields:
                incomplete['products']['app'].pop(field)
            self.assertEqual(self.plan(incomplete)['operations'][0]['action'], 'install')
        path.write_bytes(b'b')
        result = self.plan(db)
        self.assertEqual(result['operations'][0]['action'], 'upgrade')
        self.assertEqual(result['warnings'][0]['status'], 'warning')

    def test_pending_requires_actual_success_receipt(self):
        self.artifact('app-1.0.exe', b'a')
        op = self.plan()['operations'][0]
        for changed in (False, True):
            db = c.transition(self.db, op, 'post', [], verified={'installer_changed': changed})
            self.assertEqual(self.plan(db)['operations'][0]['action'], 'recover' if changed else 'install')
        db = c.transition(self.db, op, 'pending', [])
        self.assertEqual(self.plan(db)['operations'][0]['action'], 'install')

    def test_batch_only_planned_and_reused_across_hosts(self):
        a = self.artifact('app-1.0.exe', b'a')
        b = self.artifact('second-2.0.exe', b'b')
        self.artifact('unmanaged.exe', b'c')
        patterns = [self.pattern, {'id': 'second', 'mode': 'exe', 'regex': r'second-.*\.exe$'}]
        ops = self.plan(patterns=patterns)['operations']
        with patch.object(c.shutil, 'copyfile', wraps=c.shutil.copyfile) as copy:
            first = c.stage_packages(ops, str(self.source), self.dest, str(self.cache))
            second = c.stage_packages(ops, str(self.source), self.dest, str(self.cache))
            self.assertEqual(copy.call_count, 2)
        for batch in (first, second):
            self.assertEqual(len(batch['paths']), 2)
            self.assertEqual({f.name for f in Path(batch['directory']).rglob('*') if f.is_file()}, {a.name, b.name})
        db = self.commit(ops[0])
        updated = self.plan(db, patterns)['operations']
        only = c.stage_packages(updated, str(self.source), self.dest, str(self.cache))
        self.assertEqual(len(only['paths']), 1)
        self.assertEqual({f.name for f in Path(only['directory']).rglob('*') if f.is_file()}, {b.name})

    def test_changed_source_rejected_in_batch(self):
        path = self.artifact('app-1.0.exe', b'a')
        ops = self.plan()['operations']
        path.write_bytes(b'changed')
        with self.assertRaises(c.SoftwareError):
            c.stage_packages(ops, str(self.source), self.dest, str(self.cache))
        self.assertFalse(list(self.cache.glob('packages-*')))

    def test_file_batch_preserves_relative_paths_and_filters_current(self):
        a = self.artifact('a.bin', b'a')
        b = self.artifact('b.bin', b'b')
        files = [{'path': c.target(self.dest, 'a.bin'), 'source': str(a), 'checksum': c.sha(a)},
                 {'path': c.target(self.dest, 'bin/b.bin'), 'source': str(b), 'checksum': c.sha(b)}]
        staged = c.stage_files(files, self.dest, str(self.cache), {files[0]['path']: files[0]['checksum']})
        self.assertEqual(staged['count'], 1)
        self.assertEqual((Path(staged['directory']) / 'bin/b.bin').read_bytes(), b'b')
        self.assertFalse((Path(staged['directory']) / 'a.bin').exists())
        with self.assertRaises(c.SoftwareError):
            c.stage_files([dict(files[0], path=r'C:\Windows\a.bin')], self.dest, str(self.cache))

    def test_archive_shared_extraction_and_state_skip(self):
        path = self.source / 'bundle-1.0.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('bin/a', b'a')
        pattern = {'id': 'arc', 'mode': 'arc', 'regex': r'\.zip$', 'name': 'Arc'}
        op = self.plan(patterns=[pattern])['operations'][0]
        with patch.object(c, 'archive_members', wraps=c.archive_members) as extract:
            first = c.prepare(op, str(self.source), str(self.cache))
            second = c.prepare(op, str(self.source), str(self.cache))
            self.assertEqual(extract.call_count, 1)
        self.assertEqual(first, second)
        db = c.transition(self.db, op, 'done', first['files'])
        self.assertFalse(self.plan(db, [pattern])['operations'])

    def test_file_plan_and_verify_on_controller(self):
        a = self.artifact('a.bin', b'a')
        file_pattern = {'id': 'file', 'mode': 'files', 'files': ['a.bin'], 'template': False}
        op = self.plan(patterns=[file_pattern])['operations'][0]
        f = op['files'][0]
        actual = {f['path']: f['checksum']}
        self.assertEqual(c.plan_files(op, op['files'], actual)['action'], 'adopt')
        self.assertTrue(c.verify_files(op, op['files'], actual)['verified'])
        self.assertEqual(c.plan_files(op, op['files'], {f['path']: None})['action'], 'update_files')
        with self.assertRaises(c.SoftwareError):
            c.verify_files(op, op['files'], {f['path']: None})
        with self.assertRaises(c.SoftwareError):
            c.plan_files(op, op['files'], {})
        db = c.transition(self.db, op, 'done', op['files'])
        current = self.plan(db, [file_pattern])['operations'][0]
        self.assertEqual(c.plan_files(current, current['files'], actual)['action'], 'skip')
        remove = self.plan(db, [dict(file_pattern, state='absent')])['operations'][0]
        self.assertEqual(c.plan_files(remove, [], actual)['action'], 'update_files')
        with self.assertRaises(c.SoftwareError):
            c.plan_files(remove, [], {f['path']: 'b' * 64})
        with self.assertRaises(c.SoftwareError):
            c.verify_files(remove, [], actual)
        self.assertTrue(c.verify_files(remove, [], {f['path']: None})['verified'])

    def test_check_and_batch_failure_fallback_wiring(self):
        windows = yaml.safe_load((ROOT / 'task_windows.yaml').read_text())
        copy = next(t for t in windows if 'ansible.windows.win_copy' in t)
        self.assertIn('not ansible_check_mode', copy['when'])
        self.assertTrue(copy['ignore_errors'])
        self.assertNotIn('loop', copy)
        prep = yaml.safe_load((ROOT / 'task_package_prepare.yaml').read_text())
        fallback = next(t for t in prep if 'ansible.windows.win_copy' in t)
        self.assertIn('software_batch_copy is failed', fallback['when'])
        self.assertIn('software_batch_copy is skipped', fallback['when'])
        pkg = yaml.safe_load((ROOT / 'task_package.yaml').read_text())
        retry = next(t for t in pkg if 'ansible.windows.win_command' in t)
        self.assertIn('timeout', retry)
        self.assertEqual(retry['retries'], 2)
        self.assertNotIn('async', retry)
        self.assertIn('not (software_pkg_install.changed | default(false))', retry['when'])


if __name__ == '__main__':
    unittest.main()
