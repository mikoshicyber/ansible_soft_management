import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'module_utils'))
import software_core as c


class NativeDetectionTests(unittest.TestCase):
    old_code = '{00000001-1111-2222-3333-444444444444}'
    new_code = '{00000002-1111-2222-3333-444444444444}'
    family = '{00000003-1111-2222-3333-444444444444}'

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

    def artifact(self, filename, content):
        path = self.source / filename
        path.write_bytes(content)
        return str(path), c.sha(path)

    def msi(self, code=None, version='2.0.0', **extra):
        return dict(product_id=code or self.new_code, upgrade_code=self.family, version=version,
                    name='App', publisher='Vendor', language='1033', platform='x64', **extra)

    def app(self, code=None, version='1.0.0', **extra):
        return dict(product_id=code or self.old_code, version=version, name='App', publisher='Vendor',
                    provider='msi', language='1033', platform='x64', **extra)

    def snapshot(self, metadata, apps=(), related=None, states=None):
        return {'msi_metadata': metadata, 'installed': list(apps), 'probes': {},
                'msi_related': {self.family.casefold(): related if related is not None else [x['product_id'] for x in apps]},
                'msi_states': states if states is not None else dict({self.new_code.casefold(): -1, self.old_code.casefold(): -1}, **{x['product_id'].casefold(): 5 for x in apps})}

    def pattern(self, **extra):
        return dict({'id': 'app', 'regex': r'\.msi$', 'mode': 'msi'}, **extra)

    def plan(self, snapshot, db=None, pattern=None):
        return c.make_plan(c.merge([{'patterns': [pattern or self.pattern()]}], self.dest), c.index(self.source),
                           str(self.source), snapshot, db or self.db, self.dest, str(self.cache))

    def test_msi_metadata_overrides_filename_and_selects_highest(self):
        _, one = self.artifact('app-99.0.msi', b'one')
        path, two = self.artifact('app-1.0.msi', b'two')
        snapshot = self.snapshot({one: self.msi(self.old_code, '1.0.0'), two: self.msi()})
        op = self.plan(snapshot)['operations'][0]
        self.assertEqual((op['artifact']['source'], op['artifact']['version'], op['action']), (path, '2.0.0', 'install'))
        self.assertEqual(op['verification'], 'installer_result')

    def test_msi_state_authority(self):
        _, checksum = self.artifact('app.msi', b'new')
        metadata = {checksum: self.msi()}
        for app in (self.app(), self.app(version='3.0.0')):
            self.assertEqual(self.plan(self.snapshot(metadata, [app]))['operations'][0]['action'], 'install')
        db = {'schema_version': 2, 'products': {'app': {'status': 'installed', 'version': '3.0.0', 'checksum': 'a' * 64}}}
        self.assertEqual(self.plan(self.snapshot(metadata), db)['operations'][0]['action'], 'upgrade')

    def test_msi_equal_version_requires_state_and_receipt(self):
        _, checksum = self.artifact('app.msi', b'new')
        metadata = {checksum: self.msi()}
        snapshot = self.snapshot(metadata, [self.app(self.new_code, '2.0.0')])
        op = self.plan(snapshot)['operations'][0]
        self.assertEqual(op['action'], 'install')
        details = c.verify_package(op, snapshot, {'changed': True, 'rc': 0})
        db = c.transition(self.db, op, 'done', [], verified=dict(details, installer_changed=True))
        self.assertEqual(db['products']['app']['artifact_version'], '2.0.0')
        self.assertEqual(db['products']['app']['applied_checksum'], checksum)
        self.assertIsNone(db['products']['app']['installed_version'])
        self.assertFalse(self.plan(self.snapshot(metadata), db)['operations'])

    def test_msi_same_code_update_is_planned(self):
        _, checksum = self.artifact('app.msi', b'new')
        db = {'schema_version': 2, 'products': {'app': {'status': 'installed', 'version': '2.0.0', 'checksum': 'a' * 64}}}
        result = self.plan(self.snapshot({checksum: self.msi()}, [self.app(self.new_code)]), db)
        op = result['operations'][0]
        self.assertEqual(op['action'], 'upgrade')
        self.assertIn('REINSTALL=ALL REINSTALLMODE=vomus', op['msi_reinstall_command'])
        self.assertEqual(result['warnings'][0]['status'], 'warning')

    def test_msi_missing_and_conflicting_metadata(self):
        _, one = self.artifact('app.msi', b'one')
        self.assertIn('metadata unavailable', self.plan(self.snapshot({}))['blocked'][0]['reason'])
        _, two = self.artifact('other.msi', b'two')
        other = dict(self.msi(self.old_code, '1.0.0'), platform='Intel')
        self.assertIn('different product families', self.plan(self.snapshot({one: self.msi(), two: other}))['blocked'][0]['reason'])

    def test_msi_ambiguous_related_and_bad_state_on_removal(self):
        _, checksum = self.artifact('app.msi', b'new')
        metadata = {checksum: self.msi()}
        db = {'schema_version': 2, 'products': {'app': {'status': 'installer_reported', 'msi_metadata': self.msi()}}}
        absent = self.pattern(state='absent')
        result = self.plan(self.snapshot(metadata, [self.app(), self.app(self.new_code, '2.0.0')]), db, absent)
        self.assertIn('Multiple installed products', result['blocked'][0]['reason'])
        result = self.plan(self.snapshot(metadata, states={self.new_code.casefold(): 2}), db, absent)
        self.assertIn('different user', result['blocked'][0]['reason'])
        result = self.plan(self.snapshot(metadata, [self.app()], states={self.old_code.casefold(): 5}), db, absent)
        self.assertIn('state unavailable', result['blocked'][0]['reason'])

    def test_msi_verify_receipt(self):
        _, checksum = self.artifact('app.msi', b'new')
        metadata = {checksum: self.msi()}
        op = self.plan(self.snapshot(metadata, [self.app()]))['operations'][0]
        with self.assertRaises(c.SoftwareError):
            c.verify_package(op, self.snapshot(metadata, [self.app(version='2.0.0')]))
        with self.assertRaises(c.SoftwareError):
            c.verify_package(op, self.snapshot(metadata), {'changed': True, 'rc': 1603})
        details = c.verify_package(op, self.snapshot(metadata), {'changed': True, 'rc': 0})
        db = c.transition(self.db, op, 'done', [], verified=dict(details, installer_changed=True))
        self.assertEqual(db['products']['app']['applied_checksum'], checksum)
        self.assertEqual(db['products']['app']['verification'], 'installer_result')
        self.assertEqual(db['products']['app']['msi_metadata'], self.msi())

    def test_msi_removal_uses_confirmed_metadata_without_installer(self):
        path, checksum = self.artifact('app.msi', b'new')
        metadata = {checksum: self.msi()}
        snap = self.snapshot(metadata, [self.app(self.new_code, '2.0.0')])
        op = self.plan(snap)['operations'][0]
        db = c.transition(self.db, op, 'done', [], verified=c.verify_package(op, snap, {'changed': True, 'rc': 0}))
        os.unlink(path)
        remove = self.plan(snap, db, self.pattern(state='absent'))['operations'][0]
        self.assertEqual(remove['action'], 'remove')
        self.assertEqual(remove['installed']['product_id'], self.new_code)
        c.verify_package(remove, self.snapshot(metadata))
        self.assertIn('Removal requires', self.plan(snap, pattern=self.pattern(state='absent'))['blocked'][0]['reason'])

    def test_local_metadata_shared_cache_and_legacy_state(self):
        path, checksum = self.artifact('app.msi', b'new')
        patterns = c.merge([{'patterns': [self.pattern()]}], self.dest)
        args = (patterns, [path], str(self.source))
        metadata = {checksum: self.msi()}
        old = dict(self.db, msi_metadata_cache=metadata)
        self.assertEqual(c.normalize_state(json.dumps(old)), old)
        with patch.object(c, 'read_msi_metadata', return_value=self.msi()) as reader:
            first = c.discover_msi(*args, self.db, str(self.cache))
            second = c.discover_msi(*args, old, str(self.cache))
            self.assertEqual(first['metadata'], metadata)
            self.assertEqual(first, second)
            reader.assert_called_once_with(path)
        with self.assertRaises(c.SoftwareError):
            c.normalize_state(dict(self.db, msi_metadata_cache={'x': self.msi()}))

    def test_sha_cache_uses_stat_fingerprint(self):
        path, checksum = self.artifact('app.msi', b'new')
        with patch.object(c, 'sha', wraps=c.sha) as sha:
            self.assertEqual(c.cached_sha(path, self.cache), checksum)
            self.assertEqual(c.cached_sha(path, self.cache), checksum)
            self.assertEqual(sha.call_count, 1)
            Path(path).write_bytes(b'changed')
            self.assertNotEqual(c.cached_sha(path, self.cache), checksum)
            self.assertEqual(sha.call_count, 2)

    def test_exe_learning_requires_corroboration_and_unique_change(self):
        path, checksum = self.artifact('app-2.0.exe', b'exe')
        p = {'id': 'exe', 'regex': r'\.exe$', 'mode': 'exe'}
        patterns = c.merge([{'patterns': [p]}], self.dest)
        empty = {'installed': [], 'probes': {}}
        op = c.make_plan(patterns, [path], str(self.source), empty, self.db, self.dest)['operations'][0]
        app = dict(name='App', publisher='Vendor', version='2.0', product_id='app', provider='registry', registry_key=r'HKLM\Software\Uninstall\app')
        after = {'installed': [app], 'probes': {}}
        receipt = {'changed': True, 'rc': 0}
        hints = {'name': 'App', 'publisher': 'Vendor'}
        details = c.verify_package(op, after, receipt, empty, hints)
        self.assertEqual(details['verification'], 'learned_registry')
        self.assertEqual(c.verify_package(op, after, receipt, empty, {'name': 'Setup', 'publisher': 'Vendor'})['verification'], 'installer_result')
        self.assertEqual(c.verify_package(op, {'installed': [app, dict(app, registry_key='other')]}, receipt, empty, hints)['verification'], 'installer_result')
        db = c.transition(self.db, op, 'done', [], verified=dict(details, installer_changed=True))
        self.assertFalse(c.make_plan(patterns, [path], str(self.source), after, db, self.dest)['operations'])
        self.assertFalse(c.make_plan(patterns, [path], str(self.source), empty, db, self.dest)['operations'])
        self.assertEqual(c.make_plan(patterns, [path], str(self.source), {'installed': [dict(app, version='3.0')], 'probes': {}}, db, self.dest)['skipped'][0]['reason'], 'state_current')
        absent = c.merge([{'patterns': [dict(p, state='absent')]}], self.dest)
        self.assertTrue(c.make_plan(absent, [], str(self.source), after, db, self.dest)['blocked'])

    def test_verified_version_at_least_target(self):
        path, _ = self.artifact('app-2.0.exe', b'exe')
        patterns = c.merge([{'patterns': [{'id': 'exe', 'name': 'App', 'regex': r'\.exe$', 'mode': 'exe'}]}], self.dest)
        op = c.make_plan(patterns, [path], str(self.source), {'installed': []}, self.db, self.dest)['operations'][0]
        details = c.verify_package(dict(op, verification='registry'), {'installed': [{'name': 'App', 'version': '3.0'}]})
        self.assertEqual(details['installed_version'], '3.0')


class NativeWiringTests(unittest.TestCase):
    def test_local_metadata_and_check_mode_never_install(self):
        tasks = yaml.safe_load((ROOT / 'task_windows.yaml').read_text())
        discover = next(t for t in tasks if t.get('software_manager', {}).get('operation') == 'discover_msi')
        self.assertEqual(discover['delegate_to'], 'localhost')
        self.assertFalse(any('ansible.windows.win_tempfile' in t for t in tasks))
        copies = [t for t in tasks if 'ansible.windows.win_copy' in t]
        self.assertEqual(len(copies), 1)
        self.assertIn('not ansible_check_mode', copies[0]['when'])
        self.assertTrue(copies[0]['ignore_errors'])
        snapshot = next(t for t in tasks if t.get('register') == 'software_snapshot' and 'ansible.windows.win_powershell' in t)
        self.assertFalse(snapshot['check_mode'])
        self.assertEqual(set(snapshot['ansible.windows.win_powershell']['parameters']), {'ProbePaths', 'MsiMetadata', 'MsiIdentities'})
        guard = next(t for t in tasks if 'ansible.builtin.assert' in t)
        self.assertIn('not (software_metadata_only | default(false) | bool)', guard['ansible.builtin.assert']['that'])
        self.assertFalse(any('metadata_database' in str(t) for t in tasks))

    def test_package_failure_does_not_block_next_package(self):
        execute = next(t for t in yaml.safe_load((ROOT / 'task_execute.yaml').read_text()) if 'rescue' in t)
        self.assertNotIn('software_packages_blocked', str(execute))
        self.assertNotIn('software_reboot_deferred', str(execute['block']))
        self.assertIn('1618', execute['rescue'][0]['ansible.builtin.set_fact']['software_reboot_deferred'])
        windows = yaml.safe_load((ROOT / 'task_windows.yaml').read_text())
        operations = next(t for t in windows if t.get('ansible.builtin.include_tasks', {}).get('file') == 'task_execute.yaml')
        self.assertNotIn('when', operations)
        self.assertIs(windows[0]['ansible.builtin.set_fact']['software_reboot_deferred'], False)
        guarded = [t for t in windows if 'software_reboot_deferred' in str(t.get('when', []))]
        self.assertEqual(len(guarded), 2)
        self.assertIn('ansible.windows.win_reboot', guarded[0])
        self.assertEqual(guarded[1]['ansible.builtin.set_fact']['software_reboot_required'], False)
        for task in yaml.safe_load((ROOT / 'task_package.yaml').read_text()):
            if 'ansible.windows.win_package' in task:
                self.assertEqual(task['retries'], 2)
                self.assertIn('1618', task['until'])
                self.assertNotIn('async', task)

    def test_native_script_contract_and_safe_cleanup(self):
        script = (ROOT / 'scripts/installed_software.ps1').read_text()
        self.assertNotIn('OpenDatabase', script)
        self.assertNotIn('MetadataDirectory', script)
        self.assertIn("'RelatedProducts' 'GetProperty'", script)
        self.assertIn("'ProductState' 'GetProperty'", script)
        self.assertNotIn('Win32_Product', script)
        fs = (ROOT / 'scripts/filesystem.ps1').read_text()
        self.assertNotIn('cleanup_msi_probe', fs)
        self.assertIn("'cleanup_package'", fs)


if __name__ == '__main__':
    unittest.main()
