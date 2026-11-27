import io
import json
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'module_utils'))
import software_core as c


class SoftwareTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.dest = r'C:\Apps'
        self.db = c.normalize_state({})
        self.snap = {'installed': [], 'probes': {}}

    def tearDown(self):
        self.tmp.cleanup()

    def artifact(self, name, content=b'installer'):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
        return str(p)

    def patterns(self, *items):
        return c.merge([{'scope': 'all', 'patterns': list(items)}], self.dest)

    def package(self, **overrides):
        return dict({'id': 'app', 'name': 'App', 'regex': r'app-.*\.exe$', 'mode': 'exe'}, **overrides)

    def plan(self, p, snapshot=None, db=None):
        return c.make_plan(self.patterns(*p), c.index(self.root), str(self.root), snapshot or self.snap, db or self.db, self.dest)

    def installed(self, version='1.0', **kw):
        return {'installed': [dict({'name': 'App', 'version': version, 'product_id': 'app', 'provider': 'registry', 'quiet_uninstall_string': 'quiet.exe'}, **kw)], 'probes': {}}

    def archive(self, name='app-1.2.zip', files=None):
        path = self.root / name
        with zipfile.ZipFile(path, 'w') as z:
            for n, data in (files or {'bin/a.exe': b'one', 'doc/readme.txt': b'two'}).items():
                z.writestr(n, data)
        return path

    def test_index_excludes_unfinished_downloads(self):
        ready = self.artifact('app-1.0.exe')
        nested = self.artifact('stable/another-2.0.exe')
        self.artifact('.autodownload-stage/app-9.0.exe')
        self.artifact('nested/.autodownload-stage/another-9.0.exe')
        self.artifact('app-3.0.exe')
        self.artifact('app-3.0.exe.aria2')
        self.artifact('orphan.aria2')
        self.assertEqual(set(c.index(self.root)), {ready, nested})
        plan = self.plan([self.package()])
        self.assertFalse(plan['errors'])
        self.assertEqual(plan['operations'][0]['artifact']['source'], ready)

    def legacy_package(self, **overrides):
        return dict({'regex': r'app-.*\.exe$', 'mode': 'exe'}, **overrides)

    def test_legacy_plan_regex_only(self):
        artifact = self.artifact('app-1.2.exe')
        plan = self.plan([self.legacy_package()])
        self.assertFalse(plan['errors'] or plan['blocked'])
        op = plan['operations'][0]
        self.assertEqual(op['artifact']['source'], artifact)
        self.assertEqual(op['action'], 'install')
        self.assertEqual(op['verification'], 'installer_result')

    def test_legacy_receipt_idempotence_and_checksum_change(self):
        self.artifact('app-1.2.exe', b'one')
        op = self.plan([self.legacy_package()])['operations'][0]
        c.verify_package(op, self.snap, {'changed': True, 'rc': 0})
        db = c.transition(self.db, op, 'done', [])
        self.assertEqual(db['products'][op['id']]['status'], 'installer_reported')
        plan = self.plan([self.legacy_package()], db=db)
        self.assertFalse(plan['operations'])
        self.assertEqual(plan['skipped'][0]['reason'], 'state_current')
        self.artifact('app-1.2.exe', b'two')
        self.assertEqual(self.plan([self.legacy_package()], db=db)['operations'][0]['action'], 'upgrade')

    def test_legacy_unknown_version_receipt(self):
        self.artifact('app-latest.exe')
        op = self.plan([self.legacy_package()])['operations'][0]
        self.assertIsNone(op['artifact']['version'])
        db = c.transition(self.db, op, 'done', [])
        self.assertFalse(self.plan([self.legacy_package()], db=db)['operations'])
        self.assertEqual(self.plan([self.legacy_package(force=True)], db=db)['operations'][0]['action'], 'upgrade')

    def test_legacy_different_version_and_hash_updates_even_if_older(self):
        path = self.artifact('app-2.0.exe', b'new')
        op = self.plan([self.legacy_package()])['operations'][0]
        db = c.transition(self.db, op, 'done', [])
        Path(path).unlink()
        self.artifact('app-1.0.exe', b'old')
        plan = self.plan([self.legacy_package()], db=db)
        self.assertEqual(plan['operations'][0]['action'], 'upgrade')
        self.assertFalse(plan['warnings'])

    def test_legacy_remove_skip_and_missing_artifact_error_are_independent(self):
        self.artifact('app-1.2.exe')
        plan = self.plan([self.legacy_package(state='absent'), {'regex': 'missing', 'mode': 'msi'}, self.package(regex=r'app-.+\.exe$')])
        self.assertFalse(plan['errors'])
        self.assertEqual(len(plan['blocked']), 1)
        self.assertEqual(plan['blocked'][0]['status'], 'error')
        self.assertEqual(plan['skipped'], [{'id': self.legacy_package()['regex'], 'reason': 'no_removal_identity'}])
        self.assertEqual(len(plan['operations']), 1)

    def test_unidentified_removal_skips_only_without_active_state_or_probe(self):
        for mode in ('exe', 'msi'):
            pattern = {'id': 'unknown', 'regex': r'app-.*\.' + mode + '$', 'mode': mode, 'state': 'absent', 'force': True}
            with self.subTest(mode=mode):
                for snapshot in (self.snap, self.installed()):
                    plan = self.plan([pattern], snapshot)
                    self.assertFalse(plan['operations'] or plan['blocked'] or plan['warnings'] or plan['errors'])
                    self.assertEqual(plan['skipped'], [{'id': 'unknown', 'reason': 'no_removal_identity'}])
                for status in ('installed', 'installer_reported', 'pending'):
                    db = {'schema_version': 2, 'products': {'unknown': {'status': status}}}
                    self.assertIn('Removal requires registry identity', self.plan([pattern], db=db)['blocked'][0]['reason'])
                path = r'C:\Apps\app.exe'
                plan = self.plan([dict(pattern, creates_path=path)], {'installed': [], 'probes': {path: {'exists': True}}})
                self.assertIn('Removal requires registry identity', plan['blocked'][0]['reason'])

    def test_missing_nextcloud_packages_are_silent(self):
        patterns = [{'regex': regex, 'state': 'absent', 'mode': 'msi'}
                    for regex in ('Nextcloud-.*-x64.msi', 'Nextcloud.Talk-windows-x64.msi')]
        plan = self.plan(patterns, {'installed': [], 'probes': {}, 'msi_metadata': {}})
        self.assertFalse(plan['operations'] or plan['blocked'] or plan['warnings'] or plan['errors'])
        self.assertEqual(len(plan['skipped']), 2)
        self.assertTrue(all(item['reason'] == 'no_removal_identity' for item in plan['skipped']))

    def test_legacy_receipt_rejects_failed_skipped_or_nochange(self):
        self.artifact('app-1.2.exe')
        op = self.plan([self.legacy_package()])['operations'][0]
        for receipt in ({}, {'changed': False}, {'changed': True, 'failed': True}, {'changed': True, 'skipped': True}, {'changed': True, 'unreachable': True}, {'changed': True, 'rc': 5}):
            with self.subTest(receipt=receipt), self.assertRaises(c.SoftwareError):
                c.verify_package(op, self.snap, receipt)

    def test_msi_nochange_requires_reinstall_receipt(self):
        self.artifact('app-1.2.msi')
        pattern = {'regex': r'app-.*\.msi$', 'mode': 'msi'}
        op = self.plan([pattern])['operations'][0]
        for action in ('install', 'upgrade'):
            with self.assertRaises(c.SoftwareError):
                c.verify_package(dict(op, action=action), self.snap, {'changed': False})
            self.assertEqual(c.verify_package(dict(op, action=action), self.snap, {'changed': True, 'rc': 0})['verification'], 'installer_result')

    def test_legacy_pending_recovery_requires_receipt(self):
        self.artifact('app-1.2.exe')
        pattern = self.legacy_package()
        op = self.plan([pattern])['operations'][0]
        db = c.transition(self.db, op, 'post', [], verified={'installer_changed': True})
        recovery = self.plan([pattern], db=db)['operations'][0]
        self.assertEqual(recovery['action'], 'recover')
        c.verify_package(recovery, self.snap)
        db['products'][op['id']].pop('pending_verification')
        self.assertNotEqual(self.plan([pattern], db=db)['operations'][0]['action'], 'recover')
        db = c.transition(self.db, op, 'pending', [])
        self.assertNotEqual(self.plan([pattern], db=db)['operations'][0]['action'], 'recover')

    def test_legacy_identity_overrides(self):
        pattern = self.legacy_package(state='absent')
        layers = [{'scope': 'all', 'patterns': [pattern]}]
        merged = c.merge(layers, self.dest, {pattern['regex']: {'product_id': 'app'}})
        plan = c.make_plan(merged, [], str(self.root), self.installed(), self.db, self.dest)
        self.assertEqual(plan['operations'][0]['action'], 'remove')
        explicit = c.merge([{'patterns': [self.package(product_id='explicit')]}], self.dest, {'app': {'product_id': 'ignored'}})
        self.assertEqual(explicit[0]['product_id'], 'explicit')
        with self.assertRaises(c.SoftwareError):
            c.merge(layers, self.dest, {pattern['regex']: {'state': 'present'}})

    def test_conflicting_artifact_patterns_block_plan(self):
        self.artifact('app-1.2.exe')
        plan = self.plan([self.legacy_package(), self.package(regex=r'app-.+\.exe$')])
        self.assertTrue(plan['errors'])

    def test_versions(self):
        self.assertGreater(c.version_key('1.10'), c.version_key('1.9'))
        self.assertEqual(c.version_key('1.2.0'), c.version_key('1.2'))
        self.assertLess(c.version_key('2.0-rc2'), c.version_key('2.0'))
        self.assertLess(c.version_key('1.0.0-rc.1', 'semver'), c.version_key('1.0.0', 'semver'))
        self.assertLess(c.version_key('1.0.0-alpha.2', 'semver'), c.version_key('1.0.0-alpha.10', 'semver'))
        self.assertIsNone(c.version_key('latest'))

    def test_merge(self):
        patterns = c.merge([{'scope': 'all', 'patterns': [self.package()]}, {'scope': 'host', 'patterns': [{'id': 'app', 'force': 'false', 'state': 'absent'}]}], self.dest)
        self.assertEqual(patterns[0]['state'], 'absent')
        self.assertFalse(patterns[0]['force'])
        self.assertEqual(patterns[0]['name'], 'App')

    def test_regex_scope_priority(self):
        regex = r'app-.*\.exe$'
        layers = [
            {'scope': 'host', 'patterns': [{'regex': regex, 'args': '/host', 'pre': []}]},
            {'scope': 'all', 'patterns': [self.package(args='/all', pre=['stop app'])]},
            {'scope': 'group', 'patterns': [{'regex': regex, 'args': '/group', 'force': True}]},
        ]
        merged = c.merge(layers, self.dest)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]['id'], 'app')
        self.assertEqual(merged[0]['args'], '/host')
        self.assertEqual(merged[0]['pre'], [])
        self.assertTrue(merged[0]['force'])
        self.assertEqual(merged[0]['name'], 'App')

    def test_regex_group_overrides_all(self):
        regex = r'app-.*\.exe$'
        merged = c.merge([
            {'scope': 'all', 'patterns': [{'regex': regex, 'args': '/all'}]},
            {'scope': 'group', 'patterns': [{'regex': regex, 'args': '/group'}]},
        ], self.dest)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]['id'], regex)
        self.assertEqual(merged[0]['args'], '/group')

    def test_regex_explicit_id_override(self):
        merged = c.merge([
            {'scope': 'all', 'patterns': [self.package(), {'regex': 'other'}]},
            {'scope': 'group', 'patterns': [self.package(id='group-app', args='/group')]},
            {'scope': 'host', 'patterns': [{'id': 'group-app', 'state': 'absent'}]},
        ], self.dest)
        self.assertEqual([p['id'] for p in merged], ['group-app', 'other'])
        self.assertEqual(merged[0]['state'], 'absent')
        self.assertEqual(merged[0]['args'], '/group')

    def test_regex_duplicates_and_conflicting_identity(self):
        for layers in (
            [{'scope': 'all', 'patterns': [self.package(), self.package(id='duplicate')]}],
            [{'scope': 'group', 'patterns': [self.package()]},
             {'scope': 'group', 'patterns': [self.package(id='duplicate')]}],
            [{'scope': 'all', 'patterns': [self.package(), {'id': 'other', 'regex': 'other'}]},
             {'scope': 'host', 'patterns': [{'id': 'other', 'regex': self.package()['regex']}]}],
        ):
            with self.subTest(layers=layers), self.assertRaises(c.SoftwareError):
                c.merge(layers, self.dest)

    def test_regex_priority_preserves_state_and_prevents_duplicate_plan(self):
        self.artifact('app-1.2.exe')
        base = {'scope': 'all', 'patterns': [self.package(args='/all')]}
        plan = c.make_plan(c.merge([base], self.dest), c.index(self.root), str(self.root), self.snap, self.db, self.dest)
        db = c.transition(self.db, plan['operations'][0], 'done', [])
        group = {'scope': 'group', 'patterns': [{'regex': self.package()['regex'], 'args': '/group'}]}
        plan = c.make_plan(c.merge([base, group], self.dest), c.index(self.root), str(self.root), self.snap, db, self.dest)
        self.assertFalse(plan['operations'] or plan['errors'] or plan['blocked'])
        self.assertEqual(plan['skipped'][0]['id'], 'app')

    def test_group_conflict(self):
        with self.assertRaises(c.SoftwareError):
            c.merge([{'scope': 'group', 'patterns': [self.package(force=True)]}, {'scope': 'group', 'patterns': [self.package(force=False)]}], self.dest)

    def test_unsafe_paths(self):
        for path in ('../x', 'a/../b', 'a:stream', '/root', 'a//b', 'CON.txt', 'a.', 'a\\..\\b', 'x?y'):
            with self.subTest(path=path), self.assertRaises(c.SoftwareError):
                c.relative(path)
        with self.assertRaises(c.SoftwareError):
            c.winroot('C:\\')

    def test_latest_pair(self):
        self.artifact('app-1.9.exe')
        best = self.artifact('app-1.10.exe')
        self.artifact('app-1.2.exe')
        plan = self.plan([self.package()])
        self.assertFalse(plan['errors'])
        self.assertEqual(plan['operations'][0]['artifact']['source'], best)
        self.assertEqual(plan['operations'][0]['artifact']['version'], '1.10')

    def test_unknown_ambiguous(self):
        self.artifact('app-latest.exe')
        self.artifact('app-1.0.exe')
        self.assertTrue(self.plan([self.package()])['blocked'])

    def test_same_version_conflict(self):
        self.artifact('a/app-1.0.exe', b'a')
        self.artifact('b/app-1.0.exe', b'b')
        self.assertTrue(self.plan([self.package()])['blocked'])

    def test_registry_version_does_not_override_state(self):
        self.artifact('app-1.0.exe')
        self.assertEqual(self.plan([self.package()], self.installed('2.0'))['operations'][0]['action'], 'install')

    def test_install_upgrade_skip(self):
        path = self.artifact('app-2.0.exe', b'one')
        op = self.plan([self.package()])['operations'][0]
        self.assertEqual(op['action'], 'install')
        self.assertEqual(self.plan([self.package()], self.installed())['operations'][0]['action'], 'install')
        db = c.transition(self.db, op, 'done', [])
        for snap in (self.installed('2.0'), self.snap):
            self.assertFalse(self.plan([self.package()], snap, db)['operations'])
        Path(path).unlink()
        self.artifact('app-3.0.exe', b'two')
        self.assertEqual(self.plan([self.package()], self.snap, db)['operations'][0]['action'], 'upgrade')

    def test_unknown_version_is_supported_without_opt_in(self):
        self.artifact('app-latest.exe')
        result = self.plan([self.package()], self.installed())
        self.assertEqual(result['operations'][0]['action'], 'install')
        self.assertIsNone(result['operations'][0]['artifact']['version'])

    def test_checksum_change(self):
        self.artifact('app-2.0.exe', b'a')
        op = self.plan([self.package()])['operations'][0]
        db = c.transition(self.db, op, 'done', [])
        self.artifact('app-2.0.exe', b'b')
        plan = self.plan([self.package()], self.installed('2.0'), db)
        self.assertEqual(plan['operations'][0]['action'], 'upgrade')
        self.assertEqual(plan['warnings'][0]['status'], 'warning')

    def test_post_recovery(self):
        self.artifact('app-2.0.exe')
        op = self.plan([self.package()])['operations'][0]
        db = c.transition(self.db, op, 'post', [], verified={'installer_changed': True})
        self.assertEqual(self.plan([self.package()], self.installed('2.0'), db)['operations'][0]['action'], 'recover')
        db = c.transition(self.db, op, 'pending', [])
        self.assertEqual(self.plan([self.package()], self.installed('2.0'), db)['operations'][0]['action'], 'install')

    def test_removal_without_artifact(self):
        self.assertEqual(self.plan([self.package(state='absent')], self.installed())['operations'][0]['action'], 'remove')
        self.assertTrue(self.plan([self.package(state='absent')], self.installed(quiet_uninstall_string=''))['blocked'])
        self.assertFalse(self.plan([self.package(state='absent')])['operations'])

    def test_ambiguous_remove(self):
        snapshot = self.installed()
        snapshot['installed'].append(dict(snapshot['installed'][0], product_id='app2'))
        self.assertTrue(self.plan([self.package(state='absent')], snapshot)['blocked'])

    def test_verify_package(self):
        self.artifact('app-2.0.exe')
        op = self.plan([self.package()])['operations'][0]
        self.assertEqual(c.verify_package(op, self.snap, {'changed': True, 'rc': 0})['verification'], 'installer_result')
        with self.assertRaises(c.SoftwareError):
            c.verify_package(op, self.installed('2.0'))
        with self.assertRaises(c.SoftwareError):
            c.verify_package(op, self.snap, {'changed': True, 'rc': 1603})

    def test_state_migration_and_corruption(self):
        self.assertEqual(c.normalize_state({'app': '1.2'})['legacy'], {'app': '1.2'})
        for state in ('', '{broken', {'schema_version': 3, 'products': {}}, {'schema_version': 2, 'products': []}):
            with self.subTest(state=state), self.assertRaises(ValueError):
                c.normalize_state(state)

    def test_archive_manifest_and_prepare(self):
        self.archive()
        p = {'id': 'arc', 'name': 'Arc', 'regex': r'app-.*\.zip$', 'mode': 'arc'}
        op = self.plan([p])['operations'][0]
        self.assertEqual(len(op['files']), 2)
        prepared = c.prepare(op, self.root)
        try:
            for f in prepared['files']:
                self.assertEqual(c.sha(f['source']), f['checksum'])
        finally:
            import shutil
            shutil.rmtree(prepared['directory'])
        self.archive(files={'changed': b'new'})
        with self.assertRaises(c.SoftwareError):
            c.prepare(op, self.root)

    def test_archive_traversal_and_links(self):
        path = self.archive(files={'../escape': b'x'})
        with self.assertRaises(c.SoftwareError):
            c.archive_members(path)
        link = self.root / 'link.tar'
        with tarfile.open(link, 'w') as t:
            info = tarfile.TarInfo('link')
            info.type = tarfile.SYMTYPE
            info.linkname = '../outside'
            t.addfile(info)
        with self.assertRaises(c.SoftwareError):
            c.archive_members(link)

    def test_archive_limits(self):
        path = self.archive(files={'a': b'1234'})
        with self.assertRaises(c.SoftwareError):
            c.archive_members(path, max_bytes=3)
        path = self.archive(files={'A': b'1', 'a': b'2'})
        with self.assertRaises(c.SoftwareError):
            c.archive_members(path)

    def test_archive_flat_collision_and_missing(self):
        self.archive(files={'a/file': b'a', 'b/file': b'b'})
        p = {'id': 'arc', 'name': 'Arc', 'regex': r'app-.*\.zip$', 'mode': 'arc', 'files': ['a/file', 'b/file']}
        self.assertTrue(self.plan([p])['errors'])
        self.assertTrue(self.plan([dict(p, files=['missing'])])['errors'])

    def test_archive_removal_manifest(self):
        self.archive()
        p = {'id': 'arc', 'name': 'Arc', 'regex': r'app-.*\.zip$', 'mode': 'arc'}
        op = self.plan([p])['operations'][0]
        db = c.transition(self.db, op, 'done', op['files'])
        absent = self.plan([dict(p, state='absent')], db=db)['operations'][0]
        self.assertEqual(len(absent['remove']), 2)
        after = c.transition(db, absent, 'done', [])
        self.assertEqual(after['products']['arc']['status'], 'absent')
        self.assertEqual(len(after['products']['arc']['files']), 2)
        self.assertTrue(self.plan([dict(p, state='absent')])['errors'])

    def test_files_ownership(self):
        self.artifact('config.txt')
        p = {'id': 'a', 'mode': 'files', 'files': ['config.txt']}
        self.assertFalse(self.plan([p])['errors'])
        self.assertTrue(self.plan([p, dict(p, id='b')])['errors'])

    def test_manifest_escape(self):
        self.artifact('config.txt')
        p = {'id': 'a', 'mode': 'files', 'files': ['config.txt']}
        db = {'schema_version': 2, 'products': {'a': {'files': [{'path': r'C:\Windows\test.txt', 'checksum': 'a' * 64}]}}}
        self.assertTrue(self.plan([p], db=db)['errors'])

    def test_symlink_not_indexed(self):
        file = self.artifact('file')
        (self.root / 'link').symlink_to(file)
        self.assertEqual(c.index(self.root), [file])


if __name__ == '__main__':
    unittest.main()
