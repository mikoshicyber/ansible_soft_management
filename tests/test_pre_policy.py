import sys
import tempfile
import unittest
from pathlib import Path

import yaml
from jinja2 import StrictUndefined
from jinja2.nativetypes import NativeEnvironment

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'module_utils'))
import software_core as core


class PrePolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.source = Path(self.tmp.name)
        self.dest = r'C:\Apps'
        self.empty = core.normalize_state({})
        self.pattern = {'id': 'app', 'regex': r'app-.*\.exe$', 'mode': 'exe', 'pre': ['stop.exe']}
        self.path = self.source / 'app-1.0.exe'
        self.path.write_bytes(b'first')

    def plan(self, pattern=None, db=None, snapshot=None):
        patterns = core.merge([{'patterns': [pattern or self.pattern]}], self.dest)
        return core.make_plan(patterns, core.index(self.source), str(self.source), snapshot or {'installed': []}, db if db is not None else self.empty, self.dest)

    def commit(self, op):
        return core.transition(self.empty, op, 'done', op['files'], verified={'installer_changed': True, 'verification': 'installer_result'})

    def test_fresh_install_always_runs_pre(self):
        for mode in ('exe', 'msi'):
            with self.subTest(mode=mode):
                (self.source / ("app-1.0." + mode)).write_bytes(b"first")
                pattern = dict(self.pattern, mode=mode, regex=r"app-.*\." + mode + "$")
                for legacy in ({}, {'pre_on_install': False}, {'pre_on_install': True}):
                    op = self.plan(dict(pattern, **legacy))['operations'][0]
                    self.assertEqual(op['action'], 'install')
                    self.assertTrue(op['run_pre'])
                    self.assertNotIn('pre_on_install', op['pattern'])

    def test_unchanged_version_and_hash_skip_pre(self):
        db = self.commit(self.plan()['operations'][0])
        self.assertFalse(self.plan(db=db)['operations'])
        self.path.rename(self.source / 'app-2.0.exe')
        self.assertFalse(self.plan(db=db)['operations'])

    def test_changed_hash_and_force_run_pre(self):
        db = self.commit(self.plan()['operations'][0])
        forced = self.plan(dict(self.pattern, force=True), db)['operations'][0]
        self.assertTrue(forced['run_pre'])
        self.path.write_bytes(b'changed')
        op = self.plan(db=db)['operations'][0]
        self.assertEqual(op['action'], 'upgrade')
        self.assertTrue(op['run_pre'])

    def test_retry_upgrade_runs_pre_but_post_recovery_skips(self):
        db = self.commit(self.plan()['operations'][0])
        self.path.write_bytes(b'changed')
        update = self.plan(db=db)['operations'][0]
        pending = core.transition(db, update, 'pending', [])
        self.assertTrue(self.plan(db=pending)['operations'][0]['run_pre'])
        post = core.transition(db, update, 'post', [], verified={'installer_changed': True})
        op = self.plan(db=post)['operations'][0]
        self.assertEqual(op['action'], 'recover')
        self.assertFalse(op['run_pre'])
        first = self.plan()['operations'][0]
        pending_first = core.transition(self.empty, first, 'pending', [])
        self.assertTrue(self.plan(db=pending_first)['operations'][0]['run_pre'])

    def test_standalone_removal_runs_pre(self):
        for mode, provider in (('exe', 'registry'), ('msi', 'msi')):
            with self.subTest(mode=mode):
                pattern = dict(self.pattern, mode=mode, name='App', state='absent')
                snapshot = {'installed': [{'name': 'App', 'version': '1.0', 'product_id': '{12345678-1234-1234-1234-123456789ABC}' if mode == 'msi' else 'app', 'provider': provider, 'quiet_uninstall_string': 'quiet.exe'}]}
                op = self.plan(pattern, snapshot=snapshot)['operations'][0]
                self.assertEqual(op['action'], 'remove')
                self.assertTrue(op['run_pre'])
                self.assertFalse(self.plan(pattern)['operations'])

    def test_file_operations_run_pre_on_updates_and_removals(self):
        f = {'path': core.target(self.dest, 'a.bin'), 'checksum': 'a' * 64}
        p = {'state': 'present', 'force': False}
        op = {'pattern': p, 'old': {}, 'remove': [], 'artifact': {}, 'action': 'inspect'}
        for mode in ('arc', 'files'):
            candidate = dict(op, pattern=dict(p, mode=mode))
            for actual, action, expected in ((None, 'update_files', True), ('b' * 64, 'update_files', True), ('a' * 64, 'adopt', False)):
                with self.subTest(mode=mode, actual=actual):
                    self.assertEqual(core.plan_files(candidate, [f], {f['path']: actual}), {'action': action, 'run_pre': expected})
            for status in ('installed', 'absent', 'pending'):
                self.assertTrue(core.plan_files(dict(candidate, old={'status': status, 'files': [f]}), [f], {f['path']: None})['run_pre'])
            absent = dict(candidate, pattern=dict(candidate['pattern'], state='absent'), remove=[f])
            self.assertEqual(core.plan_files(absent, [], {f['path']: f['checksum']}), {'action': 'update_files', 'run_pre': True})
            self.assertEqual(core.plan_files(dict(absent, old={'status': 'installed', 'files': [f]}), [], {f['path']: None}), {'action': 'forget', 'run_pre': False})
            self.assertTrue(core.plan_files(dict(candidate, state_update=True), [f], {f['path']: f['checksum']})['run_pre'])
            self.assertTrue(core.plan_files(dict(candidate, pattern=dict(candidate['pattern'], force=True)), [f], {f['path']: f['checksum']})['run_pre'])
            self.assertEqual(core.plan_files(dict(candidate, old={'status': 'pending', 'phase': 'post'}), [f], {f['path']: f['checksum']}), {'action': 'recover', 'run_pre': False})
            self.assertEqual(core.plan_files(dict(candidate, old={'status': 'installed', 'files': [f]}), [f], {f['path']: f['checksum']}), {'action': 'skip', 'run_pre': False})

    def test_task_conditions_and_reset(self):
        tasks = yaml.safe_load((ROOT / 'task_execute.yaml').read_text())
        self.assertIs(tasks[0]['ansible.builtin.set_fact']['software_run_pre'], False)
        main = next(t['block'] for t in tasks if 'block' in t)
        decision = next(t['ansible.builtin.set_fact'] for t in main if 'software_run_pre' in t.get('ansible.builtin.set_fact', {}))
        block = next(t for t in main if 'block' in t)
        pre, post = [t for t in block['block'] if 'ansible.windows.win_shell' in t]
        self.assertEqual(pre['when'], ['not ansible_check_mode', 'software_run_pre | bool'])
        self.assertEqual(post['when'], 'software_run_hooks')
        self.assertEqual(block['when'], "not ansible_check_mode and software_action != 'skip'")
        env = NativeEnvironment(undefined=StrictUndefined)
        env.filters['bool'] = bool
        expr = env.from_string(decision['software_run_pre'])
        for mode in ('exe', 'msi', 'arc', 'files'):
            for enabled in (False, True):
                with self.subTest(mode=mode, enabled=enabled):
                    self.assertIs(expr.render(software_item={'pattern': {'mode': mode}, 'run_pre': enabled}, software_file_plan={'run_pre': enabled}), enabled)
        self.assertFalse(expr.render(software_item={'pattern': {'mode': 'exe'}}, software_file_plan={'run_pre': True}))
        hook_expr = env.from_string(decision['software_run_hooks'])
        for action in ('install', 'upgrade', 'remove', 'update_files', 'recover', 'adopt', 'forget', 'skip'):
            for check in (False, True):
                with self.subTest(action=action, check=check):
                    hooks = hook_expr.render(software_action=action)
                    self.assertIs(hooks, action in ('install', 'upgrade', 'remove', 'update_files', 'recover'))
                    runs_post = hooks and env.compile_expression(block['when'])(ansible_check_mode=check, software_action=action)
                    self.assertIs(runs_post, not check and action in ('install', 'upgrade', 'remove', 'update_files', 'recover'))
        main_tasks = block['block']
        self.assertLess(main_tasks.index(pre), next(i for i, t in enumerate(main_tasks) if t.get('ansible.builtin.include_tasks', {}).get('file') == 'task_package.yaml'))
        self.assertLess(next(i for i, t in enumerate(main_tasks) if t.get('ansible.builtin.include_tasks', {}).get('file') == 'task_files.yaml'), main_tasks.index(post))
        self.assertLess(main_tasks.index(post), next(i for i, t in enumerate(main_tasks) if t.get('vars', {}).get('software_phase') == 'done'))
        for check in (False, True):
            for enabled in (False, True):
                self.assertEqual(all(env.compile_expression(cond)(ansible_check_mode=check, software_run_pre=enabled) for cond in pre['when']), enabled and not check)

    def test_file_staging_only_discards_snapshot_when_pre_runs_or_force(self):
        tasks = yaml.safe_load((ROOT / 'task_files.yaml').read_text())
        stage = next(t['software_manager'] for t in tasks if t.get('software_manager', {}).get('operation') == 'stage_files')
        env = NativeEnvironment(undefined=StrictUndefined)
        env.filters['bool'] = bool
        expr = env.from_string(stage['snapshot'])
        snapshot = {'file': 'hash'}
        for enabled, force, pre in ((False, False, ['stop']), (True, False, ['stop']), (True, False, []), (False, True, [])):
            with self.subTest(enabled=enabled, force=force, pre=pre):
                self.assertEqual(expr.render(software_run_pre=enabled, software_item={'pattern': {'force': force, 'pre': pre}}, software_file_hashes=snapshot), {} if force or (enabled and pre) else snapshot)


if __name__ == '__main__':
    unittest.main()
