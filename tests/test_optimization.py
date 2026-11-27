import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import yaml
from jinja2 import StrictUndefined
from jinja2.nativetypes import NativeEnvironment

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'module_utils'))
import software_core as core


def load(name):
    return yaml.safe_load((ROOT / name).read_text())


class OptimizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name)
        self.dest = r'C:\Apps'
        self.db = {'schema_version': 2, 'products': {}}
        for name in ('a.txt', 'b.txt', 'c.txt', 'd.txt', 'app-1.0.exe', 'other-1.0.exe'):
            (self.source / name).write_text(name)

    def plan(self, patterns, db=None, **kwargs):
        patterns = core.merge([{'scope': 'all', 'patterns': patterns}], self.dest)
        return core.make_plan(patterns, core.index(self.source), str(self.source), {'installed': []}, self.db if db is None else db, self.dest, **kwargs)

    def files(self, name, **kwargs):
        return dict(id=name, mode='files', files=[name], template=False, **kwargs)

    def test_timeout_validation_before_staging_is_independent(self):
        plan = self.plan([{'id': 'bad', 'regex': 'app-', 'package_timeout': 4}, {'id': 'ok', 'regex': 'other-', 'package_timeout': 600}], timeouts={'package': 180, 'hook': 120})
        self.assertEqual([op['id'] for op in plan['operations']], ['ok'])
        self.assertEqual(plan['operations'][0]['package_timeout_seconds'], 600)
        self.assertEqual(plan['blocked'][0]['id'], 'bad')
        self.assertIn('package_timeout', plan['blocked'][0]['reason'])
        self.assertFalse(plan['errors'])

    def test_invalid_hook_timeout_only_when_hooks_run(self):
        rule = {'id': 'app', 'regex': 'app-', 'pre': ['stop'], 'hook_timeout': 2}
        self.assertEqual(len(self.plan([rule])['blocked']), 1)
        op = self.plan([dict(rule, hook_timeout=120)])['operations'][0]
        db = core.transition(self.db, op, 'done', [], verified={'verification': 'installer_result', 'installer_changed': True})
        self.assertEqual(len(self.plan([rule], db)['skipped']), 1)
        f = self.plan([self.files('a.txt', pre=['stop'], hook_timeout=2)])['operations'][0]
        with self.assertRaisesRegex(core.SoftwareError, 'hook_timeout'):
            core.plan_files(f, f['files'], {f['files'][0]['path']: None})

    def test_consecutive_file_inspection_batches(self):
        operations = self.plan([self.files('a.txt'), self.files('b.txt'), {'id': 'app', 'regex': 'app-'}, self.files('c.txt'), self.files('d.txt')])['operations']
        paths = [core.target(self.dest, n) for n in ('a.txt', 'b.txt', 'c.txt', 'd.txt')]
        self.assertEqual(operations[0]['inspection_paths'], paths[:2])
        self.assertEqual(operations[1]['inspection_paths'], paths[1:2])
        self.assertNotIn('inspection_paths', operations[2])
        self.assertEqual(operations[3]['inspection_paths'], paths[2:])
        self.assertEqual(operations[4]['inspection_paths'], paths[3:])
        self.assertEqual(core.plan_files(operations[0], operations[0]['files'], {paths[0]: None, paths[1]: {'error': 'locked'}})['action'], 'update_files')
        with self.assertRaisesRegex(core.SoftwareError, 'locked'):
            core.plan_files(operations[1], operations[1]['files'], {paths[0]: None, paths[1]: {'error': 'locked'}})

    def test_preflight_excludes_only_confirmed_unchanged_prefix(self):
        rules = [self.files('a.txt'), self.files('b.txt'), {'id': 'app', 'regex': 'app-'}, self.files('c.txt')]
        initial = self.plan(rules)
        db = self.db
        for op in initial['operations']:
            if op['pattern']['mode'] == 'files':
                db = core.transition(db, op, 'done', op['files'])
        plan = self.plan(rules, db)
        operations = plan['operations']
        snapshot = {f['path']: f['checksum'] for op in operations for f in op['files']}
        self.assertEqual(plan['file_preflight']['count'], 2)
        self.assertEqual(plan['file_preflight']['paths'], operations[0]['inspection_paths'])
        self.assertEqual(plan['file_preflight']['templates'], [])
        result = core.prune_file_operations(operations, snapshot, {})
        self.assertEqual(result['execution_indices'], [2, 3])
        self.assertEqual([x['id'] for x in result['skipped']], ['a.txt', 'b.txt'])
        path = operations[1]['files'][0]['path']
        for value in (None, {'error': 'access denied'}, 'f' * 64):
            with self.subTest(value=value):
                result = core.prune_file_operations(operations, dict(snapshot, **{path: value}), {})
                self.assertEqual(result['execution_indices'], [1, 2, 3])
        self.assertEqual(core.prune_file_operations(operations, {}, {})['execution_indices'], [0, 1, 2, 3])
        unchanged = operations[:2]
        self.assertEqual(core.prune_file_operations(unchanged, snapshot, {})['execution_indices'], [])
        self.assertEqual(core.file_preflight(operations[2:])['count'], 0)
        self.assertEqual(core.prune_file_operations(operations[2:], snapshot, {})['execution_indices'], [0, 1])
        self.assertEqual(core.prune_file_operations([], {}, {}), {'execution_indices': [], 'skipped': []})

    def test_preflight_preserves_force_adopt_recovery_and_removal(self):
        rule = self.files('a.txt')
        initial = self.plan([rule])['operations'][0]
        snapshot = {f['path']: f['checksum'] for f in initial['files']}
        db = core.transition(self.db, initial, 'done', initial['files'])
        self.assertEqual(core.prune_file_operations([initial], snapshot, {})['execution_indices'], [0])
        for phase in ('pending', 'post'):
            pending = core.transition(self.db, initial, phase, initial['files'])
            op = self.plan([rule], pending)['operations'][0]
            self.assertEqual(core.prune_file_operations([op], snapshot, {})['execution_indices'], [0])
        for change in ({'force': True}, {'state': 'absent'}):
            op = self.plan([dict(rule, **change)], db)['operations'][0]
            self.assertEqual(core.prune_file_operations([op], snapshot, {})['execution_indices'], [0])
        removed = self.plan([dict(rule, state='absent')], db)['operations'][0]
        self.assertEqual(core.prune_file_operations([removed], {next(iter(snapshot)): None}, {})['execution_indices'], [0])

    def test_preflight_requires_rendered_template_hashes(self):
        rule = dict(self.files('a.txt'), template=True, files=['a.txt', 'b.txt'])
        initial = self.plan([rule])['operations'][0]
        files = [dict(f, checksum=str(i + 1) * 64) for i, f in enumerate(initial['files'])]
        db = core.transition(self.db, initial, 'done', files)
        plan = self.plan([rule], db)
        ops = plan['operations']
        checksums = {f['path']: f['checksum'] for f in files}
        self.assertEqual(plan['file_preflight']['templates'], [{'index': 0, 'file': f} for f in ops[0]['files']])
        self.assertEqual(core.prune_file_operations(ops, checksums, {'a.txt': checksums})['execution_indices'], [])
        self.assertEqual(core.prune_file_operations(ops, checksums, {})['execution_indices'], [0])
        partial = {files[0]['path']: files[0]['checksum']}
        self.assertEqual(core.prune_file_operations(ops, checksums, {'a.txt': partial})['execution_indices'], [0])
        changed = dict(checksums, **{files[1]['path']: 'f' * 64})
        self.assertEqual(core.prune_file_operations(ops, checksums, {'a.txt': changed})['execution_indices'], [0])
        raw = {f['path']: f['checksum'] for f in ops[0]['files']}
        self.assertEqual(core.prune_file_operations(ops, raw, {'a.txt': checksums})['execution_indices'], [0])

    def test_preflight_wiring_filters_execution_and_falls_back(self):
        tasks = load('task_windows.yaml')
        preflight = next(t for t in tasks if t['name'] == 'Preflight managed files')
        execute = next(t for t in tasks if t.get('ansible.builtin.include_tasks', {}).get('file') == 'task_execute.yaml')
        self.assertLess(tasks.index(preflight), tasks.index(execute))
        probe = next(t for t in preflight['block'] if t.get('register') == 'software_preflight_snapshot')
        compare = next(t for t in preflight['block'] if t.get('software_manager', {}).get('operation') == 'prune_files')
        self.assertEqual(probe['ansible.windows.win_powershell']['parameters']['Operation'], 'inspect_batch')
        self.assertIs(probe['check_mode'], False)
        self.assertEqual(compare['delegate_to'], 'localhost')
        self.assertTrue(preflight['rescue'])
        env = NativeEnvironment(undefined=StrictUndefined)
        template = env.from_string(execute['loop'])
        plan = {'operations': [{}, {}]}
        self.assertEqual(template.render(software_plan=plan, software_preflight_result={'execution_indices': []}), [])
        self.assertEqual(template.render(software_plan=plan, software_preflight_result={'execution_indices': [1]}), [1])
        self.assertEqual(template.render(software_plan=plan, software_preflight_result={'failed': True}), [0, 1])
        self.assertEqual(template.render(software_plan=plan), [0, 1])

    def test_cache_reuse_and_invalidation_wiring(self):
        tasks = load('task_file_plan.yaml')
        probe = next(t for t in tasks if t.get('register') == 'software_file_snapshot')
        env = NativeEnvironment(undefined=StrictUndefined)
        cond = env.compile_expression(probe['when'])
        self.assertTrue(cond(software_file_hashes={}, software_item={'inspection_paths': ['a', 'b']}))
        self.assertFalse(cond(software_file_hashes={'a': None, 'b': None}, software_item={'inspection_paths': ['b']}))
        self.assertFalse(cond(software_file_hashes={}, software_item={'inspection_paths': []}))
        execution = next(t for t in load('task_execute.yaml') if 'rescue' in t)
        result = next(t for t in execution['block'] if 'software_cleanup_hashes' in t.get('ansible.builtin.set_fact', {}))
        self.assertEqual(result['when'], "software_action != 'skip'")
        self.assertEqual(result['ansible.builtin.set_fact']['software_file_hashes'], {})
        self.assertEqual(execution['rescue'][0]['ansible.builtin.set_fact']['software_file_hashes'], {})
        self.assertIn('not ansible_check_mode', result['ansible.builtin.set_fact']['software_cleanup_hashes'])
        env.filters['combine'] = lambda a, b: dict(a, **b)
        queue = env.from_string(result['ansible.builtin.set_fact']['software_cleanup_hashes'])
        item = {'cache_path': 'a', 'artifact': {'checksum': 'hash'}}
        for check, action, expected in [(False, 'install', {'a': 'hash'}), (True, 'install', {}), (False, 'update_files', {}), (False, 'remove', {}), (False, 'recover', {'a': 'hash'})]:
            self.assertEqual(queue.render(software_cleanup_hashes={}, software_item=item, ansible_check_mode=check, software_action=action), expected)

    def test_absent_package_state_cleanup_is_not_reported(self):
        execution = next(t for t in load('task_execute.yaml') if 'rescue' in t)
        result = next(t for t in execution['block'] if 'software_cleanup_hashes' in t.get('ansible.builtin.set_fact', {}))
        env = NativeEnvironment(undefined=StrictUndefined)
        report = env.from_string(result['ansible.builtin.set_fact']['software_results'])
        previous = [{'id': 'other', 'status': 'error'}]
        for mode, action, count in [('exe', 'forget', 1), ('msi', 'forget', 1), ('msi', 'remove', 2), ('files', 'forget', 2)]:
            with self.subTest(mode=mode, action=action):
                actual = report.render(software_results=previous, software_action=action,
                                       software_item={'id': 'app', 'pattern': {'mode': mode}, 'artifact': {}, 'installed': {}},
                                       ansible_check_mode=False, software_verified={}, software_item_reboot=False)
                self.assertEqual(len(actual), count)
                self.assertEqual(actual[0], previous[0])

    def invoke_verify(self, op, snapshot, receipt=None):
        module = Mock()
        module.params = {'operation': 'verify_files' if op['pattern']['mode'] == 'files' else 'verify', 'item': op, 'files': op['files'], 'state': self.db, 'phase': 'done', 'snapshot': snapshot, 'receipt': receipt or {}, 'before': {}, 'hints': {}, 'reboot': False}
        def finish(**kwargs):
            raise SystemExit(0 if 'database' in kwargs else 1)
        module.exit_json.side_effect = finish
        module.fail_json.side_effect = lambda **kwargs: (_ for _ in ()).throw(SystemExit(1))
        basic = types.ModuleType('ansible.module_utils.basic')
        basic.AnsibleModule = Mock(return_value=module)
        utils = types.ModuleType('ansible.module_utils')
        utils.software_core = core
        ansible = types.ModuleType('ansible')
        ansible.module_utils = utils
        spec = importlib.util.spec_from_file_location('manager_test', ROOT / 'library/software_manager.py')
        manager = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {'ansible': ansible, 'ansible.module_utils': utils, 'ansible.module_utils.basic': basic}):
            spec.loader.exec_module(manager)
            with self.assertRaises(SystemExit) as error:
                manager.main()
        return error.exception.code, module

    def test_verify_and_prepare_state_only_on_success(self):
        op = self.plan([self.files('a.txt')])['operations'][0]
        f = op['files'][0]
        code, module = self.invoke_verify(op, {f['path']: f['checksum']})
        self.assertEqual(code, 0)
        self.assertEqual(module.exit_json.call_args.kwargs['database'], core.transition(self.db, op, 'done', op['files']))
        code, module = self.invoke_verify(op, {f['path']: None})
        self.assertEqual(code, 1)
        module.exit_json.assert_not_called()
        op = self.plan([{'id': 'app', 'regex': 'app-'}])['operations'][0]
        code, module = self.invoke_verify(op, {}, {'changed': True, 'rc': 0})
        self.assertEqual(code, 0)
        self.assertEqual(module.exit_json.call_args.kwargs['database']['products']['app']['status'], 'installer_reported')
        code, module = self.invoke_verify(op, {}, {'changed': False})
        self.assertEqual(code, 1)
        module.exit_json.assert_not_called()


if __name__ == '__main__':
    unittest.main()
