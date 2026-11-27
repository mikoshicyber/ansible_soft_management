import re
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import yaml
from jinja2 import StrictUndefined
from jinja2.nativetypes import NativeEnvironment

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'module_utils'))
import software_core as core


def walk(tasks):
    for task in tasks:
        yield task
        for key in ('block', 'rescue', 'always'):
            yield from walk(task.get(key, []))


class HookFixTests(unittest.TestCase):
    def setUp(self):
        self.env = NativeEnvironment(undefined=StrictUndefined)
        self.env.filters['bool'] = bool
        self.env.tests['search'] = lambda value, pattern, ignorecase=False: re.search(pattern, value, re.I if ignorecase else 0) is not None
        self.execute = next(t for t in yaml.safe_load((ROOT / 'task_execute.yaml').read_text()) if 'block' in t)
        self.tasks = list(walk([self.execute]))
        self.hooks = [t for t in self.tasks if 'ansible.windows.win_shell' in t]

    def test_only_simple_hooks_are_special(self):
        values = ['sc stop tor', 'SC.EXE start "Windows Exporter"', 'taskkill /im aimp* /f', 'TASKKILL.EXE /F /IM "keepass.exe"', 'taskkill /im soffice.* /f', 'sc stop tor && sc start tor', 'taskkill /f /im app.exe /t', 'taskkill /f /im *.EXE', 'taskkill /f /im *', 'regedit /s C:\\temp\\hide.reg']
        hooks = core.hook_commands(values)
        self.assertEqual([h['command'] for h in hooks], values)
        self.assertEqual([h['kind'] for h in hooks], ['service', 'service', 'process', 'process', 'process', 'command', 'command', 'command', 'command', 'command'])
        self.assertEqual(hooks[0]['accepted_rc'], [0, 1060, 1062])
        self.assertEqual(hooks[1]['accepted_rc'], [0, 1056])
        self.assertEqual([h['image'] for h in hooks[2:5]], ['aimp*', 'keepass.exe', 'soffice.*'])
        pattern = core.merge([{'patterns': [{'regex': 'app', 'pre': values, 'post': 'sc start tor'}]}], r'C:\Apps')[0]
        self.assertEqual(pattern['pre_commands'], hooks)
        self.assertEqual(pattern['post_commands'], core.hook_commands(['sc start tor']))

    def test_return_codes_and_changed(self):
        cases = [('sc stop tor', 1062, '', False, False), ('sc stop tor', 1060, '', False, False), ('sc stop tor', 0, '', False, True), ('sc start tor', 1056, '', False, False), ('sc start tor', 1060, '', True, False), ('sc stop tor', 5, '', True, False), ('sc stop tor', 1056, '', True, False), ('taskkill /im aimp* /f', 0, 'SOFTWARE_MANAGER_NO_PROCESS\r\n', False, False), ('taskkill /f /im app.exe', 0, '', False, True), ('taskkill /f /im app.exe', 1, '', True, False), ('other.exe', 1062, '', True, False)]
        for task in self.hooks:
            for command, rc, stdout, failed, changed in cases:
                with self.subTest(task=task['register'], command=command, rc=rc):
                    args = {'software_command': core.hook_commands([command])[0], task['register']: {'rc': rc, 'stdout': stdout}}
                    self.assertEqual(self.env.compile_expression(task['failed_when'])(**args), failed)
                    self.assertEqual(self.env.compile_expression(task['changed_when'])(**args), changed)
            for result in ({}, {'rc': 1062, 'msg': 'launch failed'}):
                self.assertTrue(self.env.compile_expression(task['failed_when'])(software_command=core.hook_commands(['sc stop tor'])[0], **{task['register']: result}))

    def test_shell_selection_and_command_rendering(self):
        self.env.globals['lookup'] = lambda *_args, **_kw: (ROOT / 'scripts/stop_process.ps1').read_text()
        for task in self.hooks:
            for cmd in ['sc stop tor', 'taskkill /im "keepass.exe" /f', 'echo a & echo b']:
                hook = core.hook_commands([cmd])[0]
                args = {'software_command': hook, 'playbook_dir': str(ROOT)}
                text = self.env.from_string(task['ansible.windows.win_shell']).render(**args)
                shell = self.env.from_string(task['args']['executable']).render(**args)
                if hook['kind'] == 'process':
                    self.assertEqual(shell, 'powershell')
                    self.assertTrue(text.startswith("$image = 'keepass.exe';\n"))
                    self.assertIn('Stop-Process -InputObject $process -Force -ErrorAction Stop', text)
                else:
                    self.assertEqual(shell, 'cmd.exe')
                    self.assertEqual(text, cmd)

    def test_hook_timeout_and_error_report(self):
        expr = self.execute['vars']['software_hook_timeout_seconds']
        for pattern, globals_, expected in [({}, {}, 120), ({}, {'software_hook_timeout': 180}, 180), ({'hook_timeout': 300}, {'software_hook_timeout': 180}, 300)]:
            self.assertEqual(self.env.from_string(expr).render(software_item={'pattern': pattern}, **globals_), expected)
        for task in self.hooks:
            self.assertEqual(self.env.from_string(task['timeout']).render(software_hook_timeout_seconds=120), 120)
        rescue = self.execute['rescue'][0]
        for result, expected, timeout in [({'results': [{'failed': False, 'rc': 0}, {'failed': True, 'rc': 5, 'msg': 'non-zero return code', 'stdout': 'Access denied', 'software_command': {'kind': 'service'}}]}, 'rc=5; non-zero return code; Access denied', False), ({'results': [{'failed': True, 'timedout': {'period': 120}}]}, 'hook timeout (120 s)', True)]:
            values = dict(ansible_failed_task={'name': 'PRE', 'action': 'ansible.windows.win_shell'}, ansible_failed_result=result, software_package_timeout_seconds=900, software_hook_timeout_seconds=120, software_results=[], software_item={'id': 'app', 'pattern': {'mode': 'exe'}}, software_action='upgrade')
            for key, value in rescue['vars'].items():
                values[key] = self.env.from_string(value).render(**values)
            self.assertIn(expected, values['software_error_reason'])
            self.assertEqual(values['software_failed_hook_timeout'], timeout)
            report = self.env.from_string(rescue['ansible.builtin.set_fact']['software_results']).render(**values)
            self.assertEqual(report[0]['timed_out'], timeout)
            self.assertEqual(self.env.from_string(rescue['ansible.builtin.set_fact']['software_reboot_deferred']).render(**values), timeout)

    def test_metadata_refresh_without_reinstall(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)
            for mode, ext in [('exe', '.exe'), ('arc', '.zip')]:
                with self.subTest(mode=mode):
                    old = source / ('app-1.0' + ext)
                    new = source / ('app-2.0' + ext)
                    if mode == 'arc':
                        with zipfile.ZipFile(old, 'w') as zf:
                            zf.writestr('app.bin', b'abc')
                    else:
                        old.write_bytes(b'abc')
                    dest = r'C:\Apps'
                    pattern = core.merge([{'patterns': [{'id': 'app', 'regex': r'app-.*' + re.escape(ext) + '$', 'mode': mode, 'pre': ['sc stop app'], 'post': ['sc start app']}]}], dest)
                    db = core.normalize_state({})
                    def plan():
                        return core.make_plan(pattern, core.index(source), tmp, {'installed': []}, db, dest)
                    op = plan()['operations'][0]
                    db = core.transition(db, op, 'done', op['files'], verified={'verification': 'installer_result', 'installer_changed': True, 'installed_version': '1.0'} if mode == 'exe' else {})
                    old.rename(new)
                    result = plan()
                    self.assertEqual(result['operations'], [])
                    self.assertEqual(len(result['warnings']), 1)
                    self.assertEqual(db['products']['app']['version'], '1.0')
                    refreshed = result['state_refresh']['app']
                    self.assertEqual(refreshed['version'], '2.0')
                    if mode == 'exe':
                        self.assertEqual(refreshed['artifact_version'], '2.0')
                        self.assertEqual(refreshed['installed_version'], '1.0')
                    self.assertEqual(refreshed['checksum'], db['products']['app']['checksum'])
                    self.assertEqual(refreshed['status'], db['products']['app']['status'])
                    db['products'].update(result['state_refresh'])
                    self.assertEqual(plan()['warnings'], [])
                    self.assertEqual(plan()['state_refresh'], {})
                    new.unlink()

    def test_checkpoint_and_debug_guards(self):
        post = next(t for t in self.tasks if t.get('vars', {}).get('software_phase') == 'post')
        for action, mode, hooks, expected in [('install', 'exe', [], False), ('upgrade', 'msi', [], False), ('upgrade', 'exe', ['post'], True), ('update_files', 'arc', [], True), ('remove', 'msi', [], False), ('remove', 'msi', ['post'], True)]:
            args = dict(software_run_operation=True, software_action=action, software_item_reboot=False, software_item={'pattern': {'mode': mode, 'post': hooks}})
            self.assertEqual(all(self.env.compile_expression(c)(**args) for c in post['when']), expected)
        self.assertTrue(all(self.env.compile_expression(c)(software_run_operation=True, software_action='remove', software_item_reboot=True, software_item={'pattern': {'mode': 'msi', 'post': []}}) for c in post['when']))
        for file in [*ROOT.glob('task_*.yaml'), ROOT / 'telegram.yaml']:
            if '_v2' in file.name:
                continue
            for task in walk(yaml.safe_load(file.read_text())):
                if task.get('tags') == ['never', 'debug']:
                    cond = self.env.compile_expression(task['when'])
                    self.assertFalse(cond(ansible_run_tags=['all']))
                    self.assertFalse(cond(ansible_run_tags=['always']))
                    self.assertTrue(cond(ansible_run_tags=['debug']))
        windows = yaml.safe_load((ROOT / 'task_windows.yaml').read_text())
        for task in windows:
            if 'batch installer transfer' in task['name'] or 'batch transfer' in task['name'] or 'Transfer installers in batch' in task['name']:
                self.assertNotIn('artifact.filename', task['name'])


if __name__ == '__main__':
    unittest.main()
