import re
import sys
import unittest
from pathlib import Path

import yaml
from jinja2 import StrictUndefined
from jinja2.nativetypes import NativeEnvironment


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'module_utils'))
import software_core as core


def load(name):
    return yaml.safe_load((ROOT / name).read_text(encoding='utf-8'))


class PackageTimeoutTests(unittest.TestCase):
    def setUp(self):
        self.package = load('task_package.yaml')
        self.execute = next(task for task in load('task_execute.yaml') if 'block' in task)
        self.env = NativeEnvironment(undefined=StrictUndefined)
        self.env.filters['bool'] = bool
        self.env.tests['match'] = lambda value, pattern: re.match(pattern, value) is not None
        self.env.tests['search'] = lambda value, pattern, ignorecase=False: re.search(pattern, value, re.I if ignorecase else 0) is not None

    def render(self, template, **values):
        return self.env.from_string(template).render(**values)

    def timeout(self, pattern=None, **values):
        return self.render(self.execute['vars']['software_package_timeout_seconds'], software_item={'pattern': pattern or {}}, **values)

    def test_default_timeout(self):
        self.assertEqual(self.timeout(), 900)

    def test_global_timeout(self):
        self.assertEqual(self.timeout(software_package_timeout=600), 600)

    def test_package_override(self):
        self.assertEqual(self.timeout({'package_timeout': 1800}, software_package_timeout=600), 1800)

    def test_timeout_validation(self):
        for value in [5, 900, 86400, '600']:
            with self.subTest(value=value):
                self.assertEqual(core.timeout_value(value, 'timeout'), int(value))
        for value in [0, -1, 4, 86401, False, True, 0.5, 'abc', '900.5', None, '']:
            with self.subTest(value=value):
                with self.assertRaises(core.SoftwareError):
                    core.timeout_value(value, 'timeout')

    def test_install_remove_are_bounded(self):
        tasks = [task for task in self.package if 'ansible.windows.win_powershell' in task]
        self.assertEqual(len(tasks), 3)
        for task in tasks:
            self.assertNotIn('async', task)
            self.assertNotIn('poll', task)
            self.assertEqual(self.render(task['timeout'], software_package_timeout_seconds=600), 720)
            self.assertEqual(self.render(task['ansible.windows.win_powershell']['parameters']['TimeoutSeconds'], software_package_timeout_seconds=600), 600)
            self.assertIs(task['no_log'], True)
            self.assertNotIn('ignore_errors', task)
            self.assertIn('timed_out', task['failed_when'])

    def test_check_mode_and_pending_before_package(self):
        block = next(task for task in self.execute['block'] if 'block' in task and any(t.get('ansible.builtin.include_tasks', {}).get('file') == 'task_package.yaml' for t in task['block']))
        self.assertIn('not ansible_check_mode', block['when'])
        tasks = block['block']
        pending = next(i for i, task in enumerate(tasks) if task.get('vars', {}).get('software_phase') == 'pending')
        package = next(i for i, task in enumerate(tasks) if task.get('ansible.builtin.include_tasks', {}).get('file') == 'task_package.yaml')
        post = next(i for i, task in enumerate(tasks) if task.get('vars', {}).get('software_phase') == 'post')
        done = next(i for i, task in enumerate(tasks) if task.get('vars', {}).get('software_phase') == 'done')
        self.assertLess(pending, package)
        self.assertLess(package, post)
        self.assertLess(post, done)
        self.assertFalse(any(task.get('ansible.builtin.include_tasks', {}).get('file') == 'task_state.yaml' for task in self.execute['rescue']))

    def rescue_values(self, name, action, result):
        rescue = self.execute['rescue'][0]
        values = dict(software_results=[], software_item={'id': 'app', 'pattern': {'mode': 'msi'}}, software_action='install', software_package_timeout_seconds=900, software_hook_timeout_seconds=120, ansible_failed_task={'name': name, 'action': action}, ansible_failed_result=result)
        for key, expression in rescue['vars'].items():
            values[key] = self.render(expression, **values)
        return values, self.render(rescue['ansible.builtin.set_fact']['software_results'], **values)

    def test_timeout_report(self):
        for name in ['Install or upgrade package setup.exe', 'Remove package Example', 'Reapply MSI Example']:
            for result, confirmed in [({'timedout': {'frame': 'Interrupted', 'period': 1020}}, False), ({'msg': 'The ansible.windows.win_powershell action failed to execute in the expected time frame (1020) and was terminated'}, False), ({'result': {'timed_out': True, 'cleanup_confirmed': True}}, True), ({'result': {'timed_out': True, 'cleanup_confirmed': False}}, False)]:
                with self.subTest(name=name, result=result):
                    values, report = self.rescue_values(name, 'ansible.windows.win_powershell', result)
                    self.assertIs(values['software_failed_package_timeout'], True)
                    reason = 'package timeout (900 s); ' + ('installer job terminated' if confirmed else 'installer termination not confirmed')
                    self.assertEqual(report, [{'id': 'app', 'status': 'error', 'action': 'install', 'filename': 'app', 'reason': reason, 'timed_out': True}])
                    self.assertTrue(self.render(self.execute['rescue'][0]['ansible.builtin.set_fact']['software_reboot_deferred'], **values))

    def test_other_failures_are_not_timeouts(self):
        for name, action, result in [('Install or upgrade package app', 'ansible.windows.win_powershell', {'result': {'rc': 1603}}), ('Check file', 'ansible.windows.win_powershell', {'timedout': {'period': 900}}), ('PRE', 'ansible.windows.win_shell', {'timedout': {'period': 900}})]:
            values, _ = self.rescue_values(name, action, result)
            self.assertIs(values['software_failed_package_timeout'], False)

    def test_secret_not_copied_into_report(self):
        result = {'result': {'rc': 1603}, 'msg': 'password=SECRET', 'stdout': 'SECRET', 'stderr': 'SECRET', 'invocation': {'arguments': 'SECRET'}}
        _, report = self.rescue_values('Install or upgrade package app', 'ansible.windows.win_powershell', result)
        self.assertEqual(report[0]['reason'], 'Install or upgrade package app; rc=1603')
        self.assertNotIn('SECRET', str(report))

    def test_msi_busy_defers_reboot(self):
        values, report = self.rescue_values('Install or upgrade package app', 'ansible.windows.win_powershell', {'result': {'rc': 1618}})
        self.assertFalse(report[0]['timed_out'])
        self.assertTrue(self.render(self.execute['rescue'][0]['ansible.builtin.set_fact']['software_reboot_deferred'], **values))


if __name__ == '__main__':
    unittest.main()
