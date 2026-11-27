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
        tasks = [task for task in self.package if 'ansible.windows.win_package' in task]
        self.assertEqual(len(tasks), 2)
        for task in tasks:
            self.assertNotIn('async', task)
            self.assertNotIn('poll', task)
            self.assertEqual(self.render(task['timeout'], software_package_timeout_seconds=600), 600)
            self.assertIs(task['no_log'], False)
            self.assertNotIn('ignore_errors', task)
            self.assertNotIn('failed_when', task)

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

    def test_timeout_report(self):
        rescue = self.execute['rescue'][0]
        template = rescue['vars']['software_failed_package_timeout']
        for name in ['Install or upgrade package setup.exe', 'Remove package Example', 'Another task name']:
            for result in [{'timedout': {'frame': 'Interrupted', 'period': 900}}, {'msg': 'The ansible.windows.win_package action failed to execute in the expected time frame (900) and was terminated'}]:
                with self.subTest(name=name, result=result):
                    timed_out = self.render(template, ansible_failed_task={'name': name, 'action': 'ansible.windows.win_package'}, ansible_failed_result=result)
                    self.assertIs(timed_out, True)
                    values = dict(software_results=[], software_item={'id': 'app'}, software_action='install', software_package_timeout_seconds=900, software_hook_timeout_seconds=120, ansible_failed_task={'name': name, 'action': 'ansible.windows.win_package'}, ansible_failed_result=result)
                    for key, expression in rescue['vars'].items():
                        values[key] = self.render(expression, **values)
                    report = self.render(rescue['ansible.builtin.set_fact']['software_results'], **values)
                    self.assertEqual(report, [{'id': 'app', 'status': 'error', 'action': 'install', 'filename': 'app', 'reason': 'package timeout (900 s)', 'timed_out': True}])

    def test_other_failures_are_not_timeouts(self):
        template = self.execute['rescue'][0]['vars']['software_failed_package_timeout']
        for action, message in [('ansible.windows.win_package', 'unexpected return code'), ('ansible.windows.win_shell', 'The action failed to execute in the expected time frame (900)'), ('ansible.windows.win_package', '')]:
            self.assertIs(self.render(template, ansible_failed_task={'name': 'any', 'action': action}, ansible_failed_result={'msg': message}), False)


if __name__ == '__main__':
    unittest.main()
