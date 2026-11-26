import unittest
from pathlib import Path

import yaml
from jinja2 import StrictUndefined
from jinja2.nativetypes import NativeEnvironment


ROOT = Path(__file__).resolve().parents[1]


def load(name):
    return yaml.safe_load((ROOT / name).read_text(encoding='utf-8'))


class CleanupWarningTests(unittest.TestCase):
    def setUp(self):
        self.operation = next(task for task in load('task_execute.yaml') if 'block' in task)
        self.execution = next(task for task in self.operation['block'] if 'block' in task)
        self.env = NativeEnvironment(undefined=StrictUndefined)
        self.env.tests['failed'] = lambda result: result.get('failed', False)

    def check_warning(self, tasks, index, expected_register):
        cleanup, warning = tasks[index:index + 2]
        self.assertIs(cleanup['ignore_errors'], True)
        self.assertEqual(cleanup['register'], expected_register)
        self.assertEqual(warning['when'], expected_register + ' is failed')
        self.assertEqual(warning['tags'], ['always'])
        self.assertNotIn('ansible.builtin.set_fact', warning)
        self.assertNotIn('software_results', str(warning))
        condition = self.env.compile_expression(warning['when'])
        for result, expected in [({'failed': True}, True), ({'changed': True}, False), ({'skipped': True}, False)]:
            self.assertEqual(condition(**{expected_register: result}), expected)
        for result in [{'failed': True, 'msg': 'Access denied'}, {'failed': True, 'error': [{'output': 'File locked'}]}, {'failed': True}]:
            message = self.env.from_string(warning['ansible.builtin.debug']['msg']).render(software_package_label='app.exe', **{expected_register: result})
            self.assertIn('WARNING:', message)
            if 'msg' in result:
                self.assertIn(result['msg'], message)
            if 'error' in result and expected_register != 'software_cleanup':
                self.assertIn('File locked', message)

    def test_installer_cleanup_is_nonfatal_after_state_commit(self):
        tasks = self.execution['block']
        done = next(i for i, task in enumerate(tasks) if task.get('vars', {}).get('software_phase') == 'done')
        cleanup = next(i for i, task in enumerate(tasks) if task.get('ansible.windows.win_powershell', {}).get('parameters', {}).get('Operation') == 'cleanup_package')
        self.assertLess(done, cleanup)
        self.assertIn("software_action in ['install', 'upgrade', 'recover']", tasks[cleanup]['when'])
        self.assertIn('ExpectedHashes', tasks[cleanup]['ansible.windows.win_powershell']['parameters'])
        self.assertIn('not ansible_check_mode', self.execution['when'])
        self.check_warning(tasks, cleanup, 'software_package_cleanup')
        result = next(task for task in self.operation['block'] if 'Зарегистрировать результат продукта' in task['name'])
        self.assertIn('software_results', result['ansible.builtin.set_fact'])
        self.assertNotIn('software_package_cleanup', str(result))

    def test_empty_cache_cleanup(self):
        tasks = load('task_windows.yaml')
        index = next(i for i, task in enumerate(tasks) if task.get('ansible.windows.win_powershell', {}).get('parameters', {}).get('Operation') == 'prune_cache')
        self.assertEqual(tasks[index]['when'], 'not ansible_check_mode')
        self.check_warning(tasks, index, 'software_cache_cleanup')

    def test_controller_extraction_cleanup(self):
        tasks = self.operation['always']
        self.check_warning(tasks, 0, 'software_cleanup')
        self.assertIn('not ansible_check_mode', tasks[0]['when'])

    def test_real_operation_errors_are_still_reported(self):
        rescue = self.operation['rescue'][0]['ansible.builtin.set_fact']
        self.assertIn("'status': 'error'", rescue['software_results'])
        for task in self.execution['block']:
            if task.get('ansible.builtin.include_tasks', {}).get('file') in ('task_package.yaml', 'task_state.yaml', 'task_verify.yaml'):
                self.assertFalse(task.get('ignore_errors', False))


if __name__ == '__main__':
    unittest.main()
