import unittest
from pathlib import Path

import yaml
from jinja2 import StrictUndefined
from jinja2.nativetypes import NativeEnvironment


ROOT = Path(__file__).resolve().parents[1]


def load(name):
    return yaml.safe_load((ROOT / name).read_text(encoding='utf-8'))


class FileLoggingTests(unittest.TestCase):
    def setUp(self):
        self.env = NativeEnvironment(undefined=StrictUndefined)

    def render(self, template, **values):
        return self.env.from_string(template).render(**values)

    def package_label(self, item):
        execute = next(t for t in load('task_windows.yaml') if t.get('ansible.builtin.include_tasks', {}).get('file') == 'task_execute.yaml')
        return self.render(execute['vars']['software_package_label'], software_item=item)

    def render_package_name(self, template, item, **values):
        return self.render(template, software_item=item, software_package_label=self.package_label(item), **values)

    def test_index_replaces_start_debug(self):
        tasks = load('task_package.yaml')
        self.assertFalse(any('ansible.builtin.debug' in task and task['tags'] == ['always'] for task in tasks))
        execute = next(t for t in load('task_windows.yaml') if t.get('ansible.builtin.include_tasks', {}).get('file') == 'task_execute.yaml')
        item = {'id': 'example', 'action': 'upgrade', 'artifact': {'filename': 'setup.exe'}, 'pattern': {'args': 'SECRET'}}
        plan = {'operations': [item]}
        self.assertEqual(self.render(execute['loop'], software_plan=plan), [0])
        self.assertEqual(execute['loop_control']['loop_var'], 'software_index')
        self.assertEqual(self.render(execute['vars']['software_item'], software_plan=plan, software_index=0), item)
        label = self.render(execute['vars']['software_index_label'], software_plan=plan, software_index=0)
        self.assertEqual(label, 'Index 1/1')
        text = self.render_package_name(execute['loop_control']['label'], item, software_index_label=label)
        self.assertEqual(text, 'Index 1/1: upgrade setup.exe')
        self.assertNotIn('SECRET', text)
        self.assertFalse(execute.get('no_log', False))

    def test_package_and_prepare_names(self):
        install, remove = [task for task in load('task_package.yaml') if task.get('ansible.windows.win_powershell', {}).get('parameters', {}).get('Operation') in ('install', 'remove')]
        item = {'id': 'example', 'artifact': {'filename': 'setup.exe'}, 'pattern': {'args': 'SECRET'}}
        self.assertIn('setup.exe', self.render_package_name(install['name'], item, software_index_label='Index 1/1'))
        self.assertNotIn('SECRET', self.render_package_name(install['name'], item, software_index_label='Index 1/1'))
        self.assertIn('Example', self.render_package_name(remove['name'], {'id': 'example', 'installed': {'name': 'Example'}}, software_index_label='Index 1/1'))
        for task in (install, remove):
            self.assertIs(task['no_log'], True)
        for task in load('task_package_prepare.yaml'):
            if 'win_copy' in ' '.join(task) or 'checksum' in task['name']:
                self.assertIn('setup.exe', self.render_package_name(task['name'], item, software_index_label='Index 1/1'))

    def test_file_batches_preserve_order_and_disable_diff(self):
        tasks = load('task_files.yaml')
        self.assertFalse(any('ansible.builtin.include_tasks' in task or 'ansible.builtin.debug' in task for task in tasks))
        stage = next(t for t in tasks if t.get('software_manager', {}).get('operation') == 'stage_files')
        copy = next(t for t in tasks if 'ansible.windows.win_copy' in t)
        template = next(t for t in tasks if t.get('ansible.windows.win_powershell', {}).get('parameters', {}).get('Operation') == 'template')
        self.assertEqual(stage['delegate_to'], 'localhost')
        items = [{'path': 'template', 'content_b64': 'SECRET'}, {'path': 'binary'}]
        self.assertEqual(self.render(stage['software_manager']['files'], software_effective_files=items), [items[1]])
        self.assertEqual(self.render(template['loop'], software_effective_files=items), [items[0]])
        self.assertNotIn('loop', copy)
        self.assertLess(tasks.index(stage), tasks.index(copy))
        self.assertLess(tasks.index(copy), tasks.index(template))
        for task in (copy, template):
            self.assertIs(task['no_log'], True)
            self.assertFalse(task['diff'])
            self.assertIn('bundle.zip', self.render_package_name(task['name'], {'id': 'arc', 'artifact': {'filename': 'bundle.zip'}}, software_index_label='Index 1/1'))
        self.assertEqual(tasks[-1]['ansible.windows.win_powershell']['parameters']['Operation'], 'remove')

    def test_check_mode_logs_artifact_in_existing_task(self):
        tasks = load('task_execute.yaml')
        item = {'id': 'example', 'action': 'inspect', 'artifact': {'filename': 'bundle.zip'}}
        self.assertIn('bundle.zip', self.render_package_name(tasks[0]['name'], item, software_index_label='Index 1/1'))
        block = next(task for task in tasks if 'block' in task)
        self.assertFalse(any('ansible.builtin.debug' in t and t['tags'] == ['always'] for t in block['block']))
        decision = next(t for t in block['block'] if 'software_run_operation' in t.get('ansible.builtin.set_fact', {}))
        text = self.render_package_name(decision['name'], item, software_index_label='Index 1/1', software_action='update_files')
        self.assertIn('Index 1/1', text)
        self.assertIn('update_files: bundle.zip', text)
        self.assertTrue(self.env.compile_expression(decision['changed_when'])(ansible_check_mode=True, software_action='update_files'))
        self.assertFalse(self.env.compile_expression(decision['changed_when'])(ansible_check_mode=False, software_action='update_files'))

    def test_sensitive_tasks_are_hidden(self):
        def walk(tasks):
            for task in tasks:
                yield task
                for key in ('block', 'rescue', 'always'):
                    yield from walk(task.get(key, []))
        sensitive_operations = {'normalize', 'discover_msi', 'plan', 'prepare', 'stage_packages', 'stage_files', 'plan_files', 'prune_files', 'verify', 'verify_files', 'transition'}
        for name in ('task_windows.yaml', 'task_execute.yaml', 'task_file_plan.yaml', 'task_files.yaml', 'task_state.yaml', 'task_verify.yaml', 'task_file_verify.yaml'):
            for task in walk(load(name)):
                operation = task.get('software_manager', {}).get('operation')
                parameters = task.get('ansible.windows.win_powershell', {}).get('parameters', {})
                facts = task.get('ansible.builtin.set_fact', {})
                if operation in sensitive_operations or parameters.get('Operation') in ('read', 'write', 'template') or 'ansible.windows.win_shell' in task or any(key in facts and bool(facts[key]) for key in ('software_layers', 'software_effective_files', 'software_state_current', 'software_preflight_rendered')):
                    with self.subTest(name=name, task=task['name']):
                        self.assertIs(task.get('no_log'), True)
                if 'ansible.windows.win_shell' in task:
                    self.assertNotIn('software_command.command', task['loop_control']['label'])

    def test_no_references_to_removed_helper(self):
        for path in [*ROOT.glob('*.yaml'), *ROOT.glob('*.yml')]:
            self.assertNotIn('task_file_write.yaml', path.read_text(encoding='utf-8'), path.name)


if __name__ == '__main__':
    unittest.main()
