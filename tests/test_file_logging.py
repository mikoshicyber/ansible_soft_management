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
        text = self.render(execute['loop_control']['label'], software_index_label=label, software_item=item)
        self.assertEqual(text, 'Index 1/1: upgrade setup.exe')
        self.assertNotIn('SECRET', text)
        self.assertFalse(execute.get('no_log', False))

    def test_package_and_prepare_names(self):
        install, remove = [task for task in load('task_package.yaml') if 'ansible.windows.win_package' in task]
        item = {'id': 'example', 'artifact': {'filename': 'setup.exe'}, 'pattern': {'args': 'SECRET'}}
        self.assertIn('setup.exe', self.render(install['name'], software_item=item, software_index_label='Index 1/1'))
        self.assertNotIn('SECRET', self.render(install['name'], software_item=item, software_index_label='Index 1/1'))
        self.assertIn('Example', self.render(remove['name'], software_item={'id': 'example', 'installed': {'name': 'Example'}}, software_index_label='Index 1/1'))
        for task in (install, remove):
            self.assertTrue(task['no_log'])
        for task in load('task_package_prepare.yaml'):
            if 'win_copy' in ' '.join(task) or 'контрольную сумму' in task['name']:
                self.assertIn('setup.exe', self.render(task['name'], software_item=item, software_index_label='Index 1/1'))

    def test_file_batches_preserve_order_and_secrecy(self):
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
            self.assertTrue(task['no_log'])
            self.assertFalse(task['diff'])
            self.assertIn('bundle.zip', self.render(task['name'], software_item={'id': 'arc', 'artifact': {'filename': 'bundle.zip'}}, software_index_label='Index 1/1'))
        self.assertEqual(tasks[-1]['ansible.windows.win_powershell']['parameters']['Operation'], 'remove')

    def test_check_mode_logs_artifact_in_existing_task(self):
        tasks = load('task_execute.yaml')
        item = {'id': 'example', 'action': 'inspect', 'artifact': {'filename': 'bundle.zip'}}
        self.assertIn('bundle.zip', self.render(tasks[0]['name'], software_item=item, software_index_label='Index 1/1'))
        block = next(task for task in tasks if 'block' in task)
        self.assertFalse(any('ansible.builtin.debug' in t and t['tags'] == ['always'] for t in block['block']))
        decision = next(t for t in block['block'] if 'software_run_operation' in t.get('ansible.builtin.set_fact', {}))
        text = self.render(decision['name'], software_item=item, software_index_label='Index 1/1', software_action='update_files')
        self.assertIn('Index 1/1', text)
        self.assertIn('update_files: bundle.zip', text)
        self.assertTrue(self.env.compile_expression(decision['changed_when'])(ansible_check_mode=True, software_action='update_files'))
        self.assertFalse(self.env.compile_expression(decision['changed_when'])(ansible_check_mode=False, software_action='update_files'))

    def test_no_references_to_removed_helper(self):
        for path in [*ROOT.glob('*.yaml'), *ROOT.glob('*.yml')]:
            self.assertNotIn('task_file_write.yaml', path.read_text(encoding='utf-8'), path.name)


if __name__ == '__main__':
    unittest.main()
