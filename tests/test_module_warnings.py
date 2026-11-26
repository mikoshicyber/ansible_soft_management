import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


class ModuleWarningTests(unittest.TestCase):
    def run_plan(self, warnings):
        module = Mock()
        module.params = {
            'operation': 'plan', 'state': {}, 'patterns': [], 'catalog': [],
            'source': '/source', 'snapshot': {}, 'dest': r'C:\Apps',
            'cache_dir': None,
        }
        emitted = []
        payload = {}

        def warn(message):
            if not isinstance(message, str):
                raise TypeError(f'warn requires a string not a {type(message)}')
            emitted.append(message)

        def exit_json(**result):
            for warning in result.get('warnings', []):
                warn(warning)
            payload.update(result)
            raise SystemExit(0)

        module.warn.side_effect = warn
        module.exit_json.side_effect = exit_json
        module.fail_json.side_effect = lambda **kwargs: self.fail(str(kwargs))
        core = Mock()
        core.normalize_state.return_value = {'products': {}}
        core.make_plan.return_value = {'operations': [], 'warnings': warnings}
        basic = types.ModuleType('ansible.module_utils.basic')
        basic.AnsibleModule = Mock(return_value=module)
        utils = types.ModuleType('ansible.module_utils')
        utils.software_core = core
        ansible = types.ModuleType('ansible')
        ansible.module_utils = utils
        spec = importlib.util.spec_from_file_location('software_manager_test', ROOT / 'library/software_manager.py')
        manager = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {'ansible': ansible, 'ansible.module_utils': utils, 'ansible.module_utils.basic': basic}):
            spec.loader.exec_module(manager)
            with self.assertRaises(SystemExit) as exc:
                manager.main()
        self.assertEqual(exc.exception.code, 0)
        self.assertNotIn('warnings', payload)
        self.assertEqual(payload['plan_warnings'], warnings)
        self.assertEqual(emitted, [f"{w['filename']}: {w['reason']}" for w in warnings])
        module.fail_json.assert_not_called()

    def test_no_warnings(self):
        self.run_plan([])

    def test_structured_warnings(self):
        self.run_plan([
            {'id': 'a', 'filename': 'app-2.exe', 'action': 'skip', 'status': 'warning', 'reason': 'Version differs but SHA-256 matches'},
            {'id': 'b', 'filename': 'other.exe', 'action': 'upgrade', 'status': 'warning', 'reason': 'Version matches but SHA-256 differs'},
        ])

    def test_report_uses_structured_field(self):
        text = (ROOT / 'task_windows.yaml').read_text()
        self.assertIn('software_plan.plan_warnings | default([])', text)
        self.assertNotIn('software_plan.warnings', text)


if __name__ == '__main__':
    unittest.main()
