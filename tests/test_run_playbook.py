import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'run_playbook.py'
SPEC = importlib.util.spec_from_file_location('run_playbook', SCRIPT)
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


def listing(*hosts):
    return ('\nplaybook: playbook.yml\n'
            '  play #1 (localhost): Index artifacts\tTAGS: []\n'
            '    pattern: [\'localhost\']\n    hosts (0):\n'
            '  play #2 (all,localhost): Manage Windows software\tTAGS: []\n'
            f'    pattern: [\'all\', \'localhost\']\n    hosts ({len(hosts)}):\n'
            + ''.join(f'      {host}\n' for host in hosts)
            + '  play #3 (localhost): Final report\tTAGS: []\n    hosts (0):\n')


class LauncherTests(unittest.TestCase):
    def test_ansible_python_reexec(self):
        output = '  python version = 3.12.12 (main, Mar 9 2026) (/usr/bin/python3.12)\n'
        with patch.object(launcher.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, output)), patch.object(launcher.os.path, 'isfile', return_value=True), patch.object(launcher.os, 'access', return_value=True), patch.object(launcher.sys, 'executable', '/usr/bin/python3.9'), patch.object(launcher.sys, 'argv', ['run_playbook.py', '--limit', 'a-pc', '--check']), patch.object(launcher.os, 'execv') as execute:
            launcher.ensure_ansible_python()
            execute.assert_called_once_with('/usr/bin/python3.12', ['/usr/bin/python3.12', str(SCRIPT), '--limit', 'a-pc', '--check'])

    def test_ansible_python_already_correct(self):
        output = f'  python version = 3.12.12 (main) ({sys.executable})\n'
        with patch.object(launcher.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, output)), patch.object(launcher.os, 'execv') as execute:
            launcher.ensure_ansible_python()
            execute.assert_not_called()

    def test_ansible_python_invalid_output(self):
        with patch.object(launcher.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'invalid')), self.assertRaisesRegex(RuntimeError, 'Unable to determine Python'):
            launcher.ensure_ansible_python()

    def test_ansible_python_failed_command(self):
        with patch.object(launcher.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '')), self.assertRaisesRegex(RuntimeError, 'exit code 1'):
            launcher.ensure_ansible_python()

    def test_ansible_python_not_executable(self):
        output = '  python version = 3.12.12 (main) (/missing/python)\n'
        with patch.object(launcher.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, output)), self.assertRaisesRegex(RuntimeError, 'not executable'):
            launcher.ensure_ansible_python()

    def test_selected_hosts(self):
        self.assertEqual(launcher.parse_hosts(listing('b-pc', 'localhost', 'a-pc')), ['a-pc', 'b-pc'])

    def test_empty_selection(self):
        self.assertEqual(launcher.parse_hosts(listing()), [])

    def test_invalid_listing(self):
        for text in ('invalid', listing('a').replace('hosts (1)', 'hosts (2)'), listing('a', 'a'), listing('all,!a')):
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                launcher.parse_hosts(text)

    def test_only_localhost(self):
        with patch.object(launcher.subprocess, 'run') as run:
            self.assertEqual(launcher.select_hosts([], 'localhost', {}), [])
            run.assert_not_called()

    def test_native_limit_selection(self):
        for limit in ('a-pc', 'windows:&office:!disabled', '@hosts.txt'):
            with self.subTest(limit=limit), patch.object(launcher.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, listing('a-pc'))) as run:
                args = ['playbook.yml', '--limit', limit, '--check']
                self.assertEqual(launcher.select_hosts(args, limit, {}), ['a-pc'])
                self.assertEqual(run.call_args.args[0], ['ansible-playbook', *args, '--list-hosts'])

    def test_preview_failure(self):
        with patch.object(launcher.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '')):
            with self.assertRaises(RuntimeError):
                launcher.select_hosts([], 'unknown', {})

    def test_add_option_before_separator(self):
        self.assertEqual(launcher.add_option(['--limit=x', '--', 'playbook.yml'], '--limit='), ['--limit=x', '--limit=', '--', 'playbook.yml'])

    def test_missing_files(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(RuntimeError, 'installed_software.ps1'):
            launcher.preflight(Path(directory))

    def test_denied_files(self):
        with patch.object(launcher.os, 'access', return_value=False), self.assertRaisesRegex(RuntimeError, 'library'):
            launcher.preflight(SCRIPT.parents[1])

    def invoke(self, limit=None, syntax=False, skip_tags=None, step=False, start=None):
        cli_options = types.SimpleNamespace(args=[str(SCRIPT.parents[1] / 'playbook.yml')], skip_tags=skip_tags, start_at_task=start, step=step, subset=limit, syntax=syntax)
        cli_module = types.ModuleType('ansible.cli.playbook')
        cli_module.PlaybookCLI = lambda args: types.SimpleNamespace(init_parser=lambda: None, parser=types.SimpleNamespace(parse_args=lambda args: cli_options))
        with patch.dict(sys.modules, {'ansible': types.ModuleType('ansible'), 'ansible.cli': types.ModuleType('ansible.cli'), 'ansible.cli.playbook': cli_module}), patch.object(launcher, 'preflight'), patch.object(launcher, 'select_hosts', return_value=['a-pc']) as select, patch.object(launcher.os, 'execvpe') as execute, patch.dict(os.environ, {launcher.TARGET_ENV: '["stale"]'}):
            launcher.main(['-i', 'inventory.yaml', 'playbook.yml', '--check'])
            return select, execute

    def test_main_limit(self):
        select, execute = self.invoke(limit='windows:&office')
        select.assert_called_once()
        command, args, env = execute.call_args.args
        self.assertEqual(command, 'ansible-playbook')
        self.assertEqual(args[-1], '--limit=')
        self.assertEqual(json.loads(env[launcher.TARGET_ENV]), ['a-pc', 'localhost'])

    def test_main_no_limit(self):
        select, execute = self.invoke()
        select.assert_not_called()
        self.assertNotIn(launcher.TARGET_ENV, execute.call_args.args[2])
        self.assertEqual(execute.call_args.args[1][-1], '--check')

    def test_main_rejects_skip(self):
        for options in ({'skip_tags': ['debug,always']}, {'step': True}, {'start': 'task'}):
            with self.subTest(options=options), self.assertRaisesRegex(RuntimeError, 'skip required'):
                self.invoke(**options)

    def test_syntax_check(self):
        select, execute = self.invoke(limit='a-pc', syntax=True)
        select.assert_not_called()
        execute.assert_called_once()


if __name__ == '__main__':
    unittest.main()
