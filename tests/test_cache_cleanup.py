import os
import shutil
import subprocess
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load(name):
    return yaml.safe_load((ROOT / name).read_text(encoding='utf-8'))


class CacheCleanupTests(unittest.TestCase):
    def test_cleanup_queue_after_commit_and_file_removal(self):
        operation = next(task for task in load('task_execute.yaml') if 'block' in task)
        execution = next(task for task in operation['block'] if 'block' in task and any(t.get('ansible.builtin.include_tasks', {}).get('file') == 'task_package.yaml' for t in task['block']))
        self.assertIn('not ansible_check_mode', execution['when'])
        self.assertTrue(any(t.get('vars', {}).get('software_phase') == 'done' for t in execution['block']))
        queue = next(t for t in operation['block'] if 'software_cleanup_hashes' in t.get('ansible.builtin.set_fact', {}))
        self.assertLess(operation['block'].index(execution), operation['block'].index(queue))
        self.assertIn('software_item.cache_path', queue['ansible.builtin.set_fact']['software_cleanup_hashes'])
        self.assertIn('not ansible_check_mode', queue['ansible.builtin.set_fact']['software_cleanup_hashes'])
        self.assertFalse(any(t.get('ansible.windows.win_powershell', {}).get('parameters', {}).get('Operation') in ('remove', 'prune_cache', 'cleanup_package', 'cleanup_packages') for t in execution['block']))

    def test_final_cleanup_runs_before_reboot_and_completion(self):
        tasks = load('task_windows.yaml')
        execute = next(i for i, task in enumerate(tasks) if task.get('ansible.builtin.include_tasks', {}).get('file') == 'task_execute.yaml')
        prune = next(i for i, task in enumerate(tasks) if task.get('ansible.windows.win_powershell', {}).get('parameters', {}).get('Operation') == 'cleanup_packages')
        reboot = next(i for i, task in enumerate(tasks) if 'ansible.windows.win_reboot' in task)
        self.assertLess(execute, prune)
        self.assertLess(prune, reboot)
        self.assertIn('not ansible_check_mode', tasks[prune]['when'])
        self.assertTrue(tasks[prune]['ignore_errors'])
        self.assertEqual(tasks[prune]['ansible.windows.win_powershell']['parameters'], {'Operation': 'cleanup_packages', 'ManagedRoot': '{{ dest }}', 'Paths': '{{ software_cleanup_hashes.keys() | list }}', 'ExpectedHashes': '{{ software_cleanup_hashes }}'})
        self.assertIn('software_cache_cleanup is failed', tasks[prune + 1]['when'])
        self.assertEqual(tasks[prune + 2]['tags'], ['never', 'debug'])

    def test_script_uses_nonrecursive_deletion_and_path_guards(self):
        script = (ROOT / 'scripts/filesystem.ps1').read_text(encoding='utf-8')
        prune = script.split("function Remove-EmptyCacheDirectories", 1)[1].split("function Remove-CachedInstaller", 1)[0]
        self.assertIn("'^[0-9a-f]{64}$'", prune)
        self.assertIn('[IO.Directory]::Delete($full, $false)', prune)
        self.assertEqual(prune.count('[IO.Directory]::Delete('), 1)
        self.assertIn('[IO.Directory]::GetFileSystemEntries($full).Length -ne 0', prune)
        self.assertIn('[IO.FileAttributes]::ReparsePoint', prune)
        self.assertIn('Get-SafePath $directory', prune)
        self.assertNotIn('[IO.File]::Delete', prune)
        self.assertNotIn('Remove-Item', prune)
        self.assertEqual(script.count('[System.Management.Automation.Language.NullString]::Value'), 2)

    @unittest.skipUnless(os.name == 'nt' and shutil.which('powershell.exe'), 'Windows PowerShell required')
    def test_windows_filesystem(self):
        subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(ROOT / 'tests/test_cache_cleanup.ps1')], check=True)


if __name__ == '__main__':
    unittest.main()
