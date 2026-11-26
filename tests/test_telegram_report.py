import re
import unittest
from pathlib import Path

import yaml
from jinja2 import StrictUndefined
from jinja2.nativetypes import NativeEnvironment


ROOT = Path(__file__).resolve().parents[1]
TASKS = yaml.safe_load((ROOT / 'telegram.yaml').read_text())
REPORT = next(task for task in TASKS if 'software_notifications' in task.get('ansible.builtin.set_fact', {}))
BLOCK = next(task for task in TASKS if 'block' in task)
NOTICE, SEND, ERROR, SUCCESS = BLOCK['block']


class TelegramReportTest(unittest.TestCase):
    def setUp(self):
        self.environment = NativeEnvironment(undefined=StrictUndefined, trim_blocks=True)
        self.environment.filters['regex_findall'] = lambda value, pattern: re.findall(pattern, value)
        self.environment.filters['bool'] = lambda value: str(value).lower() in ('true', 'yes', 'on', '1')
        self.environment.tests['failed'] = lambda value: value.get('failed', False)
        self.environment.tests['succeeded'] = lambda value: not value.get('failed', False)
        self.environment.tests['skipped'] = lambda value: value.get('skipped', False)

    def render(self, value, **context):
        return self.environment.from_string(value).render(**context)

    def condition(self, value, **context):
        return self.render('{{ ' + value + ' }}', **context)

    def report(self, hosts, failed=False, **context):
        context.update(software_report=hosts, software_failed=failed)
        return self.render(REPORT['ansible.builtin.set_fact']['software_notifications'], **context)

    def credentials(self, env=None, **variables):
        env = env or {}
        lookup = lambda plugin, key: env.get(key, '')
        return {key: self.render(value, lookup=lookup, **variables) for key, value in BLOCK['vars'].items()}

    def test_success_and_error_report(self):
        hosts = [{'host': 'pc-a', 'completed': True, 'reboot_required': True, 'results': [
            {'id': 'aimp', 'filename': 'AIMP.exe', 'action': 'install', 'status': 'unverified', 'installed_version': None},
            {'id': 'blender', 'action': 'plan', 'status': 'error', 'reason': 'No matching artifact'},
            {'id': 'krita', 'action': 'upgrade', 'status': 'ok', 'installed_version': '5.3.5'}]}]
        parts = self.report(hosts, failed=True, software_catalog={'catalog': []})
        self.assertEqual(len(parts), 1)
        text = parts[0]
        for value in ('<b>Updates completed with errors</b>', '<b>pc-a</b>:', '<i>Installed/updated</i>:', '• AIMP.exe', '<i>Errors</i>:', '• blender — No matching artifact', '• krita', 'Reboot required.'):
            self.assertIn(value, text)

    def test_original_compact_success_format(self):
        hosts = [
            {'host': 'pc-a', 'completed': True, 'reboot_required': False, 'results': [
                {'id': 'firefox', 'filename': 'Firefox.exe', 'action': 'upgrade', 'status': 'installer_reported', 'installed_version': '161.0'},
                {'id': 'krita', 'filename': 'Krita.exe', 'action': 'install', 'status': 'unverified', 'reason': 'installer succeeded'}]},
            {'host': 'pc-b', 'completed': True, 'reboot_required': False, 'results': []},
            {'host': 'pc-c', 'completed': True, 'reboot_required': False, 'results': [
                {'id': 'aimp', 'filename': 'AIMP.exe', 'action': 'install', 'status': 'ok'}]},
        ]
        parts = self.report(hosts, software_catalog={'catalog': []})
        self.assertEqual(len(parts), 1)
        message = self.render(SEND['community.general.telegram']['api_args']['text'], item=parts[0], software_notification_index=0, software_notifications=parts)
        self.assertEqual(message, '<b>Updates completed</b>\n<b>pc-a</b>:\n<i>Installed/updated</i>:\n• Firefox.exe\n• Krita.exe\n<b>pc-c</b>:\n<i>Installed/updated</i>:\n• AIMP.exe')

    def test_incomplete_host_without_results(self):
        hosts = [{'host': 'pc-a', 'completed': False, 'reboot_required': False, 'results': []}]
        parts = self.report(hosts, failed=True, software_catalog={'catalog': []})
        self.assertIn('<b>pc-a</b>:', parts[0])
        self.assertIn('Processing incomplete.', parts[0])
        self.assertNotIn('No changes.', parts[0])

    def test_no_changes_still_sends_report(self):
        hosts = [{'host': 'pc-a', 'completed': True, 'reboot_required': False, 'results': []}]
        parts = self.report(hosts, software_catalog={'catalog': []})
        self.assertEqual(len(parts), 1)
        self.assertIn('<b>Updates completed</b>', parts[0])
        self.assertIn('No changes.', parts[0])

    def test_catalog_failure_and_no_hosts(self):
        parts = self.report([], failed=True)
        self.assertIn('Failed to prepare local catalog', parts[0])
        self.assertIn('No Windows host results', parts[0])

    def test_long_unicode_report_parts(self):
        hosts = [{'host': 'pc-a', 'completed': False, 'reboot_required': False, 'results': [
            {'id': 'failure', 'status': 'error', 'reason': '🚧' * 9000}]}]
        parts = self.report(hosts, failed=True, software_catalog={'catalog': []})
        self.assertGreater(len(parts), 1)
        self.assertIn('🚧' * 9000, ''.join(parts))
        for index, part in enumerate(parts):
            message = self.render(SEND['community.general.telegram']['api_args']['text'], item=part, software_notification_index=index, software_notifications=parts)
            self.assertTrue(message.startswith(f'Part {index + 1}/{len(parts)}\n'))
            self.assertLessEqual(len(message.encode('utf-16-le')) // 2, 4096)

    def test_html_escaping_and_sections(self):
        from html import unescape
        from xml.etree import ElementTree

        hosts = [{'host': '<pc&>', 'completed': True, 'reboot_required': False, 'results': [
            {'id': 'deleted', 'action': 'uninstall', 'status': 'ok'},
            {'id': 'warn', 'action': 'skip', 'status': 'warning', 'reason': '<&>' * 1000},
            {'id': 'bad', 'status': 'error', 'reason': '</b><a href="x">'}]}]
        parts = self.report(hosts, failed=True, software_catalog={'catalog': []})
        for part in parts:
            ElementTree.fromstring('<root>' + part + '</root>')
            self.assertLessEqual(len(part.encode('utf-16-le')) // 2, 3600)
        joined = ''.join(parts)
        self.assertIn('<b>&lt;pc&amp;&gt;</b>:', joined)
        self.assertIn('<i>Removed</i>:', joined)
        self.assertIn('<i>Warnings</i>:', joined)
        self.assertIn('<&>' * 1000, unescape(joined))
        self.assertIn('&lt;/b&gt;&lt;a href="x"&gt;', joined)

    def test_legacy_credentials_and_precedence(self):
        cases = [
            ({'TELEGRAM_BOT_TOKEN': 'env-token', 'TELEGRAM_TOKEN': 'env-alias'}, {'telegram_bot_token': 'new', 'telegram_token': 'old'}, 'env-token'),
            ({'TELEGRAM_BOT_TOKEN': '  ', 'TELEGRAM_TOKEN': 'env-alias'}, {'telegram_bot_token': 'new'}, 'env-alias'),
            ({}, {'telegram_bot_token': 'new', 'telegram_token': 'old'}, 'new'),
            ({}, {'telegram_bot_token': '', 'telegram_token': 'old'}, 'old'),
            ({}, {}, ''),
        ]
        for env, variables, expected in cases:
            with self.subTest(expected=expected):
                creds = self.credentials(env, telegram_chat_id=-100123, **variables)
                self.assertEqual(creds['software_telegram_token'], expected)
                self.assertEqual(str(creds['software_telegram_chat']), '-100123')
                self.assertEqual(bool(self.condition(NOTICE['when'], **creds)), not bool(expected))
                self.assertEqual(all(self.condition(condition, **creds) for condition in SEND['when']), bool(expected))

    def test_missing_chat_prevents_send(self):
        creds = self.credentials(telegram_token='old')
        self.assertTrue(self.condition(NOTICE['when'], **creds))
        self.assertFalse(all(self.condition(condition, **creds) for condition in SEND['when']))

    def test_proxy_only_for_telegram(self):
        for env, variables, expected in [({}, {}, {}), ({'TELEGRAM_HTTPS_PROXY': 'http://proxy:8080'}, {}, {'https_proxy': 'http://proxy:8080', 'HTTPS_PROXY': 'http://proxy:8080'})]:
            with self.subTest(expected=expected):
                creds = self.credentials(env, **variables)
                self.assertEqual(self.render(SEND['environment'], **creds), expected)

    def test_check_and_metadata_mode(self):
        for check, metadata, expected in [(False, False, True), (True, False, False), (False, True, False)]:
            context = {'ansible_check_mode': check, 'software_metadata_only': metadata}
            self.assertEqual(all(self.condition(condition, **context) for condition in BLOCK['when']), expected)

    def test_delivery_result_and_secrets(self):
        self.assertIs(SEND['no_log'], True)
        self.assertIs(SEND['ignore_errors'], True)
        self.assertEqual(SEND['community.general.telegram']['api_args']['parse_mode'], 'HTML')
        for result, success, failure in [({}, True, False), ({'failed': True}, False, True), ({'skipped': True}, False, False)]:
            context = {'software_telegram_result': result}
            self.assertEqual(all(self.condition(condition, **context) for condition in SUCCESS['when']), success)
            self.assertEqual(self.condition(ERROR['when'], **context), failure)
        self.assertIn('ansible.builtin.fail', TASKS[-1])
        self.assertEqual(TASKS[-1]['when'], 'software_failed')

    def test_docker_environment_forwarding(self):
        run = (ROOT / 'run.sh').read_text()
        for name in ('TELEGRAM_BOT_TOKEN', 'TELEGRAM_TOKEN', 'TELEGRAM_CHAT_ID', 'TELEGRAM_HTTPS_PROXY'):
            self.assertIn('-e ' + name, run)


if __name__ == '__main__':
    unittest.main()
