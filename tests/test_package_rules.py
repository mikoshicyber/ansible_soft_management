import sys
import tempfile
import unittest
from pathlib import Path

import yaml
from jinja2 import StrictUndefined
from jinja2.nativetypes import NativeEnvironment

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'module_utils'))
import software_core as core


class PackageRulesTests(unittest.TestCase):
    def test_filename_matching(self):
        cases = [
            (r'7z[\d.]+-x64.exe', 'exe', '7z2600-x64.exe', True),
            ('AIMP', 'exe', 'aimp_5.40.2731_w64.exe', True),
            (r'audacity-win-[\d.]+-64bit.exe', 'exe', 'audacity-win-3.7.9-64bit.exe', True),
            (r'blender-[\d\.]-windows-x64\.msi', 'msi', 'blender-5.3.0-windows-x64.msi', False),
            (r'calibre-64bit-.*\.msi', 'msi', 'calibre-64bit-9.19.0.msi', True),
            ('dbeaver', 'exe', 'dbeaver-ce-latest-x86_64-setup.exe', True),
            (r'draw.io-.*-windows-installer.exe', 'exe', 'draw.io-32.7.4-windows-installer.exe', True),
            (r'Far[\d.ab]+.x64.[\d]+.msi', 'msi', 'Far_3.0.6757.5047_x64_20261125_0e5577a.msi', False),
            ('ffmpeg-master-latest-win64-gpl.zip', 'arc', 'ffmpeg-master-latest-win64-gpl.zip', True),
            ('Firefox', 'exe', 'Firefox Setup 161.0.exe', True),
            ('Freelens-.*-windows-amd64.msi', 'msi', 'Freelens-2.1.0-windows-amd64.msi', True),
            ('gimp', 'exe', 'gimp-3.2.8-setup.exe', True),
            ('HeidiSQL', 'exe', 'HeidiSQL_12.22.0.7433_Setup.exe', True),
            ('inkscape-.+-x64.exe', 'exe', 'inkscape-1.4.4_2026-05-05_dcaf3e7-x64.signed.exe', False),
            ('jami.release.x64.msi', 'msi', 'jami.release.x64.msi', True),
            ('keepass', 'exe', 'KeePass-2.62-Setup.exe', True),
            ('K-Lite_Codec_Pack_.+_Mega.exe', 'exe', 'K-Lite_Codec_Pack_2020_Mega.exe', True),
            (r'krita-x64-[\d.-]+-setup.exe', 'exe', 'krita-x64-5.3.4.1-setup.exe', True),
            ('libreoffice.*help', 'msi', 'LibreOffice_26.8.3_Win_x86-64_helppack_ru.msi', True),
            ('libreoffice.*_Win_x86-64.msi', 'msi', 'LibreOffice_26.8.3_Win_x86-64.msi', True),
            ('libreoffice.*_Win_x86-64.msi', 'msi', 'LibreOffice_26.8.3_Win_x86-64_helppack_ru.msi', False),
            (r'mumble_client-[\d.]+.x64.msi', 'msi', 'mumble_client-1.5.939.x64.exe', False),
            ('Nextcloud.Talk-windows-x64.msi', 'msi', 'Nextcloud.Talk-windows-x64.msi', True),
            ('Nextcloud.Talk-windows-x64.msi', 'msi', 'Nextcloud.Talk-windows-x64.exe', False),
            ('Nextcloud-.*-x64.msi', 'msi', 'Nextcloud-35.0.3-x64.msi', True),
            ('Nextcloud-.*-x64.msi', 'msi', 'Nextcloud.Talk-windows-x64.msi', False),
            ('npp.+Installer.x64.exe', 'exe', 'npp.8.9.9.1.Installer.x64.exe', True),
            (r'OBS-Studio-[\d.-]+-Windows-x64-Installer.exe', 'exe', 'OBS-Studio-33.0.3-Windows-x64-Installer.exe', True),
            ('openconnect', 'exe', 'openconnect-gui-1.6.2-win64.exe', True),
            ('openvpn', 'msi', 'OpenVPN-2.7.9-I002-amd64.msi', True),
            (r'putty-64bit-[\d.]+-installer.msi', 'msi', 'putty-64bit-0.85-installer.msi', True),
            (r'python-[\d.]+-amd64.exe', 'exe', 'python-3.15.2-amd64.exe', True),
            ('ShareX', 'exe', 'ShareX-22.4.0-setup-x64.exe', True),
            ('Thunderbird', 'exe', 'Thunderbird Setup 161.0.exe', True),
            (r'tightvnc-[\d.]+-gpl-setup-64bit.msi', 'msi', 'tightvnc-2.8.90-gpl-setup-64bit.msi', True),
            ('tor-browser', 'exe', 'tor-browser-windows-x86_64-portable-16.0.3.exe', True),
            (r'tor-expert-bundle-windows-x86_64-[\d.-]+.tar.gz', 'arc', 'tor-expert-bundle-windows-x86_64-16.0.3.tar.gz', True),
            (r'tor-expert-bundle-windows-x86_64-[\d.-]+.tar.gz', 'arc', 'tor-expert-bundle-linux-x86_64-16.0.3.tar.gz', False),
            (r'transgui-[\d.]+-setup_64bit.exe', 'exe', 'transgui-5.18.0-setup_64bit.exe', True),
            (r'VeraCrypt_Setup_x64_[\d.]+.msi', 'msi', 'VeraCrypt_Setup_x64_1.26.31.msi', True),
            ('VirtualBox-.*-Win.exe', 'exe', 'VirtualBox-7.2.22-175245-Win.exe', True),
            (r'vlc-[\d.]+-win64.exe', 'exe', 'vlc-3.0.24-win64.exe', True),
            ('VSCodeUserSetup', 'exe', 'VSCodeUserSetup-x64-1.147.0.exe', True),
            ('windows_exporter-.*-amd64.msi', 'msi', 'windows_exporter-0.32.1-amd64.msi', True),
            ('WinSCP-.*-Setup', 'exe', 'WinSCP-6.7.1-Setup.exe', True),
            ('XnConvert-win-x64', 'exe', 'XnConvert-win-x64.exe', True),
            ('XnViewMP-win-x64', 'exe', 'XnViewMP-win-x64.exe', True),
        ]
        for regex, mode, filename, expected in cases:
            with self.subTest(filename=filename, regex=regex):
                self.assertEqual(bool(core.matching_paths({'regex': regex, 'mode': mode}, ['/source/' + filename])), expected)

    def test_corrected_regexes(self):
        cases = [
            (r'^blender-\d+(?:\.\d+)+-windows-x64\.msi$', 'msi', 'blender-5.3.0-windows-x64.msi'),
            (r'^Far_\d+(?:\.\d+)+_x64_\d{8}_[0-9a-f]+\.msi$', 'msi', 'Far_3.0.6757.5047_x64_20261125_0e5577a.msi'),
            (r'^inkscape-.+-x64(?:\.signed)?\.exe$', 'exe', 'inkscape-1.4.4_2026-05-05_dcaf3e7-x64.signed.exe'),
            (r'^mumble_client-\d+(?:\.\d+)+\.x64\.exe$', 'exe', 'mumble_client-1.5.939.x64.exe'),
        ]
        for regex, mode, filename in cases:
            with self.subTest(filename=filename):
                self.assertEqual(core.matching_paths({'regex': regex, 'mode': mode, 'match_filename_only': True}, ['/source/' + filename]), ['/source/' + filename])

    def test_architecture_is_not_version(self):
        cases = {
            'tor-expert-bundle-windows-x86_64-16.0.3.tar.gz': '16.0.3',
            'tor-browser-windows-x86_64-portable-16.0.3.exe': '16.0.3',
            'dbeaver-ce-latest-x86_64-setup.exe': None,
            'VeraCrypt_Setup_x64_1.26.31.msi': '1.26.31',
            'tsetup-x64.7.2.5.exe': '7.2.5',
            '7z2600-x64.exe': None,
            'Far_3.0.6757.5047_x64_20261125_0e5577a.msi': '3.0.6757.5047',
            'OBS-Studio-33.0.3-Windows-x64-Installer.exe': '33.0.3',
            'Nextcloud.Talk-windows-x64.msi': None,
            'go1.27rc3.windows-amd64.msi': '1.27rc3',
        }
        for filename, expected in cases.items():
            with self.subTest(filename=filename):
                self.assertEqual(core.parse_version(filename, {'version_type': 'auto'}), expected)
        self.assertEqual(core.parse_version('7z2600-x64.exe', {'version_type': 'auto', 'version_regex': r'^7z(\d+)'}), '2600')
        self.assertEqual(core.parse_version('inkscape-1.4.4_2026-05-05_dcaf3e7-x64.signed.exe', {'version_type': 'auto', 'version_regex': r'^inkscape-(\d+(?:\.\d+)+)'}), '1.4.4')

    def test_msi_arguments(self):
        args = ['/quiet', '/norestart', 'ENABLED_COLLECTORS="[defaults],process,textfile"', r'TEXTFILE_DIRS="C:\metrics"']
        expected = r'ENABLED_COLLECTORS="[defaults],process,textfile" TEXTFILE_DIRS="C:\metrics"'
        self.assertEqual(core.msi_arguments(args), expected)
        self.assertEqual(core.msi_arguments(['/qn', 'ADDLOCAL=Server']), 'ADDLOCAL=Server')
        self.assertEqual(core.msi_arguments(['/quiet', 'ACCEPTLICENSE=YES']), 'ACCEPTLICENSE=YES')
        self.assertEqual(core.msi_arguments([r'TARGETDIR=C:\Program Files\App']), r'TARGETDIR="C:\Program Files\App"')
        self.assertEqual(core.msi_arguments(expected), expected)
        p = core.merge([{'patterns': [{'regex': 'app', 'mode': 'msi', 'args': args, 'force': 'false', 'pre': 'taskkill /f /im app.exe'}]}], r'C:\Apps')[0]
        self.assertEqual(p['args'], expected)
        self.assertFalse(p['force'])
        self.assertEqual(p['pre'], ['taskkill /f /im app.exe'])

    def test_msi_explicit_full_filename_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a = root / 'Far_3.0.6757.5046_x64_20261124_aaaaaaa.msi'
            b = root / 'Far_3.0.6757.5047_x64_20261125_bbbbbbb.msi'
            a.write_bytes(b'old')
            b.write_bytes(b'new')
            meta = {'product_id': '{11111111-1111-1111-1111-111111111111}', 'upgrade_code': '{22222222-2222-2222-2222-222222222222}', 'version': '3.0.6757', 'name': 'Far', 'publisher': 'Far', 'language': '1033', 'platform': 'x64'}
            metadata = {core.sha(a): meta, core.sha(b): meta}
            p = core.merge([{'patterns': [{'mode': 'msi', 'regex': r'^Far_.*\.msi$', 'match_filename_only': True, 'version_regex': r'^Far_(\d+(?:\.\d+)+)_'}]}], r'C:\Apps')[0]
            artifact = core.select_artifact(p, [str(a), str(b)], str(root), metadata)
            self.assertEqual(artifact['filename'], b.name)
            self.assertEqual(artifact['version'], '3.0.6757.5047')
            self.assertEqual(artifact['msi_metadata']['version'], '3.0.6757')

    def test_unsafe_or_conflicting_rules_rejected(self):
        for patterns in ([{'regex': 'AIMP', 'args': '/a'}, {'regex': 'AIMP', 'args': '/b'}], [{'regex': 'Tesseract', 'mode': 'files', 'state': 'absent'}]):
            with self.subTest(patterns=patterns), self.assertRaises(core.SoftwareError):
                core.merge([{'scope': 'all', 'patterns': patterns}], r'C:\Apps')

    def test_all_per_package_names_include_label(self):
        env = NativeEnvironment(undefined=StrictUndefined)
        windows = yaml.safe_load((ROOT / 'task_windows.yaml').read_text())
        execute = next(t for t in windows if t.get('ansible.builtin.include_tasks', {}).get('file') == 'task_execute.yaml')
        labels = [({'id': 'r', 'artifact': {'filename': 'Firefox Setup 161.0.exe'}}, 'Firefox Setup 161.0.exe'), ({'id': 'r', 'installed': {'name': 'Blender'}}, 'Blender'), ({'id': 'r', 'old': {'filename': 'app.msi'}}, 'app.msi'), ({'id': 'r', 'pattern': {'files': ['torrc', 'tor_install.bat']}}, 'torrc, tor_install.bat'), ({'id': 'r'}, 'r')]
        for item, expected in labels:
            self.assertEqual(env.from_string(execute['vars']['software_package_label']).render(software_item=item), expected)
        def walk(tasks):
            for task in tasks:
                yield task
                for key in ('block', 'rescue', 'always'):
                    yield from walk(task.get(key, []))
        for file in ('task_execute.yaml', 'task_package.yaml', 'task_package_prepare.yaml', 'task_state.yaml', 'task_verify.yaml', 'task_files.yaml', 'task_file_plan.yaml', 'task_file_verify.yaml'):
            for task in walk(yaml.safe_load((ROOT / file).read_text())):
                with self.subTest(file=file, name=task['name']):
                    self.assertIn('software_package_label', task['name'])
                    self.assertIn('software_index_label', task['name'])
                    text = env.from_string(task['name']).render(software_package_label='app.exe', software_index_label='Index 2/3', software_item={'action': 'install'}, software_action='install')
                    self.assertIn('app.exe', text)
                    self.assertIn('Index 2/3', text)


if __name__ == '__main__':
    unittest.main()
