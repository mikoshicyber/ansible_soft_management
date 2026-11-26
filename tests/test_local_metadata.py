import os
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'module_utils'))
import software_core as c


class LocalMetadataTests(unittest.TestCase):
    code = '{00000001-1111-2222-3333-444444444444}'
    family = '{00000002-1111-2222-3333-444444444444}'
    property_table = ('Property\tValue\r\ns72\tl0\r\nProperty\tProperty\r\n'
                      f'ProductCode\t{code}\r\nUpgradeCode\t{family}\r\n'
                      'ProductVersion\t2.1.0\r\nProductName\tExample App\r\n'
                      'Manufacturer\tExample Vendor\r\nProductLanguage\t1033\r\n')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.source = self.root / 'source'
        self.source.mkdir()
        self.cache = self.root / 'cache'
        self.cache.mkdir()
        self.package = self.source / 'setup with spaces.msi'
        self.package.write_bytes(b'fixture')

    def metadata(self):
        return {'product_id': self.code, 'upgrade_code': self.family, 'version': '2.1.0',
                'name': 'Example App', 'publisher': 'Example Vendor', 'language': '1033', 'platform': 'x64'}

    def test_read_msi_with_real_subprocess_stub(self):
        binary = self.root / 'msiinfo'
        binary.write_text('#!' + sys.executable + '\nimport sys\n'
                          + 'assert sys.argv[2] == ' + repr(str(self.package)) + '\n'
                          + 'if sys.argv[1:] == ' + repr(['export', str(self.package), 'Property']) + ':\n'
                          + '    sys.stdout.write(' + repr(self.property_table) + ')\n'
                          + 'elif sys.argv[1:] == ' + repr(['suminfo', str(self.package)]) + ':\n'
                          + '    print("Title: Example\\nTemplate: x64;1033")\n'
                          + 'else:\n    sys.exit(3)\n')
        binary.chmod(0o755)
        with patch.dict(os.environ, {'PATH': str(self.root) + os.pathsep + os.environ.get('PATH', '')}):
            self.assertEqual(c.read_msi_metadata(str(self.package)), self.metadata())
        self.assertEqual(self.package.read_bytes(), b'fixture')

    def test_msi_empty_platform_uses_intel(self):
        with patch.object(c, 'msiinfo', side_effect=[self.property_table, 'Template: ;1033\n']):
            self.assertEqual(c.read_msi_metadata(str(self.package))['platform'], 'Intel')

    def test_invalid_property_table_and_guid(self):
        for table in ('invalid', self.property_table.replace(self.code, 'not-a-guid'), self.property_table + f'ProductCode\t{self.code}\n'):
            with self.subTest(table=table), patch.object(c, 'msiinfo', side_effect=[table, 'Template: x64;1033\n']), self.assertRaises(c.SoftwareError):
                c.read_msi_metadata(str(self.package))

    def test_msiinfo_timeout_and_nonzero(self):
        for error in (subprocess.TimeoutExpired(['msiinfo'], 60), subprocess.CalledProcessError(1, ['msiinfo'])):
            with self.subTest(error=error), patch.object(c.subprocess, 'run', side_effect=error), self.assertRaisesRegex(c.SoftwareError, 'msiinfo export failed'):
                c.read_msi_metadata(str(self.package))

    def test_metadata_error_blocks_only_matching_package(self):
        patterns = c.merge([{'patterns': [{'id': 'msi', 'regex': r'\.msi$', 'mode': 'msi'}]}], r'C:\Apps')
        paths = c.index(self.source)
        with patch.object(c, 'read_msi_metadata', side_effect=c.SoftwareError('read failed')):
            result = c.discover_msi(patterns, paths, str(self.source), c.normalize_state({}), str(self.cache))
        self.assertFalse(result['metadata'])
        snapshot = {'installed': [], 'msi_metadata': result['metadata'], 'local_msi_errors': result['errors']}
        plan = c.make_plan(patterns, paths, str(self.source), snapshot, c.normalize_state({}), r'C:\Apps', str(self.cache))
        self.assertFalse(plan['operations'])
        self.assertFalse(plan['errors'])
        self.assertIn('read failed', plan['blocked'][0]['reason'])

    def test_changed_file_during_metadata_read_rejected(self):
        checksum = c.sha(self.package)
        def mutate(path):
            Path(path).write_bytes(b'modified')
            return self.metadata()
        with patch.object(c, 'read_msi_metadata', side_effect=mutate), self.assertRaisesRegex(c.SoftwareError, 'Artifact changed during'):
            c.local_metadata(str(self.package), checksum, 'msi', str(self.cache))
        self.assertFalse(list(self.cache.glob('local-*.json')))

    def test_exe_resources_and_conflicting_languages(self):
        pe = Mock()
        pe.FILE_HEADER.Machine = 0x8664
        pe.FileInfo = [[types.SimpleNamespace(StringTable=[types.SimpleNamespace(entries={
            b'ProductName': b'Example', b'CompanyName': b'Vendor', b'ProductVersion': b'2.1.0', b'FileVersion': b'5.0'})])],
                       [types.SimpleNamespace(StringTable=[types.SimpleNamespace(entries={b'FileVersion': b'6.0'})])]]
        module = types.SimpleNamespace(PE=Mock(return_value=pe), DIRECTORY_ENTRY={'IMAGE_DIRECTORY_ENTRY_RESOURCE': 2}, PEFormatError=ValueError)
        with patch.dict(sys.modules, {'pefile': module}):
            result = c.read_exe_metadata('fixture.exe')
        self.assertEqual(result, {'name': 'Example', 'publisher': 'Vendor', 'product_version': '2.1.0', 'machine': 0x8664})
        pe.parse_data_directories.assert_called_once_with(directories=[2])
        pe.close.assert_called_once()

    def test_exe_hint_not_used_as_installed_version(self):
        path = self.source / 'setup-2.0.exe'
        path.write_bytes(b'fixture')
        patterns = c.merge([{'patterns': [{'id': 'exe', 'regex': r'\.exe$', 'mode': 'exe'}]}], r'C:\Apps')
        with patch.object(c, 'read_exe_metadata', return_value={'product_version': '99.0', 'name': 'Example'}) as reader:
            for _ in range(2):
                artifact = c.select_artifact(patterns[0], c.index(self.source), str(self.source), cache_dir=str(self.cache))
                self.assertEqual(artifact['version'], '2.0')
                self.assertEqual(artifact['exe_metadata']['product_version'], '99.0')
            reader.assert_called_once_with(str(path))

    def test_missing_tools_fail_preflight(self):
        with patch.object(c.shutil, 'which', return_value=None), self.assertRaisesRegex(c.SoftwareError, 'msiinfo not found'):
            c.check_metadata_tools()
        with patch.object(c.shutil, 'which', return_value='/usr/bin/msiinfo'), patch.dict(sys.modules, {'pefile': None}), self.assertRaisesRegex(c.SoftwareError, 'pefile not found'):
            c.check_metadata_tools()


if __name__ == '__main__':
    unittest.main()
