import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TARGET = 'ansible-ee:metadata'
BASE = 'quay.io/ansible/awx-ee:latest'
MOCK = '''#!/usr/bin/env python3
import gzip
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
state = Path(os.environ['MOCK_STATE'])
images = json.loads(state.read_text())
with open(os.environ['MOCK_LOG'], 'a') as log:
    log.write(json.dumps(args) + '\\n')
operation = ' '.join(args[:2]) if args[0] == 'image' else args[0]
if operation == os.environ.get('MOCK_FAIL'):
    if operation == 'image save':
        sys.stdout.write('partial')
    sys.exit(9)
if operation == 'info':
    pass
elif operation == 'image inspect':
    sys.exit(0 if args[2] in images else 1)
elif operation == 'image pull':
    images.append(args[2])
elif operation == 'build':
    assert args[-1] == '-'
    assert sys.stdin.read() == os.environ['MOCK_DOCKERFILE']
    base = args[args.index('--build-arg') + 1].split('=', 1)[1]
    assert base in images
    if not os.environ.get('MOCK_WRONG_TAG'):
        images.append(args[args.index('--tag') + 1])
elif operation == 'image tag':
    assert args[2] in images
    images.append(args[3])
elif operation == 'image save':
    assert args[2] in images
    sys.stdout.write(args[2])
elif operation == 'image load':
    with gzip.open(args[3], 'rt') as archive:
        images.append(archive.read())
elif operation == 'run':
    print('ANSIBLE MOCK')
else:
    sys.exit(10)
state.write_text(json.dumps(images))
'''


class RunImageBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / 'project with spaces'
        self.project.mkdir()
        shutil.copy2(ROOT / 'run.sh', self.project / 'run.sh')
        self.dockerfile = 'ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n'
        (self.project / 'Dockerfile').write_text(self.dockerfile)
        (self.project / 'inventory.yaml').touch()
        self.source = self.root / 'source'
        self.source.mkdir()
        self.cache = self.project / '.docker-images'
        self.cache.mkdir()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        docker = self.bin / 'docker'
        docker.write_text(MOCK)
        docker.chmod(0o755)
        self.state = self.root / 'state.json'
        self.state.write_text('[]')
        self.log = self.root / 'commands.jsonl'
        self.env = dict(os.environ)
        for name in ('ANSIBLE_EE_IMAGE', 'ANSIBLE_EE_BASE_IMAGE', 'ANSIBLE_EE_CACHE_DIR', 'ANSIBLE_INVENTORY_FILE', 'MOCK_FAIL', 'MOCK_WRONG_TAG'):
            self.env.pop(name, None)
        self.env.update(PATH=f'{self.bin}:{self.env["PATH"]}', SOURCE_DIR=str(self.source), MOCK_STATE=str(self.state), MOCK_LOG=str(self.log), MOCK_DOCKERFILE=self.dockerfile)

    def archive(self, image=TARGET):
        return self.cache / (hashlib.sha256(image.encode()).hexdigest() + '.tar.gz')

    def put_archive(self, image=TARGET, contents=None):
        with gzip.open(self.archive(image), 'wt') as archive:
            archive.write(image if contents is None else contents)

    def images(self, *images):
        self.state.write_text(json.dumps(images))

    def execute(self, *args, success=True):
        result = subprocess.run(['bash', str(self.project / 'run.sh'), *args], cwd=self.root, env=self.env, capture_output=True, text=True, timeout=15)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        self.calls = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        return result

    def operations(self):
        return [' '.join(call[:2]) if call[0] == 'image' else call[0] for call in self.calls if call[:2] != ['image', 'inspect']]

    def test_local_image_and_archive(self):
        self.images(TARGET)
        self.put_archive()
        self.execute()
        self.assertEqual(self.operations(), ['info', 'run'])

    def test_local_image_without_archive(self):
        self.images(TARGET)
        self.execute()
        self.assertEqual(self.operations(), ['info', 'image save', 'run'])
        self.assertEqual(gzip.decompress(self.archive().read_bytes()).decode(), TARGET)

    def test_restore_archive_without_base_or_dockerfile(self):
        self.put_archive()
        (self.project / 'Dockerfile').unlink()
        self.execute()
        self.assertEqual(self.operations(), ['info', 'image load', 'run'])

    def test_cold_build(self):
        self.execute('--limit', 'host one', '--check')
        self.assertEqual(self.operations(), ['info', 'image pull', 'build', 'image save', 'run'])
        self.assertIn(['image', 'pull', BASE], self.calls)
        self.assertEqual(self.calls[-1][-8:], ['python3', '/work/scripts/run_playbook.py', '-i', 'inventory.yaml', 'playbook.yml', '--limit', 'host one', '--check'])
        self.assertIn('--pull=never', self.calls[-1])
        self.assertEqual(gzip.decompress(self.archive().read_bytes()).decode(), TARGET)

    def test_local_base_skips_pull(self):
        self.images(BASE)
        self.execute()
        self.assertEqual(self.operations(), ['info', 'build', 'image save', 'run'])

    def test_custom_base_and_target(self):
        self.env.update(ANSIBLE_EE_BASE_IMAGE='example/base:1', ANSIBLE_EE_IMAGE='example/ee:2')
        self.execute()
        self.assertIn(['image', 'pull', 'example/base:1'], self.calls)
        self.assertIn(['build', '--pull=false', '--build-arg', 'BASE_IMAGE=example/base:1', '--tag', 'example/ee:2', '-'], self.calls)
        self.assertTrue(self.archive('example/ee:2').is_file())

    def test_legacy_archive(self):
        legacy = self.archive().with_suffix('')
        legacy.write_text(TARGET)
        self.execute()
        self.assertEqual(self.operations(), ['info', 'image load', 'run'])
        self.assertTrue(legacy.exists())
        self.assertTrue(self.archive().exists())

    def test_pull_failure(self):
        self.env['MOCK_FAIL'] = 'image pull'
        self.execute(success=False)
        self.assertEqual(self.operations(), ['info', 'image pull'])
        self.assertFalse(self.archive().exists())

    def test_build_failure(self):
        self.env['MOCK_FAIL'] = 'build'
        self.execute(success=False)
        self.assertEqual(self.operations(), ['info', 'image pull', 'build'])
        self.assertFalse(self.archive().exists())

    def test_save_failure(self):
        self.env['MOCK_FAIL'] = 'image save'
        self.execute(success=False)
        self.assertEqual(self.operations(), ['info', 'image pull', 'build', 'image save'])
        self.assertFalse(self.archive().exists())
        self.assertEqual(list(self.cache.glob('*.tmp.*')), [])

    def test_corrupt_archive(self):
        self.archive().write_bytes(b'not gzip')
        self.execute(success=False)
        self.assertEqual(self.operations(), ['info', 'image load'])

    def test_archive_wrong_image(self):
        self.put_archive(contents='other:image')
        self.execute(success=False)
        self.assertEqual(self.operations(), ['info', 'image load'])

    def test_build_missing_final_tag(self):
        self.env['MOCK_WRONG_TAG'] = '1'
        self.execute(success=False)
        self.assertEqual(self.operations(), ['info', 'image pull', 'build'])

    def test_missing_dockerfile(self):
        (self.project / 'Dockerfile').unlink()
        self.execute(success=False)
        self.assertEqual(self.operations(), ['info'])

    def test_same_base_and_target_rejected(self):
        self.env['ANSIBLE_EE_IMAGE'] = BASE
        self.execute(success=False)
        self.assertEqual(self.calls, [])

    def test_prebuilt_digest(self):
        image = 'example/ee@sha256:' + 'a' * 64
        self.env['ANSIBLE_EE_IMAGE'] = image
        self.execute()
        self.assertEqual(self.operations(), ['info', 'image pull', 'image tag', 'image save', 'run'])
        cached = 'ansible-ee-cache:sha256-' + hashlib.sha256(image.encode()).hexdigest()
        self.assertEqual(gzip.decompress(self.archive(image).read_bytes()).decode(), cached)
        self.images()
        self.log.unlink()
        self.execute()
        self.assertEqual(self.operations(), ['info', 'image load', 'run'])
        self.assertIn(cached, self.calls[-1])

    def test_help_without_docker(self):
        result = self.execute('--help')
        self.assertIn('ANSIBLE_EE_BASE_IMAGE', result.stdout)
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
